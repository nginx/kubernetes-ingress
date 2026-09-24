package k8s

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	fake_v1 "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// newVSRStatusTestLBC builds a LoadBalancerController wired to a fake
// configuration clientset, ready to drive VirtualServer/VirtualServerRoute
// resources through the normal Configuration -> processChanges/processProblems
// path outside of the task queue, mirroring newWeightTestLBCWithAutoadjust in
// weight_fast_lane_test.go. Unlike that harness, isNginxReady is true from the
// start, so VS/VSR status writes go straight to the fake clientset instead of
// the startup pending slices, and the fake clientset is returned so tests can
// assert on the persisted status.
//
// The single namespacedInformer is registered under the "" (global) key,
// which getNamespacedInformer treats as "watching all namespaces" -- see its
// isGlobalNs branch. That lets cross-namespace VS/VSR references (a hostless
// VSR in one namespace selected by a VS in another) work against this one
// shared store without the harness needing to know in advance which
// namespaces a given test will use.
func newVSRStatusTestLBC(tb testing.TB) (*LoadBalancerController, *fake_v1.Clientset) {
	tb.Helper()

	mgr := nginx.NewFakeManager("/etc/nginx")

	templateExecutor, err := version1.NewTemplateExecutor(
		filepath.Join("..", "configs", "version1", "nginx.tmpl"),
		filepath.Join("..", "configs", "version1", "nginx.ingress.tmpl"),
	)
	if err != nil {
		tb.Fatalf("v1 template executor: %v", err)
	}
	templateExecutorV2, err := version2.NewTemplateExecutor(
		filepath.Join("..", "configs", "version2", "nginx.virtualserver.tmpl"),
		filepath.Join("..", "configs", "version2", "nginx.transportserver.tmpl"),
		filepath.Join("..", "configs", "version2", "oidc.tmpl"),
	)
	if err != nil {
		tb.Fatalf("v2 template executor: %v", err)
	}

	nsi := &namespacedInformer{
		virtualServerLister:      cache.NewStore(cache.MetaNamespaceKeyFunc),
		virtualServerRouteLister: cache.NewStore(cache.MetaNamespaceKeyFunc),
	}

	confClient := fake_v1.NewSimpleClientset()

	lbc := &LoadBalancerController{
		configurator: configs.NewConfigurator(configs.ConfiguratorParams{
			NginxManager:       mgr,
			StaticCfgParams:    &configs.StaticConfigParams{},
			Config:             configs.NewDefaultConfigParams(context.Background(), false),
			MGMTCfgParams:      configs.NewDefaultMGMTConfigParams(context.Background()),
			TemplateExecutor:   templateExecutor,
			TemplateExecutorV2: templateExecutorV2,
			IsPlus:             true,
		}),
		configuration: NewConfiguration(
			func(interface{}) bool { return true },
			true, false, false,
			validation.NewVirtualServerValidator(),
			validation.NewGlobalConfigurationValidator(map[int]bool{}),
			validation.NewTransportServerValidator(false, false, false),
			false, false, false, false, false, false,
		),
		recorder:                  record.NewFakeRecorder(100),
		Logger:                    nl.LoggerFromContext(context.Background()),
		client:                    fake.NewClientset(),
		isNginxReady:              true,
		namespacedInformers:       map[string]*namespacedInformer{"": nsi},
		areCustomResourcesEnabled: true,
		statusUpdater: &statusUpdater{
			confClient:          confClient,
			namespacedInformers: map[string]*namespacedInformer{"": nsi},
			keyFunc:             cache.DeletionHandlingMetaNamespaceKeyFunc,
			logger:              nl.LoggerFromContext(context.Background()),
		},
	}
	lbc.configuration.CompleteStartup()

	return lbc, confClient
}

// addVSRStatusTest seeds vsr into both the informer store and the fake
// clientset (so the statusUpdater's UpdateStatus calls succeed), then drives
// it through Configuration and the normal change/problem processing.
func addVSRStatusTest(tb testing.TB, lbc *LoadBalancerController, confClient *fake_v1.Clientset, vsr *conf_v1.VirtualServerRoute) {
	tb.Helper()

	nsi := lbc.getNamespacedInformer(vsr.Namespace)
	if err := nsi.virtualServerRouteLister.Add(vsr); err != nil {
		tb.Fatalf("seeding VSR informer: %v", err)
	}
	if _, err := confClient.K8sV1().VirtualServerRoutes(vsr.Namespace).Create(context.TODO(), vsr, metav1.CreateOptions{}); err != nil {
		tb.Fatalf("seeding VSR clientset: %v", err)
	}

	changes, problems := lbc.configuration.AddOrUpdateVirtualServerRoute(vsr)
	lbc.processChanges(changes)
	lbc.processProblems(problems)

	syncVSRInformerFromClient(tb, lbc, confClient, vsr.Namespace, vsr.Name)
}

// addVSStatusTest seeds vs into both the informer store and the fake
// clientset, then drives it through Configuration and the normal
// change/problem processing.
func addVSStatusTest(tb testing.TB, lbc *LoadBalancerController, confClient *fake_v1.Clientset, vs *conf_v1.VirtualServer, vsrNamespaces []string, vsrNames []string) {
	tb.Helper()

	nsi := lbc.getNamespacedInformer(vs.Namespace)
	if err := nsi.virtualServerLister.Add(vs); err != nil {
		tb.Fatalf("seeding VS informer: %v", err)
	}
	if _, err := confClient.K8sV1().VirtualServers(vs.Namespace).Create(context.TODO(), vs, metav1.CreateOptions{}); err != nil {
		tb.Fatalf("seeding VS clientset: %v", err)
	}

	changes, problems := lbc.configuration.AddOrUpdateVirtualServer(vs)
	lbc.processChanges(changes)
	lbc.processProblems(problems)

	for i := range vsrNamespaces {
		syncVSRInformerFromClient(tb, lbc, confClient, vsrNamespaces[i], vsrNames[i])
	}
}

// updateVSStatusTest replaces an already-seeded vs in both the informer store
// and the fake clientset, then drives the update through Configuration and
// the normal change/problem processing. Unlike addVSStatusTest, it uses
// Update against both stores since vs is expected to already exist.
func updateVSStatusTest(tb testing.TB, lbc *LoadBalancerController, confClient *fake_v1.Clientset, vs *conf_v1.VirtualServer, vsrNamespaces []string, vsrNames []string) {
	tb.Helper()

	nsi := lbc.getNamespacedInformer(vs.Namespace)
	if err := nsi.virtualServerLister.Update(vs); err != nil {
		tb.Fatalf("updating VS informer: %v", err)
	}
	if _, err := confClient.K8sV1().VirtualServers(vs.Namespace).Update(context.TODO(), vs, metav1.UpdateOptions{}); err != nil {
		tb.Fatalf("updating VS clientset: %v", err)
	}

	changes, problems := lbc.configuration.AddOrUpdateVirtualServer(vs)
	lbc.processChanges(changes)
	lbc.processProblems(problems)

	for i := range vsrNamespaces {
		syncVSRInformerFromClient(tb, lbc, confClient, vsrNamespaces[i], vsrNames[i])
	}
}

// deleteVSStatusTest removes vs from the informer store and the fake
// clientset, then drives the deletion through Configuration and the normal
// change/problem processing.
func deleteVSStatusTest(tb testing.TB, lbc *LoadBalancerController, confClient *fake_v1.Clientset, namespace, name string, vsrNamespaces []string, vsrNames []string) {
	tb.Helper()

	key := namespace + "/" + name
	nsi := lbc.getNamespacedInformer(namespace)
	if err := nsi.virtualServerLister.Delete(&conf_v1.VirtualServer{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}); err != nil {
		tb.Fatalf("removing VS from informer: %v", err)
	}
	if err := confClient.K8sV1().VirtualServers(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		tb.Fatalf("removing VS from clientset: %v", err)
	}

	changes, problems := lbc.configuration.DeleteVirtualServer(key)
	lbc.processChanges(changes)
	lbc.processProblems(problems)

	for i := range vsrNamespaces {
		syncVSRInformerFromClient(tb, lbc, confClient, vsrNamespaces[i], vsrNames[i])
	}
}

// syncVSRInformerFromClient copies the VirtualServerRoute's current state
// (including Status, which is only ever mutated via the fake clientset) back
// into the informer store, simulating a real informer observing the
// controller's own status write. Without this, statusUpdater always reads a
// stale Status from the lister, which would mask both the bug under test and
// any regression in preserving State/Reason/Message across a referencedBy-only
// update.
func syncVSRInformerFromClient(tb testing.TB, lbc *LoadBalancerController, confClient *fake_v1.Clientset, namespace, name string) {
	tb.Helper()

	nsi := lbc.getNamespacedInformer(namespace)
	latest, err := confClient.K8sV1().VirtualServerRoutes(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		tb.Fatalf("reading VSR %s/%s from clientset: %v", namespace, name, err)
	}
	if _, exists, _ := nsi.virtualServerRouteLister.GetByKey(namespace + "/" + name); exists {
		if err := nsi.virtualServerRouteLister.Update(latest); err != nil {
			tb.Fatalf("syncing VSR informer: %v", err)
		}
	}
}

// vsrStatusTestVS returns a VS in the "default" namespace referencing the
// fixed "default/coffee" VSR built by vsrStatusTestVSR.
func vsrStatusTestVS(name, host string) *conf_v1.VirtualServer {
	return vsrStatusTestVSInNamespace("default", name, host, "default/coffee")
}

// vsrStatusTestVSInNamespace is vsrStatusTestVS with an explicit VS
// namespace, for exercising a VS that references a hostless VSR in a
// different namespace.
func vsrStatusTestVSInNamespace(namespace, name, host, vsrKey string) *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: conf_v1.VirtualServerSpec{
			IngressClass: "nginx",
			Host:         host,
			Routes: []conf_v1.Route{
				{Path: "/coffee", Route: vsrKey},
			},
		},
	}
}

// vsrStatusTestVSR returns a hostless VSR named "coffee" in the "default"
// namespace.
func vsrStatusTestVSR() *conf_v1.VirtualServerRoute {
	return vsrStatusTestVSRInNamespace("default")
}

// vsrStatusTestVSRInNamespace is vsrStatusTestVSR with an explicit
// namespace, for exercising a hostless VSR referenced cross-namespace.
func vsrStatusTestVSRInNamespace(namespace string) *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "coffee"},
		Spec: conf_v1.VirtualServerRouteSpec{
			IngressClass: "nginx",
			Host:         "",
			Subroutes: []conf_v1.Route{
				{
					Path:   "/coffee",
					Action: &conf_v1.Action{Return: &conf_v1.ActionReturn{Body: "coffee"}},
				},
			},
		},
	}
}

// TestVSRReferencedByLifecycle drives a hostless VirtualServerRoute through
// no-VS -> 1-VS -> 2-VS -> 1-VS -> no-VS and asserts that Status.ReferencedBy
// (and State/Reason) are correct after every step. The 2-VS -> 1-VS step
// (removing vs-b while vs-a still references the VSR) is the reported bug:
// nothing re-renders vs-a's config when only vs-b is deleted, so nothing used
// to refresh the VSR's stale referencedBy list.
func TestVSRReferencedByLifecycle(t *testing.T) {
	t.Parallel()
	lbc, confClient := newVSRStatusTestLBC(t)

	vsr := vsrStatusTestVSR()

	// Step 1: VSR with no VS -> orphaned.
	addVSRStatusTest(t, lbc, confClient, vsr)
	assertVSRStatus(t, confClient, "", conf_v1.StateWarning, nl.EventReasonNoVirtualServerFound)

	// Step 2: add vs-a -> referencedBy = [vs-a].
	vsA := vsrStatusTestVS("vs-a", "vs-a.example.com")
	addVSStatusTest(t, lbc, confClient, vsA, []string{"default"}, []string{"coffee"})
	assertVSRStatus(t, confClient, "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 3: add vs-b -> referencedBy = [vs-a, vs-b].
	vsB := vsrStatusTestVS("vs-b", "vs-b.example.com")
	addVSStatusTest(t, lbc, confClient, vsB, []string{"default"}, []string{"coffee"})
	assertVSRStatus(t, confClient, "default/vs-a, default/vs-b", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 4 (the bug): delete vs-b -> referencedBy must shrink back to
	// [vs-a]. vs-a's own config is untouched by this deletion, so nothing
	// re-renders it; the fix must refresh the VSR status directly.
	deleteVSStatusTest(t, lbc, confClient, "default", "vs-b", []string{"default"}, []string{"coffee"})
	assertVSRStatus(t, confClient, "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 5: delete vs-a -> VSR becomes orphaned again.
	deleteVSStatusTest(t, lbc, confClient, "default", "vs-a", []string{"default"}, []string{"coffee"})
	assertVSRStatus(t, confClient, "", conf_v1.StateWarning, nl.EventReasonNoVirtualServerFound)
}

// TestVSRReferencedByDetachWithoutDeletion covers the case
// TestVSRReferencedByLifecycle cannot: a VS is edited to stop selecting the
// hostless VSR without being deleted. rebuildHosts rewrites
// ResourceChange.Resource to the latest version of any changed resource, so
// the controller cannot recover the *old* VSR reference from the changes
// slice alone -- the fix's Configuration-level diff
// (GetVirtualServerRoutesWithChangedReferences) is the only thing that can
// detect this and drive the referencedBy refresh.
func TestVSRReferencedByDetachWithoutDeletion(t *testing.T) {
	t.Parallel()
	lbc, confClient := newVSRStatusTestLBC(t)

	vsr := vsrStatusTestVSR()
	addVSRStatusTest(t, lbc, confClient, vsr)

	vsA := vsrStatusTestVS("vs-a", "vs-a.example.com")
	addVSStatusTest(t, lbc, confClient, vsA, []string{"default"}, []string{"coffee"})

	vsB := vsrStatusTestVS("vs-b", "vs-b.example.com")
	addVSStatusTest(t, lbc, confClient, vsB, []string{"default"}, []string{"coffee"})

	assertVSRStatus(t, confClient, "default/vs-a, default/vs-b", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Edit vs-b so it no longer references the VSR at all, without deleting
	// vs-b itself.
	vsBDetached := &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vs-b"},
		Spec: conf_v1.VirtualServerSpec{
			IngressClass: "nginx",
			Host:         "vs-b.example.com",
			Routes: []conf_v1.Route{
				{Path: "/coffee", Action: &conf_v1.Action{Return: &conf_v1.ActionReturn{Body: "vs-b-local"}}},
			},
		},
	}
	updateVSStatusTest(t, lbc, confClient, vsBDetached, []string{"default"}, []string{"coffee"})

	assertVSRStatus(t, confClient, "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)
}

// TestVSRReferencedByLifecycleCrossNamespace is TestVSRReferencedByLifecycle
// with the hostless VSR and its referencing VirtualServers spread across
// three different namespaces, matching the cross-namespace hostless-VSR
// support covered at the Configuration level by
// TestHostlessVSR_CrossNamespace. referencedBy entries are sorted by VS key
// ("namespace/name"), so with vs-b in "apps-ns" and vs-a in "default", vs-b
// sorts first ("apps-ns" < "default").
func TestVSRReferencedByLifecycleCrossNamespace(t *testing.T) {
	t.Parallel()
	lbc, confClient := newVSRStatusTestLBC(t)

	vsr := vsrStatusTestVSRInNamespace("routes-ns")

	// Step 1: VSR with no VS -> orphaned.
	addVSRStatusTest(t, lbc, confClient, vsr)
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "", conf_v1.StateWarning, nl.EventReasonNoVirtualServerFound)

	// Step 2: add vs-a (namespace "default") -> referencedBy = [vs-a].
	vsA := vsrStatusTestVSInNamespace("default", "vs-a", "vs-a.example.com", "routes-ns/coffee")
	addVSStatusTest(t, lbc, confClient, vsA, []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 3: add vs-b (namespace "apps-ns") -> referencedBy = [vs-b, vs-a]
	// in sorted VS-key order.
	vsB := vsrStatusTestVSInNamespace("apps-ns", "vs-b", "vs-b.example.com", "routes-ns/coffee")
	addVSStatusTest(t, lbc, confClient, vsB, []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "apps-ns/vs-b, default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 4 (the bug, cross-namespace): delete vs-b -> referencedBy must
	// shrink back to [vs-a]. vs-a's own config (a different namespace
	// entirely) is untouched by this deletion, so nothing re-renders it; the
	// fix must refresh the VSR status directly.
	deleteVSStatusTest(t, lbc, confClient, "apps-ns", "vs-b", []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 5: delete vs-a -> VSR becomes orphaned again.
	deleteVSStatusTest(t, lbc, confClient, "default", "vs-a", []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "", conf_v1.StateWarning, nl.EventReasonNoVirtualServerFound)
}

// TestVSRReferencedByDetachWithoutDeletionCrossNamespace is
// TestVSRReferencedByDetachWithoutDeletion with the detaching VS in a
// different namespace than both the VSR and the VS that keeps referencing it.
func TestVSRReferencedByDetachWithoutDeletionCrossNamespace(t *testing.T) {
	t.Parallel()
	lbc, confClient := newVSRStatusTestLBC(t)

	vsr := vsrStatusTestVSRInNamespace("routes-ns")
	addVSRStatusTest(t, lbc, confClient, vsr)

	vsA := vsrStatusTestVSInNamespace("default", "vs-a", "vs-a.example.com", "routes-ns/coffee")
	addVSStatusTest(t, lbc, confClient, vsA, []string{"routes-ns"}, []string{"coffee"})

	vsB := vsrStatusTestVSInNamespace("apps-ns", "vs-b", "vs-b.example.com", "routes-ns/coffee")
	addVSStatusTest(t, lbc, confClient, vsB, []string{"routes-ns"}, []string{"coffee"})

	assertVSRStatusInNamespace(t, confClient, "routes-ns", "apps-ns/vs-b, default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Edit vs-b (in "apps-ns") so it no longer references the cross-namespace
	// VSR at all, without deleting vs-b itself.
	vsBDetached := &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps-ns", Name: "vs-b"},
		Spec: conf_v1.VirtualServerSpec{
			IngressClass: "nginx",
			Host:         "vs-b.example.com",
			Routes: []conf_v1.Route{
				{Path: "/coffee", Action: &conf_v1.Action{Return: &conf_v1.ActionReturn{Body: "vs-b-local"}}},
			},
		},
	}
	updateVSStatusTest(t, lbc, confClient, vsBDetached, []string{"routes-ns"}, []string{"coffee"})

	assertVSRStatusInNamespace(t, confClient, "routes-ns", "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)
}

// assertVSRStatus checks the "default/coffee" VSR, the fixed identity used by
// vsrStatusTestVSR and every same-namespace test.
func assertVSRStatus(t *testing.T, confClient *fake_v1.Clientset, wantReferencedBy, wantState, wantReason string) {
	t.Helper()
	assertVSRStatusInNamespace(t, confClient, "default", wantReferencedBy, wantState, wantReason)
}

// assertVSRStatusInNamespace is assertVSRStatus with an explicit VSR
// namespace, for cross-namespace tests. The VSR name is always "coffee", the
// fixed identity used by vsrStatusTestVSR/vsrStatusTestVSRInNamespace.
func assertVSRStatusInNamespace(t *testing.T, confClient *fake_v1.Clientset, namespace, wantReferencedBy, wantState, wantReason string) {
	t.Helper()

	got, err := confClient.K8sV1().VirtualServerRoutes(namespace).Get(context.TODO(), "coffee", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading VSR status: %v", err)
	}

	if got.Status.ReferencedBy != wantReferencedBy {
		t.Errorf("ReferencedBy = %q, want %q", got.Status.ReferencedBy, wantReferencedBy)
	}
	if got.Status.State != wantState {
		t.Errorf("State = %q, want %q", got.Status.State, wantState)
	}
	if got.Status.Reason != wantReason {
		t.Errorf("Reason = %q, want %q", got.Status.Reason, wantReason)
	}
}
