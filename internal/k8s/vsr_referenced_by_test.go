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

// newVSRStatusTestLBC registers the informer under the "" key, which getNamespacedInformer treats as global (matches any namespace).
// isNginxReady is true from the start, so status writes bypass the startup-pending path.
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

// Sync status into the fake informer so stale lister reads cannot mask a regression.
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

func vsrStatusTestVS(name, host string) *conf_v1.VirtualServer {
	return vsrStatusTestVSInNamespace("default", name, host, "default/coffee")
}

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

func vsrStatusTestVSR() *conf_v1.VirtualServerRoute {
	return vsrStatusTestVSRInNamespace("default")
}

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

// TestVSRReferencedByLifecycle checks reference status as VSs are added and removed.
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

	// Step 4: delete vs-b; vs-a is not re-rendered, but referencedBy must shrink.
	deleteVSStatusTest(t, lbc, confClient, "default", "vs-b", []string{"default"}, []string{"coffee"})
	assertVSRStatus(t, confClient, "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 5: delete vs-a -> VSR becomes orphaned again.
	deleteVSStatusTest(t, lbc, confClient, "default", "vs-a", []string{"default"}, []string{"coffee"})
	assertVSRStatus(t, confClient, "", conf_v1.StateWarning, nl.EventReasonNoVirtualServerFound)
}

// TestVSRReferencedByDetachWithoutDeletion: rebuildHosts rewrites ResourceChange to the latest VS version, so only the reverse-index diff (not the changes slice) can detect the dropped reference.
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

	// Update vs-b so it no longer references the VSR.
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

// TestVSRReferencedByLifecycleCrossNamespace checks reference status across namespaces.
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

	// Step 3: add vs-b (namespace "apps-ns") -> referencedBy = [vs-b, vs-a] in sorted VS-key order.
	vsB := vsrStatusTestVSInNamespace("apps-ns", "vs-b", "vs-b.example.com", "routes-ns/coffee")
	addVSStatusTest(t, lbc, confClient, vsB, []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "apps-ns/vs-b, default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 4: delete vs-b; vs-a is not re-rendered, but referencedBy must shrink.
	deleteVSStatusTest(t, lbc, confClient, "apps-ns", "vs-b", []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "default/vs-a", conf_v1.StateValid, nl.EventReasonAddedOrUpdated)

	// Step 5: delete vs-a -> VSR becomes orphaned again.
	deleteVSStatusTest(t, lbc, confClient, "default", "vs-a", []string{"routes-ns"}, []string{"coffee"})
	assertVSRStatusInNamespace(t, confClient, "routes-ns", "", conf_v1.StateWarning, nl.EventReasonNoVirtualServerFound)
}

// TestVSRReferencedByDetachWithoutDeletionCrossNamespace checks detachment across namespaces.
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

	// Update vs-b so it no longer references the VSR.
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

func assertVSRStatus(t *testing.T, confClient *fake_v1.Clientset, wantReferencedBy, wantState, wantReason string) {
	t.Helper()
	assertVSRStatusInNamespace(t, confClient, "default", wantReferencedBy, wantState, wantReason)
}

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
