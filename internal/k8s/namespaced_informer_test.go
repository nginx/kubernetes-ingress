package k8s

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	k8s_nginx_fake "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// TestNewLoadBalancerControllerWatchesSecretNamespaces checks which Secrets the
// controller sees for each way -watch-namespace and -watch-secret-namespace
// combine.
func TestNewLoadBalancerControllerWatchesSecretNamespaces(t *testing.T) {
	t.Parallel()

	allNamespaces := []string{"ns-a", "ns-b", "ns-c"}

	tests := []struct {
		name             string
		namespaces       []string // -watch-namespace, where "" is every namespace
		secretNamespaces []string // -watch-secret-namespace, which defaults to namespaces
		wantWatched      []string
	}{
		{
			name:             "all namespaces",
			namespaces:       []string{""},
			secretNamespaces: []string{""},
			wantWatched:      allNamespaces,
		},
		{
			name:             "all namespaces, secrets in listed namespaces",
			namespaces:       []string{""},
			secretNamespaces: []string{"ns-a", "ns-b"},
			wantWatched:      []string{"ns-a", "ns-b"},
		},
		{
			name:             "listed namespaces, secrets in listed namespaces",
			namespaces:       []string{"ns-a", "ns-c"},
			secretNamespaces: []string{"ns-a", "ns-b"},
			wantWatched:      []string{"ns-a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var objs []runtime.Object
			for _, ns := range allNamespaces {
				objs = append(objs, &api_v1.Secret{ObjectMeta: meta_v1.ObjectMeta{Name: "tls-secret", Namespace: ns}})
			}
			lbc := NewLoadBalancerController(NewLoadBalancerControllerInput{
				KubeClient:      fake.NewClientset(objs...),
				LoggerContext:   context.Background(),
				Namespace:       tc.namespaces,
				SecretNamespace: tc.secretNamespaces,
			})
			startNamespacedInformers(t, lbc)
			lbc.preSyncSecrets()

			store := lbc.secretStore.(*secrets.LocalSecretStore)
			for _, ns := range allNamespaces {
				key := ns + "/tls-secret"
				want := slices.Contains(tc.wantWatched, ns)
				if got := store.HoldsSecret(key); got != want {
					t.Errorf("HoldsSecret(%q) after preSyncSecrets = %t, want %t", key, got, want)
				}
				if _, err := lbc.getSecret(key); (err == nil) != want {
					t.Errorf("getSecret(%q) error = %v, want found = %t", key, err, want)
				}
			}
		})
	}
}

// startNamespacedInformers starts every informer group of lbc, as Run does, and
// waits for their caches to sync. The groups are stopped when the test ends.
func startNamespacedInformers(t *testing.T, lbc *LoadBalancerController) {
	t.Helper()

	var cacheSyncs []cache.InformerSynced
	lbc.namespacedInformers.ForEach(func(nsi *namespacedInformer) {
		nsi.start()
		t.Cleanup(nsi.stop)
		cacheSyncs = append(cacheSyncs, nsi.cacheSyncs...)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if !cache.WaitForCacheSync(ctx.Done(), cacheSyncs...) {
		t.Fatal("informer caches did not sync")
	}
}

// TestSyncNamespaceUnwatchesNamespaceWithoutSecrets drives the label-removed
// branch of syncNamespace for a namespace left out of -watch-secret-namespace,
// so its informer group has no Secret lister. Cleaning it up used to dereference
// that nil lister and crash the controller.
func TestSyncNamespaceUnwatchesNamespaceWithoutSecrets(t *testing.T) {
	t.Parallel()

	lbc := newBatchTestLBC(t, newSecretReconciliationNginxManager())
	lbc.client = fake.NewClientset(&api_v1.Namespace{
		ObjectMeta: meta_v1.ObjectMeta{Name: "app-ns"},
		Status:     api_v1.NamespaceStatus{Phase: api_v1.NamespaceActive},
	})
	lbc.secretNamespaceList = []string{"secrets-ns"}
	// Empty: "app-ns" still exists but lost the watch label.
	lbc.namespaceLabeledLister = cache.NewStore(cache.MetaNamespaceKeyFunc)
	if _, err := lbc.newNamespacedInformer("app-ns"); err != nil {
		t.Fatalf("newNamespacedInformer(\"app-ns\") returned error: %v", err)
	}

	lbc.syncNamespace(task{Key: "app-ns"})

	if got := lbc.namespacedInformers.Get("app-ns"); got != nil {
		t.Errorf("namespacedInformers.Get(\"app-ns\") after the watch label was removed = %v, want nil", got)
	}
}

func TestAddCustomResourceHandlers_Disabled(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{areCustomResourcesEnabled: false}
	nsi := &namespacedInformer{}

	err := lbc.addCustomResourceHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when custom resources disabled, got %v", err)
	}
	if nsi.areCustomResourcesEnabled {
		t.Error("expected nsi.areCustomResourcesEnabled to remain false")
	}
	if nsi.confSharedInformerFactory != nil {
		t.Error("expected nsi.confSharedInformerFactory to remain nil")
	}
	if len(nsi.cacheSyncs) != 0 {
		t.Errorf("expected no cacheSyncs when disabled, got %d", len(nsi.cacheSyncs))
	}
}

func TestAddCustomResourceHandlers_Enabled(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{
		areCustomResourcesEnabled: true,
		confClient:                k8s_nginx_fake.NewSimpleClientset(),
		Logger:                    nl.LoggerFromContext(context.Background()),
	}
	nsi := &namespacedInformer{}

	err := lbc.addCustomResourceHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when custom resources enabled, got %v", err)
	}
	if !nsi.areCustomResourcesEnabled {
		t.Error("expected nsi.areCustomResourcesEnabled to be true")
	}
	if nsi.confSharedInformerFactory == nil {
		t.Error("expected nsi.confSharedInformerFactory to be set")
	}
	// VS, VSR, TransportServer, Policy
	const wantCacheSyncs = 4
	if len(nsi.cacheSyncs) != wantCacheSyncs {
		t.Errorf("expected %d cacheSyncs, got %d", wantCacheSyncs, len(nsi.cacheSyncs))
	}

	if nsi.policySecretIndexer == nil {
		t.Fatal("expected Policy Secret indexer to be configured")
	}
	if _, exists := nsi.policySecretIndexer.GetIndexers()[policySecretIndex]; !exists {
		t.Errorf("expected %q index to be registered", policySecretIndex)
	}
}

func TestAddAppProtectHandlers_Disabled(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{
		appProtectEnabled:    false,
		appProtectDosEnabled: false,
	}
	nsi := &namespacedInformer{}

	err := lbc.addAppProtectHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when app protect disabled, got %v", err)
	}
	if nsi.appProtectEnabled {
		t.Error("expected nsi.appProtectEnabled to remain false")
	}
	if nsi.appProtectDosEnabled {
		t.Error("expected nsi.appProtectDosEnabled to remain false")
	}
	if nsi.dynInformerFactory != nil {
		t.Error("expected nsi.dynInformerFactory to remain nil")
	}
	if len(nsi.cacheSyncs) != 0 {
		t.Errorf("expected no cacheSyncs when disabled, got %d", len(nsi.cacheSyncs))
	}
}

func TestAddAppProtectHandlers_AppProtectEnabled(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{
		appProtectEnabled:    true,
		appProtectDosEnabled: false,
		dynClient:            dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		Logger:               nl.LoggerFromContext(context.Background()),
	}
	nsi := &namespacedInformer{}

	err := lbc.addAppProtectHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when app protect enabled, got %v", err)
	}
	if !nsi.appProtectEnabled {
		t.Error("expected nsi.appProtectEnabled to be true")
	}
	if nsi.appProtectDosEnabled {
		t.Error("expected nsi.appProtectDosEnabled to remain false")
	}
	if nsi.dynInformerFactory == nil {
		t.Error("expected nsi.dynInformerFactory to be set")
	}
	// Policy, LogConf, UserSig
	const wantCacheSyncs = 3
	if len(nsi.cacheSyncs) != wantCacheSyncs {
		t.Errorf("expected %d cacheSyncs for app protect, got %d", wantCacheSyncs, len(nsi.cacheSyncs))
	}
}

func TestAddAppProtectHandlers_PLMEnabled(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{
		appProtectEnabled:    true,
		appProtectDosEnabled: false,
		plmEnabled:           true,
		dynClient:            dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		Logger:               nl.LoggerFromContext(context.Background()),
	}
	nsi := &namespacedInformer{}

	err := lbc.addAppProtectHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when PLM is enabled, got %v", err)
	}
	if !nsi.appProtectEnabled {
		t.Error("expected nsi.appProtectEnabled to be true")
	}
	// PLM compiles APUserSig content into bundles. NIC must not register the
	// legacy raw-user-signature handler, which would write nac-usersigs files.
	const wantCacheSyncs = 2 // Policy, LogConf
	if len(nsi.cacheSyncs) != wantCacheSyncs {
		t.Errorf("expected %d cacheSyncs for PLM app protect, got %d", wantCacheSyncs, len(nsi.cacheSyncs))
	}
}

func TestAddAppProtectHandlers_AppProtectDosEnabled(t *testing.T) {
	t.Parallel()
	fakeVsClient := k8s_nginx_fake.NewSimpleClientset()
	lbc := &LoadBalancerController{
		appProtectEnabled:         false,
		appProtectDosEnabled:      true,
		areCustomResourcesEnabled: true,
		confClient:                fakeVsClient,
		dynClient:                 dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		Logger:                    nl.LoggerFromContext(context.Background()),
	}
	nsi := &namespacedInformer{}

	// addAppProtectDosProtectedResourceHandler depends on confSharedInformerFactory
	// which is set by addCustomResourceHandlers — mirror the production call order.
	if err := lbc.addCustomResourceHandlers(nsi, "test-ns"); err != nil {
		t.Fatalf("addCustomResourceHandlers failed: %v", err)
	}
	initialCacheSyncs := len(nsi.cacheSyncs)

	err := lbc.addAppProtectHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when app protect dos enabled, got %v", err)
	}
	if nsi.appProtectEnabled {
		t.Error("expected nsi.appProtectEnabled to remain false")
	}
	if !nsi.appProtectDosEnabled {
		t.Error("expected nsi.appProtectDosEnabled to be true")
	}
	if nsi.dynInformerFactory == nil {
		t.Error("expected nsi.dynInformerFactory to be set")
	}
	// DosPolicy, DosLogConf, DosProtectedResource
	const wantAdditionalCacheSyncs = 3
	if got := len(nsi.cacheSyncs) - initialCacheSyncs; got != wantAdditionalCacheSyncs {
		t.Errorf("expected %d additional cacheSyncs for app protect dos, got %d", wantAdditionalCacheSyncs, got)
	}
}

func TestAddAppProtectHandlers_BothEnabled(t *testing.T) {
	t.Parallel()
	fakeVsClient := k8s_nginx_fake.NewSimpleClientset()
	lbc := &LoadBalancerController{
		appProtectEnabled:         true,
		appProtectDosEnabled:      true,
		areCustomResourcesEnabled: true,
		confClient:                fakeVsClient,
		dynClient:                 dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		Logger:                    nl.LoggerFromContext(context.Background()),
	}
	nsi := &namespacedInformer{}

	// addAppProtectDosProtectedResourceHandler depends on confSharedInformerFactory
	// which is set by addCustomResourceHandlers — mirror the production call order.
	if err := lbc.addCustomResourceHandlers(nsi, "test-ns"); err != nil {
		t.Fatalf("addCustomResourceHandlers failed: %v", err)
	}
	initialCacheSyncs := len(nsi.cacheSyncs)

	err := lbc.addAppProtectHandlers(nsi, "test-ns")
	if err != nil {
		t.Errorf("expected nil error when both app protect features enabled, got %v", err)
	}
	if !nsi.appProtectEnabled {
		t.Error("expected nsi.appProtectEnabled to be true")
	}
	if !nsi.appProtectDosEnabled {
		t.Error("expected nsi.appProtectDosEnabled to be true")
	}
	// Policy, LogConf, UserSig + DosPolicy, DosLogConf, DosProtectedResource
	const wantAdditionalCacheSyncs = 6
	if got := len(nsi.cacheSyncs) - initialCacheSyncs; got != wantAdditionalCacheSyncs {
		t.Errorf("expected %d additional cacheSyncs when both enabled, got %d", wantAdditionalCacheSyncs, got)
	}
}
