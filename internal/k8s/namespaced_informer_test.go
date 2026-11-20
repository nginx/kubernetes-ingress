package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nsregistry"
	k8s_nginx_fake "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	networking "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

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

func newTestWatchErrorTracker() (*watchErrorTracker, *bytes.Buffer) {
	var buf bytes.Buffer
	return newWatchErrorTracker(slog.New(slog.NewTextHandler(&buf, nil))), &buf
}

func newTestReflector() *cache.Reflector {
	return cache.NewReflector(&cache.ListWatch{}, &networking.Ingress{}, cache.NewStore(cache.MetaNamespaceKeyFunc), 0)
}

func forbiddenListError(gr schema.GroupResource, namespace string) error {
	return k8serrors.NewForbidden(gr, "", errors.New(`User "system:serviceaccount:`+namespace+`:nic" cannot list resource`))
}

func TestWatchErrorTrackerLogsForbiddenOnce(t *testing.T) {
	t.Parallel()

	tracker, buf := newTestWatchErrorTracker()
	gr := networking.Resource("ingresses")
	handler := tracker.handler(gr, "team-a-apps")
	reflector := newTestReflector()

	for range 3 {
		handler(context.Background(), reflector, forbiddenListError(gr, "team-a-apps"))
	}

	got := buf.String()
	if n := strings.Count(got, "missing permission"); n != 1 {
		t.Fatalf("logged %d missing permission errors, want 1; log:\n%s", n, got)
	}
	want := "missing permission: list and watch ingresses.networking.k8s.io in namespace team-a-apps"
	if !strings.Contains(got, want) {
		t.Errorf("log does not contain %q; log:\n%s", want, got)
	}
	if !strings.Contains(got, "level=ERROR") {
		t.Errorf("log is not at error level; log:\n%s", got)
	}
}

func TestWatchErrorTrackerSeparatesResourcesAndNamespaces(t *testing.T) {
	t.Parallel()

	tracker, buf := newTestWatchErrorTracker()
	ingresses := networking.Resource("ingresses")
	services := schema.GroupResource{Resource: "services"}
	reflector := newTestReflector()

	tracker.handler(ingresses, "team-a")(context.Background(), reflector, forbiddenListError(ingresses, "team-a"))
	tracker.handler(ingresses, "team-a-apps")(context.Background(), reflector, forbiddenListError(ingresses, "team-a-apps"))
	tracker.handler(services, "team-a")(context.Background(), reflector, forbiddenListError(services, "team-a"))
	tracker.handler(ingresses, "")(context.Background(), reflector, forbiddenListError(ingresses, ""))

	got := buf.String()
	for _, want := range []string{
		"list and watch ingresses.networking.k8s.io in namespace team-a;",
		"list and watch ingresses.networking.k8s.io in namespace team-a-apps;",
		"list and watch services in namespace team-a;",
		"list and watch ingresses.networking.k8s.io in all namespaces;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log does not contain %q; log:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "missing permission"); n != 4 {
		t.Errorf("logged %d missing permission errors, want 4; log:\n%s", n, got)
	}
}

func TestWatchErrorTrackerReportsAgainAfterSuccessfulList(t *testing.T) {
	t.Parallel()

	state := &watchErrorState{}

	tests := []struct {
		resourceVersion string
		want            bool
	}{
		{resourceVersion: "", want: true},     // first forbidden error
		{resourceVersion: "", want: false},    // retry, still forbidden
		{resourceVersion: "100", want: true},  // a list succeeded in between, then forbidden again
		{resourceVersion: "100", want: false}, // retry, still forbidden
		{resourceVersion: "250", want: true},  // another successful list, then forbidden again
	}
	for i, test := range tests {
		if got := state.shouldReport(test.resourceVersion); got != test.want {
			t.Errorf("call %d: shouldReport(%q) = %v, want %v", i, test.resourceVersion, got, test.want)
		}
	}
}

// TestWatchErrorTrackerNewHandlerReportsAgain pins the behavior that replaces
// explicit cleanup: each call to handler() gets its own report state, so a
// replacement informer for the same resource and namespace (for example, a
// namespace that is unwatched and watched again) reports its own forbidden
// error instead of being suppressed by the old informer's history.
func TestWatchErrorTrackerNewHandlerReportsAgain(t *testing.T) {
	t.Parallel()

	tracker, buf := newTestWatchErrorTracker()
	gr := networking.Resource("ingresses")
	reflector := newTestReflector()

	first := tracker.handler(gr, "team-a")
	first(context.Background(), reflector, forbiddenListError(gr, "team-a"))
	first(context.Background(), reflector, forbiddenListError(gr, "team-a")) // suppressed by first's own state

	second := tracker.handler(gr, "team-a")
	second(context.Background(), reflector, forbiddenListError(gr, "team-a"))

	if n := strings.Count(buf.String(), "missing permission"); n != 2 {
		t.Errorf("logged %d missing permission errors, want 2 (one per handler); log:\n%s", n, buf.String())
	}
}

func TestWatchErrorTrackerIgnoresOtherErrors(t *testing.T) {
	t.Parallel()

	tracker, buf := newTestWatchErrorTracker()
	gr := networking.Resource("ingresses")
	handler := tracker.handler(gr, "team-a")
	reflector := newTestReflector()

	handler(context.Background(), reflector, k8serrors.NewInternalError(errors.New("etcd unavailable")))
	handler(context.Background(), reflector, k8serrors.NewUnauthorized("token expired"))

	if got := buf.String(); got != "" {
		t.Errorf("tracker logged non-forbidden errors; log:\n%s", got)
	}
}

func TestWatchErrorTrackerNilIsNoop(t *testing.T) {
	t.Parallel()

	var tracker *watchErrorTracker
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &networking.Ingress{}, 0, cache.Indexers{})
	if err := tracker.setWatchErrorHandler(informer, networking.Resource("ingresses"), "team-a"); err != nil {
		t.Errorf("setWatchErrorHandler() on nil tracker returned %v, want nil", err)
	}
}

// syncBuffer is a bytes.Buffer that is safe for concurrent writes from informer goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNamespacedInformerLogsForbiddenList runs a real namespaced informer against a
// fake clientset that forbids listing Ingresses, and checks that the forbidden error
// is logged once with the missing permission while the informer keeps retrying.
func TestNamespacedInformerLogsForbiddenList(t *testing.T) {
	t.Parallel()

	var ingressLists atomic.Int32
	client := fake.NewClientset()
	client.PrependReactor("list", "ingresses", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ingressLists.Add(1)
		return true, nil, k8serrors.NewForbidden(networking.Resource("ingresses"), "",
			fmt.Errorf(`User "system:serviceaccount:team-a:nic" cannot list resource "ingresses" in API group "networking.k8s.io" in the namespace %q`, action.GetNamespace()))
	})

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	lbc := &LoadBalancerController{
		client:              client,
		Logger:              logger,
		watchErrors:         newWatchErrorTracker(logger),
		namespacedInformers: nsregistry.New[namespacedInformer](),
		syncQueue:           newTaskQueue(logger, func(task) {}),
	}

	nsi, err := lbc.newNamespacedInformer("team-a-apps")
	if err != nil {
		t.Fatalf("newNamespacedInformer() returned error: %v", err)
	}
	nsi.start()
	t.Cleanup(nsi.stop)

	// The reflector retries with backoff starting at 800ms; wait for at least one retry.
	if !assert.Eventually(t, func() bool { return ingressLists.Load() >= 2 }, 10*time.Second, 50*time.Millisecond) {
		t.Fatalf("informer listed Ingresses %d times, want at least 2", ingressLists.Load())
	}

	got := buf.String()
	want := "missing permission: list and watch ingresses.networking.k8s.io in namespace team-a-apps"
	if n := strings.Count(got, want); n != 1 {
		t.Errorf("logged %q %d times, want 1; log:\n%s", want, n, got)
	}
	if n := strings.Count(got, "missing permission"); n != 1 {
		t.Errorf("logged %d missing permission errors, want 1 (only Ingresses are forbidden); log:\n%s", n, got)
	}
}
