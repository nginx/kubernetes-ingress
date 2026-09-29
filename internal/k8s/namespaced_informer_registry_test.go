package k8s

import (
	"context"
	"sync"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/nsregistry"
	"k8s.io/client-go/kubernetes/fake"
)

// registryFrom builds a registry pre-populated from m. Tests construct informer
// groups as a plain map for readability; the controller itself always builds the
// registry empty and fills it via Set.
func registryFrom(m map[string]*namespacedInformer) *nsregistry.Registry[namespacedInformer] {
	r := nsregistry.New[namespacedInformer]()
	for ns, nsi := range m {
		r.Set(ns, nsi)
	}
	return r
}

// TestStatusUpdaterSharesControllerRegistry pins the invariant the whole
// registry depends on: the controller and its statusUpdater must hold the same
// instance. Were statusUpdater given its own, every namespace would resolve as
// unwatched on the status path and status updates would stop without any error.
func TestStatusUpdaterSharesControllerRegistry(t *testing.T) {
	t.Parallel()

	lbc := NewLoadBalancerController(NewLoadBalancerControllerInput{
		KubeClient:    fake.NewClientset(),
		LoggerContext: context.Background(),
	})

	if lbc.namespacedInformers == nil {
		t.Fatal("controller registry is nil")
	}
	if lbc.statusUpdater.namespacedInformers != lbc.namespacedInformers {
		t.Error("statusUpdater holds a different registry than the controller; they must share one instance")
	}
}

// TestRemoveNamespacedInformerUnregistersAndStops checks that removal both
// unregisters the group and stops it. The ordering between the two is enforced
// by the API rather than by this test: Remove returns the group, so there is
// nothing to stop until it has already been unregistered.
func TestRemoveNamespacedInformerUnregistersAndStops(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{namespace: "doomed", stopCh: make(chan struct{})}
	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"doomed": nsi}),
	}

	lbc.removeNamespacedInformer("doomed")

	if got := lbc.namespacedInformers.Get("doomed"); got != nil {
		t.Errorf("Get after removeNamespacedInformer = %v, want nil", got)
	}
	select {
	case <-nsi.stopCh:
		// stopped, as expected
	default:
		t.Error("informer was unregistered but never stopped")
	}
}

// TestUnwatchNamespaceCleansUpBeforeUnregistering pins the ordering the WAF and
// DoS fan-out depends on. Cleanup resolves dependants through getAllPolicies,
// which walks the registry, so unregistering first would hide this namespace's
// Policy CRs and leave VirtualServers elsewhere that reference them stale.
func TestUnwatchNamespaceCleansUpBeforeUnregistering(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{namespace: "unlabelled", stopCh: make(chan struct{})}
	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"unlabelled": nsi}),
	}

	var (
		cleanupCalls         int
		registeredAtCleanup  bool
		stoppedBeforeCleanup bool
	)
	lbc.unwatchNamespace("unlabelled", func(got *namespacedInformer) {
		cleanupCalls++
		if got != nsi {
			t.Errorf("cleanup got informer %v, want %v", got, nsi)
		}
		registeredAtCleanup = lbc.namespacedInformers.Get("unlabelled") == nsi
		select {
		case <-nsi.stopCh:
			stoppedBeforeCleanup = true
		default:
		}
	})

	if cleanupCalls != 1 {
		t.Errorf("cleanup called %d times, want 1", cleanupCalls)
	}
	if !registeredAtCleanup {
		t.Error("namespace was already unregistered during cleanup; WAF policy fan-out cannot see its Policy CRs")
	}
	if stoppedBeforeCleanup {
		t.Error("informer was stopped before cleanup ran")
	}
	if got := lbc.namespacedInformers.Get("unlabelled"); got != nil {
		t.Errorf("Get after unwatchNamespace = %v, want nil", got)
	}
	select {
	case <-nsi.stopCh:
		// stopped, as expected
	default:
		t.Error("informer was cleaned up but never stopped")
	}
}

// TestUnwatchNamespaceSkipsUnwatchedNamespace checks an unwatched key is a no-op
// rather than a nil cleanup call.
func TestUnwatchNamespaceSkipsUnwatchedNamespace(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{}),
	}

	lbc.unwatchNamespace("never-watched", func(*namespacedInformer) {
		t.Error("cleanup ran for a namespace that was never watched")
	})
}

// TestNamespacedInformerStopIsIdempotent covers shutdown: Stop sweeps every
// registered group while the sync queue worker may be unregistering one, so both
// can reach the same group. A second close of stopCh would panic.
func TestNamespacedInformerStopIsIdempotent(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{namespace: "ns", stopCh: make(chan struct{})}

	nsi.stop()
	nsi.stop()

	select {
	case <-nsi.stopCh:
	default:
		t.Error("stopCh was not closed")
	}
}

// TestStopRacesWithNamespaceRemoval reproduces the shutdown interleaving under
// -race: Stop's sweep and removeNamespacedInformer can target the same group.
func TestStopRacesWithNamespaceRemoval(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{
			"a": {namespace: "a", stopCh: make(chan struct{})},
			"b": {namespace: "b", stopCh: make(chan struct{})},
		}),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		lbc.namespacedInformers.ForEach(func(nsi *namespacedInformer) {
			nsi.stop()
		})
	}()
	go func() {
		defer wg.Done()
		lbc.removeNamespacedInformer("a")
	}()
	wg.Wait()
}
