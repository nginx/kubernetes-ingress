package k8s

import (
	"context"
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
