package certmanager

import (
	"context"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/nsregistry"
	vsapi "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// The registry itself is covered by internal/nsregistry. These cover how this
// controller uses it.

// TestSyncFnSkipsUnwatchedNamespace covers a VirtualServer whose namespace
// stopped being watched between the item being queued and it being processed.
// The lookup reports the namespace unwatched, and nothing is dereferenced.
func TestSyncFnSkipsUnwatchedNamespace(t *testing.T) {
	t.Parallel()

	vs := &vsapi.VirtualServer{
		ObjectMeta: v1.ObjectMeta{Namespace: "not-watched", Name: "test-vs"},
		Spec: vsapi.VirtualServerSpec{
			TLS: &vsapi.TLS{
				Secret:      "test-secret",
				CertManager: &vsapi.CertManager{Issuer: "test-issuer"},
			},
		},
	}

	sync := SyncFnFor(&record.FakeRecorder{}, nil, nsregistry.New[namespacedInformer]())

	if err := sync(context.Background(), vs); err != nil {
		t.Errorf("sync for an unwatched namespace returned %v, want nil", err)
	}
}

// TestProcessItemSkipsUnwatchedNamespace covers the same case on the queue
// worker's own lookup.
func TestProcessItemSkipsUnwatchedNamespace(t *testing.T) {
	t.Parallel()

	c := &CmController{
		ctx:           context.Background(),
		informerGroup: nsregistry.New[namespacedInformer](),
	}

	key := types.NamespacedName{Namespace: "not-watched", Name: "test-vs"}
	if err := c.processItem(context.Background(), key); err != nil {
		t.Errorf("processItem for an unwatched namespace returned %v, want nil", err)
	}
}

// TestRemoveNamespacedInformerUnregistersAndStops checks that removal both
// unregisters the group and stops it. The ordering between the two is enforced
// by the API rather than by this test: Remove returns the group, so there is
// nothing to stop until it has already been unregistered.
func TestRemoveNamespacedInformerUnregistersAndStops(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{stopCh: make(chan struct{})}
	c := &CmController{
		ctx:           context.Background(),
		informerGroup: nsregistry.New[namespacedInformer](),
	}
	c.informerGroup.Set("doomed", nsi)

	c.RemoveNamespacedInformer("doomed")

	if got := c.informerGroup.Get("doomed"); got != nil {
		t.Errorf("Get after RemoveNamespacedInformer = %v, want nil", got)
	}
	select {
	case <-nsi.stopCh:
		// stopped, as expected
	default:
		t.Error("informer was unregistered but never stopped")
	}
}
