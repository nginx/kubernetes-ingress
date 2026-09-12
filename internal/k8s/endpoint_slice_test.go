package k8s

import (
	"context"
	"testing"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// TestSyncEndpointSlicesNamespaceNotWatched guards against a nil pointer dereference
// panic (see getNamespacedInformer) when an EndpointSlice task for a namespace that is
// no longer watched (e.g. its watch-namespace-label was removed) is processed.
func TestSyncEndpointSlicesNamespaceNotWatched(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		namespacedInformers: map[string]*namespacedInformer{},
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	result := lbc.syncEndpointSlices(task{Kind: endpointslice, Key: "not-watched/some-endpointslice"})
	if result {
		t.Errorf("syncEndpointSlices() = %v, expected false for an unwatched namespace", result)
	}
}
