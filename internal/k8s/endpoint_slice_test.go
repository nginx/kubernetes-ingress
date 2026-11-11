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
		namespacedInformers: registryFrom(map[string]*namespacedInformer{}),
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	// The assertion is that this doesn't panic; getNamespacedInformer returning nil
	// for an unwatched namespace must take syncEndpointSlices's early return.
	lbc.syncEndpointSlices(task{Kind: endpointslice, Key: "not-watched/some-endpointslice"})
}
