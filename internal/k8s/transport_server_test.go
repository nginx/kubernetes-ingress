package k8s

import (
	"context"
	"testing"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// TestSyncTransportServerNamespaceNotWatched guards against a nil pointer dereference
// panic (see getNamespacedInformer) when a TransportServer task for a namespace that is
// no longer watched (e.g. its watch-namespace-label was removed) is processed.
func TestSyncTransportServerNamespaceNotWatched(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		namespacedInformers: map[string]*namespacedInformer{},
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	lbc.syncTransportServer(task{Kind: transportserver, Key: "not-watched/some-transportserver"})
}
