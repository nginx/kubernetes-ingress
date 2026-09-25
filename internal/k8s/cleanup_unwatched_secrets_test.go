package k8s

import (
	"context"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	"k8s.io/client-go/tools/cache"
)

// TestCleanupUnwatchedNamespacedResourcesWithSecretsDisabled covers a namespace
// watched for resources but not for Secrets. It has no Secrets informer, so its
// secretLister is unset and cleanup must skip the Secrets work, as it already
// does for App Protect.
func TestCleanupUnwatchedNamespacedResourcesWithSecretsDisabled(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		Logger:       nl.LoggerFromContext(context.Background()),
		configurator: createTestPolicySyncConfigurator(t, nginx.NewFakeManager("/etc/nginx")),
		secretStore:  secrets.NewEmptyFakeSecretsStore(),
	}

	nsi := &namespacedInformer{
		namespace: "watched-but-no-secrets",
		stopCh:    make(chan struct{}), // cleanup stops the group when done
		ingressLister: storeToIngressLister{Store: &cache.FakeCustomStore{
			ListFunc: func() []interface{} { return nil },
		}},
		// no Secrets informer, so the lister was never assigned
		isSecretsEnabledNamespace: false,
		secretLister:              nil,
		areCustomResourcesEnabled: false,
	}

	lbc.cleanupUnwatchedNamespacedResources(nsi)
}
