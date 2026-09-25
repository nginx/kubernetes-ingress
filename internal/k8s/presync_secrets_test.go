package k8s

import (
	"context"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func secretListerForNamespace(ns string) *fakeStore {
	return &fakeStore{cache.FakeCustomStore{
		ListFunc: func() []interface{} {
			return []interface{}{
				&api_v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{Name: "tls-secret", Namespace: ns},
					Type:       api_v1.SecretTypeTLS,
				},
			}
		},
	}}
}

// TestPreSyncSecretsLoadsEverySecretsEnabledNamespace covers a deployment using
// -watch-secret-namespace to watch a narrower set of namespaces for Secrets
// than for other resources, so some informer groups have secrets disabled.
//
// Every namespace that does have secrets enabled must be preloaded regardless
// of the order iteration happens to yield them in. Go randomizes map iteration
// order per run, so this repeats to catch an order-dependent regression rather
// than passing on a lucky ordering.
func TestPreSyncSecretsLoadsEverySecretsEnabledNamespace(t *testing.T) {
	t.Parallel()

	const runs = 50

	for i := 0; i < runs; i++ {
		lbc := LoadBalancerController{
			secretStore: secrets.NewEmptyFakeSecretsStore(),
			Logger:      nl.LoggerFromContext(context.Background()),
			namespacedInformers: map[string]*namespacedInformer{
				"no-secrets": {
					namespace:                 "no-secrets",
					isSecretsEnabledNamespace: false,
					secretLister:              secretListerForNamespace("no-secrets"),
				},
				"ns-a": {
					namespace:                 "ns-a",
					isSecretsEnabledNamespace: true,
					secretLister:              secretListerForNamespace("ns-a"),
				},
				"ns-b": {
					namespace:                 "ns-b",
					isSecretsEnabledNamespace: true,
					secretLister:              secretListerForNamespace("ns-b"),
				},
			},
		}

		lbc.preSyncSecrets()

		loaded := lbc.secretStore.(*secrets.FakeSecretStore).GetSecretReferenceMap()
		for _, key := range []string{"ns-a/tls-secret", "ns-b/tls-secret"} {
			if _, ok := loaded[key]; !ok {
				t.Fatalf("run %d: Secret %q was not preloaded; got %d secrets", i, key, len(loaded))
			}
		}
		if _, ok := loaded["no-secrets/tls-secret"]; ok {
			t.Fatalf("run %d: preloaded a Secret from a namespace with secrets disabled", i)
		}
	}
}
