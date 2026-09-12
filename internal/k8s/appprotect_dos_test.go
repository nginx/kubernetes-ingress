package k8s

import (
	"context"
	"testing"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// TestAppProtectDosSyncNamespaceNotWatched guards against a nil pointer dereference
// panic (see getNamespacedInformer) when an AppProtectDos-related task for a namespace
// that is no longer watched (e.g. its watch-namespace-label was removed) is processed.
func TestAppProtectDosSyncNamespaceNotWatched(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sync func(lbc *LoadBalancerController, key string)
	}{
		{
			name: "AppProtectDosPolicy",
			sync: func(lbc *LoadBalancerController, key string) {
				lbc.syncAppProtectDosPolicy(task{Kind: appProtectDosPolicy, Key: key})
			},
		},
		{
			name: "AppProtectDosLogConf",
			sync: func(lbc *LoadBalancerController, key string) {
				lbc.syncAppProtectDosLogConf(task{Kind: appProtectDosLogConf, Key: key})
			},
		},
		{
			name: "DosProtectedResource",
			sync: func(lbc *LoadBalancerController, key string) {
				lbc.syncDosProtectedResource(task{Kind: appProtectDosProtectedResource, Key: key})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lbc := &LoadBalancerController{
				namespacedInformers: map[string]*namespacedInformer{},
				Logger:              nl.LoggerFromContext(context.Background()),
			}
			tc.sync(lbc, "not-watched/some-resource")
		})
	}
}
