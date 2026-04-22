package k8s

import (
	"context"
	"testing"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	k8s_nginx_fake "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
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
