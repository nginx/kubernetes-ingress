package telemetry_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	"github.com/nginx/kubernetes-ingress/internal/telemetry"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	tel "github.com/nginx/telemetry-exporter/pkg/telemetry"
	"github.com/stretchr/testify/assert"
	coreV1 "k8s.io/api/core/v1"
	networkingV1 "k8s.io/api/networking/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"

	testClient "k8s.io/client-go/kubernetes/fake"
)

func TestCreateNewCollectorWithCustomReportingPeriod(t *testing.T) {
	t.Parallel()

	cfg := telemetry.CollectorConfig{
		Period: 24 * time.Hour,
	}

	c, err := telemetry.NewCollector(cfg)
	if err != nil {
		t.Fatal(err)
	}

	want := 24.0
	got := c.Config.Period.Hours()

	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCreateNewCollectorWithCustomExporter(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	cfg := telemetry.CollectorConfig{
		K8sClientReader: newTestClientset(),
		Configurator:    newConfigurator(t),
		Version:         telemetryNICData.ProjectVersion,
	}
	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	td := telemetry.Data{
		Data: tel.Data{
			ProjectName:         telemetryNICData.ProjectName,
			ProjectVersion:      telemetryNICData.ProjectVersion,
			ClusterVersion:      telemetryNICData.ClusterVersion,
			ProjectArchitecture: runtime.GOARCH,
		},
	}
	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectNodeCountInClusterWithOneNode(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	td := telemetry.Data{
		Data: tel.Data{
			ProjectName:         telemetryNICData.ProjectName,
			ProjectVersion:      telemetryNICData.ProjectVersion,
			ClusterVersion:      telemetryNICData.ClusterVersion,
			ProjectArchitecture: runtime.GOARCH,
			ClusterNodeCount:    1,
			ClusterPlatform:     "other",
		},
		NICResourceCounts: telemetry.NICResourceCounts{
			VirtualServers:      0,
			VirtualServerRoutes: 0,
			TransportServers:    0,
		},
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectNodeCountInClusterWithThreeNodes(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, node2, node3),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
		ProjectArchitecture: runtime.GOARCH,
		ClusterNodeCount:    3,
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectClusterIDInClusterWithOneNode(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	td := telemetry.Data{
		Data: tel.Data{
			ProjectName:         telemetryNICData.ProjectName,
			ProjectVersion:      telemetryNICData.ProjectVersion,
			ClusterVersion:      telemetryNICData.ClusterVersion,
			ClusterPlatform:     "other",
			ProjectArchitecture: runtime.GOARCH,
			ClusterNodeCount:    1,
			ClusterID:           telemetryNICData.ClusterID,
		},
		NICResourceCounts: telemetry.NICResourceCounts{
			VirtualServers:      0,
			VirtualServerRoutes: 0,
			TransportServers:    0,
		},
	}
	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectClusterVersion(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectPolicyCountOnCustomResourcesEnabled(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		policies func() []*conf_v1.Policy
		want     int
	}{
		{
			name: "SinglePolicy",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{egressMTLSPolicy}
			},
			want: 1,
		},
		{
			name: "CachePolicy",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{cachePolicy}
			},
			want: 1,
		},
		{
			name: "MultiplePolicies",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{rateLimitPolicy, wafPolicy, oidcPolicy}
			},
			want: 3,
		},
		{
			name: "MultipleSamePolicies",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{rateLimitPolicy, rateLimitPolicy}
			},
			want: 2,
		},
		{
			name: "SingleInvalidPolicy",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{rateLimitPolicyInvalid}
			},
			want: 0,
		},
		{
			name: "MultiplePoliciesOneValidOneInvalid",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{rateLimitPolicy, rateLimitPolicyInvalid}
			},
			want: 1,
		},
		{
			name: "RateLimitPolicies",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{rateLimitPolicy, wafPolicy, oidcPolicy}
			},
			want: 3,
		},
		{
			name: "RateLimitConditionPolicies",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{rateLimitPolicy, rateLimitJWTPolicy, rateLimitVariablesPolicy}
			},
			want: 3,
		},
		{
			name:     "NoPolicies",
			policies: func() []*conf_v1.Policy { return []*conf_v1.Policy{} },
			want:     0,
		},
		{
			name:     "NilPolicies",
			policies: nil,
			want:     0,
		},
		{
			name:     "NilPolicyValue",
			policies: func() []*conf_v1.Policy { return nil },
			want:     0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			cfg := telemetry.CollectorConfig{
				Policies:               tc.policies,
				CustomResourcesEnabled: true,
			}
			collector, err := telemetry.NewCollector(cfg)
			if err != nil {
				t.Fatal(err)
			}

			for _, polCount := range collector.PolicyCount() {
				got += polCount
			}

			if tc.want != got {
				t.Errorf("want %d policies, got %d", tc.want, got)
			}
		})
	}
}

func TestCollectPolicyCountOnCustomResourcesDisabled(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		policies func() []*conf_v1.Policy
		want     int
	}{
		{
			name:     "Nil func",
			policies: nil,
			want:     0,
		},
		{
			name: "No policies",
			policies: func() []*conf_v1.Policy {
				return []*conf_v1.Policy{}
			},
			want: 0,
		},
		{
			name: "Nil policies",
			policies: func() []*conf_v1.Policy {
				return nil
			},
			want: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			cfg := telemetry.CollectorConfig{
				Policies:               tc.policies,
				CustomResourcesEnabled: false,
			}
			collector, err := telemetry.NewCollector(cfg)
			if err != nil {
				t.Fatal(err)
			}

			for _, polCount := range collector.PolicyCount() {
				got += polCount
			}

			if tc.want != got {
				t.Errorf("want %d policies, got %d", tc.want, got)
			}
		})
	}
}

func TestCollectPoliciesReportOnEnabledCustomResources(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
		Policies: func() []*conf_v1.Policy {
			return []*conf_v1.Policy{
				egressMTLSPolicy,
				egressMTLSPolicy,
				rateLimitPolicyInvalid,
				wafPolicy,
				wafPolicy,
				oidcPolicy,
				cachePolicy,
			}
		},
		CustomResourcesEnabled: true,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		RateLimitPolicies:  0,
		WAFPolicies:        2,
		OIDCPolicies:       1,
		EgressMTLSPolicies: 2,
		CachePolicies:      1,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectRateLimitPoliciesReportOnEnabledCustomResources(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
		Policies: func() []*conf_v1.Policy {
			return []*conf_v1.Policy{
				rateLimitPolicy,
				rateLimitJWTPolicy,
				rateLimitJWTPolicy,
				rateLimitVariablesPolicy,
			}
		},
		CustomResourcesEnabled: true,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		RateLimitPolicies:          1,
		JWTRateLimitPolicies:       2,
		VariablesRateLimitPolicies: 1,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectPoliciesReportOnDisabledCustomResources(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
		Policies: func() []*conf_v1.Policy {
			return []*conf_v1.Policy{
				egressMTLSPolicy,
				egressMTLSPolicy,
				rateLimitPolicyInvalid,
				wafPolicy,
				wafPolicy,
				oidcPolicy,
				cachePolicy,
			}
		},
		CustomResourcesEnabled: false,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		RateLimitPolicies:  0,
		WAFPolicies:        0,
		OIDCPolicies:       0,
		EgressMTLSPolicies: 0,
		CachePolicies:      0,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectIsPlus(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		isPlus bool
		want   bool
	}{
		{
			name:   "Plus enabled",
			isPlus: true,
			want:   true,
		},
		{
			name:   "Plus disabled",
			isPlus: false,
			want:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}

			configurator := newConfiguratorWithIngress(t)

			cfg := telemetry.CollectorConfig{
				Configurator:    configurator,
				K8sClientReader: newTestClientset(node1, kubeNS),
				Version:         telemetryNICData.ProjectVersion,
				IsPlus:          tc.isPlus,
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			ver := c.IsPlusEnabled()

			if tc.want != ver {
				t.Errorf("want: %t, got: %t", tc.want, ver)
			}
		})
	}
}

func TestCollectInvalidIsPlus(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		isPlus bool
		want   bool
	}{
		{
			name:   "Plus disabled but want enabled",
			isPlus: false,
			want:   true,
		},
		{
			name:   "Plus disabled but want enabled",
			isPlus: false,
			want:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}

			configurator := newConfiguratorWithIngress(t)

			cfg := telemetry.CollectorConfig{
				Configurator:    configurator,
				K8sClientReader: newTestClientset(node1, kubeNS),
				Version:         telemetryNICData.ProjectVersion,
				IsPlus:          tc.isPlus,
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			ver := c.IsPlusEnabled()

			if tc.want == ver {
				t.Errorf("want: %t, got: %t", tc.want, ver)
			}
		})
	}
}

func TestIngressCountReportsNoDeployedIngresses(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
		RegularIngressCount: 0,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestMergeableIngressAnnotations(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	masterAnnotations := map[string]string{
		"nginx.org/mergeable-ingress-type": "master",
	}
	coffeeAnnotations := map[string]string{
		"nginx.org/mergeable-ingress-type":     "minion",
		"nginx.org/proxy-set-header":           "X-Forwarded-ABC",
		"appprotect.f5.com/app-protect-enable": "False",
	}
	teaAnnotations := map[string]string{
		"nginx.org/mergeable-ingress-type": "minion",
		"nginx.org/proxy-set-header":       "X-Forwarded-Tea: Chai",
		"nginx.com/health-checks":          "False",
	}

	configurator := newConfiguratorWithMergeableIngressCustomAnnotations(t, masterAnnotations, coffeeAnnotations, teaAnnotations)

	cfg := telemetry.CollectorConfig{
		Configurator:    configurator,
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	expectedAnnotations := []string{
		"nginx.org/mergeable-ingress-type",
		"nginx.org/proxy-set-header",
		"nginx.com/health-checks",
		"appprotect.f5.com/app-protect-enable",
	}

	got := buf.String()
	for _, expectedAnnotation := range expectedAnnotations {
		if !strings.Contains(got, expectedAnnotation) {
			t.Errorf("expected %v in %v", expectedAnnotation, got)
		}
	}
}

func TestInvalidMergeableIngressAnnotations(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	masterAnnotations := map[string]string{
		"nginx.org/ingress-type":                           "master",
		"kubectl.kubernetes.io/last-applied-configuration": "s",
	}
	coffeeAnnotations := map[string]string{
		"nginx.org/mergeable-ingress-type": "minion",
	}
	teaAnnotations := map[string]string{
		"nginx.org/mergeable-type":                   "minion",
		"nginx.org/proxy-set":                        "X-$-ABC",
		"nginx.ingress.kubernetes.io/rewrite-target": "/",
	}

	configurator := newConfiguratorWithMergeableIngressCustomAnnotations(t, masterAnnotations, coffeeAnnotations, teaAnnotations)

	cfg := telemetry.CollectorConfig{
		Configurator:    configurator,
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	expectedAnnotations := []string{
		"kubectl.kubernetes.io/last-applied-configuration",
		"nginx.org/proxy-set-header",
		"nginx.ingress.kubernetes.io/rewrite-target",
	}

	got := buf.String()
	for _, expectedAnnotation := range expectedAnnotations {
		if strings.Contains(got, expectedAnnotation) {
			t.Errorf("expected %v in %v", expectedAnnotation, got)
		}
	}
}

func TestStandardIngressAnnotations(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	annotations := map[string]string{
		"appprotect.f5.com/app-protect-enable": "False",
		"nginx.org/proxy-set-header":           "X-Forwarded-ABC",
		"ingress.kubernetes.io/ssl-redirect":   "True",
		"nginx.com/slow-start":                 "0s",
	}

	configurator := newConfiguratorWithIngressWithCustomAnnotations(t, annotations)

	cfg := telemetry.CollectorConfig{
		Configurator:    configurator,
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	expectedAnnotations := []string{
		"appprotect.f5.com/app-protect-enable",
		"nginx.org/proxy-set-header",
		"nginx.com/slow-start",
		"ingress.kubernetes.io/ssl-redirect",
	}

	got := buf.String()
	for _, expectedAnnotation := range expectedAnnotations {
		if !strings.Contains(got, expectedAnnotation) {
			t.Errorf("expected %v in %v", expectedAnnotation, got)
		}
	}
}

func TestInvalidStandardIngressAnnotations(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	annotations := map[string]string{
		"alb.ingress.kubernetes.io/group.order":      "0",
		"alb.ingress.kubernetes.io/ip-address-type":  "ipv4",
		"alb.ingress.kubernetes.io/scheme":           "internal",
		"nginx.ingress.kubernetes.io/rewrite-target": "/",
	}

	configurator := newConfiguratorWithIngressWithCustomAnnotations(t, annotations)

	cfg := telemetry.CollectorConfig{
		Configurator:    configurator,
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	expectedAnnotations := []string{
		"alb.ingress.kubernetes.io/scheme",
		"alb.ingress.kubernetes.io/group.order",
		"alb.ingress.kubernetes.io/ip-address-type",
		"nginx.ingress.kubernetes.io/rewrite-target",
	}

	got := buf.String()
	for _, expectedAnnotation := range expectedAnnotations {
		if strings.Contains(got, expectedAnnotation) {
			t.Errorf("expected %v in %v", expectedAnnotation, got)
		}
	}
}

func TestIngressCountReportsNumberOfDeployedIngresses(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	configurator := newConfiguratorWithIngress(t)

	cfg := telemetry.CollectorConfig{
		Configurator:    configurator,
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
		RegularIngressCount: 1,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestMasterMinionIngressCountReportsNumberOfDeployedIngresses(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}

	configurator := newConfiguratorWithMergeableIngress(t)

	cfg := telemetry.CollectorConfig{
		Configurator:    configurator,
		K8sClientReader: newTestClientset(node1, kubeNS),
		Version:         telemetryNICData.ProjectVersion,
	}

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
		MasterIngressCount:  1,
		MinionIngressCount:  2,
		IngressAnnotations:  []string{"nginx.org/mergeable-ingress-type"},
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectAppProtectVersion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		appProtectVersion string
		wantVersion       string
	}{
		{
			name:              "AppProtect 4.8",
			appProtectVersion: "4.8.1",
			wantVersion:       "4.8.1",
		},
		{
			name:              "AppProtect 4.9",
			appProtectVersion: "4.9",
			wantVersion:       "4.9",
		},
		{
			name:              "AppProtect 5.1",
			appProtectVersion: "5.1",
			wantVersion:       "5.1",
		},
		{
			name:              "No AppProtect Installed",
			appProtectVersion: "",
			wantVersion:       "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}

			configurator := newConfiguratorWithIngress(t)

			cfg := telemetry.CollectorConfig{
				Configurator:      configurator,
				K8sClientReader:   newTestClientset(node1, kubeNS),
				Version:           telemetryNICData.ProjectVersion,
				AppProtectVersion: tc.appProtectVersion,
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			ver := c.AppProtectVersion()

			if tc.wantVersion != ver {
				t.Errorf("want: %s, got: %s", tc.wantVersion, ver)
			}
		})
	}
}

func TestCollectInvalidAppProtectVersion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		appProtectVersion string
		wantVersion       string
	}{
		{
			name:              "AppProtect Not Installed",
			appProtectVersion: "",
			wantVersion:       "4.8.1",
		},
		{
			name:              "Cant Find AppProtect 4.9",
			appProtectVersion: "4.9",
			wantVersion:       "",
		},
		{
			name:              "Found Different AppProtect Version",
			appProtectVersion: "5.1",
			wantVersion:       "4.9",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}

			configurator := newConfiguratorWithIngress(t)

			cfg := telemetry.CollectorConfig{
				Configurator:      configurator,
				K8sClientReader:   newTestClientset(node1, kubeNS),
				Version:           telemetryNICData.ProjectVersion,
				AppProtectVersion: tc.appProtectVersion,
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			ver := c.AppProtectVersion()

			if tc.wantVersion == ver {
				t.Errorf("want: %s, got: %s", tc.wantVersion, ver)
			}
		})
	}
}

func TestCollectInstallationFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		setFlags  []string
		wantFlags []string
	}{
		{
			name: "first flag",
			setFlags: []string{
				"nginx-plus=true",
			},
			wantFlags: []string{
				"nginx-plus=true",
			},
		},
		{
			name: "second flag",
			setFlags: []string{
				"-log-level=debug",
			},
			wantFlags: []string{
				"-log-level=debug",
			},
		},
		{
			name: "multiple flags",
			setFlags: []string{
				"nginx-plus=true",
				"-log-level=debug",
			},
			wantFlags: []string{
				"nginx-plus=true",
				"-log-level=debug",
			},
		},
		{
			name:      "no flags",
			setFlags:  []string{},
			wantFlags: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}

			configurator := newConfigurator(t)

			cfg := telemetry.CollectorConfig{
				Configurator:      configurator,
				K8sClientReader:   newTestClientset(node1, kubeNS),
				Version:           telemetryNICData.ProjectVersion,
				InstallationFlags: tc.setFlags,
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			telData := tel.Data{
				ProjectName:         telemetryNICData.ProjectName,
				ProjectVersion:      telemetryNICData.ProjectVersion,
				ProjectArchitecture: telemetryNICData.ProjectArchitecture,
				ClusterNodeCount:    1,
				ClusterID:           telemetryNICData.ClusterID,
				ClusterVersion:      telemetryNICData.ClusterVersion,
				ClusterPlatform:     "other",
			}

			nicResourceCounts := telemetry.NICResourceCounts{
				InstallationFlags: tc.wantFlags,
			}

			td := telemetry.Data{
				Data:              telData,
				NICResourceCounts: nicResourceCounts,
			}

			want := fmt.Sprintf("%+v", &td)

			got := buf.String()
			if !cmp.Equal(want, got) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

func TestCollectConfigMapKeys(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		configMap map[string]string
		want      []string
	}{
		{
			name: "one key",
			configMap: map[string]string{
				"error-log-level": "debug",
			},
			want: []string{"error-log-level"},
		},
		{
			name: "two keys",
			configMap: map[string]string{
				"error-log-level": "debug",
				"zone-sync":       "true",
			},
			want: []string{"error-log-level", "zone-sync"},
		},
		{
			name: "two keys and one key that will be ignored",
			configMap: map[string]string{
				"error-log-level": "debug",
				"zone-sync":       "true",
				"hello":           "world",
			},
			want: []string{"error-log-level", "zone-sync"},
		},
		{
			name:      "no keys",
			configMap: map[string]string{},
			want:      []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.JSONExporter{Endpoint: buf}

			configurator := newConfigurator(t)
			namespace := "default"
			name := "nginx-config"

			cfg := telemetry.CollectorConfig{
				Version:      telemetryNICData.ProjectVersion,
				Configurator: configurator,
				K8sClientReader: newTestClientset(
					&coreV1.ConfigMap{
						ObjectMeta: metaV1.ObjectMeta{
							Name:      name,
							Namespace: namespace,
						},
						Data: tc.configMap,
					},
				),
				MainConfigMapName: fmt.Sprintf("%s/%s", namespace, name),
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			sort.Strings(tc.want)

			telData := tel.Data{
				ProjectName:         telemetryNICData.ProjectName,
				ProjectVersion:      telemetryNICData.ProjectVersion,
				ProjectArchitecture: telemetryNICData.ProjectArchitecture,
				ClusterVersion:      telemetryNICData.ClusterVersion,
			}

			nicResourceCounts := telemetry.NICResourceCounts{
				ConfigMapKeys: tc.want,
			}

			td := telemetry.Data{
				Data:              telData,
				NICResourceCounts: nicResourceCounts,
			}

			got := buf.String()

			tdGot := new(telemetry.Data)
			err = json.Unmarshal([]byte(got), &tdGot)
			if err != nil {
				t.Fatalf("failed to unmarshal telemetry data: %v\n%s", err, got)
			}

			assert.ElementsMatchf(t, td.ConfigMapKeys, tdGot.ConfigMapKeys, "want: %s\ngot: %s", td.ConfigMapKeys, tdGot.ConfigMapKeys)
		})
	}
}

func TestCollectMGMTConfigMapKeys(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		configMap map[string]string
		want      []string
	}{
		{
			name: "one key",
			configMap: map[string]string{
				"license-token-secret-name": "license-token",
			},
			want: []string{"license-token-secret-name"},
		},
		{
			name: "two keys",
			configMap: map[string]string{
				"license-token-secret-name": "license-token",
				"enforce-initial-report":    "true",
			},
			want: []string{"enforce-initial-report", "license-token-secret-name"},
		},
		{
			name: "ignored keys",
			configMap: map[string]string{
				"license":   "license",
				"report":    "true",
				"zone-sync": "true",
			},
			want: nil,
		},
		{
			name:      "no keys",
			configMap: map[string]string{},
			want:      []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.JSONExporter{Endpoint: buf}

			configurator := newConfigurator(t)
			namespace := "default"
			name := "nginx-config-mgmt"

			cfg := telemetry.CollectorConfig{
				Version:      telemetryNICData.ProjectVersion,
				Configurator: configurator,
				IsPlus:       true,
				K8sClientReader: newTestClientset(
					&coreV1.ConfigMap{
						ObjectMeta: metaV1.ObjectMeta{
							Name:      name,
							Namespace: namespace,
						},
						Data: tc.configMap,
					},
				),
				MGMTConfigMapName: fmt.Sprintf("%s/%s", namespace, name),
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			sort.Strings(tc.want)

			telData := tel.Data{
				ProjectName:         telemetryNICData.ProjectName,
				ProjectVersion:      telemetryNICData.ProjectVersion,
				ProjectArchitecture: telemetryNICData.ProjectArchitecture,
				ClusterVersion:      telemetryNICData.ClusterVersion,
			}

			nicResourceCounts := telemetry.NICResourceCounts{
				MGMTConfigMapKeys: tc.want,
				IsPlus:            true,
			}

			td := telemetry.Data{
				Data:              telData,
				NICResourceCounts: nicResourceCounts,
			}

			got := buf.String()

			tdGot := new(telemetry.Data)
			err = json.Unmarshal([]byte(got), &tdGot)
			if err != nil {
				t.Fatalf("failed to unmarshal telemetry data: %v\n%s", err, got)
			}

			assert.ElementsMatchf(t, td.MGMTConfigMapKeys, tdGot.MGMTConfigMapKeys, "want: %s\ngot: %s", td.MGMTConfigMapKeys, tdGot.MGMTConfigMapKeys)
		})
	}
}

func TestCollectBuildOS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		buildOS string
		wantOS  string
	}{
		{
			name:    "debian plus image",
			buildOS: "debian-plus",
			wantOS:  "debian-plus",
		},
		{
			name:    "ubi-9 plus app protect image",
			buildOS: "ubi-9-plus-nap",
			wantOS:  "ubi-9-plus-nap",
		},
		{
			name:    "alpine oss image",
			buildOS: "alpine",
			wantOS:  "alpine",
		},
		{
			name:    "self built image",
			buildOS: "",
			wantOS:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}

			configurator := newConfiguratorWithIngress(t)

			cfg := telemetry.CollectorConfig{
				Configurator:    configurator,
				K8sClientReader: newTestClientset(node1, kubeNS),
				Version:         telemetryNICData.ProjectVersion,
				BuildOS:         tc.buildOS,
			}

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			buildOS := c.BuildOS()

			if tc.wantOS != buildOS {
				t.Errorf("want: %s, got: %s", tc.wantOS, buildOS)
			}
		})
	}
}

func TestCountVirtualServersOnCustomResourceEnabled(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		vs   []*configs.VirtualServerEx
		want int
	}{
		{
			name: "Single VirtualServer",
			vs: []*configs.VirtualServerEx{
				{
					VirtualServer: &conf_v1.VirtualServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.VirtualServerSpec{},
					},
				},
			},
			want: 1,
		},
		{
			name: "Multiple VirtualServers",
			vs: []*configs.VirtualServerEx{
				{
					VirtualServer: &conf_v1.VirtualServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.VirtualServerSpec{},
					},
				},
				{
					VirtualServer: &conf_v1.VirtualServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "tea",
						},
						Spec: conf_v1.VirtualServerSpec{},
					},
				},
			},
			want: 2,
		},
	}

	for _, tc := range tt {
		configurator := newConfigurator(t)
		for _, v := range tc.vs {
			_, err := configurator.AddOrUpdateVirtualServer(v)
			if err != nil {
				t.Fatal(err)
			}
		}

		mainConfigMap := &coreV1.ConfigMap{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      "nginx-config",
				Namespace: "nginx-ingress",
			},
		}

		c, err := telemetry.NewCollector(telemetry.CollectorConfig{
			K8sClientReader:        newTestClientset(kubeNS, node1, pod1, replica, mainConfigMap),
			SecretStore:            newSecretStore(t),
			Configurator:           configurator,
			Version:                telemetryNICData.ProjectVersion,
			CustomResourcesEnabled: true, // This field value indicates we count custom resources.
			MainConfigMapName:      "nginx-ingress/nginx-config",
		})
		if err != nil {
			t.Fatal(err)
		}
		c.Config.PodNSName = types.NamespacedName{
			Namespace: "nginx-ingress",
			Name:      "nginx-ingress",
		}

		got, err := c.BuildReport(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		if got.VirtualServers != tc.want {
			t.Errorf("Got %d VS in TelemetryReport, want %d", got.VirtualServers, tc.want)
		}
	}
}

func TestCountVirtualServersOnCustomResourceDisabled(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		vs   []*configs.VirtualServerEx
		want int
	}{
		{
			name: "Multiple VS reported as 0",
			vs: []*configs.VirtualServerEx{
				{
					VirtualServer: &conf_v1.VirtualServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.VirtualServerSpec{},
					},
				},
				{
					VirtualServer: &conf_v1.VirtualServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "tea",
						},
						Spec: conf_v1.VirtualServerSpec{},
					},
				},
			},
			want: 0,
		},
	}

	for _, tc := range tt {
		configurator := newConfigurator(t)

		for _, v := range tc.vs {
			_, err := configurator.AddOrUpdateVirtualServer(v)
			if err != nil {
				t.Fatal(err)
			}
		}

		configmap := &coreV1.ConfigMap{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      "nginx-config",
				Namespace: "nginx-ingress",
			},
		}

		c, err := telemetry.NewCollector(telemetry.CollectorConfig{
			K8sClientReader:        newTestClientset(kubeNS, node1, pod1, replica, configmap),
			SecretStore:            newSecretStore(t),
			Configurator:           configurator,
			Version:                telemetryNICData.ProjectVersion,
			CustomResourcesEnabled: false, // This field value indicates we don't count custom resources.
			MainConfigMapName:      "nginx-ingress/nginx-config",
		})
		if err != nil {
			t.Fatal(err)
		}
		c.Config.PodNSName = types.NamespacedName{
			Namespace: "nginx-ingress",
			Name:      "nginx-ingress",
		}

		got, err := c.BuildReport(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		if got.VirtualServers != tc.want {
			t.Errorf("Got %d VS in TelemetryReport, want %d", got.VirtualServers, tc.want)
		}
	}
}

func TestCountTransportServersOnCustomResourcesEnabled(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		ts   []*configs.TransportServerEx
		want int
	}{
		{
			name: "Single TransportServer",
			ts: []*configs.TransportServerEx{
				{
					TransportServer: &conf_v1.TransportServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.TransportServerSpec{
							Action: &conf_v1.TransportServerAction{
								Pass: "coffee",
							},
						},
					},
				},
			},
			want: 1,
		},
		{
			name: "Multiple TransportServers",
			ts: []*configs.TransportServerEx{
				{
					TransportServer: &conf_v1.TransportServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.TransportServerSpec{
							Action: &conf_v1.TransportServerAction{
								Pass: "coffee",
							},
						},
					},
				},
				{
					TransportServer: &conf_v1.TransportServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "tea",
						},
						Spec: conf_v1.TransportServerSpec{
							Action: &conf_v1.TransportServerAction{
								Pass: "tea",
							},
						},
					},
				},
			},
			want: 2,
		},
	}

	for _, tc := range tt {
		cfg := newConfigurator(t)

		for _, ts := range tc.ts {
			_, err := cfg.AddOrUpdateTransportServer(ts)
			if err != nil {
				t.Fatal(err)
			}
		}

		configmap := &coreV1.ConfigMap{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      "nginx-config",
				Namespace: "nginx-ingress",
			},
		}

		c, err := telemetry.NewCollector(telemetry.CollectorConfig{
			K8sClientReader:        newTestClientset(kubeNS, node1, pod1, replica, configmap),
			SecretStore:            newSecretStore(t),
			Configurator:           cfg,
			Version:                telemetryNICData.ProjectVersion,
			CustomResourcesEnabled: true, // This field value indicates we count custom resources.
			MainConfigMapName:      "nginx-ingress/nginx-config",
		})
		if err != nil {
			t.Fatal(err)
		}
		c.Config.PodNSName = types.NamespacedName{
			Namespace: "nginx-ingress",
			Name:      "nginx-ingress",
		}

		got, err := c.BuildReport(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		if got.TransportServers != tc.want {
			t.Errorf("Got %d TR in TelemetryReport, want %d", got.TransportServers, tc.want)
		}
	}
}

func TestCountTransportServersOnCustomResourcesDisabled(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		ts   []*configs.TransportServerEx
		want int
	}{
		{
			name: "Single TransportServer",
			ts: []*configs.TransportServerEx{
				{
					TransportServer: &conf_v1.TransportServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.TransportServerSpec{
							Action: &conf_v1.TransportServerAction{
								Pass: "coffee",
							},
						},
					},
				},
			},
			want: 0,
		},
		{
			name: "Multiple TransportServers",
			ts: []*configs.TransportServerEx{
				{
					TransportServer: &conf_v1.TransportServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "coffee",
						},
						Spec: conf_v1.TransportServerSpec{
							Action: &conf_v1.TransportServerAction{
								Pass: "coffee",
							},
						},
					},
				},
				{
					TransportServer: &conf_v1.TransportServer{
						ObjectMeta: metaV1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "tea",
						},
						Spec: conf_v1.TransportServerSpec{
							Action: &conf_v1.TransportServerAction{
								Pass: "tea",
							},
						},
					},
				},
			},
			want: 0,
		},
	}

	for _, tc := range tt {
		cfg := newConfigurator(t)

		for _, ts := range tc.ts {
			_, err := cfg.AddOrUpdateTransportServer(ts)
			if err != nil {
				t.Fatal(err)
			}
		}

		configmap := &coreV1.ConfigMap{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      "nginx-config",
				Namespace: "nginx-ingress",
			},
		}

		c, err := telemetry.NewCollector(telemetry.CollectorConfig{
			K8sClientReader:        newTestClientset(kubeNS, node1, pod1, replica, configmap),
			SecretStore:            newSecretStore(t),
			Configurator:           cfg,
			Version:                telemetryNICData.ProjectVersion,
			CustomResourcesEnabled: false, // This field value indicates we do not count custom resources.
			MainConfigMapName:      "nginx-ingress/nginx-config",
		})
		if err != nil {
			t.Fatal(err)
		}
		c.Config.PodNSName = types.NamespacedName{
			Namespace: "nginx-ingress",
			Name:      "nginx-ingress",
		}

		got, err := c.BuildReport(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		if got.TransportServers != tc.want {
			t.Errorf("Got %d TR in TelemetryReport, want %d", got.TransportServers, tc.want)
		}
	}
}

func TestCountSecretsWithTwoSecrets(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		SecretStore:     newSecretStore(t),
		Version:         telemetryNICData.ProjectVersion,
	}

	// Add multiple secrets.
	cfg.SecretStore.AddOrUpdateSecret(secret1)
	cfg.SecretStore.AddOrUpdateSecret(secret2)

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
		Secrets:             2,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCountSecretsAddTwoSecretsAndDeleteOne(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	exp := &telemetry.StdoutExporter{Endpoint: buf}
	cfg := telemetry.CollectorConfig{
		Configurator:    newConfigurator(t),
		K8sClientReader: newTestClientset(node1, kubeNS),
		SecretStore:     newSecretStore(t),
		Version:         telemetryNICData.ProjectVersion,
	}

	// Add multiple secrets.
	cfg.SecretStore.AddOrUpdateSecret(secret1)
	cfg.SecretStore.AddOrUpdateSecret(secret2)

	// Delete one secret.
	cfg.SecretStore.DeleteSecret(fmt.Sprintf("%s/%s", secret2.Namespace, secret2.Name))

	c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
	if err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())

	telData := tel.Data{
		ProjectName:         telemetryNICData.ProjectName,
		ProjectVersion:      telemetryNICData.ProjectVersion,
		ProjectArchitecture: telemetryNICData.ProjectArchitecture,
		ClusterNodeCount:    1,
		ClusterID:           telemetryNICData.ClusterID,
		ClusterVersion:      telemetryNICData.ClusterVersion,
		ClusterPlatform:     "other",
	}

	nicResourceCounts := telemetry.NICResourceCounts{
		VirtualServers:      0,
		VirtualServerRoutes: 0,
		TransportServers:    0,
		Secrets:             1,
	}

	td := telemetry.Data{
		Data:              telData,
		NICResourceCounts: nicResourceCounts,
	}

	want := fmt.Sprintf("%+v", &td)
	got := buf.String()
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestCollectGetServices(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		config telemetry.CollectorConfig
		want   map[string]int
	}{
		{
			name: "OneClusterIP",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, clusterIPService),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ClusterIP": 1,
			},
		},
		{
			name: "MultipleClusterIPs",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, clusterIPService, clusterIPService2),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ClusterIP": 2,
			},
		},
		{
			name: "MultipleExternalNamesAndNodePort",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, externalNameService, externalNameService2, nodePortService),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ExternalName": 2,
				"NodePort":     1,
			},
		},
		{
			name: "MultipleServices",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, externalNameService, externalNameService2, nodePortService, nodePortService2, clusterIPService2, clusterIPService, loadBalancerService),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ClusterIP":    2,
				"ExternalName": 2,
				"NodePort":     2,
				"LoadBalancer": 1,
			},
		},
		{
			name: "noServices",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}
			cfg := tc.config

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			telData := tel.Data{
				ProjectName:         telemetryNICData.ProjectName,
				ProjectVersion:      telemetryNICData.ProjectVersion,
				ProjectArchitecture: telemetryNICData.ProjectArchitecture,
				ClusterID:           telemetryNICData.ClusterID,
				ClusterVersion:      telemetryNICData.ClusterVersion,
			}
			clusterIPServices := tc.want["ClusterIP"]
			nodePortServices := tc.want["NodePort"]
			loadBalancerServices := tc.want["LoadBalancer"]
			externalNameServices := tc.want["ExternalName"]

			nicResourceCounts := telemetry.NICResourceCounts{
				ClusterIPServices:    int64(clusterIPServices),
				NodePortServices:     int64(nodePortServices),
				LoadBalancerServices: int64(loadBalancerServices),
				ExternalNameServices: int64(externalNameServices),
			}

			td := telemetry.Data{
				Data:              telData,
				NICResourceCounts: nicResourceCounts,
			}

			want := fmt.Sprintf("%+v", &td)
			got := buf.String()
			if !cmp.Equal(want, got) {
				t.Error(cmp.Diff(want, got))
			}
		})
	}
}

func TestCollectGetInvalidServices(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		config telemetry.CollectorConfig
		want   map[string]int
	}{
		{
			name: "WantNoClusterIPServices",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, clusterIPService),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ClusterIP": 0,
			},
		},
		{
			name: "WantMultipleExternalNamesAndNodePort",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, externalNameService2),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ExternalName": 2,
				"NodePort":     1,
			},
		},
		{
			name: "WantManyServices",
			config: telemetry.CollectorConfig{
				Configurator:    newConfigurator(t),
				K8sClientReader: newTestClientset(defaultNS, kubeNS, nodePortService2, clusterIPService2, clusterIPService, loadBalancerService),
				Version:         telemetryNICData.ProjectVersion,
			},
			want: map[string]int{
				"ClusterIP":    2,
				"ExternalName": 2,
				"NodePort":     2,
				"LoadBalancer": 2,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			exp := &telemetry.StdoutExporter{Endpoint: buf}
			cfg := tc.config

			c, err := telemetry.NewCollector(cfg, telemetry.WithExporter(exp))
			if err != nil {
				t.Fatal(err)
			}
			c.Collect(context.Background())

			telData := tel.Data{
				ProjectName:         telemetryNICData.ProjectName,
				ProjectVersion:      telemetryNICData.ProjectVersion,
				ProjectArchitecture: telemetryNICData.ProjectArchitecture,
				ClusterID:           telemetryNICData.ClusterID,
				ClusterVersion:      telemetryNICData.ClusterVersion,
			}
			clusterIPServices := tc.want["ClusterIP"]
			nodePortServices := tc.want["NodePort"]
			externalNameServices := tc.want["ExternalName"]

			nicResourceCounts := telemetry.NICResourceCounts{
				ClusterIPServices:    int64(clusterIPServices),
				NodePortServices:     int64(nodePortServices),
				ExternalNameServices: int64(externalNameServices),
			}

			td := telemetry.Data{
				Data:              telData,
				NICResourceCounts: nicResourceCounts,
			}

			want := fmt.Sprintf("%+v", &td)
			got := buf.String()
			if cmp.Equal(want, got) {
				t.Error(cmp.Diff(want, got))
			}
		})
	}
}

func createCafeIngressEx() configs.IngressEx {
	cafeIngress := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "cafe-ingress",
			Namespace: "default",
		},
		Spec: networkingV1.IngressSpec{
			TLS: []networkingV1.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{
							Paths: []networkingV1.HTTPIngressPath{
								{
									Path: "/coffee",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
								{
									Path: "/tea",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "tea-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	cafeIngressEx := configs.IngressEx{
		Ingress: &cafeIngress,
		Endpoints: map[string][]string{
			"coffee-svc80": {"10.0.0.1:80"},
			"tea-svc80":    {"10.0.0.2:80"},
		},
		ExternalNameSvcs: map[string]bool{},
		ValidHosts: map[string]bool{
			"cafe.example.com": true,
		},
		SecretRefs: map[string]*secrets.SecretReference{
			"cafe-secret": {
				Secret: &coreV1.Secret{
					Type: coreV1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-cafe-secret",
			},
		},
	}
	return cafeIngressEx
}

func createMergeableCafeIngress() *configs.MergeableIngresses {
	master := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
		Spec: networkingV1.IngressSpec{
			TLS: []networkingV1.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{ // HTTP must not be nil for Master
							Paths: []networkingV1.HTTPIngressPath{},
						},
					},
				},
			},
		},
	}

	coffeeMinion := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "cafe-ingress-coffee-minion",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "minion",
			},
		},
		Spec: networkingV1.IngressSpec{
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{
							Paths: []networkingV1.HTTPIngressPath{
								{
									Path: "/coffee",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	teaMinion := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "cafe-ingress-tea-minion",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "minion",
			},
		},
		Spec: networkingV1.IngressSpec{
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{
							Paths: []networkingV1.HTTPIngressPath{
								{
									Path: "/tea",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "tea-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	mergeableIngresses := &configs.MergeableIngresses{
		Master: &configs.IngressEx{
			Ingress: &master,
			Endpoints: map[string][]string{
				"coffee-svc80": {"10.0.0.1:80"},
				"tea-svc80":    {"10.0.0.2:80"},
			},
			ValidHosts: map[string]bool{
				"cafe.example.com": true,
			},
			SecretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &coreV1.Secret{
						Type: coreV1.SecretTypeTLS,
					},
					Path:  "/etc/nginx/secrets/default-cafe-secret",
					Error: nil,
				},
			},
		},
		Minions: []*configs.IngressEx{
			{
				Ingress: &coffeeMinion,
				Endpoints: map[string][]string{
					"coffee-svc80": {"10.0.0.1:80"},
				},
				ValidHosts: map[string]bool{
					"cafe.example.com": true,
				},
				ValidMinionPaths: map[string]bool{
					"/coffee": true,
				},
				SecretRefs: map[string]*secrets.SecretReference{},
			},
			{
				Ingress: &teaMinion,
				Endpoints: map[string][]string{
					"tea-svc80": {"10.0.0.2:80"},
				},
				ValidHosts: map[string]bool{
					"cafe.example.com": true,
				},
				ValidMinionPaths: map[string]bool{
					"/tea": true,
				},
				SecretRefs: map[string]*secrets.SecretReference{},
			},
		},
	}

	return mergeableIngresses
}

func createMergeableIngressWithCustomAnnotations(masterAnnotations, coffeeAnnotations, teaAnnotations map[string]string) *configs.MergeableIngresses {
	master := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:        "cafe-ingress-master",
			Namespace:   "default",
			Annotations: masterAnnotations,
		},
		Spec: networkingV1.IngressSpec{
			TLS: []networkingV1.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{ // HTTP must not be nil for Master
							Paths: []networkingV1.HTTPIngressPath{},
						},
					},
				},
			},
		},
	}

	coffeeMinion := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:        "cafe-ingress-coffee-minion",
			Namespace:   "default",
			Annotations: coffeeAnnotations,
		},
		Spec: networkingV1.IngressSpec{
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{
							Paths: []networkingV1.HTTPIngressPath{
								{
									Path: "/coffee",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	teaMinion := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:        "cafe-ingress-tea-minion",
			Namespace:   "default",
			Annotations: teaAnnotations,
		},
		Spec: networkingV1.IngressSpec{
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{
							Paths: []networkingV1.HTTPIngressPath{
								{
									Path: "/tea",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "tea-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	mergeableIngresses := &configs.MergeableIngresses{
		Master: &configs.IngressEx{
			Ingress: &master,
			Endpoints: map[string][]string{
				"coffee-svc80": {"10.0.0.1:80"},
				"tea-svc80":    {"10.0.0.2:80"},
			},
			ValidHosts: map[string]bool{
				"cafe.example.com": true,
			},
			SecretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &coreV1.Secret{
						Type: coreV1.SecretTypeTLS,
					},
					Path:  "/etc/nginx/secrets/default-cafe-secret",
					Error: nil,
				},
			},
		},
		Minions: []*configs.IngressEx{
			{
				Ingress: &coffeeMinion,
				Endpoints: map[string][]string{
					"coffee-svc80": {"10.0.0.1:80"},
				},
				ValidHosts: map[string]bool{
					"cafe.example.com": true,
				},
				ValidMinionPaths: map[string]bool{
					"/coffee": true,
				},
				SecretRefs: map[string]*secrets.SecretReference{},
			},
			{
				Ingress: &teaMinion,
				Endpoints: map[string][]string{
					"tea-svc80": {"10.0.0.2:80"},
				},
				ValidHosts: map[string]bool{
					"cafe.example.com": true,
				},
				ValidMinionPaths: map[string]bool{
					"/tea": true,
				},
				SecretRefs: map[string]*secrets.SecretReference{},
			},
		},
	}

	return mergeableIngresses
}

func createCafeIngressExWithCustomAnnotations(annotations map[string]string) configs.IngressEx {
	cafeIngress := networkingV1.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:        "cafe-ingress",
			Namespace:   "default",
			Annotations: annotations,
		},
		Spec: networkingV1.IngressSpec{
			TLS: []networkingV1.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			Rules: []networkingV1.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networkingV1.IngressRuleValue{
						HTTP: &networkingV1.HTTPIngressRuleValue{
							Paths: []networkingV1.HTTPIngressPath{
								{
									Path: "/coffee",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
								{
									Path: "/tea",
									Backend: networkingV1.IngressBackend{
										Service: &networkingV1.IngressServiceBackend{
											Name: "tea-svc",
											Port: networkingV1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	cafeIngressEx := configs.IngressEx{
		Ingress: &cafeIngress,
		Endpoints: map[string][]string{
			"coffee-svc80": {"10.0.0.1:80"},
			"tea-svc80":    {"10.0.0.2:80"},
		},
		ExternalNameSvcs: map[string]bool{},
		ValidHosts: map[string]bool{
			"cafe.example.com": true,
		},
		SecretRefs: map[string]*secrets.SecretReference{
			"cafe-secret": {
				Secret: &coreV1.Secret{
					Type: coreV1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-cafe-secret",
			},
		},
	}
	return cafeIngressEx
}

func newConfiguratorWithIngress(t *testing.T) *configs.Configurator {
	t.Helper()

	ingressEx := createCafeIngressEx()
	c := newConfigurator(t)
	_, err := c.AddOrUpdateIngress(&ingressEx)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newConfiguratorWithIngressWithCustomAnnotations(t *testing.T, annotations map[string]string) *configs.Configurator {
	t.Helper()

	ingressEx := createCafeIngressExWithCustomAnnotations(annotations)
	c := newConfigurator(t)
	_, err := c.AddOrUpdateIngress(&ingressEx)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newConfiguratorWithMergeableIngress(t *testing.T) *configs.Configurator {
	t.Helper()

	ingressEx := createMergeableCafeIngress()
	c := newConfigurator(t)
	_, err := c.AddOrUpdateMergeableIngress(ingressEx)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newConfiguratorWithMergeableIngressCustomAnnotations(t *testing.T, masterAnnotations, coffeeAnnotations, teaAnnotations map[string]string) *configs.Configurator {
	t.Helper()

	ingressEx := createMergeableIngressWithCustomAnnotations(masterAnnotations, coffeeAnnotations, teaAnnotations)
	c := newConfigurator(t)
	_, err := c.AddOrUpdateMergeableIngress(ingressEx)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newConfigurator(t *testing.T) *configs.Configurator {
	t.Helper()

	templateExecutor, err := version1.NewTemplateExecutor(mainTemplatePath, ingressTemplatePath)
	if err != nil {
		t.Fatal(err)
	}

	templateExecutorV2, err := version2.NewTemplateExecutor(virtualServerTemplatePath, transportServerTemplatePath)
	if err != nil {
		t.Fatal(err)
	}

	manager := nginx.NewFakeManager("/etc/nginx")
	cnf := configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager: manager,
		StaticCfgParams: &configs.StaticConfigParams{
			HealthStatus:                   true,
			HealthStatusURI:                "/nginx-health",
			NginxStatus:                    true,
			NginxStatusAllowCIDRs:          []string{"127.0.0.1"},
			NginxStatusPort:                8080,
			StubStatusOverUnixSocketForOSS: false,
			NginxVersion:                   nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)"),
		},
		Config:                  configs.NewDefaultConfigParams(context.Background(), false),
		TemplateExecutor:        templateExecutor,
		TemplateExecutorV2:      templateExecutorV2,
		LatencyCollector:        nil,
		LabelUpdater:            nil,
		IsPlus:                  false,
		IsWildcardEnabled:       false,
		IsPrometheusEnabled:     false,
		IsLatencyMetricsEnabled: false,
	})
	return cnf
}

func newSecretStore(t *testing.T) *secrets.LocalSecretStore {
	t.Helper()
	configurator := newConfigurator(t)
	return secrets.NewLocalSecretStore(configurator)
}

// newTestClientset takes k8s runtime objects and returns a k8s fake clientset.
// The clientset is configured to return kubernetes version v1.30.0.
// (call to Discovery().ServerVersion())
//
// version.Info struct can hold more information about K8s platform, for example:
//
//	type Info struct {
//	  Major        string
//	  Minor        string
//	  GitVersion   string
//	  GitCommit    string
//	  GitTreeState string
//	  BuildDate    string
//	  GoVersion    string
//	  Compiler     string
//	  Platform     string
//	}
func newTestClientset(objects ...k8sruntime.Object) *testClient.Clientset {
	client := testClient.NewSimpleClientset(objects...)
	client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		GitVersion: "v1.30.0",
	}
	return client
}

const (
	mainTemplatePath            = "../configs/version1/nginx-plus.tmpl"
	ingressTemplatePath         = "../configs/version1/nginx-plus.ingress.tmpl"
	virtualServerTemplatePath   = "../configs/version2/nginx-plus.virtualserver.tmpl"
	transportServerTemplatePath = "../configs/version2/nginx-plus.transportserver.tmpl"
)

// telemetryNICData holds static test data for telemetry tests.
var telemetryNICData = tel.Data{
	ProjectName:         "NIC",
	ProjectVersion:      "3.5.0",
	ClusterVersion:      "v1.30.0",
	ProjectArchitecture: runtime.GOARCH,
	ClusterID:           "329766ff-5d78-4c9e-8736-7faad1f2e937",
	ClusterNodeCount:    1,
	ClusterPlatform:     "other",
}

// Policies used for testing for PolicyCount method
var (
	rateLimitPolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "rate-limit-policy3",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			RateLimit: &conf_v1.RateLimit{},
		},
		Status: conf_v1.PolicyStatus{},
	}

	rateLimitJWTPolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "rate-limit-policy4",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			RateLimit: &conf_v1.RateLimit{
				Condition: &conf_v1.RateLimitCondition{
					JWT: &conf_v1.JWTCondition{
						Claim: "sub",
						Match: "abc",
					},
				},
			},
		},
		Status: conf_v1.PolicyStatus{},
	}

	rateLimitVariablesPolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "rate-limit-policy5",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			RateLimit: &conf_v1.RateLimit{
				Condition: &conf_v1.RateLimitCondition{
					Variables: &[]conf_v1.VariableCondition{
						{
							Name:  "var1",
							Match: "value1",
						},
					},
				},
			},
		},
		Status: conf_v1.PolicyStatus{},
	}

	rateLimitPolicyInvalid = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "INVALID-rate-limit-policy",
			Namespace: "default",
		},
		Spec:   conf_v1.PolicySpec{},
		Status: conf_v1.PolicyStatus{},
	}

	egressMTLSPolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "rate-limit-policy3",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			EgressMTLS: &conf_v1.EgressMTLS{},
		},
		Status: conf_v1.PolicyStatus{},
	}

	oidcPolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "rate-limit-policy3",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			OIDC: &conf_v1.OIDC{},
		},
		Status: conf_v1.PolicyStatus{},
	}

	wafPolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "rate-limit-policy3",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{},
		},
		Status: conf_v1.PolicyStatus{},
	}

	cachePolicy = &conf_v1.Policy{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "k8s.nginx.org/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "cache-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			Cache: &conf_v1.Cache{},
		},
		Status: conf_v1.PolicyStatus{},
	}
)
