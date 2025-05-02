package configs

import (
	"context"
	"testing"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

func createTestConfiguratorBench() (*Configurator, error) {
	templateExecutor, err := version1.NewTemplateExecutor("version1/nginx-plus.tmpl", "version1/nginx-plus.ingress.tmpl")
	if err != nil {
		return nil, err
	}

	templateExecutorV2, err := version2.NewTemplateExecutor("version2/nginx-plus.virtualserver.tmpl", "version2/nginx-plus.transportserver.tmpl")
	if err != nil {
		return nil, err
	}

	manager := nginx.NewFakeManager("/etc/nginx")
	cnf := NewConfigurator(ConfiguratorParams{
		NginxManager:            manager,
		StaticCfgParams:         createTestStaticConfigParams(),
		Config:                  NewDefaultConfigParams(context.Background(), false),
		TemplateExecutor:        templateExecutor,
		TemplateExecutorV2:      templateExecutorV2,
		LatencyCollector:        nil,
		LabelUpdater:            nil,
		IsPlus:                  false,
		IsWildcardEnabled:       false,
		IsPrometheusEnabled:     false,
		IsLatencyMetricsEnabled: false,
		NginxVersion:            nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)"),
	})
	cnf.isReloadsEnabled = true
	return cnf, nil
}

func BenchmarkAddOrUpdateIngress(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	ingress := createCafeIngressEx()

	b.ResetTimer()
	for range b.N {
		_, err := cnf.AddOrUpdateIngress(&ingress)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddOrUpdateMergeableIngress(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	mergeableIngress := createMergeableCafeIngress()

	b.ResetTimer()
	for range b.N {
		_, err := cnf.AddOrUpdateMergeableIngress(mergeableIngress)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchUpdateEndpoints(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	ingress := createCafeIngressEx()
	ingresses := []*IngressEx{&ingress}

	b.ResetTimer()
	for range b.N {
		err := cnf.UpdateEndpoints(ingresses)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUpdateEndpointsMergeableIngress(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	mergeableIngress := createMergeableCafeIngress()
	mergeableIngresses := []*MergeableIngresses{mergeableIngress}

	b.ResetTimer()
	for range b.N {
		err := cnf.UpdateEndpointsMergeableIngress(mergeableIngresses)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddVirtualServerMetricsLabels(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}

	cnf.isPlus = true
	cnf.labelUpdater = newFakeLabelUpdater()
	testLatencyCollector := newMockLatencyCollector()
	cnf.latencyCollector = testLatencyCollector

	vsEx := &VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "test-vs",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "example.com",
			},
		},
		PodsByIP: map[string]PodInfo{
			"10.0.0.1:80": {Name: "pod-1"},
			"10.0.0.2:80": {Name: "pod-2"},
		},
	}

	upstreams := []version2.Upstream{
		{
			Name: "upstream-1",
			Servers: []version2.UpstreamServer{
				{
					Address: "10.0.0.1:80",
				},
			},
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "service-1",
				ResourceType:      "virtualserver",
				ResourceName:      vsEx.VirtualServer.Name,
				ResourceNamespace: vsEx.VirtualServer.Namespace,
			},
		},
		{
			Name: "upstream-2",
			Servers: []version2.UpstreamServer{
				{
					Address: "10.0.0.2:80",
				},
			},
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "service-2",
				ResourceType:      "virtualserver",
				ResourceName:      vsEx.VirtualServer.Name,
				ResourceNamespace: vsEx.VirtualServer.Namespace,
			},
		},
	}

	b.ResetTimer()
	for range b.N {
		cnf.updateVirtualServerMetricsLabels(vsEx, upstreams)
	}
}

func BenchmarkAddTransportServerMetricsLabels(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	cnf.isPlus = true
	cnf.labelUpdater = newFakeLabelUpdater()

	tsEx := &TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "test-transportserver",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "dns-tcp",
					Protocol: "TCP",
				},
			},
		},
		PodsByIP: map[string]string{
			"10.0.0.1:80": "pod-1",
			"10.0.0.2:80": "pod-2",
		},
	}

	streamUpstreams := []version2.StreamUpstream{
		{
			Name: "upstream-1",
			Servers: []version2.StreamUpstreamServer{
				{
					Address: "10.0.0.1:80",
				},
			},
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "service-1",
				ResourceType:      "transportserver",
				ResourceName:      tsEx.TransportServer.Name,
				ResourceNamespace: tsEx.TransportServer.Namespace,
			},
		},
		{
			Name: "upstream-2",
			Servers: []version2.StreamUpstreamServer{
				{
					Address: "10.0.0.2:80",
				},
			},
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "service-2",
				ResourceType:      "transportserver",
				ResourceName:      tsEx.TransportServer.Name,
				ResourceNamespace: tsEx.TransportServer.Namespace,
			},
		},
	}

	b.ResetTimer()
	for range b.N {
		cnf.updateTransportServerMetricsLabels(tsEx, streamUpstreams)
	}
}
