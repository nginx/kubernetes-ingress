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

	templateExecutorV2, err := version2.NewTemplateExecutor("version2/nginx-plus.virtualserver.tmpl", "version2/nginx-plus.transportserver.tmpl", "version2/oidc.tmpl")
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

func BenchmarkUpdateEndpoints(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	ingresses := []*IngressEx{new(createCafeIngressEx())}

	b.ResetTimer()
	for range b.N {
		_, err := cnf.UpdateEndpoints(ingresses)
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
		_, err := cnf.UpdateEndpointsMergeableIngress(mergeableIngresses)
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

// vsExWithEndpoints returns the standard cafe VirtualServerEx with populated endpoints.
func vsExWithEndpoints() VirtualServerEx {
	vs := vsEx()
	vs.Endpoints = map[string][]string{
		"default/tea-svc:80": {
			"10.0.0.20:80",
		},
		"default/tea-svc_version=v1:80": {
			"10.0.0.30:80",
		},
		"default/coffee-svc:80": {
			"10.0.0.40:80",
		},
		"default/sub-tea-svc_version=v1:80": {
			"10.0.0.50:80",
		},
	}
	return vs
}

// vsExWithSplits returns a VirtualServerEx that uses split routing (weight-based traffic splitting).
func vsExWithSplits() VirtualServerEx {
	return VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea-v1",
						Service: "tea-svc-v1",
						Port:    80,
					},
					{
						Name:    "tea-v2",
						Service: "tea-svc-v2",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Splits: []conf_v1.Split{
							{
								Weight: 90,
								Action: &conf_v1.Action{
									Pass: "tea-v1",
								},
							},
							{
								Weight: 10,
								Action: &conf_v1.Action{
									Pass: "tea-v2",
								},
							},
						},
					},
					{
						Path:  "/coffee",
						Route: "default/coffee",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc-v1:80": {
				"10.0.0.20:80",
			},
			"default/tea-svc-v2:80": {
				"10.0.0.21:80",
			},
			"default/coffee-svc-v1:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc-v2:80": {
				"10.0.0.31:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "coffee-v1",
							Service: "coffee-svc-v1",
							Port:    80,
						},
						{
							Name:    "coffee-v2",
							Service: "coffee-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Splits: []conf_v1.Split{
								{
									Weight: 40,
									Action: &conf_v1.Action{
										Pass: "coffee-v1",
									},
								},
								{
									Weight: 60,
									Action: &conf_v1.Action{
										Pass: "coffee-v2",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// vsExWithMatches returns a VirtualServerEx that uses match routing (header/arg conditions).
func vsExWithMatches() VirtualServerEx {
	return VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea-v1",
						Service: "tea-svc-v1",
						Port:    80,
					},
					{
						Name:    "tea-v2",
						Service: "tea-svc-v2",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Matches: []conf_v1.Match{
							{
								Conditions: []conf_v1.Condition{
									{
										Header: "x-version",
										Value:  "v2",
									},
								},
								Action: &conf_v1.Action{
									Pass: "tea-v2",
								},
							},
						},
						Action: &conf_v1.Action{
							Pass: "tea-v1",
						},
					},
					{
						Path:  "/coffee",
						Route: "default/coffee",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc-v1:80": {
				"10.0.0.20:80",
			},
			"default/tea-svc-v2:80": {
				"10.0.0.21:80",
			},
			"default/coffee-svc-v1:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc-v2:80": {
				"10.0.0.31:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "coffee-v1",
							Service: "coffee-svc-v1",
							Port:    80,
						},
						{
							Name:    "coffee-v2",
							Service: "coffee-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Matches: []conf_v1.Match{
								{
									Conditions: []conf_v1.Condition{
										{
											Argument: "version",
											Value:    "v2",
										},
									},
									Action: &conf_v1.Action{
										Pass: "coffee-v2",
									},
								},
							},
							Action: &conf_v1.Action{
								Pass: "coffee-v1",
							},
						},
					},
				},
			},
		},
	}
}

func BenchmarkAddOrUpdateVirtualServer(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	virtualServerEx := vsExWithEndpoints()

	b.ResetTimer()
	for range b.N {
		_, err := cnf.AddOrUpdateVirtualServer(&virtualServerEx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddOrUpdateVirtualServerWithSplits(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	virtualServerEx := vsExWithSplits()

	b.ResetTimer()
	for range b.N {
		_, err := cnf.AddOrUpdateVirtualServer(&virtualServerEx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddOrUpdateVirtualServerWithMatches(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	virtualServerEx := vsExWithMatches()

	b.ResetTimer()
	for range b.N {
		_, err := cnf.AddOrUpdateVirtualServer(&virtualServerEx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddOrUpdateTransportServer(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	transportServerEx := tsEx()
	transportServerEx.ListenerPort = 2020
	transportServerEx.Endpoints = map[string][]string{
		"default/tcp-app-svc:5001": {
			"10.0.0.20:5001",
		},
	}

	b.ResetTimer()
	for range b.N {
		_, err := cnf.AddOrUpdateTransportServer(&transportServerEx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateVirtualServerConfig(b *testing.B) {
	virtualServerEx := vsExWithEndpoints()
	cfgParams := &ConfigParams{
		Context: context.Background(),
	}
	staticParams := &StaticConfigParams{}
	vsc := newVirtualServerConfigurator(cfgParams, false, false, staticParams, false, nil)

	b.ResetTimer()
	for range b.N {
		vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	}
}

func BenchmarkGenerateVirtualServerConfigWithSplits(b *testing.B) {
	virtualServerEx := vsExWithSplits()
	cfgParams := &ConfigParams{
		Context: context.Background(),
	}
	staticParams := &StaticConfigParams{}
	vsc := newVirtualServerConfigurator(cfgParams, false, false, staticParams, false, nil)

	b.ResetTimer()
	for range b.N {
		vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	}
}

func BenchmarkGenerateVirtualServerConfigWithMatches(b *testing.B) {
	virtualServerEx := vsExWithMatches()
	cfgParams := &ConfigParams{
		Context: context.Background(),
	}
	staticParams := &StaticConfigParams{}
	vsc := newVirtualServerConfigurator(cfgParams, false, false, staticParams, false, nil)

	b.ResetTimer()
	for range b.N {
		vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	}
}

func BenchmarkGenerateTransportServerConfig(b *testing.B) {
	transportServerEx := tsEx()
	transportServerEx.ListenerPort = 2020
	transportServerEx.Endpoints = map[string][]string{
		"default/tcp-app-svc:5001": {
			"10.0.0.20:5001",
		},
	}
	params := transportServerConfigParams{
		transportServerEx: &transportServerEx,
		listenerPort:      transportServerEx.ListenerPort,
		isPlus:            false,
	}

	b.ResetTimer()
	for range b.N {
		generateTransportServerConfig(params)
	}
}

func BenchmarkUpdateEndpointsForVirtualServers(b *testing.B) {
	cnf, err := createTestConfiguratorBench()
	if err != nil {
		b.Fatal(err)
	}
	virtualServerEx := vsExWithEndpoints()

	// Initial add so the VS exists for endpoint updates.
	if _, err := cnf.AddOrUpdateVirtualServer(&virtualServerEx); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := cnf.UpdateEndpointsForVirtualServers([]*VirtualServerEx{&virtualServerEx})
		if err != nil {
			b.Fatal(err)
		}
	}
}
