package configs

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

// ---------------------------------------------------------------------------
// memTracker -- per-iteration peak memory tracking for benchmarks
// ---------------------------------------------------------------------------

// memTracker records per-iteration allocation deltas via runtime.MemStats and
// reports peak/p99/mean values through b.ReportMetric. It adds ~1-5% overhead
// per iteration from ReadMemStats, which is acceptable for operations >50us.
//
// Usage:
//
//	mt := newMemTracker()
//	b.ResetTimer()
//	for range b.N {
//	    mt.before()
//	    // ... operation under test ...
//	    mt.after()
//	}
//	b.StopTimer()
//	mt.report(b)
type memTracker struct {
	iterAllocs []uint64 // bytes allocated per iteration
	iterObjs   []uint64 // objects allocated per iteration
	peakHeap   uint64   // max HeapInuse observed
	snap       runtime.MemStats
}

func newMemTracker() *memTracker {
	return &memTracker{
		iterAllocs: make([]uint64, 0, 1024),
		iterObjs:   make([]uint64, 0, 1024),
	}
}

func (mt *memTracker) before() {
	runtime.ReadMemStats(&mt.snap)
}

func (mt *memTracker) after() {
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	mt.iterAllocs = append(mt.iterAllocs, after.TotalAlloc-mt.snap.TotalAlloc)
	mt.iterObjs = append(mt.iterObjs, after.Mallocs-mt.snap.Mallocs)

	if after.HeapInuse > mt.peakHeap {
		mt.peakHeap = after.HeapInuse
	}
}

func (mt *memTracker) report(b *testing.B) {
	b.Helper()
	if len(mt.iterAllocs) == 0 {
		return
	}

	var maxAlloc, sumAlloc uint64
	var maxObjs, sumObjs uint64
	for i, a := range mt.iterAllocs {
		sumAlloc += a
		if a > maxAlloc {
			maxAlloc = a
		}
		o := mt.iterObjs[i]
		sumObjs += o
		if o > maxObjs {
			maxObjs = o
		}
	}

	n := uint64(len(mt.iterAllocs))
	b.ReportMetric(float64(maxAlloc), "peak-B/op")
	b.ReportMetric(float64(sumAlloc/n), "avg-B/op")
	b.ReportMetric(float64(maxObjs), "peak-allocs/op")
	b.ReportMetric(float64(sumObjs/n), "avg-allocs/op")
	b.ReportMetric(float64(mt.peakHeap)/(1024*1024), "peak-heap-MB")
}

// ---------------------------------------------------------------------------
// Scaled VS fixture generator
// ---------------------------------------------------------------------------

// vsExWithScale creates a VirtualServerEx with the given number of upstreams
// and routes, each with populated endpoints. This simulates configs of varying
// complexity to reveal scaling characteristics.
func vsExWithScale(numUpstreams, numRoutes int) VirtualServerEx {
	upstreams := make([]conf_v1.Upstream, 0, numUpstreams)
	endpoints := make(map[string][]string, numUpstreams)

	for i := range numUpstreams {
		name := fmt.Sprintf("svc-%d", i)
		upstreams = append(upstreams, conf_v1.Upstream{
			Name:    name,
			Service: name + "-svc",
			Port:    80,
		})
		endpoints[fmt.Sprintf("default/%s-svc:80", name)] = []string{
			fmt.Sprintf("10.0.%d.%d:80", i/256, i%256),
		}
	}

	routes := make([]conf_v1.Route, 0, numRoutes)
	for i := range numRoutes {
		upIdx := i % numUpstreams
		routes = append(routes, conf_v1.Route{
			Path: fmt.Sprintf("/path-%d", i),
			Action: &conf_v1.Action{
				Pass: upstreams[upIdx].Name,
			},
		})
	}

	return VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "scale-test",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host:      "scale.example.com",
				Upstreams: upstreams,
				Routes:    routes,
			},
		},
		Endpoints: endpoints,
	}
}

// ---------------------------------------------------------------------------
// Scaled benchmarks -- config generation at varying sizes
// ---------------------------------------------------------------------------

func BenchmarkGenerateVirtualServerConfig_Scale(b *testing.B) {
	scales := []struct {
		upstreams int
		routes    int
	}{
		{3, 6},     // small (typical)
		{10, 20},   // medium
		{50, 100},  // large
		{100, 200}, // very large
		{500, 500}, // extreme
	}

	for _, s := range scales {
		name := fmt.Sprintf("up=%d/rt=%d", s.upstreams, s.routes)
		vsEx := vsExWithScale(s.upstreams, s.routes)
		cfgParams := &ConfigParams{Context: context.Background()}
		staticParams := &StaticConfigParams{}

		b.Run(name, func(b *testing.B) {
			vsc := newVirtualServerConfigurator(cfgParams, false, false, staticParams, false, nil)
			mt := newMemTracker()
			b.ResetTimer()
			for range b.N {
				mt.before()
				vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)
				mt.after()
			}
			b.StopTimer()
			mt.report(b)
		})
	}
}

// ---------------------------------------------------------------------------
// Scaled benchmarks -- full path (config gen + template + file write)
// ---------------------------------------------------------------------------

func BenchmarkAddOrUpdateVirtualServer_Scale(b *testing.B) {
	scales := []struct {
		upstreams int
		routes    int
	}{
		{3, 6},     // small (typical)
		{10, 20},   // medium
		{50, 100},  // large
		{100, 200}, // very large
	}

	for _, s := range scales {
		name := fmt.Sprintf("up=%d/rt=%d", s.upstreams, s.routes)
		vsEx := vsExWithScale(s.upstreams, s.routes)

		b.Run(name, func(b *testing.B) {
			cnf, err := createTestConfiguratorBench()
			if err != nil {
				b.Fatal(err)
			}
			mt := newMemTracker()
			b.ResetTimer()
			for range b.N {
				mt.before()
				_, err := cnf.AddOrUpdateVirtualServer(&vsEx)
				if err != nil {
					b.Fatal(err)
				}
				mt.after()
			}
			b.StopTimer()
			mt.report(b)
		})
	}
}

// ---------------------------------------------------------------------------
// Burst simulation -- many VS configs loaded in rapid succession
// ---------------------------------------------------------------------------

// BenchmarkVirtualServerBurst simulates a reconciliation storm: N VirtualServer
// configs are generated and written in sequence (as happens during controller
// startup or a large batch apply). Reports peak heap and per-config allocation
// spikes across the entire burst.
func BenchmarkVirtualServerBurst(b *testing.B) {
	burstSizes := []int{10, 50, 100}

	for _, burstSize := range burstSizes {
		// Pre-generate distinct VS fixtures.
		fixtures := make([]VirtualServerEx, burstSize)
		for i := range burstSize {
			fixtures[i] = VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      fmt.Sprintf("vs-%d", i),
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: fmt.Sprintf("vs-%d.example.com", i),
						Upstreams: []conf_v1.Upstream{
							{Name: "tea", Service: "tea-svc", Port: 80},
							{Name: "coffee", Service: "coffee-svc", Port: 80},
						},
						Routes: []conf_v1.Route{
							{Path: "/tea", Action: &conf_v1.Action{Pass: "tea"}},
							{Path: "/coffee", Action: &conf_v1.Action{Pass: "coffee"}},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80":    {"10.0.0.1:80"},
					"default/coffee-svc:80": {"10.0.0.2:80"},
				},
			}
		}

		b.Run(fmt.Sprintf("burst=%d", burstSize), func(b *testing.B) {
			cnf, err := createTestConfiguratorBench()
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for range b.N {
				// Force GC before each burst to get a clean heap baseline.
				runtime.GC()
				var baseline, peak runtime.MemStats
				runtime.ReadMemStats(&baseline)

				// Simulate the burst: load all VS configs in sequence.
				for j := range fixtures {
					if _, err := cnf.AddOrUpdateVirtualServer(&fixtures[j]); err != nil {
						b.Fatal(err)
					}
				}

				runtime.ReadMemStats(&peak)
				b.ReportMetric(float64(peak.TotalAlloc-baseline.TotalAlloc)/float64(burstSize), "burst-avg-B/vs")
				b.ReportMetric(float64(peak.HeapInuse-baseline.HeapInuse)/(1024*1024), "burst-heap-delta-MB")
				b.ReportMetric(float64(peak.NumGC-baseline.NumGC), "burst-gc-cycles")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Template execution at scale
// ---------------------------------------------------------------------------

func BenchmarkExecuteVirtualServerTemplate_Scale(b *testing.B) {
	scales := []struct {
		upstreams int
		locations int
	}{
		{3, 6},
		{10, 20},
		{50, 100},
		{100, 200},
	}

	for _, s := range scales {
		name := fmt.Sprintf("up=%d/loc=%d", s.upstreams, s.locations)

		// Build a version2.VirtualServerConfig directly at the desired scale.
		cfg := buildScaledVSConfig(s.upstreams, s.locations)

		b.Run(name, func(b *testing.B) {
			executor, err := version2.NewTemplateExecutor(
				"version2/nginx-plus.virtualserver.tmpl",
				"version2/nginx-plus.transportserver.tmpl",
				"version2/oidc.tmpl",
			)
			if err != nil {
				b.Fatal(err)
			}
			mt := newMemTracker()
			b.ResetTimer()
			for range b.N {
				mt.before()
				_, err := executor.ExecuteVirtualServerTemplate(cfg)
				if err != nil {
					b.Fatal(err)
				}
				mt.after()
			}
			b.StopTimer()
			mt.report(b)
		})
	}
}

// buildScaledVSConfig creates a version2.VirtualServerConfig with the given
// number of upstreams and locations for template execution benchmarks.
func buildScaledVSConfig(numUpstreams, numLocations int) *version2.VirtualServerConfig {
	upstreams := make([]version2.Upstream, 0, numUpstreams)
	for i := range numUpstreams {
		upstreams = append(upstreams, version2.Upstream{
			Name: fmt.Sprintf("vs_default_scale_%s", fmt.Sprintf("svc-%d", i)),
			Servers: []version2.UpstreamServer{
				{Address: fmt.Sprintf("10.0.%d.%d:80", i/256, i%256)},
			},
			UpstreamLabels: version2.UpstreamLabels{
				Service:           fmt.Sprintf("svc-%d", i),
				ResourceType:      "virtualserver",
				ResourceName:      "scale-test",
				ResourceNamespace: "default",
			},
		})
	}

	locations := make([]version2.Location, 0, numLocations)
	for i := range numLocations {
		upIdx := i % numUpstreams
		locations = append(locations, version2.Location{
			Path:                     fmt.Sprintf("/path-%d", i),
			ProxyPass:                fmt.Sprintf("http://%s", upstreams[upIdx].Name),
			ProxyConnectTimeout:      "60s",
			ProxyReadTimeout:         "60s",
			ProxySendTimeout:         "60s",
			ClientMaxBodySize:        "1m",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyPassRequestHeaders:  true,
		})
	}

	return &version2.VirtualServerConfig{
		Upstreams: upstreams,
		Server: version2.Server{
			ServerName: "scale.example.com",
			StatusZone: "scale.example.com",
			Locations:  locations,
		},
	}
}
