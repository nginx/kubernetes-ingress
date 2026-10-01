package configs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// osReadFile / osWriteFile / osMkdirAll / bytesEqual are aliases so the
// diskManager helper reads cleanly without importing os/bytes in every
// caller. They're plain wrappers, no test-only behavior.
var (
	osReadFile  = os.ReadFile
	osWriteFile = os.WriteFile
	osMkdirAll  = os.MkdirAll
	bytesEqual  = bytes.Equal
)

// recordingBatchManager wraps FakeManager and records calls to the reload
// paths gated by Configurator.isReloadsEnabled — Reload and the Plus API
// upstream writes. Referenced by the batch/reload regression tests for
// https://github.com/nginx/kubernetes-ingress/pull/7779 and
// https://github.com/nginx/kubernetes-ingress/issues/10397.
type recordingBatchManager struct {
	*nginx.FakeManager
	reloads             atomic.Int32
	updateServersInPlus atomic.Int32
	updateStreamServers atomic.Int32
}

func newRecordingBatchManager() *recordingBatchManager {
	return &recordingBatchManager{FakeManager: nginx.NewFakeManager("/etc/nginx")}
}

func (m *recordingBatchManager) Reload(isEndpointsUpdate bool) error {
	m.reloads.Add(1)
	return m.FakeManager.Reload(isEndpointsUpdate)
}

func (m *recordingBatchManager) UpdateServersInPlus(upstream string, servers []string, cfg nginx.ServerConfig) error {
	m.updateServersInPlus.Add(1)
	return m.FakeManager.UpdateServersInPlus(upstream, servers, cfg)
}

func (m *recordingBatchManager) UpdateStreamServersInPlus(upstream string, servers []string) error {
	m.updateStreamServers.Add(1)
	return m.FakeManager.UpdateStreamServersInPlus(upstream, servers)
}

// TestBatchModeDropsPlusEndpointUpdates highlights the regression that
// PR #7779 (https://github.com/nginx/kubernetes-ingress/pull/7779) introduces
// on top of the pre-existing behavior flagged in issue #7778.
//
// During batch sync, sync() calls Configurator.DisableReloads() at batch start.
// The same isReloadsEnabled flag also gates updateServersInPlus /
// updateStreamServersInPlus (see Configurator.updateServersInPlus), which
// silently return nil when reloads are disabled. Before PR #7779, the safety
// net was ReloadForBatchUpdates(true) at queue drain: it picked up the freshly
// rewritten config with the new endpoints. PR #7779 removes that reload for
// endpointslice-only batches on Plus without lifting the API gate, so during
// a batch neither path applies endpoint changes to the running NGINX Plus.
//
// The test asserts the *correct* behavior (the Plus API upstream write should
// still fire during a batch). It therefore FAILS on current main and will
// only pass once updateServersInPlus is ungated during batch, or an explicit
// Plus API flush runs at batch end.
func TestBatchModeDropsPlusEndpointUpdates(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	cnf := createTestConfiguratorWithManager(t, mgr)
	cnf.isPlus = true

	vsEx := &VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{Name: "cafe", Namespace: "default"},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{Name: "tea", Service: "tea-svc", Port: 80},
				},
				Routes: []conf_v1.Route{
					{Path: "/tea", Action: &conf_v1.Action{Pass: "tea"}},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {"10.0.0.1:80"},
		},
	}

	if err := cnf.updatePlusEndpointsForVirtualServer(vsEx); err != nil {
		t.Fatalf("baseline updatePlusEndpointsForVirtualServer: %v", err)
	}
	if got := mgr.updateServersInPlus.Load(); got != 1 {
		t.Fatalf("baseline UpdateServersInPlus calls = %d, want 1", got)
	}

	// sync() enters batch mode when the work queue has more than one item.
	cnf.DisableReloads()

	// Endpointslice update during the batch: fresh pod IP arrives.
	vsEx.Endpoints["default/tea-svc:80"] = []string{"10.0.0.2:80"}
	if err := cnf.updatePlusEndpointsForVirtualServer(vsEx); err != nil {
		t.Fatalf("in-batch updatePlusEndpointsForVirtualServer: %v", err)
	}

	if got := mgr.updateServersInPlus.Load(); got != 2 {
		t.Fatalf("Plus API upstream write suppressed during batch: UpdateServersInPlus calls = %d, want 2 "+
			"(PR #7779 relies on the Plus API to propagate endpoints while it skips the reload; "+
			"the same isReloadsEnabled flag suppresses that API call, so endpoints go stale)", got)
	}

	// PR #7779's Plus batch-end path: ReloadForBatchUpdates(false), a no-op.
	cnf.EnableReloads()
	if err := cnf.ReloadForBatchUpdates(false); err != nil {
		t.Fatalf("ReloadForBatchUpdates: %v", err)
	}
	if got := mgr.reloads.Load(); got != 0 {
		t.Fatalf("PR #7779 Plus path: reload count = %d, want 0 "+
			"(confirms neither path applies endpoints; the running NGINX Plus "+
			"stays on pre-batch upstream membership until a subsequent non-batch "+
			"event arrives for this service)", got)
	}
}

// TestBatchModeSilentlyDropsOSSReload demonstrates the primitive that
// amplifies into issue #10397 (https://github.com/nginx/kubernetes-ingress/issues/10397)
// at the controller level: while batching is active, every call to
// Configurator.Reload is a silent no-op regardless of how much fresh config
// gets written to disk. sync() only re-enables reloads and fires
// ReloadForBatchUpdates when syncQueue.Len() == 0. Under sustained
// endpointslice churn the queue never drains, so a real config change
// (Ingress / VirtualServer / TransportServer) enqueued during the batch has
// its reload deferred by the duration of the churn — the "stale IPs for
// several minutes" symptom reported in #10397.
//
// See TestOSSBatchNeverDrainsUnderEndpointsliceChurn in the internal/k8s
// package for the end-to-end amplification driven through sync().
func TestBatchModeSilentlyDropsOSSReload(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	cnf := createTestConfiguratorWithManager(t, mgr)
	cnf.isPlus = false

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		t.Fatalf("baseline Reload: %v", err)
	}
	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("baseline reload count = %d, want 1", got)
	}

	// sync() enters batch mode when queue.Len() > 1.
	cnf.DisableReloads()

	// Three config-relevant events land during the batch: two endpointslice
	// updates (OSS: reload required to apply) and one Ingress change. All
	// are silently dropped by Reload().
	for i := 0; i < 3; i++ {
		if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
			t.Fatalf("in-batch Reload #%d: %v", i, err)
		}
	}
	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("in-batch reload count = %d, want 1 (all three in-batch reloads should be deferred)", got)
	}

	// sync() only calls ReloadForBatchUpdates when syncQueue.Len() == 0.
	// Under continuous endpointslice churn (#10397) this never happens until
	// the churn subsides.
	cnf.EnableReloads()
	if err := cnf.ReloadForBatchUpdates(true); err != nil {
		t.Fatalf("ReloadForBatchUpdates: %v", err)
	}
	if got := mgr.reloads.Load(); got != 2 {
		t.Fatalf("post-batch reload count = %d, want 2", got)
	}
}

// newBenchConfigurator builds a Configurator against the real templates,
// suitable for both *testing.T and *testing.B callers. It intentionally
// omits the isReloadsEnabled=true toggle that createTestConfigurator does,
// so the caller controls batch state per sub-benchmark.
func newBenchConfigurator(tb testing.TB, mgr nginx.Manager, isPlus bool) *Configurator {
	tb.Helper()
	v1Exec, err := version1.NewTemplateExecutor("version1/nginx-plus.tmpl", "version1/nginx-plus.ingress.tmpl")
	if err != nil {
		tb.Fatalf("v1 template executor: %v", err)
	}
	v2Exec, err := version2.NewTemplateExecutor("version2/nginx-plus.virtualserver.tmpl", "version2/nginx-plus.transportserver.tmpl", "version2/oidc.tmpl")
	if err != nil {
		tb.Fatalf("v2 template executor: %v", err)
	}
	return NewConfigurator(ConfiguratorParams{
		NginxManager:       mgr,
		StaticCfgParams:    &StaticConfigParams{NginxVersion: nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)")},
		Config:             NewDefaultConfigParams(context.Background(), isPlus),
		MGMTCfgParams:      NewDefaultMGMTConfigParams(context.Background()),
		TemplateExecutor:   v1Exec,
		TemplateExecutorV2: v2Exec,
		IsPlus:             isPlus,
		NginxVersion:       nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)"),
	})
}

// makeVSExWithUpstreams builds a VirtualServerEx with `upstreams` upstreams,
// each carrying `endpoints` endpoints. Larger fanouts are the ones that make
// createUpstreamsForPlus + generateUpstream + template execution expensive.
func makeVSExWithUpstreams(upstreams, endpoints int) *VirtualServerEx {
	spec := conf_v1.VirtualServerSpec{Host: "cafe.example.com"}
	eps := map[string][]string{}
	for u := 0; u < upstreams; u++ {
		name := fmt.Sprintf("u%d", u)
		svc := fmt.Sprintf("svc-%d", u)
		spec.Upstreams = append(spec.Upstreams, conf_v1.Upstream{Name: name, Service: svc, Port: 80})
		spec.Routes = append(spec.Routes, conf_v1.Route{
			Path:   fmt.Sprintf("/p%d", u),
			Action: &conf_v1.Action{Pass: name},
		})
		key := fmt.Sprintf("default/%s:80", svc)
		addrs := make([]string, 0, endpoints)
		for e := 0; e < endpoints; e++ {
			addrs = append(addrs, fmt.Sprintf("10.%d.%d.%d:80", u/256, u%256, e+1))
		}
		eps[key] = addrs
	}
	return &VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{Name: "cafe", Namespace: "default"},
			Spec:       spec,
		},
		Endpoints: eps,
	}
}

// BenchmarkUpdateEndpointsForVirtualServers measures the cost of the code
// path syncEndpointSlices takes for every endpointslice event that hits a
// VirtualServer. This is the realistic hot path — unlike
// BenchmarkSyncBatchChurn (informer miss), each iteration here runs
// addOrUpdateVirtualServer (template execution + config write) and, on Plus,
// updatePlusEndpointsForVirtualServer.
//
// Sub-benchmarks span the 2×2 matrix of {OSS, Plus} × {BatchOff, BatchOn}:
//
//   - OSS/BatchOff : template exec + config write + Reload (fake).
//   - OSS/BatchOn  : template exec + config write; Reload gated → shows the
//     wasted config regen cost during batch.
//   - Plus/BatchOff: template exec + config write + Plus API call (fake).
//   - Plus/BatchOn : template exec + config write; Plus API gated → matches
//     the PR #7779 scenario where endpoints never leave the process.
//
// Collect a CPU profile with:
//
//	go test -run='^$' -bench=BenchmarkUpdateEndpointsForVirtualServers \
//	    -cpuprofile=/tmp/uev.pprof ./internal/configs
//	go tool pprof -http=: /tmp/uev.pprof
//
// The pprof top / flame graph will attribute time to
// createUpstreamsForPlus, template.Execute, and addOrUpdate* — those are
// the primary optimisation targets for making batch drain faster.
func BenchmarkUpdateEndpointsForVirtualServers(b *testing.B) {
	cases := []struct {
		name    string
		isPlus  bool
		batchOn bool
	}{
		{"OSS/BatchOff", false, false},
		{"OSS/BatchOn", false, true},
		{"Plus/BatchOff", true, false},
		{"Plus/BatchOn", true, true},
	}

	// Two fanouts: a "small" ingress and one closer to what a busy cluster
	// hits (many services on one VS).
	sizes := []struct {
		name              string
		upstreams, endpts int
	}{
		{"1u_3ep", 1, 3},
		{"10u_5ep", 10, 5},
		{"50u_10ep", 50, 10},
	}

	for _, c := range cases {
		for _, s := range sizes {
			name := c.name + "/" + s.name
			b.Run(name, func(b *testing.B) {
				mgr := nginx.NewFakeManager("/etc/nginx")
				cnf := newBenchConfigurator(b, mgr, c.isPlus)
				vsEx := makeVSExWithUpstreams(s.upstreams, s.endpts)

				// Warm-up: register the VS so subsequent calls exercise the
				// "update" branch, matching steady-state churn.
				cnf.EnableReloads()
				if _, err := cnf.UpdateEndpointsForVirtualServers([]*VirtualServerEx{vsEx}); err != nil {
					b.Fatalf("warm-up: %v", err)
				}
				if c.batchOn {
					cnf.DisableReloads()
				}

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := cnf.UpdateEndpointsForVirtualServers([]*VirtualServerEx{vsEx}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// diskManager wraps FakeManager and replaces CreateConfig with a real disk
// write into a tmpdir, matching what LocalManager.CreateConfig does in
// production (createFileAndWrite: os.Create + Write + Close, no fsync).
// It also mimics LocalManager's read-then-compare-then-write pattern via
// configContentsChanged, so the recorded I/O reflects both the read and
// the write path.
type diskManager struct {
	*nginx.FakeManager
	confdDir string
}

func newDiskManager(tb testing.TB) *diskManager {
	tb.Helper()
	root := tb.TempDir()
	confd := root + "/conf.d"
	if err := osMkdirAll(confd, 0o755); err != nil {
		tb.Fatalf("mkdir confd: %v", err)
	}
	return &diskManager{FakeManager: nginx.NewFakeManager(root), confdDir: confd}
}

func (m *diskManager) CreateConfig(name string, content []byte) (bool, error) {
	filename := m.confdDir + "/" + name + ".conf"
	// Mirror LocalManager.configContentsChanged: read existing then compare.
	existing, _ := osReadFile(filename)
	changed := !bytesEqual(existing, content)
	if err := osWriteFile(filename, content, 0o644); err != nil {
		return false, err
	}
	return changed, nil
}

// BenchmarkUpdateEndpointsForVirtualServersWithDisk mirrors
// BenchmarkUpdateEndpointsForVirtualServers but replaces the in-memory
// FakeManager.CreateConfig with a real disk write into t.TempDir(), so
// the ns/op number includes actual filesystem I/O. Compare against the
// no-disk benchmark: the delta is the disk cost per event.
//
// Real hardware is highly variable — tmpfs/APFS on a laptop is not what a
// prod pod sees. Take the shape of the numbers, not the absolute values.
func BenchmarkUpdateEndpointsForVirtualServersWithDisk(b *testing.B) {
	// Only the OSS/BatchOff × Plus/BatchOff variants for the interesting
	// fanouts: BatchOn does the same config write, so the disk cost is
	// identical to BatchOff.
	sizes := []struct {
		name              string
		upstreams, endpts int
	}{
		{"1u_3ep", 1, 3},
		{"10u_5ep", 10, 5},
		{"50u_10ep", 50, 10},
	}
	for _, isPlus := range []bool{false, true} {
		flavor := "OSS"
		if isPlus {
			flavor = "Plus"
		}
		for _, s := range sizes {
			b.Run(flavor+"/"+s.name, func(b *testing.B) {
				mgr := newDiskManager(b)
				cnf := newBenchConfigurator(b, mgr, isPlus)
				vsEx := makeVSExWithUpstreams(s.upstreams, s.endpts)

				cnf.EnableReloads()
				if _, err := cnf.UpdateEndpointsForVirtualServers([]*VirtualServerEx{vsEx}); err != nil {
					b.Fatalf("warm-up: %v", err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := cnf.UpdateEndpointsForVirtualServers([]*VirtualServerEx{vsEx}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
