package k8s

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"

	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// recordingBatchManager wraps FakeManager to distinguish the two batch-end
// reload paths taken by LoadBalancerController.sync():
//   - reloads counts every nginxManager.Reload() call (both paths call it).
//   - mainConfigs counts CreateMainConfig() calls, which are only reached
//     from updateAllConfigs() → configurator.UpdateConfig(). The
//     ReloadForBatchUpdates() path never calls CreateMainConfig, so this
//     counter is the observable signal for "updateAllConfigs was called".
type recordingBatchManager struct {
	*nginx.FakeManager
	reloads     atomic.Int32
	mainConfigs atomic.Int32
}

func newRecordingBatchManager() *recordingBatchManager {
	return &recordingBatchManager{FakeManager: nginx.NewFakeManager("/etc/nginx")}
}

func (m *recordingBatchManager) Reload(isEndpointsUpdate bool) error {
	m.reloads.Add(1)
	return m.FakeManager.Reload(isEndpointsUpdate)
}

func (m *recordingBatchManager) CreateMainConfig(content []byte) (bool, error) {
	m.mainConfigs.Add(1)
	return m.FakeManager.CreateMainConfig(content)
}

// newBatchTestLBC wires the minimum LoadBalancerController surface needed
// to drive batch-mode sync() drains to completion. Tests must only enqueue
// Kinds whose sync handler works with the sparsely-wired informer stores
// here (endpointslice with an empty lister, or configMap with a key that
// does not match the LBC's configured names).
func newBatchTestLBC(tb testing.TB, mgr nginx.Manager) *LoadBalancerController {
	tb.Helper()

	esStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	nsi := &namespacedInformer{
		endpointSliceLister: storeToEndpointSliceLister{Store: esStore},
	}

	lbc := &LoadBalancerController{
		configurator: newBatchTestConfigurator(tb, mgr),
		configuration: NewConfiguration(
			func(interface{}) bool { return true },
			false, false, false,
			validation.NewVirtualServerValidator(),
			validation.NewGlobalConfigurationValidator(map[int]bool{}),
			validation.NewTransportServerValidator(false, false, false),
			false, false, false, false, false, false,
		),
		recorder:            record.NewFakeRecorder(100),
		Logger:              nl.LoggerFromContext(context.Background()),
		client:              fake.NewClientset(),
		isNginxReady:        true,
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"default": nsi}),
		metadata: controllerMetadata{
			pod: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					OwnerReferences: []meta_v1.OwnerReference{
						{Kind: "ReplicaSet", Name: "test-ic-abc123"},
					},
				},
			},
		},
	}
	lbc.syncQueue = newTaskQueue(lbc.Logger, lbc.sync)
	tb.Cleanup(func() { lbc.syncQueue.queue.ShutDown() })
	return lbc
}

// newBatchTestConfigurator returns a real *configs.Configurator wired against
// the OSS templates so batch-drain code paths (DisableReloads / EnableReloads
// / UpdateConfig / ReloadForBatchUpdates) execute without stubs.
func newBatchTestConfigurator(tb testing.TB, manager nginx.Manager) *configs.Configurator {
	tb.Helper()

	templateExecutor, err := version1.NewTemplateExecutor(
		filepath.Join("..", "configs", "version1", "nginx.tmpl"),
		filepath.Join("..", "configs", "version1", "nginx.ingress.tmpl"),
	)
	if err != nil {
		tb.Fatalf("v1 template executor: %v", err)
	}
	templateExecutorV2, err := version2.NewTemplateExecutor(
		filepath.Join("..", "configs", "version2", "nginx.virtualserver.tmpl"),
		filepath.Join("..", "configs", "version2", "nginx.transportserver.tmpl"),
		filepath.Join("..", "configs", "version2", "oidc.tmpl"),
	)
	if err != nil {
		tb.Fatalf("v2 template executor: %v", err)
	}
	return configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:       manager,
		StaticCfgParams:    &configs.StaticConfigParams{NginxVersion: nginx.NewVersion("nginx version: nginx/1.25.3")},
		Config:             configs.NewDefaultConfigParams(context.Background(), false),
		MGMTCfgParams:      configs.NewDefaultMGMTConfigParams(context.Background()),
		TemplateExecutor:   templateExecutor,
		TemplateExecutorV2: templateExecutorV2,
	})
}

// drainSyncQueue processes items until the queue is empty, invoking sync
// directly rather than via taskQueue.Run so the test can observe controller
// state between batches without racing the worker goroutine.
func drainSyncQueue(t *testing.T, lbc *LoadBalancerController) {
	t.Helper()
	for lbc.syncQueue.queue.Len() > 0 {
		obj, quit := lbc.syncQueue.queue.Get()
		if quit {
			t.Fatal("queue shut down mid-test")
		}
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)
	}
}

// TestBatchModeResetsUpdateAllConfigsFlag verifies that the
// updateAllConfigsOnBatch flag is cleared at the end of every batch drain.
// If the flag stays sticky, every subsequent batch keeps taking the heavy
// updateAllConfigs() path instead of the lighter ReloadForBatchUpdates()
// path, even when the batch did not contain a ConfigMap task.
//
// Two consecutive batches are driven through sync():
//
//	batch 1: ConfigMap + endpointslice tasks
//	  → updateAllConfigsOnBatch is set inside the configMap case
//	  → batch-end must call updateAllConfigs() (observed as
//	    CreateMainConfig() = 1 on the recording manager)
//	  → flag must be reset to false after drain
//
//	batch 2: endpointslice tasks only, no ConfigMap
//	  → batch-end must take ReloadForBatchUpdates() (no CreateMainConfig)
//	  → CreateMainConfig() must remain 1; a sticky flag would push it to 2
func TestBatchModeResetsUpdateAllConfigsFlag(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)

	// Batch 1: enqueue >1 tasks so batch mode activates on the first sync.
	// ConfigMap first so the case-configMap branch sets
	// updateAllConfigsOnBatch=true; endpointslice tasks then keep the
	// queue non-empty while batch mode persists. The empty
	// endpointSliceLister makes each endpointslice task a no-op.
	lbc.syncQueue.queue.Add(task{Kind: configMap, Key: "nginx-ingress/nginx-config"})
	for i := 0; i < 3; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-a-%d", i)})
	}

	drainSyncQueue(t, lbc)

	if got := mgr.mainConfigs.Load(); got != 1 {
		t.Fatalf("batch 1: CreateMainConfig calls = %d, want 1 (updateAllConfigs must fire when a batch contains a ConfigMap)", got)
	}
	if lbc.updateAllConfigsOnBatch {
		t.Fatal("batch 1: updateAllConfigsOnBatch still true after drain — reset missing")
	}
	if lbc.batchSyncEnabled {
		t.Fatal("batch 1: batchSyncEnabled still true after drain")
	}

	// Batch 2: no ConfigMap. Batch-end must take the ReloadForBatchUpdates
	// path — CreateMainConfig must not fire again. A sticky flag from
	// batch 1 would cause updateAllConfigs to run and increment the counter.
	for i := 0; i < 4; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-b-%d", i)})
	}

	drainSyncQueue(t, lbc)

	if got := mgr.mainConfigs.Load(); got != 1 {
		t.Fatalf("batch 2: CreateMainConfig calls = %d, want still 1 — sticky updateAllConfigsOnBatch would cause updateAllConfigs to fire again", got)
	}
	if lbc.updateAllConfigsOnBatch {
		t.Fatal("batch 2: updateAllConfigsOnBatch became true without a ConfigMap task in the batch")
	}
	if lbc.batchSyncEnabled {
		t.Fatal("batch 2: batchSyncEnabled still true after drain")
	}
}

// TestOSSBatchNeverDrainsUnderEndpointsliceChurn drives sync() with a real
// syncQueue and demonstrates issue #10397
// (https://github.com/nginx/kubernetes-ingress/issues/10397): without a
// bounded batch window, the deferred reload for a real config change is not
// fired while endpointslice churn keeps syncQueue.Len() > 0.
//
// Scenario:
//   - Batch mode is entered on the first sync (queue.Len() > 1).
//   - One non-endpointslice task early in the batch sets enableBatchReload=true
//     (models an Ingress/VS change that would need a reload).
//   - All other tasks are endpointslice events targeting a namespace whose
//     endpointSliceLister is empty — syncEndpointSlices returns false without
//     touching config, matching "endpointslice churn for services this
//     controller does not track".
//   - batchReloadWindow is left at its zero value (disabled), so this test
//     pins the pre-fix, unbounded-drain semantics: no reload fires while
//     queue.Len() > 0, and the batch-end reload fires exactly once when the
//     queue finally drains. All 51 syncs run synchronously in well under the
//     production batchReloadWindowDefault, so this is unaffected by the fix
//     in TestBatchEndsOnWindowUnderContinuousChurn below.
func TestOSSBatchNeverDrainsUnderEndpointsliceChurn(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)

	const churnCount = 50

	// One config-relevant task (any Kind that != endpointslice). We use a
	// value outside the switch cases so dispatch is a no-op, but the top-of-
	// sync branch still sets enableBatchReload=true because the Kind is not
	// endpointslice.
	const configRelevant = 999
	lbc.syncQueue.queue.Add(task{Kind: configRelevant, Key: "default/dummy-ingress"})

	// Sustained endpointslice churn from unrelated services. Each task must
	// carry a distinct Key because workqueue.Add deduplicates on the item
	// value; identical tasks would collapse into a single queue entry.
	for i := 0; i < churnCount; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/churn-svc-%d", i)})
	}

	for lbc.syncQueue.queue.Len() > 0 {
		obj, quit := lbc.syncQueue.queue.Get()
		if quit {
			t.Fatal("queue shut down mid-test")
		}
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)

		if lbc.syncQueue.queue.Len() > 0 {
			if got := mgr.reloads.Load(); got != 0 {
				t.Fatalf("reload fired while queue.Len() = %d: reloads = %d, want 0",
					lbc.syncQueue.queue.Len(), got)
			}
		}
	}

	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("post-drain reload count = %d, want 1 (batch-end reload should fire exactly once)", got)
	}
}

// TestBatchEndsOnWindowUnderContinuousChurn is the fix-side counterpart to
// TestOSSBatchNeverDrainsUnderEndpointsliceChurn: it drives the same
// continuous-arrivals-outpacing-drain scenario from issue #10397
// (https://github.com/nginx/kubernetes-ingress/issues/10397) — a single
// "real" config change (dummy Ingress) enqueued alongside endpointslice
// churn, with a *new* endpointslice task enqueued for every task processed
// so arrivals outpace drain and syncQueue.Len() never reaches 0 — but with
// batchReloadWindow set to a tiny positive duration (matching what
// NewLoadBalancerController wires up in production via
// batchReloadWindowDefault). It asserts the fix actually closes the gap:
// the pending reload fires well before the churn itself stops, instead of
// being deferred for the full duration of a rolling deployment.
func TestBatchEndsOnWindowUnderContinuousChurn(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)
	lbc.batchReloadWindow = time.Microsecond

	// Enter batch mode: at least two items so queue.Len() > 1 on first sync.
	const configRelevant = 999
	lbc.syncQueue.queue.Add(task{Kind: configRelevant, Key: "default/user-ingress"})
	for i := 0; i < 5; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-init-%d", i)})
	}

	const maxProcessed = 200
	processed := 0
	for lbc.syncQueue.queue.Len() > 0 && processed < maxProcessed {
		obj, quit := lbc.syncQueue.queue.Get()
		if quit {
			t.Fatal("queue shut down mid-test")
		}
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)

		// New endpointslice event arrives — models arrivals outpacing drain.
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-churn-%d", processed)})
		processed++

		if mgr.reloads.Load() > 0 {
			break
		}
	}

	if lbc.syncQueue.queue.Len() == 0 {
		t.Fatal("test setup error: queue drained; churn injection failed")
	}
	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("issue #10397 fix: after %d syncs with continuous churn and a %s batch window, "+
			"reload count = %d, want 1 (the batch window should force the deferred reload to fire "+
			"even though the queue never drains)", processed, lbc.batchReloadWindow, got)
	}
}

// TestBatchWindowRepeatsAcrossMultipleCycles strengthens
// TestBatchEndsOnWindowUnderContinuousChurn, which only proves the window
// forces a *single* reload and then stops. It does not prove that, once a
// window-triggered batch ends, sync() actually re-enters batch mode and
// applies a *fresh* window for the next cycle — i.e. that under sustained
// churn the controller keeps reloading periodically for as long as the
// churn (and real config changes) continue, rather than reloading once and
// then going silent again (which would just move the staleness problem
// from "forever" to "forever after the first window").
//
// This is driven by real wall-clock time rather than a fixed iteration
// count, because the thing under test — LoadBalancerController.batchStart
// being reset on every new batch entry (see sync() in controller.go) — is
// itself wall-clock based. A recurring non-endpointslice task is re-added
// every iteration alongside endpointslice churn, modeling continuous real
// Ingress/VS changes arriving throughout a rolling deployment, so every
// window has genuine pending work to reload (pure untracked-endpoint churn
// with nothing referencing it correctly produces zero reloads — that's the
// #7778 fix, not a bug — so asserting repetition requires real work).
func TestBatchWindowRepeatsAcrossMultipleCycles(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)
	const window = 10 * time.Millisecond
	const testDuration = 150 * time.Millisecond // 15x window: generous margin for slow/loaded CI runners.
	const minReloads = 3                        // conservative: observed ~15 on a dev laptop; only prove repetition, not a precise rate.
	lbc.batchReloadWindow = window

	const configRelevant = 999
	lbc.syncQueue.queue.Add(task{Kind: configRelevant, Key: "default/user-ingress"})
	for i := 0; i < 5; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-init-%d", i)})
	}

	deadline := time.Now().Add(testDuration)
	processed := 0
	for time.Now().Before(deadline) {
		obj, quit := lbc.syncQueue.queue.Get()
		if quit {
			t.Fatal("queue shut down mid-test")
		}
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)

		// Re-add both a recurring "real" config change and endpointslice
		// churn every iteration, so every batch window has genuine pending
		// work — unlike TestBatchEndsOnWindowUnderContinuousChurn, which only
		// seeds one real task and therefore only ever proves one reload.
		lbc.syncQueue.queue.Add(task{Kind: configRelevant, Key: fmt.Sprintf("default/real-%d", processed)})
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-churn-%d", processed)})
		processed++
	}

	if got := mgr.reloads.Load(); got < minReloads {
		t.Fatalf("reload count = %d over %s of continuous real-work churn with a %s batch window, want >= %d "+
			"(the batch must re-enter and reload again every window as long as churn continues, "+
			"not just once)", got, testDuration, window, minReloads)
	}
}

// BenchmarkSyncBatchChurn profiles the per-task cost of sync() while batch
// mode is active and the queue is dominated by endpointslice events that
// don't produce useful work (informer miss). This is the hot path in the
// churn scenario from issue #10397.
//
// Run:
//
//	go test -run='^$' -bench=BenchmarkSyncBatchChurn -benchmem \
//	    -cpuprofile=/tmp/sync_cpu.pprof -memprofile=/tmp/sync_mem.pprof \
//	    ./internal/k8s
//	go tool pprof -http=: /tmp/sync_cpu.pprof
//
// The point of interest is what fraction of CPU is spent in workqueue
// bookkeeping, informer store lookups, and logging vs. any actual reload
// or Plus API work.
func BenchmarkSyncBatchChurn(b *testing.B) {
	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(b, mgr)

	// Prime batch mode by enqueuing a second dummy task so queue.Len() > 1
	// on the first sync() call. This dummy stays in the queue for the
	// whole benchmark so batch mode never exits.
	lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: "default/anchor"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/churn-%d", i)})
		obj, _ := lbc.syncQueue.queue.Get()
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)
	}
}
