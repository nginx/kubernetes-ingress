package k8s

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// recordingBatchManager wraps FakeManager and counts reload invocations.
// A minimal version that only records what the batch-drain deferral test
// needs to observe.
type recordingBatchManager struct {
	*nginx.FakeManager
	reloads atomic.Int32
}

func newRecordingBatchManager() *recordingBatchManager {
	return &recordingBatchManager{FakeManager: nginx.NewFakeManager("/etc/nginx")}
}

func (m *recordingBatchManager) Reload(isEndpointsUpdate bool) error {
	m.reloads.Add(1)
	return m.FakeManager.Reload(isEndpointsUpdate)
}

// newBatchTestLBC wires the minimal LoadBalancerController surface that
// sync() touches for endpointslice tasks and for tasks whose Kind is not
// covered by the dispatch switch. It intentionally omits the informer
// stores for ingress / VS / TS so tests must not enqueue those Kinds.
func newBatchTestLBC(tb testing.TB, mgr nginx.Manager) *LoadBalancerController {
	tb.Helper()

	esStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	nsi := &namespacedInformer{
		endpointSliceLister: storeToEndpointSliceLister{Store: esStore},
	}

	lbc := &LoadBalancerController{
		configurator:        newBatchTestConfigurator(tb, mgr),
		recorder:            record.NewFakeRecorder(100),
		Logger:              nl.LoggerFromContext(context.Background()),
		client:              fake.NewClientset(),
		isNginxReady:        true,
		namespacedInformers: map[string]*namespacedInformer{"default": nsi},
	}
	lbc.syncQueue = newTaskQueue(lbc.Logger, lbc.sync)
	tb.Cleanup(func() { lbc.syncQueue.queue.ShutDown() })
	return lbc
}

// newBatchTestConfigurator mirrors createTestPolicySyncConfigurator but
// accepts testing.TB so the same helper can back both tests and benchmarks.
func newBatchTestConfigurator(tb testing.TB, manager nginx.Manager) *configs.Configurator {
	tb.Helper()

	templateExecutor, err := version1.NewTemplateExecutor(
		filepath.Join("..", "configs", "version1", "nginx-plus.tmpl"),
		filepath.Join("..", "configs", "version1", "nginx-plus.ingress.tmpl"),
	)
	if err != nil {
		tb.Fatalf("v1 template executor: %v", err)
	}
	templateExecutorV2, err := version2.NewTemplateExecutor(
		filepath.Join("..", "configs", "version2", "nginx-plus.virtualserver.tmpl"),
		filepath.Join("..", "configs", "version2", "nginx-plus.transportserver.tmpl"),
		filepath.Join("..", "configs", "version2", "oidc.tmpl"),
	)
	if err != nil {
		tb.Fatalf("v2 template executor: %v", err)
	}
	return configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:       manager,
		StaticCfgParams:    &configs.StaticConfigParams{NginxVersion: nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)")},
		Config:             configs.NewDefaultConfigParams(context.Background(), false),
		MGMTCfgParams:      configs.NewDefaultMGMTConfigParams(context.Background()),
		TemplateExecutor:   templateExecutor,
		TemplateExecutorV2: templateExecutorV2,
	})
}

// TestOSSBatchNeverDrainsUnderEndpointsliceChurn drives sync() with a real
// syncQueue and demonstrates issue #10397
// (https://github.com/nginx/kubernetes-ingress/issues/10397): the deferred
// reload for a real config change is not fired while endpointslice churn
// keeps syncQueue.Len() > 0.
//
// Scenario:
//   - Batch mode is entered on the first sync (queue.Len() > 1).
//   - One non-endpointslice task early in the batch sets enableBatchReload=true
//     (models an Ingress/VS change that would need a reload).
//   - All other tasks are endpointslice events targeting a namespace whose
//     endpointSliceLister is empty — syncEndpointSlices returns false without
//     touching config, matching "endpointslice churn for services this
//     controller does not track".
//   - The test asserts no reload fires while queue.Len() > 0, then confirms
//     that ReloadForBatchUpdates(true) is called exactly once when the queue
//     finally drains.
//
// Fix criterion: the batch should finalize on a bounded time / item budget
// rather than exclusively on queue.Len() == 0.
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
				t.Fatalf("issue #10397: reload fired while queue.Len() = %d: reloads = %d, want 0",
					lbc.syncQueue.queue.Len(), got)
			}
		}
	}

	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("post-drain reload count = %d, want 1 (batch-end reload should fire exactly once)", got)
	}

	// The queue drained here because the test stops enqueuing. In production
	// the queue can stay non-empty for the entire duration of a rolling
	// deployment's endpointslice churn, deferring the reload for that long.
}

// TestOSSBatchReloadStarvedByContinuousChurn is the direct counterpart to
// TestOSSBatchNeverDrainsUnderEndpointsliceChurn: while
// TestOSSBatchNeverDrains... proves the batch-end reload fires *once* the
// queue drains, this test proves that reload never fires while churn keeps
// syncQueue.Len() > 0 — matching the reporter's symptom in
// https://github.com/nginx/kubernetes-ingress/issues/10397 of "several
// minutes of stale IPs" during a rolling deployment.
//
// A single "real" config change (dummy Ingress) is enqueued alongside
// endpointslice churn, then for each task processed a *new* endpointslice
// task is enqueued — modeling arrivals outpacing drain. After processing
// a large number of tasks, no reload has fired despite enableBatchReload
// being set on the first sync.
func TestOSSBatchReloadStarvedByContinuousChurn(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)

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
	}

	if lbc.syncQueue.queue.Len() == 0 {
		t.Fatal("test setup error: queue drained; churn injection failed")
	}
	if got := mgr.reloads.Load(); got != 0 {
		t.Fatalf("issue #10397: after %d syncs with continuous churn, reload count = %d, want 0 "+
			"(the reload for the ingress change should have been deferred by the batch-drain condition; "+
			"under sustained churn this deferral is unbounded)", processed, got)
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
