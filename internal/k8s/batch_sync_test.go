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
	discovery_v1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
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
// This is driven by a fixed number of cycles with a manually backdated
// batchStart rather than real elapsed time, so the test has no dependency on
// wall-clock scheduling and cannot flake under a loaded or paused CI worker.
// batchReloadWindow is set to an hour (effectively "never elapses on its
// own"); each cycle enqueues one "real" config-relevant task (T1) plus three
// endpointslice tasks (T2-T4):
//
//   - processing T1 enters batch mode and records batchStart = time.Now().
//   - processing T2 must NOT end the batch (reload count unchanged) — this
//     is the baseline the backdating step is contrasted against.
//   - batchStart is then backdated two hours into the past, which is the
//     only way batchWindowElapsed can become true without sleeping.
//   - processing T3 (queue still non-empty) must end the batch via the
//     window check (not the drain check) and fire exactly one reload.
//   - processing T4 drains the queue to 0 with batch mode already off, so it
//     must not fire another reload and must not re-enter batch mode.
//
// The next cycle then re-enters batch mode on its own T1 and must record a
// fresh (non-backdated) batchStart — if sync() failed to reset batchStart on
// re-entry, the stale backdated value would make the new batch's window look
// already elapsed, ending it immediately at T1 instead of surviving T2.
// Asserting the reload count after T1 and T2 in every cycle is what proves
// that reset happens.
func TestBatchWindowRepeatsAcrossMultipleCycles(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)
	lbc.batchReloadWindow = time.Hour

	const configRelevant = 999
	const cycles = 3

	processNext := func() {
		obj, quit := lbc.syncQueue.queue.Get()
		if quit {
			t.Fatal("queue shut down mid-test")
		}
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)
	}

	for cycle := 0; cycle < cycles; cycle++ {
		lbc.syncQueue.queue.Add(task{Kind: configRelevant, Key: fmt.Sprintf("default/user-ingress-%d", cycle)})
		for i := 0; i < 3; i++ {
			lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/es-%d-%d", cycle, i)})
		}

		// T1: enters batch mode (queue.Len() > 1 after Get()) and sets a
		// fresh batchStart.
		processNext()
		// T2: endpointslice churn; must not end the batch.
		processNext()
		if got := mgr.reloads.Load(); got != int32(cycle) {
			t.Fatalf("cycle %d: reload count after T1+T2 = %d, want %d "+
				"(the batch window must not have elapsed yet — if this fired, "+
				"batchStart was not reset on re-entry into batch mode)", cycle, got, cycle)
		}

		// Backdate batchStart so the window check reports elapsed without
		// any real waiting.
		lbc.batchStart = time.Now().Add(-2 * time.Hour)

		// T3: queue is still non-empty (T4 remains), so this must end the
		// batch via the window check, not the drain check.
		processNext()
		if got := mgr.reloads.Load(); got != int32(cycle+1) {
			t.Fatalf("cycle %d: reload count after T3 = %d, want %d "+
				"(the backdated batchStart should force the window-based batch end)", cycle, got, cycle+1)
		}

		// T4: drains the queue to 0 with batch mode already off; must not
		// fire a second reload for this cycle.
		processNext()
		if got := mgr.reloads.Load(); got != int32(cycle+1) {
			t.Fatalf("cycle %d: reload count after T4 = %d, want %d (no reload should fire while batch mode is off)", cycle, got, cycle+1)
		}
		if lbc.batchSyncEnabled {
			t.Fatalf("cycle %d: batchSyncEnabled still true after queue drained", cycle)
		}
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

	// Prime batch mode with two anchor tasks. workqueue.Get() removes the
	// returned item from the queue before sync() checks syncQueue.Len(), so
	// with only one anchor plus one churn item added per iteration, Len()
	// is always 1 at that check and batch mode is never entered. Two
	// anchors leave Len() == 2 after the first Get(), which both triggers
	// batch mode and — since every later iteration adds exactly one churn
	// item per Get() — keeps Len() == 2 for the rest of the run, so batch
	// mode never exits (syncQueue.Len() never reaches 0).
	lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: "default/anchor-1"})
	lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: "default/anchor-2"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: fmt.Sprintf("default/churn-%d", i)})
		obj, _ := lbc.syncQueue.queue.Get()
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)
	}
}

// failOnDefaultServerManager makes CreateConfig fail only for
// configs.DefaultServerConfigName, simulating addOrUpdateIngress succeeding on the
// Ingress's own config write and then failing in the subsequent
// syncDefaultServerConfig() call in the same function — a partial write, not a clean
// failure. Embeds recordingBatchManager so reloads are still counted.
type failOnDefaultServerManager struct {
	*recordingBatchManager
}

func (m *failOnDefaultServerManager) CreateConfig(name string, content []byte) (bool, error) {
	if name == configs.DefaultServerConfigName {
		return false, fmt.Errorf("simulated CreateConfig failure for %s", name)
	}
	return m.FakeManager.CreateConfig(name, content)
}

// TestBatchReplicaChangeEndpointslicePartialWriteStillReloads drives the actual
// regression end-to-end through sync(), rather than calling the Configurator
// directly: an EndpointSlice event for the controller's own Service (detected via
// statusUpdater.namespace/externalServiceName in syncEndpointSlices) takes an early
// return to updateNumberOfIngressControllerReplicas, which calls
// Configurator.AddOrUpdateIngress for every Ingress using rate-limit scaling
// (nginx.org/limit-req-scale: "true") — not one of the UpdateEndpoints* wrappers that
// sync() otherwise relies on.
//
// addOrUpdateIngress writes the Ingress's own config successfully and then fails in
// the subsequent syncDefaultServerConfig() call, all within AddOrUpdateIngress, before
// it ever reaches its own Reload() call. Because every task in this batch has
// Kind == endpointslice, sync() never sets enableBatchReload (see the #7778 fix), so
// the only thing that can carry the pending reload to batch end is
// Configurator.reloadDeferred, set by AddOrUpdateIngress's error path.
//
// All three tasks are endpointslice so the batch is driven purely by queue drain
// (lbc.batchReloadWindow is left at its zero value, i.e. disabled — see sync() in
// controller.go), matching production behavior for a short burst of EndpointSlice
// events that drains before the window would ever matter.
func TestBatchReplicaChangeEndpointslicePartialWriteStillReloads(t *testing.T) {
	t.Parallel()

	mgr := &failOnDefaultServerManager{recordingBatchManager: newRecordingBatchManager()}
	lbc := newBatchTestLBC(t, mgr)

	const (
		controllerSvcName = "nginx-ingress-svc"
		controllerSvcNS   = "default"
	)
	lbc.statusUpdater = &statusUpdater{
		namespace:           controllerSvcNS,
		externalServiceName: controllerSvcName,
	}

	// An Ingress that opts into rate-limit scaling, so
	// FindIngressesWithRatelimitScaling picks it up once the controller's own
	// replica count changes. A single Host-only rule (no HTTP paths, no TLS) is
	// enough to pass validation and skip endpoint/secret resolution entirely in
	// createIngressEx, keeping this fixture minimal.
	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "scaled-ingress",
			Namespace: controllerSvcNS,
			Annotations: map[string]string{
				"nginx.org/limit-req-scale": "true",
			},
		},
		Spec: networking.IngressSpec{
			Rules: []networking.IngressRule{
				{Host: "ratelimit.example.com"},
			},
		},
	}
	lbc.configuration.AddOrUpdateIngress(ing)
	if _, problems := lbc.configuration.CompleteStartup(); len(problems) > 0 {
		t.Fatalf("CompleteStartup: unexpected problems: %+v", problems)
	}

	// The controller's own EndpointSlice, with two ready endpoints so
	// countReadyEndpoints(...) != the zero-value previous replica count and
	// updateNumberOfIngressControllerReplicas takes its "changed" branch.
	ready := true
	controllerEndpointSliceKey := controllerSvcNS + "/" + controllerSvcName + "-abc12"
	epSlice := &discovery_v1.EndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      controllerSvcName + "-abc12",
			Namespace: controllerSvcNS,
			Labels:    map[string]string{"kubernetes.io/service-name": controllerSvcName},
		},
		Endpoints: []discovery_v1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.0.0.2"}, Conditions: discovery_v1.EndpointConditions{Ready: &ready}},
		},
	}
	nsi := lbc.getNamespacedInformer(controllerSvcNS)
	if nsi == nil {
		t.Fatal("test setup error: no namespacedInformer for " + controllerSvcNS)
	}
	if err := nsi.endpointSliceLister.Add(epSlice); err != nil {
		t.Fatalf("test setup error: adding EndpointSlice to the lister: %v", err)
	}

	// Three endpointslice tasks so queue.Len() > 1 on the first Get() (entering
	// batch mode) and so the real task (processed second) still has at least one
	// task behind it — not strictly required for correctness here, since the
	// assertion is only made after the whole batch drains, but it keeps this
	// aligned with the "endpointslice churn either side of the real event" shape
	// used elsewhere in this file.
	lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: "default/unrelated-churn-1"})
	lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: controllerEndpointSliceKey})
	lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: "default/unrelated-churn-2"})

	drainSyncQueue(t, lbc)

	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("reload count = %d, want 1 (the replica-change Ingress config write must not be "+
			"silently dropped just because every task in the batch was an endpointslice)", got)
	}
	if lbc.batchSyncEnabled {
		t.Fatal("batchSyncEnabled still true after the queue drained")
	}
}

// TestBatchFlushKeepsBatchingAtLowBacklog pins the fix to the batch-end block in
// sync(): a window-triggered flush (syncQueue.Len() != 0 but batchReloadWindow has
// elapsed) must stay in batch mode — re-disabling reloads and re-arming batchStart —
// rather than clearing batchSyncEnabled the way a genuine drain (Len() == 0) does.
//
// Without that distinction, sustained low-backlog EndpointSlice churn (arrivals
// keeping the queue pinned at a small constant depth, e.g. 1, rather than draining to
// 0 or piling up) regresses to a reload on every single event once the window first
// elapses: ending batch mode means the next sync's entry check (syncQueue.Len() > 1)
// fails at backlog 1, so reloads stay enabled and every subsequent EndpointSlice event
// that references a real resource reaches Configurator.Reload() directly — the
// per-event reload storm batching exists to prevent, and a regression of
// https://github.com/nginx/kubernetes-ingress/issues/7778's symptom even though the
// #7778 fix itself (Configurator.isPlusAPIEnabled) is untouched.
//
// This drives real endpoint-triggered reloads (not no-op informer misses) through an
// Ingress that actually references the churning service, so that — on OSS, where
// Configurator.UpdateEndpoints always reaches Reload() once reloads are enabled —
// a regression here is observable as reloads incrementing on every churn event
// instead of once per window.
func TestBatchFlushKeepsBatchingAtLowBacklog(t *testing.T) {
	t.Parallel()

	mgr := newRecordingBatchManager()
	lbc := newBatchTestLBC(t, mgr)
	lbc.batchReloadWindow = time.Hour // never elapses on its own; elapsed via backdating only
	lbc.statusUpdater = &statusUpdater{}

	const (
		svcName = "churn-svc"
		svcNS   = "default"
	)

	// An Ingress that actually references svcName, so every EndpointSlice event
	// for it takes the real UpdateEndpoints path in syncEndpointSlices rather than
	// the empty-lister no-op used by the other churn tests in this file.
	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{Name: "churn-ingress", Namespace: svcNS},
		Spec: networking.IngressSpec{
			Rules: []networking.IngressRule{
				{
					Host: "churn.example.com",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path: "/",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: svcName,
											Port: networking.ServiceBackendPort{Number: 80},
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
	lbc.configuration.AddOrUpdateIngress(ing)
	if _, problems := lbc.configuration.CompleteStartup(); len(problems) > 0 {
		t.Fatalf("CompleteStartup: unexpected problems: %+v", problems)
	}

	nsi := lbc.getNamespacedInformer(svcNS)
	if nsi == nil {
		t.Fatal("test setup error: no namespacedInformer for " + svcNS)
	}
	// getServiceForIngressBackend does a real nsi.svcLister.GetByKey call; newBatchTestLBC
	// doesn't wire one up (none of the other tests in this file need it), so a nil
	// Store here would panic. An empty Store is enough — a lookup miss is handled
	// gracefully (logged, endpoints left empty), it just can't be a nil interface.
	nsi.svcLister = cache.NewStore(cache.MetaNamespaceKeyFunc)

	// Each churn event uses a distinct key. workqueue.Add dedups same-key items
	// that are still queued/unprocessed, so reusing one key across iterations
	// here would silently collapse back-to-back adds into a single queue entry —
	// defeating "pin the backlog at N" before any Get() has drained the previous
	// one. The distinct name doesn't change which service the event is for: all
	// of them carry the same "kubernetes.io/service-name" label, so every one
	// independently triggers Ingress.ingressRequiresEndpointsUpdate(svcName).
	ready := true
	nextChurn := 0
	addChurnEvent := func() {
		name := fmt.Sprintf("%s-slice-%d", svcName, nextChurn)
		nextChurn++
		epSlice := &discovery_v1.EndpointSlice{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      name,
				Namespace: svcNS,
				Labels:    map[string]string{"kubernetes.io/service-name": svcName},
			},
			Endpoints: []discovery_v1.Endpoint{
				{Addresses: []string{"10.0.0.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &ready}},
			},
		}
		if err := nsi.endpointSliceLister.Add(epSlice); err != nil {
			t.Fatalf("test setup error: adding EndpointSlice to the lister: %v", err)
		}
		lbc.syncQueue.queue.Add(task{Kind: endpointslice, Key: svcNS + "/" + name})
	}

	processNext := func() {
		obj, quit := lbc.syncQueue.queue.Get()
		if quit {
			t.Fatal("queue shut down mid-test")
		}
		lbc.sync(obj.(task))
		lbc.syncQueue.queue.Done(obj)
	}

	// Arm batch mode: seed one non-endpointslice task plus two churn events, so
	// queue.Len() > 1 on the first Get().
	const configRelevant = 999
	lbc.syncQueue.queue.Add(task{Kind: configRelevant, Key: "default/unrelated"})
	addChurnEvent()
	addChurnEvent()

	processNext() // enters batch mode; queue.Len() == 2 remaining
	processNext() // queue.Len() == 1 remaining

	// Pin the backlog at exactly 1 for several syncs: add one churn event, then
	// drain exactly one via processNext, so queue.Len() is 1 both before and after
	// every Get() in this loop — steady low-backlog churn, never draining to 0 and
	// never piling up.
	pinBacklog := func(n int) {
		for i := 0; i < n; i++ {
			addChurnEvent()
			processNext()
		}
	}

	pinBacklog(3)
	if got := mgr.reloads.Load(); got != 0 {
		t.Fatalf("reload count = %d, want 0 (the window hasn't elapsed yet, so nothing should "+
			"have flushed)", got)
	}
	if !lbc.batchSyncEnabled {
		t.Fatal("batchSyncEnabled became false while the queue never drained — batch mode must only " +
			"end on a genuine drain, not merely because reloads haven't happened yet")
	}

	// Force the window to have elapsed, without any real waiting.
	lbc.batchStart = time.Now().Add(-2 * time.Hour)

	// The next churn event's sync() call sees batchWindowElapsed == true with a
	// non-empty queue: this must flush the pending reload (#1) and, per the fix,
	// stay in batch mode rather than exiting it.
	pinBacklog(1)
	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("reload count = %d, want 1 (the elapsed window should flush exactly once)", got)
	}
	if !lbc.batchSyncEnabled {
		t.Fatal("batchSyncEnabled became false after a window-triggered flush with a non-empty queue — " +
			"the fix requires staying in batch mode here, or sustained low-backlog churn regresses to a " +
			"reload on every event (see the comment on this test)")
	}

	// The discriminating assertion: several more syncs at the same pinned backlog,
	// with no further backdating of batchStart, must NOT produce another reload.
	// Before the fix, the flush above would have cleared batchSyncEnabled, so each
	// of these would independently fail the batch-entry threshold
	// (syncQueue.Len() == 1 is not > 1), leaving reloads enabled — and since this
	// Ingress really does reference the churning service, each call would reach
	// Configurator.Reload() directly, incrementing the count on every iteration.
	pinBacklog(3)
	if got := mgr.reloads.Load(); got != 1 {
		t.Fatalf("reload count = %d, want 1 (sustained low-backlog churn after a window flush must stay "+
			"batched — a count > 1 here means it regressed to a reload per event)", got)
	}
	if !lbc.batchSyncEnabled {
		t.Fatal("batchSyncEnabled became false during sustained low-backlog churn")
	}

	// The first flush proves reloads stay deferred after it — it does not prove
	// pending work accumulated since that flush is ever actually applied. A
	// regression that flushed correctly once and then silently stopped
	// re-arming (e.g. failing to reset batchStart, or failing to re-disable
	// reloads) would still pass every assertion above, because this test would
	// simply end before a second window ever elapses. That's the exact failure
	// mode this fix exists to prevent — reloadDeferred is true going into this
	// point (set by the 3 no-op Reload() calls in the pinBacklog(3) above), so
	// it must still result in a real reload once the next window elapses.
	lbc.batchStart = time.Now().Add(-2 * time.Hour)
	pinBacklog(1)
	if got := mgr.reloads.Load(); got != 2 {
		t.Fatalf("reload count = %d, want 2 (the same active batch must flush again after a second window "+
			"elapses — not just once)", got)
	}
	if !lbc.batchSyncEnabled {
		t.Fatal("batchSyncEnabled became false after the second window flush")
	}
	if lbc.syncQueue.Len() == 0 {
		t.Fatal("test setup error: queue drained during the second flush — this would end the batch via " +
			"the genuine-drain path instead of the window-flush path, invalidating the assertions above")
	}

	// And the same no-further-reload discriminator as after the first flush:
	// churn following the second flush must stay deferred, not re-trigger.
	pinBacklog(3)
	if got := mgr.reloads.Load(); got != 2 {
		t.Fatalf("reload count = %d, want 2 (no further reload should fire before a third window elapses)", got)
	}
	if !lbc.batchSyncEnabled {
		t.Fatal("batchSyncEnabled became false during sustained low-backlog churn after the second flush")
	}
}
