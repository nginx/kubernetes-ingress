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
		namespacedInformers: map[string]*namespacedInformer{"default": nsi},
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
