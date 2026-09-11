package k8s

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	fake_v1 "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	api_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// recordingWeightManager records the keyval writes and config/reload activity
// that the dynamic-weight-change fast lane is supposed to avoid. Keyval writes
// with no config write and no reload is the signature of the fast lane; the
// reverse is the signature of the normal path.
type recordingWeightManager struct {
	*nginx.FakeManager

	mu      sync.Mutex
	keyvals []configs.WeightUpdate

	configWrites atomic.Int32
	reloads      atomic.Int32
}

func newRecordingWeightManager() *recordingWeightManager {
	return &recordingWeightManager{FakeManager: nginx.NewFakeManager("/etc/nginx")}
}

func (m *recordingWeightManager) UpsertSplitClientsKeyVal(zoneName, key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyvals = append(m.keyvals, configs.WeightUpdate{Zone: zoneName, Key: key, Value: value})
}

func (m *recordingWeightManager) recordedKeyvals() []configs.WeightUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]configs.WeightUpdate(nil), m.keyvals...)
}

// keyvalsSince returns the writes recorded after the first n. A full render
// also seeds the keyval zones with the current weights, so tests have to
// discount whatever the seeding sync produced before judging the fast lane.
func (m *recordingWeightManager) keyvalsSince(n int) []configs.WeightUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]configs.WeightUpdate(nil), m.keyvals[n:]...)
}

func (m *recordingWeightManager) CreateConfig(name string, content []byte) (bool, error) {
	m.configWrites.Add(1)
	return m.FakeManager.CreateConfig(name, content)
}

func (m *recordingWeightManager) Reload(isEndpointsUpdate bool) error {
	m.reloads.Add(1)
	return m.FakeManager.Reload(isEndpointsUpdate)
}

// newWeightTestLBC wires the minimum LoadBalancerController surface needed to
// drive syncVirtualServer and syncVirtualServerRoute to completion.
//
// isNginxReady is left false so status writes land on the pending slices
// instead of needing a live status updater backend; the fast-lane decision
// happens well before that branch.
func newWeightTestLBC(tb testing.TB, dynamicReload bool) (*LoadBalancerController, *recordingWeightManager) {
	tb.Helper()

	mgr := newRecordingWeightManager()

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

	// svcLister and endpointSliceLister are needed because
	// createVirtualServerEx resolves upstream endpoints; the services below
	// exist so resolution produces no endpoints rather than panicking.
	svcStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, name := range []string{"v1-svc", "v2-svc"} {
		if err := svcStore.Add(&api_v1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec: api_v1.ServiceSpec{
				Ports: []api_v1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(80)}},
			},
		}); err != nil {
			tb.Fatalf("seeding service %s: %v", name, err)
		}
	}

	nsi := &namespacedInformer{
		virtualServerLister:      cache.NewStore(cache.MetaNamespaceKeyFunc),
		virtualServerRouteLister: cache.NewStore(cache.MetaNamespaceKeyFunc),
		svcLister:                svcStore,
		endpointSliceLister:      storeToEndpointSliceLister{Store: cache.NewStore(cache.MetaNamespaceKeyFunc)},
	}

	// processProblems writes VS/VSR statuses straight through rather than
	// deferring them to the pending slices, so a real statusUpdater backed by
	// the fake CRD clientset is needed for fixtures that produce problems
	// (an unattached VirtualServerRoute, for instance).
	confClient := fake_v1.NewClientset()

	lbc := &LoadBalancerController{
		configurator: configs.NewConfigurator(configs.ConfiguratorParams{
			NginxManager:       mgr,
			StaticCfgParams:    &configs.StaticConfigParams{DynamicWeightChangesReload: dynamicReload},
			Config:             configs.NewDefaultConfigParams(context.Background(), false),
			MGMTCfgParams:      configs.NewDefaultMGMTConfigParams(context.Background()),
			TemplateExecutor:   templateExecutor,
			TemplateExecutorV2: templateExecutorV2,
			IsPlus:             true,
		}),
		configuration: NewConfiguration(
			func(interface{}) bool { return true },
			true, false, false,
			validation.NewVirtualServerValidator(),
			validation.NewGlobalConfigurationValidator(map[int]bool{}),
			validation.NewTransportServerValidator(false, false, false),
			false, false, false, false, false, false,
		),
		weightChangesDynamicReload: dynamicReload,
		recorder:                   record.NewFakeRecorder(100),
		Logger:                     nl.LoggerFromContext(context.Background()),
		client:                     fake.NewClientset(),
		isNginxReady:               false,
		namespacedInformers:        map[string]*namespacedInformer{"default": nsi},
		statusUpdater: &statusUpdater{
			confClient:          confClient,
			namespacedInformers: map[string]*namespacedInformer{"default": nsi},
			keyFunc:             cache.DeletionHandlingMetaNamespaceKeyFunc,
			logger:              nl.LoggerFromContext(context.Background()),
		},
	}
	lbc.configuration.CompleteStartup()
	lbc.syncQueue = newTaskQueue(lbc.Logger, lbc.sync)
	tb.Cleanup(func() { lbc.syncQueue.queue.ShutDown() })

	return lbc, mgr
}

func weightTestVS(name string, generation int64, routes []conf_v1.Route) *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, Generation: generation},
		Spec: conf_v1.VirtualServerSpec{
			IngressClass: "nginx",
			Host:         name + ".example.com",
			Upstreams: []conf_v1.Upstream{
				{Name: "v1", Service: "v1-svc", Port: 80},
				{Name: "v2", Service: "v2-svc", Port: 80},
			},
			Routes: routes,
		},
	}
}

// path is retained on every caller for fixture readability; unparam flags it
// because every current caller passes "/tea", but that will change as more
// route-shape fixtures land.
//
//nolint:unparam
func twoWayRoute(path string, w0, w1 int) conf_v1.Route {
	return conf_v1.Route{
		Path: path,
		Splits: []conf_v1.Split{
			{Weight: w0, Action: &conf_v1.Action{Pass: "v1"}},
			{Weight: w1, Action: &conf_v1.Action{Pass: "v2"}},
		},
	}
}

// seedVS applies vs through the normal path so that Configuration holds it as
// the last-applied baseline and the informer store can serve it, exactly as it
// would be after a real first sync.
func seedVS(tb testing.TB, lbc *LoadBalancerController, vs *conf_v1.VirtualServer) {
	tb.Helper()

	nsi := lbc.namespacedInformers["default"]
	if err := nsi.virtualServerLister.Add(vs); err != nil {
		tb.Fatalf("seeding informer: %v", err)
	}
	changes, problems := lbc.configuration.AddOrUpdateVirtualServer(vs)
	lbc.processChanges(changes)
	lbc.processProblems(problems)

	if got := lbc.configuration.GetVirtualServer(getResourceKey(&vs.ObjectMeta)); got == nil {
		tb.Fatalf("seeding failed: Configuration does not hold %s", vs.Name)
	}
}

// updateVS replaces the informer's copy, standing in for the UPDATE event that
// would normally precede a sync.
func updateVS(tb testing.TB, lbc *LoadBalancerController, vs *conf_v1.VirtualServer) {
	tb.Helper()

	if err := lbc.namespacedInformers["default"].virtualServerLister.Update(vs); err != nil {
		tb.Fatalf("updating informer: %v", err)
	}
}

func TestSyncVirtualServer_WeightOnlyDiffAppliesKeyvalWithoutReload(t *testing.T) {
	t.Parallel()

	lbc, mgr := newWeightTestLBC(t, true)

	vs := weightTestVS("cafe", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
	seedVS(t, lbc, vs)

	// Seeding goes through the normal path, so discount everything it did.
	writesAfterSeed := mgr.configWrites.Load()
	keyvalsAfterSeed := len(mgr.recordedKeyvals())
	reloadsAfterSeed := mgr.reloads.Load()

	updated := weightTestVS("cafe", 2, []conf_v1.Route{twoWayRoute("/tea", 70, 30)})
	updateVS(t, lbc, updated)

	lbc.syncVirtualServer(task{Kind: virtualserver, Key: "default/cafe"})

	namer := configs.NewVSVariableNamer(updated)
	want := []configs.WeightUpdate{{
		Zone:  namer.GetNameOfKeyvalZoneForSplitClientIndex(0),
		Key:   namer.GetNameOfKeyvalKeyForSplitClientIndex(0),
		Value: namer.GetNameOfKeyOfMapForWeights(0, 70, 30),
	}}
	if diff := cmp.Diff(want, mgr.keyvalsSince(keyvalsAfterSeed)); diff != "" {
		t.Errorf("keyval writes mismatch (-want +got):\n%s", diff)
	}

	if got := mgr.configWrites.Load() - writesAfterSeed; got != 0 {
		t.Errorf("fast lane wrote %d NGINX configs, want 0", got)
	}
	if got := mgr.reloads.Load() - reloadsAfterSeed; got != 0 {
		t.Errorf("fast lane triggered %d reloads, want 0", got)
	}

	// The baseline must advance, or the next weight change would be computed
	// against a stale spec.
	stored := lbc.configuration.GetVirtualServer("default/cafe")
	if got := stored.Spec.Routes[0].Splits[0].Weight; got != 70 {
		t.Errorf("Configuration baseline weight = %d, want 70", got)
	}
}

func TestSyncVirtualServer_FallsBackToReload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		dynamicReload bool
		// mutate produces the version fed to the sync handler.
		mutate func(*conf_v1.VirtualServer)
		// skipSeed leaves Configuration without a baseline.
		skipSeed bool
	}{
		{
			name:          "feature flag disabled",
			dynamicReload: false,
			mutate: func(vs *conf_v1.VirtualServer) {
				vs.Spec.Routes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
			},
		},
		{
			name:          "spec change beyond weights",
			dynamicReload: true,
			mutate: func(vs *conf_v1.VirtualServer) {
				vs.Spec.Routes = []conf_v1.Route{
					twoWayRoute("/tea", 70, 30),
					{Path: "/coffee", Action: &conf_v1.Action{Pass: "v1"}},
				}
			},
		},
		{
			name:          "split count changed",
			dynamicReload: true,
			mutate: func(vs *conf_v1.VirtualServer) {
				vs.Spec.Routes = []conf_v1.Route{{
					Path: "/tea",
					Splits: []conf_v1.Split{
						{Weight: 34, Action: &conf_v1.Action{Pass: "v1"}},
						{Weight: 33, Action: &conf_v1.Action{Pass: "v2"}},
						{Weight: 33, Action: &conf_v1.Action{Pass: "v1"}},
					},
				}}
			},
		},
		{
			name:          "no baseline in Configuration",
			dynamicReload: true,
			skipSeed:      true,
			mutate: func(vs *conf_v1.VirtualServer) {
				vs.Spec.Routes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
			},
		},
		{
			name:          "current object reports StateInvalid",
			dynamicReload: true,
			mutate: func(vs *conf_v1.VirtualServer) {
				vs.Spec.Routes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
				vs.Status.State = conf_v1.StateInvalid
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lbc, mgr := newWeightTestLBC(t, test.dynamicReload)

			vs := weightTestVS("cafe", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
			nsi := lbc.namespacedInformers["default"]

			if test.skipSeed {
				if err := nsi.virtualServerLister.Add(vs); err != nil {
					t.Fatalf("seeding informer: %v", err)
				}
			} else {
				seedVS(t, lbc, vs)
			}

			writesAfterSeed := mgr.configWrites.Load()
			keyvalsAfterSeed := len(mgr.recordedKeyvals())

			updated := weightTestVS("cafe", 2, nil)
			test.mutate(updated)
			if err := nsi.virtualServerLister.Update(updated); err != nil {
				t.Fatalf("updating informer: %v", err)
			}

			lbc.syncVirtualServer(task{Kind: virtualserver, Key: "default/cafe"})

			// The normal path is identified by a config write. It may also
			// re-seed the keyval zones as part of rendering, so the absence of
			// keyval writes is not the signal here; the config write is.
			if got := mgr.configWrites.Load() - writesAfterSeed; got == 0 {
				t.Error("normal path not taken: no NGINX config was written")
			}
			if lbc.weightChangesDynamicReload {
				return
			}
			if got := mgr.keyvalsSince(keyvalsAfterSeed); len(got) != 0 {
				t.Errorf("keyval writes with the feature disabled: %d, want 0", len(got))
			}
		})
	}
}

// TestSyncVirtualServer_RejectedUpdateHaltsDespiteUnrelatedProblems pins a bug
// where the halt-before-reload guard keyed off the full problems slice
// returned alongside changes. That slice carries every problem detected
// across the whole configuration -- including ones for resources that have
// nothing to do with the VS being synced -- so an unrelated orphan
// VirtualServerRoute elsewhere could either mask a real rejection (event
// never reported) or, if empty, let a rejected weight-only update fall
// through to a reload that removes the last valid config. The halt must be
// keyed off whether this VS's own change carries an error instead.
func TestSyncVirtualServer_RejectedUpdateHaltsDespiteUnrelatedProblems(t *testing.T) {
	t.Parallel()

	lbc, mgr := newWeightTestLBC(t, true)

	vs := weightTestVS("cafe", 1, []conf_v1.Route{twoWayRoute("/tea", 70, 30)})
	seedVS(t, lbc, vs)

	// An orphan VirtualServerRoute unrelated to "cafe", inserted directly so
	// that the next rebuildHosts() pass -- the one triggered by cafe's own
	// update below -- is the first time it's evaluated and reports it as a
	// problem. This reproduces the field symptom: an unrelated problem
	// surfacing in the very same sync as a weight-only rejection.
	orphan := &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "orphan"},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host:      "orphan.example.com",
			Subroutes: []conf_v1.Route{{Path: "/", Action: &conf_v1.Action{Pass: "v1"}}},
		},
	}
	lbc.configuration.virtualServerRoutes[getResourceKey(&orphan.ObjectMeta)] = orphan

	writesAfterSeed := mgr.configWrites.Load()
	reloadsAfterSeed := mgr.reloads.Load()
	keyvalsAfterSeed := len(mgr.recordedKeyvals())

	// 70/40 doesn't sum to 100: rejected by NIC's own validation.
	invalid := weightTestVS("cafe", 2, []conf_v1.Route{twoWayRoute("/tea", 70, 40)})
	updateVS(t, lbc, invalid)

	lbc.syncVirtualServer(task{Kind: virtualserver, Key: "default/cafe"})

	if got := mgr.configWrites.Load() - writesAfterSeed; got != 0 {
		t.Errorf("rejected update wrote %d NGINX configs, want 0 (last valid config must keep serving)", got)
	}
	if got := mgr.reloads.Load() - reloadsAfterSeed; got != 0 {
		t.Errorf("rejected update triggered %d reloads, want 0", got)
	}
	if got := mgr.keyvalsSince(keyvalsAfterSeed); len(got) != 0 {
		t.Errorf("rejected update wrote %d keyvals, want 0", len(got))
	}

	fakeRecorder, ok := lbc.recorder.(*record.FakeRecorder)
	if !ok {
		t.Fatalf("recorder is %T, want *record.FakeRecorder", lbc.recorder)
	}
	close(fakeRecorder.Events)
	var sawCafeRejected bool
	for e := range fakeRecorder.Events {
		if strings.Contains(e, "cafe") && strings.Contains(e, "Rejected") {
			sawCafeRejected = true
		}
	}
	if !sawCafeRejected {
		t.Error("no Rejected event was recorded for default/cafe; the unrelated orphan problem must not swallow it")
	}
}

// name is retained on every caller for fixture readability; unparam flags it
// because every current caller passes "coffee".
//
//nolint:unparam
func weightTestVSR(name string, generation int64, subroutes []conf_v1.Route) *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, Generation: generation},
		Spec: conf_v1.VirtualServerRouteSpec{
			IngressClass: "nginx",
			Host:         "cafe.example.com",
			Upstreams: []conf_v1.Upstream{
				{Name: "v1", Service: "v1-svc", Port: 80},
				{Name: "v2", Service: "v2-svc", Port: 80},
			},
			Subroutes: subroutes,
		},
	}
}

// weightTestSelectorVS builds a VirtualServer whose single route attaches
// VirtualServerRoutes by label rather than by name, so that a VSR label change
// alone can change which VSRs the rendered configuration contains.
func weightTestSelectorVS(name string, generation int64) *conf_v1.VirtualServer {
	vs := weightTestVS(name, generation, []conf_v1.Route{{
		Path:          "/tea",
		RouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "route"}},
	}})
	return vs
}

// TestSyncVirtualServerRoute_FallsBackToReload covers the cases where a
// VirtualServerRoute update looks weight-only but still needs a full render.
//
// The VSR UpdateFunc enqueues on a spec change *or* a label change, and labels
// drive routeSelector matching, so "the spec differs only in 2-way weights" is
// not sufficient grounds to skip rendering. Taking the fast lane in these
// cases consumes the sync and leaves NGINX serving a configuration that no
// longer matches the cluster.
func TestSyncVirtualServerRoute_FallsBackToReload(t *testing.T) {
	t.Parallel()

	const attached = "app"

	tests := []struct {
		name string
		// seedLabels are the VSR's labels when first applied.
		seedLabels map[string]string
		// mutate produces the updated VSR fed to the sync handler.
		mutate func(*conf_v1.VirtualServerRoute)
	}{
		{
			// A label change that newly attaches the VSR to the selector VS.
			// The spec is untouched, so a spec-only predicate sees a
			// weight-only diff and the new subroute would never be rendered.
			name:       "label change attaches the VSR",
			seedLabels: nil,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Labels = map[string]string{attached: "route"}
			},
		},
		{
			// A label change that detaches it. Already handled by the
			// change-set reference filter; pinned so that stays true.
			name:       "label change detaches the VSR",
			seedLabels: map[string]string{attached: "route"},
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Labels = map[string]string{attached: "other"}
			},
		},
		{
			// A single apply that changes a label and a weight together. Both
			// clauses of the enqueue condition fire, the spec diff really is
			// weight-only, and a weight really did change — so only the label
			// comparison keeps this out of the fast lane.
			name:       "label and weight change together",
			seedLabels: nil,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Labels = map[string]string{attached: "route"}
				vsr.Spec.Subroutes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lbc, mgr := newWeightTestLBC(t, true)
			nsi := lbc.namespacedInformers["default"]

			vsr := weightTestVSR("coffee", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
			vsr.Labels = test.seedLabels
			if err := nsi.virtualServerRouteLister.Add(vsr); err != nil {
				t.Fatalf("seeding VSR informer: %v", err)
			}
			lbc.configuration.AddOrUpdateVirtualServerRoute(vsr)

			seedVS(t, lbc, weightTestSelectorVS("cafe", 1))

			writesAfterSeed := mgr.configWrites.Load()

			updated := weightTestVSR("coffee", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
			updated.Labels = test.seedLabels
			test.mutate(updated)
			if err := nsi.virtualServerRouteLister.Update(updated); err != nil {
				t.Fatalf("updating VSR informer: %v", err)
			}

			lbc.syncVirtualServerRoute(task{Kind: virtualServerRoute, Key: "default/coffee"})

			// A config write is the discriminator: the fast lane returns
			// before processChanges, so if it had been taken the attachment
			// change would never reach NGINX. Keyval writes are not a useful
			// signal here, because a full render also re-seeds the keyval
			// zones with the current weights.
			if got := mgr.configWrites.Load() - writesAfterSeed; got == 0 {
				t.Error("fast lane taken: no NGINX config was written, so the label change never reached NGINX")
			}
		})
	}
}

func TestSyncVirtualServerRoute_WeightOnlyDiffAppliesKeyvalWithoutReload(t *testing.T) {
	t.Parallel()

	lbc, mgr := newWeightTestLBC(t, true)
	nsi := lbc.namespacedInformers["default"]

	vsr := weightTestVSR("coffee", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
	if err := nsi.virtualServerRouteLister.Add(vsr); err != nil {
		t.Fatalf("seeding VSR informer: %v", err)
	}
	lbc.configuration.AddOrUpdateVirtualServerRoute(vsr)

	vs := weightTestVS("cafe", 1, []conf_v1.Route{{Path: "/tea", Route: "coffee"}})
	seedVS(t, lbc, vs)

	vsConfig, ok := lbc.configuration.hosts["cafe.example.com"].(*VirtualServerConfiguration)
	if !ok || len(vsConfig.VirtualServerRoutes) != 1 {
		t.Fatalf("fixture did not attach the VirtualServerRoute to the VirtualServer")
	}

	writesAfterSeed := mgr.configWrites.Load()
	keyvalsAfterSeed := len(mgr.recordedKeyvals())
	reloadsAfterSeed := mgr.reloads.Load()

	updated := weightTestVSR("coffee", 2, []conf_v1.Route{twoWayRoute("/tea", 70, 30)})
	if err := nsi.virtualServerRouteLister.Update(updated); err != nil {
		t.Fatalf("updating VSR informer: %v", err)
	}

	lbc.syncVirtualServerRoute(task{Kind: virtualServerRoute, Key: "default/coffee"})

	// Keyval zone names are VirtualServer scoped, so the update is addressed
	// with the referencing VirtualServer's namer, not the VSR's.
	namer := configs.NewVSVariableNamer(vs)
	want := []configs.WeightUpdate{{
		Zone:  namer.GetNameOfKeyvalZoneForSplitClientIndex(0),
		Key:   namer.GetNameOfKeyvalKeyForSplitClientIndex(0),
		Value: namer.GetNameOfKeyOfMapForWeights(0, 70, 30),
	}}
	if diff := cmp.Diff(want, mgr.keyvalsSince(keyvalsAfterSeed)); diff != "" {
		t.Errorf("keyval writes mismatch (-want +got):\n%s", diff)
	}

	if got := mgr.configWrites.Load() - writesAfterSeed; got != 0 {
		t.Errorf("fast lane wrote %d NGINX configs, want 0", got)
	}
	if got := mgr.reloads.Load() - reloadsAfterSeed; got != 0 {
		t.Errorf("fast lane triggered %d reloads, want 0", got)
	}

	stored := lbc.configuration.GetVirtualServerRoute("default/coffee")
	if got := stored.Spec.Subroutes[0].Splits[0].Weight; got != 70 {
		t.Errorf("Configuration baseline weight = %d, want 70", got)
	}
}

// TestApplyWeightOnlyVSChanges_RejectsUnexpectedChangeShapes pins the guard
// that keeps the fast lane safe by construction. A weight-only spec diff is
// expected to produce exactly one AddOrUpdate for the VirtualServer itself;
// anything else has to fall through to processChanges, which handles every
// shape correctly.
func TestApplyWeightOnlyVSChanges_RejectsUnexpectedChangeShapes(t *testing.T) {
	t.Parallel()

	const key = "default/cafe"
	vsc := &VirtualServerConfiguration{
		VirtualServer: weightTestVS("cafe", 2, []conf_v1.Route{twoWayRoute("/tea", 70, 30)}),
	}
	otherVSC := &VirtualServerConfiguration{
		VirtualServer: weightTestVS("other", 1, []conf_v1.Route{twoWayRoute("/tea", 70, 30)}),
	}

	tests := []struct {
		name    string
		changes []ResourceChange
	}{
		{name: "no changes", changes: nil},
		{
			name:    "delete instead of add-or-update",
			changes: []ResourceChange{{Op: Delete, Resource: vsc}},
		},
		{
			name: "cascade to a second resource",
			changes: []ResourceChange{
				{Op: AddOrUpdate, Resource: vsc},
				{Op: AddOrUpdate, Resource: otherVSC},
			},
		},
		{
			name:    "change is for a different VirtualServer",
			changes: []ResourceChange{{Op: AddOrUpdate, Resource: otherVSC}},
		},
		{
			name:    "change is not a VirtualServerConfiguration",
			changes: []ResourceChange{{Op: AddOrUpdate, Resource: &TransportServerConfiguration{}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lbc, mgr := newWeightTestLBC(t, true)
			updates := []configs.WeightUpdate{{Zone: "z", Key: "k", Value: "v"}}

			if lbc.applyWeightOnlyVSChanges(key, test.changes, updates) {
				t.Error("applyWeightOnlyVSChanges() = true, want false")
			}
			if got := mgr.recordedKeyvals(); len(got) != 0 {
				t.Errorf("rejected change set still wrote %d keyvals, want 0", len(got))
			}
		})
	}
}

// TestApplyWeightOnlyVSRChanges_RejectsUnexpectedChangeShapes covers the VSR
// guard, which additionally has to reject VirtualServers that do not reference
// the VSR: rebuildHosts reports a change for every host whose configuration
// moved, so an unrelated VirtualServer can appear in the set, and it needs a
// real render.
func TestApplyWeightOnlyVSRChanges_RejectsUnexpectedChangeShapes(t *testing.T) {
	t.Parallel()

	vsrOld := testVSRWithSubroutes("default", "coffee", []splitShape{{routeSplits: []int{50, 50}}})
	vsrNew := testVSRWithSubroutes("default", "coffee", []splitShape{{routeSplits: []int{70, 30}}})

	referencing := &VirtualServerConfiguration{
		VirtualServer:       weightTestVS("cafe", 2, nil),
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsrNew},
	}
	unrelated := &VirtualServerConfiguration{
		VirtualServer: weightTestVS("other", 1, nil),
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			testVSRWithSubroutes("default", "tea", []splitShape{{routeSplits: []int{50, 50}}}),
		},
	}

	tests := []struct {
		name    string
		changes []ResourceChange
	}{
		{
			name:    "delete instead of add-or-update",
			changes: []ResourceChange{{Op: Delete, Resource: referencing}},
		},
		{
			name:    "change is not a VirtualServerConfiguration",
			changes: []ResourceChange{{Op: AddOrUpdate, Resource: &TransportServerConfiguration{}}},
		},
		{
			name:    "VirtualServer does not reference the VSR",
			changes: []ResourceChange{{Op: AddOrUpdate, Resource: unrelated}},
		},
		{
			name: "one referencing VirtualServer and one unrelated",
			changes: []ResourceChange{
				{Op: AddOrUpdate, Resource: referencing},
				{Op: AddOrUpdate, Resource: unrelated},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lbc, mgr := newWeightTestLBC(t, true)

			if lbc.applyWeightOnlyVSRChanges(vsrOld, vsrNew, test.changes) {
				t.Error("applyWeightOnlyVSRChanges() = true, want false")
			}
			if got := mgr.recordedKeyvals(); len(got) != 0 {
				t.Errorf("rejected change set still wrote %d keyvals, want 0", len(got))
			}
		})
	}
}

// TestApplyWeightOnlyVSRChanges_EmptyChangeSet covers a VSR that no
// VirtualServer references: there is nothing to render and nothing to poke, so
// the fast lane succeeds trivially rather than forcing a reload.
func TestApplyWeightOnlyVSRChanges_EmptyChangeSet(t *testing.T) {
	t.Parallel()

	lbc, mgr := newWeightTestLBC(t, true)

	vsrOld := testVSRWithSubroutes("default", "coffee", []splitShape{{routeSplits: []int{50, 50}}})
	vsrNew := testVSRWithSubroutes("default", "coffee", []splitShape{{routeSplits: []int{70, 30}}})

	if !lbc.applyWeightOnlyVSRChanges(vsrOld, vsrNew, nil) {
		t.Error("applyWeightOnlyVSRChanges() = false, want true for an empty change set")
	}
	if got := mgr.recordedKeyvals(); len(got) != 0 {
		t.Errorf("empty change set wrote %d keyvals, want 0", len(got))
	}
}

// TestSyncHandlersReleaseConfigurationLock is the replacement for the deleted
// haltIfVS(R)ConfigInvalid deadlock guard.
//
// The old fast path held Configuration's write lock across status updates and
// configurator calls, which made Configuration writable from two goroutines
// and left every accessor one RLock away from a self-deadlock. The lock is now
// taken and released inside AddOrUpdate* and never held while the handler
// calls anything else, so an accessor that takes the read lock is safe from
// any point in the handler.
//
// Taking the write lock from a second goroutine after the handler returns
// proves the handler left nothing held.
func TestSyncHandlersReleaseConfigurationLock(t *testing.T) {
	t.Parallel()

	lbc, _ := newWeightTestLBC(t, true)

	vs := weightTestVS("cafe", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
	seedVS(t, lbc, vs)

	updated := weightTestVS("cafe", 2, []conf_v1.Route{twoWayRoute("/tea", 70, 30)})
	updateVS(t, lbc, updated)

	lbc.syncVirtualServer(task{Kind: virtualserver, Key: "default/cafe"})

	// A read accessor must be callable, and the write lock must be free.
	if got := lbc.configuration.GetVirtualServer("default/cafe"); got == nil {
		t.Fatal("GetVirtualServer() returned nil after sync")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		lbc.configuration.lock.Lock()
		// Lock() making the timeout below is the assertion; the read is
		// just here to keep staticcheck quiet about the empty crit section.
		_ = len(lbc.configuration.virtualServers)
		lbc.configuration.lock.Unlock()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Configuration.lock still held after syncVirtualServer returned")
	}
}

// TestVSRWeightOnlyEligible covers every branch of the fast-lane decision for
// VirtualServerRoutes directly, including the ones no sync-level fixture can
// distinguish.
func TestVSRWeightOnlyEligible(t *testing.T) {
	t.Parallel()

	seed := func() *conf_v1.VirtualServerRoute {
		vsr := weightTestVSR("coffee", 1, []conf_v1.Route{twoWayRoute("/tea", 50, 50)})
		vsr.Labels = map[string]string{"app": "route"}
		return vsr
	}

	tests := []struct {
		name          string
		dynamicReload bool
		skipSeed      bool
		mutate        func(*conf_v1.VirtualServerRoute)
		want          bool
	}{
		{
			name:          "pure weight change",
			dynamicReload: true,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Spec.Subroutes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
			},
			want: true,
		},
		{
			name:          "current object reports StateInvalid",
			dynamicReload: true,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Spec.Subroutes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
				vsr.Status.State = conf_v1.StateInvalid
			},
			want: false,
		},
		{
			name:          "no baseline in Configuration",
			dynamicReload: true,
			skipSeed:      true,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Spec.Subroutes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
			},
			want: false,
		},
		{
			name:          "spec change beyond weights",
			dynamicReload: true,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Spec.Subroutes = []conf_v1.Route{
					twoWayRoute("/tea", 70, 30),
					{Path: "/coffee", Action: &conf_v1.Action{Pass: "v1"}},
				}
			},
			want: false,
		},
		{
			name:          "labels changed alongside a weight change",
			dynamicReload: true,
			mutate: func(vsr *conf_v1.VirtualServerRoute) {
				vsr.Spec.Subroutes = []conf_v1.Route{twoWayRoute("/tea", 70, 30)}
				vsr.Labels = map[string]string{"app": "other"}
			},
			want: false,
		},
		{
			// Nothing changed. Weight-only-equal specs can also be identical,
			// which happens when the sync was triggered by something other
			// than this resource's own weights, and there is nothing to apply
			// in place.
			name:          "identical spec and labels",
			dynamicReload: true,
			mutate:        func(*conf_v1.VirtualServerRoute) {},
			want:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lbc, _ := newWeightTestLBC(t, test.dynamicReload)
			if !test.skipSeed {
				lbc.configuration.AddOrUpdateVirtualServerRoute(seed())
			}

			cur := seed()
			test.mutate(cur)

			prev := lbc.configuration.GetVirtualServerRoute("default/coffee")
			got := vsrWeightOnlyEligible(prev, cur)
			if got != test.want {
				t.Errorf("vsrWeightOnlyEligible() = %v, want %v", got, test.want)
			}
		})
	}
}
