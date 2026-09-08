package k8s

import (
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// vsWithRouteSplits returns a VirtualServer whose single route has one
// top-level 2-way split with the given weights.
func vsWithRouteSplits(w0, w1 int) *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "default"},
		Spec: conf_v1.VirtualServerSpec{
			Host: "example.com",
			Routes: []conf_v1.Route{{
				Path: "/",
				Splits: []conf_v1.Split{
					{Weight: w0, Action: &conf_v1.Action{Pass: "u1"}},
					{Weight: w1, Action: &conf_v1.Action{Pass: "u2"}},
				},
			}},
		},
	}
}

// vsWithMatchSplits returns a VirtualServer whose single route has one match
// with one 2-way split with the given weights.
func vsWithMatchSplits(w0, w1 int) *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "default"},
		Spec: conf_v1.VirtualServerSpec{
			Host: "example.com",
			Routes: []conf_v1.Route{{
				Path: "/",
				Matches: []conf_v1.Match{{
					Conditions: []conf_v1.Condition{{Header: "x-test", Value: "1"}},
					Splits: []conf_v1.Split{
						{Weight: w0, Action: &conf_v1.Action{Pass: "u1"}},
						{Weight: w1, Action: &conf_v1.Action{Pass: "u2"}},
					},
				}},
			}},
		},
	}
}

func TestComputeVSWeightUpdates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		prev, cur    *conf_v1.VirtualServer
		wantNumZones int
	}{
		{
			name:         "no diff yields no updates",
			prev:         vsWithRouteSplits(50, 50),
			cur:          vsWithRouteSplits(50, 50),
			wantNumZones: 0,
		},
		{
			name:         "route split weight change",
			prev:         vsWithRouteSplits(50, 50),
			cur:          vsWithRouteSplits(70, 30),
			wantNumZones: 1,
		},
		{
			name:         "match split weight change",
			prev:         vsWithMatchSplits(50, 50),
			cur:          vsWithMatchSplits(10, 90),
			wantNumZones: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := computeVSWeightUpdates(tc.prev, tc.cur)
			if len(got) != tc.wantNumZones {
				t.Fatalf("computeVSWeightUpdates() returned %d updates, want %d: %+v", len(got), tc.wantNumZones, got)
			}
			for _, w := range got {
				if w.Zone == "" || w.Key == "" || w.Value == "" {
					t.Errorf("computeVSWeightUpdates() produced empty field in %+v", w)
				}
			}
		})
	}
}

func TestComputeVSWeightUpdates_ValueEncodesWeights(t *testing.T) {
	t.Parallel()

	prev := vsWithRouteSplits(50, 50)
	cur := vsWithRouteSplits(70, 30)
	got := computeVSWeightUpdates(prev, cur)
	if len(got) != 1 {
		t.Fatalf("expected 1 weight update, got %d", len(got))
	}
	// The value is derived from the new weights via NewVSVariableNamer; regenerating
	// it here proves the compute helper wires the namer to cur (not prev).
	namer := configs.NewVSVariableNamer(cur)
	wantValue := namer.GetNameOfKeyOfMapForWeights(0, 70, 30)
	if got[0].Value != wantValue {
		t.Errorf("update value = %q, want %q", got[0].Value, wantValue)
	}
}

// vsrWithSubrouteSplits returns a VirtualServerRoute whose single subroute has
// one top-level 2-way split with the given weights.
func vsrWithSubrouteSplits(w0, w1 int) *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "vsr", Namespace: "default"},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host: "example.com",
			Subroutes: []conf_v1.Route{{
				Path: "/coffee",
				Splits: []conf_v1.Split{
					{Weight: w0, Action: &conf_v1.Action{Pass: "u1"}},
					{Weight: w1, Action: &conf_v1.Action{Pass: "u2"}},
				},
			}},
		},
	}
}

func TestComputeVSRWeightUpdates(t *testing.T) {
	t.Parallel()

	// Parent VS carries no splits so startingIndex is 0 for the VSR under test.
	parentVS := &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "default"},
		Spec:       conf_v1.VirtualServerSpec{Host: "example.com"},
	}
	prev := vsrWithSubrouteSplits(60, 40)
	cur := vsrWithSubrouteSplits(90, 10)

	vsEx := &configs.VirtualServerEx{
		VirtualServer:       parentVS,
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{cur},
	}
	got := computeVSRWeightUpdates(vsEx, prev, cur, 0)
	if len(got) != 1 {
		t.Fatalf("computeVSRWeightUpdates() returned %d updates, want 1: %+v", len(got), got)
	}
	namer := configs.NewVSVariableNamer(parentVS)
	if want := namer.GetNameOfKeyOfMapForWeights(0, 90, 10); got[0].Value != want {
		t.Errorf("update value = %q, want %q", got[0].Value, want)
	}
}

func TestComputeVSRWeightUpdates_NoDiffYieldsNothing(t *testing.T) {
	t.Parallel()

	parentVS := &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "default"},
		Spec:       conf_v1.VirtualServerSpec{Host: "example.com"},
	}
	same := vsrWithSubrouteSplits(50, 50)
	vsEx := &configs.VirtualServerEx{
		VirtualServer:       parentVS,
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{same},
	}
	if got := computeVSRWeightUpdates(vsEx, same, same, 0); len(got) != 0 {
		t.Errorf("computeVSRWeightUpdates() with identical prev/cur returned %d updates, want 0", len(got))
	}
}

func TestIsWeightOnlyVSDiff(t *testing.T) {
	t.Parallel()

	base := vsWithRouteSplits(50, 50)

	tests := []struct {
		name string
		prev *conf_v1.VirtualServer
		cur  *conf_v1.VirtualServer
		want bool
	}{
		{
			name: "identical specs",
			prev: base,
			cur:  base.DeepCopy(),
			want: true,
		},
		{
			name: "weight-only diff",
			prev: base,
			cur:  vsWithRouteSplits(70, 30),
			want: true,
		},
		{
			name: "host change is not weight-only",
			prev: base,
			cur: func() *conf_v1.VirtualServer {
				c := base.DeepCopy()
				c.Spec.Host = "other.example.com"
				return c
			}(),
			want: false,
		},
		{
			name: "added route is not weight-only",
			prev: base,
			cur: func() *conf_v1.VirtualServer {
				c := base.DeepCopy()
				c.Spec.Routes = append(c.Spec.Routes, conf_v1.Route{Path: "/tea"})
				return c
			}(),
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isWeightOnlyVSDiff(tc.prev, tc.cur); got != tc.want {
				t.Errorf("isWeightOnlyVSDiff() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsWeightOnlyVSRDiff(t *testing.T) {
	t.Parallel()

	base := vsrWithSubrouteSplits(50, 50)

	tests := []struct {
		name string
		prev *conf_v1.VirtualServerRoute
		cur  *conf_v1.VirtualServerRoute
		want bool
	}{
		{
			name: "identical specs",
			prev: base,
			cur:  base.DeepCopy(),
			want: true,
		},
		{
			name: "weight-only diff",
			prev: base,
			cur:  vsrWithSubrouteSplits(90, 10),
			want: true,
		},
		{
			name: "host change is not weight-only",
			prev: base,
			cur: func() *conf_v1.VirtualServerRoute {
				c := base.DeepCopy()
				c.Spec.Host = "other.example.com"
				return c
			}(),
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isWeightOnlyVSRDiff(tc.prev, tc.cur); got != tc.want {
				t.Errorf("isWeightOnlyVSRDiff() = %v, want %v", got, tc.want)
			}
		})
	}
}

// newLBCForWeightUpdateFallbackTest builds a minimal LoadBalancerController
// wired for the syncVirtualServerWeightUpdate fallback-only paths. syncQueue
// consumes nothing so enqueued tasks accumulate for inspection via Len().
func newLBCForWeightUpdateFallbackTest(t *testing.T, store cache.Store) *LoadBalancerController {
	t.Helper()
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	nsi := map[string]*namespacedInformer{
		"default": {virtualServerLister: store},
	}
	return &LoadBalancerController{
		Logger:              l,
		configuration:       createTestConfiguration(),
		namespacedInformers: nsi,
		syncQueue:           newTaskQueue(l, func(task) {}),
	}
}

func TestSyncVirtualServerWeightUpdate_FallsBackWhenBaselineMissing(t *testing.T) {
	t.Parallel()

	curVs := vsWithRouteSplits(70, 30)
	store := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (interface{}, bool, error) {
			if key == "default/vs" {
				return curVs, true, nil
			}
			return nil, false, nil
		},
	}}
	lbc := newLBCForWeightUpdateFallbackTest(t, store)

	lbc.syncVirtualServerWeightUpdate(task{Kind: virtualServerWeightUpdate, Key: "default/vs"})

	if got := lbc.syncQueue.Len(); got != 1 {
		t.Errorf("expected AddSyncQueue fallback (queue len 1), got %d", got)
	}
}

func TestSyncVirtualServerWeightUpdate_NoOpWhenInformerReturnsMissing(t *testing.T) {
	t.Parallel()

	store := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(_ string) (interface{}, bool, error) {
			return nil, false, nil
		},
	}}
	lbc := newLBCForWeightUpdateFallbackTest(t, store)

	lbc.syncVirtualServerWeightUpdate(task{Kind: virtualServerWeightUpdate, Key: "default/vs"})

	if got := lbc.syncQueue.Len(); got != 0 {
		t.Errorf("expected no enqueue when VS is gone, got queue len %d", got)
	}
}

func TestSyncVirtualServerRouteWeightUpdate_FallsBackWhenBaselineMissing(t *testing.T) {
	t.Parallel()

	curVsr := vsrWithSubrouteSplits(70, 30)
	store := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (interface{}, bool, error) {
			if key == "default/vsr" {
				return curVsr, true, nil
			}
			return nil, false, nil
		},
	}}
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	nsi := map[string]*namespacedInformer{
		"default": {virtualServerRouteLister: store},
	}
	lbc := &LoadBalancerController{
		Logger:              l,
		configuration:       createTestConfiguration(),
		namespacedInformers: nsi,
		syncQueue:           newTaskQueue(l, func(task) {}),
	}

	lbc.syncVirtualServerRouteWeightUpdate(task{Kind: virtualServerRouteWeightUpdate, Key: "default/vsr"})

	if got := lbc.syncQueue.Len(); got != 1 {
		t.Errorf("expected AddSyncQueue fallback (queue len 1), got %d", got)
	}
}

// TestZeroOutVirtualServerSplitWeights_IsPureAndPreservesStructure exists so
// that the isWeightOnlyVSDiff / isWeightOnlyVSRDiff helpers, which rely on the
// zero-out being idempotent and structure-preserving, don't silently regress
// if the zero-out helpers are later moved or rewritten.
func TestZeroOutVirtualServerSplitWeights_IsPureAndPreservesStructure(t *testing.T) {
	t.Parallel()

	original := vsWithRouteSplits(70, 30)
	clone := original.DeepCopy()

	zeroOutVirtualServerSplitWeights(clone)

	// Original untouched.
	if diff := cmp.Diff(vsWithRouteSplits(70, 30), original); diff != "" {
		t.Errorf("zeroOutVirtualServerSplitWeights mutated an alias (-want +got):\n%s", diff)
	}
	// Structure preserved on clone.
	if len(clone.Spec.Routes) != 1 || len(clone.Spec.Routes[0].Splits) != 2 {
		t.Errorf("zeroOutVirtualServerSplitWeights damaged split structure: %+v", clone.Spec.Routes)
	}
	if clone.Spec.Routes[0].Splits[0].Weight != 0 || clone.Spec.Routes[0].Splits[1].Weight != 0 {
		t.Errorf("zeroOutVirtualServerSplitWeights did not zero all weights: %+v", clone.Spec.Routes[0].Splits)
	}
}

// seedVSBaseline writes vs directly into the Configuration's tracked map,
// bypassing validation and ingress-class filtering. Only safe in fallback
// tests where the sync handler returns before AddOrUpdateVirtualServer is
// called; anything past that point relies on rebuildHosts state that this
// shortcut does not populate.
func seedVSBaseline(c *Configuration, vs *conf_v1.VirtualServer) {
	key := vs.Namespace + "/" + vs.Name
	c.lock.Lock()
	defer c.lock.Unlock()
	c.virtualServers[key] = vs
}

func TestSyncVirtualServerWeightUpdate_FallsBackOnNonWeightOnlyDiff(t *testing.T) {
	t.Parallel()

	baseline := vsWithRouteSplits(50, 50)
	// Same route/split shape, weights unchanged — but Host differs, so the
	// diff is not weight-only.
	curVs := baseline.DeepCopy()
	curVs.Spec.Host = "other.example.com"

	store := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (interface{}, bool, error) {
			if key == "default/vs" {
				return curVs, true, nil
			}
			return nil, false, nil
		},
	}}
	lbc := newLBCForWeightUpdateFallbackTest(t, store)
	seedVSBaseline(lbc.configuration, baseline)

	lbc.syncVirtualServerWeightUpdate(task{Kind: virtualServerWeightUpdate, Key: "default/vs"})

	if got := lbc.syncQueue.Len(); got != 1 {
		t.Errorf("expected AddSyncQueue fallback (queue len 1), got %d", got)
	}
}

func TestSyncVirtualServerWeightUpdate_FallsBackOnStateInvalid(t *testing.T) {
	t.Parallel()

	baseline := vsWithRouteSplits(50, 50)
	curVs := vsWithRouteSplits(70, 30)
	curVs.Status.State = conf_v1.StateInvalid

	store := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (interface{}, bool, error) {
			if key == "default/vs" {
				return curVs, true, nil
			}
			return nil, false, nil
		},
	}}
	lbc := newLBCForWeightUpdateFallbackTest(t, store)
	seedVSBaseline(lbc.configuration, baseline)

	lbc.syncVirtualServerWeightUpdate(task{Kind: virtualServerWeightUpdate, Key: "default/vs"})

	if got := lbc.syncQueue.Len(); got != 1 {
		t.Errorf("expected AddSyncQueue fallback (queue len 1), got %d", got)
	}
}

// vsWith2WayRouteSplitAcrossRoutes returns a VS with n routes, each carrying a
// 2-way top-level split. Used to build predictable startingSplitClientsIndex
// offsets for getStartingSplitClientsIndex tests.
func vsWith2WayRouteSplitAcrossRoutes(n int) *conf_v1.VirtualServer {
	vs := &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "default"},
		Spec:       conf_v1.VirtualServerSpec{Host: "example.com"},
	}
	for i := 0; i < n; i++ {
		vs.Spec.Routes = append(vs.Spec.Routes, conf_v1.Route{
			Path: "/",
			Splits: []conf_v1.Split{
				{Weight: 50, Action: &conf_v1.Action{Pass: "u1"}},
				{Weight: 50, Action: &conf_v1.Action{Pass: "u2"}},
			},
		})
	}
	return vs
}

// vsrWith2WaySubrouteSplits returns a VSR with the given name and n
// 2-way-split subroutes.
func vsrWith2WaySubrouteSplits(name string, n int) *conf_v1.VirtualServerRoute {
	vsr := &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       conf_v1.VirtualServerRouteSpec{Host: "example.com"},
	}
	for i := 0; i < n; i++ {
		vsr.Spec.Subroutes = append(vsr.Spec.Subroutes, conf_v1.Route{
			Path: "/coffee",
			Splits: []conf_v1.Split{
				{Weight: 50, Action: &conf_v1.Action{Pass: "u1"}},
				{Weight: 50, Action: &conf_v1.Action{Pass: "u2"}},
			},
		})
	}
	return vsr
}

func TestGetStartingSplitClientsIndex(t *testing.T) {
	t.Parallel()

	target := vsrWith2WaySubrouteSplits("target", 1)

	tests := []struct {
		name string
		vsEx *configs.VirtualServerEx
		vsr  *conf_v1.VirtualServerRoute
		want int
	}{
		{
			name: "no parent VS splits, target VSR is first",
			vsEx: &configs.VirtualServerEx{
				VirtualServer:       vsWith2WayRouteSplitAcrossRoutes(0),
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{target},
			},
			vsr:  target,
			want: 0,
		},
		{
			name: "one 2-way split on parent VS pushes offset by splitClientAmount",
			vsEx: &configs.VirtualServerEx{
				VirtualServer:       vsWith2WayRouteSplitAcrossRoutes(1),
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{target},
			},
			vsr:  target,
			want: splitClientAmountWhenWeightChangesDynamicReload,
		},
		{
			name: "three 2-way splits on parent VS multiply the offset",
			vsEx: &configs.VirtualServerEx{
				VirtualServer:       vsWith2WayRouteSplitAcrossRoutes(3),
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{target},
			},
			vsr:  target,
			want: 3 * splitClientAmountWhenWeightChangesDynamicReload,
		},
		{
			name: "preceding VSR with two 2-way subroute splits contributes to the offset",
			vsEx: &configs.VirtualServerEx{
				VirtualServer: vsWith2WayRouteSplitAcrossRoutes(0),
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					vsrWith2WaySubrouteSplits("prev", 2),
					target,
				},
			},
			vsr:  target,
			want: 2 * splitClientAmountWhenWeightChangesDynamicReload,
		},
		{
			name: "parent VS splits combine with preceding VSR splits",
			vsEx: &configs.VirtualServerEx{
				VirtualServer: vsWith2WayRouteSplitAcrossRoutes(1),
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					vsrWith2WaySubrouteSplits("prev", 1),
					target,
				},
			},
			vsr:  target,
			want: 2 * splitClientAmountWhenWeightChangesDynamicReload,
		},
	}

	lbc := &LoadBalancerController{}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := lbc.getStartingSplitClientsIndex(tc.vsr, tc.vsEx); got != tc.want {
				t.Errorf("getStartingSplitClientsIndex() = %d, want %d", got, tc.want)
			}
		})
	}
}
