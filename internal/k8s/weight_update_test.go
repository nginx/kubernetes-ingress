package k8s

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The split_clients index accounting in computeVSWeightUpdates must mirror
// configs.GenerateVirtualServerConfig exactly. There are four branches, and
// this test has to cover all of them, because the walk reimplements each one:
//
//	route-level 2-way split      -> += splitClientAmountWhenWeightChangesDynamicReload
//	route-level non-2-way split  -> += 1
//	match-level 2-way split      -> += splitClientAmountWhenWeightChangesDynamicReload
//	match-level non-2-way split  -> += 1
//
// A route carrying both matches and route-level splits accounts the matches
// first, then the route-level splits, sharing one counter.
//
// The ground truth for these sequences is pinned on the generator side by
// TestGenerateVirtualServerConfigSplitClientsIndexSequence in
// internal/configs/virtualserver_routing_test.go, which uses the same
// fixtures and the same literal indices. The two cannot be compared directly
// in one test because virtualServerConfigurator is unexported, so if the
// expectations there change, they must change here too.

// weightUpdateVS builds a VS whose routes are described by routeSplits: one
// route per entry, and within each route one match per matchSplits entry
// followed by the route-level split. A nil or empty split list means "no
// splits on this route/match".
type weightUpdateRoute struct {
	matchSplits [][]int
	routeSplits []int
}

func buildWeightUpdateVS(routes []weightUpdateRoute) *conf_v1.VirtualServer {
	vs := &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cafe"},
		Spec: conf_v1.VirtualServerSpec{
			Host: "cafe.example.com",
		},
	}

	for i, r := range routes {
		route := conf_v1.Route{Path: fmt.Sprintf("/route-%d", i)}

		for _, weights := range r.matchSplits {
			route.Matches = append(route.Matches, conf_v1.Match{
				Conditions: []conf_v1.Condition{{Header: "x-test", Value: "yes"}},
				Splits:     buildSplits(weights),
			})
		}
		route.Splits = buildSplits(r.routeSplits)

		vs.Spec.Routes = append(vs.Spec.Routes, route)
	}
	return vs
}

func buildSplits(weights []int) []conf_v1.Split {
	if len(weights) == 0 {
		return nil
	}
	splits := make([]conf_v1.Split, 0, len(weights))
	for i, w := range weights {
		splits = append(splits, conf_v1.Split{
			Weight: w,
			Action: &conf_v1.Action{Pass: fmt.Sprintf("upstream-%d", i)},
		})
	}
	return splits
}

// wantUpdate builds the WeightUpdate that computeVSWeightUpdates should emit
// for a 2-way split sitting at splitClientsIndex with the given new weights.
// Deriving it from the namer keeps these tests about index arithmetic (which
// is what the bug is) rather than about zone naming (which is not).
func wantUpdate(vs *conf_v1.VirtualServer, splitClientsIndex, w0, w1 int) configs.WeightUpdate {
	namer := configs.NewVSVariableNamer(vs)
	return configs.WeightUpdate{
		Zone:  namer.GetNameOfKeyvalZoneForSplitClientIndex(splitClientsIndex),
		Key:   namer.GetNameOfKeyvalKeyForSplitClientIndex(splitClientsIndex),
		Value: namer.GetNameOfKeyOfMapForWeights(splitClientsIndex, w0, w1),
	}
}

func TestComputeVSWeightUpdates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		old  []weightUpdateRoute
		cur  []weightUpdateRoute
		// wantIndexes are the split_clients indices the updates must target,
		// paired with the new weights at that index.
		wantIndexes [][3]int // {splitClientsIndex, weight0, weight1}
	}{
		{
			name:        "single route-level split changes",
			old:         []weightUpdateRoute{{routeSplits: []int{50, 50}}},
			cur:         []weightUpdateRoute{{routeSplits: []int{70, 30}}},
			wantIndexes: [][3]int{{0, 70, 30}},
		},
		{
			name: "two route-level splits, only the first changes",
			old: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{70, 30}},
				{routeSplits: []int{50, 50}},
			},
			wantIndexes: [][3]int{{0, 70, 30}},
		},
		{
			name: "two route-level splits, only the second changes",
			old: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{70, 30}},
			},
			wantIndexes: [][3]int{{101, 70, 30}},
		},
		{
			// Regression case for the double-increment: the extra increment
			// only fired when an earlier route-level split had itself changed,
			// so each changed split added a surplus 101 to every index after
			// it. Today this returns indices 0 and 202.
			name: "two route-level splits, both change",
			old: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{70, 30}},
				{routeSplits: []int{60, 40}},
			},
			wantIndexes: [][3]int{{0, 70, 30}, {101, 60, 40}},
		},
		{
			// Drift accumulates. Today this returns 0, 202, 404 — and 404 is
			// past the end of the 303 split_clients blocks the generator
			// emitted, so that update is silently dropped by the keyval API.
			name: "three route-level splits, all change",
			old: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{70, 30}},
				{routeSplits: []int{60, 40}},
				{routeSplits: []int{90, 10}},
			},
			wantIndexes: [][3]int{{0, 70, 30}, {101, 60, 40}, {202, 90, 10}},
		},
		{
			// Match-level and route-level splits share one counter sequence.
			name: "match split then route split, both change",
			old: []weightUpdateRoute{
				{matchSplits: [][]int{{50, 50}}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{matchSplits: [][]int{{80, 20}}},
				{routeSplits: []int{60, 40}},
			},
			wantIndexes: [][3]int{{0, 80, 20}, {101, 60, 40}},
		},
		{
			// A non-2-way split advances the counter by 1, not 101. The
			// following 2-way split therefore sits at index 1.
			name: "three-way split advances index by one",
			old: []weightUpdateRoute{
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{70, 30}},
			},
			wantIndexes: [][3]int{{1, 70, 30}},
		},
		{
			// Mirrors the "non-two-way splits advance the counter by one
			// each" fixture in the generator-side test: two 3-way splits
			// ahead of a 2-way one, so it lands at index 2.
			name: "two non-two-way splits then a two-way split",
			old: []weightUpdateRoute{
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{70, 30}},
			},
			wantIndexes: [][3]int{{2, 70, 30}},
		},
		{
			// Mirrors the "mixed match-level, non-two-way and route-level
			// splits" fixture in the generator-side test. Covers all four
			// accounting branches in one sequence, including a route that
			// carries both matches and route-level splits:
			//
			//	/a match[0] 2-way   -> index 0,   +101
			//	/a match[1] 3-way   -> index 101, +1
			//	/a route    2-way   -> index 102, +101
			//	/b route    3-way   -> index 203, +1
			//	/c route    2-way   -> index 204, +101
			//
			// The 3-way splits are left unchanged: they emit no update but
			// must still advance the counter, which is exactly what would
			// break if a generator branch changed underneath us.
			name: "mixed match-level, non-two-way and route-level splits",
			old: []weightUpdateRoute{
				{matchSplits: [][]int{{50, 50}, {34, 33, 33}}, routeSplits: []int{50, 50}},
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{matchSplits: [][]int{{80, 20}, {34, 33, 33}}, routeSplits: []int{70, 30}},
				{routeSplits: []int{34, 33, 33}},
				{routeSplits: []int{60, 40}},
			},
			wantIndexes: [][3]int{{0, 80, 20}, {102, 70, 30}, {204, 60, 40}},
		},
		{
			name: "identical specs produce no updates",
			old: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
			},
			cur: []weightUpdateRoute{
				{routeSplits: []int{50, 50}},
				{routeSplits: []int{50, 50}},
			},
			wantIndexes: nil,
		},
		{
			name:        "route with no splits produces no updates",
			old:         []weightUpdateRoute{{}},
			cur:         []weightUpdateRoute{{}},
			wantIndexes: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			vsOld := buildWeightUpdateVS(test.old)
			vsNew := buildWeightUpdateVS(test.cur)

			var want []configs.WeightUpdate
			for _, w := range test.wantIndexes {
				want = append(want, wantUpdate(vsNew, w[0], w[1], w[2]))
			}

			got := computeVSWeightUpdates(vsOld, vsNew)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("computeVSWeightUpdates() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
