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
// configs.GenerateVirtualServerConfig exactly: the generator advances its
// running counter by splitClientAmountWhenWeightChangesDynamicReload (101) for
// every 2-way split, because generateSplitsForWeightChangesDynamicReload emits
// 101 split_clients blocks for one, and by 1 for any other split count.
//
// The ground truth for that sequence is pinned on the generator side by
// TestGenerateVirtualServerConfigSplitClientsIndexSequence in
// internal/configs/virtualserver_routing_test.go.  If the generator's
// accounting ever changes, that test fails and the walk here needs the same
// change.  The two cannot be compared directly in one test because
// virtualServerConfigurator is unexported.

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
