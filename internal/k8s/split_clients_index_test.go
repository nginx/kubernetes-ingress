package k8s

import (
	"fmt"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// splitShape describes the splits on one route or subroute: zero or more
// matches, each with its own split weights, followed by the route-level split
// weights. An empty weight list means "no splits here".
type splitShape struct {
	matchSplits [][]int
	routeSplits []int
}

func splitsFromWeights(weights []int) []conf_v1.Split {
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

func routesFromShapes(pathPrefix string, shapes []splitShape) []conf_v1.Route {
	var routes []conf_v1.Route
	for i, s := range shapes {
		route := conf_v1.Route{Path: fmt.Sprintf("/%s-%d", pathPrefix, i)}
		for _, weights := range s.matchSplits {
			route.Matches = append(route.Matches, conf_v1.Match{
				Conditions: []conf_v1.Condition{{Header: "x-test", Value: "yes"}},
				Splits:     splitsFromWeights(weights),
			})
		}
		route.Splits = splitsFromWeights(s.routeSplits)
		routes = append(routes, route)
	}
	return routes
}

func testVSRWithSubroutes(namespace, name string, shapes []splitShape) *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host:      "cafe.example.com",
			Subroutes: routesFromShapes(name, shapes),
		},
	}
}

// TestGetStartingSplitClientsIndex covers the offset a VirtualServerRoute's
// subroutes start at within its referencing VirtualServer's split_clients
// sequence.
//
// The walk accumulates the VS's own routes first, then every VSR ahead of the
// target in vsEx.VirtualServerRoutes, advancing by
// splitClientAmountWhenWeightChangesDynamicReload per 2-way split and by 1 for
// any other split count.
//
// Identifying the target VSR by name alone is not sufficient: a VS may
// reference VSRs in other namespaces (`route: other-ns/coffee`, see
// Configuration.validateVSRs), and routeSelector matches across all
// namespaces, so vsEx.VirtualServerRoutes can hold two VSRs with the same
// name from different namespaces.
func TestGetStartingSplitClientsIndex(t *testing.T) {
	t.Parallel()

	const step = splitClientAmountWhenWeightChangesDynamicReload

	oneTwoWaySubroute := []splitShape{{routeSplits: []int{50, 50}}}

	tests := []struct {
		name string
		// vsShapes are the splits on the referencing VS's own routes.
		vsShapes []splitShape
		vsrs     []*conf_v1.VirtualServerRoute
		// targetIdx is the index into vsrs of the VSR to look up.
		targetIdx int
		want      int
	}{
		{
			name:      "single VSR, no VS-level splits",
			vsrs:      []*conf_v1.VirtualServerRoute{testVSRWithSubroutes("default", "coffee", oneTwoWaySubroute)},
			targetIdx: 0,
			want:      0,
		},
		{
			name:     "VS route-level two-way split offsets the first VSR",
			vsShapes: []splitShape{{routeSplits: []int{50, 50}}},
			vsrs:     []*conf_v1.VirtualServerRoute{testVSRWithSubroutes("default", "coffee", oneTwoWaySubroute)},
			// The VS's own 2-way split consumes indices 0..100.
			targetIdx: 0,
			want:      step,
		},
		{
			name: "second VSR starts after the first VSR's two-way split",
			vsrs: []*conf_v1.VirtualServerRoute{
				testVSRWithSubroutes("default", "coffee", oneTwoWaySubroute),
				testVSRWithSubroutes("default", "tea", oneTwoWaySubroute),
			},
			targetIdx: 1,
			want:      step,
		},
		{
			// Regression case. Both VSRs are named "coffee" but live in
			// different namespaces, which is legal and reachable via either a
			// namespaced `route:` reference or a routeSelector. Matching on
			// name alone returns 0 for both, so ns-b/coffee's weight updates
			// land in ns-a/coffee's keyval zone.
			name: "same-name VSRs in different namespaces are distinguished",
			vsrs: []*conf_v1.VirtualServerRoute{
				testVSRWithSubroutes("ns-a", "coffee", oneTwoWaySubroute),
				testVSRWithSubroutes("ns-b", "coffee", oneTwoWaySubroute),
			},
			targetIdx: 1,
			want:      step,
		},
		{
			// The same collision with the target first: this direction
			// already returns 0 today, so it pins that the fix does not
			// overshoot in the other direction.
			name: "same-name VSRs in different namespaces, target is first",
			vsrs: []*conf_v1.VirtualServerRoute{
				testVSRWithSubroutes("ns-a", "coffee", oneTwoWaySubroute),
				testVSRWithSubroutes("ns-b", "coffee", oneTwoWaySubroute),
			},
			targetIdx: 0,
			want:      0,
		},
		{
			// Three same-name VSRs: drift accumulates, so the third is two
			// steps in rather than one.
			name: "three same-name VSRs in different namespaces",
			vsrs: []*conf_v1.VirtualServerRoute{
				testVSRWithSubroutes("ns-a", "coffee", oneTwoWaySubroute),
				testVSRWithSubroutes("ns-b", "coffee", oneTwoWaySubroute),
				testVSRWithSubroutes("ns-c", "coffee", oneTwoWaySubroute),
			},
			targetIdx: 2,
			want:      2 * step,
		},
		{
			// Non-2-way splits advance by 1, and match-level splits count
			// too, so this exercises the accounting either side of the
			// identity check as well as the check itself.
			name: "mixed split shapes ahead of a same-name VSR",
			vsShapes: []splitShape{
				{matchSplits: [][]int{{50, 50}}}, // +step
				{routeSplits: []int{34, 33, 33}}, // +1
			},
			vsrs: []*conf_v1.VirtualServerRoute{
				testVSRWithSubroutes("ns-a", "coffee", []splitShape{
					{routeSplits: []int{50, 50}},     // +step
					{routeSplits: []int{34, 33, 33}}, // +1
				}),
				testVSRWithSubroutes("ns-b", "coffee", oneTwoWaySubroute),
			},
			targetIdx: 1,
			want:      2*step + 2,
		},
		{
			// A VSR absent from the VS's list yields the total accumulated
			// offset. Pinning the existing behaviour so the fix is not
			// mistaken for changing it.
			name: "target VSR not referenced by the VS",
			vsrs: []*conf_v1.VirtualServerRoute{
				testVSRWithSubroutes("ns-a", "coffee", oneTwoWaySubroute),
			},
			targetIdx: -1,
			want:      step,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			vsEx := &configs.VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cafe"},
					Spec: conf_v1.VirtualServerSpec{
						Host:   "cafe.example.com",
						Routes: routesFromShapes("route", test.vsShapes),
					},
				},
				VirtualServerRoutes: test.vsrs,
			}

			target := testVSRWithSubroutes("other-ns", "absent", oneTwoWaySubroute)
			if test.targetIdx >= 0 {
				target = test.vsrs[test.targetIdx]
			}

			if got := getStartingSplitClientsIndex(target, vsEx); got != test.want {
				t.Errorf("getStartingSplitClientsIndex(%s/%s) = %d, want %d",
					target.Namespace, target.Name, got, test.want)
			}
		})
	}
}
