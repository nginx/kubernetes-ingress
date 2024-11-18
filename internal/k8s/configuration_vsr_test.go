package k8s

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WIP - Jakub
func TestAddVirtualServerVSR(t *testing.T) {

	// Add a VirtualServer
	vs := createTestVirtualServer("virtualserver", "foo.example.com")
	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: vs,
			},
		},
	}

	// =========
	// Note: call t.Fatal() as there is no point to carry on and update the VS if the VS is not created
	// meaning we have errors or `problems` when creating the VS.
	configuration := createTestConfiguration()
	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.AddOrUpdateVirtualServer(vs)

	if !cmp.Equal(expectedChanges, changes) {
		t.Fatal(cmp.Diff(expectedChanges, changes))
	}
	if !cmp.Equal(expectedProblems, problems) {
		t.Fatal(cmp.Diff(expectedProblems, problems))
	}
	// ========= End Add VS =========

	// Update VirtualServer

	updatedVS := vs.DeepCopy()
	updatedVS.Generation++
	updatedVS.Spec.ServerSnippets = "# snippet"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedVS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(updatedVS)
	if !cmp.Equal(expectedChanges, changes) {
		t.Fatal(cmp.Diff(expectedChanges, changes))
	}
	if !cmp.Equal(expectedProblems, problems) {
		t.Fatal(cmp.Diff(expectedProblems, problems))
	}
	// ========= End Update VS =========

	// Make VirtualServer invalid

	invalidVS := updatedVS.DeepCopy()
	invalidVS.Generation++
	invalidVS.Spec.Host = ""

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedVS,
			},
			Error: "spec.host: Required value",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(invalidVS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore VirtualServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedVS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(updatedVS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update VirtualServer host

	updatedHostVS := updatedVS.DeepCopy()
	updatedHostVS.Generation++
	updatedHostVS.Spec.Host = "bar.example.com"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedHostVS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(updatedHostVS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete VirtualServer
	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedHostVS,
			},
		},
	}

	changes, problems = configuration.DeleteVirtualServer("default/virtualserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

// Test if correct changes and problems are reported
// if we try to update VS with invalid configuration.
//
// TODO: add workflow (Jakub)
func TestAddVirtualServer_InvalidVS(t *testing.T) {
	t.Parallel()

}

// WIP - Jakub
// TODO: vsr route selector test
func TestAddVirtualServerWithVirtualServerRoutesVSR(t *testing.T) {
	configuration := createTestConfiguration()

	// Add VirtualServerRoute-1

	vsr1 := createTestVirtualServerRoute("virtualserverroute-1", "foo.example.com", "/first", nil)
	var expectedChanges []ResourceChange
	expectedProblems := []ConfigurationProblem{
		{
			Object:  vsr1,
			Reason:  "NoVirtualServerFound",
			Message: "VirtualServer is invalid or doesn't exist",
		},
	}

	changes, problems := configuration.AddOrUpdateVirtualServerRoute(vsr1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add VirtualServer

	vs := createTestVirtualServerWithRoutes(
		"virtualserver",
		"foo.example.com",
		[]conf_v1.Route{
			{
				Path:  "/first",
				Route: "virtualserverroute-1",
			},
			{
				Path:  "/second",
				Route: "virtualserverroute-2",
			},
			{
				Path:          "/",
				RouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "route"}},
			},
		})
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-2 doesn't exist or invalid"},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServer(vs)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add VirtualServerRoute-2

	vsr2 := createTestVirtualServerRoute("virtualserverroute-2", "foo.example.com", "/second", nil)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr2},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(vsr2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update VirtualServerRoute-1

	updatedVSR1 := vsr1.DeepCopy()
	updatedVSR1.Generation++
	updatedVSR1.Spec.Subroutes[0].LocationSnippets = "# snippet"
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{updatedVSR1, vsr2},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(updatedVSR1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add VirtualServerRoute-3 and VirtualServerRoute-4 with selectors

	vsr3 := createTestVirtualServerRoute("virtualserverroute-3", "foo.example.com", "/third", map[string]string{"app": "route"})
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:               vs,
				VirtualServerRoutes:         []*conf_v1.VirtualServerRoute{updatedVSR1, vsr2, vsr3},
				VirtualServerRouteSelectors: map[string][]string{"app=route": {"default/virtualserverroute-3"}},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(vsr3)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make VirtualServerRoute-1 invalid

	invalidVSR1 := updatedVSR1.DeepCopy()
	invalidVSR1.Generation++
	invalidVSR1.Spec.Host = ""
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2, vsr3},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 doesn't exist or invalid"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  invalidVSR1,
			IsError: true,
			Reason:  "Rejected",
			Message: "VirtualServerRoute default/virtualserverroute-1 was rejected with error: spec.host: Required value",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(invalidVSR1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore VirtualServerRoute-1

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr2, vsr3},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(vsr1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make VirtualServerRoute-1 invalid for VirtualServer

	invalidForVSVSR1 := vsr1.DeepCopy()
	invalidForVSVSR1.Generation++
	invalidForVSVSR1.Spec.Subroutes[0].Path = "/"
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2, vsr3},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 is invalid: spec.subroutes[0]: Invalid value: \"/\": must start with '/first'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  invalidForVSVSR1,
			Reason:  "Ignored",
			Message: "VirtualServer default/virtualserver ignores VirtualServerRoute",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(invalidForVSVSR1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore VirtualServerRoute-1

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr2, vsr3},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(vsr1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update host of VirtualServerRoute-2

	updatedVSR2 := vsr2.DeepCopy()
	updatedVSR2.Generation++
	updatedVSR2.Spec.Host = "bar.example.com"
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr3},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-2 is invalid: spec.host: Invalid value: \"bar.example.com\": must be equal to 'foo.example.com'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedVSR2,
			Reason:  "NoVirtualServerFound",
			Message: "VirtualServer is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(updatedVSR2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update host of VirtualServer

	updatedVS := vs.DeepCopy()
	updatedVS.Generation++
	updatedVS.Spec.Host = "bar.example.com"
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       updatedVS,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{updatedVSR2},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 is invalid: spec.host: Invalid value: \"foo.example.com\": must be equal to 'bar.example.com'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  vsr1,
			Reason:  "NoVirtualServerFound",
			Message: "VirtualServer is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(updatedVS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore host of VirtualServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr3},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-2 is invalid: spec.host: Invalid value: \"bar.example.com\": must be equal to 'foo.example.com'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedVSR2,
			Reason:  "NoVirtualServerFound",
			Message: "VirtualServer is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(vs)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore host of VirtualServerRoute-2

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr2, vsr3},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServerRoute(vsr2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove VirtualServerRoute-1

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2, vsr3},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 doesn't exist or invalid"},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteVirtualServerRoute("default/virtualserverroute-1")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove VirtualServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 doesn't exist or invalid"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  vsr2,
			Reason:  "NoVirtualServerFound",
			Message: "VirtualServer is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.DeleteVirtualServer("default/virtualserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove VirtualServerRoute-2

	expectedChanges = nil
	expectedProblems = nil

	changes, problems = configuration.DeleteVirtualServerRoute("default/virtualserverroute-2")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
}

// WIP (Jakub)
// TODO: vsr route selector test
func TestIsEqualForVirtualServersVSR(t *testing.T) {
	t.Parallel()
	vs := createTestVirtualServerWithRoutes(
		"virtualserver",
		"foo.example.com",
		[]conf_v1.Route{
			{
				Path:  "/",
				Route: "virtualserverroute",
			},
		})
	vsr := createTestVirtualServerRoute("virtualserverroute", "foo.example.com", "/", nil)

	vsWithUpdatedGen := vs.DeepCopy()
	vsWithUpdatedGen.Generation++

	vsrWithUpdatedGen := vsr.DeepCopy()
	vsrWithUpdatedGen.Generation++

	tests := []struct {
		vsConfig1 *VirtualServerConfiguration
		vsConfig2 *VirtualServerConfiguration
		expected  bool
		msg       string
	}{
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, nil, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, nil, []string{}),
			expected:  true,
			msg:       "equal virtual servers",
		},
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, nil, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vsWithUpdatedGen, []*conf_v1.VirtualServerRoute{vsr}, nil, []string{}),
			expected:  false,
			msg:       "virtual servers with different generation",
		},
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, nil, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{}, nil, []string{}),
			expected:  false,
			msg:       "virtual servers with different number of virtual server routes",
		},
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, nil, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsrWithUpdatedGen}, nil, []string{}),
			expected:  false,
			msg:       "virtual servers with virtual server routes with different generation",
		},
	}

	for _, test := range tests {
		result := test.vsConfig1.IsEqual(test.vsConfig2)
		if result != test.expected {
			t.Errorf("IsEqual() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}
