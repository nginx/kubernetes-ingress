package k8s

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func createTestConfiguration() *Configuration {
	lbc := LoadBalancerController{
		ingressClass: "nginx",
		Logger:       nl.LoggerFromContext(context.Background()),
	}
	isPlus := false
	appProtectEnabled := false
	appProtectDosEnabled := false
	internalRoutesEnabled := false
	isTLSPassthroughEnabled := true
	certManagerEnabled := true
	snippetsEnabled := true
	isIPV6Disabled := false
	isDirectiveAutoadjustEnabled := false
	return NewConfiguration(
		lbc.HasCorrectIngressClass,
		isPlus,
		appProtectEnabled,
		appProtectDosEnabled,
		internalRoutesEnabled,
		validation.NewVirtualServerValidator(validation.IsPlus(isTLSPassthroughEnabled), validation.IsDosEnabled(appProtectDosEnabled), validation.IsCertManagerEnabled(certManagerEnabled)),
		validation.NewGlobalConfigurationValidator(map[int]bool{
			80:  true,
			443: true,
		}),
		validation.NewTransportServerValidator(isTLSPassthroughEnabled, snippetsEnabled, isPlus),
		isTLSPassthroughEnabled,
		snippetsEnabled,
		certManagerEnabled,
		isIPV6Disabled,
		isDirectiveAutoadjustEnabled,
	)
}

func TestAddIngressForRegularIngress(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem

	// Add a new Ingress

	ing := createTestIngress("ingress", "foo.example.com")
	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: ing,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}

	changes, problems := configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update the Ingress

	updatedIng := ing.DeepCopy()
	updatedIng.Annotations["nginx.org/max_fails"] = "1"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: updatedIng,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(updatedIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the Ingress invalid

	invalidIng := updatedIng.DeepCopy()
	invalidIng.Generation++
	invalidIng.Spec.Rules = []networking.IngressRule{
		{
			Host:             "foo.example.com",
			IngressRuleValue: networking.IngressRuleValue{},
		},
		{
			Host:             "foo.example.com",
			IngressRuleValue: networking.IngressRuleValue{},
		},
	}

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &IngressConfiguration{
				Ingress: updatedIng,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
			Error: `spec.rules[1].host: Duplicate value: "foo.example.com"`,
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(invalidIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore the Ingress

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: updatedIng,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(updatedIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update the host of the Ingress

	updatedHostIng := updatedIng.DeepCopy()
	updatedHostIng.Generation++
	updatedHostIng.Spec.Rules = []networking.IngressRule{
		{
			Host:             "bar.example.com",
			IngressRuleValue: networking.IngressRuleValue{},
		},
	}

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: updatedHostIng,
				ValidHosts: map[string]bool{
					"bar.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(updatedHostIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete Ingress
	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &IngressConfiguration{
				Ingress: updatedHostIng,
				ValidHosts: map[string]bool{
					"bar.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}

	changes, problems = configuration.DeleteIngress("default/ingress")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddInvalidIngress(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	ing := createTestIngress("ingress", "foo.example.com", "foo.example.com")

	var expectedChanges []ResourceChange
	expectedProblems := []ConfigurationProblem{
		{
			Object:  ing,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: `spec.rules[1].host: Duplicate value: "foo.example.com"`,
		},
	}

	changes, problems := configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteNonExistingIngress(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.DeleteIngress("default/ingress")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddIngressForMergeableIngresses(t *testing.T) {
	configuration := createTestConfiguration()

	// Add  minion-1

	minion1 := createTestIngressMinion("ingress-minion-1", "foo.example.com", "/path-1")
	var expectedChanges []ResourceChange
	expectedProblems := []ConfigurationProblem{
		{
			Object:  minion1,
			Reason:  nl.EventReasonNoIngressMasterFound,
			Message: "Ingress master is invalid or doesn't exist",
		},
	}

	changes, problems := configuration.AddOrUpdateIngress(minion1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add master

	master := createTestIngressMaster("ingress-master", "foo.example.com")
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(master)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add minion-2

	minion2 := createTestIngressMinion("ingress-minion-2", "foo.example.com", "/path-2")
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(minion2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update minion-1

	updatedMinion1 := minion1.DeepCopy()
	updatedMinion1.Annotations["nginx.org/proxy-connect-timeout"] = "10s"
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: updatedMinion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(updatedMinion1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make minion-1 invalid

	invalidMinion1 := updatedMinion1.DeepCopy()
	invalidMinion1.Generation++
	invalidMinion1.Spec.Rules = []networking.IngressRule{
		{
			Host:             "example.com",
			IngressRuleValue: networking.IngressRuleValue{},
		},
		{
			Host:             "example.com",
			IngressRuleValue: networking.IngressRuleValue{},
		},
	}

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  invalidMinion1,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: `[spec.rules[1].host: Duplicate value: "example.com", spec.rules: Too many: 2: must have at most 1 items]`,
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(invalidMinion1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore minion-1

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: updatedMinion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(updatedMinion1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update host of minion-2

	updatedMinion2 := minion2.DeepCopy()
	updatedMinion2.Generation++
	updatedMinion2.Spec.Rules[0].Host = "bar.example.com"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: updatedMinion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedMinion2,
			Reason:  nl.EventReasonNoIngressMasterFound,
			Message: "Ingress master is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(updatedMinion2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update host of master

	updatedMaster := master.DeepCopy()
	updatedMaster.Generation++
	updatedMaster.Spec.Rules[0].Host = "bar.example.com"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: updatedMaster,
				ValidHosts: map[string]bool{
					"bar.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: updatedMinion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedMinion1,
			Reason:  nl.EventReasonNoIngressMasterFound,
			Message: "Ingress master is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(updatedMaster)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore host
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: updatedMinion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedMinion2,
			Reason:  nl.EventReasonNoIngressMasterFound,
			Message: "Ingress master is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(master)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore host of minion-2

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: updatedMinion1,
						ValidPaths: map[string]bool{
							"/path-1": true,
						},
					},
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(minion2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove minion-1

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteIngress("default/ingress-minion-1")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove master

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/path-2": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  minion2,
			Reason:  nl.EventReasonNoIngressMasterFound,
			Message: "Ingress master is invalid or doesn't exist",
		},
	}

	changes, problems = configuration.DeleteIngress("default/ingress-master")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove minion-2

	expectedChanges = nil
	expectedProblems = nil

	changes, problems = configuration.DeleteIngress("default/ingress-minion-2")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestMinionPathCollisions(t *testing.T) {
	configuration := createTestConfiguration()

	// Add master

	master := createTestIngressMaster("ingress-master", "foo.example.com")
	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster:      true,
				ChildWarnings: map[string][]string{},
			},
		},
	}
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.AddOrUpdateIngress(master)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add  minion-1

	minion1 := createTestIngressMinion("ingress-minion-1", "foo.example.com", "/")
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion1,
						ValidPaths: map[string]bool{
							"/": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(minion1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add minion-2

	minion2 := createTestIngressMinion("ingress-minion-2", "foo.example.com", "/")
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion1,
						ValidPaths: map[string]bool{
							"/": true,
						},
					},
					{
						Ingress:    minion2,
						ValidPaths: map[string]bool{},
					},
				},
				ChildWarnings: map[string][]string{
					"default/ingress-minion-2": {
						"path / is taken by another resource",
					},
				},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(minion2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete minion-1
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: master,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				IsMaster: true,
				Minions: []*MinionConfiguration{
					{
						Ingress: minion2,
						ValidPaths: map[string]bool{
							"/": true,
						},
					},
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteIngress("default/ingress-minion-1")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddIngressWithIncorrectClass(t *testing.T) {
	configuration := createTestConfiguration()

	// Add Ingress with incorrect class

	ing := createTestIngress("regular-ingress", "foo.example.com")
	ing.Annotations["kubernetes.io/ingress.class"] = "someproxy"

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class correct

	updatedIng := ing.DeepCopy()
	updatedIng.Annotations["kubernetes.io/ingress.class"] = "nginx"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: updatedIng,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(updatedIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class incorrect

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &IngressConfiguration{
				Ingress: updatedIng,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddVirtualServer(t *testing.T) {
	configuration := createTestConfiguration()

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem

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

	changes, problems := configuration.AddOrUpdateVirtualServer(vs)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

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
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

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

func TestAddInvalidVirtualServer(t *testing.T) {
	configuration := createTestConfiguration()

	vs := createTestVirtualServer("virtualserver", "")

	var expectedChanges []ResourceChange
	expectedProblems := []ConfigurationProblem{
		{
			Object:  vs,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: "VirtualServer default/virtualserver was rejected with error: spec.host: Required value",
		},
	}

	changes, problems := configuration.AddOrUpdateVirtualServer(vs)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddInvalidVirtualServerWithIncorrectClass(t *testing.T) {
	configuration := createTestConfiguration()

	// Add VirtualServer with incorrect class

	vs := createTestVirtualServer("virtualserver", "example.com")
	vs.Spec.IngressClass = "someproxy"

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.AddOrUpdateVirtualServer(vs)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class correct

	updatedVS := vs.DeepCopy()
	updatedVS.Generation++
	updatedVS.Spec.IngressClass = "nginx"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedVS,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateVirtualServer(updatedVS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class incorrect

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &VirtualServerConfiguration{
				VirtualServer: updatedVS,
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
}

func TestDeleteNonExistingVirtualServer(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.DeleteVirtualServer("default/virtualserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddVirtualServerWithVirtualServerRoutes(t *testing.T) {
	configuration := createTestConfiguration()

	// Add VirtualServerRoute-1

	vsr1 := createTestVirtualServerRoute("virtualserverroute-1", "foo.example.com", "/first")
	var expectedChanges []ResourceChange
	expectedProblems := []ConfigurationProblem{
		{
			Object:  vsr1,
			Reason:  nl.EventReasonNoVirtualServerFound,
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

	vsr2 := createTestVirtualServerRoute("virtualserverroute-2", "foo.example.com", "/second")

	// Add VirtualServerRoute-2

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

	// Make VirtualServerRoute-1 invalid

	invalidVSR1 := updatedVSR1.DeepCopy()
	invalidVSR1.Generation++
	invalidVSR1.Spec.Host = ""
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 doesn't exist or invalid"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  invalidVSR1,
			IsError: true,
			Reason:  nl.EventReasonRejected,
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
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr2},
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
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-1 is invalid: spec.subroutes[0]: Invalid value: \"/\": must start with '/first'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  invalidForVSVSR1,
			Reason:  nl.EventReasonIgnored,
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
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1, vsr2},
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
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-2 is invalid: spec.host: Invalid value: \"bar.example.com\": must be equal to 'foo.example.com'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedVSR2,
			Reason:  nl.EventReasonNoVirtualServerFound,
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
			Reason:  nl.EventReasonNoVirtualServerFound,
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
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1},
				Warnings:            []string{"VirtualServerRoute default/virtualserverroute-2 is invalid: spec.host: Invalid value: \"bar.example.com\": must be equal to 'foo.example.com'"},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  updatedVSR2,
			Reason:  nl.EventReasonNoVirtualServerFound,
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

	// Remove VirtualServerRoute-1

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr2},
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
			Reason:  nl.EventReasonNoVirtualServerFound,
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

func TestAddInvalidVirtualServerRoute(t *testing.T) {
	configuration := createTestConfiguration()

	vsr := createTestVirtualServerRoute("virtualserverroute", "", "/")

	var expectedChanges []ResourceChange
	expectedProblems := []ConfigurationProblem{
		{
			Object:  vsr,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: "VirtualServerRoute default/virtualserverroute was rejected with error: spec.host: Required value",
		},
	}

	changes, problems := configuration.AddOrUpdateVirtualServerRoute(vsr)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddVirtualServerWithIncorrectClass(t *testing.T) {
	configuration := createTestConfiguration()

	vsr := createTestVirtualServerRoute("virtualserver", "foo.example.com", "/")
	vsr.Spec.IngressClass = "someproxy"

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.AddOrUpdateVirtualServerRoute(vsr)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteNonExistingVirtualServerRoute(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.DeleteVirtualServerRoute("default/virtualserverroute")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteVirtualServerRoute() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestHostCollisions(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedProblems []ConfigurationProblem

	masterIng := createTestIngressMaster("master-ingress", "foo.example.com")
	regularIng := createTestIngress("regular-ingress", "foo.example.com", "bar.example.com")
	vs := createTestVirtualServer("virtualserver", "foo.example.com")
	regularIng2 := createTestIngress("regular-ingress-2", "foo.example.com")
	ts := createTestTLSPassthroughTransportServer("transportserver", "foo.example.com")

	// Add TransportServer

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
			},
		},
	}
	expectedProblems = nil

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add VirtualServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
				Warnings:        []string{"host foo.example.com is taken by another resource"},
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: vs,
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Host is taken by another resource",
		},
	}

	changes, problems = configuration.AddOrUpdateVirtualServer(vs)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add regular Ingress

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &VirtualServerConfiguration{
				VirtualServer: vs,
				Warnings:      []string{"host foo.example.com is taken by another resource"},
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress:       regularIng,
				ValidHosts:    map[string]bool{"foo.example.com": true, "bar.example.com": true},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  vs,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Host is taken by another resource",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(regularIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add master Ingress

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress:       regularIng,
				ValidHosts:    map[string]bool{"bar.example.com": true, "foo.example.com": false},
				Warnings:      []string{"host foo.example.com is taken by another resource"},
				ChildWarnings: map[string][]string{},
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress:       masterIng,
				IsMaster:      true,
				ValidHosts:    map[string]bool{"foo.example.com": true},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateIngress(masterIng)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add regular Ingress-2

	expectedChanges = nil
	expectedProblems = []ConfigurationProblem{
		{
			Object:  regularIng2,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "All hosts are taken by other resources",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(regularIng2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete regular Ingress-2
	expectedChanges = nil
	expectedProblems = nil

	changes, problems = configuration.DeleteIngress("default/regular-ingress-2")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete master Ingress

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &IngressConfiguration{
				Ingress:       masterIng,
				IsMaster:      true,
				ValidHosts:    map[string]bool{"foo.example.com": true},
				ChildWarnings: map[string][]string{},
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress:       regularIng,
				ValidHosts:    map[string]bool{"foo.example.com": true, "bar.example.com": true},
				ChildWarnings: map[string][]string{},
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteIngress("default/master-ingress")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete regular Ingress

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &IngressConfiguration{
				Ingress:       regularIng,
				ValidHosts:    map[string]bool{"foo.example.com": true, "bar.example.com": true},
				ChildWarnings: map[string][]string{},
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: vs,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteIngress("default/regular-ingress")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete VirtualServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &VirtualServerConfiguration{
				VirtualServer: vs,
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteVirtualServer("default/virtualserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	ts := createTestTransportServer("transportserver", "tcp-7777", "TCP")

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	// Add TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportServer

	updatedTS := ts.DeepCopy()
	updatedTS.Generation++

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make TransportServer invalid

	invalidTS := updatedTS.DeepCopy()
	invalidTS.Generation++
	invalidTS.Spec.Upstreams = nil

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
			Error: `spec.action.pass: Not found: "myapp"`,
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(invalidTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerWithHost(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	secretName := "echo-secret"

	ts := createTestTransportServerWithHost("transportserver", "echo.example.com", "tcp-7777", secretName)

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	// Add TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportServer

	updatedTS := ts.DeepCopy()
	updatedTS.Generation++

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make TransportServer invalid

	invalidTS := updatedTS.DeepCopy()
	invalidTS.Generation++
	invalidTS.Spec.Upstreams = nil

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
			Error: `spec.action.pass: Not found: "myapp"`,
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(invalidTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerForTLSPassthrough(t *testing.T) {
	configuration := createTestConfiguration()

	ts := createTestTLSPassthroughTransportServer("transportserver", "foo.example.com")

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem

	// Add TransportServer

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// DeleteTransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
			},
		},
	}

	changes, problems = configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestListenerFlip(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "tcp-8888",
			Port:     8888,
			Protocol: "TCP",
		},
	}
	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	ts := createTestTransportServer("transportserver", "tcp-7777", "TCP")

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	// Add TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportServer listener

	updatedListenerTS := ts.DeepCopy()
	updatedListenerTS.Generation++
	updatedListenerTS.Spec.Listener.Name = "tcp-8888"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: updatedListenerTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedListenerTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportSever listener to TLS Passthrough

	updatedWithPassthroughTS := updatedListenerTS.DeepCopy()
	updatedWithPassthroughTS.Generation++
	updatedWithPassthroughTS.Spec.Listener.Name = "tls-passthrough"
	updatedWithPassthroughTS.Spec.Listener.Protocol = "TLS_PASSTHROUGH"
	updatedWithPassthroughTS.Spec.Host = "example.com"

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: updatedListenerTS,
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: updatedWithPassthroughTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedWithPassthroughTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddInvalidTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	ts := createTestTransportServer("transportserver", "", "TCP")

	expectedProblems := []ConfigurationProblem{
		{
			Object:  ts,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: "TransportServer default/transportserver was rejected with error: spec.listener.name: Required value",
		},
	}
	var expectedChanges []ResourceChange

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerWithIncorrectClass(t *testing.T) {
	configuration := createTestConfiguration()

	// Add TransportServer with incorrect class

	ts := createTestTLSPassthroughTransportServer("transportserver", "foo.example.com")
	ts.Spec.IngressClass = "someproxy"

	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class correct

	updatedTS := ts.DeepCopy()
	updatedTS.Generation++
	updatedTS.Spec.IngressClass = "nginx"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				TransportServer: updatedTS,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class incorrect

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				TransportServer: updatedTS,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerWithNonExistingListener(t *testing.T) {
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, []conf_v1.Listener{}, noChanges, noProblems)

	ts := createTestTransportServer("transportserver", "tcp-7777", "TCP")

	expectedProblems := []ConfigurationProblem{
		{
			Object:  ts,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: `Listener tcp-7777 doesn't exist`,
		},
	}
	var expectedChanges []ResourceChange

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteNonExistingTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddOrUpdateGlobalConfiguration(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "tcp-8888",
			Port:     8888,
			Protocol: "TCP",
		},
	}
	gc := createTestGlobalConfiguration(listeners)

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems, err := configuration.AddOrUpdateGlobalConfiguration(gc)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if err != nil {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected error: %v", err)
	}
}

//gocyclo:ignore
func TestAddOrUpdateGlobalConfigurationThenAddTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "tcp-8888",
			Port:     8888,
			Protocol: "TCP",
		},
	}
	gc := createTestGlobalConfiguration(listeners)

	var nilGC *conf_v1.GlobalConfiguration

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems, err := configuration.AddOrUpdateGlobalConfiguration(gc.DeepCopy())
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if err != nil {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected error: %v", err)
	}

	ts1 := createTestTransportServer("transportserver-1", "tcp-7777", "TCP")
	ts2 := createTestTransportServer("transportserver-2", "tcp-8888", "TCP")

	// Add first TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts1,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateTransportServer(ts1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	storedGC := configuration.GetGlobalConfiguration()
	if diff := cmp.Diff(gc, storedGC); diff != "" {
		t.Errorf("GetGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update GlobalConfiguration

	updatedGC1 := gc.DeepCopy()
	updatedGC1.Spec.Listeners[0].Port = 7000

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7000,
				TransportServer: ts1,
			},
		},
	}
	expectedProblems = nil

	changes, problems, err = configuration.AddOrUpdateGlobalConfiguration(updatedGC1.DeepCopy())
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if err != nil {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected error: %v", err)
	}
	storedGC = configuration.GetGlobalConfiguration()
	if diff := cmp.Diff(updatedGC1, storedGC); diff != "" {
		t.Errorf("GetGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add second TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts2,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateTransportServer(ts2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Swap listeners

	// We need to handle this case in Controller propoperly - update config for all TransportServers and reload once
	// to avoid any race conditions
	// and errors like nginx: [emerg] duplicate "0.0.0.0:8888" address and port pair in /etc/nginx/nginx.conf:73

	updatedGC2 := updatedGC1.DeepCopy()
	updatedGC2.Spec.Listeners[0].Port = 8888
	updatedGC2.Spec.Listeners[1].Port = 7000

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts1,
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7000,
				TransportServer: ts2,
			},
		},
	}
	expectedProblems = nil

	changes, problems, err = configuration.AddOrUpdateGlobalConfiguration(updatedGC2.DeepCopy())
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if err != nil {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected error: %v", err)
	}

	// Make listener for TransportServer ts1 invalid

	invalidGC := updatedGC2.DeepCopy()
	invalidGC.Spec.Listeners[0].Port = -1

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts1,
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts1,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-7777 doesn't exist",
		},
	}
	expectedErrMsg := "spec.listeners[0].port: Invalid value: -1: must be between 1 and 65535, inclusive"
	expectedGC3 := invalidGC.DeepCopy()
	expectedGC3.Spec.Listeners = invalidGC.Spec.Listeners[1:]

	changes, problems, err = configuration.AddOrUpdateGlobalConfiguration(invalidGC.DeepCopy())
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if err.Error() != expectedErrMsg {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned error %v but expected %v", err, expectedErrMsg)
	}
	storedGC = configuration.GetGlobalConfiguration()
	if diff := cmp.Diff(expectedGC3, storedGC); diff != "" {
		t.Errorf("GetGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore GlobalConfiguration

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts1,
			},
		},
	}
	expectedProblems = nil

	changes, problems, err = configuration.AddOrUpdateGlobalConfiguration(updatedGC2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if err != nil {
		t.Errorf("AddOrUpdateGlobalConfiguration() returned unexpected error: %v", err)
	}
	storedGC = configuration.GetGlobalConfiguration()
	if diff := cmp.Diff(updatedGC2, storedGC); diff != "" {
		t.Errorf("GetGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete GlobalConfiguration

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts1,
			},
		},
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7000,
				TransportServer: ts2,
			},
		},
	}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts1,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-7777 doesn't exist",
		},
		{
			Object:  ts2,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-8888 doesn't exist",
		},
	}

	changes, problems = configuration.DeleteGlobalConfiguration()
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
	storedGC = configuration.GetGlobalConfiguration()
	if diff := cmp.Diff(nilGC, storedGC); diff != "" {
		t.Errorf("GetGlobalConfiguration() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddGlobalConfigurationThenAddVirtualServerWithValidCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithValidCustomListenersFirstThenAddGlobalConfiguration(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     0,
				Warnings:      []string{"Listeners defined, but no GlobalConfiguration is deployed"},
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, expectedChanges, noProblems)
}

func TestAddVirtualServerWithValidCustomListenersAndNoGlobalConfiguration(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     0,
				Warnings:      []string{"Listeners defined, but no GlobalConfiguration is deployed"},
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithCustomHttpListenerThatDoNotExistInGlobalConfiguration(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-bogus",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     8442,
				Warnings:      []string{"Listener http-bogus is not defined in GlobalConfiguration"},
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithCustomHttpsListenerThatDoNotExistInGlobalConfiguration(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-bogus")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     0,
				Warnings:      []string{"Listener https-bogus is not defined in GlobalConfiguration"},
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestDeleteHttpListenerFromExistingGlobalConfigurationWithVirtualServerDeployedWithValidCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     8442,
				Warnings:      []string{"Listener http-8082 is not defined in GlobalConfiguration"},
			},
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPSListener, expectedChanges, noProblems)
}

func TestDeleteHttpsListenerFromExistingGlobalConfigurationWithVirtualServerDeployedWithValidCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}
	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     0,
				Warnings:      []string{"Listener https-8442 is not defined in GlobalConfiguration"},
			},
		},
	}
	addOrUpdateGlobalConfiguration(t, configuration, customHTTPListener, expectedChanges, noProblems)
}

func TestDeleteGlobalConfigurationWithVirtualServerDeployedWithValidCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}
	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     0,
				Warnings:      []string{"Listeners defined, but no GlobalConfiguration is deployed"},
			},
		},
	}
	deleteGlobalConfiguration(t, configuration, expectedChanges, noProblems)
}

func TestRenameHttpListenerInExistingGlobalConfigurationWithVirtualServerDeployedWithValidCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners("cafe", "cafe.example.com", "http-8082", "https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     8442,
				Warnings:      []string{"Listener http-8082 is not defined in GlobalConfiguration"},
			},
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, bogusHTTPListener, expectedChanges, noProblems)
}

func TestRenameHttpsListenerInExistingGlobalConfigurationWithVirtualServerDeployedWithValidCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners("cafe", "cafe.example.com", "http-8082", "https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}
	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     0,
				Warnings:      []string{"Listener https-8442 is not defined in GlobalConfiguration"},
			},
		},
	}
	addOrUpdateGlobalConfiguration(t, configuration, bogusHTTPSListener, expectedChanges, noProblems)
}

func TestAddVirtualServerWithCustomHttpListenerInHttpsBlock(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"http-8082")

	expectedWarningMsg := "Listener http-8082 can't be use in `listener.https` context as SSL is not enabled for that listener."

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     0,
				Warnings:      []string{expectedWarningMsg},
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithCustomHttpsListenerInHttpBlock(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"https-8442",
		"https-8442")

	expectedWarningMsg := "Listener https-8442 can't be use in `listener.http` context as SSL is enabled for that listener."

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     8442,
				Warnings:      []string{expectedWarningMsg},
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithNoHttpsListener(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     0,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithNoHttpListener(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithNoHttpOrHttpsListener(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"",
		"")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     0,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)
}

func TestAddVirtualServerWithValidCustomListenersAndChangeValueOfSslToFalseInGlobalConfiguration(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedWarningMsg := "Listener https-8442 can't be use in `listener.https` context as SSL is not enabled for that listener."

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     0,
				Warnings:      []string{expectedWarningMsg},
			},
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPSListenerSSLFalse, expectedChanges, noProblems)
}

func TestAddVirtualServerWithValidCustomListenersAndChangeValueOfSslToTrueInGlobalConfiguration(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	expectedWarningMsg := "Listener http-8082 can't be use in `listener.http` context as SSL is enabled for that listener."

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     8442,
				Warnings:      []string{expectedWarningMsg},
			},
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPListenerSSLTrue, expectedChanges, noProblems)
}

func TestAddMultipleVirtualServersWithTheSameCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServerCafe := createTestVirtualServerWithListeners(
		"cafe",
		"cafe.example.com",
		"http-8082",
		"https-8442")

	virtualServerFoo := createTestVirtualServerWithListeners(
		"foo",
		"foo.example.com",
		"http-8082",
		"https-8442")

	expectedChangesForVsCafe := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServerCafe,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}
	addOrUpdateVirtualServer(t, configuration, virtualServerCafe, expectedChangesForVsCafe, noProblems)

	expectedChangesForVsFoo := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServerFoo,
				HTTPPort:      8082,
				HTTPSPort:     8442,
			},
		},
	}
	addOrUpdateVirtualServer(t, configuration, virtualServerFoo, expectedChangesForVsFoo, noProblems)
}

func TestUpdateGlobalConfigurationWithVirtualServerDeployedWithNoCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServer(
		"cafe",
		"cafe.example.com")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     0,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	// Update GlobalConfiguration by removing a listener
	// Since our VirtualServer does not have any listener
	// we do not want to see any VirtualServerConfiguration events
	addOrUpdateGlobalConfiguration(t, configuration, customHTTPListener, noChanges, noProblems)
}

func TestDeleteGlobalConfigurationWithVirtualServerDeployedWithNoCustomListeners(t *testing.T) {
	t.Parallel()
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, customHTTPAndHTTPSListeners, noChanges, noProblems)

	virtualServer := createTestVirtualServer(
		"cafe",
		"cafe.example.com")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer: virtualServer,
				HTTPPort:      0,
				HTTPSPort:     0,
			},
		},
	}

	addOrUpdateVirtualServer(t, configuration, virtualServer, expectedChanges, noProblems)

	// Delete the existing GlobalConfiguration
	// Since our VirtualServer does not have any listeners
	// we do not want to see any VirtualServerConfiguration events
	deleteGlobalConfiguration(t, configuration, noChanges, noProblems)
}

func TestPortCollisions(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}
	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	ts1 := createTestTransportServer("transportserver-1", "tcp-7777", "TCP")
	ts2 := createTestTransportServer("transportserver-2", "tcp-7777", "TCP")
	ts3 := createTestTransportServer("transportserver-3", "tcp-7777", "TCP")

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts1,
			},
		},
	}
	expectedProblems = nil

	// Add first TransportServer

	changes, problems := configuration.AddOrUpdateTransportServer(ts1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add second TransportServer

	expectedChanges = nil
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts2,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-7777 with host empty host is taken by another resource",
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(ts2)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Add third TransportServer

	expectedChanges = nil
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts3,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-7777 with host empty host is taken by another resource",
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(ts3)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Remove first TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts1,
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts2,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.DeleteTransportServer("default/transportserver-1")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestChallengeIngressToVSR(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedProblems []ConfigurationProblem

	// Add a new Ingress

	vs := createTestVirtualServer("virtualserver", "foo.example.com")
	vsr1 := createTestChallengeVirtualServerRoute("challenge", "foo.example.com", "/.well-known/acme-challenge/test")

	ing := createTestChallengeIngress("challenge", "foo.example.com", "/.well-known/acme-challenge/test", "cm-acme-http-solver-test")

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &VirtualServerConfiguration{
				VirtualServer:       vs,
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr1},
				Warnings:            nil,
			},
		},
	}

	configuration.AddOrUpdateVirtualServer(vs)
	changes, problems := configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	expectedChanges = nil

	changes, problems = configuration.DeleteIngress(ing.Name)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	expectedChanges = nil
	ing = createTestIngress("wrong-challenge", "foo.example.com", "bar.example.com")
	ing.Labels = map[string]string{"acme.cert-manager.io/http01-solver": "true"}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ing,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: "spec.rules: Forbidden: challenge Ingress must have exactly 1 rule defined",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}

	ing = createTestIngress("wrong-challenge", "foo.example.com")
	ing.Labels = map[string]string{"acme.cert-manager.io/http01-solver": "true"}
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ing,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: "spec.rules.HTTP.Paths: Forbidden: challenge Ingress must have exactly 1 path defined",
		},
	}

	changes, problems = configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestChallengeIngressNoVSR(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedProblems []ConfigurationProblem

	vs := createTestVirtualServer("virtualserver", "bar.example.com")
	ing := createTestChallengeIngress("challenge", "foo.example.com", "/.well-known/acme-challenge/test", "cm-acme-http-solver-test")
	configuration.AddOrUpdateVirtualServer(vs)
	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &IngressConfiguration{
				Ingress: ing,
				ValidHosts: map[string]bool{
					"foo.example.com": true,
				},
				ChildWarnings: map[string][]string{},
			},
		},
	}

	changes, problems := configuration.AddOrUpdateIngress(ing)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateIngress() returned unexpected result (-want +got):\n%s", diff)
	}
}

func addOrUpdateGlobalConfiguration(t *testing.T, c *Configuration, listeners []conf_v1.Listener, expectedChanges []ResourceChange, expectedProblems []ConfigurationProblem) {
	t.Helper()
	gc := createTestGlobalConfiguration(listeners)
	changes, problems, err := c.AddOrUpdateGlobalConfiguration(gc)

	if !cmp.Equal(expectedChanges, changes) {
		t.Fatalf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s",
			cmp.Diff(expectedChanges, changes))
	}

	if !cmp.Equal(expectedProblems, problems) {
		t.Fatalf("AddOrUpdateGlobalConfiguration() returned unexpected result (-want +got):\n%s",
			cmp.Diff(expectedProblems, problems))
	}
	if err != nil {
		t.Fatalf("AddOrUpdateGlobalConfiguration() returned an unexpected error %v", err)
	}
}

func deleteGlobalConfiguration(t *testing.T, c *Configuration, expectedChanges []ResourceChange, expectedProblems []ConfigurationProblem) {
	t.Helper()
	changes, problems := c.DeleteGlobalConfiguration()
	if !cmp.Equal(expectedChanges, changes) {
		t.Fatalf("DeleteGlobalConfiguration() returned unexpected result (-want +got):\n%s",
			cmp.Diff(expectedChanges, changes))
	}

	if !cmp.Equal(expectedProblems, problems) {
		t.Fatalf("DeleteGlobalConfiguration() returned unexpected result (-want +got):\n%s",
			cmp.Diff(expectedProblems, problems))
	}
}

func addOrUpdateVirtualServer(t *testing.T, c *Configuration, virtualServer *conf_v1.VirtualServer, expectedChanges []ResourceChange, expectedProblems []ConfigurationProblem) {
	changes, problems := c.AddOrUpdateVirtualServer(virtualServer)

	if !cmp.Equal(expectedChanges, changes) {
		t.Fatalf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s",
			cmp.Diff(expectedChanges, changes))
	}

	if !cmp.Equal(expectedProblems, problems) {
		t.Fatalf("AddOrUpdateVirtualServer() returned unexpected result (-want +got):\n%s",
			cmp.Diff(noProblems, problems))
	}
}

func createTestIngressMaster(name string, host string) *networking.Ingress {
	ing := createTestIngress(name, host)
	ing.Annotations["nginx.org/mergeable-ingress-type"] = "master"
	return ing
}

func createTestIngressMinion(name string, host string, path string) *networking.Ingress {
	ing := createTestIngress(name, host)
	ing.Spec.Rules[0].IngressRuleValue = networking.IngressRuleValue{
		HTTP: &networking.HTTPIngressRuleValue{
			Paths: []networking.HTTPIngressPath{
				{
					Path: path,
				},
			},
		},
	}

	ing.Annotations["nginx.org/mergeable-ingress-type"] = "minion"

	return ing
}

func createTestIngress(name string, hosts ...string) *networking.Ingress {
	var rules []networking.IngressRule

	for _, h := range hosts {
		rules = append(rules, networking.IngressRule{
			Host:             h,
			IngressRuleValue: networking.IngressRuleValue{},
		})
	}

	return &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
			},
		},
		Spec: networking.IngressSpec{
			Rules: rules,
		},
	}
}

func createTestChallengeIngress(name string, host string, path string, serviceName string) *networking.Ingress {
	var rules []networking.IngressRule
	backend := networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: serviceName,
			Port: networking.ServiceBackendPort{
				Number: 8089,
			},
		},
	}

	rules = append(rules, networking.IngressRule{
		Host: host,
		IngressRuleValue: networking.IngressRuleValue{
			HTTP: &networking.HTTPIngressRuleValue{
				Paths: []networking.HTTPIngressPath{
					{
						Path:    path,
						Backend: backend,
					},
				},
			},
		},
	},
	)

	return &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
			},
			Labels: map[string]string{
				"acme.cert-manager.io/http01-solver": "true",
			},
		},
		Spec: networking.IngressSpec{
			Rules: rules,
		},
	}
}

func createTestVirtualServer(name string, host string) *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              name,
			CreationTimestamp: metav1.Now(),
		},
		Spec: conf_v1.VirtualServerSpec{
			IngressClass: "nginx",
			Host:         host,
		},
	}
}

func createTestVirtualServerWithListeners(name string, host string, httpListener string, httpsListener string) *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              name,
			CreationTimestamp: metav1.Now(),
		},
		Spec: conf_v1.VirtualServerSpec{
			Listener: &conf_v1.VirtualServerListener{
				HTTP:  httpListener,
				HTTPS: httpsListener,
			},
			IngressClass: "nginx",
			Host:         host,
		},
	}
}

func createTestVirtualServerWithRoutes(name string, host string, routes []conf_v1.Route) *conf_v1.VirtualServer {
	vs := createTestVirtualServer(name, host)
	vs.Spec.Routes = routes
	return vs
}

func createTestVirtualServerRoute(name string, host string, path string) *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      name,
		},
		Spec: conf_v1.VirtualServerRouteSpec{
			IngressClass: "nginx",
			Host:         host,
			Subroutes: []conf_v1.Route{
				{
					Path: path,
					Action: &conf_v1.Action{
						Return: &conf_v1.ActionReturn{
							Body: "vsr",
						},
					},
				},
			},
		},
	}
}

func createTestChallengeVirtualServerRoute(name string, host string, path string) *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      name,
		},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host: host,
			Upstreams: []conf_v1.Upstream{
				{
					Name:    "challenge",
					Service: "cm-acme-http-solver-test",
					Port:    8089,
				},
			},
			Subroutes: []conf_v1.Route{
				{
					Path: path,
					Action: &conf_v1.Action{
						Pass: "challenge",
					},
				},
			},
		},
	}
}

func createTestTransportServer(name string, listenerName string, listenerProtocol string) *conf_v1.TransportServer {
	return &conf_v1.TransportServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
			Generation:        1,
		},
		Spec: conf_v1.TransportServerSpec{
			Listener: conf_v1.TransportServerListener{
				Name:     listenerName,
				Protocol: listenerProtocol,
			},
			Upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "myapp",
					Service: "myapp-svc",
					Port:    1234,
				},
			},
			Action: &conf_v1.TransportServerAction{
				Pass: "myapp",
			},
		},
	}
}

func createTestTransportServerWithHost(name string, host string, listenerName string, secretName string) *conf_v1.TransportServer {
	ts := createTestTransportServer(name, listenerName, "TCP")
	ts.Spec.Host = host
	ts.Spec.TLS = &conf_v1.TransportServerTLS{Secret: secretName}

	return ts
}

func createTestTLSPassthroughTransportServer(name string, host string) *conf_v1.TransportServer {
	ts := createTestTransportServer(name, conf_v1.TLSPassthroughListenerName, conf_v1.TLSPassthroughListenerProtocol)
	ts.Spec.Host = host

	return ts
}

func createTestGlobalConfiguration(listeners []conf_v1.Listener) *conf_v1.GlobalConfiguration {
	return &conf_v1.GlobalConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "globalconfiguration",
			Namespace: "nginx-ingress",
		},
		Spec: conf_v1.GlobalConfigurationSpec{
			Listeners: listeners,
		},
	}
}

func TestChooseObjectMetaWinner(t *testing.T) {
	now := metav1.Now()
	afterNow := metav1.NewTime(now.Add(1 * time.Second))

	tests := []struct {
		meta1    *metav1.ObjectMeta
		meta2    *metav1.ObjectMeta
		msg      string
		expected bool
	}{
		{
			meta1: &metav1.ObjectMeta{
				UID:               "a",
				CreationTimestamp: now,
			},
			meta2: &metav1.ObjectMeta{
				UID:               "b",
				CreationTimestamp: afterNow,
			},
			msg:      "first is older",
			expected: true,
		},
		{
			meta1: &metav1.ObjectMeta{
				UID:               "a",
				CreationTimestamp: afterNow,
			},
			meta2: &metav1.ObjectMeta{
				UID:               "b",
				CreationTimestamp: now,
			},
			msg:      "second is older",
			expected: false,
		},
		{
			meta1: &metav1.ObjectMeta{
				UID:               "a",
				CreationTimestamp: now,
			},
			meta2: &metav1.ObjectMeta{
				UID:               "b",
				CreationTimestamp: now,
			},
			msg:      "both not older, but second wins",
			expected: false,
		},
	}

	for _, test := range tests {
		result := chooseObjectMetaWinner(test.meta1, test.meta2)
		if result != test.expected {
			t.Errorf("chooseObjectMetaWinner() returned %v but expected %v for the case %s", result, test.expected, test.msg)
		}
	}
}

func TestSquashResourceChanges(t *testing.T) {
	t.Parallel()
	ingConfig := &IngressConfiguration{
		Ingress: createTestIngress("test", "foo.example.com"),
	}

	vsConfig := &VirtualServerConfiguration{
		VirtualServer: createTestVirtualServer("test", "bar.example.com"),
	}

	tests := []struct {
		changes  []ResourceChange
		expected []ResourceChange
		msg      string
	}{
		{
			changes: []ResourceChange{
				{
					Op:       Delete,
					Resource: ingConfig,
				},
				{
					Op:       Delete,
					Resource: ingConfig,
				},
			},
			expected: []ResourceChange{
				{
					Op:       Delete,
					Resource: ingConfig,
				},
			},
			msg: "squash deletes",
		},
		{
			changes: []ResourceChange{
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			expected: []ResourceChange{
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			msg: "squash updates",
		},
		{
			changes: []ResourceChange{
				{
					Op:       Delete,
					Resource: ingConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			expected: []ResourceChange{
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			msg: "squash update and delete",
		},
		{
			changes: []ResourceChange{
				{
					Op:       Delete,
					Resource: vsConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			expected: []ResourceChange{
				{
					Op:       Delete,
					Resource: vsConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			msg: "preserve the order",
		},
		{
			changes: []ResourceChange{
				{
					Op:       Delete,
					Resource: ingConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: vsConfig,
				},
			},
			expected: []ResourceChange{
				{
					Op:       Delete,
					Resource: ingConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: vsConfig,
				},
			},
			msg: "do not squash different resource with same ns/name",
		},
		{
			changes: []ResourceChange{
				{
					Op:       Delete,
					Resource: ingConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
				{
					Op:       Delete,
					Resource: vsConfig,
				},
			},
			expected: []ResourceChange{
				{
					Op:       Delete,
					Resource: vsConfig,
				},
				{
					Op:       AddOrUpdate,
					Resource: ingConfig,
				},
			},
			msg: "squashed delete and update must follow delete",
		},
	}

	for _, test := range tests {
		result := squashResourceChanges(test.changes)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("squashResourceChanges() returned unexpected result for the case of %s (-want +got):\n%s", test.msg, diff)
		}
	}
}

type testReferenceChecker struct {
	resourceName            string
	resourceNamespace       string
	onlyIngresses           bool
	onlyMinions             bool
	onlyVirtualServers      bool
	onlyVirtualServerRoutes bool
	onlyTransportServers    bool
}

func (rc *testReferenceChecker) IsReferencedByIngress(namespace string, name string, _ *networking.Ingress) bool {
	return rc.onlyIngresses && namespace == rc.resourceNamespace && name == rc.resourceName
}

func (rc *testReferenceChecker) IsReferencedByMinion(namespace string, name string, _ *networking.Ingress) bool {
	return rc.onlyMinions && namespace == rc.resourceNamespace && name == rc.resourceName
}

func (rc *testReferenceChecker) IsReferencedByVirtualServer(namespace string, name string, _ *conf_v1.VirtualServer) bool {
	return rc.onlyVirtualServers && namespace == rc.resourceNamespace && name == rc.resourceName
}

func (rc *testReferenceChecker) IsReferencedByVirtualServerRoute(namespace string, name string, _ *conf_v1.VirtualServerRoute) bool {
	return rc.onlyVirtualServerRoutes && namespace == rc.resourceNamespace && name == rc.resourceName
}

func (rc *testReferenceChecker) IsReferencedByTransportServer(namespace string, name string, _ *conf_v1.TransportServer) bool {
	return rc.onlyTransportServers && namespace == rc.resourceNamespace && name == rc.resourceName
}

func TestFindResourcesForResourceReference(t *testing.T) {
	t.Parallel()
	regularIng := createTestIngress("regular-ingress", "foo.example.com")
	master := createTestIngressMaster("master-ingress", "bar.example.com")
	minion := createTestIngressMinion("minion-ingress", "bar.example.com", "/")
	vs := createTestVirtualServer("virtualserver-1", "qwe.example.com")
	vsWithVSR := createTestVirtualServerWithRoutes(
		"virtualserver-2",
		"asd.example.com",
		[]conf_v1.Route{
			{
				Path:  "/",
				Route: "virtualserverroute",
			},
		})
	vsr := createTestVirtualServerRoute("virtualserverroute", "asd.example.com", "/")
	tsPassthrough := createTestTLSPassthroughTransportServer("transportserver-passthrough", "ts.example.com")
	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}
	gc := createTestGlobalConfiguration(listeners)
	tsTCP := createTestTransportServer("transportserver-tcp", "tcp-7777", "TCP")

	configuration := createTestConfiguration()

	configuration.AddOrUpdateIngress(regularIng)
	configuration.AddOrUpdateIngress(master)
	configuration.AddOrUpdateIngress(minion)
	configuration.AddOrUpdateVirtualServer(vs)
	configuration.AddOrUpdateVirtualServer(vsWithVSR)
	configuration.AddOrUpdateVirtualServerRoute(vsr)
	_, _, _ = configuration.AddOrUpdateGlobalConfiguration(gc)
	configuration.AddOrUpdateTransportServer(tsPassthrough)
	configuration.AddOrUpdateTransportServer(tsTCP)

	tests := []struct {
		rc       resourceReferenceChecker
		expected []Resource
		msg      string
	}{
		{
			rc: &testReferenceChecker{
				resourceNamespace: "default",
				resourceName:      "test",
				onlyIngresses:     true,
			},
			expected: []Resource{
				configuration.hosts["bar.example.com"],
				configuration.hosts["foo.example.com"],
			},
			msg: "only Ingresses",
		},
		{
			rc: &testReferenceChecker{
				resourceNamespace: "default",
				resourceName:      "test",
				onlyMinions:       true,
			},
			expected: []Resource{
				configuration.hosts["bar.example.com"],
			},
			msg: "only Minions",
		},
		{
			rc: &testReferenceChecker{
				resourceNamespace:  "default",
				resourceName:       "test",
				onlyVirtualServers: true,
			},
			expected: []Resource{
				configuration.hosts["asd.example.com"],
				configuration.hosts["qwe.example.com"],
			},
			msg: "only VirtualServers",
		},
		{
			rc: &testReferenceChecker{
				resourceNamespace:       "default",
				resourceName:            "test",
				onlyVirtualServerRoutes: true,
			},
			expected: []Resource{
				configuration.hosts["asd.example.com"],
			},
			msg: "only VirtualServerRoutes",
		},
		{
			rc: &testReferenceChecker{
				resourceNamespace:    "default",
				resourceName:         "test",
				onlyTransportServers: true,
			},
			expected: []Resource{
				configuration.hosts["ts.example.com"],
				configuration.listenerHosts[listenerHostKey{ListenerName: "tcp-7777", Host: ""}],
			},
			msg: "only TransportServers",
		},
	}

	for _, test := range tests {
		result := configuration.findResourcesForResourceReference("default", "test", test.rc)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("findResourcesForResourceReference() returned unexpected result for the case of %s (-want +got):\n%s", test.msg, diff)
		}

		var noResources []Resource

		result = configuration.findResourcesForResourceReference("default", "wrong", test.rc)
		if diff := cmp.Diff(noResources, result); diff != "" {
			t.Errorf("findResourcesForResourceReference() returned unexpected result for the case of %s and wrong name (-want +got):\n%s", test.msg, diff)
		}

		result = configuration.findResourcesForResourceReference("wrong", "test", test.rc)
		if diff := cmp.Diff(noResources, result); diff != "" {
			t.Errorf("findResourcesForResourceReference() returned unexpected result for the case of %s and wrong namespace (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetResources(t *testing.T) {
	t.Parallel()
	ing := createTestIngress("ingress", "foo.example.com", "bar.example.com")
	vs := createTestVirtualServer("virtualserver", "qwe.example.com")
	passTS := createTestTLSPassthroughTransportServer("transportserver", "abc.example.com")
	ts := createTestTransportServer("transportserver-tcp", "tcp-7777", "TCP")

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}
	gc := createTestGlobalConfiguration(listeners)

	configuration := createTestConfiguration()

	_, _, err := configuration.AddOrUpdateGlobalConfiguration(gc)
	if err != nil {
		t.Fatalf("AddOrUpdateGlobalConfiguration() returned unexpected error %v", err)
	}
	configuration.AddOrUpdateIngress(ing)
	configuration.AddOrUpdateVirtualServer(vs)
	configuration.AddOrUpdateTransportServer(passTS)
	configuration.AddOrUpdateTransportServer(ts)

	expected := []Resource{
		configuration.hosts["foo.example.com"],
		configuration.hosts["abc.example.com"],
		configuration.listenerHosts[listenerHostKey{ListenerName: "tcp-7777", Host: ""}],
		configuration.hosts["qwe.example.com"],
	}

	result := configuration.GetResources()
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GetResources() returned unexpected result (-want +got):\n%s", diff)
	}

	expected = []Resource{
		configuration.hosts["foo.example.com"],
	}

	result = configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GetResources() returned unexpected result (-want +got):\n%s", diff)
	}

	expected = []Resource{
		configuration.hosts["qwe.example.com"],
	}

	result = configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GetResources() returned unexpected result (-want +got):\n%s", diff)
	}

	expected = []Resource{
		configuration.hosts["abc.example.com"],
		configuration.listenerHosts[listenerHostKey{ListenerName: "tcp-7777", Host: ""}],
	}

	result = configuration.GetResourcesWithFilter(resourceFilter{TransportServers: true})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GetResources() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestGetTransportServerMetrics(t *testing.T) {
	t.Parallel()
	tsPass := createTestTLSPassthroughTransportServer("transportserver", "abc.example.com")
	tsTCP := createTestTransportServer("transportserver-tcp", "tcp-7777", "TCP")
	tsUDP := createTestTransportServer("transportserver-udp", "udp-7777", "UDP")

	tests := []struct {
		tses     []*conf_v1.TransportServer
		expected *TransportServerMetrics
		msg      string
	}{
		{
			tses: nil,
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 0,
				TotalTCP:            0,
				TotalUDP:            0,
			},
			msg: "no TransportServers",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsPass,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 1,
				TotalTCP:            0,
				TotalUDP:            0,
			},
			msg: "one TLSPassthrough TransportServer",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsTCP,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 0,
				TotalTCP:            1,
				TotalUDP:            0,
			},
			msg: "one TCP TransportServer",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsUDP,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 0,
				TotalTCP:            0,
				TotalUDP:            1,
			},
			msg: "one UDP TransportServer",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsPass, tsTCP, tsUDP,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 1,
				TotalTCP:            1,
				TotalUDP:            1,
			},
			msg: "TLSPassthrough, TCP and UDP TransportServers",
		},
	}

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "udp-7777",
			Port:     7777,
			Protocol: "UDP",
		},
	}
	gc := createTestGlobalConfiguration(listeners)

	for _, test := range tests {
		configuration := createTestConfiguration()

		_, _, err := configuration.AddOrUpdateGlobalConfiguration(gc)
		if err != nil {
			t.Fatalf("AddOrUpdateGlobalConfiguration() returned unexpected error %v", err)
		}

		for _, ts := range test.tses {
			configuration.AddOrUpdateTransportServer(ts)
		}

		result := configuration.GetTransportServerMetrics()
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GetTransportServerMetrics() returned unexpected result for the case of %s (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestIsEqualForIngressConfigurations(t *testing.T) {
	t.Parallel()
	regularIng := createTestIngress("regular-ingress", "foo.example.com")

	ingConfigWithInvalidHost := NewRegularIngressConfiguration(regularIng)
	ingConfigWithInvalidHost.ValidHosts["foo.example.com"] = false

	ingConfigWithUpdatedIsMaster := NewRegularIngressConfiguration(regularIng)
	ingConfigWithUpdatedIsMaster.IsMaster = true

	regularIngWithUpdatedGen := regularIng.DeepCopy()
	regularIngWithUpdatedGen.Generation++

	regularIngWithUpdatedAnnotations := regularIng.DeepCopy()
	regularIngWithUpdatedAnnotations.Annotations["new"] = "value"

	masterIng := createTestIngressMaster("master-ingress", "bar.example.com")
	minionIng := createTestIngressMinion("minion-ingress", "bar.example.com", "/")

	minionIngWithUpdatedGen := minionIng.DeepCopy()
	minionIngWithUpdatedGen.Generation++

	minionIngWithUpdatedAnnotations := minionIng.DeepCopy()
	minionIngWithUpdatedAnnotations.Annotations["new"] = "value"

	tests := []struct {
		ingConfig1 *IngressConfiguration
		ingConfig2 *IngressConfiguration
		expected   bool
		msg        string
	}{
		{
			ingConfig1: NewRegularIngressConfiguration(regularIng),
			ingConfig2: NewRegularIngressConfiguration(regularIng),
			expected:   true,
			msg:        "equal regular ingresses",
		},
		{
			ingConfig1: NewRegularIngressConfiguration(regularIng),
			ingConfig2: ingConfigWithInvalidHost,
			expected:   false,
			msg:        "regular ingresses with different valid hosts",
		},
		{
			ingConfig1: NewRegularIngressConfiguration(regularIng),
			ingConfig2: ingConfigWithUpdatedIsMaster,
			expected:   false,
			msg:        "regular ingresses with different IsMaster value",
		},
		{
			ingConfig1: NewRegularIngressConfiguration(regularIng),
			ingConfig2: NewRegularIngressConfiguration(regularIngWithUpdatedGen),
			expected:   false,
			msg:        "regular ingresses with different generation",
		},
		{
			ingConfig1: NewRegularIngressConfiguration(regularIng),
			ingConfig2: NewRegularIngressConfiguration(regularIngWithUpdatedAnnotations),
			expected:   false,
			msg:        "regular ingresses with different annotations",
		},
		{
			ingConfig1: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIng)}, map[string][]string{}),
			ingConfig2: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIng)}, map[string][]string{}),
			expected:   true,
			msg:        "equal master ingresses",
		},
		{
			ingConfig1: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIng)}, map[string][]string{}),
			ingConfig2: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{}, map[string][]string{}),
			expected:   false,
			msg:        "masters with different number of minions",
		},
		{
			ingConfig1: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIng)}, map[string][]string{}),
			ingConfig2: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIngWithUpdatedGen)}, map[string][]string{}),
			expected:   false,
			msg:        "masters with minions with different generation",
		},
		{
			ingConfig1: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIng)}, map[string][]string{}),
			ingConfig2: NewMasterIngressConfiguration(masterIng, []*MinionConfiguration{NewMinionConfiguration(minionIngWithUpdatedAnnotations)}, map[string][]string{}),
			expected:   false,
			msg:        "masters with minions with different annotations",
		},
	}

	for _, test := range tests {
		result := test.ingConfig1.IsEqual(test.ingConfig2)
		if result != test.expected {
			t.Errorf("IsEqual() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestIsEqualForVirtualServers(t *testing.T) {
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
	vsr := createTestVirtualServerRoute("virtualserverroute", "foo.example.com", "/")

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
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, []string{}),
			expected:  true,
			msg:       "equal virtual servers",
		},
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vsWithUpdatedGen, []*conf_v1.VirtualServerRoute{vsr}, []string{}),
			expected:  false,
			msg:       "virtual servers with different generation",
		},
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{}, []string{}),
			expected:  false,
			msg:       "virtual servers with different number of virtual server routes",
		},
		{
			vsConfig1: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsr}, []string{}),
			vsConfig2: NewVirtualServerConfiguration(vs, []*conf_v1.VirtualServerRoute{vsrWithUpdatedGen}, []string{}),
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

func TestIsEqualForDifferentResources(t *testing.T) {
	t.Parallel()
	ingConfig := NewRegularIngressConfiguration(createTestIngress("ingress", "foo.example.com"))
	vsConfig := NewVirtualServerConfiguration(createTestVirtualServer("virtualserver", "bar.example.com"), []*conf_v1.VirtualServerRoute{}, []string{})

	result := ingConfig.IsEqual(vsConfig)
	if result != false {
		t.Error("IsEqual() for different resources returned true but expected false")
	}
}

func TestCompareConfigurationProblems(t *testing.T) {
	t.Parallel()
	tests := []struct {
		problem1 *ConfigurationProblem
		problem2 *ConfigurationProblem
		expected bool
		msg      string
	}{
		{
			problem1: &ConfigurationProblem{
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			problem2: &ConfigurationProblem{
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			expected: true,
			msg:      "equal problems",
		},
		{
			problem1: &ConfigurationProblem{
				Object:  createTestIngress("ingress-1", "foo.example.com"),
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			problem2: &ConfigurationProblem{
				Object:  createTestIngress("ingress-2", "bar.example.com"),
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			expected: true,
			msg:      "equal problems although objects are different",
		},
		{
			problem1: &ConfigurationProblem{
				IsError: true,
				Reason:  "reason",
				Message: "message",
			},
			problem2: &ConfigurationProblem{
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			expected: false,
			msg:      "different isError",
		},
		{
			problem1: &ConfigurationProblem{
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			problem2: &ConfigurationProblem{
				IsError: false,
				Reason:  "another reason",
				Message: "message",
			},
			expected: false,
			msg:      "different Reason",
		},
		{
			problem1: &ConfigurationProblem{
				IsError: false,
				Reason:  "reason",
				Message: "message",
			},
			problem2: &ConfigurationProblem{
				IsError: false,
				Reason:  "reason",
				Message: "another message",
			},
			expected: false,
			msg:      "different Message",
		},
	}

	for _, test := range tests {
		result := compareConfigurationProblems(test.problem1, test.problem2)
		if result != test.expected {
			t.Errorf("compareConfigurationProblems() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

var (
	noChanges  []ResourceChange
	noProblems []ConfigurationProblem

	// customHTTPAndHTTPSListeners defines a custom HTTP and HTTPS listener on port 8082 and 8442
	customHTTPAndHTTPSListeners = []conf_v1.Listener{
		{
			Name:     "http-8082",
			Port:     8082,
			Protocol: "HTTP",
		},
		{
			Name:     "https-8442",
			Port:     8442,
			Protocol: "HTTP",
			Ssl:      true,
		},
	}

	// customHTTPSListener defines a customHTTPS listener on port 8442
	customHTTPSListener = []conf_v1.Listener{
		{
			Name:     "https-8442",
			Port:     8442,
			Protocol: "HTTP",
			Ssl:      true,
		},
	}

	// customHTTPListener defines a custom HTTP listener on port 8082
	customHTTPListener = []conf_v1.Listener{
		{
			Name:     "http-8082",
			Port:     8082,
			Protocol: "HTTP",
		},
	}

	// customHTTPListenerSSLTrue defines a custom HTTP listener on port 8082 with SSL set to true
	customHTTPListenerSSLTrue = []conf_v1.Listener{
		{
			Name:     "http-8082",
			Port:     8082,
			Protocol: "HTTP",
			Ssl:      true,
		},
		{
			Name:     "https-8442",
			Port:     8442,
			Protocol: "HTTP",
			Ssl:      true,
		},
	}

	// customHTTPSListenerSSLFalse defines a custom HTTPS listener on port 8442 with SSL set to false
	customHTTPSListenerSSLFalse = []conf_v1.Listener{
		{
			Name:     "http-8082",
			Port:     8082,
			Protocol: "HTTP",
			Ssl:      false,
		},
		{
			Name:     "https-8442",
			Port:     8442,
			Protocol: "HTTP",
			Ssl:      false,
		},
	}

	// bogusHTTPListener defines a HTTP listener with an invalid name
	bogusHTTPListener = []conf_v1.Listener{
		{
			Name:     "http-bogus",
			Port:     8082,
			Protocol: "HTTP",
		},
		{
			Name:     "https-8442",
			Port:     8442,
			Protocol: "HTTP",
			Ssl:      true,
		},
	}

	// bogusHTTPsListener defines a HTTPs listener with an invalid name
	bogusHTTPSListener = []conf_v1.Listener{
		{
			Name:     "http-8082",
			Port:     8082,
			Protocol: "HTTP",
		},
		{
			Name:     "https-bogus",
			Port:     8442,
			Protocol: "HTTP",
			Ssl:      true,
		},
	}
)

func TestTransportServerListenerHostCollisions(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "tcp-8888",
			Port:     8888,
			Protocol: "TCP",
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	// Create TransportServers with the same listener and host
	ts1 := createTestTransportServerWithHost("ts1", "example.com", "tcp-7777", "secret1")
	ts2 := createTestTransportServerWithHost("ts2", "example.com", "tcp-7777", "secret2") // same listener and host
	ts3 := createTestTransportServerWithHost("ts3", "example.org", "tcp-7777", "secret3") // different host
	ts4 := createTestTransportServer("ts4", "tcp-7777", "TCP")                            // No host same listener
	ts5 := createTestTransportServer("ts5", "tcp-7777", "TCP")                            // same as ts4 to induce error with empty host twice
	ts6 := createTestTransportServerWithHost("ts6", "example.com", "tcp-8888", "secret4") // different listener

	// Add ts1 to the configuration
	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts1,
			},
		},
	}
	changes, problems := configuration.AddOrUpdateTransportServer(ts1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts1) returned unexpected result (-want +got):\n%s", diff)
	}
	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts1) returned problems %v", problems)
	}

	// Try to add ts2, should be rejected due to conflict
	changes, problems = configuration.AddOrUpdateTransportServer(ts2)
	expectedChanges = nil // No changes expected
	expectedProblems := []ConfigurationProblem{
		{
			Object:  ts2,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-7777 with host example.com is taken by another resource",
		},
	}

	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts2) returned unexpected changes (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts2) returned unexpected problems (-want +got):\n%s", diff)
	}

	// Add ts3 with a different host, should be accepted
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts3,
			},
		},
	}
	changes, problems = configuration.AddOrUpdateTransportServer(ts3)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts3) returned unexpected result (-want +got):\n%s", diff)
	}
	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts3) returned problems %v", problems)
	}

	// Add ts4 with no host, should be accepted
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts4,
			},
		},
	}
	changes, problems = configuration.AddOrUpdateTransportServer(ts4)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts4) returned unexpected result (-want +got):\n%s", diff)
	}
	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts4) returned problems %v", problems)
	}

	// Try to add ts5 with no host, should be rejected due to conflict
	changes, problems = configuration.AddOrUpdateTransportServer(ts5)
	expectedChanges = nil
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts5,
			IsError: false,
			Reason:  nl.EventReasonRejected,
			Message: "Listener tcp-7777 with host empty host is taken by another resource",
		},
	}

	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts5) returned unexpected changes (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts5) returned unexpected problems (-want +got):\n%s", diff)
	}

	// Try to add ts6 with different listener, but same domain as initial ts, should be fine as different listener
	changes, problems = configuration.AddOrUpdateTransportServer(ts6)
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts6,
			},
		},
	}
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts6) returned unexpected changes (-want +got):\n%s", diff)
	}

	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts6) returned problems %v", problems)
	}
}
