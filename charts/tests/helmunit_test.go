//go:build helmunit

package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"sigs.k8s.io/yaml"
)

func TestMain(m *testing.M) {
	code := m.Run()

	// After all tests have run `go-snaps` will sort snapshots
	snaps.Clean(m, snaps.CleanOpts{Sort: true})

	os.Exit(code)
}

// An example of how to verify the rendered template object of a Helm Chart given various inputs.
func TestHelmNICTemplate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		valuesFile    string
		releaseName   string
		namespace     string
		templateFiles []string
	}{
		"default values file": {
			valuesFile:  "",
			releaseName: "default",
			namespace:   "default",
		},
		"deployment-hpa": {
			valuesFile:  "testdata/deployment-hpa.yaml",
			releaseName: "deployment-hpa",
			namespace:   "default",
		},
		"deployment-hpa-no-create": {
			valuesFile:  "testdata/deployment-hpa-no-create.yaml",
			releaseName: "deployment-hpa-no-create",
			namespace:   "default",
		},
		"daemonset": {
			valuesFile:  "testdata/daemonset.yaml",
			releaseName: "daemonset",
			namespace:   "default",
		},
		"daemonset-readonly": {
			valuesFile:  "testdata/daemonset-readonly.yaml",
			releaseName: "daemonset-readonly",
			namespace:   "default",
		},
		"statefulset": {
			valuesFile:  "testdata/statefulset.yaml",
			releaseName: "statefulset",
			namespace:   "default",
		},
		"statefulset-readonly": {
			valuesFile:  "testdata/statefulset-readonly.yaml",
			releaseName: "statefulset-readonly",
			namespace:   "default",
		},
		"statefulset-config": {
			valuesFile:  "testdata/statefulset-config.yaml",
			releaseName: "statefulset-config",
			namespace:   "default",
		},
		"statefulset-no-storageclass": {
			valuesFile:  "testdata/statefulset-no-storageclass.yaml",
			releaseName: "statefulset-no-storageclass",
			namespace:   "default",
		},
		"namespace": {
			valuesFile:  "",
			releaseName: "namespace",
			namespace:   "nginx-ingress",
		},
		"plus": {
			valuesFile:  "testdata/plus.yaml",
			releaseName: "plus",
			namespace:   "default",
		},
		"plus-debug": {
			valuesFile:  "testdata/plus-debug.yaml",
			releaseName: "plus-debug",
			namespace:   "default",
		},
		"plus-mgmt": {
			valuesFile:  "testdata/plus-mgmt.yaml",
			releaseName: "plus-mgmt",
			namespace:   "default",
		},
		"plus-mgmt-custom-endpoint": {
			valuesFile:  "testdata/plus-mgmt-custom-endpoint.yaml",
			releaseName: "plus-mgmt-custom-endpoint",
			namespace:   "default",
		},
		"plus-mgmt-proxy-host": {
			valuesFile:  "testdata/plus-mgmt-proxy-host.yaml",
			releaseName: "plus-mgmt-proxy-host",
			namespace:   "default",
		},
		"plus-mgmt-proxy-host-auth": {
			valuesFile:  "testdata/plus-mgmt-proxy-host-auth.yaml",
			releaseName: "plus-mgmt-proxy-host-auth",
			namespace:   "default",
		},
		"ingressClass": {
			valuesFile:  "testdata/ingress-class.yaml",
			releaseName: "ingress-class",
			namespace:   "default",
		},
		"ingressClassValidationSkip": {
			valuesFile:  "testdata/ingress-class-validation-skip.yaml",
			releaseName: "ingress-class-validation-skip",
			namespace:   "default",
		},
		"globalConfig": {
			valuesFile:  "testdata/global-configuration.yaml",
			releaseName: "global-configuration",
			namespace:   "gc",
		},
		"globalConfigCustomName": {
			valuesFile:  "testdata/global-config-custom-name.yaml",
			releaseName: "global-config-custom-name",
			namespace:   "default",
		},
		"customResources": {
			valuesFile:  "testdata/custom-resources.yaml",
			releaseName: "custom-resources",
			namespace:   "custom-resources",
		},
		"externalDNSNginx": {
			valuesFile:  "testdata/external-dns-nginx.yaml",
			releaseName: "external-dns-nginx",
			namespace:   "default",
		},
		"externalDNSUpstream": {
			valuesFile:  "testdata/external-dns-upstream.yaml",
			releaseName: "external-dns-upstream",
			namespace:   "default",
		},
		"appProtectWAF": {
			valuesFile:  "testdata/app-protect-waf.yaml",
			releaseName: "appprotect-waf",
			namespace:   "appprotect-waf",
		},
		"appProtectWAFV5": {
			valuesFile:  "testdata/app-protect-wafv5.yaml",
			releaseName: "appprotect-wafv5",
			namespace:   "appprotect-wafv5",
		},
		"appProtectWAFV5Resources": {
			valuesFile:  "testdata/app-protect-wafv5-resources.yaml",
			releaseName: "appprotect-wafv5-resources",
			namespace:   "appprotect-wafv5",
		},
		"appProtectWAFPLM": {
			valuesFile:  "testdata/app-protect-waf-plm.yaml",
			releaseName: "appprotect-waf-plm",
			namespace:   "appprotect-waf-plm",
		},
		"appProtectDOS": {
			valuesFile:  "testdata/app-protect-dos.yaml",
			releaseName: "appprotect-dos",
			namespace:   "appprotect-dos",
		},
		"ossAgentV3": {
			valuesFile:  "testdata/oss-agentv3.yaml",
			releaseName: "oss-agent",
			namespace:   "default",
		},
		"plusAgentV3": {
			valuesFile:  "testdata/plus-agentv3.yaml",
			releaseName: "plus-agent",
			namespace:   "default",
		},
		"plusAgentV3All": {
			valuesFile:  "testdata/plus-agentv3-all.yaml",
			releaseName: "plus-agent-all",
			namespace:   "custom",
		},
		"appProtectWAFV5AgentV2": {
			valuesFile:  "testdata/app-protect-wafv5-agentv2.yaml",
			releaseName: "app-protect-wafv5-agentv2",
			namespace:   "default",
		},
		"appProtectWAFV5AgentV3": {
			valuesFile:  "testdata/app-protect-wafv5-agentv3.yaml",
			releaseName: "app-protect-wafv5-agentv3",
			namespace:   "default",
		},
		"appProtectWAFV4AgentV2": {
			valuesFile:  "testdata/app-protect-waf-agentv2.yaml",
			releaseName: "app-protect-waf-agentv2",
			namespace:   "default",
		},
		"appProtectWAFV4AgentV3": {
			valuesFile:  "testdata/app-protect-waf-agentv3.yaml",
			releaseName: "app-protect-waf-agentv3",
			namespace:   "default",
		},
		"startupStatusValid": {
			valuesFile:  "testdata/startupstatus-valid.yaml",
			releaseName: "startupstatus",
			namespace:   "default",
		},
		"networkPolicyDisabled": {
			valuesFile:  "testdata/network-policy-disabled.yaml",
			releaseName: "network-policy-disabled",
			namespace:   "default",
		},
		"networkPolicyIngress": {
			valuesFile:  "testdata/network-policy-ingress.yaml",
			releaseName: "network-policy-ingress",
			namespace:   "default",
		},
		"networkPolicyIngressEgress": {
			valuesFile:  "testdata/network-policy-ingress-egress.yaml",
			releaseName: "network-policy-ingress-egress",
			namespace:   "default",
		},
		"loadBalancerClass": {
			valuesFile:  "testdata/service-loadbalancerclass.yaml",
			releaseName: "loadbalancerclass",
			namespace:   "default",
		},
		"nodePort": {
			valuesFile:  "testdata/service-nodeport.yaml",
			releaseName: "nodeport",
			namespace:   "default",
		},
		"nodePortZero": {
			valuesFile:  "testdata/service-nodeport-zero.yaml",
			releaseName: "nodeport-zero",
			namespace:   "default",
		},
		"additionalServices": {
			valuesFile:    "testdata/additional-services.yaml",
			releaseName:   "additional-services",
			namespace:     "default",
			templateFiles: []string{"templates/controller-additional-services.yaml"},
		},
		"additionalServicesCommonLabels": {
			valuesFile:    "testdata/additional-services-common-labels.yaml",
			releaseName:   "additional-services-common-labels",
			namespace:     "default",
			templateFiles: []string{"templates/controller-additional-services.yaml"},
		},
		"topologyAwareRouting": {
			valuesFile:  "testdata/topology-aware-routing.yaml",
			releaseName: "topology-aware-routing",
			namespace:   "default",
		},
		"listConfigurations": {
			valuesFile:  "testdata/list-configurations.yaml",
			releaseName: "list-configs",
			namespace:   "default",
		},
		"allowEmptyIngressHost": {
			valuesFile:  "testdata/allow-empty-ingress-host.yaml",
			releaseName: "allow-empty-ingress-host",
			namespace:   "default",
		},
		"latencyMetricsBuckets": {
			valuesFile:  "testdata/latency-metrics-buckets.yaml",
			releaseName: "latency-metrics-buckets",
			namespace:   "default",
		},
		"allowEmptyIngressHostWithoutCRs": {
			valuesFile:  "testdata/allow-empty-ingress-host-no-crs.yaml",
			releaseName: "allow-empty-ingress-host-no-crs",
			namespace:   "default",
		},
		"defaultListenerPortsWithoutCRs": {
			valuesFile:  "testdata/default-listener-ports-no-crs.yaml",
			releaseName: "default-listener-ports-no-crs",
			namespace:   "default",
		},
		"commonLabels": {
			valuesFile:  "testdata/common-labels.yaml",
			releaseName: "common-labels",
			namespace:   "default",
		},
		"batchReloadWindow": {
			valuesFile:  "testdata/batch-reload-window.yaml",
			releaseName: "batch-reload-window",
			namespace:   "default",
		},
		"tenant": {
			valuesFile:  "testdata/tenant.yaml",
			releaseName: "nic",
			namespace:   "team-a",
		},
		"tenantReleaseNamespaceOnly": {
			valuesFile:  "testdata/tenant-release-namespace-only.yaml",
			releaseName: "nic",
			namespace:   "team-a",
		},
		"tenantMessyNamespaces": {
			valuesFile:  "testdata/tenant-messy-namespaces.yaml",
			releaseName: "nic",
			namespace:   "team-a",
		},
		"tenantAllFeatures": {
			valuesFile:  "testdata/tenant-all-features.yaml",
			releaseName: "nic",
			namespace:   "team-a",
		},
		"tenantNoCustomResources": {
			valuesFile:  "testdata/tenant-no-custom-resources.yaml",
			releaseName: "nic",
			namespace:   "team-a",
		},
		"platform": {
			valuesFile:  "testdata/platform.yaml",
			releaseName: "nic-team-a-platform",
			namespace:   "nic-platform",
		},
		"platformExistingIngressClass": {
			valuesFile:  "testdata/platform-existing-ingress-class.yaml",
			releaseName: "nic-team-a-platform",
			namespace:   "nic-platform",
		},
		"platformNoTenantReader": {
			valuesFile:  "testdata/platform-no-tenant-reader.yaml",
			releaseName: "nic-team-a-platform",
			namespace:   "nic-platform",
		},
	}

	// Path to the helm chart we will test
	helmChartPath, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal("Failed to open helm chart path ../nginx-ingress")
	}

	for testName, tc := range tests {
		t.Run(testName, func(t *testing.T) {
			options := helmOptions{namespace: tc.namespace}

			if tc.valuesFile != "" {
				options.valuesFiles = []string{tc.valuesFile}
			}

			var extraArgs []string
			for _, f := range tc.templateFiles {
				extraArgs = append(extraArgs, "--show-only", f)
			}

			output := renderTemplate(t, helmChartPath, tc.releaseName, options, extraArgs...)

			assertNoDuplicateYAMLKeys(t, output)

			snaps.MatchSnapshot(t, output)
			t.Log(output)
		})
	}
}

// assertNoDuplicateYAMLKeys fails the test if any rendered manifest contains
// a duplicate mapping key (e.g. a label set by both commonLabels and an
// extraLabels field). Such manifests are invalid YAML: the duplicate is
// silently dropped by last-wins parsing instead of being rejected, so a
// plain string/snapshot comparison would not catch it.
func assertNoDuplicateYAMLKeys(t *testing.T, output string) {
	t.Helper()

	for _, doc := range strings.Split(output, "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var out map[string]interface{}
		if err := yaml.UnmarshalStrict([]byte(doc), &out); err != nil {
			t.Fatalf("rendered manifest contains invalid YAML (likely a duplicate key): %v\n%s", err, doc)
		}
	}
}

// Test for negative cases where helm template rendering should fail
func TestHelmNICTemplateNegative(t *testing.T) {
	t.Parallel()

	negativeTests := map[string]struct {
		valuesFile        string
		releaseName       string
		namespace         string
		expectedErrorMsgs []string
	}{
		"startupStatusInvalid": {
			valuesFile:        "testdata/startupstatus-invalid.yaml",
			releaseName:       "startupstatus-invalid",
			namespace:         "default",
			expectedErrorMsgs: []string{"missing properties 'port', 'path'"},
		},
		"installModeInvalid": {
			valuesFile:        "testdata/install-mode-invalid.yaml",
			releaseName:       "install-mode-invalid",
			namespace:         "default",
			expectedErrorMsgs: []string{"/installMode", "value must be one of 'full', 'platform', 'tenant'"},
		},
		"tenantWatchNamespaceLabel": {
			valuesFile:        "testdata/tenant-watch-namespace-label.yaml",
			releaseName:       "nic",
			namespace:         "team-a",
			expectedErrorMsgs: []string{`installMode "tenant" does not support controller.watchNamespaceLabel`},
		},
		"tenantNoServiceAccount": {
			valuesFile:        "testdata/tenant-no-service-account.yaml",
			releaseName:       "nic",
			namespace:         "team-a",
			expectedErrorMsgs: []string{`installMode "tenant" requires controller.serviceAccount.name`},
		},
		"tenantSecretNamespaceNotWatched": {
			valuesFile:        "testdata/tenant-secret-namespace-not-watched.yaml",
			releaseName:       "nic",
			namespace:         "team-a",
			expectedErrorMsgs: []string{`controller.watchSecretNamespace entry "team-b" is not a watched namespace`},
		},
		"platformNoTenantNamespace": {
			valuesFile:        "testdata/platform-no-tenant-namespace.yaml",
			releaseName:       "nic-team-a-platform",
			namespace:         "nic-platform",
			expectedErrorMsgs: []string{`installMode "platform" requires platform.tenantNamespace`},
		},
		"platformNoServiceAccount": {
			valuesFile:        "testdata/platform-no-service-account.yaml",
			releaseName:       "nic-team-a-platform",
			namespace:         "nic-platform",
			expectedErrorMsgs: []string{`installMode "platform" with platform.tenantReader.create requires controller.serviceAccount.name`},
		},
		"ingressClassValidationInvalid": {
			valuesFile:        "testdata/ingress-class-validation-invalid.yaml",
			releaseName:       "ingress-class-validation-invalid",
			namespace:         "default",
			expectedErrorMsgs: []string{"/controller/ingressClass/validation", "value must be one of 'strict', 'skip'"},
		},
		"globalConfigInvalidFormat": {
			valuesFile:        "testdata/global-config-invalid-format.yaml",
			releaseName:       "global-config-invalid-format",
			namespace:         "default",
			expectedErrorMsgs: []string{"globalConfiguration.customName must contain exactly one '/' separator in namespace/name format (e.g., \"my-namespace/my-global-config\")"},
		},
		"globalConfigMultipleSlashes": {
			valuesFile:        "testdata/global-config-multiple-slashes.yaml",
			releaseName:       "global-config-multiple-slashes",
			namespace:         "default",
			expectedErrorMsgs: []string{"globalConfiguration.customName must contain exactly one '/' separator in namespace/name format (e.g., \"my-namespace/my-global-config\")"},
		},
		"globalConfigEmptyName": {
			valuesFile:        "testdata/global-config-empty-name.yaml",
			releaseName:       "global-config-empty-name",
			namespace:         "default",
			expectedErrorMsgs: []string{"globalConfiguration.customName namespace and name parts cannot be empty (e.g., \"my-namespace/my-global-config\")"},
		},
		"additionalServiceWithoutPorts": {
			valuesFile:        "testdata/additional-service-without-ports.yaml",
			releaseName:       "additional-service-without-ports",
			namespace:         "default",
			expectedErrorMsgs: []string{"missing property 'ports'"},
		},
		"additionalServiceExternalName": {
			valuesFile:        "testdata/additional-service-external-name.yaml",
			releaseName:       "additional-service-external-name",
			namespace:         "default",
			expectedErrorMsgs: []string{"value must be one of 'ClusterIP', 'NodePort', 'LoadBalancer'"},
		},
		"additionalServiceEmptyPorts": {
			valuesFile:        "testdata/additional-service-empty-ports.yaml",
			releaseName:       "additional-service-empty-ports",
			namespace:         "default",
			expectedErrorMsgs: []string{"minItems: got 0, want 1"},
		},
		"additionalServiceNameCollision": {
			valuesFile:        "testdata/additional-service-name-collision.yaml",
			releaseName:       "additional-service-name-collision",
			namespace:         "default",
			expectedErrorMsgs: []string{"additional Service name \"duplicate-service\" must not match the primary controller Service name"},
		},
		"additionalServiceInvalidName": {
			valuesFile:        "testdata/additional-service-invalid-name.yaml",
			releaseName:       "additional-service-invalid-name",
			namespace:         "default",
			expectedErrorMsgs: []string{"'Invalid_Name' does not match pattern"},
		},
		"additionalServiceReservedLabel": {
			valuesFile:        "testdata/additional-service-reserved-label.yaml",
			releaseName:       "additional-service-reserved-label",
			namespace:         "default",
			expectedErrorMsgs: []string{`label "app.kubernetes.io/managed-by" is managed by the chart and cannot be overridden`},
		},
		"latencyMetricsBucketsInvalid": {
			valuesFile:        "testdata/latency-metrics-buckets-invalid.yaml",
			releaseName:       "latency-metrics-buckets-invalid",
			namespace:         "default",
			expectedErrorMsgs: []string{"does not match pattern"},
		},
		"appProtectWAFPLMWithoutV5": {
			valuesFile:        "testdata/app-protect-waf-plm-without-v5.yaml",
			releaseName:       "appprotect-waf-plm-without-v5",
			namespace:         "default",
			expectedErrorMsgs: []string{"controller.appprotect.plmStorage.url requires controller.appprotect.v5=true"},
		},
		"commonLabelsReserved": {
			valuesFile:        "testdata/common-labels-reserved.yaml",
			releaseName:       "common-labels-reserved",
			namespace:         "default",
			expectedErrorMsgs: []string{`label "app.kubernetes.io/name" is managed by the chart and cannot be overridden`},
		},
		"agentLabelsInvalid": {
			valuesFile:  "testdata/agent-labels-invalid.yaml",
			releaseName: "agent-labels-invalid",
			namespace:   "default",
			expectedErrorMsgs: []string{
				"invalid propertyName 'bad,key'",
				"'/nginxAgent/labels/comma': 'a,b' does not match pattern",
				"'/nginxAgent/labels/equals': 'a=b' does not match pattern",
				"'/nginxAgent/labels/empty': '' does not match pattern",
				"'/nginxAgent/labels/number': got number, want string",
			},
		},
		"appProtectWAFPLMWithoutPlus": {
			valuesFile:        "testdata/app-protect-waf-plm-without-plus.yaml",
			releaseName:       "appprotect-waf-plm-without-plus",
			namespace:         "default",
			expectedErrorMsgs: []string{"controller.appprotect.plmStorage.url requires controller.nginxplus=true"},
		},
		"appProtectWAFPLMWithoutAppProtect": {
			valuesFile:        "testdata/app-protect-waf-plm-without-appprotect.yaml",
			releaseName:       "appprotect-waf-plm-without-appprotect",
			namespace:         "default",
			expectedErrorMsgs: []string{"controller.appprotect.plmStorage.url requires controller.appprotect.enable=true"},
		},
		"appProtectWAFPLMWithoutCredentials": {
			valuesFile:        "testdata/app-protect-waf-plm-without-credentials.yaml",
			releaseName:       "appprotect-waf-plm-without-credentials",
			namespace:         "default",
			expectedErrorMsgs: []string{"controller.appprotect.plmStorage.credentialsSecret must be set when controller.appprotect.plmStorage.url is set"},
		},
		"appProtectWAFPLMWithoutURL": {
			valuesFile:        "testdata/app-protect-waf-plm-without-url.yaml",
			releaseName:       "appprotect-waf-plm-without-url",
			namespace:         "default",
			expectedErrorMsgs: []string{"controller.appprotect.plmStorage auxiliary values require controller.appprotect.plmStorage.url"},
		},
	}

	// Path to the helm chart we will test
	helmChartPath, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal("Failed to open helm chart path ../nginx-ingress")
	}

	for testName, tc := range negativeTests {
		t.Run(testName, func(t *testing.T) {
			options := helmOptions{namespace: tc.namespace}

			if tc.valuesFile != "" {
				options.valuesFiles = []string{tc.valuesFile}
			}
			_, err := renderTemplateE(helmChartPath, tc.releaseName, options)

			if err == nil {
				t.Fatalf("Expected helm template to fail for invalid configuration, but it succeeded")
			}

			if len(tc.expectedErrorMsgs) > 0 {
				for _, expectedMsg := range tc.expectedErrorMsgs {
					if !strings.Contains(err.Error(), expectedMsg) {
						t.Fatalf("Expected error to contain '%s', but got: %s", expectedMsg, err.Error())
					}
				}
			}

			t.Logf("Expected failure occurred: %s", err.Error())
		})
	}
}

// TestHelmNICNetworkPolicyLegacyValues renders the chart with legacy values
// that omit controller.networkPolicy, the state a release ends up in on
// `helm upgrade --reuse-values` from a version that predates the feature.
func TestHelmNICNetworkPolicyLegacyValues(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal("Failed to open helm chart path ../nginx-ingress")
	}

	options := helmOptions{
		namespace:   "default",
		valuesFiles: []string{"testdata/network-policy-legacy-values.yaml"},
	}

	// The values.schema.json types networkPolicy as "object" and rejects an
	// explicit null; the real --reuse-values path skips this check because the
	// key is simply absent.
	output, err := renderTemplateE(helmChartPath, "network-policy-legacy", options, "--skip-schema-validation")
	if err != nil {
		t.Fatalf("helm template must succeed when controller.networkPolicy is absent, got: %v", err)
	}

	if strings.Contains(output, "kind: NetworkPolicy") {
		t.Fatalf("expected no NetworkPolicy resource when controller.networkPolicy is absent, rendered output:\n%s", output)
	}
	if strings.Contains(output, "controller-networkpolicy.yaml") {
		t.Fatalf("expected controller-networkpolicy.yaml to render empty, rendered output:\n%s", output)
	}
}

// manifest is the part of a rendered object that the install mode tests inspect.
type manifest struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Rules []policyRule `json:"rules"`
}

// policyRule is an RBAC rule, as rendered in a Role or ClusterRole.
type policyRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames"`
	Verbs         []string `json:"verbs"`
}

// parseManifests parses normalized helm template output into one manifest per object.
func parseManifests(t *testing.T, output string) []manifest {
	t.Helper()

	var out []manifest
	for _, doc := range strings.Split(output, "\n---\n") {
		doc = strings.TrimPrefix(doc, "---\n")
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var m manifest
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("failed to parse rendered manifest: %v\n%s", err, doc)
		}
		if m.Kind != "" {
			out = append(out, m)
		}
	}
	return out
}

// clusterScopedKinds are the kinds this chart can render that have no namespace.
var clusterScopedKinds = map[string]bool{
	"ClusterRole":                    true,
	"ClusterRoleBinding":             true,
	"IngressClass":                   true,
	"CustomResourceDefinition":       true,
	"Namespace":                      true,
	"ValidatingWebhookConfiguration": true,
	"MutatingWebhookConfiguration":   true,
}

// permission is one verb on one resource, optionally limited to one resource name.
type permission struct {
	group, resource, name, verb string
}

// expand returns every permission a rule grants. A rule with no resourceNames grants
// the verb on every name, which is recorded with an empty name.
func (r policyRule) expand() []permission {
	names := r.ResourceNames
	if len(names) == 0 {
		names = []string{""}
	}
	var out []permission
	for _, g := range r.APIGroups {
		for _, res := range r.Resources {
			for _, n := range names {
				for _, v := range r.Verbs {
					out = append(out, permission{group: g, resource: res, name: n, verb: v})
				}
			}
		}
	}
	return out
}

// uncovered returns the permissions in rules that grants does not cover. A grant with
// no resource name covers the same verb on every name.
func uncovered(rules, grants []policyRule) []permission {
	have := map[permission]bool{}
	for _, g := range grants {
		for _, p := range g.expand() {
			have[p] = true
		}
	}
	var missing []permission
	for _, r := range rules {
		for _, p := range r.expand() {
			unscoped := p
			unscoped.name = ""
			if !have[p] && !have[unscoped] {
				missing = append(missing, p)
			}
		}
	}
	return missing
}

// installModeCases are the values files rendered by the install mode tests.
var installModeCases = map[string]struct {
	valuesFile  string
	releaseName string
	namespace   string
}{
	"tenant":                       {"testdata/tenant.yaml", "nic", "team-a"},
	"tenantReleaseNamespaceOnly":   {"testdata/tenant-release-namespace-only.yaml", "nic", "team-a"},
	"tenantMessyNamespaces":        {"testdata/tenant-messy-namespaces.yaml", "nic", "team-a"},
	"tenantAllFeatures":            {"testdata/tenant-all-features.yaml", "nic", "team-a"},
	"tenantNoCustomResources":      {"testdata/tenant-no-custom-resources.yaml", "nic", "team-a"},
	"platform":                     {"testdata/platform.yaml", "nic-team-a-platform", "nic-platform"},
	"platformExistingIngressClass": {"testdata/platform-existing-ingress-class.yaml", "nic-team-a-platform", "nic-platform"},
	"platformNoTenantReader":       {"testdata/platform-no-tenant-reader.yaml", "nic-team-a-platform", "nic-platform"},
}

func renderInstallMode(t *testing.T, chartDir, valuesFile, releaseName, namespace string) []manifest {
	t.Helper()
	return parseManifests(t, renderTemplate(t, chartDir, releaseName, helmOptions{namespace: namespace, valuesFiles: []string{valuesFile}}))
}

// TestHelmNICTenantRendersOnlyNamespacedResources checks that installMode tenant renders no
// cluster-scoped object, and that each Role and RoleBinding is in a watched namespace.
func TestHelmNICTenantRendersOnlyNamespacedResources(t *testing.T) {
	t.Parallel()

	chartDir, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		wantRoleNamespaces []string
	}{
		"tenant":                     {wantRoleNamespaces: []string{"team-a", "team-a-apps"}},
		"tenantReleaseNamespaceOnly": {wantRoleNamespaces: []string{"team-a"}},
		"tenantMessyNamespaces":      {wantRoleNamespaces: []string{"team-a", "team-a-apps", "team-b"}},
		"tenantAllFeatures":          {wantRoleNamespaces: []string{"team-a", "team-a-apps"}},
		"tenantNoCustomResources":    {wantRoleNamespaces: []string{"team-a", "team-a-apps"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc := installModeCases[name]

			var roleNamespaces, bindingNamespaces []string
			for _, m := range renderInstallMode(t, chartDir, tc.valuesFile, tc.releaseName, tc.namespace) {
				if clusterScopedKinds[m.Kind] {
					t.Errorf("installMode tenant rendered cluster-scoped %s %q", m.Kind, m.Metadata.Name)
				}
				if m.Metadata.Namespace == "" {
					t.Errorf("installMode tenant rendered %s %q without a namespace", m.Kind, m.Metadata.Name)
				}
				switch m.Kind {
				case "Role":
					roleNamespaces = append(roleNamespaces, m.Metadata.Namespace)
				case "RoleBinding":
					bindingNamespaces = append(bindingNamespaces, m.Metadata.Namespace)
				}
			}

			if strings.Join(roleNamespaces, ",") != strings.Join(test.wantRoleNamespaces, ",") {
				t.Errorf("Roles rendered in %v, want %v", roleNamespaces, test.wantRoleNamespaces)
			}
			if strings.Join(bindingNamespaces, ",") != strings.Join(test.wantRoleNamespaces, ",") {
				t.Errorf("RoleBindings rendered in %v, want %v", bindingNamespaces, test.wantRoleNamespaces)
			}
		})
	}
}

// TestHelmNICPlatformRendersOnlyPrerequisites checks that installMode platform renders only the
// tenant's IngressClass and the tenant reader ClusterRole and ClusterRoleBinding.
func TestHelmNICPlatformRendersOnlyPrerequisites(t *testing.T) {
	t.Parallel()

	chartDir, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]string{
		"platform":                     {"ClusterRole", "ClusterRoleBinding", "IngressClass"},
		"platformExistingIngressClass": {"ClusterRole", "ClusterRoleBinding"},
		"platformNoTenantReader":       {"IngressClass"},
	}

	for name, wantKinds := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc := installModeCases[name]

			var kinds []string
			for _, m := range renderInstallMode(t, chartDir, tc.valuesFile, tc.releaseName, tc.namespace) {
				kinds = append(kinds, m.Kind)
			}
			slices.Sort(kinds)
			if strings.Join(kinds, ",") != strings.Join(wantKinds, ",") {
				t.Errorf("installMode platform rendered %v, want %v", kinds, wantKinds)
			}
		})
	}
}

// TestHelmNICTenantRoleIsSubsetOfFullRBAC checks that every rule a tenant Role grants is also
// granted by the full install's ClusterRole and Role for the same values, so tenant mode never
// grants NIC more than the full install does.
func TestHelmNICTenantRoleIsSubsetOfFullRBAC(t *testing.T) {
	t.Parallel()

	chartDir, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"tenant", "tenantMessyNamespaces", "tenantAllFeatures", "tenantNoCustomResources"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc := installModeCases[name]

			// The same values rendered as a full install. watchNamespace and serviceAccount.name don't
			// change the full install's rules.
			full := parseManifests(t, renderTemplate(t, chartDir, tc.releaseName,
				helmOptions{namespace: tc.namespace, valuesFiles: []string{tc.valuesFile}}, "--set", "installMode=full"))
			var fullRules []policyRule
			for _, m := range full {
				if m.Kind == "ClusterRole" || m.Kind == "Role" {
					fullRules = append(fullRules, m.Rules...)
				}
			}
			if len(fullRules) == 0 {
				t.Fatal("full install rendered no ClusterRole or Role rules")
			}

			for _, m := range renderInstallMode(t, chartDir, tc.valuesFile, tc.releaseName, tc.namespace) {
				if m.Kind != "Role" {
					continue
				}
				if missing := uncovered(m.Rules, fullRules); len(missing) > 0 {
					t.Errorf("tenant Role in namespace %s grants permissions the full install doesn't: %+v", m.Metadata.Namespace, missing)
				}
			}
		})
	}
}

// TestHelmNICTenantChartPackaging packages the chart the way publish-helm.yml does for
// nginx-ingress-tenant, and checks the result: no CRDs, installMode tenant by default,
// and any other installMode rejected.
func TestHelmNICTenantChartPackaging(t *testing.T) {
	t.Parallel()

	chartDir := copyChartWithCRDs(t)
	if !strings.Contains(helmShowCRDs(t, chartDir), "kind: CustomResourceDefinition") {
		t.Fatal("copied chart has no CRDs before repackaging")
	}

	// The same edits as the Package step of .github/workflows/publish-helm.yml with tenant: true.
	if err := os.Remove(filepath.Join(chartDir, "crds")); err != nil {
		t.Fatal(err)
	}
	replaceLine(t, filepath.Join(chartDir, "Chart.yaml"), "name: nginx-ingress", "name: nginx-ingress-tenant")
	replaceLine(t, filepath.Join(chartDir, "values.yaml"), "installMode: full", "installMode: tenant")

	if crds := helmShowCRDs(t, chartDir); strings.TrimSpace(crds) != "" {
		t.Errorf("tenant chart contains CRDs:\n%s", crds)
	}

	// Rendered without setting installMode, the packaged default must be tenant mode.
	output := renderTemplate(t, chartDir, "nic", helmOptions{namespace: "team-a"},
		"--set", "controller.serviceAccount.name=nic")
	for _, m := range parseManifests(t, output) {
		if clusterScopedKinds[m.Kind] {
			t.Errorf("tenant chart with default values rendered cluster-scoped %s %q", m.Kind, m.Metadata.Name)
		}
	}
	if !strings.Contains(output, "- -watch-namespace=team-a") {
		t.Errorf("tenant chart with default values does not watch the release namespace:\n%s", output)
	}

	opts := helmOptions{namespace: "team-a", valuesFiles: []string{"testdata/tenant.yaml"}}
	want := `the nginx-ingress-tenant chart only supports installMode "tenant"`
	for _, mode := range []string{"full", "platform"} {
		_, err := renderTemplateE(chartDir, "nic", opts, "--set", "installMode="+mode, "--set", "platform.tenantNamespace=team-a")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("tenant chart with installMode %q: error %v, want one containing %q", mode, err, want)
		}
	}
}

// copyChartWithCRDs copies the chart to a temp directory. os.CopyFS doesn't copy symlinks, so the
// crds symlink is recreated, pointing at the same CRDs as in the repository.
func copyChartWithCRDs(t *testing.T) string {
	t.Helper()

	srcDir, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal(err)
	}
	chartDir := filepath.Join(t.TempDir(), "nginx-ingress")
	if err := os.CopyFS(chartDir, os.DirFS(srcDir)); err != nil {
		t.Fatalf("failed to copy chart: %v", err)
	}
	crdsTarget, err := filepath.EvalSymlinks(filepath.Join(srcDir, "crds"))
	if err != nil {
		t.Fatal(err)
	}
	crdsLink := filepath.Join(chartDir, "crds")
	if err := os.RemoveAll(crdsLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(crdsTarget, crdsLink); err != nil {
		t.Fatal(err)
	}
	return chartDir
}

// helmShowCRDs returns the CRDs in a chart directory, as printed by helm show crds.
func helmShowCRDs(t *testing.T, chartDir string) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "helm", "show", "crds", chartDir).CombinedOutput() //nolint:gosec // chartDir is a test temp directory
	if err != nil {
		t.Fatalf("helm show crds: %v\n%s", err, out)
	}
	return string(out)
}

// replaceLine replaces the line equal to old with new in the file, and fails if there isn't exactly one.
func replaceLine(t *testing.T, file, old, replacement string) {
	t.Helper()

	data, err := os.ReadFile(file) //nolint:gosec // file is in a test temp directory
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	found := 0
	for i, line := range lines {
		if line == old {
			lines[i] = replacement
			found++
		}
	}
	if found != 1 {
		t.Fatalf("%s: found %d lines equal to %q, want 1", file, found, old)
	}
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o600); err != nil { //nolint:gosec // file is in a test temp directory
		t.Fatal(err)
	}
}

// rbacManifestHeader is written at the top of each generated file in deployments/rbac/.
const rbacManifestHeader = `# Generated from the Helm chart by "make update-rbac-manifests". Do not edit.
`

// helmLabelLines are the labels removed from generated manifests, because they name a Helm release and chart version.
var helmLabelLines = []string{
	"helm.sh/chart:",
	"app.kubernetes.io/version:",
	"app.kubernetes.io/managed-by:",
	"app.kubernetes.io/instance:",
}

// staticRBACManifest renders one chart template as a static manifest for deployments/rbac/:
// release labels are removed and the release name prefix is replaced by the plain object name.
func staticRBACManifest(t *testing.T, chartDir, template string, extraArgs ...string) string {
	t.Helper()

	opts := helmOptions{namespace: "nginx-ingress", valuesFiles: []string{"testdata/rbac-manifests.yaml"}}
	// With the release name equal to the chart name, the chart's full name is "nginx-ingress".
	args := append([]string{"--show-only", template}, extraArgs...)
	output := renderTemplate(t, chartDir, "nginx-ingress", opts, args...)

	var b strings.Builder
	b.WriteString(rbacManifestHeader)
	for i, doc := range strings.Split(output, "\n---\n") {
		if i > 0 {
			b.WriteString("---\n")
		}
		for _, line := range strings.Split(strings.TrimPrefix(doc, "---\n"), "\n") {
			if strings.HasPrefix(line, "# Source:") {
				continue
			}
			if strings.HasPrefix(line, "    ") && slices.ContainsFunc(helmLabelLines, func(l string) bool {
				return strings.HasPrefix(strings.TrimSpace(line), l)
			}) {
				continue
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// TestHelmNICStaticRBACManifests checks that the generated files in deployments/rbac/ match the chart.
// Run "make update-rbac-manifests" to regenerate them.
func TestHelmNICStaticRBACManifests(t *testing.T) {
	t.Parallel()

	chartDir, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"../../deployments/rbac/tenant-role.yaml": staticRBACManifest(t, chartDir, "templates/tenant-role.yaml",
			"--set", "installMode=tenant"),
		"../../deployments/rbac/platform-tenant-reader.yaml": staticRBACManifest(t, chartDir, "templates/platform-tenant-reader.yaml",
			"--set", "installMode=platform"),
	}

	for file, want := range files {
		if os.Getenv("UPDATE_RBAC_MANIFESTS") == "true" {
			if err := os.WriteFile(file, []byte(want), 0o644); err != nil { //nolint:gosec // committed repo file, readable like the rest of deployments/
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(file) //nolint:gosec // file is one of the fixed paths above
		if err != nil {
			t.Fatalf("%v; run make update-rbac-manifests", err)
		}
		if string(got) != want {
			t.Errorf("%s is out of date; run make update-rbac-manifests", file)
		}
	}
}

// TestHelmNICTenantAggregateCoversTenantRole checks that deployments/rbac/nic-tenant-aggregate.yaml
// grants every rule a tenant Role can contain, so a namespace admin can create the tenant Roles.
// A rule without resourceNames in the aggregate covers the same rule with resourceNames in a Role.
func TestHelmNICTenantAggregateCoversTenantRole(t *testing.T) {
	t.Parallel()

	chartDir, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("../../deployments/rbac/nic-tenant-aggregate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	aggregates := parseManifests(t, string(data))
	if len(aggregates) != 1 || aggregates[0].Kind != "ClusterRole" {
		t.Fatalf("nic-tenant-aggregate.yaml must contain exactly one ClusterRole, got %+v", aggregates)
	}
	aggregate := aggregates[0]
	if !strings.Contains(string(data), `rbac.authorization.k8s.io/aggregate-to-admin: "true"`) {
		t.Error(`nic-tenant-aggregate.yaml is not labeled rbac.authorization.k8s.io/aggregate-to-admin: "true"`)
	}

	// Every tenant fixture, so each feature is covered both on and off.
	for _, name := range []string{"tenant", "tenantMessyNamespaces", "tenantAllFeatures", "tenantNoCustomResources"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc := installModeCases[name]

			roles := 0
			for _, m := range renderInstallMode(t, chartDir, tc.valuesFile, tc.releaseName, tc.namespace) {
				if m.Kind != "Role" {
					continue
				}
				roles++
				if missing := uncovered(m.Rules, aggregate.Rules); len(missing) > 0 {
					t.Errorf("nic-tenant-aggregate.yaml does not cover the tenant Role in namespace %s: %+v", m.Metadata.Namespace, missing)
				}
			}
			if roles == 0 {
				t.Fatal("no tenant Role rendered")
			}
		})
	}
}
