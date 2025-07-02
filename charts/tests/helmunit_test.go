//go:build helmunit

package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
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
		valuesFile  string
		releaseName string
		namespace   string
	}{
		"default values file": {
			valuesFile:  "",
			releaseName: "default",
			namespace:   "default",
		},
		"daemonset": {
			valuesFile:  "testdata/daemonset.yaml",
			releaseName: "daemonset",
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
		"globalConfig": {
			valuesFile:  "testdata/global-configuration.yaml",
			releaseName: "global-configuration",
			namespace:   "gc",
		},
		"customResources": {
			valuesFile:  "testdata/custom-resources.yaml",
			releaseName: "custom-resources",
			namespace:   "custom-resources",
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
		"appProtectWAFV4AgentV2": {
			valuesFile:  "testdata/app-protect-waf-agentv2.yaml",
			releaseName: "app-protect-waf-agentv2",
			namespace:   "default",
		},
	}

	// Path to the helm chart we will test
	helmChartPath, err := filepath.Abs("../nginx-ingress")
	if err != nil {
		t.Fatal("Failed to open helm chart path ../nginx-ingress")
	}

	for testName, tc := range tests {
		t.Run(testName, func(t *testing.T) {
			options := &helm.Options{
				KubectlOptions: k8s.NewKubectlOptions("", "", tc.namespace),
			}

			if tc.valuesFile != "" {
				options.ValuesFiles = []string{tc.valuesFile}
			}

			output := helm.RenderTemplate(t, options, helmChartPath, tc.releaseName, make([]string, 0))

			snaps.MatchSnapshot(t, output)
			t.Log(output)
		})
	}
}
