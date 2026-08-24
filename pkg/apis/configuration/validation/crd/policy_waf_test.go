//go:build envtest

package crd

import (
	"strings"
	"testing"
)

// TestPolicyWAFBundleSource_CRDValidation locks in the CRD-level rules
// on WAF.ApBundleSource. The URL Pattern, MinLength/MaxLength, the
// DNS-1123 Pattern on Secret/TrustedCertSecret, MaxLength=63 on
// Name/Namespace, the RetryAttempts range, and the Type enum are all
// only enforced by kubebuilder markers.
func TestPolicyWAFBundleSource_CRDValidation(t *testing.T) {
	baseWAF := func(mut func(bs map[string]any)) map[string]any {
		bs := map[string]any{
			"url":           "https://waf.example.com/bundle.tgz",
			"enablePolling": false,
		}
		if mut != nil {
			mut(bs)
		}
		return map[string]any{"waf": map[string]any{"apBundleSource": bs}}
	}

	cases := []admissionCase{
		{
			name: "valid HTTPS bundle source",
			spec: baseWAF(nil),
		},
		{
			name: "http URL is rejected (Pattern)",
			spec: baseWAF(func(bs map[string]any) {
				bs["url"] = "http://waf.example.com/bundle.tgz"
			}),
			wantErr: true,
		},
		{
			name: "empty URL is rejected (MinLength=1)",
			spec: baseWAF(func(bs map[string]any) {
				bs["url"] = ""
			}),
			wantErr: true,
		},
		{
			name: "URL over MaxLength is rejected",
			spec: baseWAF(func(bs map[string]any) {
				bs["url"] = "https://waf.example.com/" + strings.Repeat("a", 2100)
			}),
			wantErr: true,
		},
		{
			name: "invalid type is rejected (Enum)",
			spec: baseWAF(func(bs map[string]any) {
				bs["type"] = "FTP"
			}),
			wantErr: true,
		},
		{
			name: "NIM type with valid name is accepted",
			spec: baseWAF(func(bs map[string]any) {
				bs["type"] = "NIM"
				bs["name"] = "prod-policy"
			}),
		},
		{
			name: "N1C type with name and namespace is accepted",
			spec: baseWAF(func(bs map[string]any) {
				bs["type"] = "N1C"
				bs["name"] = "prod-policy"
				bs["namespace"] = "tenant-a"
			}),
		},
		{
			name: "name over MaxLength=63 is rejected",
			spec: baseWAF(func(bs map[string]any) {
				bs["type"] = "NIM"
				bs["name"] = strings.Repeat("a", 64)
			}),
			wantErr: true,
		},
		{
			name: "namespace over MaxLength=63 is rejected",
			spec: baseWAF(func(bs map[string]any) {
				bs["type"] = "N1C"
				bs["name"] = "prod-policy"
				bs["namespace"] = strings.Repeat("b", 64)
			}),
			wantErr: true,
		},
		{
			name: "secret with uppercase is rejected (Pattern)",
			spec: baseWAF(func(bs map[string]any) {
				bs["secret"] = "MySecret"
			}),
			wantErr: true,
		},
		{
			name: "trustedCertSecret with dot is rejected (Pattern)",
			spec: baseWAF(func(bs map[string]any) {
				bs["trustedCertSecret"] = "my.ca"
			}),
			wantErr: true,
		},
		{
			name: "retryAttempts=0 is rejected (Minimum=1)",
			spec: baseWAF(func(bs map[string]any) {
				bs["retryAttempts"] = 0
			}),
			wantErr: true,
		},
		{
			name: "retryAttempts=11 is rejected (Maximum=10)",
			spec: baseWAF(func(bs map[string]any) {
				bs["retryAttempts"] = 11
			}),
			wantErr: true,
		},
		{
			name: "retryAttempts=10 is accepted",
			spec: baseWAF(func(bs map[string]any) {
				bs["retryAttempts"] = 10
			}),
		},
	}

	runAdmissionCases(t, cases)
}
