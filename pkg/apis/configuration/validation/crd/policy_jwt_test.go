//go:build envtest

package crd

import "testing"

// TestPolicyJWTAuth_CRDValidation locks in the CRD-level Pattern on
// TrustedCertSecret and the Minimum=0 constraint on SSLVerifyDepth.
// Both live only in kubebuilder markers.
func TestPolicyJWTAuth_CRDValidation(t *testing.T) {
	baseJWT := func(mut func(m map[string]any)) map[string]any {
		j := map[string]any{
			"realm":  "MyAPI",
			"secret": "jwt-secret",
		}
		if mut != nil {
			mut(j)
		}
		return map[string]any{"jwt": j}
	}

	cases := []admissionCase{
		{
			name: "valid minimal jwt",
			spec: baseJWT(nil),
		},
		{
			name: "trustedCertSecret with uppercase is rejected (Pattern)",
			spec: baseJWT(func(j map[string]any) {
				j["trustedCertSecret"] = "MySecret"
			}),
			wantErr: true,
		},
		{
			name: "trustedCertSecret starting with hyphen is rejected (Pattern)",
			spec: baseJWT(func(j map[string]any) {
				j["trustedCertSecret"] = "-bad"
			}),
			wantErr: true,
		},
		{
			name: "trustedCertSecret with dot is rejected (Pattern)",
			spec: baseJWT(func(j map[string]any) {
				j["trustedCertSecret"] = "my.secret"
			}),
			wantErr: true,
		},
		{
			name: "valid DNS-1123 trustedCertSecret is accepted",
			spec: baseJWT(func(j map[string]any) {
				j["trustedCertSecret"] = "my-ca-secret"
			}),
		},
		{
			name: "negative sslVerifyDepth is rejected (Minimum=0)",
			spec: baseJWT(func(j map[string]any) {
				j["sslVerifyDepth"] = -1
			}),
			wantErr: true,
		},
	}

	runAdmissionCases(t, cases)
}
