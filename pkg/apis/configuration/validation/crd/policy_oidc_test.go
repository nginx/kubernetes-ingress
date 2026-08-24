//go:build envtest

package crd

import "testing"

// TestPolicyOIDC_CRDValidation locks in the CRD-level Pattern on
// TrustedCertSecret, Minimum=0 on SSLVerifyDepth, and the
// sslVerify/trustedCertSecret pairing CEL rule attached to the
// PolicySpec.oidc field.
func TestPolicyOIDC_CRDValidation(t *testing.T) {
	baseOIDC := func(mut func(m map[string]any)) map[string]any {
		o := map[string]any{
			"authEndpoint":  "https://idp.example.com/authorize",
			"tokenEndpoint": "https://idp.example.com/token",
			"jwksURI":       "https://idp.example.com/.well-known/jwks.json",
			"clientID":      "my-client",
			"clientSecret":  "oidc-secret",
		}
		if mut != nil {
			mut(o)
		}
		return map[string]any{"oidc": o}
	}

	cases := []admissionCase{
		{
			name: "valid minimal oidc",
			spec: baseOIDC(nil),
		},
		{
			name: "trustedCertSecret with uppercase is rejected (Pattern)",
			spec: baseOIDC(func(o map[string]any) {
				o["sslVerify"] = true
				o["trustedCertSecret"] = "MyCa"
			}),
			wantErr: true,
		},
		{
			name: "trustedCertSecret set with sslVerify=false is rejected (CEL)",
			spec: baseOIDC(func(o map[string]any) {
				o["sslVerify"] = false
				o["trustedCertSecret"] = "my-ca-secret"
			}),
			wantErr:   true,
			errSubstr: "trustedCertSecret can be set only if sslVerify is true",
		},
		{
			name: "trustedCertSecret set with sslVerify=true is accepted",
			spec: baseOIDC(func(o map[string]any) {
				o["sslVerify"] = true
				o["trustedCertSecret"] = "my-ca-secret"
			}),
		},
		{
			name: "negative sslVerifyDepth is rejected (Minimum=0)",
			spec: baseOIDC(func(o map[string]any) {
				o["sslVerifyDepth"] = -1
			}),
			wantErr: true,
		},
	}

	runAdmissionCases(t, cases)
}
