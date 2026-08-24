//go:build envtest

package crd

import (
	"strings"
	"testing"
)

// TestPolicyExternalAuth_CRDValidation locks in the OpenAPI patterns
// on AuthURI, AuthServiceName, AuthSigninURI, AuthSigninRedirectBasePath,
// TrustedCertSecret and SNIName, plus Minimum=0 on SSLVerifyDepth.
// The Go validator does not re-check these regex patterns.
func TestPolicyExternalAuth_CRDValidation(t *testing.T) {
	baseEA := func(mut func(m map[string]any)) map[string]any {
		e := map[string]any{
			"authURI":         "/auth",
			"authServiceName": "auth-svc",
		}
		if mut != nil {
			mut(e)
		}
		return map[string]any{"externalAuth": e}
	}

	cases := []admissionCase{
		{
			name: "valid minimal externalAuth",
			spec: baseEA(nil),
		},
		{
			name: "authURI without leading slash is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["authURI"] = "auth"
			}),
			wantErr: true,
		},
		{
			name: "authServiceName with uppercase is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["authServiceName"] = "AuthSvc"
			}),
			wantErr: true,
		},
		{
			name: "authServiceName in namespace/name form is accepted",
			spec: baseEA(func(e map[string]any) {
				e["authServiceName"] = "auth-ns/auth-svc"
			}),
		},
		{
			name: "authServiceName with three segments is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["authServiceName"] = "a/b/c"
			}),
			wantErr: true,
		},
		{
			name: "authSigninURI without leading slash is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["authSigninURI"] = "signin"
			}),
			wantErr: true,
		},
		{
			name: "authSigninRedirectBasePath with space is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["authSigninRedirectBasePath"] = "/oauth 2"
			}),
			wantErr: true,
		},
		{
			name: "trustedCertSecret in namespace/name form is accepted",
			spec: baseEA(func(e map[string]any) {
				e["trustedCertSecret"] = "auth-ns/ca-secret"
			}),
		},
		{
			name: "trustedCertSecret with dot is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["trustedCertSecret"] = "ca.secret"
			}),
			wantErr: true,
		},
		{
			name: "sniName with underscore is rejected (Pattern)",
			spec: baseEA(func(e map[string]any) {
				e["sniName"] = "bad_host.example.com"
			}),
			wantErr: true,
		},
		{
			name: "valid sniName is accepted",
			spec: baseEA(func(e map[string]any) {
				e["sniName"] = "auth.example.com"
			}),
		},
		{
			name: "negative sslVerifyDepth is rejected (Minimum=0)",
			spec: baseEA(func(e map[string]any) {
				e["sslVerifyDepth"] = -1
			}),
			wantErr: true,
		},
		{
			name: "long authSnippets round-trips",
			spec: baseEA(func(e map[string]any) {
				e["authSnippets"] = strings.Repeat("proxy_set_header X-Test 1;\n", 20)
			}),
		},
	}

	runAdmissionCases(t, cases)
}
