//go:build envtest

package crd

import "testing"

// TestPolicyCORS_CRDValidation locks in the CEL rules on the CORS
// policy. The wildcard-with-credentials rule and the per-element
// non-empty rules only exist as CRD markers.
func TestPolicyCORS_CRDValidation(t *testing.T) {
	baseCORS := func(mut func(m map[string]any)) map[string]any {
		c := map[string]any{
			"allowOrigin": []any{"https://example.com"},
		}
		if mut != nil {
			mut(c)
		}
		return map[string]any{"cors": c}
	}

	cases := []admissionCase{
		{
			name: "valid minimal cors",
			spec: baseCORS(nil),
		},
		{
			name: "empty allowOrigin list is rejected (MinItems=1)",
			spec: baseCORS(func(c map[string]any) {
				c["allowOrigin"] = []any{}
			}),
			wantErr: true,
		},
		{
			name: "allowOrigin containing empty string is rejected (CEL)",
			spec: baseCORS(func(c map[string]any) {
				c["allowOrigin"] = []any{"https://example.com", ""}
			}),
			wantErr:   true,
			errSubstr: "origin cannot be empty",
		},
		{
			name: "wildcard origin with allowCredentials=true is rejected (CEL)",
			spec: baseCORS(func(c map[string]any) {
				c["allowOrigin"] = []any{"*"}
				c["allowCredentials"] = true
			}),
			wantErr:   true,
			errSubstr: "cannot use wildcard '*' for allowOrigin when allowCredentials is true",
		},
		{
			name: "wildcard origin with allowCredentials=false is accepted",
			spec: baseCORS(func(c map[string]any) {
				c["allowOrigin"] = []any{"*"}
				c["allowCredentials"] = false
			}),
		},
		{
			name: "wildcard origin without allowCredentials is accepted",
			spec: baseCORS(func(c map[string]any) {
				c["allowOrigin"] = []any{"*"}
			}),
		},
		{
			name: "allowMethods containing empty string is rejected (CEL)",
			spec: baseCORS(func(c map[string]any) {
				c["allowMethods"] = []any{"GET", ""}
			}),
			wantErr:   true,
			errSubstr: "method name cannot be empty",
		},
		{
			name: "allowHeaders containing empty string is rejected (CEL)",
			spec: baseCORS(func(c map[string]any) {
				c["allowHeaders"] = []any{"Authorization", ""}
			}),
			wantErr:   true,
			errSubstr: "header name cannot be empty",
		},
		{
			name: "exposeHeaders containing empty string is rejected (CEL)",
			spec: baseCORS(func(c map[string]any) {
				c["exposeHeaders"] = []any{"X-Custom", ""}
			}),
			wantErr:   true,
			errSubstr: "header name cannot be empty",
		},
		{
			name: "maxAge=-1 is rejected (Minimum=0)",
			spec: baseCORS(func(c map[string]any) {
				c["maxAge"] = -1
			}),
			wantErr: true,
		},
	}

	runAdmissionCases(t, cases)
}
