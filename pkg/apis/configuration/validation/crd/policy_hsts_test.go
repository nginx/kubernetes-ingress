//go:build envtest

package crd

import "testing"

// TestPolicyHSTS_CRDValidation locks in the two CEL rules on HSTS and
// the OpenAPI-level Required/Minimum constraints on MaxAge. All of
// these live only in the CRD schema; validateHSTS in policy.go
// duplicates the CEL logic but not the OpenAPI rules.
func TestPolicyHSTS_CRDValidation(t *testing.T) {
	baseHSTS := func(mut func(m map[string]any)) map[string]any {
		h := map[string]any{"maxAge": 3600}
		if mut != nil {
			mut(h)
		}
		return map[string]any{"hsts": h}
	}

	cases := []admissionCase{
		{
			name: "valid minimal hsts",
			spec: baseHSTS(nil),
		},
		{
			name:    "missing maxAge is rejected (Required)",
			spec:    map[string]any{"hsts": map[string]any{}},
			wantErr: true,
		},
		{
			name: "negative maxAge is rejected (Minimum=0)",
			spec: baseHSTS(func(h map[string]any) {
				h["maxAge"] = -1
			}),
			wantErr: true,
		},
		{
			name: "preload without includeSubDomains is rejected (CEL)",
			spec: baseHSTS(func(h map[string]any) {
				h["maxAge"] = 31536000
				h["preload"] = true
			}),
			wantErr:   true,
			errSubstr: "preload requires includeSubDomains to be enabled",
		},
		{
			name: "preload with maxAge below one year is rejected (CEL)",
			spec: baseHSTS(func(h map[string]any) {
				h["maxAge"] = 3600
				h["preload"] = true
				h["includeSubDomains"] = true
			}),
			wantErr:   true,
			errSubstr: "preload requires maxAge to be at least 31536000",
		},
		{
			name: "preload with both conditions met is accepted",
			spec: baseHSTS(func(h map[string]any) {
				h["maxAge"] = 31536000
				h["preload"] = true
				h["includeSubDomains"] = true
			}),
		},
	}

	runAdmissionCases(t, cases)
}
