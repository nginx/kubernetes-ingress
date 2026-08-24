//go:build envtest

package crd

import "testing"

// TestPolicyRateLimit_CRDValidation locks in the OpenAPI patterns and
// MaxItems constraints on RateLimitCondition. The Go layer does not
// re-check these patterns.
func TestPolicyRateLimit_CRDValidation(t *testing.T) {
	baseRL := func(mut func(m map[string]any)) map[string]any {
		r := map[string]any{
			"rate":     "10r/s",
			"key":      "${request_uri}",
			"zoneSize": "10M",
		}
		if mut != nil {
			mut(r)
		}
		return map[string]any{"rateLimit": r}
	}

	cases := []admissionCase{
		{
			name: "valid minimal rateLimit",
			spec: baseRL(nil),
		},
		{
			name: "jwt condition with $ in claim is rejected (Pattern)",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"jwt": map[string]any{"claim": "sub$", "match": "gold"},
				}
			}),
			wantErr: true,
		},
		{
			name: "jwt condition with whitespace in match is rejected (Pattern)",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"jwt": map[string]any{"claim": "sub", "match": "gold tier"},
				}
			}),
			wantErr: true,
		},
		{
			name: "jwt condition with quote in match is rejected (Pattern)",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"jwt": map[string]any{"claim": "sub", "match": `gold"`},
				}
			}),
			wantErr: true,
		},
		{
			name: "valid jwt condition is accepted",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"jwt": map[string]any{"claim": "sub.role", "match": "gold"},
				}
			}),
		},
		{
			name: "variables condition with two entries is rejected (MaxItems=1)",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"variables": []any{
						map[string]any{"name": "$request_method", "match": "GET"},
						map[string]any{"name": "$request_uri", "match": "/api"},
					},
				}
			}),
			wantErr: true,
		},
		{
			name: "variables condition with whitespace in name is rejected (Pattern)",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"variables": []any{
						map[string]any{"name": "$http_ user", "match": "x"},
					},
				}
			}),
			wantErr: true,
		},
		{
			name: "valid variables condition is accepted",
			spec: baseRL(func(r map[string]any) {
				r["condition"] = map[string]any{
					"variables": []any{
						map[string]any{"name": "$request_method", "match": "GET"},
					},
				}
			}),
		},
	}

	runAdmissionCases(t, cases)
}
