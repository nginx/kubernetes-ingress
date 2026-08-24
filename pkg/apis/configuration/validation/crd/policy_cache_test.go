//go:build envtest

package crd

import "testing"

// TestPolicyCache_CRDValidation locks in the CEL rules and OpenAPI
// patterns on the Cache policy. These live only in types.go markers
// and are not re-checked by the Go validators in policy.go, so this
// is the only place they get unit-test coverage.
func TestPolicyCache_CRDValidation(t *testing.T) {
	baseCache := func(mut func(m map[string]any)) map[string]any {
		c := map[string]any{
			"cacheZoneName": "mycache",
			"cacheZoneSize": "10m",
		}
		if mut != nil {
			mut(c)
		}
		return map[string]any{"cache": c}
	}

	cases := []admissionCase{
		{
			name: "valid minimal cache",
			spec: baseCache(nil),
		},
		{
			name: "allowedCodes without time is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["allowedCodes"] = []any{200}
			}),
			wantErr:   true,
			errSubstr: "time is required when allowedCodes is specified",
		},
		{
			name: "allowedCodes with time is accepted",
			spec: baseCache(func(c map[string]any) {
				c["allowedCodes"] = []any{200}
				c["time"] = "5m"
			}),
		},
		{
			name: "lock.timeout without enable is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["lock"] = map[string]any{"timeout": "5s"}
			}),
			wantErr:   true,
			errSubstr: "timeout or age require enable=true",
		},
		{
			name: "lock.age without enable is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["lock"] = map[string]any{"age": "10s"}
			}),
			wantErr:   true,
			errSubstr: "timeout or age require enable=true",
		},
		{
			name: "lock.timeout with enable=true is accepted",
			spec: baseCache(func(c map[string]any) {
				c["lock"] = map[string]any{"enable": true, "timeout": "5s"}
			}),
		},
		{
			name: "cacheKey with $( is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["cacheKey"] = "$scheme$(command)"
			}),
			wantErr:   true,
			errSubstr: "command execution patterns",
		},
		{
			name: "cacheKey with backtick is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["cacheKey"] = "$scheme`whoami`"
			}),
			wantErr:   true,
			errSubstr: "command execution patterns",
		},
		{
			name: "cacheKey with semicolon is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["cacheKey"] = "$scheme;evil"
			}),
			wantErr:   true,
			errSubstr: "command execution patterns",
		},
		{
			name: "cacheKey with && is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["cacheKey"] = "$scheme && evil"
			}),
			wantErr:   true,
			errSubstr: "command execution patterns",
		},
		{
			name: "cacheKey with || is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["cacheKey"] = "$scheme || evil"
			}),
			wantErr:   true,
			errSubstr: "command execution patterns",
		},
		{
			name: "cacheKey plain nginx variables are accepted",
			spec: baseCache(func(c map[string]any) {
				c["cacheKey"] = "$scheme$proxy_host$uri"
			}),
		},
		{
			name: "cacheZoneName with uppercase is rejected (Pattern)",
			spec: baseCache(func(c map[string]any) {
				c["cacheZoneName"] = "MyCache"
			}),
			wantErr: true,
		},
		{
			name: "cacheZoneName ending with underscore is rejected (Pattern)",
			spec: baseCache(func(c map[string]any) {
				c["cacheZoneName"] = "my_cache_"
			}),
			wantErr: true,
		},
		{
			name: "cacheZoneSize with bare number is rejected (Pattern)",
			spec: baseCache(func(c map[string]any) {
				c["cacheZoneSize"] = "10"
			}),
			wantErr: true,
		},
		{
			name: "cacheMinUses=0 is rejected (Minimum=1)",
			spec: baseCache(func(c map[string]any) {
				c["cacheMinUses"] = 0
			}),
			wantErr: true,
		},
		{
			name: "manager.files=0 is rejected (Minimum=1)",
			spec: baseCache(func(c map[string]any) {
				c["manager"] = map[string]any{"files": 0}
			}),
			wantErr: true,
		},
		{
			name: "manager.sleep with invalid unit is rejected (Pattern)",
			spec: baseCache(func(c map[string]any) {
				c["manager"] = map[string]any{"sleep": "50x"}
			}),
			wantErr: true,
		},
		{
			name: "allowedMethods with PUT is rejected (CEL)",
			spec: baseCache(func(c map[string]any) {
				c["allowedMethods"] = []any{"PUT"}
				c["time"] = "1m"
			}),
			wantErr:   true,
			errSubstr: "allowed methods must be one of: GET, HEAD, POST",
		},
	}

	runAdmissionCases(t, cases)
}
