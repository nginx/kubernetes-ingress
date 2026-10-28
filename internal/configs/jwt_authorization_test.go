package configs

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dlclark/regexp2/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	internalValidation "github.com/nginx/kubernetes-ingress/internal/validation"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

func matchType(m conf_v1.JWTClaimMatchType) *conf_v1.JWTClaimMatchType { return &m }

func requireType(r conf_v1.JWTRequireType) *conf_v1.JWTRequireType { return &r }

func jwtOwner(ns, name string) policyOwnerDetails {
	return policyOwnerDetails{
		ownerNamespace:  ns,
		ownerName:       name,
		parentNamespace: ns,
		parentName:      name,
		parentType:      "vs",
	}
}

// evalMaps applies the generated maps the way NGINX does: exact key, then the first matching regex,
// then default. A missing claim reads as the empty string.
func evalMaps(t *testing.T, maps []version2.Map, vars map[string]string) map[string]string {
	t.Helper()

	env := make(map[string]string, len(vars))
	for k, v := range vars {
		env[k] = v
	}

	for _, m := range maps {
		source := jwtTestVarRe.ReplaceAllStringFunc(m.Source, func(name string) string { return env[name] })
		env[m.Variable] = evalMap(t, m, source)
	}
	return env
}

var jwtTestVarRe = regexp.MustCompile(`\$[A-Za-z0-9_]+`)

// evalMap returns the value of one map for the given source, and checks that it is a single 0 or 1.
func evalMap(t *testing.T, m version2.Map, source string) string {
	t.Helper()

	var regexKeys []version2.Parameter
	defaultResult, hasDefault := "", false

	for _, p := range m.Parameters {
		switch {
		case p.Value == "default":
			defaultResult, hasDefault = p.Result, true
		case strings.HasPrefix(p.Value, `"~`):
			regexKeys = append(regexKeys, p)
		case strings.Trim(p.Value, `"`) == source:
			return checkMapResult(t, m, p.Result)
		}
	}

	for _, p := range regexKeys {
		pattern := strings.TrimPrefix(internalValidation.UnescapeNGINXToken(strings.Trim(p.Value, `"`)), "~")
		re, err := regexp2.Compile(pattern)
		if err != nil {
			t.Fatalf("map %s: key %s does not compile: %v", m.Variable, p.Value, err)
		}
		matched, err := re.MatchString(source)
		if err != nil {
			t.Fatalf("map %s: key %s: %v", m.Variable, p.Value, err)
		}
		if matched {
			return checkMapResult(t, m, p.Result)
		}
	}

	if !hasDefault {
		t.Fatalf("map %s has no match for %q and no default", m.Variable, source)
	}
	return checkMapResult(t, m, defaultResult)
}

func checkMapResult(t *testing.T, m version2.Map, result string) string {
	t.Helper()
	if result != "0" && result != "1" {
		t.Fatalf("map %s returned %q, every claim and rule map must return exactly one of 0 or 1", m.Variable, result)
	}
	return result
}

func allowed(t *testing.T, gen jwtAuthorization, claimVars map[string]string) bool {
	t.Helper()
	env := evalMaps(t, gen.Maps, claimVars)
	return env[gen.RequireVariable] == "1"
}

func singleClaimPolicy(claim conf_v1.JWTClaim) *conf_v1.JWTAuthorization {
	return &conf_v1.JWTAuthorization{
		Rules: []conf_v1.JWTAuthorizationRule{{Claims: []conf_v1.JWTClaim{claim}}},
	}
}

func TestGenerateJWTAuthorization_MatchSemantics(t *testing.T) {
	t.Parallel()

	owner := jwtOwner("default", "cafe")
	claimVar := generateAuthJwtClaimSetVariable("c", owner)

	const missing = ""

	tests := []struct {
		name   string
		match  conf_v1.JWTClaimMatchType
		values []string
		negate bool
		cases  map[string]bool
	}{
		{
			name: "Exact", match: conf_v1.JWTClaimMatchExact, values: []string{"admin", "root"},
			cases: map[string]bool{
				"admin": true, "root": true,
				"Admin": false, "ADMIN": false, // case-sensitive, unlike a plain map string key
				"administrator": false, "xadmin": false,
				"admin\n": false, // PCRE $ would let this through, \z does not
				"a,admin": false, "admin root": false,
				missing: false,
			},
		},
		{
			name: "Exact negated", match: conf_v1.JWTClaimMatchExact, values: []string{"admin", "root"}, negate: true,
			cases: map[string]bool{
				"admin": false, "root": false,
				"guest": true, "Admin": true, "administrator": true,
				"admin\n": true,  // not equal to "admin", so the negated check passes
				missing:   false, // a value check never passes on a missing claim, even negated
			},
		},
		{
			name: "Contains", match: conf_v1.JWTClaimMatchContains, values: []string{"orders:read", "orders:write"},
			cases: map[string]bool{
				"orders:read": true, "openid orders:read": true, "orders:write profile": true,
				"a,orders:read,b":                 true, // array claims are comma-joined by auth_jwt_claim_set
				"openid orders:read orders:write": true,
				"orders:readonly":                 false, "xorders:read": false, "orders": false,
				"ORDERS:READ": false, "openid profile": false,
				"orders:read\n": false,
				missing:         false,
			},
		},
		{
			name: "Contains negated", match: conf_v1.JWTClaimMatchContains, values: []string{"guest"}, negate: true,
			cases: map[string]bool{
				"customer": true, "customer,staff": true, "guests": true, "xguest": true,
				"guest": false, "customer,guest": false, "guest customer": false, "a guest b": false,
				missing: false, // missing claim fails even though it "does not contain guest"
			},
		},
		{
			name: "Regex", match: conf_v1.JWTClaimMatchRegex, values: []string{`^[^@]+@example\.com$`, `^svc-[0-9]+$`},
			cases: map[string]bool{
				"bob@example.com": true, "svc-42": true,
				"bob@EXAMPLE.com": false, // ~ is case-sensitive
				"bob@exampleXcom": false, "svc-": false, "svc-4a": false,
				missing: false,
			},
		},
		{
			name: "Regex that matches the empty string", match: conf_v1.JWTClaimMatchRegex, values: []string{`.*`},
			cases: map[string]bool{
				"anything": true,
				missing:    false, // the literal "" key wins, so .* cannot fail open on a missing claim
			},
		},
		{
			name: "Regex negated", match: conf_v1.JWTClaimMatchRegex, values: []string{`^[^@]+@example\.com$`}, negate: true,
			cases: map[string]bool{
				"bob@example.com": false,
				"bob@other.com":   true,
				missing:           false,
			},
		},
		{
			name: "Present", match: conf_v1.JWTClaimMatchPresent,
			cases: map[string]bool{
				"x": true, "0": true, " ": true,
				missing: false,
			},
		},
		{
			name: "Present negated, claim must be absent", match: conf_v1.JWTClaimMatchPresent, negate: true,
			cases: map[string]bool{
				"x":     false,
				"0":     false,
				missing: true, // the only check that accepts a missing claim
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claim := conf_v1.JWTClaim{Name: "c", Match: matchType(tc.match), Values: tc.values, Negate: tc.negate}
			gen := generateJWTAuthorization(singleClaimPolicy(claim), "default", "pol", owner)

			for value, want := range tc.cases {
				if got := allowed(t, gen, map[string]string{claimVar: value}); got != want {
					t.Errorf("claim value %q: allowed = %v, want %v", value, got, want)
				}
			}
		})
	}
}

func TestGenerateJWTAuthorization_ExactIsDefaultMatch(t *testing.T) {
	t.Parallel()

	owner := jwtOwner("default", "cafe")
	explicit := generateJWTAuthorization(singleClaimPolicy(conf_v1.JWTClaim{Name: "c", Match: matchType(conf_v1.JWTClaimMatchExact), Values: []string{"a"}}), "default", "pol", owner)
	implicit := generateJWTAuthorization(singleClaimPolicy(conf_v1.JWTClaim{Name: "c", Values: []string{"a"}}), "default", "pol", owner)

	if diff := cmp.Diff(explicit, implicit); diff != "" {
		t.Errorf("omitting match must behave as Exact (-explicit +implicit):\n%s", diff)
	}
}

func TestGenerateJWTAuthorization_Structure(t *testing.T) {
	t.Parallel()

	owner := jwtOwner("default", "shop-vs")
	authz := &conf_v1.JWTAuthorization{
		ErrorCode: new(401),
		Rules: []conf_v1.JWTAuthorizationRule{
			{
				Require: requireType(conf_v1.JWTRequireAll),
				Claims: []conf_v1.JWTClaim{
					{Name: "aud", Match: matchType(conf_v1.JWTClaimMatchContains), Values: []string{"orders-api"}},
					{Name: "scope", Match: matchType(conf_v1.JWTClaimMatchContains), Values: []string{"orders:read", "orders:write"}, ProxySetHeader: "X-Token-Scope"},
					{Name: "realm_access.roles", Match: matchType(conf_v1.JWTClaimMatchContains), Values: []string{"guest"}, Negate: true},
				},
			},
		},
	}

	got := generateJWTAuthorization(authz, "default", "orders-api-jwt", owner)

	policyVar := "$jwt_authz_default_shop_vs_vs_default_orders_api_jwt"
	want := jwtAuthorization{
		ClaimSets: []version2.AuthJWTClaimSet{
			{Variable: "$jwt_default_shop_vs_vs_aud", Claim: "aud"},
			{Variable: "$jwt_default_shop_vs_vs_scope", Claim: "scope"},
			{Variable: "$jwt_default_shop_vs_vs_realm_access_roles", Claim: "realm_access roles"},
		},
		Maps: []version2.Map{
			{
				Source: "$jwt_default_shop_vs_vs_aud", Variable: policyVar + "_r0_c0",
				Parameters: []version2.Parameter{
					{Value: `""`, Result: "0"},
					{Value: `"~(^|[ ,])(orders-api)([ ,]|\\z)"`, Result: "1"},
					{Value: "default", Result: "0"},
				},
			},
			{
				Source: "$jwt_default_shop_vs_vs_scope", Variable: policyVar + "_r0_c1",
				Parameters: []version2.Parameter{
					{Value: `""`, Result: "0"},
					{Value: `"~(^|[ ,])(orders:read|orders:write)([ ,]|\\z)"`, Result: "1"},
					{Value: "default", Result: "0"},
				},
			},
			{
				Source: "$jwt_default_shop_vs_vs_scope", Variable: policyVar + "_r0_c1_hdr",
				Parameters: []version2.Parameter{
					{Value: `"~[\r\n]"`, Result: `""`},
					{Value: "default", Result: "$jwt_default_shop_vs_vs_scope"},
				},
			},
			{
				Source: "$jwt_default_shop_vs_vs_realm_access_roles", Variable: policyVar + "_r0_c2",
				Parameters: []version2.Parameter{
					{Value: `""`, Result: "0"},
					{Value: `"~(^|[ ,])(guest)([ ,]|\\z)"`, Result: "0"},
					{Value: "default", Result: "1"},
				},
			},
			{
				Source: policyVar + "_r0_c0" + policyVar + "_r0_c1" + policyVar + "_r0_c2", Variable: policyVar + "_r0",
				Parameters: []version2.Parameter{{Value: `"~^1+$"`, Result: "1"}, {Value: "default", Result: "0"}},
			},
			{
				Source: policyVar + "_r0", Variable: policyVar,
				Parameters: []version2.Parameter{{Value: `"~^1+$"`, Result: "1"}, {Value: "default", Result: "0"}},
			},
		},
		RequireVariable: policyVar,
		ErrorCode:       401,
		ProxySetHeaders: []version2.Header{{Name: "X-Token-Scope", Value: policyVar + "_r0_c1_hdr"}},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("generateJWTAuthorization() mismatch (-want +got):\n%s", diff)
	}
}

func TestGenerateJWTAuthorization_DefaultsAndEmptyHeaders(t *testing.T) {
	t.Parallel()

	got := generateJWTAuthorization(singleClaimPolicy(conf_v1.JWTClaim{Name: "iss", Values: []string{"a"}}), "default", "p", jwtOwner("default", "cafe"))

	if got.ErrorCode != 403 {
		t.Errorf("ErrorCode = %d, want the default 403", got.ErrorCode)
	}
	if len(got.ProxySetHeaders) != 0 {
		t.Errorf("ProxySetHeaders = %v, want none", got.ProxySetHeaders)
	}
}

func TestGenerateJWTAuthorization_RequireAnyAll(t *testing.T) {
	t.Parallel()

	owner := jwtOwner("default", "cafe")
	issVar := generateAuthJwtClaimSetVariable("iss", owner)
	tierVar := generateAuthJwtClaimSetVariable("tier", owner)

	rule := func(require *conf_v1.JWTRequireType, claims ...conf_v1.JWTClaim) conf_v1.JWTAuthorizationRule {
		return conf_v1.JWTAuthorizationRule{Require: require, Claims: claims}
	}
	iss := func(v string) conf_v1.JWTClaim { return conf_v1.JWTClaim{Name: "iss", Values: []string{v}} }
	tier := func(v string) conf_v1.JWTClaim { return conf_v1.JWTClaim{Name: "tier", Values: []string{v}} }

	tests := []struct {
		name  string
		top   *conf_v1.JWTRequireType
		rules []conf_v1.JWTAuthorizationRule
		vars  map[string]string
		want  bool
	}{
		{"rule default Any: first claim passes", nil, []conf_v1.JWTAuthorizationRule{rule(nil, iss("a"), tier("g"))}, map[string]string{issVar: "a", tierVar: "x"}, true},
		{"rule default Any: second claim passes", nil, []conf_v1.JWTAuthorizationRule{rule(nil, iss("a"), tier("g"))}, map[string]string{issVar: "x", tierVar: "g"}, true},
		{"rule default Any: none pass", nil, []conf_v1.JWTAuthorizationRule{rule(nil, iss("a"), tier("g"))}, map[string]string{issVar: "x", tierVar: "x"}, false},
		{"rule All: one fails", nil, []conf_v1.JWTAuthorizationRule{rule(requireType(conf_v1.JWTRequireAll), iss("a"), tier("g"))}, map[string]string{issVar: "a", tierVar: "x"}, false},
		{"rule All: both pass", nil, []conf_v1.JWTAuthorizationRule{rule(requireType(conf_v1.JWTRequireAll), iss("a"), tier("g"))}, map[string]string{issVar: "a", tierVar: "g"}, true},
		{"rule All: claim missing", nil, []conf_v1.JWTAuthorizationRule{rule(requireType(conf_v1.JWTRequireAll), iss("a"), tier("g"))}, map[string]string{issVar: "a"}, false},

		{"top default All: one rule fails", nil, []conf_v1.JWTAuthorizationRule{rule(nil, iss("a")), rule(nil, tier("g"))}, map[string]string{issVar: "a", tierVar: "x"}, false},
		{"top default All: both rules pass", nil, []conf_v1.JWTAuthorizationRule{rule(nil, iss("a")), rule(nil, tier("g"))}, map[string]string{issVar: "a", tierVar: "g"}, true},
		{"top Any: one rule passes", requireType(conf_v1.JWTRequireAny), []conf_v1.JWTAuthorizationRule{rule(nil, iss("a")), rule(nil, tier("g"))}, map[string]string{issVar: "a", tierVar: "x"}, true},
		{"top Any: no rule passes", requireType(conf_v1.JWTRequireAny), []conf_v1.JWTAuthorizationRule{rule(nil, iss("a")), rule(nil, tier("g"))}, map[string]string{issVar: "x", tierVar: "x"}, false},
		{"top All: explicit", requireType(conf_v1.JWTRequireAll), []conf_v1.JWTAuthorizationRule{rule(nil, iss("a")), rule(nil, tier("g"))}, map[string]string{issVar: "a", tierVar: "g"}, true},

		{
			"any-of-all: second rule matches", requireType(conf_v1.JWTRequireAny),
			[]conf_v1.JWTAuthorizationRule{
				rule(requireType(conf_v1.JWTRequireAll), iss("staff"), tier("t1")),
				rule(requireType(conf_v1.JWTRequireAll), iss("partner"), tier("g")),
			},
			map[string]string{issVar: "partner", tierVar: "g"},
			true,
		},
		{
			"any-of-all: mixed claims from two rules do not pass", requireType(conf_v1.JWTRequireAny),
			[]conf_v1.JWTAuthorizationRule{
				rule(requireType(conf_v1.JWTRequireAll), iss("staff"), tier("t1")),
				rule(requireType(conf_v1.JWTRequireAll), iss("partner"), tier("g")),
			},
			map[string]string{issVar: "staff", tierVar: "g"},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gen := generateJWTAuthorization(&conf_v1.JWTAuthorization{Require: tc.top, Rules: tc.rules}, "default", "pol", owner)
			if got := allowed(t, gen, tc.vars); got != tc.want {
				t.Errorf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// A missing claim is allowed only when the policy says so explicitly (Example 3 of the plan).
func TestGenerateJWTAuthorization_ExplicitlyAllowMissingClaim(t *testing.T) {
	t.Parallel()

	owner := jwtOwner("default", "cafe")
	audVar := generateAuthJwtClaimSetVariable("aud", owner)
	roleVar := generateAuthJwtClaimSetVariable("role", owner)

	authz := &conf_v1.JWTAuthorization{
		Rules: []conf_v1.JWTAuthorizationRule{
			{Claims: []conf_v1.JWTClaim{{Name: "aud", Match: matchType(conf_v1.JWTClaimMatchContains), Values: []string{"api"}}}},
			{
				Require: requireType(conf_v1.JWTRequireAny),
				Claims: []conf_v1.JWTClaim{
					{Name: "role", Values: []string{"guest"}, Negate: true},
					{Name: "role", Match: matchType(conf_v1.JWTClaimMatchPresent), Negate: true},
				},
			},
		},
	}
	gen := generateJWTAuthorization(authz, "default", "pol", owner)

	for role, want := range map[string]bool{"admin": true, "guest": false, "": true} {
		if got := allowed(t, gen, map[string]string{audVar: "api", roleVar: role}); got != want {
			t.Errorf("role %q: allowed = %v, want %v", role, got, want)
		}
	}
	if allowed(t, gen, map[string]string{audVar: "other", roleVar: "admin"}) {
		t.Error("a token that fails the aud rule must be rejected whatever its role")
	}

	if len(gen.ClaimSets) != 3 {
		t.Errorf("ClaimSets = %v, want aud once plus role twice before de-duplication", gen.ClaimSets)
	}
	if len(removeDuplicateAuthJWTClaimSets(gen.ClaimSets)) != 2 {
		t.Errorf("de-duplicated claim sets = %v, want 2", removeDuplicateAuthJWTClaimSets(gen.ClaimSets))
	}
}

func TestGenerateJWTAuthorization_NamingIsPerParentAndPolicy(t *testing.T) {
	t.Parallel()

	authz := singleClaimPolicy(conf_v1.JWTClaim{Name: "iss", Values: []string{"a"}})

	vs1 := generateJWTAuthorization(authz, "default", "shared-pol", jwtOwner("default", "cafe"))
	vs2 := generateJWTAuthorization(authz, "default", "shared-pol", jwtOwner("default", "tea"))
	otherPol := generateJWTAuthorization(authz, "default", "other-pol", jwtOwner("default", "cafe"))
	otherPolNS := generateJWTAuthorization(authz, "prod", "shared-pol", jwtOwner("default", "cafe"))

	names := map[string]string{
		"vs1": vs1.RequireVariable, "vs2": vs2.RequireVariable,
		"otherPol": otherPol.RequireVariable, "otherPolNS": otherPolNS.RequireVariable,
	}
	seen := map[string]string{}
	for label, name := range names {
		if prev, ok := seen[name]; ok {
			t.Errorf("%s and %s share the variable %s: two VirtualServers sharing a policy, or two routes with different policies, would collide", prev, label, name)
		}
		seen[name] = label
		if !strings.HasPrefix(name, "$jwt_authz_") {
			t.Errorf("%s: variable %q does not start with $jwt_authz_", label, name)
		}
		if strings.ContainsAny(name[1:], "-./") {
			t.Errorf("%s: variable %q is not a valid NGINX variable name", label, name)
		}
	}

	for _, gen := range []jwtAuthorization{vs1, vs2, otherPol, otherPolNS} {
		vars := map[string]bool{}
		for _, m := range gen.Maps {
			if vars[m.Variable] {
				t.Errorf("duplicate map variable %s", m.Variable)
			}
			vars[m.Variable] = true
		}
	}
}

func TestGenerateJWTAuthorization_VariableNamesAreValidForNamesWithDots(t *testing.T) {
	t.Parallel()

	gen := generateJWTAuthorization(singleClaimPolicy(conf_v1.JWTClaim{Name: "iss", Values: []string{"a"}}),
		"my.ns", "my.policy-name", jwtOwner("my.ns", "cafe.example-vs"))

	valid := regexp.MustCompile(`^\$[A-Za-z0-9_]+$`)
	validSource := regexp.MustCompile(`^(\$[A-Za-z0-9_]+)+$`) // require maps concatenate several variables
	for _, m := range gen.Maps {
		if !valid.MatchString(m.Variable) {
			t.Errorf("map variable %q is not a valid NGINX variable name", m.Variable)
		}
		if !validSource.MatchString(m.Source) {
			t.Errorf("map source %q is not a valid NGINX variable reference", m.Source)
		}
	}
	if len(gen.ClaimSets) == 0 {
		t.Fatal("no claim sets generated")
	}
	for _, cs := range gen.ClaimSets {
		if !valid.MatchString(cs.Variable) {
			t.Errorf("claim set variable %q is not a valid NGINX variable name", cs.Variable)
		}
	}
}

func TestGenerateJWTAuthorization_MapKeysEscapeQuotesAndBackslashes(t *testing.T) {
	t.Parallel()

	owner := jwtOwner("default", "cafe")
	claimVar := generateAuthJwtClaimSetVariable("c", owner)

	tests := []struct {
		name    string
		match   conf_v1.JWTClaimMatchType
		value   string
		literal string
	}{
		{"Exact with a quote", conf_v1.JWTClaimMatchExact, `a" b`, `a" b`},
		{"Exact with a backslash", conf_v1.JWTClaimMatchExact, `a\b`, `a\b`},
		{"Exact with a quote and a backslash", conf_v1.JWTClaimMatchExact, `a\"b`, `a\"b`},
		{"Exact with regex metacharacters", conf_v1.JWTClaimMatchExact, `a.b*c(d)`, `a.b*c(d)`},
		{"Contains with a quote", conf_v1.JWTClaimMatchContains, `a"b`, `x,a"b,y`},
		{"Contains with a backslash", conf_v1.JWTClaimMatchContains, `a\b`, `x a\b y`},
		{"Regex with a quote", conf_v1.JWTClaimMatchRegex, `^a"b$`, `a"b`},
		{"Regex with a backslash", conf_v1.JWTClaimMatchRegex, `^a\\b$`, `a\b`},
		{"Regex with an escape", conf_v1.JWTClaimMatchRegex, `^a\.b$`, `a.b`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gen := generateJWTAuthorization(singleClaimPolicy(conf_v1.JWTClaim{Name: "c", Match: matchType(tc.match), Values: []string{tc.value}}), "default", "p", owner)

			for _, p := range gen.Maps[0].Parameters {
				if !strings.HasPrefix(p.Value, `"~`) {
					continue
				}
				inner := p.Value[1 : len(p.Value)-1]
				if strings.HasSuffix(p.Value, `\"`) && !strings.HasSuffix(p.Value, `\\"`) {
					t.Errorf("key %s ends in an escaped closing quote, so the token would not terminate", p.Value)
				}
				if unescapedQuote(inner) {
					t.Errorf("key %s contains an unescaped quote, which would end the NGINX token early", p.Value)
				}
			}

			if !allowed(t, gen, map[string]string{claimVar: tc.literal}) {
				t.Errorf("claim value %q must match %s, after NGINX unescaping", tc.literal, tc.value)
			}
			if allowed(t, gen, map[string]string{claimVar: "other"}) {
				t.Errorf("claim value %q must not match", "other")
			}
		})
	}
}

func unescapedQuote(s string) bool {
	backslashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			backslashes++
			continue
		case '"':
			if backslashes%2 == 0 {
				return true
			}
		}
		backslashes = 0
	}
	return false
}

func TestGenerateJWTClaimPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		match  conf_v1.JWTClaimMatchType
		values []string
		want   []string
	}{
		{"Exact ends with \\z, not $", conf_v1.JWTClaimMatchExact, []string{"admin", "root"}, []string{`^(admin|root)\z`}},
		{"Exact escapes metacharacters", conf_v1.JWTClaimMatchExact, []string{"a.b", "c+d"}, []string{`^(a\.b|c\+d)\z`}},
		{"Contains closing group is ([ ,]|\\z)", conf_v1.JWTClaimMatchContains, []string{"a", "b"}, []string{`(^|[ ,])(a|b)([ ,]|\z)`}},
		{"Contains escapes metacharacters", conf_v1.JWTClaimMatchContains, []string{"orders:read", "a.b"}, []string{`(^|[ ,])(orders:read|a\.b)([ ,]|\z)`}},
		{"Regex is used as written, one pattern per value", conf_v1.JWTClaimMatchRegex, []string{`^a.c$`, `^[^@]+@example\.com$`}, []string{`^a.c$`, `^[^@]+@example\.com$`}},
		{"duplicate values are removed", conf_v1.JWTClaimMatchExact, []string{"a", "b", "a"}, []string{`^(a|b)\z`}},
		{"duplicate Regex values are removed", conf_v1.JWTClaimMatchRegex, []string{`^a$`, `^a$`}, []string{`^a$`}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, generateJWTClaimPatterns(tc.match, tc.values)); diff != "" {
				t.Errorf("generateJWTClaimPatterns() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestQuoteJWTMapRegexKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		want    string
	}{
		{`^(admin)\z`, `"~^(admin)\\z"`}, // each backslash is doubled
		{`^a"b$`, `"~^a\"b$"`},           // a quote is escaped
		{`^a\"b$`, `"~^a\\\"b$"`},        // both
		{`(^|[ ,])(a)([ ,]|\z)`, `"~(^|[ ,])(a)([ ,]|\\z)"`},
	}

	for _, tc := range tests {
		got := quoteJWTMapRegexKey(tc.pattern)
		if got != tc.want {
			t.Errorf("quoteJWTMapRegexKey(%q) = %s, want %s", tc.pattern, got, tc.want)
		}
		if !strings.HasPrefix(got, `"~`) {
			t.Errorf("key %s must start with \"~", got)
		}
		if round := strings.TrimPrefix(internalValidation.UnescapeNGINXToken(got[1:len(got)-1]), "~"); round != tc.pattern {
			t.Errorf("round trip of %q gave %q", tc.pattern, round)
		}
	}
}

func TestGenerateJWTAuthzNone(t *testing.T) {
	t.Parallel()

	variable := generateJWTAuthzNoneVariable("my-ns", "cafe.example")
	if variable != "$jwt_authz_none_my_ns_cafe_example" {
		t.Errorf("generateJWTAuthzNoneVariable() = %q", variable)
	}
	if other := generateJWTAuthzNoneVariable("my-ns", "tea"); other == variable {
		t.Error("two VirtualServers must not share the reset variable: duplicate map variables fail nginx -t")
	}

	m := generateJWTAuthzNoneMap(variable)
	want := version2.Map{
		Source:     "$uri",
		Variable:   variable,
		Parameters: []version2.Parameter{{Value: "default", Result: "1"}},
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("generateJWTAuthzNoneMap() mismatch (-want +got):\n%s", diff)
	}
}

func registrySet(claim, variable string) version2.AuthJWTClaimSet {
	return version2.AuthJWTClaimSet{Variable: variable, Claim: claim}
}

func registryAuthz(r jwtClaimRegistry, sets ...version2.AuthJWTClaimSet) string {
	return r.claimAuthorization(sets)
}

func TestJWTClaimRegistry_AuthorizationConflicts(t *testing.T) {
	t.Parallel()

	set, authz := registrySet, registryAuthz

	t.Run("authorization: same claim twice is fine", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		if c := authz(r, set("a b", "$jwt_x_a_b")); c != "" {
			t.Fatal(c)
		}
		if c := authz(r, set("a b", "$jwt_x_a_b")); c != "" {
			t.Errorf("the same claim registered twice must not conflict: %s", c)
		}
	})

	t.Run("authorization: different claim, same variable is rejected", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("a b", "$jwt_x_a_b"))
		c := authz(r, set("a_b", "$jwt_x_a_b"))
		if c == "" || !strings.Contains(c, `"a_b"`) || !strings.Contains(c, `"a b"`) {
			t.Errorf("want a conflict naming both claims, got %q", c)
		}
	})

	t.Run("authorization: variable names are compared case-insensitively", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("Role", "$jwt_x_Role"))
		if c := authz(r, set("role", "$jwt_x_role")); c == "" {
			t.Error("Role and role map to one NGINX variable and must conflict")
		}
	})

	t.Run("authorization: conflict within one policy", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		if c := authz(r, set("a.b", "$jwt_x_a_b"), set("a-b", "$jwt_x_a_b")); c == "" {
			t.Error("two claims of one policy that share a variable must conflict")
		}
	})
}

func TestJWTClaimRegistry_AuthorizationAndRateLimit(t *testing.T) {
	t.Parallel()

	set, authz := registrySet, registryAuthz

	t.Run("authorization: a rejected policy leaves nothing behind", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("a b", "$jwt_x_a_b"))

		if c := authz(r, set("other", "$jwt_x_other"), set("a_b", "$jwt_x_a_b")); c == "" {
			t.Fatal("expected a conflict")
		}
		if c := authz(r, set("other2", "$jwt_x_other")); c != "" {
			t.Errorf("a claim of a rejected policy blocked a later policy: %s", c)
		}
	})

	t.Run("authorization is rejected when a rate limit owns the variable", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		if c := r.claimRateLimit(set("a b", "$jwt_x_a_b")); c != "" {
			t.Fatal(c)
		}
		if c := authz(r, set("a_b", "$jwt_x_a_b")); c == "" {
			t.Error("an authorization claim must not be allowed to collide with an earlier rate limit claim")
		}
	})

	t.Run("authorization on the claim a rate limit already uses takes ownership", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		r.claimRateLimit(set("a b", "$jwt_x_a_b"))
		if c := authz(r, set("a b", "$jwt_x_a_b")); c != "" {
			t.Fatalf("the same claim path is not a collision: %s", c)
		}
		if c := r.claimRateLimit(set("a_b", "$jwt_x_a_b")); c == "" {
			t.Error("a rate limit colliding with an authorization claim must be reported")
		}
	})
}

func TestJWTClaimRegistry_RateLimit(t *testing.T) {
	t.Parallel()

	set, authz := registrySet, registryAuthz

	t.Run("rate limit: never reports a collision with another rate limit", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		r.claimRateLimit(set("a b", "$jwt_x_a_b"))
		if c := r.claimRateLimit(set("a_b", "$jwt_x_a_b")); c != "" {
			t.Errorf("two rate limits that collide keep their old behavior, nothing is reported: %s", c)
		}
		if r["$jwt_x_a_b"].claim != "a b" {
			t.Errorf("the first rate limit claim must stay the owner, got %+v", r["$jwt_x_a_b"])
		}
	})

	t.Run("rate limit: reports a collision with an authorization claim, with both claims named", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("a b", "$jwt_x_a_b"))
		c := r.claimRateLimit(set("a_b", "$jwt_x_a_b"))
		if !strings.Contains(c, `"a_b"`) || !strings.Contains(c, `"a b"`) || !strings.Contains(c, "authorization") {
			t.Errorf("want both claims and the word authorization, got %q", c)
		}
		if r["$jwt_x_a_b"].claim != "a b" || !r["$jwt_x_a_b"].authorization {
			t.Errorf("the authorization claim must stay the owner, got %+v", r["$jwt_x_a_b"])
		}
	})

	t.Run("rate limit: the same claim as an authorization claim is fine", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("a b", "$jwt_x_a_b"))
		if c := r.claimRateLimit(set("a b", "$jwt_x_a_b")); c != "" {
			t.Errorf("the same claim path is not a collision: %s", c)
		}
	})

	t.Run("rate limit: variable names are compared case-insensitively", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("Role", "$jwt_x_Role"))
		if c := r.claimRateLimit(set("role", "$jwt_x_role")); c == "" {
			t.Error("Role and role map to one NGINX variable and must be reported")
		}
	})

	t.Run("rate limit: case-insensitive the other way round, a capitalised rate limit claim after a lower-case authorization claim", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("role", "$jwt_x_role"))
		if c := r.claimRateLimit(set("Role", "$jwt_x_Role")); c == "" {
			t.Error("role and Role map to one NGINX variable and must be reported, whichever spelling registered first")
		}
	})
}

func TestJWTClaimRegistry_NilAndFork(t *testing.T) {
	t.Parallel()

	set, authz := registrySet, registryAuthz

	t.Run("nil registry accepts everything", func(t *testing.T) {
		t.Parallel()
		var r jwtClaimRegistry
		if c := authz(r, set("a b", "$x"), set("a_b", "$x")); c != "" {
			t.Errorf("nil registry must not reject: %s", c)
		}
		if c := r.claimRateLimit(set("a b", "$x")); c != "" {
			t.Errorf("nil registry must not report: %s", c)
		}
		if r.fork() != nil {
			t.Error("a nil registry forks to nil")
		}
		r.merge(jwtClaimRegistry{"$x": {claim: "a"}}) // must not panic
	})

	t.Run("fork is isolated until it is merged", func(t *testing.T) {
		t.Parallel()
		r := jwtClaimRegistry{}
		authz(r, set("a b", "$jwt_x_a_b"))

		forked := r.fork()
		authz(forked, set("other", "$jwt_x_other"))
		if _, ok := r["$jwt_x_other"]; ok {
			t.Fatal("registering into a fork must not change the original")
		}

		r.merge(forked)
		if got := r["$jwt_x_other"]; got.claim != "other" || !got.authorization {
			t.Errorf("merge must copy the fork's entries back, got %+v", got)
		}
		if got := r["$jwt_x_a_b"]; got.claim != "a b" {
			t.Errorf("merge must keep the existing entries, got %+v", got)
		}
	})
}

func TestJWTRequireResetNeeded(t *testing.T) {
	t.Parallel()

	serverWithAuthz := &version2.JWTAuth{Realm: "s", RequireVariable: "$authz"}
	serverWithoutAuthz := &version2.JWTAuth{Realm: "s"}

	tests := []struct {
		name     string
		location version2.Location
		server   *version2.JWTAuth
		want     bool
	}{
		{"no server JWT policy", version2.Location{JWTAuth: &version2.JWTAuth{Realm: "r"}}, nil, false},
		{"server JWT policy without authorization", version2.Location{JWTAuth: &version2.JWTAuth{Realm: "r"}}, serverWithoutAuthz, false},
		{"location has no JWT of its own, inherits the server's", version2.Location{}, serverWithAuthz, false},
		{"route JWT policy without authorization overrides the server's", version2.Location{JWTAuth: &version2.JWTAuth{Realm: "r"}}, serverWithAuthz, true},
		{"route JWT policy with its own authorization", version2.Location{JWTAuth: &version2.JWTAuth{Realm: "r", RequireVariable: "$route"}}, serverWithAuthz, false},
		{"legacy OIDC location", version2.Location{OIDC: true}, serverWithAuthz, true},
		{"OIDC location that also has its own requirement", version2.Location{OIDC: true, JWTAuth: &version2.JWTAuth{RequireVariable: "$r"}}, serverWithAuthz, false},
		{"ACME challenge location runs auth_jwt off", version2.Location{ACMEChallenge: true, JWTAuth: &version2.JWTAuth{Realm: "r"}}, serverWithAuthz, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := jwtRequireResetNeeded(tc.location, tc.server); got != tc.want {
				t.Errorf("jwtRequireResetNeeded() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAddJWTRequireReset(t *testing.T) {
	t.Parallel()

	server := &version2.JWTAuth{RequireVariable: "$authz"}
	locations := []version2.Location{
		{Path: "/inherits"},
		{Path: "/own-auth", JWTAuth: &version2.JWTAuth{Realm: "r"}},
		{Path: "/own-authz", JWTAuth: &version2.JWTAuth{Realm: "r", RequireVariable: "$route"}},
		{Path: "/acme", ACMEChallenge: true},
	}

	if !addJWTRequireReset(locations, server, "$none") {
		t.Fatal("addJWTRequireReset() = false, want true")
	}
	got := map[string]string{}
	for _, l := range locations {
		got[l.Path] = l.JWTRequireReset
	}
	want := map[string]string{"/inherits": "", "/own-auth": "$none", "/own-authz": "", "/acme": ""}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("JWTRequireReset mismatch (-want +got):\n%s", diff)
	}

	if addJWTRequireReset([]version2.Location{{Path: "/x"}}, server, "$none") {
		t.Error("addJWTRequireReset() = true when no location needs a reset, the none map must not be emitted")
	}
	if addJWTRequireReset(locations, nil, "$none") {
		t.Error("addJWTRequireReset() = true without a server JWT policy")
	}
}

func TestGenerateProxySetHeaders_PolicyHeaderMerge(t *testing.T) {
	t.Parallel()

	routeSet := func(headers ...conf_v1.Header) *conf_v1.ActionProxy {
		return &conf_v1.ActionProxy{RequestHeaders: &conf_v1.ProxyRequestHeaders{Set: headers}}
	}
	policy := func(headers ...version2.Header) []version2.Header { return headers }

	tests := []struct {
		name          string
		proxy         *conf_v1.ActionProxy
		forwarded     bool
		policyHeaders []version2.Header
		want          []version2.Header
	}{
		{
			name:          "policy header and fallback Host",
			policyHeaders: policy(version2.Header{Name: "X-Token-Scope", Value: "$jwt_scope"}),
			want:          []version2.Header{{Name: "X-Token-Scope", Value: "$jwt_scope"}, {Name: "Host", Value: "$host"}},
		},
		{
			name:          "route requestHeaders win over the policy, compared case-insensitively",
			proxy:         routeSet(conf_v1.Header{Name: "x-token-scope", Value: "route"}),
			policyHeaders: policy(version2.Header{Name: "X-Token-Scope", Value: "$jwt_scope"}),
			want:          []version2.Header{{Name: "x-token-scope", Value: "route"}, {Name: "Host", Value: "$host"}},
		},
		{
			name:          "policy Host replaces the fallback Host when the route sets none",
			policyHeaders: policy(version2.Header{Name: "Host", Value: "$jwt_tenant"}),
			want:          []version2.Header{{Name: "Host", Value: "$jwt_tenant"}},
		},
		{
			name:          "policy Host is matched case-insensitively",
			policyHeaders: policy(version2.Header{Name: "HOST", Value: "$jwt_tenant"}),
			want:          []version2.Header{{Name: "HOST", Value: "$jwt_tenant"}},
		},
		{
			name:          "route Host wins over a policy Host",
			proxy:         routeSet(conf_v1.Header{Name: "Host", Value: "route.example.com"}),
			policyHeaders: policy(version2.Header{Name: "Host", Value: "$jwt_tenant"}),
			want:          []version2.Header{{Name: "Host", Value: "route.example.com"}},
		},
		{
			name: "policy X-Real-IP and X-Forwarded-For are in the list the template checks, so NIC defaults are skipped",
			policyHeaders: policy(
				version2.Header{Name: "X-Real-IP", Value: "$jwt_ip"},
				version2.Header{Name: "X-Forwarded-For", Value: "$jwt_fwd"},
			),
			want: []version2.Header{
				{Name: "X-Real-IP", Value: "$jwt_ip"},
				{Name: "X-Forwarded-For", Value: "$jwt_fwd"},
				{Name: "Host", Value: "$host"},
			},
		},
		{
			name:          "route X-Real-IP wins over a policy X-Real-IP, and it is emitted once",
			proxy:         routeSet(conf_v1.Header{Name: "X-Real-IP", Value: "route"}),
			policyHeaders: policy(version2.Header{Name: "X-Real-IP", Value: "$jwt_ip"}),
			want:          []version2.Header{{Name: "X-Real-IP", Value: "route"}, {Name: "Host", Value: "$host"}},
		},
		{
			name:          "fallback Host honors useForwardedHeaders",
			forwarded:     true,
			policyHeaders: policy(version2.Header{Name: "X-Token-Scope", Value: "$jwt_scope"}),
			want:          []version2.Header{{Name: "X-Token-Scope", Value: "$jwt_scope"}, {Name: "Host", Value: "$forwarded_host"}},
		},
		{
			name:          "route headers keep their order, policy headers follow",
			proxy:         routeSet(conf_v1.Header{Name: "A", Value: "1"}, conf_v1.Header{Name: "B", Value: "2"}),
			policyHeaders: policy(version2.Header{Name: "C", Value: "$c"}),
			want:          []version2.Header{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}, {Name: "C", Value: "$c"}, {Name: "Host", Value: "$host"}},
		},
		{
			name: "no policy headers is unchanged behavior",
			want: []version2.Header{{Name: "Host", Value: "$host"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := generateProxySetHeaders(tc.proxy, tc.forwarded, tc.policyHeaders)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("generateProxySetHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestJWTPolicyProxyHeaders(t *testing.T) {
	t.Parallel()

	withHeaders := func(name string) policiesCfg {
		return policiesCfg{JWTAuth: jwtAuth{Auth: &version2.JWTAuth{ProxySetHeaders: []version2.Header{{Name: name, Value: "$v"}}}}}
	}
	withoutHeaders := policiesCfg{JWTAuth: jwtAuth{Auth: &version2.JWTAuth{}}}

	tests := []struct {
		name        string
		route, spec policiesCfg
		want        []version2.Header
	}{
		{"route policy only", withHeaders("X-Route"), policiesCfg{}, []version2.Header{{Name: "X-Route", Value: "$v"}}},
		{"spec policy inherited when the route has none", policiesCfg{}, withHeaders("X-Spec"), []version2.Header{{Name: "X-Spec", Value: "$v"}}},
		{"route policy overrides the spec policy", withHeaders("X-Route"), withHeaders("X-Spec"), []version2.Header{{Name: "X-Route", Value: "$v"}}},
		{"route policy without headers does not inherit the spec headers", withoutHeaders, withHeaders("X-Spec"), nil},
		{"no JWT policy", policiesCfg{}, policiesCfg{}, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, jwtPolicyProxyHeaders(tc.route, tc.spec)); diff != "" {
				t.Errorf("jwtPolicyProxyHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// evalHeaderMap applies a sanitizing header map to a claim value the way NGINX does: the first
// matching regex wins, else the default. A result of "" is empty and any other result is a variable.
func evalHeaderMap(t *testing.T, m version2.Map, claimValue string) string {
	t.Helper()

	result, found := "", false
	for _, p := range m.Parameters {
		if !strings.HasPrefix(p.Value, `"~`) {
			continue
		}
		pattern := strings.TrimPrefix(internalValidation.UnescapeNGINXToken(strings.Trim(p.Value, `"`)), "~")
		re, err := regexp2.Compile(pattern)
		if err != nil {
			t.Fatalf("map %s: key %s does not compile: %v", m.Variable, p.Value, err)
		}
		matched, err := re.MatchString(claimValue)
		if err != nil {
			t.Fatalf("map %s: key %s: %v", m.Variable, p.Value, err)
		}
		if matched {
			result, found = p.Result, true
			break
		}
	}
	if !found {
		for _, p := range m.Parameters {
			if p.Value == "default" {
				result = p.Result
			}
		}
	}

	if result == `""` {
		return ""
	}
	if result != m.Source {
		t.Fatalf("map %s resolved to %q, want an empty string or the claim variable %s", m.Variable, result, m.Source)
	}
	return claimValue
}

func TestGenerateJWTAuthorization_ProxyHeaderMapDropsCRAndLF(t *testing.T) {
	t.Parallel()

	gen := generateJWTAuthorization(singleClaimPolicy(conf_v1.JWTClaim{Name: "iss", Values: []string{"a"}, ProxySetHeader: "X-Iss"}),
		"default", "p", jwtOwner("default", "cafe"))

	if len(gen.ProxySetHeaders) != 1 {
		t.Fatalf("ProxySetHeaders = %v, want one", gen.ProxySetHeaders)
	}
	var hdr *version2.Map
	for i := range gen.Maps {
		if gen.Maps[i].Variable == gen.ProxySetHeaders[0].Value {
			hdr = &gen.Maps[i]
		}
	}
	if hdr == nil {
		t.Fatalf("no map for header variable %s", gen.ProxySetHeaders[0].Value)
	}

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"clean value is forwarded", "https://idp.example.com", "https://idp.example.com"},
		{"CR is dropped", "v\rX-Foo: bar", ""},
		{"LF is dropped", "v\nX-Foo: bar", ""},
		{"CRLF is dropped", "v\r\nX-Foo: bar", ""},
		{"trailing LF is dropped", "v\n", ""},
		{"leading CR is dropped", "\rv", ""},
		{"a literal backslash-n is forwarded", `v\nbar`, `v\nbar`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := evalHeaderMap(t, *hdr, tc.value); got != tc.want {
				t.Errorf("header for %q = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
