package validation

import (
	"strings"
	"testing"

	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func jwtMatch(m v1.JWTClaimMatchType) *v1.JWTClaimMatchType { return &m }

func jwtRequire(r v1.JWTRequireType) *v1.JWTRequireType { return &r }

func jwtErrorCode(c int) *int { return &c }

// jwtWithClaims returns a valid JWT policy whose single rule holds the given claims.
func jwtWithClaims(claims ...v1.JWTClaim) *v1.JWTAuth {
	return &v1.JWTAuth{
		Realm:  "My Product API",
		Secret: "my-jwk",
		Authorization: &v1.JWTAuthorization{
			Rules: []v1.JWTAuthorizationRule{{Claims: claims}},
		},
	}
}

func TestValidateJWTAuthorization_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jwt  *v1.JWTAuth
	}{
		{
			name: "exact by default",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "iss", Values: []string{"https://login.example.com"}}),
		},
		{
			name: "contains with array and scope claims",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "aud", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{"orders-api"}},
				v1.JWTClaim{Name: "scope", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{"orders:read", "orders:write"}, ProxySetHeader: "X-Token-Scope"},
			),
		},
		{
			name: "nested claim with negate",
			jwt: jwtWithClaims(v1.JWTClaim{
				Name: "realm_access.roles", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{"guest"}, Negate: true,
			}),
		},
		{
			name: "256 multibyte characters in value",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "iss", Values: []string{strings.Repeat("é", 256)}}),
		},
		{
			name: "256 three-byte characters in value",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "iss", Values: []string{strings.Repeat("日", 256)}}),
		},
		{
			name: "present without values",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchPresent)}),
		},
		{
			name: "present negated, claim must be absent",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "act", Match: jwtMatch(v1.JWTClaimMatchPresent), Negate: true}),
		},
		{
			name: "present with proxySetHeader",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchPresent), ProxySetHeader: "X-Email"}),
		},
		{
			name: "claim name with dash and nesting",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "user-details.level", Values: []string{"Premium"}}),
		},
		{
			name: "same name twice with different match and negate",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "role", Values: []string{"guest"}, Negate: true},
				v1.JWTClaim{Name: "role", Match: jwtMatch(v1.JWTClaimMatchPresent), Negate: true},
			),
		},
		{
			name: "exact value with double quote and backslash, escaped at generation",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "name", Values: []string{`a" b`, `back\slash`}}),
		},
		{
			name: "contains value with double quote and backslash",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "name", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{`a"b`, `back\slash`}}),
		},
		{
			name: "regex with quote and backslash",
			jwt:  jwtWithClaims(v1.JWTClaim{Name: "name", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`^a"b\\c$`}}),
		},
		{
			name: "error code 401, any at both levels",
			jwt: &v1.JWTAuth{
				Realm:  "My Product API",
				Secret: "my-jwk",
				Authorization: &v1.JWTAuthorization{
					ErrorCode: jwtErrorCode(401),
					Require:   jwtRequire(v1.JWTRequireAny),
					Rules: []v1.JWTAuthorizationRule{
						{Require: jwtRequire(v1.JWTRequireAll), Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}},
						{Require: jwtRequire(v1.JWTRequireAny), Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"b"}}}},
					},
				},
			},
		},
		{
			name: "error code 403",
			jwt: &v1.JWTAuth{
				Realm:  "My Product API",
				Secret: "my-jwk",
				Authorization: &v1.JWTAuthorization{
					ErrorCode: jwtErrorCode(403),
					Rules:     []v1.JWTAuthorizationRule{{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}},
				},
			},
		},
		{
			name: "authorization with jwksURI",
			jwt: &v1.JWTAuth{
				Realm:    "My Product API",
				JwksURI:  "https://idp.com/token",
				KeyCache: "1h",
				Authorization: &v1.JWTAuthorization{
					Rules: []v1.JWTAuthorizationRule{{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if allErrs := validateJWT(tc.jwt, field.NewPath("jwt")); len(allErrs) != 0 {
				t.Errorf("validateJWT() returned errors %v for valid input", allErrs)
			}
		})
	}
}

func TestValidateJWTAuthorization_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	tooManyValues := make([]string, 65)
	for i := range tooManyValues {
		tooManyValues[i] = "v" + strings.Repeat("x", i%5)
	}
	tooManyClaims := make([]v1.JWTClaim, 33)
	for i := range tooManyClaims {
		tooManyClaims[i] = v1.JWTClaim{Name: "c" + strings.Repeat("x", i), Values: []string{"a"}}
	}
	tooManyRules := make([]v1.JWTAuthorizationRule, 17)
	for i := range tooManyRules {
		tooManyRules[i] = v1.JWTAuthorizationRule{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}
	}
	badRequire := v1.JWTRequireType("Some")

	tests := []struct {
		name    string
		jwt     *v1.JWTAuth
		wantErr string
	}{
		{
			name:    "error code 404",
			jwt:     &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{ErrorCode: jwtErrorCode(404), Rules: []v1.JWTAuthorizationRule{{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}}}},
			wantErr: "errorCode",
		},
		{
			name:    "invalid top-level require",
			jwt:     &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{Require: &badRequire, Rules: []v1.JWTAuthorizationRule{{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}}}},
			wantErr: "authorization.require",
		},
		{
			name:    "invalid rule require",
			jwt:     &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{Rules: []v1.JWTAuthorizationRule{{Require: &badRequire, Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}}}},
			wantErr: "rules[0].require",
		},
		{
			name:    "no rules",
			jwt:     &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{}},
			wantErr: "rules",
		},
		{
			name:    "too many rules",
			jwt:     &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{Rules: tooManyRules}},
			wantErr: "rules",
		},
		{
			name:    "rule without claims",
			jwt:     &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{Rules: []v1.JWTAuthorizationRule{{}}}},
			wantErr: "claims",
		},
		{
			name:    "too many claims",
			jwt:     jwtWithClaims(tooManyClaims...),
			wantErr: "claims",
		},
		{
			name:    "too many values",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "iss", Values: tooManyValues}),
			wantErr: "values",
		},
		{
			name:    "values missing for exact",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud"}),
			wantErr: "values",
		},
		{
			name:    "values missing for contains",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Match: jwtMatch(v1.JWTClaimMatchContains)}),
			wantErr: "values",
		},
		{
			name:    "values forbidden with present",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchPresent), Values: []string{"x"}}),
			wantErr: "values",
		},
		{
			name:    "explicit empty values forbidden with present",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchPresent), Values: []string{}}),
			wantErr: "values",
		},
		{
			name:    "empty value",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{""}}),
			wantErr: "values[0]",
		},
		{
			name:    "value too long",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{strings.Repeat("a", 257)}}),
			wantErr: "values[0]",
		},
		{
			name:    "value too long in multibyte characters",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{strings.Repeat("é", 257)}}),
			wantErr: "values[0]",
		},
		{
			name:    "unknown match type",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Match: jwtMatch("Prefix"), Values: []string{"a"}}),
			wantErr: "match",
		},
		{
			name:    "proxySetHeader with present and negate",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "debug", Match: jwtMatch(v1.JWTClaimMatchPresent), Negate: true, ProxySetHeader: "X-D"}),
			wantErr: "proxySetHeader",
		},
		{
			name:    "proxySetHeader with invalid characters",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{"a"}, ProxySetHeader: "X Bad;"}),
			wantErr: "proxySetHeader",
		},
		{
			name:    "proxySetHeader too long",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{"a"}, ProxySetHeader: strings.Repeat("a", 254)}),
			wantErr: "proxySetHeader",
		},
		{
			name: "duplicate proxySetHeader across claims, compared case-insensitively",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "aud", Values: []string{"a"}, ProxySetHeader: "X-Claim"},
				v1.JWTClaim{Name: "iss", Values: []string{"a"}, ProxySetHeader: "x-claim"},
			),
			wantErr: "proxySetHeader",
		},
		{
			name: "duplicate proxySetHeader across rules",
			jwt: &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{Rules: []v1.JWTAuthorizationRule{
				{Claims: []v1.JWTClaim{{Name: "aud", Values: []string{"a"}, ProxySetHeader: "X-Claim"}}},
				{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}, ProxySetHeader: "X-Claim"}}},
			}}},
			wantErr: "proxySetHeader",
		},
		{
			name: "duplicate name, match and negate within a rule",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "aud", Values: []string{"a"}},
				v1.JWTClaim{Name: "aud", Values: []string{"b"}},
			),
			wantErr: "Duplicate",
		},
		{
			name: "duplicate when match is spelled out and defaulted",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "aud", Values: []string{"a"}},
				v1.JWTClaim{Name: "aud", Match: jwtMatch(v1.JWTClaimMatchExact), Values: []string{"b"}},
			),
			wantErr: "Duplicate",
		},
		{
			name: "claims Role and role collide on one NGINX variable",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "Role", Values: []string{"a"}},
				v1.JWTClaim{Name: "role", Values: []string{"b"}},
			),
			wantErr: "same NGINX variable",
		},
		{
			name: "claims a.b and a_b collide on one NGINX variable",
			jwt: jwtWithClaims(
				v1.JWTClaim{Name: "a.b", Values: []string{"a"}},
				v1.JWTClaim{Name: "a_b", Values: []string{"b"}},
			),
			wantErr: "same NGINX variable",
		},
		{
			name: "claims a-b and a_b collide across rules",
			jwt: &v1.JWTAuth{Realm: "r", Secret: "s", Authorization: &v1.JWTAuthorization{Rules: []v1.JWTAuthorizationRule{
				{Claims: []v1.JWTClaim{{Name: "a-b", Values: []string{"a"}}}},
				{Claims: []v1.JWTClaim{{Name: "a_b", Values: []string{"a"}}}},
			}}},
			wantErr: "same NGINX variable",
		},
		{
			name:    "contains value with a space",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "scope", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{"read admin"}}),
			wantErr: "space or comma",
		},
		{
			name:    "contains value with a comma",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "scope", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{"read,admin"}}),
			wantErr: "space or comma",
		},
		{
			name:    "exact value with semicolon",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{"a;b"}}),
			wantErr: "must not contain any of the characters",
		},
		{
			name:    "exact value with dollar",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{"$host"}}),
			wantErr: "must not contain any of the characters",
		},
		{
			name:    "exact value with braces",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{"a{b}"}}),
			wantErr: "must not contain any of the characters",
		},
		{
			name:    "contains value with backtick",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Match: jwtMatch(v1.JWTClaimMatchContains), Values: []string{"a`b"}}),
			wantErr: "must not contain any of the characters",
		},
		{
			name:    "exact value with newline",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "aud", Values: []string{"a\nb"}}),
			wantErr: "non-printable",
		},
		{
			name:    "regex that does not compile",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{"([a-z"}}),
			wantErr: "valid regular expression",
		},
		{
			name:    "regex with newline",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{"a\nb"}}),
			wantErr: "non-printable",
		},
		{
			name:    "regex with backtick",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{"a`b"}}),
			wantErr: "backticks",
		},
		{
			name:    "regex with named capture (?<name>)",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`^(?<host>.*)$`}}),
			wantErr: "named captures",
		},
		{
			name:    "regex with named capture (?P<name>)",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`^(?P<host>.*)$`}}),
			wantErr: "named captures",
		},
		{
			name:    "regex with named capture (?'name')",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`^(?'host'.*)$`}}),
			wantErr: "named captures",
		},
		{
			name:    "regex with fixed-length lookbehind",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`(?<=a)b`}}),
			wantErr: "lookbehind",
		},
		{
			name:    "regex with negative lookbehind",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`(?<!a)b`}}),
			wantErr: "lookbehind",
		},
		{
			name:    "regex with variable-length lookbehind",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`(?<=a+)b`}}),
			wantErr: "lookbehind",
		},
		{
			name:    "regex with escaped (?< is refused like the CRD CEL rule",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`^\(?<n>x\)$`}}),
			wantErr: "named captures",
		},
		{
			name:    "regex with (?< inside a character class is refused like the CRD CEL rule",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{`^[(?<n>]x$`}}),
			wantErr: "named captures",
		},
		{
			name:    "claim name with empty segment",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "a..b", Values: []string{"a"}}),
			wantErr: "empty segments",
		},
		{
			name:    "claim name with leading dot",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: ".a", Values: []string{"a"}}),
			wantErr: "empty segments",
		},
		{
			name:    "claim name with trailing dot",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "a.", Values: []string{"a"}}),
			wantErr: "empty segments",
		},
		{
			name:    "claim name with slash, as used by Auth0 namespaced claims",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "https://example.com/roles", Values: []string{"a"}}),
			wantErr: "each segment",
		},
		{
			name:    "claim name with colon",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "a:b", Values: []string{"a"}}),
			wantErr: "each segment",
		},
		{
			name:    "claim name with dollar",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "a$b", Values: []string{"a"}}),
			wantErr: "'$'",
		},
		{
			name:    "claim name with space",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "a b", Values: []string{"a"}}),
			wantErr: "each segment",
		},
		{
			name:    "claim name with semicolon",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "a;b", Values: []string{"a"}}),
			wantErr: "each segment",
		},
		{
			name:    "empty claim name",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: "", Values: []string{"a"}}),
			wantErr: "name",
		},
		{
			name:    "claim name too long",
			jwt:     jwtWithClaims(v1.JWTClaim{Name: strings.Repeat("a", 254), Values: []string{"a"}}),
			wantErr: "name",
		},
		{
			name: "invalid authentication fields are still reported alongside authorization",
			jwt: &v1.JWTAuth{
				Realm: "My Product API",
				Authorization: &v1.JWTAuthorization{
					Rules: []v1.JWTAuthorizationRule{{Claims: []v1.JWTClaim{{Name: "iss", Values: []string{"a"}}}}},
				},
			},
			wantErr: "secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allErrs := validateJWT(tc.jwt, field.NewPath("jwt"))
			if len(allErrs) == 0 {
				t.Fatalf("validateJWT() returned no errors for invalid input")
			}
			if !strings.Contains(allErrs.ToAggregate().Error(), tc.wantErr) {
				t.Errorf("validateJWT() errors %q do not mention %q", allErrs.ToAggregate().Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateJWTAuthorization_AcceptsRegexesUsedInDocsAndExamples(t *testing.T) {
	t.Parallel()

	// Regex values from docs/developer/jwt-claim-validation-plan.md and examples/custom-resources.
	// They use '$', which ContainsDangerousChars rejects for literal matches.
	patterns := []string{
		`^[^@]+@example\.com$`,
		`^[^@]+@example\.com\z`,
		`^(Gold|Platinum)$`,
		`^[a-z0-9]{3,12}$`,
		`^(?:admin|root)$`,
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			jwt := jwtWithClaims(v1.JWTClaim{Name: "email", Match: jwtMatch(v1.JWTClaimMatchRegex), Values: []string{pattern}})
			if allErrs := validateJWT(jwt, field.NewPath("jwt")); len(allErrs) != 0 {
				t.Errorf("validateJWT() rejected regex %q: %v", pattern, allErrs)
			}
		})
	}
}

func TestValidateJWTClaimPath(t *testing.T) {
	t.Parallel()

	valid := []string{"sub", "aud", "realm_access.roles", "user-details.level", "a.b.c", "A1_b-2", "tenant.tier"}
	for _, path := range valid {
		if allErrs := validateJWTClaimPath(path, field.NewPath("name")); len(allErrs) != 0 {
			t.Errorf("validateJWTClaimPath(%q) returned errors %v", path, allErrs)
		}
	}

	invalid := []string{"", ".", "a..b", ".a", "a.", "a b", "a/b", "a:b", "a@b", "a$b", "a;b", "a{b", "a\"b", "a#b", "a\\b", "a\nb"}
	for _, path := range invalid {
		if allErrs := validateJWTClaimPath(path, field.NewPath("name")); len(allErrs) == 0 {
			t.Errorf("validateJWTClaimPath(%q) returned no errors for invalid input", path)
		}
	}
}

func TestValidatePolicy_JWTAuthorizationRequiresPlus(t *testing.T) {
	t.Parallel()

	policy := &v1.Policy{Spec: v1.PolicySpec{JWTAuth: jwtWithClaims(v1.JWTClaim{Name: "iss", Values: []string{"a"}})}}

	if err := ValidatePolicy(policy, PolicyValidationConfig{IsPlus: false}); err == nil {
		t.Error("ValidatePolicy() accepted a JWT policy with authorization on NGINX OSS")
	}
	if err := ValidatePolicy(policy, PolicyValidationConfig{IsPlus: true}); err != nil {
		t.Errorf("ValidatePolicy() rejected a valid JWT policy with authorization on NGINX Plus: %v", err)
	}
}
