package validation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/dlclark/regexp2/v2"
	validation2 "github.com/nginx/kubernetes-ingress/internal/validation"
	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	maxJWTAuthorizationRules  = 16
	maxJWTClaimsPerRule       = 32
	maxJWTClaimValues         = 32
	maxJWTClaimValueLength    = 256
	maxJWTClaimNameLength     = 253
	maxJWTProxySetHeaderLen   = 253
	jwtAuthorizationDefaultEC = 403
)

var (
	jwtClaimSegmentRegexp   = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	jwtProxySetHeaderRegexp = regexp.MustCompile(`^[-_A-Za-z0-9]+$`)
)

// validateJWTAuthorization validates the claim authorization rules of a JWT policy.
// The checks mirror the CEL rules on the CRD, so that clusters without CEL enforcement
// behave the same, and add the Go-only rules that CEL cannot express.
func validateJWTAuthorization(authz *v1.JWTAuthorization, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if authz.ErrorCode != nil && *authz.ErrorCode != 401 && *authz.ErrorCode != jwtAuthorizationDefaultEC {
		allErrs = append(allErrs, field.NotSupported(fieldPath.Child("errorCode"), *authz.ErrorCode, []string{"401", "403"}))
	}
	allErrs = append(allErrs, validateJWTRequire(authz.Require, fieldPath.Child("require"))...)

	rulesPath := fieldPath.Child("rules")
	switch {
	case len(authz.Rules) == 0:
		allErrs = append(allErrs, field.Required(rulesPath, "at least one rule must be set"))
	case len(authz.Rules) > maxJWTAuthorizationRules:
		allErrs = append(allErrs, field.TooMany(rulesPath, len(authz.Rules), maxJWTAuthorizationRules))
	}

	// State shared by all rules of the policy.
	seen := jwtAuthorizationSeen{
		variables: map[string]string{},
		headers:   map[string]struct{}{},
	}
	for i, rule := range authz.Rules {
		allErrs = append(allErrs, validateJWTAuthorizationRule(rule, rulesPath.Index(i), &seen)...)
	}

	return allErrs
}

// jwtAuthorizationSeen tracks what earlier rules of one policy already used.
type jwtAuthorizationSeen struct {
	// variables maps the NGINX variable a claim resolves to onto the claim path that first used it.
	variables map[string]string
	// headers holds the lower-cased proxySetHeader names in use.
	headers map[string]struct{}
}

// jwtClaimKey identifies a claim check within a rule.
type jwtClaimKey struct {
	name   string
	match  v1.JWTClaimMatchType
	negate bool
}

func validateJWTAuthorizationRule(rule v1.JWTAuthorizationRule, rulePath *field.Path, seen *jwtAuthorizationSeen) field.ErrorList {
	allErrs := validateJWTRequire(rule.Require, rulePath.Child("require"))

	claimsPath := rulePath.Child("claims")
	switch {
	case len(rule.Claims) == 0:
		allErrs = append(allErrs, field.Required(claimsPath, "at least one claim must be set"))
	case len(rule.Claims) > maxJWTClaimsPerRule:
		allErrs = append(allErrs, field.TooMany(claimsPath, len(rule.Claims), maxJWTClaimsPerRule))
	}

	inRule := map[jwtClaimKey]struct{}{}
	for j, claim := range rule.Claims {
		claimPath := claimsPath.Index(j)
		allErrs = append(allErrs, validateJWTClaim(claim, claimPath)...)

		key := jwtClaimKey{name: claim.Name, match: jwtClaimMatch(claim), negate: claim.Negate}
		if _, ok := inRule[key]; ok {
			allErrs = append(allErrs, field.Duplicate(claimPath, fmt.Sprintf("name %q with match %q and negate %v", key.name, key.match, key.negate)))
		}
		inRule[key] = struct{}{}

		allErrs = append(allErrs, seen.checkVariable(claim.Name, claimPath.Child("name"))...)
		allErrs = append(allErrs, seen.checkHeader(claim.ProxySetHeader, claimPath.Child("proxySetHeader"))...)
	}
	return allErrs
}

// checkVariable rejects a claim path that resolves to the same NGINX variable as a different, earlier claim path.
// NGINX variable names are case-insensitive and the generator maps '.' and '-' to '_', so distinct claim
// paths can share one variable. The second check would then silently read the first claim.
func (s *jwtAuthorizationSeen) checkVariable(name string, fieldPath *field.Path) field.ErrorList {
	if validateJWTClaimPath(name, fieldPath).ToAggregate() != nil {
		return nil // already reported as an invalid name
	}
	variable := jwtClaimVariableKey(name)
	existing, ok := s.variables[variable]
	if !ok {
		s.variables[variable] = name
		return nil
	}
	if existing == name {
		return nil
	}
	return field.ErrorList{field.Invalid(fieldPath, name,
		fmt.Sprintf("claim %q resolves to the same NGINX variable as claim %q", name, existing))}
}

// checkHeader rejects a proxySetHeader name that an earlier claim of the policy already uses.
func (s *jwtAuthorizationSeen) checkHeader(header string, fieldPath *field.Path) field.ErrorList {
	if header == "" {
		return nil
	}
	lower := strings.ToLower(header)
	if _, ok := s.headers[lower]; ok {
		return field.ErrorList{field.Duplicate(fieldPath, header)}
	}
	s.headers[lower] = struct{}{}
	return nil
}

func jwtClaimMatch(claim v1.JWTClaim) v1.JWTClaimMatchType {
	if claim.Match == nil {
		return v1.JWTClaimMatchExact
	}
	return *claim.Match
}

// jwtClaimVariableKey returns the case-folded variable suffix that a claim path produces.
// It must stay in step with the variable naming in internal/configs.
func jwtClaimVariableKey(claim string) string {
	return strings.ToLower(strings.NewReplacer(".", "_", "-", "_").Replace(claim))
}

func validateJWTRequire(require *v1.JWTRequireType, fieldPath *field.Path) field.ErrorList {
	if require == nil {
		return nil
	}
	if *require != v1.JWTRequireAny && *require != v1.JWTRequireAll {
		return field.ErrorList{field.NotSupported(fieldPath, *require, []string{string(v1.JWTRequireAny), string(v1.JWTRequireAll)})}
	}
	return nil
}

// validateJWTClaim validates a single claim check.
func validateJWTClaim(claim v1.JWTClaim, fieldPath *field.Path) field.ErrorList {
	allErrs := validateJWTClaimPath(claim.Name, fieldPath.Child("name"))

	match := jwtClaimMatch(claim)
	switch match {
	case v1.JWTClaimMatchExact, v1.JWTClaimMatchContains, v1.JWTClaimMatchRegex, v1.JWTClaimMatchPresent:
	default:
		return append(allErrs, field.NotSupported(fieldPath.Child("match"), match, []string{
			string(v1.JWTClaimMatchExact), string(v1.JWTClaimMatchContains), string(v1.JWTClaimMatchRegex), string(v1.JWTClaimMatchPresent),
		}))
	}

	valuesPath := fieldPath.Child("values")
	if match == v1.JWTClaimMatchPresent {
		if len(claim.Values) > 0 {
			allErrs = append(allErrs, field.Forbidden(valuesPath, "values must not be set when match is Present"))
		}
		if claim.Negate && claim.ProxySetHeader != "" {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("proxySetHeader"), "proxySetHeader cannot be set when match is Present and negate is true, there is no claim value to forward"))
		}
	} else {
		switch {
		case len(claim.Values) == 0:
			allErrs = append(allErrs, field.Required(valuesPath, "values must be set unless match is Present"))
		case len(claim.Values) > maxJWTClaimValues:
			allErrs = append(allErrs, field.TooMany(valuesPath, len(claim.Values), maxJWTClaimValues))
		}
		for k, value := range claim.Values {
			allErrs = append(allErrs, validateJWTClaimValue(value, match, valuesPath.Index(k))...)
		}
	}

	if claim.ProxySetHeader != "" {
		allErrs = append(allErrs, validateJWTProxySetHeader(claim.ProxySetHeader, fieldPath.Child("proxySetHeader"))...)
	}

	return allErrs
}

func validateJWTProxySetHeader(header string, fieldPath *field.Path) field.ErrorList {
	if len(header) > maxJWTProxySetHeaderLen {
		return field.ErrorList{field.TooLong(fieldPath, header, maxJWTProxySetHeaderLen)}
	}
	if !jwtProxySetHeaderRegexp.MatchString(header) {
		return field.ErrorList{field.Invalid(fieldPath, header, "must contain only letters, digits, '-' and '_'")}
	}
	return nil
}

// validateJWTClaimPath validates a claim name such as realm_access.roles. Nested claims are
// separated by '.', and every segment must be a single NGINX token that can be part of a variable name.
//
// It is shared by every feature that reads a JWT claim into an NGINX variable.
func validateJWTClaimPath(path string, fieldPath *field.Path) field.ErrorList {
	if path == "" {
		return field.ErrorList{field.Required(fieldPath, "claim name must not be empty")}
	}
	if len(path) > maxJWTClaimNameLength {
		return field.ErrorList{field.TooLong(fieldPath, path, maxJWTClaimNameLength)}
	}
	for _, segment := range strings.Split(path, ".") {
		if segment == "" {
			return field.ErrorList{field.Invalid(fieldPath, path, "must not contain empty segments, nested claims are separated by a single '.'")}
		}
		if strings.Contains(segment, "$") {
			return field.ErrorList{field.Invalid(fieldPath, path, "must not contain '$'")}
		}
		if !jwtClaimSegmentRegexp.MatchString(segment) {
			return field.ErrorList{field.Invalid(fieldPath, path, "each segment must contain only letters, digits, '-' and '_'")}
		}
		if err := validation2.ValidateDirectiveToken(segment); err != nil {
			return field.ErrorList{field.Invalid(fieldPath, path, err.Error())}
		}
	}
	return nil
}

// validateJWTClaimValue validates one entry of claims[].values for a value match type.
func validateJWTClaimValue(value string, match v1.JWTClaimMatchType, fieldPath *field.Path) field.ErrorList {
	if value == "" {
		return field.ErrorList{field.Invalid(fieldPath, value, "must not be empty, use match: Present to check that a claim exists")}
	}
	if len(value) > maxJWTClaimValueLength {
		return field.ErrorList{field.TooLong(fieldPath, value, maxJWTClaimValueLength)}
	}
	// The generator escapes quotes and backslashes in every value, but other control
	// characters have no defined meaning in a quoted NGINX token.
	for _, char := range value {
		if !unicode.IsPrint(char) {
			return field.ErrorList{field.Invalid(fieldPath, value, "must not include non-printable characters")}
		}
	}

	if match == v1.JWTClaimMatchRegex {
		return validateJWTClaimRegex(value, fieldPath)
	}

	// Exact and Contains values are matched literally, so they get the strict character check.
	if ContainsDangerousChars(value) {
		return field.ErrorList{field.Invalid(fieldPath, value, "must not contain any of the characters ; { } $ ` or line breaks")}
	}
	if match == v1.JWTClaimMatchContains && strings.ContainsAny(value, " ,") {
		return field.ErrorList{field.Invalid(fieldPath, value, "must not contain a space or comma when match is Contains, the claim is split on those characters")}
	}
	return nil
}

// validateJWTClaimRegex validates a PCRE pattern used as a claim value.
//
// Regex values are exempt from ContainsDangerousChars: patterns legitimately use '$', '{' and '}'
// (for example ^[^@]+@example\.com$), and NGINX never variable-expands a map key. The generator
// escapes the key for the NGINX token. The pattern is validated as written, without unescaping.
func validateJWTClaimRegex(pattern string, fieldPath *field.Path) field.ErrorList {
	if strings.ContainsAny(pattern, "\r\n`") {
		return field.ErrorList{field.Invalid(fieldPath, pattern, "must not include line breaks or backticks")}
	}
	// NGINX registers a named capture in a map regex as an HTTP variable, so (?<host>.*) would
	// collide with $host and fail to load. Numbered captures and non-capturing groups are fine.
	if hasNamedCapture(pattern) {
		return field.ErrorList{field.Invalid(fieldPath, pattern, "must not use named captures, use a numbered or non-capturing group instead")}
	}
	// regexp2 accepts variable-length lookbehind, but NGINX builds with PCRE2 older than 10.43 reject it
	// and fail to load the configuration, so lookbehind is refused outright.
	if hasLookbehind(pattern) {
		return field.ErrorList{field.Invalid(fieldPath, pattern, "must not use lookbehind ((?<= or (?<!), it is not supported by every PCRE2 version NGINX is built with")}
	}
	if _, err := regexp2.Compile(pattern); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, pattern, fmt.Sprintf("must be a valid regular expression: %v", err))}
	}
	return nil
}

// hasNamedCapture reports whether the pattern defines a named capture group, in any of the
// syntaxes (?<name>...), (?P<name>...) or (?'name'...). Escaped characters and character
// classes are skipped, and lookbehinds ((?<= and (?<!) are not named captures.
func hasNamedCapture(pattern string) bool {
	return hasGroup(pattern, opensNamedCapture)
}

// hasLookbehind reports whether the pattern contains a lookbehind, (?<= or (?<!. Escaped
// characters and character classes are skipped.
func hasLookbehind(pattern string) bool {
	return hasGroup(pattern, opensLookbehind)
}

// hasGroup reports whether opens is true for the text after any unescaped '(' outside a character class.
func hasGroup(pattern string, opens func(rest []rune) bool) bool {
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			i++ // skip the escaped character
		case '[':
			i = skipCharClass(runes, i)
		case '(':
			if opens(runes[i+1:]) {
				return true
			}
		}
	}
	return false
}

// skipCharClass returns the index of the ']' that closes the character class opened at runes[start].
// A ']' directly after '[' or '[^' is a literal. An unterminated class runs to the end of the pattern.
func skipCharClass(runes []rune, start int) int {
	i := start + 1
	if i < len(runes) && runes[i] == '^' {
		i++
	}
	if i < len(runes) && runes[i] == ']' {
		i++
	}
	for ; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			i++
		case ']':
			return i
		}
	}
	return len(runes)
}

// opensNamedCapture reports whether the text after a '(' starts a named capture group.
func opensNamedCapture(rest []rune) bool {
	if len(rest) < 2 || rest[0] != '?' {
		return false
	}
	switch rest[1] {
	case '\'':
		return true
	case 'P':
		return len(rest) > 2 && rest[2] == '<'
	case '<':
		// (?<= and (?<! are lookbehinds.
		return len(rest) > 2 && rest[2] != '=' && rest[2] != '!'
	}
	return false
}

// opensLookbehind reports whether the text after a '(' starts a lookbehind.
func opensLookbehind(rest []rune) bool {
	return len(rest) > 2 && rest[0] == '?' && rest[1] == '<' && (rest[2] == '=' || rest[2] == '!')
}
