package configs

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

const (
	jwtAuthzDefaultErrorCode = 403

	// Claim and rule maps return exactly one of these, which the "~^1+$" and "~1" rule maps rely on.
	jwtAuthzAllow = "1"
	jwtAuthzDeny  = "0"
)

type jwtAuthorization struct {
	ClaimSets       []version2.AuthJWTClaimSet
	Maps            []version2.Map
	RequireVariable string
	ErrorCode       int
	ProxySetHeaders []version2.Header
}

// The chain is always emitted in full, even for a single rule or claim.
func generateJWTAuthorization(authz *conf_v1.JWTAuthorization, polNamespace, polName string, owner policyOwnerDetails) jwtAuthorization {
	policyVar := generateJWTAuthzVariable(owner, polNamespace, polName)
	result := jwtAuthorization{
		RequireVariable: policyVar,
		ErrorCode:       generateIntFromPointer(authz.ErrorCode, jwtAuthzDefaultErrorCode),
	}

	ruleVars := make([]string, 0, len(authz.Rules))
	for i, rule := range authz.Rules {
		ruleVar := fmt.Sprintf("%s_r%d", policyVar, i)

		claimVars := make([]string, 0, len(rule.Claims))
		for j, claim := range rule.Claims {
			claimVar := fmt.Sprintf("%s_c%d", ruleVar, j)
			claimSet := version2.AuthJWTClaimSet{
				Variable: generateAuthJwtClaimSetVariable(claim.Name, owner),
				Claim:    generateAuthJwtClaimSetClaim(claim.Name),
			}

			result.ClaimSets = append(result.ClaimSets, claimSet)
			result.Maps = append(result.Maps, version2.Map{
				Source:     claimSet.Variable,
				Variable:   claimVar,
				Parameters: generateJWTClaimMapParameters(claim),
			})
			if claim.ProxySetHeader != "" {
				// Sanitize CR/LF before forwarding: a signed claim like "v\nX-Foo: bar" would
				// otherwise inject a second upstream header. The sanitizing map produces an empty
				// value (which proxy_set_header silently drops) on any CR or LF.
				hdrVar := claimVar + "_hdr"
				result.Maps = append(result.Maps, version2.Map{
					Source:   claimSet.Variable,
					Variable: hdrVar,
					Parameters: []version2.Parameter{
						{Value: `"~[\r\n]"`, Result: `""`},
						{Value: "default", Result: claimSet.Variable},
					},
				})
				result.ProxySetHeaders = append(result.ProxySetHeaders, version2.Header{
					Name:  claim.ProxySetHeader,
					Value: hdrVar,
				})
			}
			claimVars = append(claimVars, claimVar)
		}

		result.Maps = append(result.Maps, generateJWTRequireMap(claimVars, ruleVar, rule.Require, conf_v1.JWTRequireAny))
		ruleVars = append(ruleVars, ruleVar)
	}
	result.Maps = append(result.Maps, generateJWTRequireMap(ruleVars, policyVar, authz.Require, conf_v1.JWTRequireAll))

	return result
}

// The name includes the parent and the policy: without the parent, VirtualServers sharing a
// policy would emit duplicate maps, and without the policy, routes with different JWT policies would collide.
func generateJWTAuthzVariable(owner policyOwnerDetails, polNamespace, polName string) string {
	return "$" + jwtVariableSafe(fmt.Sprintf("jwt_authz_%s_%s_%s_%s_%s",
		owner.parentNamespace, owner.parentName, owner.parentType, polNamespace, polName))
}

func generateJWTAuthzNoneVariable(vsNamespace, vsName string) string {
	return "$" + jwtVariableSafe(fmt.Sprintf("jwt_authz_none_%s_%s", vsNamespace, vsName))
}

func generateJWTAuthzNoneMap(variable string) version2.Map {
	return version2.Map{
		Source:   "$uri",
		Variable: variable,
		Parameters: []version2.Parameter{
			{Value: "default", Result: jwtAuthzAllow},
		},
	}
}

// Resource names may contain '.', which would end an NGINX variable name.
func jwtVariableSafe(name string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(name)
}

func generateJWTRequireMap(sources []string, variable string, require *conf_v1.JWTRequireType, defaultRequire conf_v1.JWTRequireType) version2.Map {
	mode := defaultRequire
	if require != nil {
		mode = *require
	}

	pattern := `"~^1+$"`
	if mode == conf_v1.JWTRequireAny {
		pattern = `"~1"`
	}

	return version2.Map{
		Source:   strings.Join(sources, ""),
		Variable: variable,
		Parameters: []version2.Parameter{
			{Value: pattern, Result: jwtAuthzAllow},
			{Value: "default", Result: jwtAuthzDeny},
		},
	}
}

// The exact key "" is matched before any regular expression, so a value check never passes on a
// missing claim, negated or not. Only Present with negate accepts one.
//
// Values use a case-sensitive regex ("~") because quoted map string keys are case-insensitive.
func generateJWTClaimMapParameters(claim conf_v1.JWTClaim) []version2.Parameter {
	match := conf_v1.JWTClaimMatchExact
	if claim.Match != nil {
		match = *claim.Match
	}

	if match == conf_v1.JWTClaimMatchPresent {
		missing, present := jwtAuthzDeny, jwtAuthzAllow
		if claim.Negate {
			missing, present = present, missing
		}
		return []version2.Parameter{
			{Value: `""`, Result: missing},
			{Value: "default", Result: present},
		}
	}

	matched, unmatched := jwtAuthzAllow, jwtAuthzDeny
	if claim.Negate {
		matched, unmatched = unmatched, matched
	}

	params := []version2.Parameter{{Value: `""`, Result: jwtAuthzDeny}}
	for _, pattern := range generateJWTClaimPatterns(match, claim.Values) {
		params = append(params, version2.Parameter{Value: quoteJWTMapRegexKey(pattern), Result: matched})
	}
	return append(params, version2.Parameter{Value: "default", Result: unmatched})
}

// Anchors are \z, not $, because PCRE's $ also matches before a final newline, so "admin\n"
// would pass Exact: [admin]. Regex values are used as written. See quoteJWTMapRegexKey for the escaping.
func generateJWTClaimPatterns(match conf_v1.JWTClaimMatchType, values []string) []string {
	values = uniqueStrings(values)

	if match == conf_v1.JWTClaimMatchRegex {
		return values
	}

	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, regexp.QuoteMeta(v))
	}
	alternatives := strings.Join(quoted, "|")

	if match == conf_v1.JWTClaimMatchContains {
		// scope is space-delimited and auth_jwt_claim_set joins array elements with commas.
		return []string{`(^|[ ,])(` + alternatives + `)([ ,]|\z)`}
	}
	return []string{`^(` + alternatives + `)\z`}
}

// quoteJWTMapRegexKey escapes the finished pattern for the NGINX token. The "~" goes inside the
// quotes, and QuoteMeta does not escape '"', so this step is what stops a value like a" b ending the key.
func quoteJWTMapRegexKey(pattern string) string {
	return `"` + escapeNginxString("~"+pattern) + `"`
}

// uniqueStrings drops repeats because a map rejects the same exact key twice.
func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

type jwtClaimOwner struct {
	claim         string
	authorization bool
}

// jwtClaimRegistry records which claim path owns each claim variable of one VirtualServer.
//
// '.' and '-' both map to '_' and NGINX variable names are case-insensitive, so different paths
// (a.b, a_b, Role, role) can share a variable, and de-duplication keeps only the first. On a collision:
//   - an authorization policy is rejected, since reading another claim would bypass its check;
//   - a rate limit colliding with another rate limit is unchanged: accepted and silent;
//   - a rate limit colliding with an authorization claim is accepted with a warning.
type jwtClaimRegistry map[string]jwtClaimOwner

// fork returns a copy to register into. Merge it back only if generation succeeds: a failed call
// renders none of its claims, so they must not make a later policy collide.
func (r jwtClaimRegistry) fork() jwtClaimRegistry {
	if r == nil {
		return nil
	}
	forked := make(jwtClaimRegistry, len(r))
	for k, v := range r {
		forked[k] = v
	}
	return forked
}

func (r jwtClaimRegistry) merge(forked jwtClaimRegistry) {
	if r == nil {
		return
	}
	for k, v := range forked {
		r[k] = v
	}
}

// claimAuthorization registers nothing and returns the conflict if any claim is already owned by a
// different path, so a rejected policy leaves nothing behind.
func (r jwtClaimRegistry) claimAuthorization(sets []version2.AuthJWTClaimSet) string {
	if r == nil {
		return ""
	}

	pending := make(map[string]string, len(sets))
	for _, set := range sets {
		key := strings.ToLower(set.Variable)
		owner, found := r[key]
		claim := owner.claim
		if !found {
			claim, found = pending[key]
		}
		if found && claim != set.Claim {
			return fmt.Sprintf("claim %q resolves to the same NGINX variable %s as claim %q", set.Claim, set.Variable, claim)
		}
		pending[key] = set.Claim
	}

	for key, claim := range pending {
		r[key] = jwtClaimOwner{claim: claim, authorization: true}
	}
	return ""
}

// claimRateLimit never rejects. It reports only a collision with an authorization claim.
func (r jwtClaimRegistry) claimRateLimit(set version2.AuthJWTClaimSet) string {
	if r == nil {
		return ""
	}

	key := strings.ToLower(set.Variable)
	owner, found := r[key]
	if !found {
		r[key] = jwtClaimOwner{claim: set.Claim}
		return ""
	}
	if owner.claim == set.Claim || !owner.authorization {
		return ""
	}
	return fmt.Sprintf("claim %q resolves to the same NGINX variable %s as claim %q, which a JWT authorization policy uses", set.Claim, set.Variable, owner.claim)
}

// jwtRequireResetNeeded reports whether a location runs its own JWT handling under a server policy
// that requires claims. auth_jwt_require is inherited and has no "off", so it must be reset.
func jwtRequireResetNeeded(location version2.Location, serverAuth *version2.JWTAuth) bool {
	if serverAuth == nil || serverAuth.RequireVariable == "" || location.ACMEChallenge {
		return false
	}
	if location.JWTAuth != nil && location.JWTAuth.RequireVariable != "" {
		return false // the location sets its own requirement
	}
	return location.JWTAuth != nil || location.OIDC
}

func addJWTRequireReset(locations []version2.Location, serverAuth *version2.JWTAuth, resetVariable string) bool {
	needed := false
	for i := range locations {
		if jwtRequireResetNeeded(locations[i], serverAuth) {
			locations[i].JWTRequireReset = resetVariable
			needed = true
		}
	}
	return needed
}

// jwtPolicyProxyHeaders returns the headers a location sends for JWT authorization claims.
//
// A forwarded claim must come from a token the policy checked. auth_jwt is inherited, so a route
// without its own JWT policy sends the spec's headers. Where the spec's checks do not run (the route has
// its own JWT policy, or legacy OIDC, which validates the ID token instead), the spec's headers are
// kept with an empty value: proxy_set_header then drops any copy the client sent, and an
// unchecked claim cannot reach the backend.
//
// A header NIC sets itself is not blanked: an empty entry would suppress NIC's default (see
// jwtNICDefaultHeader) and the backend would lose it.
func jwtPolicyProxyHeaders(route, spec policiesCfg, disableForwardedHeaders bool) []version2.Header {
	if route.JWTAuth.Auth == nil && route.OIDC == nil {
		if spec.JWTAuth.Auth != nil {
			return spec.JWTAuth.Auth.ProxySetHeaders
		}
		return nil
	}

	var headers []version2.Header
	if route.JWTAuth.Auth != nil {
		headers = append(headers, route.JWTAuth.Auth.ProxySetHeaders...)
	}
	if spec.JWTAuth.Auth != nil {
		// A name the route also sets is dropped later: the first header of a name wins.
		for _, h := range spec.JWTAuth.Auth.ProxySetHeaders {
			if jwtNICDefaultHeader(h.Name, disableForwardedHeaders) {
				continue
			}
			headers = append(headers, version2.Header{Name: h.Name, Value: ""})
		}
	}
	return headers
}

// jwtNICDefaultHeader reports whether NIC sets the header itself on a proxied location: Host and
// X-Real-IP always, and the X-Forwarded-* headers unless forwarded headers are disabled. Keep in step
// with the default headers in nginx-plus.virtualserver.tmpl and generateProxySetHeaders.
func jwtNICDefaultHeader(name string, disableForwardedHeaders bool) bool {
	switch strings.ToLower(name) {
	case "host", "x-real-ip":
		return true
	case "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto":
		return !disableForwardedHeaders
	}
	return false
}
