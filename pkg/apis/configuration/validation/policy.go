package validation

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidatePolicy validates a Policy.
func ValidatePolicy(policy *v1.Policy, isPlus, enableOIDC, enableAppProtect bool) error {
	allErrs := validatePolicySpec(&policy.Spec, field.NewPath("spec"), isPlus, enableOIDC, enableAppProtect)
	return allErrs.ToAggregate()
}

func validatePolicySpec(spec *v1.PolicySpec, fieldPath *field.Path, isPlus, enableOIDC, enableAppProtect bool) field.ErrorList {
	allErrs := field.ErrorList{}

	fieldCount := 0

	if spec.AccessControl != nil {
		allErrs = append(allErrs, validateAccessControl(spec.AccessControl, fieldPath.Child("accessControl"))...)
		fieldCount++
	}

	if spec.RateLimit != nil {
		allErrs = append(allErrs, validateRateLimit(spec.RateLimit, fieldPath.Child("rateLimit"), isPlus)...)
		fieldCount++
	}

	if spec.JWTAuth != nil {
		if !isPlus {
			return append(allErrs, field.Forbidden(fieldPath.Child("jwt"), "jwt secrets are only supported in NGINX Plus"))
		}

		allErrs = append(allErrs, validateJWT(spec.JWTAuth, fieldPath.Child("jwt"))...)
		fieldCount++
	}

	if spec.BasicAuth != nil {
		fieldCount++
	}

	if spec.IngressMTLS != nil {
		allErrs = append(allErrs, validateIngressMTLS(spec.IngressMTLS, fieldPath.Child("ingressMTLS"))...)
		fieldCount++
	}

	if spec.EgressMTLS != nil {
		allErrs = append(allErrs, validateEgressMTLS(spec.EgressMTLS, fieldPath.Child("egressMTLS"))...)
		fieldCount++
	}

	if spec.OIDC != nil {
		if !enableOIDC {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("oidc"),
				"OIDC must be enabled via cli argument -enable-oidc to use OIDC policy"))
		}
		if !isPlus {
			return append(allErrs, field.Forbidden(fieldPath.Child("oidc"), "OIDC is only supported in NGINX Plus"))
		}

		allErrs = append(allErrs, validateOIDC(spec.OIDC, fieldPath.Child("oidc"))...)
		fieldCount++
	}

	if spec.APIKey != nil {
		allErrs = append(allErrs, validateAPIKey(spec.APIKey, fieldPath.Child("apiKey"))...)
		fieldCount++
	}

	if spec.WAF != nil {
		if !isPlus {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("waf"), "WAF is only supported in NGINX Plus"))
		}
		if !enableAppProtect {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("waf"),
				"App Protect must be enabled via cli argument -enable-app-protect to use WAF policy"))
		}

		allErrs = append(allErrs, validateWAF(spec.WAF, fieldPath.Child("waf"))...)
		fieldCount++
	}

	if fieldCount != 1 {
		msg := "must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`, `basicAuth`, `apiKey`"
		if isPlus {
			msg = fmt.Sprint(msg, ", `jwt`, `oidc`, `waf`")
		}
		allErrs = append(allErrs, field.Invalid(fieldPath, "", msg))
	}

	return allErrs
}

func validateAccessControl(accessControl *v1.AccessControl, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	fieldCount := 0

	if accessControl.Allow != nil {
		for i, ipOrCIDR := range accessControl.Allow {
			allErrs = append(allErrs, validateIPorCIDR(ipOrCIDR, fieldPath.Child("allow").Index(i))...)
		}
		fieldCount++
	}

	if accessControl.Deny != nil {
		for i, ipOrCIDR := range accessControl.Deny {
			allErrs = append(allErrs, validateIPorCIDR(ipOrCIDR, fieldPath.Child("deny").Index(i))...)
		}
		fieldCount++
	}

	if fieldCount != 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", "must specify exactly one of: `allow` or `deny`"))
	}

	return allErrs
}

func validateRateLimit(rateLimit *v1.RateLimit, fieldPath *field.Path, isPlus bool) field.ErrorList {
	allErrs := validateRateLimitZoneSize(rateLimit.ZoneSize, fieldPath.Child("zoneSize"))
	allErrs = append(allErrs, validateRate(rateLimit.Rate, fieldPath.Child("rate"))...)
	allErrs = append(allErrs, validateRateLimitKey(rateLimit.Key, fieldPath.Child("key"), isPlus)...)

	if rateLimit.Delay != nil {
		allErrs = append(allErrs, validatePositiveInt(*rateLimit.Delay, fieldPath.Child("delay"))...)
	}

	if rateLimit.Burst != nil {
		allErrs = append(allErrs, validatePositiveInt(*rateLimit.Burst, fieldPath.Child("burst"))...)
	}

	if rateLimit.LogLevel != "" {
		allErrs = append(allErrs, validateRateLimitLogLevel(rateLimit.LogLevel, fieldPath.Child("logLevel"))...)
	}

	if rateLimit.RejectCode != nil {
		if *rateLimit.RejectCode < 400 || *rateLimit.RejectCode > 599 {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("rejectCode"), rateLimit.RejectCode,
				"must be within the range [400-599]"))
		}
	}

	if rateLimit.Condition != nil && rateLimit.Condition.JWT == nil {
		allErrs = append(allErrs, field.Required(fieldPath.Child("jwt"), "jwt cannot be nil"))
	}

	if rateLimit.Condition != nil && rateLimit.Condition.JWT != nil && !isPlus {
		allErrs = append(allErrs, field.Forbidden(fieldPath.Child("condition.jwt"), "is only supported in NGINX Plus"))
	}

	return allErrs
}

// validateJWT validates JWT Policy according the rules specified in documentation
// for using [jwt] local k8s secrets and using [jwks] from remote location.
//
// [jwt]: https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#jwt-using-local-kubernetes-secret
// [jwks]: https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#jwt-using-jwks-from-remote-location
func validateJWT(jwt *v1.JWTAuth, fieldPath *field.Path) field.ErrorList {
	// Realm is always required.
	if jwt.Realm == "" {
		return field.ErrorList{field.Required(fieldPath.Child("realm"), "realm field must be present")}
	}
	allErrs := validateRealm(jwt.Realm, fieldPath.Child("realm"))

	// Use either JWT Secret or JWKS URI, they are mutually exclusive.
	if jwt.Secret == "" && jwt.JwksURI == "" {
		return append(allErrs, field.Required(fieldPath.Child("secret"), "either Secret or JwksURI must be present"))
	}
	if jwt.Secret != "" && jwt.JwksURI != "" {
		return append(allErrs, field.Forbidden(fieldPath.Child("secret"), "only either of Secret or JwksURI can be used"))
	}

	// Verify a case when using JWT Secret
	if jwt.Secret != "" {
		allErrs = append(allErrs, validateSecretName(jwt.Secret, fieldPath.Child("secret"))...)
		// jwt.Token is not required field. Verify it when provided.
		if jwt.Token != "" {
			allErrs = append(allErrs, validateJWTToken(jwt.Token, fieldPath.Child("token"))...)
		}

		// keyCache must not be present when using Secret
		if jwt.KeyCache != "" {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("keyCache"), "key cache must not be used when using Secret"))
		}
		return allErrs
	}

	// Verify a case when using JWKS
	if jwt.JwksURI != "" {
		allErrs = append(allErrs, validateURL(jwt.JwksURI, fieldPath.Child("JwksURI"))...)
		allErrs = append(allErrs, validateTime(jwt.KeyCache, fieldPath.Child("keyCache"))...)
		// jwt.Token is not required field. Verify it if it's provided.
		if jwt.Token != "" {
			allErrs = append(allErrs, validateJWTToken(jwt.Token, fieldPath.Child("token"))...)
		}
		// keyCache must be present when using JWKS
		if jwt.KeyCache == "" {
			allErrs = append(allErrs, field.Required(fieldPath.Child("keyCache"), "key cache must be set, example value: 1h"))
		}
		return allErrs
	}
	return allErrs
}

func validateIngressMTLS(ingressMTLS *v1.IngressMTLS, fieldPath *field.Path) field.ErrorList {
	if ingressMTLS.ClientCertSecret == "" {
		return field.ErrorList{field.Required(fieldPath.Child("clientCertSecret"), "")}
	}
	allErrs := validateSecretName(ingressMTLS.ClientCertSecret, fieldPath.Child("clientCertSecret"))
	allErrs = append(allErrs, validateIngressMTLSVerifyClient(ingressMTLS.VerifyClient, fieldPath.Child("verifyClient"))...)
	if ingressMTLS.VerifyDepth != nil {
		allErrs = append(allErrs, validatePositiveIntOrZero(*ingressMTLS.VerifyDepth, fieldPath.Child("verifyDepth"))...)
	}
	return allErrs
}

func validateEgressMTLS(egressMTLS *v1.EgressMTLS, fieldPath *field.Path) field.ErrorList {
	allErrs := validateSecretName(egressMTLS.TLSSecret, fieldPath.Child("tlsSecret"))

	if egressMTLS.VerifyServer && egressMTLS.TrustedCertSecret == "" {
		return append(allErrs, field.Required(fieldPath.Child("trustedCertSecret"), "must be set when verifyServer is 'true'"))
	}
	allErrs = append(allErrs, validateSecretName(egressMTLS.TrustedCertSecret, fieldPath.Child("trustedCertSecret"))...)

	if egressMTLS.VerifyDepth != nil {
		allErrs = append(allErrs, validatePositiveIntOrZero(*egressMTLS.VerifyDepth, fieldPath.Child("verifyDepth"))...)
	}
	return append(allErrs, validateSSLName(egressMTLS.SSLName, fieldPath.Child("sslName"))...)
}

func validateOIDC(oidc *v1.OIDC, fieldPath *field.Path) field.ErrorList {
	if oidc.AuthEndpoint == "" {
		return field.ErrorList{field.Required(fieldPath.Child("authEndpoint"), "")}
	}
	if oidc.TokenEndpoint == "" {
		return field.ErrorList{field.Required(fieldPath.Child("tokenEndpoint"), "")}
	}
	if oidc.JWKSURI == "" {
		return field.ErrorList{field.Required(fieldPath.Child("jwksURI"), "")}
	}
	if oidc.ClientID == "" {
		return field.ErrorList{field.Required(fieldPath.Child("clientID"), "")}
	}
	if oidc.ClientSecret == "" {
		return field.ErrorList{field.Required(fieldPath.Child("clientSecret"), "")}
	}
	if oidc.EndSessionEndpoint == "" && oidc.PostLogoutRedirectURI != "" {
		msg := "postLogoutRedirectURI can only be set when endSessionEndpoint is set"
		return field.ErrorList{field.Forbidden(fieldPath.Child("postLogoutRedirectURI"), msg)}
	}

	allErrs := field.ErrorList{}
	if oidc.Scope != "" {
		allErrs = append(allErrs, validateOIDCScope(oidc.Scope, fieldPath.Child("scope"))...)
	}
	if oidc.RedirectURI != "" {
		allErrs = append(allErrs, validatePath(oidc.RedirectURI, fieldPath.Child("redirectURI"))...)
	}
	if oidc.EndSessionEndpoint != "" {
		allErrs = append(allErrs, validateURL(oidc.EndSessionEndpoint, fieldPath.Child("endSessionEndpoint"))...)
	}
	if oidc.PostLogoutRedirectURI != "" {
		allErrs = append(allErrs, validatePath(oidc.PostLogoutRedirectURI, fieldPath.Child("postLogoutRedirectURI"))...)
	}
	if oidc.ZoneSyncLeeway != nil {
		allErrs = append(allErrs, validatePositiveIntOrZero(*oidc.ZoneSyncLeeway, fieldPath.Child("zoneSyncLeeway"))...)
	}
	if oidc.AuthExtraArgs != nil {
		allErrs = append(allErrs, validateQueryString(strings.Join(oidc.AuthExtraArgs, "&"), fieldPath.Child("authExtraArgs"))...)
	}

	allErrs = append(allErrs, validateURL(oidc.AuthEndpoint, fieldPath.Child("authEndpoint"))...)
	allErrs = append(allErrs, validateURL(oidc.TokenEndpoint, fieldPath.Child("tokenEndpoint"))...)
	allErrs = append(allErrs, validateURL(oidc.JWKSURI, fieldPath.Child("jwksURI"))...)
	allErrs = append(allErrs, validateSecretName(oidc.ClientSecret, fieldPath.Child("clientSecret"))...)
	return append(allErrs, validateClientID(oidc.ClientID, fieldPath.Child("clientID"))...)
}

func validateAPIKey(apiKey *v1.APIKey, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if apiKey == nil {
		allErrs = append(allErrs, field.Required(fieldPath, "apiKey cannot be nil"))
		return allErrs
	}

	if apiKey.SuppliedIn == nil {
		allErrs = append(allErrs, field.Required(fieldPath.Child("suppliedIn"), "suppliedIn cannot be nil"))
		return allErrs
	}

	if apiKey.SuppliedIn.Query == nil && apiKey.SuppliedIn.Header == nil {
		msg := "at least one query or header name must be provided"
		allErrs = append(allErrs, field.Required(fieldPath.Child("suppliedIn"), msg))
	}

	if apiKey.SuppliedIn.Header != nil {
		for _, header := range apiKey.SuppliedIn.Header {
			for _, msg := range validation.IsHTTPHeaderName(header) {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("suppliedIn.header"), header, msg))
			}
		}
	}

	if apiKey.SuppliedIn.Query != nil {
		for _, query := range apiKey.SuppliedIn.Query {
			if err := ValidateEscapedString(query); err != nil {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("suppliedIn.query"), query, err.Error()))
			}
		}
	}

	if apiKey.ClientSecret == "" {
		allErrs = append(allErrs, field.Required(fieldPath.Child("clientSecret"), "clientSecret cannot be empty"))
	} else {
		allErrs = append(allErrs, validateSecretName(apiKey.ClientSecret, fieldPath.Child("clientSecret"))...)
	}

	return allErrs
}

func validateWAF(waf *v1.WAF, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	bundleMode := waf.ApBundle != ""

	// WAF Policy references either apPolicy or apBundle.
	if waf.ApPolicy != "" && waf.ApBundle != "" {
		msg := "apPolicy and apBundle fields in the WAF policy are mutually exclusive"
		allErrs = append(allErrs,
			field.Invalid(fieldPath.Child("apPolicy"), waf.ApPolicy, msg),
			field.Invalid(fieldPath.Child("apBundle"), waf.ApBundle, msg),
		)
	}

	if waf.ApPolicy != "" {
		for _, msg := range validation.IsQualifiedName(waf.ApPolicy) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("apPolicy"), waf.ApPolicy, msg))
		}
	}

	if bundleMode {
		for _, msg := range validation.IsQualifiedName(waf.ApBundle) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("apBundle"), waf.ApBundle, msg))
		}
	}

	if waf.SecurityLog != nil {
		allErrs = append(allErrs, validateLogConf(waf.SecurityLog, fieldPath.Child("securityLog"), bundleMode)...)
	}

	if waf.SecurityLogs != nil {
		allErrs = append(allErrs, validateLogConfs(waf.SecurityLogs, fieldPath.Child("securityLogs"), bundleMode)...)
	}
	return allErrs
}

func validateLogConfs(logs []*v1.SecurityLog, fieldPath *field.Path, bundleMode bool) field.ErrorList {
	allErrs := field.ErrorList{}

	for i := range logs {
		allErrs = append(allErrs, validateLogConf(logs[i], fieldPath.Index(i), bundleMode)...)
	}

	return allErrs
}

func validateLogConf(logConf *v1.SecurityLog, fieldPath *field.Path, bundleMode bool) field.ErrorList {
	allErrs := field.ErrorList{}

	if logConf.ApLogConf != "" && logConf.ApLogBundle != "" {
		msg := "apLogConf and apLogBundle fields in the securityLog are mutually exclusive"
		allErrs = append(allErrs,
			field.Invalid(fieldPath.Child("apLogConf"), logConf.ApLogConf, msg),
			field.Invalid(fieldPath.Child("apLogBundle"), logConf.ApLogBundle, msg),
		)
	}

	if logConf.ApLogConf != "" {
		if bundleMode {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("apLogConf"), logConf.ApLogConf, "apLogConf is not supported with apBundle"))
		}
		for _, msg := range validation.IsQualifiedName(logConf.ApLogConf) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("apLogConf"), logConf.ApLogConf, msg))
		}
	}

	if logConf.ApLogBundle != "" {
		if !bundleMode {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("apLogConf"), logConf.ApLogConf, "apLogBundle is not supported with apPolicy"))
		}
		for _, msg := range validation.IsQualifiedName(logConf.ApLogBundle) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("apBundle"), logConf.ApLogBundle, msg))
		}
	}

	err := ValidateAppProtectLogDestination(logConf.LogDest)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("logDest"), logConf.LogDest, err.Error()))
	}
	return allErrs
}

func validateClientID(client string, fieldPath *field.Path) field.ErrorList {
	// isValidHeaderValue checks for $ and " in the string
	if isValidHeaderValue(client) != nil {
		return field.ErrorList{field.Invalid(
			fieldPath,
			client,
			`invalid string. String must contain valid ASCII characters, must have all '"' escaped and must not contain any '$' or end with an unescaped '\'
		`)}
	}
	return nil
}

// Allowed unicode ranges in OIDC scope tokens.
// Ref. https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
var validOIDCScopeRanges = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x21, 0x21, 1},
		{0x23, 0x5B, 1},
		{0x5D, 0x7E, 1},
	},
}

// validateOIDCScope takes a scope representing OIDC scope tokens and
// checks if the scope is valid. OIDC scope must contain scope token
// "openid". Additionally, custom scope tokens can be added to the scope.
//
// Ref:
// - https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
//
// Scope tokens must be separated by "+", and the "+" can't be a part of the token.
func validateOIDCScope(scope string, fieldPath *field.Path) field.ErrorList {
	if !strings.Contains(scope, "openid") {
		return field.ErrorList{field.Required(fieldPath, "openid is required")}
	}

	for _, token := range strings.Split(scope, "+") {
		for _, v := range token {
			if !unicode.Is(validOIDCScopeRanges, v) {
				msg := fmt.Sprintf("not allowed character %v in scope %s", v, scope)
				return field.ErrorList{field.Invalid(fieldPath, scope, msg)}
			}
		}
	}
	return nil
}

func validateURL(name string, fieldPath *field.Path) field.ErrorList {
	u, err := url.Parse(name)
	if err != nil {
		return field.ErrorList{field.Invalid(fieldPath, name, err.Error())}
	}
	if u.Scheme == "" {
		return field.ErrorList{field.Invalid(fieldPath, name, "scheme required, please use the prefix http(s)://")}
	}
	if u.Host == "" {
		return field.ErrorList{field.Invalid(fieldPath, name, "hostname required")}
	}
	if u.Path == "" {
		return field.ErrorList{field.Invalid(fieldPath, name, "path required")}
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	allErrs := validateSSLName(host, fieldPath)
	if port != "" {
		allErrs = append(allErrs, validatePortNumber(port, fieldPath)...)
	}
	return allErrs
}

func validateQueryString(queryString string, fieldPath *field.Path) field.ErrorList {
	_, err := url.ParseQuery(queryString)
	if err != nil {
		return field.ErrorList{field.Invalid(fieldPath, queryString, err.Error())}
	}
	return nil
}

func validatePortNumber(port string, fieldPath *field.Path) field.ErrorList {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return field.ErrorList{field.Invalid(fieldPath, port, "invalid port")}
	}
	msg := validation.IsValidPortNum(portInt)
	if msg != nil {
		return field.ErrorList{field.Invalid(fieldPath, port, msg[0])}
	}
	return nil
}

func validateSSLName(name string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if name != "" {
		for _, msg := range validation.IsDNS1123Subdomain(name) {
			allErrs = append(allErrs, field.Invalid(fieldPath, name, msg))
		}
	}
	return allErrs
}

var validateVerifyClientKeyParameters = map[string]bool{
	"on":             true,
	"off":            true,
	"optional":       true,
	"optional_no_ca": true,
}

func validateIngressMTLSVerifyClient(verifyClient string, fieldPath *field.Path) field.ErrorList {
	if verifyClient != "" {
		return ValidateParameter(verifyClient, validateVerifyClientKeyParameters, fieldPath)
	}
	return nil
}

const (
	rateFmt    = `[1-9]\d*r/[sSmM]`
	rateErrMsg = "must consist of numeric characters followed by a valid rate suffix. 'r/s|r/m"
)

var rateRegexp = regexp.MustCompile("^" + rateFmt + "$")

func validateRate(rate string, fieldPath *field.Path) field.ErrorList {
	if rate == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}
	if !rateRegexp.MatchString(rate) {
		msg := validation.RegexError(rateErrMsg, rateFmt, "16r/s", "32r/m", "64r/s")
		return field.ErrorList{field.Invalid(fieldPath, rate, msg)}
	}
	return nil
}

func validateRateLimitZoneSize(zoneSize string, fieldPath *field.Path) field.ErrorList {
	if zoneSize == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}

	allErrs := validateSize(zoneSize, fieldPath)
	kbZoneSize := strings.TrimSuffix(strings.ToLower(zoneSize), "k")
	kbZoneSizeNum, err := strconv.Atoi(kbZoneSize)
	mbZoneSize := strings.TrimSuffix(strings.ToLower(zoneSize), "m")
	mbZoneSizeNum, mbErr := strconv.Atoi(mbZoneSize)

	if err == nil && kbZoneSizeNum < 32 || mbErr == nil && mbZoneSizeNum == 0 {
		allErrs = append(allErrs, field.Invalid(fieldPath, zoneSize, "must be greater than 31k"))
	}
	return allErrs
}

var rateLimitKeySpecialVariables = []string{"arg_", "http_", "cookie_", "jwt_claim_"}

// rateLimitKeyVariables includes NGINX variables allowed to be used in a rateLimit policy key.
var rateLimitKeyVariables = map[string]bool{
	"binary_remote_addr": true,
	"request_uri":        true,
	"uri":                true,
	"args":               true,
}

func validateRateLimitKey(key string, fieldPath *field.Path, isPlus bool) field.ErrorList {
	if key == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}
	allErrs := field.ErrorList{}
	if err := ValidateEscapedString(key, `Hello World! \n`, `\"${request_uri}\" is unavailable. \n`); err != nil {
		allErrs = append(allErrs, field.Invalid(fieldPath, key, err.Error()))
	}
	return append(allErrs, validateStringWithVariables(key, fieldPath, rateLimitKeySpecialVariables, rateLimitKeyVariables, isPlus)...)
}

var jwtTokenSpecialVariables = []string{"arg_", "http_", "cookie_"}

func validateJWTToken(token string, fieldPath *field.Path) field.ErrorList {
	if token == "" {
		return nil
	}

	nginxVars := strings.Split(token, "$")
	if len(nginxVars) != 2 {
		return field.ErrorList{field.Invalid(fieldPath, token, "must have 1 var")}
	}

	nVar := token[1:]

	special := false
	for _, specialVar := range jwtTokenSpecialVariables {
		if strings.HasPrefix(nVar, specialVar) {
			special = true
			break
		}
	}

	if !special {
		return field.ErrorList{field.Invalid(fieldPath, token, "must only have special vars")}
	}
	// validateJWTToken is called only when NGINX Plus is running
	return validateSpecialVariable(nVar, fieldPath, true)
}

var validLogLevels = map[string]bool{
	"info":   true,
	"notice": true,
	"warn":   true,
	"error":  true,
}

func validateRateLimitLogLevel(logLevel string, fieldPath *field.Path) field.ErrorList {
	if !validLogLevels[logLevel] {
		return field.ErrorList{field.Invalid(fieldPath, logLevel, fmt.Sprintf("Accepted values: %s",
			mapToPrettyString(validLogLevels)))}
	}
	return nil
}

const (
	realmFmt              = `([^"$\\]|\\[^$])*`
	realmFmtErrMsg string = `a valid realm must have all '"' escaped and must not contain any '$' or end with an unescaped '\'`
)

var realmFmtRegexp = regexp.MustCompile("^" + realmFmt + "$")

func validateRealm(realm string, fieldPath *field.Path) field.ErrorList {
	if !realmFmtRegexp.MatchString(realm) {
		msg := validation.RegexError(realmFmtErrMsg, realmFmt, "MyAPI", "My Product API")
		return field.ErrorList{field.Invalid(fieldPath, realm, msg)}
	}
	return nil
}

func validateIPorCIDR(ipOrCIDR string, fieldPath *field.Path) field.ErrorList {
	_, _, err := net.ParseCIDR(ipOrCIDR)
	if err == nil {
		// valid CIDR
		return nil
	}
	ip := net.ParseIP(ipOrCIDR)
	if ip != nil {
		// valid IP
		return nil
	}
	return field.ErrorList{field.Invalid(fieldPath, ipOrCIDR, "must be a CIDR or IP")}
}

func validatePositiveInt(n int, fieldPath *field.Path) field.ErrorList {
	if n <= 0 {
		return field.ErrorList{field.Invalid(fieldPath, n, "must be positive")}
	}
	return nil
}
