package validation

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	validation2 "github.com/nginx/kubernetes-ingress/internal/validation"
	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// PolicyValidationConfig holds configuration flags needed for policy validation.
type PolicyValidationConfig struct {
	IsPlus           bool
	EnableOIDC       bool
	EnableAppProtect bool
	EnableSnippets   bool
}

// ValidatePolicy validates a Policy.
func ValidatePolicy(policy *v1.Policy, cfg PolicyValidationConfig) error {
	allErrs := validatePolicySpec(&policy.Spec, field.NewPath("spec"), cfg)
	return allErrs.ToAggregate()
}

// policyGate represents a feature-gate check for a policy type.
type policyGate struct {
	// blocked returns true when the required feature is not enabled.
	blocked func(PolicyValidationConfig) bool
	// message is the error message when the gate is violated.
	message string
	// fatal means return immediately without continuing validation.
	fatal bool
}

// policyEntry defines a single policy type for table-driven validation.
type policyEntry struct {
	// name is used in the "must specify exactly one" error message.
	name string
	// fieldName is the fieldPath child name for error paths.
	fieldName string
	// plusOnly means this policy is only listed in the message when IsPlus is true.
	plusOnly bool
	// isSet returns true if this policy type is configured in the spec.
	isSet func(*v1.PolicySpec) bool
	// gates are feature-gate checks run before validation.
	gates []policyGate
	// validate performs the actual field validation.
	validate func(*v1.PolicySpec, *field.Path, PolicyValidationConfig) field.ErrorList
}

// policyEntries defines all policy types in message-display order.
// Non-Plus policies are listed first, then Plus-only policies.
var policyEntries = []policyEntry{
	{
		name: "accessControl", fieldName: "accessControl",
		isSet: func(s *v1.PolicySpec) bool { return s.AccessControl != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateAccessControl(s.AccessControl, fp.Child("accessControl"))
		},
	},
	{
		name: "rateLimit", fieldName: "rateLimit",
		isSet: func(s *v1.PolicySpec) bool { return s.RateLimit != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, cfg PolicyValidationConfig) field.ErrorList {
			return validateRateLimit(s.RateLimit, fp.Child("rateLimit"), cfg.IsPlus)
		},
	},
	{
		name: "ingressMTLS", fieldName: "ingressMTLS",
		isSet: func(s *v1.PolicySpec) bool { return s.IngressMTLS != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateIngressMTLS(s.IngressMTLS, fp.Child("ingressMTLS"))
		},
	},
	{
		name: "egressMTLS", fieldName: "egressMTLS",
		isSet: func(s *v1.PolicySpec) bool { return s.EgressMTLS != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateEgressMTLS(s.EgressMTLS, fp.Child("egressMTLS"))
		},
	},
	{
		name: "basicAuth", fieldName: "basicAuth",
		isSet: func(s *v1.PolicySpec) bool { return s.BasicAuth != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateBasic(s.BasicAuth, fp.Child("basicAuth"))
		},
	},
	{
		name: "apiKey", fieldName: "apiKey",
		isSet: func(s *v1.PolicySpec) bool { return s.APIKey != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateAPIKey(s.APIKey, fp.Child("apiKey"))
		},
	},
	{
		name: "cache", fieldName: "cache",
		isSet: func(s *v1.PolicySpec) bool { return s.Cache != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, cfg PolicyValidationConfig) field.ErrorList {
			return validateCache(s.Cache, fp.Child("cache"), cfg.IsPlus)
		},
	},
	{
		name: "cors", fieldName: "cors",
		isSet: func(s *v1.PolicySpec) bool { return s.CORS != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateCORS(s.CORS, fp.Child("cors"))
		},
	},
	{
		name: "externalAuth", fieldName: "externalAuth",
		isSet: func(s *v1.PolicySpec) bool { return s.ExternalAuth != nil },
		validate: func(s *v1.PolicySpec, fp *field.Path, cfg PolicyValidationConfig) field.ErrorList {
			return validateExternalAuth(s.ExternalAuth, fp.Child("externalAuth"), cfg.EnableSnippets)
		},
	},
	{
		name: "jwt", fieldName: "jwt", plusOnly: true,
		isSet: func(s *v1.PolicySpec) bool { return s.JWTAuth != nil },
		gates: []policyGate{
			{
				blocked: func(cfg PolicyValidationConfig) bool { return !cfg.IsPlus },
				message: "jwt secrets are only supported in NGINX Plus",
				fatal:   true,
			},
		},
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateJWT(s.JWTAuth, fp.Child("jwt"))
		},
	},
	{
		name: "oidc", fieldName: "oidc", plusOnly: true,
		isSet: func(s *v1.PolicySpec) bool { return s.OIDC != nil },
		gates: []policyGate{
			{
				blocked: func(cfg PolicyValidationConfig) bool { return !cfg.EnableOIDC },
				message: "OIDC must be enabled via cli argument -enable-oidc to use OIDC policy",
				fatal:   false,
			},
			{
				blocked: func(cfg PolicyValidationConfig) bool { return !cfg.IsPlus },
				message: "OIDC is only supported in NGINX Plus",
				fatal:   true,
			},
		},
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateOIDC(s.OIDC, fp.Child("oidc"))
		},
	},
	{
		name: "waf", fieldName: "waf", plusOnly: true,
		isSet: func(s *v1.PolicySpec) bool { return s.WAF != nil },
		gates: []policyGate{
			{
				blocked: func(cfg PolicyValidationConfig) bool { return !cfg.IsPlus },
				message: "WAF is only supported in NGINX Plus",
				fatal:   false,
			},
			{
				blocked: func(cfg PolicyValidationConfig) bool { return !cfg.EnableAppProtect },
				message: "App Protect must be enabled via cli argument -enable-app-protect to use WAF policy",
				fatal:   false,
			},
		},
		validate: func(s *v1.PolicySpec, fp *field.Path, _ PolicyValidationConfig) field.ErrorList {
			return validateWAF(s.WAF, fp.Child("waf"))
		},
	},
}

func validatePolicySpec(spec *v1.PolicySpec, fieldPath *field.Path, cfg PolicyValidationConfig) field.ErrorList {
	allErrs := field.ErrorList{}
	fieldCount := 0

	for _, entry := range policyEntries {
		if !entry.isSet(spec) {
			continue
		}

		fatalGate := false
		for _, gate := range entry.gates {
			if gate.blocked(cfg) {
				allErrs = append(allErrs, field.Forbidden(fieldPath.Child(entry.fieldName), gate.message))
				if gate.fatal {
					fatalGate = true
					break
				}
			}
		}
		if fatalGate {
			return allErrs
		}

		allErrs = append(allErrs, entry.validate(spec, fieldPath, cfg)...)
		fieldCount++
	}

	if fieldCount != 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", buildPolicySpecMsg(cfg)))
	}

	return allErrs
}

// buildPolicySpecMsg generates the "must specify exactly one of" error message
// from the policyEntries table, filtering Plus-only entries when not running Plus.
func buildPolicySpecMsg(cfg PolicyValidationConfig) string {
	names := make([]string, 0, len(policyEntries))
	for _, entry := range policyEntries {
		if !entry.plusOnly || cfg.IsPlus {
			names = append(names, "`"+entry.name+"`")
		}
	}
	return "must specify exactly one of: " + strings.Join(names, ", ")
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

	if rateLimit.Condition != nil && (rateLimit.Condition.JWT == nil && rateLimit.Condition.Variables == nil) {
		allErrs = append(allErrs, field.Required(fieldPath.Child("condition"), "must specify either jwt or variable conditions"))
	}

	if rateLimit.Condition != nil && rateLimit.Condition.JWT != nil && rateLimit.Condition.Variables != nil {
		allErrs = append(allErrs, field.Required(fieldPath.Child("condition"), "only one condition, jwt or variables is allowed"))
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

		// If JwksURI is not set, then none of the SNI fields should be set.
		if jwt.SNIEnabled {
			return append(allErrs, field.Forbidden(fieldPath.Child("sniEnabled"), "sniEnabled can only be set when JwksURI is set"))
		}

		if jwt.SNIName != "" {
			return append(allErrs, field.Forbidden(fieldPath.Child("sniName"), "sniName can only be set when JwksURI is set"))
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

		// if SNI server name is provided, but SNI is not enabled, return an error
		if jwt.SNIName != "" && !jwt.SNIEnabled {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("sniServerName"), "sniServerName can only be set when sniEnabled is true"))
		}

		// if SNI is enabled and SNI server name is provided, make sure it's a valid URI
		if jwt.SNIEnabled && jwt.SNIName != "" {
			err := validation2.ValidateURI(jwt.SNIName,
				validation2.WithAllowedSchemes("https"),
				validation2.WithUserAllowed(false),
				validation2.WithDefaultScheme("https"))
			if err != nil {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("sniServerName"), jwt.SNIName, "sniServerName is not a valid URI"))
			}
		}

		if jwt.TrustedCertSecret != "" {
			allErrs = append(allErrs, validateSecretName(jwt.TrustedCertSecret, fieldPath.Child("trustedCertSecret"))...)
			// If trustedCertSecret is set but sslVerify is false, warn user
			if !jwt.SSLVerify {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("sslVerify"), jwt.SSLVerify, "sslVerify should be enabled when trustedCertSecret is specified"))
			}
		}
	}
	return allErrs
}

func validateBasic(basic *v1.BasicAuth, fieldPath *field.Path) field.ErrorList {
	if basic.Secret == "" {
		return field.ErrorList{field.Required(fieldPath.Child("secret"), "")}
	}

	allErrs := field.ErrorList{}
	if basic.Realm != "" {
		allErrs = append(allErrs, validateRealm(basic.Realm, fieldPath.Child("realm"))...)
	}
	return append(allErrs, validateSecretName(basic.Secret, fieldPath.Child("secret"))...)
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
	if oidc.EndSessionEndpoint == "" && oidc.PostLogoutRedirectURI != "" {
		msg := "postLogoutRedirectURI can only be set when endSessionEndpoint is set"
		return field.ErrorList{field.Forbidden(fieldPath.Child("postLogoutRedirectURI"), msg)}
	}

	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validatePKCE(oidc.PKCEEnable, oidc.ClientSecret, fieldPath.Child("clientSecret"))...)

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

// validateCache validates a cache policy
func validateCache(cache *v1.Cache, fieldPath *field.Path, isPlus bool) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateCacheAllowedCodes(cache, fieldPath)...)

	// Validate NGINX Plus features
	allErrs = append(allErrs, validateCachePlusFeatures(cache, fieldPath, isPlus)...)

	// Validate time fields
	if cache.Inactive != "" {
		allErrs = append(allErrs, validateTime(cache.Inactive, fieldPath.Child("inactive"))...)
	}

	// Validate size fields
	if cache.MaxSize != "" {
		allErrs = append(allErrs, validateOffset(cache.MaxSize, fieldPath.Child("maxSize"))...)
	}
	if cache.MinFree != "" {
		allErrs = append(allErrs, validateOffset(cache.MinFree, fieldPath.Child("minFree"))...)
	}

	// Validate manager fields
	if cache.Manager != nil {
		managerPath := fieldPath.Child("manager")
		if cache.Manager.Files != nil && *cache.Manager.Files <= 0 {
			allErrs = append(allErrs, field.Invalid(managerPath.Child("files"), *cache.Manager.Files, "must be a positive integer"))
		}
		if cache.Manager.Sleep != "" {
			allErrs = append(allErrs, validateTime(cache.Manager.Sleep, managerPath.Child("sleep"))...)
		}
		if cache.Manager.Threshold != "" {
			allErrs = append(allErrs, validateTime(cache.Manager.Threshold, managerPath.Child("threshold"))...)
		}
	}

	// Validate cache min uses
	if cache.CacheMinUses != nil && *cache.CacheMinUses <= 0 {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("cacheMinUses"), *cache.CacheMinUses, "must be a positive integer"))
	}

	// Validate lock fields
	if cache.Lock != nil {
		lockPath := fieldPath.Child("lock")
		if cache.Lock.Timeout != "" {
			allErrs = append(allErrs, validateTime(cache.Lock.Timeout, lockPath.Child("timeout"))...)
		}
		if cache.Lock.Age != "" {
			allErrs = append(allErrs, validateTime(cache.Lock.Age, lockPath.Child("age"))...)
		}
	}

	// Validate cache key
	if cache.CacheKey != "" {
		if err := ValidateEscapedString(cache.CacheKey); err != nil {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("cacheKey"), cache.CacheKey, err.Error()))
		}
		// Cache keys support both ${var} and $var NGINX syntax, so we skip variable braces validation
		// but still validate basic syntax rules like not ending with $
		if strings.HasSuffix(cache.CacheKey, "$") {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("cacheKey"), cache.CacheKey, "must not end with $"))
		}
	}

	// Validate conditions
	if cache.Conditions != nil {
		conditionsPath := fieldPath.Child("conditions")
		for i, condition := range cache.Conditions.NoCache {
			if condition != "" {
				if err := ValidateEscapedString(condition); err != nil {
					allErrs = append(allErrs, field.Invalid(conditionsPath.Child("noCache").Index(i), condition, err.Error()))
				}
			}
		}
		for i, condition := range cache.Conditions.Bypass {
			if condition != "" {
				if err := ValidateEscapedString(condition); err != nil {
					allErrs = append(allErrs, field.Invalid(conditionsPath.Child("bypass").Index(i), condition, err.Error()))
				}
			}
		}
	}

	// Validate use stale
	allErrs = append(allErrs, validateCacheUseStale(cache, fieldPath)...)

	return allErrs
}

// validateCacheAllowedCodes validates the allowedCodes field
func validateCacheAllowedCodes(cache *v1.Cache, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(cache.AllowedCodes) == 0 {
		return allErrs // No validation needed for empty slice
	}

	// Check if it's the special case: single element "any"
	if len(cache.AllowedCodes) == 1 && cache.AllowedCodes[0].Type == intstr.String && cache.AllowedCodes[0].StrVal == "any" {
		return allErrs // Valid: single "any" string
	}

	// Check if it contains "any" mixed with other codes (invalid)
	hasAny := false
	for i, code := range cache.AllowedCodes {
		if code.Type == intstr.String && code.StrVal == "any" {
			hasAny = true
			if len(cache.AllowedCodes) > 1 {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("allowedCodes").Index(i), code.StrVal, "the string 'any' cannot be mixed with other codes"))
			}
		}
	}

	// If we have "any" mixed with others, we already reported the error above
	if hasAny {
		return allErrs
	}

	// Validate all elements are integers in the range 100-599
	for i, code := range cache.AllowedCodes {
		if code.Type == intstr.String { // String type
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("allowedCodes").Index(i), code.StrVal, "must be an integer HTTP status code (100-599) or the single string 'any'"))
		} else { // Integer type
			intVal := int(code.IntVal)
			if intVal < 100 || intVal > 599 {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("allowedCodes").Index(i), intVal, "HTTP status code must be between 100 and 599"))
			}
		}
	}

	return allErrs
}

// validateCachePlusFeatures validates NGINX Plus specific features, such as cache purge allow IPs
func validateCachePlusFeatures(cache *v1.Cache, fieldPath *field.Path, isPlus bool) field.ErrorList {
	allErrs := field.ErrorList{}

	// Validate cache purge allow IPs if provided
	if len(cache.CachePurgeAllow) > 0 {
		// Check if NGINX Plus is required for cache purge
		if !isPlus {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("cachePurgeAllow"), "cache purge is only supported in NGINX Plus"))
		} else {
			// Validate IP addresses/CIDRs if NGINX Plus is available
			for i, ip := range cache.CachePurgeAllow {
				if net.ParseIP(ip) == nil {
					// Try parsing as CIDR
					if _, _, err := net.ParseCIDR(ip); err != nil {
						allErrs = append(allErrs, field.Invalid(fieldPath.Child("cachePurgeAllow").Index(i), ip, "must be a valid IP address or CIDR"))
					}
				}
			}
		}
	}

	return allErrs
}

// validateCacheUseStale validates the cacheUseStale field values
// The directive's parameters match the parameters of the proxy_next_upstream directive plus "updating"
func validateCacheUseStale(cache *v1.Cache, fieldPath *field.Path) field.ErrorList {
	if len(cache.CacheUseStale) == 0 {
		return nil
	}

	allErrs := field.ErrorList{}
	allParams := sets.Set[string]{}

	for _, para := range cache.CacheUseStale {
		// Check if parameter is valid (either from validNextUpstreamParams or "updating" which is specific to cache)
		if !validNextUpstreamParams[para] && para != "updating" {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("cacheUseStale"), para, "not a valid parameter"))
		}
		if allParams.Has(para) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("cacheUseStale"), para, "can not have duplicate parameters"))
		} else {
			allParams.Insert(para)
		}
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

// validatePKCE checks for the duo of PKCEEnable and clientSecret settings.
//
//   - yes PKCE and not empty client secret is bad, because PKCE does not use
//     client secret
//   - no PKCE and empty client secret is bad because standard OIDC uses client
//     secrets
func validatePKCE(PKCEEnable bool, clientSecret string,
	clientSecretPath *field.Path,
) field.ErrorList {
	if !PKCEEnable && clientSecret == "" {
		return field.ErrorList{field.Required(clientSecretPath, "clientSecret is required when PKCE is not used")}
	}

	if PKCEEnable && clientSecret != "" {
		return field.ErrorList{field.Forbidden(clientSecretPath, "clientSecret cannot be used when PKCE is used")}
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

var rateLimitKeySpecialVariables = []string{"arg_", "http_", "cookie_", "jwt_claim_", "apikey_"}

// rateLimitKeyVariables includes NGINX variables allowed to be used in a rateLimit policy key.
var rateLimitKeyVariables = map[string]bool{
	"binary_remote_addr": true,
	"request_uri":        true,
	"uri":                true,
	"args":               true,
	"request_method":     true,
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

func validateCORS(cors *v1.CORS, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	// Validate origins
	allErrs = append(allErrs, validateCORSOrigins(cors.AllowOrigin, fieldPath.Child("allowOrigin"))...)

	// Validate allow headers
	allErrs = append(allErrs, validateCORSAllowHeaders(cors.AllowHeaders, fieldPath.Child("allowHeaders"))...)

	// Validate methods
	allErrs = append(allErrs, validateCORSMethods(cors.AllowMethods, fieldPath.Child("allowMethods"))...)

	// Validate expose headers
	allErrs = append(allErrs, validateCORSExposeHeaders(cors.ExposeHeaders, fieldPath.Child("exposeHeaders"))...)

	return allErrs
}

// validateCORSOrigins validates the allowOrigin field
func validateCORSOrigins(origins []string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	originSet := make(map[string]int) // Track origins and their first occurrence index

	for i, origin := range origins {
		// Check for duplicates
		if firstIndex, exists := originSet[origin]; exists {
			allErrs = append(allErrs, field.Duplicate(fieldPath.Index(i),
				fmt.Sprintf("origin '%s' already specified at index %d, duplicates cause nginx configuration conflicts", origin, firstIndex)))
		} else {
			originSet[origin] = i
		}

		// Validate origin format - must be wildcard, exact URL, or wildcard subdomain pattern
		if err := validateOriginFormat(origin); err != nil {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), origin, err.Error()))
		}

		// Check for dangerous characters that could cause nginx injection
		if containsDangerousChars(origin) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), origin, "origin contains dangerous characters that could cause nginx configuration injection"))
		}
	}

	return allErrs
}

// validateOriginFormat validates a single origin format
func validateOriginFormat(origin string) error {
	// Global wildcard
	if origin == "*" {
		return nil
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin URL format")
	}

	if err := validateParsedOriginBase(parsedOrigin); err != nil {
		return err
	}

	host := parsedOrigin.Host
	if strings.HasPrefix(host, "*.") {
		return validateWildcardOriginHost(origin, host)
	}

	return validateExactOriginHost(host)
}

func validateParsedOriginBase(parsedOrigin *url.URL) error {
	// Must have protocol
	if parsedOrigin.Scheme != "http" && parsedOrigin.Scheme != "https" {
		return fmt.Errorf("origin must start with http:// or https:// (or be '*')")
	}

	// Origin must contain only scheme://host[:port]
	if parsedOrigin.Host == "" {
		return fmt.Errorf("origin host cannot be empty")
	}
	if parsedOrigin.User != nil {
		return fmt.Errorf("origin must not include @")
	}
	if parsedOrigin.Path != "" && parsedOrigin.Path != "/" {
		return fmt.Errorf("origin must not include a path")
	}
	if parsedOrigin.RawQuery != "" {
		return fmt.Errorf("origin must not include query parameters")
	}
	if parsedOrigin.Fragment != "" {
		return fmt.Errorf("origin must not include a fragment")
	}

	return nil
}

func validateWildcardOriginHost(origin, host string) error {
	// Validate wildcard subdomain format
	domain := host[2:] // Remove "*."
	if domain == "" {
		return fmt.Errorf("wildcard subdomain cannot be empty (invalid format: %s)", origin)
	}

	// Ensure domain doesn't contain additional wildcards
	if strings.Contains(domain, "*") {
		return fmt.Errorf("only single-level wildcard subdomains are supported (invalid: %s)", origin)
	}

	// Split domain and port if port exists
	domainPart, port, hasPort := strings.Cut(domain, ":")
	if hasPort {
		if port == "" {
			return fmt.Errorf("port cannot be empty when colon is present (invalid: %s)", origin)
		}
		// Validate port is numeric and in valid range
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("port must be numeric (invalid: %s)", origin)
		}
	}

	// Validate domain part using Kubernetes DNS validation
	if errs := validation.IsDNS1123Subdomain(domainPart); len(errs) > 0 {
		return fmt.Errorf("wildcard subdomain is not a valid DNS name: %s (invalid: %s)", strings.Join(errs, ", "), origin)
	}

	return nil
}

func validateExactOriginHost(host string) error {
	// For exact origins, basic validation that host is not empty
	if host == "" {
		return fmt.Errorf("origin host cannot be empty")
	}

	// Check for any wildcards in non-wildcard origins
	if strings.Contains(host, "*") {
		return fmt.Errorf("wildcards are only supported in subdomain format (*.domain.com), not in other positions")
	}

	return nil
}

// validateCORSAllowHeaders validates the allowHeaders field
func validateCORSAllowHeaders(headers []string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, header := range headers {
		allErrs = append(allErrs, validateHeaderName(header, fieldPath.Index(i))...)

		// Check for wildcard
		if strings.Contains(header, "*") {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), header, "wildcard '*' is not allowed in individual header names"))
		}

		// Check for forbidden request headers that cannot be set by JavaScript
		if isForbiddenRequestHeader(header) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), header, "forbidden request header cannot be set by JavaScript and should not be listed in allowHeaders"))
		}
	}

	return allErrs
}

// validateCORSMethods validates the allowMethods field
func validateCORSMethods(methods []string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	validMethods := map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "OPTIONS": true, "PATCH": true}
	hasGet := false
	hasHead := false

	for i, method := range methods {
		// Check for dangerous characters
		if containsDangerousChars(method) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), method, "method contains dangerous characters that could cause nginx configuration injection"))
		}

		// Check for valid HTTP methods using map lookup (O(1) vs O(n))
		if !validMethods[method] {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), method, "allowed methods must be valid HTTP methods"))
		}

		// Track GET/HEAD for redundancy check
		switch method {
		case "GET":
			hasGet = true
		case "HEAD":
			hasHead = true
		}
	}

	// Check for redundant HEAD method when GET is present
	if hasGet && hasHead && len(methods) > 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, methods, "HEAD method should not be explicitly listed when GET is present as browsers automatically support HEAD for GET endpoints"))
	}

	return allErrs
}

// validateCORSExposeHeaders validates the exposeHeaders field
func validateCORSExposeHeaders(headers []string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, header := range headers {
		allErrs = append(allErrs, validateHeaderName(header, fieldPath.Index(i))...)

		// Check for wildcard
		if strings.Contains(header, "*") {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), header, "wildcard '*' is not allowed in individual header names for exposeHeaders"))
		}

		// Check for forbidden response headers that cannot be exposed
		if isForbiddenResponseHeader(header) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), header, "forbidden response header cannot be exposed via CORS and should not be listed in exposeHeaders"))
		}
	}

	return allErrs
}

// validateHeaderName validates a header name for RFC compliance and security
func validateHeaderName(header string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if !isValidHeaderName(header) {
		allErrs = append(allErrs, field.Invalid(fieldPath, header, "RFC 7230 violation: invalid header name, must contain only letters, digits, hyphens"))
	}

	// Check for dangerous characters that could cause nginx injection
	if containsDangerousChars(header) {
		allErrs = append(allErrs, field.Invalid(fieldPath, header, "header name contains dangerous characters that could cause nginx configuration injection"))
	}

	return allErrs
}

// isForbiddenRequestHeader checks if a header is forbidden for request headers according to MDN spec
// https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_request_header
func isForbiddenRequestHeader(header string) bool {
	lower := strings.ToLower(header)

	// Map of forbidden request headers that browsers control (as per MDN spec) for O(1) lookup
	forbiddenHeaders := map[string]bool{
		"accept-charset": true, "accept-encoding": true, "access-control-request-headers": true, "access-control-request-method": true,
		"connection": true, "content-length": true, "cookie": true, "date": true, "dnt": true, "expect": true, "host": true, "keep-alive": true,
		"origin": true, "referer": true, "set-cookie": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true, "via": true,
	}

	if forbiddenHeaders[lower] {
		return true
	}

	// Headers starting with proxy- or sec- are also forbidden per MDN spec
	return strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "sec-")
}

// isForbiddenResponseHeader checks if a header is forbidden for response headers according to CORS spec
func isForbiddenResponseHeader(header string) bool {
	lower := strings.ToLower(header)

	// Set-Cookie headers cannot be exposed via CORS (per MDN specification)
	return lower == "set-cookie" || lower == "set-cookie2"
}

// containsDangerousChars checks if a string contains characters that could cause nginx injection
func containsDangerousChars(value string) bool {
	// Map of dangerous characters for O(1) lookup per character
	dangerousChars := map[rune]bool{
		';':  true, // End nginx directive - NEVER ALLOWED
		'{':  true, // Start nginx block - NEVER ALLOWED
		'}':  true, // End nginx block - NEVER ALLOWED
		'\n': true, // Line break - NEVER ALLOWED
		'\r': true, // Carriage return - NEVER ALLOWED
		'$':  true, // Variable expansion in nginx - NEVER ALLOWED
		'`':  true, // Command substitution - NEVER ALLOWED
	}

	for _, char := range value {
		if dangerousChars[char] {
			return true
		}
	}
	return false
}

func validateExternalAuth(externalAuth *v1.ExternalAuth, fieldPath *field.Path, enableSnippets bool) field.ErrorList {
	allErrs := field.ErrorList{}

	// Validate AuthSnippets requires enableSnippets
	if externalAuth.AuthSnippets != "" && !enableSnippets {
		allErrs = append(allErrs, field.Forbidden(fieldPath.Child("authSnippets"),
			"snippets must be enabled via cli argument -enable-snippets to use authSnippets"))
	}

	// Validate AuthURI
	allErrs = append(allErrs, validateAuthURI(externalAuth.AuthURI, fieldPath.Child("authURI"))...)

	// Validate AuthServiceName
	parts := strings.Split(externalAuth.AuthServiceName, "/")
	if len(parts) > 2 || len(parts) < 1 {
		return field.ErrorList{field.Invalid(fieldPath, externalAuth.AuthServiceName, " service reference must be in the format service-name or namespace/service-name")}
	}
	ns := ""
	if len(parts) == 2 {
		ns = parts[0]
	}
	name := parts[len(parts)-1]
	if ns != "" {
		allErrs = append(allErrs, validateDNS1123Label(ns, fieldPath.Child("authServiceName").Child("namespace"))...)
	}
	allErrs = append(allErrs, validateServiceName(name, fieldPath.Child("authServiceName").Child("name"))...)

	// Validate AuthServicePorts
	allErrs = append(allErrs, validateServicePorts(externalAuth.AuthServicePorts, fieldPath.Child("authServicePorts"))...)

	// Validate AuthSigninURI
	if externalAuth.AuthSigninURI != "" {
		allErrs = append(allErrs, validateAuthURI(externalAuth.AuthSigninURI, fieldPath.Child("authSigninURI"))...)
	}

	// Validate AuthSigninRedirectBasePath
	if externalAuth.AuthSigninRedirectBasePath != "" {
		allErrs = append(allErrs, validateAuthURI(externalAuth.AuthSigninRedirectBasePath, fieldPath.Child("authSigninRedirectBasePath"))...)
	}

	// Validate SSL fields
	if externalAuth.SSLVerify && !externalAuth.SSLEnabled {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("sslVerify"), externalAuth.SSLVerify, "sslEnabled must be true when sslVerify is true"))
	}

	if externalAuth.TrustedCertSecret != "" && !externalAuth.SSLVerify {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("trustedCertSecret"), externalAuth.TrustedCertSecret, "sslVerify must be true when trustedCertSecret is set"))
	}

	if externalAuth.TrustedCertSecret != "" && !externalAuth.SSLEnabled {
		allErrs = append(allErrs, validateSecretName(externalAuth.TrustedCertSecret, fieldPath.Child("trustedCertSecret"))...)
		// If trustedCertSecret is set but sslVerify is false, warn user
		if !externalAuth.SSLVerify {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("sslVerify"), externalAuth.SSLVerify, "sslVerify should be enabled when trustedCertSecret is specified"))
		}
	}

	if externalAuth.SSLVerifyDepth != nil {
		if *externalAuth.SSLVerifyDepth < 0 {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("sslVerifyDepth"), *externalAuth.SSLVerifyDepth, "must be a non-negative integer"))
		}
	}

	return allErrs
}

// validateServicePorts validates the authServicePorts field to ensure it contains valid port numbers
func validateServicePorts(ports []int, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, port := range ports {
		allErrs = append(allErrs, validatePortNumber(strconv.Itoa(port), fieldPath.Index(i))...)
	}
	return allErrs
}

// validateAuthURI validates that the authURI is a valid path and not empty
func validateAuthURI(authURI string, child *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if authURI == "" {
		return append(allErrs, field.Required(child, "authURI is required"))
	}

	allErrs = append(allErrs, validatePath(authURI, child)...)

	return allErrs
}
