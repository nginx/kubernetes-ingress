package k8s

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	ap_validation "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	mergeableIngressTypeAnnotation        = "nginx.org/mergeable-ingress-type"
	lbMethodAnnotation                    = "nginx.org/lb-method"
	healthChecksAnnotation                = "nginx.com/health-checks"
	healthChecksMandatoryAnnotation       = "nginx.com/health-checks-mandatory"
	healthChecksMandatoryQueueAnnotation  = "nginx.com/health-checks-mandatory-queue"
	slowStartAnnotation                   = "nginx.com/slow-start"
	serverTokensAnnotation                = "nginx.org/server-tokens" // #nosec G101
	serverSnippetsAnnotation              = "nginx.org/server-snippets"
	locationSnippetsAnnotation            = "nginx.org/location-snippets"
	proxyConnectTimeoutAnnotation         = "nginx.org/proxy-connect-timeout"
	proxyReadTimeoutAnnotation            = "nginx.org/proxy-read-timeout"
	proxySendTimeoutAnnotation            = "nginx.org/proxy-send-timeout"
	proxyHideHeadersAnnotation            = "nginx.org/proxy-hide-headers"
	proxyPassHeadersAnnotation            = "nginx.org/proxy-pass-headers" // #nosec G101
	proxySetHeadersAnnotation             = "nginx.org/proxy-set-headers"
	clientMaxBodySizeAnnotation           = "nginx.org/client-max-body-size"
	redirectToHTTPSAnnotation             = "nginx.org/redirect-to-https"
	sslRedirectAnnotation                 = "ingress.kubernetes.io/ssl-redirect"
	proxyBufferingAnnotation              = "nginx.org/proxy-buffering"
	hstsAnnotation                        = "nginx.org/hsts"
	hstsMaxAgeAnnotation                  = "nginx.org/hsts-max-age"
	hstsIncludeSubdomainsAnnotation       = "nginx.org/hsts-include-subdomains"
	hstsBehindProxyAnnotation             = "nginx.org/hsts-behind-proxy"
	proxyBuffersAnnotation                = "nginx.org/proxy-buffers"
	proxyBufferSizeAnnotation             = "nginx.org/proxy-buffer-size"
	proxyBusyBuffersSizeAnnotation        = "nginx.org/proxy-busy-buffers-size"
	proxyMaxTempFileSizeAnnotation        = "nginx.org/proxy-max-temp-file-size"
	upstreamZoneSizeAnnotation            = "nginx.org/upstream-zone-size"
	basicAuthSecretAnnotation             = "nginx.org/basic-auth-secret" // #nosec G101
	basicAuthRealmAnnotation              = "nginx.org/basic-auth-realm"
	jwtRealmAnnotation                    = "nginx.com/jwt-realm"
	jwtKeyAnnotation                      = "nginx.com/jwt-key"
	jwtTokenAnnotation                    = "nginx.com/jwt-token" // #nosec G101
	jwtLoginURLAnnotation                 = "nginx.com/jwt-login-url"
	listenPortsAnnotation                 = "nginx.org/listen-ports"
	listenPortsSSLAnnotation              = "nginx.org/listen-ports-ssl"
	keepaliveAnnotation                   = "nginx.org/keepalive"
	maxFailsAnnotation                    = "nginx.org/max-fails"
	maxConnsAnnotation                    = "nginx.org/max-conns"
	failTimeoutAnnotation                 = "nginx.org/fail-timeout"
	appProtectEnableAnnotation            = "appprotect.f5.com/app-protect-enable"
	appProtectSecurityLogEnableAnnotation = "appprotect.f5.com/app-protect-security-log-enable"
	appProtectPolicyAnnotation            = "appprotect.f5.com/app-protect-policy"
	appProtectSecurityLogAnnotation       = "appprotect.f5.com/app-protect-security-log"
	appProtectSecurityLogDestAnnotation   = "appprotect.f5.com/app-protect-security-log-destination"
	appProtectDosProtectedAnnotation      = "appprotectdos.f5.com/app-protect-dos-resource"
	internalRouteAnnotation               = "nsm.nginx.com/internal-route"
	websocketServicesAnnotation           = "nginx.org/websocket-services"
	sslServicesAnnotation                 = "nginx.org/ssl-services"
	grpcServicesAnnotation                = "nginx.org/grpc-services"
	rewritesAnnotation                    = "nginx.org/rewrites"
	stickyCookieServicesAnnotation        = "nginx.com/sticky-cookie-services"
	pathRegexAnnotation                   = "nginx.org/path-regex"
	useClusterIPAnnotation                = "nginx.org/use-cluster-ip"
)

const (
	commaDelimiter     = ","
	annotationValueFmt = `([^"$\\]|\\[^$])*`
	jwtTokenValueFmt   = "\\$" + annotationValueFmt
)

const (
	annotationValueFmtErrMsg = `a valid annotation value must have all '"' escaped and must not contain any '$' or end with an unescaped '\'`
	jwtTokenValueFmtErrMsg   = `a valid annotation value must start with '$', have all '"' escaped, and must not contain any '$' or end with an unescaped '\'`
)

var (
	validAnnotationValueRegex         = regexp.MustCompile("^" + annotationValueFmt + "$")
	validJWTTokenAnnotationValueRegex = regexp.MustCompile("^" + jwtTokenValueFmt + "$")
)

type annotationValidationContext struct {
	annotations           map[string]string
	specServices          map[string]bool
	name                  string
	value                 string
	isPlus                bool
	appProtectEnabled     bool
	appProtectDosEnabled  bool
	internalRoutesEnabled bool
	fieldPath             *field.Path
	snippetsEnabled       bool
	directiveAutoadjust   bool
}

type (
	annotationValidationFunc   func(context *annotationValidationContext) field.ErrorList
	annotationValidationConfig map[string][]annotationValidationFunc
	validatorFunc              func(val string) error
)

var (
	// annotationValidations defines the various validations which will be applied in order to each ingress annotation.
	// If any specified validation fails, the remaining validations for that annotation will not be run.
	annotationValidations = annotationValidationConfig{
		mergeableIngressTypeAnnotation: {
			validateRequiredAnnotation,
			validateMergeableIngressTypeAnnotation,
		},
		lbMethodAnnotation: {
			validateRequiredAnnotation,
			validateLBMethodAnnotation,
		},
		healthChecksAnnotation: {
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		healthChecksMandatoryAnnotation: {
			validatePlusOnlyAnnotation,
			validateRelatedAnnotation(healthChecksAnnotation, validateIsTrue),
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		healthChecksMandatoryQueueAnnotation: {
			validatePlusOnlyAnnotation,
			validateRelatedAnnotation(healthChecksMandatoryAnnotation, validateIsTrue),
			validateRequiredAnnotation,
			validateUint64Annotation,
		},
		slowStartAnnotation: {
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateTimeAnnotation,
		},
		serverTokensAnnotation: {
			validateServerTokensAnnotation,
		},
		serverSnippetsAnnotation: {
			validateSnippetsAnnotation,
		},
		locationSnippetsAnnotation: {
			validateSnippetsAnnotation,
		},
		proxyConnectTimeoutAnnotation: {
			validateRequiredAnnotation,
			validateTimeAnnotation,
		},
		proxyReadTimeoutAnnotation: {
			validateRequiredAnnotation,
			validateTimeAnnotation,
		},
		proxySendTimeoutAnnotation: {
			validateRequiredAnnotation,
			validateTimeAnnotation,
		},
		proxyHideHeadersAnnotation: {
			validateHTTPHeadersAnnotation,
		},
		proxyPassHeadersAnnotation: {
			validateHTTPHeadersAnnotation,
		},
		proxySetHeadersAnnotation: {
			validateProxySetHeaderAnnotation,
		},
		clientMaxBodySizeAnnotation: {
			validateRequiredAnnotation,
			validateOffsetAnnotation,
		},
		redirectToHTTPSAnnotation: {
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		sslRedirectAnnotation: {
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		proxyBufferingAnnotation: {
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		hstsAnnotation: {
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		hstsMaxAgeAnnotation: {
			validateRelatedAnnotation(hstsAnnotation, validateIsBool),
			validateRequiredAnnotation,
			validateInt64Annotation,
		},
		hstsIncludeSubdomainsAnnotation: {
			validateRelatedAnnotation(hstsAnnotation, validateIsBool),
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		hstsBehindProxyAnnotation: {
			validateRelatedAnnotation(hstsAnnotation, validateIsBool),
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		proxyBuffersAnnotation: {
			validateRequiredAnnotation,
			validateProxyBuffersAnnotation,
		},
		proxyBufferSizeAnnotation: {
			validateRequiredAnnotation,
			validateSizeAnnotation,
		},
		proxyBusyBuffersSizeAnnotation: {
			validateSizeAnnotation,
		},
		proxyMaxTempFileSizeAnnotation: {
			validateRequiredAnnotation,
			validateSizeAnnotation,
		},
		upstreamZoneSizeAnnotation: {
			validateRequiredAnnotation,
			validateSizeAnnotation,
		},
		basicAuthSecretAnnotation: {
			validateRequiredAnnotation,
			validateSecretNameAnnotation,
		},
		basicAuthRealmAnnotation: {
			validateRelatedAnnotation(basicAuthSecretAnnotation, validateNoop),
			validateRealmAnnotation,
		},
		jwtRealmAnnotation: {
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateJWTRealm,
		},
		jwtKeyAnnotation: {
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateJWTKey,
		},
		jwtTokenAnnotation: {
			validatePlusOnlyAnnotation,
			validateJWTTokenAnnotation,
		},
		jwtLoginURLAnnotation: {
			validatePlusOnlyAnnotation,
			validateJWTLoginURLAnnotation,
		},
		listenPortsAnnotation: {
			validateRequiredAnnotation,
			validatePortListAnnotation,
		},
		listenPortsSSLAnnotation: {
			validateRequiredAnnotation,
			validatePortListAnnotation,
		},
		keepaliveAnnotation: {
			validateRequiredAnnotation,
			validateIntAnnotation,
		},
		maxFailsAnnotation: {
			validateRequiredAnnotation,
			validateUint64Annotation,
		},
		maxConnsAnnotation: {
			validateRequiredAnnotation,
			validateUint64Annotation,
		},
		failTimeoutAnnotation: {
			validateRequiredAnnotation,
			validateTimeAnnotation,
		},
		appProtectEnableAnnotation: {
			validateAppProtectOnlyAnnotation,
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		appProtectSecurityLogEnableAnnotation: {
			validateAppProtectOnlyAnnotation,
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		appProtectPolicyAnnotation: {
			validateAppProtectOnlyAnnotation,
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateQualifiedName,
		},
		appProtectSecurityLogAnnotation: {
			validateAppProtectOnlyAnnotation,
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateAppProtectSecurityLogAnnotation,
		},
		appProtectSecurityLogDestAnnotation: {
			validateAppProtectOnlyAnnotation,
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateAppProtectSecurityLogDestAnnotation,
		},
		appProtectDosProtectedAnnotation: {
			validateAppProtectDosOnlyAnnotation,
			validatePlusOnlyAnnotation,
			validateQualifiedName,
		},
		internalRouteAnnotation: {
			validateInternalRoutesOnlyAnnotation,
			validateRequiredAnnotation,
			validateBoolAnnotation,
		},
		websocketServicesAnnotation: {
			validateRequiredAnnotation,
			validateServiceListAnnotation,
		},
		sslServicesAnnotation: {
			validateRequiredAnnotation,
			validateServiceListAnnotation,
		},
		grpcServicesAnnotation: {
			validateRequiredAnnotation,
			validateServiceListAnnotation,
		},
		rewritesAnnotation: {
			validateRequiredAnnotation,
			validateRewriteListAnnotation,
		},
		stickyCookieServicesAnnotation: {
			validatePlusOnlyAnnotation,
			validateRequiredAnnotation,
			validateStickyServiceListAnnotation,
		},
		pathRegexAnnotation: {
			validatePathRegex,
		},
		useClusterIPAnnotation: {
			validateBoolAnnotation,
		},
	}
	annotationNames = sortedAnnotationNames(annotationValidations)
)

func validatePathRegex(context *annotationValidationContext) field.ErrorList {
	switch context.value {
	case "case_sensitive", "case_insensitive", "exact":
		return nil
	default:
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "allowed values: 'case_sensitive', 'case_insensitive' or 'exact'")}
	}
}

func validateJWTLoginURLAnnotation(context *annotationValidationContext) field.ErrorList {
	allErrs := field.ErrorList{}

	name := context.value

	u, err := url.Parse(name)
	if err != nil {
		return append(allErrs, field.Invalid(context.fieldPath, name, err.Error()))
	}
	var msg string
	if u.Scheme == "" {
		msg = "scheme required, please use the prefix http(s)://"
		return append(allErrs, field.Invalid(context.fieldPath, name, msg))
	}
	if u.Host == "" {
		msg = "hostname required"
		return append(allErrs, field.Invalid(context.fieldPath, name, msg))
	}

	return allErrs
}

func validateJWTKey(context *annotationValidationContext) field.ErrorList {
	allErrs := field.ErrorList{}

	for _, msg := range validation.IsDNS1123Subdomain(context.value) {
		allErrs = append(allErrs, field.Invalid(context.fieldPath, context.value, msg))
	}

	return allErrs
}

func validateJWTRealm(context *annotationValidationContext) field.ErrorList {
	if !validAnnotationValueRegex.MatchString(context.value) {
		msg := validation.RegexError(annotationValueFmtErrMsg, annotationValueFmt, "My Realm", "Cafe App")
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, msg)}
	}
	return nil
}

func validateJWTTokenAnnotation(context *annotationValidationContext) field.ErrorList {
	if !validJWTTokenAnnotationValueRegex.MatchString(context.value) {
		msg := validation.RegexError(jwtTokenValueFmtErrMsg, jwtTokenValueFmt, "$http_token", "$cookie_auth_token")
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, msg)}
	}
	return nil
}

func validateHTTPHeadersAnnotation(context *annotationValidationContext) field.ErrorList {
	var allErrs field.ErrorList
	headers := strings.Split(context.value, commaDelimiter)

	for _, header := range headers {
		header = strings.TrimSpace(header)
		for _, msg := range validation.IsHTTPHeaderName(header) {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, header, msg))
		}
	}
	return allErrs
}

func validateProxySetHeaderAnnotation(context *annotationValidationContext) field.ErrorList {
	var allErrs field.ErrorList
	headers := strings.Split(context.value, commaDelimiter)

	for _, header := range headers {
		header = strings.TrimSpace(header)

		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 1 && strings.Contains(header, " ") {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, header, "invalid header syntax - spaces are not allowed in header"))
		}

		if len(parts) != 2 {
			parts = append(parts, "")
		}

		name := strings.TrimSpace(parts[0])
		for _, msg := range validation.IsHTTPHeaderName(name) {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, name, msg))
		}

		value := strings.TrimSpace(parts[1])

		if strings.Contains(value, "$") {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, header, "invalid character in value: $"))
		}

		if name == "" {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, header, "empty header name: "+header))
			continue
		}

		if name == "" && value == "" {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, header, "invalid header syntax: "+header))
			continue
		}
	}
	return allErrs
}

func sortedAnnotationNames(annotationValidations annotationValidationConfig) []string {
	sortedNames := make([]string, 0)
	for annotationName := range annotationValidations {
		sortedNames = append(sortedNames, annotationName)
	}
	sort.Strings(sortedNames)
	return sortedNames
}

// validateIngress validate an Ingress resource with rules that our Ingress Controller enforces.
// Note that the full validation of Ingress resources is done by Kubernetes.
func validateIngress(
	ing *networking.Ingress,
	isPlus bool,
	appProtectEnabled bool,
	appProtectDosEnabled bool,
	internalRoutesEnabled bool,
	snippetsEnabled bool,
	directiveAutoadjust bool,
) field.ErrorList {
	allErrs := validateIngressAnnotations(
		ing.Annotations,
		getSpecServices(ing.Spec),
		isPlus,
		appProtectEnabled,
		appProtectDosEnabled,
		internalRoutesEnabled,
		field.NewPath("annotations"),
		snippetsEnabled,
		directiveAutoadjust,
	)

	allErrs = append(allErrs, validateIngressSpec(&ing.Spec, field.NewPath("spec"))...)

	if isMaster(ing) {
		allErrs = append(allErrs, validateMasterSpec(&ing.Spec, field.NewPath("spec"))...)
	} else if isMinion(ing) {
		allErrs = append(allErrs, validateMinionSpec(&ing.Spec, field.NewPath("spec"))...)
	}

	if isChallengeIngress(ing) {
		allErrs = append(allErrs, validateChallengeIngress(&ing.Spec, field.NewPath("spec"))...)
	}

	return allErrs
}

func validateChallengeIngress(spec *networking.IngressSpec, fieldPath *field.Path) field.ErrorList {
	if spec.Rules == nil || len(spec.Rules) != 1 {
		return field.ErrorList{field.Forbidden(fieldPath.Child("rules"), "challenge Ingress must have exactly 1 rule defined")}
	}
	r := spec.Rules[0]

	if r.HTTP == nil || r.HTTP.Paths == nil || len(r.HTTP.Paths) != 1 {
		return field.ErrorList{field.Forbidden(fieldPath.Child("rules.HTTP.Paths"), "challenge Ingress must have exactly 1 path defined")}
	}

	p := r.HTTP.Paths[0]

	allErrs := field.ErrorList{}
	if p.Backend.Service == nil {
		allErrs = append(allErrs, field.Required(fieldPath.Child("rules.HTTP.Paths[0].Backend.Service"), "challenge Ingress must have a Backend Service defined"))
	}

	if p.Backend.Service.Port.Name != "" {
		allErrs = append(allErrs, field.Forbidden(fieldPath.Child("rules.HTTP.Paths[0].Backend.Service.Port.Name"), "challenge Ingress must have a Backend Service Port Number defined, not Name"))
	}
	return allErrs
}

func validateIngressAnnotations(
	annotations map[string]string,
	specServices map[string]bool,
	isPlus bool,
	appProtectEnabled bool,
	appProtectDosEnabled bool,
	internalRoutesEnabled bool,
	fieldPath *field.Path,
	snippetsEnabled bool,
	directiveAutoadjust bool,
) field.ErrorList {
	allErrs := field.ErrorList{}

	for _, name := range annotationNames {
		if value, exists := annotations[name]; exists {
			context := &annotationValidationContext{
				annotations:           annotations,
				specServices:          specServices,
				name:                  name,
				value:                 value,
				isPlus:                isPlus,
				appProtectEnabled:     appProtectEnabled,
				appProtectDosEnabled:  appProtectDosEnabled,
				internalRoutesEnabled: internalRoutesEnabled,
				fieldPath:             fieldPath.Child(name),
				snippetsEnabled:       snippetsEnabled,
				directiveAutoadjust:   directiveAutoadjust,
			}
			allErrs = append(allErrs, validateIngressAnnotation(context)...)
		}
	}

	return allErrs
}

func validateIngressAnnotation(context *annotationValidationContext) field.ErrorList {
	allErrs := field.ErrorList{}
	if validationFuncs, exists := annotationValidations[context.name]; exists {
		for _, validationFunc := range validationFuncs {
			valErrors := validationFunc(context)
			if len(valErrors) > 0 {
				allErrs = append(allErrs, valErrors...)
				break
			}
		}
	}
	return allErrs
}

func validateRelatedAnnotation(name string, validator validatorFunc) annotationValidationFunc {
	return func(context *annotationValidationContext) field.ErrorList {
		val, exists := context.annotations[name]
		if !exists {
			return field.ErrorList{field.Forbidden(context.fieldPath, fmt.Sprintf("related annotation %s: must be set", name))}
		}

		if err := validator(val); err != nil {
			return field.ErrorList{field.Forbidden(context.fieldPath, fmt.Sprintf("related annotation %s: %s", name, err.Error()))}
		}
		return nil
	}
}

func validateQualifiedName(context *annotationValidationContext) field.ErrorList {
	err := validation.IsQualifiedName(context.value)
	if err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a qualified name")}
	}
	return nil
}

func validateMergeableIngressTypeAnnotation(context *annotationValidationContext) field.ErrorList {
	if context.value != "master" && context.value != "minion" {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be one of: 'master' or 'minion'")}
	}
	return nil
}

func validateLBMethodAnnotation(context *annotationValidationContext) field.ErrorList {
	parseFunc := configs.ParseLBMethod
	if context.isPlus {
		parseFunc = configs.ParseLBMethodForPlus
	}
	if _, err := parseFunc(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, err.Error())}
	}
	return nil
}

func validateServerTokensAnnotation(context *annotationValidationContext) field.ErrorList {
	if !context.isPlus {
		if _, err := configs.ParseBool(context.value); err != nil {
			return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a boolean")}
		}
	}
	if !validAnnotationValueRegex.MatchString(context.value) {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, annotationValueFmtErrMsg)}
	}
	return nil
}

func validateRequiredAnnotation(context *annotationValidationContext) field.ErrorList {
	if context.value == "" {
		return field.ErrorList{field.Required(context.fieldPath, "")}
	}
	return nil
}

func validatePlusOnlyAnnotation(context *annotationValidationContext) field.ErrorList {
	if !context.isPlus {
		return field.ErrorList{field.Forbidden(context.fieldPath, "annotation requires NGINX Plus")}
	}
	return nil
}

func validateAppProtectOnlyAnnotation(context *annotationValidationContext) field.ErrorList {
	if !context.appProtectEnabled {
		return field.ErrorList{field.Forbidden(context.fieldPath, "annotation requires AppProtect")}
	}
	return nil
}

func validateAppProtectDosOnlyAnnotation(context *annotationValidationContext) field.ErrorList {
	if !context.appProtectDosEnabled {
		return field.ErrorList{field.Forbidden(context.fieldPath, "annotation requires AppProtectDos")}
	}
	return nil
}

func validateInternalRoutesOnlyAnnotation(context *annotationValidationContext) field.ErrorList {
	if !context.internalRoutesEnabled {
		return field.ErrorList{field.Forbidden(context.fieldPath, "annotation requires Internal Routes enabled")}
	}
	return nil
}

func validateBoolAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseBool(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a boolean")}
	}
	return nil
}

func validateTimeAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseTime(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a time")}
	}
	return nil
}

func validateOffsetAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseOffset(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be an offset")}
	}
	return nil
}

func validateSizeAnnotation(context *annotationValidationContext) field.ErrorList {
	return ap_validation.ValidateSize(context.value, context.fieldPath)
}

func validateProxyBuffersAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseProxyBuffersSpec(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a proxy buffer spec")}
	}
	return nil
}

func validateUint64Annotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseUint64(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a non-negative integer")}
	}
	return nil
}

func validateInt64Annotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseInt64(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be an integer")}
	}
	return nil
}

func validateIntAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseInt(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be an integer")}
	}
	return nil
}

func validatePortListAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParsePortList(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, "must be a comma-separated list of port numbers")}
	}
	return nil
}

func validateServiceListAnnotation(context *annotationValidationContext) field.ErrorList {
	var unknownServices []string
	annotationServices := configs.ParseServiceList(context.value)
	for svc := range annotationServices {
		if _, exists := context.specServices[svc]; !exists {
			unknownServices = append(unknownServices, svc)
		}
	}
	if len(unknownServices) > 0 {
		errorMsg := fmt.Sprintf(
			"must be a comma-separated list of services. The following services were not found: %s",
			strings.Join(unknownServices, commaDelimiter),
		)
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, errorMsg)}
	}
	return nil
}

func validateStickyServiceListAnnotation(context *annotationValidationContext) field.ErrorList {
	if _, err := configs.ParseStickyServiceList(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, err.Error())}
	}
	return nil
}

func validateRewriteListAnnotation(context *annotationValidationContext) field.ErrorList {
	var unknownServices []string
	rewrites, err := configs.ParseRewriteList(context.value)
	if err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, err.Error())}
	}
	for rewrite := range rewrites {
		if _, exists := context.specServices[rewrite]; !exists {
			unknownServices = append(unknownServices, rewrite)
		}
	}
	if len(unknownServices) > 0 {
		errorMsg := fmt.Sprintf(
			"The following services were not found: %s",
			strings.Join(unknownServices, commaDelimiter),
		)
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, errorMsg)}
	}
	return nil
}

func validateAppProtectSecurityLogAnnotation(context *annotationValidationContext) field.ErrorList {
	allErrs := field.ErrorList{}
	logConf := strings.Split(context.value, ",")
	for _, logConf := range logConf {
		err := validation.IsQualifiedName(logConf)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, context.value, "security log configuration resource name must be qualified name, e.g. namespace/name"))
		}
	}
	return allErrs
}

func validateAppProtectSecurityLogDestAnnotation(context *annotationValidationContext) field.ErrorList {
	allErrs := field.ErrorList{}
	logDsts := strings.Split(context.value, ",")
	for _, logDst := range logDsts {
		err := ap_validation.ValidateAppProtectLogDestination(logDst)
		if err != nil {
			errorMsg := fmt.Sprintf("Error Validating App Protect Log Destination Config: %v", err)
			allErrs = append(allErrs, field.Invalid(context.fieldPath, context.value, errorMsg))
		}
	}
	return allErrs
}

func validateSnippetsAnnotation(context *annotationValidationContext) field.ErrorList {
	if !context.snippetsEnabled {
		return field.ErrorList{field.Forbidden(context.fieldPath, "snippet specified but snippets feature is not enabled")}
	}
	return nil
}

func validateSecretNameAnnotation(context *annotationValidationContext) field.ErrorList {
	if msgs := validation.IsDNS1123Subdomain(context.value); msgs != nil {
		allErrs := field.ErrorList{}
		for _, msg := range msgs {
			allErrs = append(allErrs, field.Invalid(context.fieldPath, context.value, msg))
		}
		return allErrs
	}
	return nil
}

func validateRealmAnnotation(context *annotationValidationContext) field.ErrorList {
	if err := validateIsValidRealm(context.value); err != nil {
		return field.ErrorList{field.Invalid(context.fieldPath, context.value, err.Error())}
	}
	return nil
}

func validateIsBool(v string) error {
	_, err := configs.ParseBool(v)
	return err
}

func validateIsTrue(v string) error {
	b, err := configs.ParseBool(v)
	if err != nil {
		return err
	}
	if !b {
		return errors.New("must be true")
	}
	return nil
}

func validateNoop(_ string) error {
	return nil
}

var realmFmtRegexp = regexp.MustCompile(`^([^"$\\]|\\[^$])*$`)

func validateIsValidRealm(v string) error {
	if !realmFmtRegexp.MatchString(v) {
		return errors.New(`a valid realm must have all '"' escaped and must not contain any '$' or end with an unescaped '\'`)
	}
	return nil
}

func validateIngressSpec(spec *networking.IngressSpec, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if spec.DefaultBackend != nil {
		allErrs = append(allErrs, validateBackend(spec.DefaultBackend, fieldPath.Child("defaultBackend"))...)
	}

	allHosts := sets.Set[string]{}

	if len(spec.Rules) == 0 {
		return append(allErrs, field.Required(fieldPath.Child("rules"), ""))
	}

	for i, r := range spec.Rules {
		idxRule := fieldPath.Child("rules").Index(i)

		if r.Host == "" {
			allErrs = append(allErrs, field.Required(idxRule.Child("host"), ""))
		} else if allHosts.Has(r.Host) {
			allErrs = append(allErrs, field.Duplicate(idxRule.Child("host"), r.Host))
		} else {
			allHosts.Insert(r.Host)
		}

		if r.HTTP == nil {
			continue
		}

		for _, path := range r.HTTP.Paths {
			path := path // address gosec G601
			idxPath := idxRule.Child("http").Child("path").Index(i)

			allErrs = append(allErrs, validatePath(path.Path, path.PathType, idxPath.Child("path"))...)
			allErrs = append(allErrs, validateBackend(&path.Backend, idxPath.Child("backend"))...)
		}
	}

	return allErrs
}

func validateBackend(backend *networking.IngressBackend, fieldPath *field.Path) field.ErrorList {
	if backend.Resource != nil {
		return field.ErrorList{field.Forbidden(fieldPath.Child("resource"), "resource backends are not supported")}
	}
	return nil
}

const (
	pathFmt    = `/[^\s;]*`
	pathErrMsg = "must start with / and must not include any whitespace character or `;`"
)

var pathRegexp = regexp.MustCompile("^" + pathFmt + "$")

func validatePath(path string, pathType *networking.PathType, fieldPath *field.Path) field.ErrorList {
	if path == "" && pathType != nil && *pathType == networking.PathTypeImplementationSpecific {
		// No path defined - no further validation needed.
		// Path is not required for ImplementationSpecific PathType - it will default to /.
		return nil
	}

	if path == "" {
		return field.ErrorList{field.Required(fieldPath, "path is required for Exact and Prefix PathTypes")}
	}

	if !pathRegexp.MatchString(path) {
		msg := validation.RegexError(pathErrMsg, pathFmt, "/", "/path", "/path/subpath-123")
		return field.ErrorList{field.Invalid(fieldPath, path, msg)}
	}

	allErrs := validateRegexPath(path, fieldPath)
	allErrs = append(allErrs, validateCurlyBraces(path, fieldPath)...)
	allErrs = append(allErrs, validateIllegalKeywords(path, fieldPath)...)

	return allErrs
}

// validateRegexPath validates correctness of the string representing the path.
//
// Internally it uses Perl5 compatible regexp2 package.
func validateRegexPath(path string, fieldPath *field.Path) field.ErrorList {
	if _, err := regexp2.Compile(path, 0); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, path, fmt.Sprintf("must be a valid regular expression: %v", err))}
	}
	if err := ValidateEscapedString(path, "*.jpg", "^/images/image_*.png$"); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, path, err.Error())}
	}
	return nil
}

const (
	curlyBracesFmt = `\{(.*?)\}`
	alphabetFmt    = `[A-Za-z]`
	curlyBracesMsg = `must not include curly braces containing alphabetical characters`
)

var (
	curlyBracesFmtRegexp = regexp.MustCompile(curlyBracesFmt)
	alphabetFmtRegexp    = regexp.MustCompile(alphabetFmt)
)

func validateCurlyBraces(path string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	bracesContents := curlyBracesFmtRegexp.FindAllStringSubmatch(path, -1)
	for _, v := range bracesContents {
		if alphabetFmtRegexp.MatchString(v[1]) {
			return append(allErrs, field.Invalid(fieldPath, path, curlyBracesMsg))
		}
	}
	return allErrs
}

const (
	escapedStringsFmt    = `([^"\\]|\\.)*`
	escapedStringsErrMsg = `must have all '"' (double quotes) escaped and must not end with an unescaped '\' (backslash)`
)

var escapedStringsFmtRegexp = regexp.MustCompile("^" + escapedStringsFmt + "$")

// ValidateEscapedString validates an escaped string.
func ValidateEscapedString(body string, examples ...string) error {
	if !escapedStringsFmtRegexp.MatchString(body) {
		msg := validation.RegexError(escapedStringsErrMsg, escapedStringsFmt, examples...)
		return errors.New(msg)
	}
	return nil
}

const (
	illegalKeywordFmt    = `/etc/|/root|/var|\\n|\\r`
	illegalKeywordErrMsg = `must not contain invalid paths`
)

var illegalKeywordFmtRegexp = regexp.MustCompile("^" + illegalKeywordFmt + "$")

func validateIllegalKeywords(path string, fieldPath *field.Path) field.ErrorList {
	if illegalKeywordFmtRegexp.MatchString(path) {
		return field.ErrorList{field.Invalid(fieldPath, path, illegalKeywordErrMsg)}
	}
	return nil
}

func validateMasterSpec(spec *networking.IngressSpec, fieldPath *field.Path) field.ErrorList {
	if len(spec.Rules) != 1 {
		return field.ErrorList{field.TooMany(fieldPath.Child("rules"), len(spec.Rules), 1)}
	}
	// the number of paths of the first rule of the spec must be 0
	if spec.Rules[0].HTTP != nil && len(spec.Rules[0].HTTP.Paths) > 0 {
		pathsField := fieldPath.Child("rules").Index(0).Child("http").Child("paths")
		return field.ErrorList{field.TooMany(pathsField, len(spec.Rules[0].HTTP.Paths), 0)}
	}
	return nil
}

func validateMinionSpec(spec *networking.IngressSpec, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(spec.TLS) > 0 {
		allErrs = append(allErrs, field.TooMany(fieldPath.Child("tls"), len(spec.TLS), 0))
	}

	if len(spec.Rules) != 1 {
		return append(allErrs, field.TooMany(fieldPath.Child("rules"), len(spec.Rules), 1))
	}

	// the number of paths of the first rule of the spec must be greater than 0
	if spec.Rules[0].HTTP == nil || len(spec.Rules[0].HTTP.Paths) == 0 {
		pathsField := fieldPath.Child("rules").Index(0).Child("http").Child("paths")
		return append(allErrs, field.Required(pathsField, "must include at least one path"))
	}

	return allErrs
}

func getSpecServices(ingressSpec networking.IngressSpec) map[string]bool {
	services := make(map[string]bool)
	if ingressSpec.DefaultBackend != nil && ingressSpec.DefaultBackend.Service != nil {
		services[ingressSpec.DefaultBackend.Service.Name] = true
	}
	for _, rule := range ingressSpec.Rules {
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					services[path.Backend.Service.Name] = true
				}
			}
		}
	}
	return services
}
