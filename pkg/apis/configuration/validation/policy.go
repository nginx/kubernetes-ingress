package validation

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidatePolicy validates a Policy.
func ValidatePolicy(policy *v1alpha1.Policy) error {
	allErrs := validatePolicySpec(&policy.Spec, field.NewPath("spec"))
	return allErrs.ToAggregate()
}

func validatePolicySpec(spec *v1alpha1.PolicySpec, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	fieldCount := 0

	if spec.AccessControl != nil {
		allErrs = append(allErrs, validateAccessControl(spec.AccessControl, fieldPath.Child("accessControl"))...)
		fieldCount++
	}

	if spec.RateLimit != nil {
		allErrs = append(allErrs, validateRateLimit(spec.RateLimit, fieldPath.Child("rateLimit"))...)
		fieldCount++
	}

	if fieldCount != 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", "must specify exactly one of: `accessControl`, `rateLimit`"))
	}

	return allErrs
}

func validateAccessControl(accessControl *v1alpha1.AccessControl, fieldPath *field.Path) field.ErrorList {
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

func validateRateLimit(rateLimit *v1alpha1.RateLimit, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateRateLimitZoneSize(rateLimit.ZoneSize, fieldPath.Child("zoneSize"))...)
	allErrs = append(allErrs, validateRate(rateLimit.Rate, fieldPath.Child("rate"))...)
	allErrs = append(allErrs, validateRateLimitKey(rateLimit.Key, fieldPath.Child("key"))...)

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
		if *rateLimit.RejectCode < 400 || *rateLimit.RejectCode > 600 {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("rejectCode"), rateLimit.RejectCode,
				"must be within the range [400-600]"))
		}
	}

	return allErrs
}

const rateFmt = `[1-9]\d*r/[sSmM]`
const rateErrMsg = "must consist of numeric characters followed by a valid rate suffix. 'r/s|r/m"

var rateRegexp = regexp.MustCompile("^" + rateFmt + "$")

func validateRate(rate string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if rate == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	if !rateRegexp.MatchString(rate) {
		msg := validation.RegexError(rateErrMsg, rateFmt, "16r/s", "32r/m", "64r/s")
		return append(allErrs, field.Invalid(fieldPath, rate, msg))
	}
	return allErrs
}

func validateRateLimitZoneSize(zoneSize string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if zoneSize == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	allErrs = append(allErrs, validateSize(zoneSize, fieldPath)...)

	kbZoneSize := strings.TrimSuffix(strings.ToLower(zoneSize), "k")
	kbZoneSizeNum, err := strconv.Atoi(kbZoneSize)

	mbZoneSize := strings.TrimSuffix(strings.ToLower(zoneSize), "m")
	mbZoneSizeNum, mbErr := strconv.Atoi(mbZoneSize)

	if err == nil && kbZoneSizeNum < 32 || mbErr == nil && mbZoneSizeNum == 0 {
		allErrs = append(allErrs, field.Invalid(fieldPath, zoneSize, "must be greater than 31k"))
	}

	return allErrs
}

var rateLimitKeySpecialVariables = []string{"arg_", "http_", "cookie_"}

// rateLimitVariables includes NGINX variables allowed to be used in a rateLimit policy key.
var rateLimitKeyVariables = map[string]bool{
	"binary_remote_addr": true,
	"request_uri":        true,
	"uri":                true,
	"args":               true,
}

func validateRateLimitKey(key string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if key == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	if !escapedStringsFmtRegexp.MatchString(key) {
		msg := validation.RegexError(escapedStringsErrMsg, escapedStringsFmt, `Hello World! \n`, `\"${request_uri}\" is unavailable. \n`)
		allErrs = append(allErrs, field.Invalid(fieldPath, key, msg))
	}

	allErrs = append(allErrs, validateStringWithVariables(key, fieldPath, rateLimitKeySpecialVariables, rateLimitKeyVariables)...)

	return allErrs
}

var validLogLevels = map[string]bool{
	"info":   true,
	"notice": true,
	"warn":   true,
	"error":  true,
}

func validateRateLimitLogLevel(logLevel string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if !validLogLevels[logLevel] {
		allErrs = append(allErrs, field.Invalid(fieldPath, logLevel, fmt.Sprintf("Accepted values: %s",
			mapToPrettyString(validLogLevels))))
	}

	return allErrs
}

func validateIPorCIDR(ipOrCIDR string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	_, _, err := net.ParseCIDR(ipOrCIDR)
	if err == nil {
		// valid CIDR
		return allErrs
	}

	ip := net.ParseIP(ipOrCIDR)
	if ip != nil {
		// valid IP
		return allErrs
	}

	return append(allErrs, field.Invalid(fieldPath, ipOrCIDR, "must be a CIDR or IP"))
}

func validatePositiveInt(n int, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if n <= 0 {
		return append(allErrs, field.Invalid(fieldPath, n, "must be positive"))
	}

	return allErrs
}
