package validation

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

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

func validateVariable(nVar string, validVars map[string]bool, fieldPath *field.Path) field.ErrorList {
	if !validVars[nVar] {
		msg := fmt.Sprintf("'%v' contains an invalid NGINX variable. Accepted variables are: %v", nVar, mapToPrettyString(validVars))
		return field.ErrorList{field.Invalid(fieldPath, nVar, msg)}
	}
	return nil
}

// isValidSpecialHeaderLikeVariable validates special variables $http_, $jwt_header_, $jwt_claim_
func isValidSpecialHeaderLikeVariable(value string) []string {
	// underscores in a header-like variable represent '-'.
	errMsgs := validation.IsHTTPHeaderName(strings.Replace(value, "_", "-", -1))
	if len(errMsgs) >= 1 || strings.Contains(value, "-") {
		return []string{"a valid special variable must consists of alphanumeric characters or '_'"}
	}
	return nil
}

func parseSpecialVariable(nVar string, fieldPath *field.Path) (name string, value string, allErrs field.ErrorList) {
	// parse NGINX Plus variables
	if strings.HasPrefix(nVar, "jwt_header") || strings.HasPrefix(nVar, "jwt_claim") {
		parts := strings.SplitN(nVar, "_", 3)
		if len(parts) != 3 {
			allErrs = append(allErrs, field.Invalid(fieldPath, nVar, "is invalid variable"))
			return name, value, allErrs
		}

		// ex: jwt_header_name_one -> jwt_header, name_one
		return strings.Join(parts[:2], "_"), parts[2], allErrs
	}

	// parse common NGINX and NGINX Plus variables
	parts := strings.SplitN(nVar, "_", 2)
	if len(parts) != 2 {
		allErrs = append(allErrs, field.Invalid(fieldPath, nVar, "is invalid variable"))
		return name, value, allErrs
	}

	// ex: http_name_one -> http, name_one
	return parts[0], parts[1], allErrs
}

func validateSpecialVariable(nVar string, fieldPath *field.Path, isPlus bool) field.ErrorList {
	name, value, allErrs := parseSpecialVariable(nVar, fieldPath)
	if len(allErrs) > 0 {
		return allErrs
	}

	addErrors := func(errors []string) {
		for _, msg := range errors {
			allErrs = append(allErrs, field.Invalid(fieldPath, nVar, msg))
		}
	}

	switch name {
	case "arg":
		addErrors(isArgumentName(value))
	case "http":
		addErrors(isValidSpecialHeaderLikeVariable(value))
	case "cookie":
		addErrors(isCookieName(value))
	case "jwt_header", "jwt_claim":
		if !isPlus {
			allErrs = append(allErrs, field.Forbidden(fieldPath, "is only supported in NGINX Plus"))
		} else {
			addErrors(isValidSpecialHeaderLikeVariable(value))
		}
	case "apikey":
		addErrors(isValidSpecialHeaderLikeVariable(value))
	default:
		allErrs = append(allErrs, field.Invalid(fieldPath, nVar, "unknown special variable"))
	}

	return allErrs
}

func validateStringWithVariables(str string, fieldPath *field.Path, specialVars []string, validVars map[string]bool, isPlus bool) field.ErrorList {
	if strings.HasSuffix(str, "$") {
		return field.ErrorList{field.Invalid(fieldPath, str, "must not end with $")}
	}

	allErrs := field.ErrorList{}
	for i, c := range str {
		if c == '$' {
			msg := "variables must be enclosed in curly braces, for example ${host}"

			if str[i+1] != '{' {
				return field.ErrorList{field.Invalid(fieldPath, str, msg)}
			}

			if !strings.Contains(str[i+1:], "}") {
				return field.ErrorList{field.Invalid(fieldPath, str, msg)}
			}
		}
	}

	nginxVars := captureVariables(str)
	for _, nVar := range nginxVars {
		special := false
		for _, specialVar := range specialVars {
			if strings.HasPrefix(nVar, specialVar) {
				special = true
				break
			}
		}

		if special {
			allErrs = append(allErrs, validateSpecialVariable(nVar, fieldPath, isPlus)...)
		} else {
			allErrs = append(allErrs, validateVariable(nVar, validVars, fieldPath)...)
		}
	}

	return allErrs
}

func validateTime(time string, fieldPath *field.Path) field.ErrorList {
	if time == "" {
		return nil
	}
	if _, err := configs.ParseTime(time); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, time, err.Error())}
	}
	return nil
}

// http://nginx.org/en/docs/syntax.html
const offsetErrMsg = "must consist of numeric characters followed by a valid size suffix. 'k|K|m|M|g|G"

func validateOffset(offset string, fieldPath *field.Path) field.ErrorList {
	if offset == "" {
		return nil
	}
	if _, err := configs.ParseOffset(offset); err != nil {
		msg := validation.RegexError(offsetErrMsg, configs.OffsetFmt, "16", "32k", "64M", "2G")
		return field.ErrorList{field.Invalid(fieldPath, offset, msg)}
	}
	return nil
}

// http://nginx.org/en/docs/syntax.html
const sizeErrMsg = "must consist of numeric characters followed by a valid size suffix. 'k|K|m|M"

// ValidateSize is a wrapper for validateSize to be used in other packages
func ValidateSize(size string, fieldPath *field.Path) field.ErrorList {
	return validateSize(size, fieldPath)
}

func validateSize(size string, fieldPath *field.Path) field.ErrorList {
	if size == "" {
		return nil
	}

	if _, err := configs.ParseSize(size); err != nil {
		msg := validation.RegexError(sizeErrMsg, configs.SizeFmt, "16", "32k", "64M")
		return field.ErrorList{field.Invalid(fieldPath, size, msg)}
	}
	return nil
}

// validateSecretName checks if a secret name is valid.
// It performs the same validation as ValidateSecretName from k8s.io/kubernetes/pkg/apis/core/validation/validation.go.
func validateSecretName(name string, fieldPath *field.Path) field.ErrorList {
	if name == "" {
		return nil
	}

	allErrs := field.ErrorList{}
	for _, msg := range validation.IsDNS1123Subdomain(name) {
		allErrs = append(allErrs, field.Invalid(fieldPath, name, msg))
	}
	return allErrs
}

func mapToPrettyString(m map[string]bool) string {
	var out []string

	for k := range m {
		out = append(out, k)
	}

	return strings.Join(out, ", ")
}

// ValidateParameter validates a parameter against a map of valid parameters for the directive
func ValidateParameter(nPar string, validParams map[string]bool, fieldPath *field.Path) field.ErrorList {
	if !validParams[nPar] {
		msg := fmt.Sprintf("'%v' contains an invalid NGINX parameter. Accepted parameters are: %v", nPar, mapToPrettyString(validParams))
		return field.ErrorList{field.Invalid(fieldPath, nPar, msg)}
	}
	return nil
}
