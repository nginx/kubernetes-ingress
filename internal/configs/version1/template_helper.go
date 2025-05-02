package version1

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"
)

func split(s string, delim string) []string {
	return strings.Split(s, delim)
}

func trim(s string) string {
	return strings.TrimSpace(s)
}

// makeLocationPath takes location and Ingress annotations and returns
// modified location path with added regex modifier or the original path
// if no path-regex annotation is present in ingressAnnotations
// or in Location's Ingress.
//
// Annotations 'path-regex' are set only on Minions. If set on Master Ingress,
// they are ignored and have no effect.
func makeLocationPath(loc *Location, ingressAnnotations map[string]string) string {
	if loc.MinionIngress != nil {
		// Case when annotation 'path-regex' set on Location's Minion.
		ingressType, isMergeable := loc.MinionIngress.Annotations["nginx.org/mergeable-ingress-type"]
		regexType, hasRegex := loc.MinionIngress.Annotations["nginx.org/path-regex"]

		if isMergeable && ingressType == "minion" && hasRegex {
			return makePathWithRegex(loc.Path, regexType)
		}
		if isMergeable && ingressType == "minion" && !hasRegex {
			return loc.Path
		}
	}

	// Case when annotation 'path-regex' set on Ingress (including Master).
	regexType, ok := ingressAnnotations["nginx.org/path-regex"]
	if !ok {
		return loc.Path
	}
	return makePathWithRegex(loc.Path, regexType)
}

// makePathWithRegex takes a path representing a location and a regexType
// (one of `case_sensitive`, `case_insensitive` or `exact`).
// It returns a location path with added regular expression modifier.
// See [Location Directive].
//
// [Location Directive]: https://nginx.org/en/docs/http/ngx_http_core_module.html#location
func makePathWithRegex(path, regexType string) string {
	switch regexType {
	case "case_sensitive":
		return fmt.Sprintf("~ \"^%s\"", path)
	case "case_insensitive":
		return fmt.Sprintf("~* \"^%s\"", path)
	case "exact":
		return fmt.Sprintf("= \"%s\"", path)
	default:
		return path
	}
}

var setHeader = regexp.MustCompile("^[-A-Za-z0-9]+$")

func validateProxySetHeader(header string) error {
	header = strings.TrimSpace(header)
	if !setHeader.MatchString(header) {
		return errors.New("invalid header syntax - syntax must be header: value")
	}
	return nil
}

func defaultHeaderValues(headerParts []string, headerName string) string {
	headerValue := strings.TrimSpace(headerParts[0])
	headerValue = strings.ReplaceAll(headerValue, "-", "_")
	headerValue = strings.ToLower(headerValue)
	return fmt.Sprintf("\n\t\tproxy_set_header %s $http_%s;", headerName, headerValue)
}

func headersGreaterThanOne(headerParts []string, headerName string) string {
	headerValue := strings.TrimSpace(headerParts[1])
	return fmt.Sprintf("\n\t\tproxy_set_header %s %q;", headerName, headerValue)
}

func splitHeaders(header string) ([]string, string) {
	header = strings.TrimSpace(header)
	headerParts := strings.SplitN(header, ":", 2)
	headerName := strings.TrimSpace(headerParts[0])
	return headerParts, headerName
}

// minionProxySetHeaders takes a location and a bool map
// and generates proxy_set_header headers for minions based on the nginx.org/proxy-set-headers annotation in a mergeable ingress.
// It returns a string containing the generated proxy headers and a map to verify that the header exists
func minionProxySetHeaders(loc *Location, minionHeaders map[string]bool) (string, map[string]bool, error) {
	proxySetHeaders, ok := loc.MinionIngress.Annotations["nginx.org/proxy-set-headers"]
	if !ok {
		return "", nil, nil
	}
	var combinedMinions string
	headers := strings.Split(proxySetHeaders, ",")
	for _, header := range headers {
		headerParts, headerName := splitHeaders(header)
		err := validateProxySetHeader(headerName)
		if err != nil {
			return "", nil, err
		}
		if len(headerParts) > 1 {
			output := headersGreaterThanOne(headerParts, headerName)
			minionHeaders[headerName] = true
			combinedMinions += output
		} else {
			output := defaultHeaderValues(headerParts, headerName)
			combinedMinions += output
		}
	}
	return combinedMinions, minionHeaders, nil
}

// standardIngressOrMasterProxySetHeaders takes two strings, two bools and a bool map
// and generates proxy_set_header headers based on the nginx.org/proxy-set-headers annotation in a standard ingress.
// It returns a string containing the generated proxy headers for either standardIngress/NonMergeable or Master.
func standardIngressOrMasterProxySetHeaders(result string, minionHeaders map[string]bool, proxySetHeaders string, ok bool, isMergeable bool) (string, error) {
	if !ok {
		return "", nil
	}
	headers := strings.Split(proxySetHeaders, ",")
	for _, header := range headers {
		headerParts, headerName := splitHeaders(header)
		if isMergeable {
			if _, ok := minionHeaders[headerName]; ok {
				continue
			}
		}
		if err := validateProxySetHeader(headerName); err != nil {
			return "", err
		}
		if len(headerParts) > 1 {
			output := headersGreaterThanOne(headerParts, headerName)
			result += output
		} else {
			output := defaultHeaderValues(headerParts, headerName)
			result += output
		}
	}
	return result, nil
}

// generateProxySetHeaders takes a location and an ingress annotations map
// and generates proxy_set_header directives based on the nginx.org/proxy-set-headers annotation.
// It returns a string containing the generated Nginx configuration to the template.
func generateProxySetHeaders(loc *Location, ingressAnnotations map[string]string) (string, error) {
	proxySetHeaders, ok := ingressAnnotations["nginx.org/proxy-set-headers"]
	var ingressResult string
	minionHeaders := make(map[string]bool)
	isMergeable := loc.MinionIngress != nil
	if !isMergeable {
		ingressResult, err := standardIngressOrMasterProxySetHeaders(ingressResult, minionHeaders, proxySetHeaders, ok, isMergeable)
		if err != nil {
			return "", err
		}
		return ingressResult, nil
	}
	combinedHeaders, minionHeaders, err := minionProxySetHeaders(loc, minionHeaders)
	if err != nil {
		return "", err
	}
	proxySetHeaders, ok = ingressAnnotations["nginx.org/proxy-set-headers"]
	if !ok {
		return combinedHeaders, nil
	}
	combinedHeaders, err = standardIngressOrMasterProxySetHeaders(combinedHeaders, minionHeaders, proxySetHeaders, ok, isMergeable)
	if err != nil {
		return "", err
	}
	return combinedHeaders, nil
}

func makeResolver(resolverAddresses []string, resolverValid string, resolverIPV6 *bool) string {
	var builder strings.Builder
	if len(resolverAddresses) > 0 {
		builder.WriteString("resolver")
		for _, address := range resolverAddresses {
			builder.WriteString(" ")
			builder.WriteString(address)
		}
		if resolverValid != "" {
			builder.WriteString(" valid=")
			builder.WriteString(resolverValid)
		}
		if resolverIPV6 != nil && !*resolverIPV6 {
			builder.WriteString(" ipv6=off")
		}
		builder.WriteString(";")
	}
	return builder.String()
}

var helperFunctions = template.FuncMap{
	"split":                   split,
	"trim":                    trim,
	"contains":                strings.Contains,
	"hasPrefix":               strings.HasPrefix,
	"hasSuffix":               strings.HasSuffix,
	"toLower":                 strings.ToLower,
	"toUpper":                 strings.ToUpper,
	"replaceAll":              strings.ReplaceAll,
	"makeLocationPath":        makeLocationPath,
	"makeSecretPath":          commonhelpers.MakeSecretPath,
	"makeOnOffFromBool":       commonhelpers.MakeOnOffFromBool,
	"generateProxySetHeaders": generateProxySetHeaders,
	"boolToPointerBool":       commonhelpers.BoolToPointerBool,
	"makeResolver":            makeResolver,
}
