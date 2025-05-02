package configs

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// There seems to be no composite interface in the kubernetes api package,
// so we have to declare our own.
type apiObject interface {
	v1.Object
	runtime.Object
}

// GetMapKeyAsBool searches the map for the given key and parses the key as bool.
func GetMapKeyAsBool(m map[string]string, key string, context apiObject) (bool, bool, error) {
	if str, exists := m[key]; exists {
		b, err := ParseBool(str)
		if err != nil {
			return false, exists, fmt.Errorf("%s %v/%v '%s' contains invalid bool: %w, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key, err)
		}

		return b, exists, nil
	}

	return false, false, nil
}

// GetMapKeyAsInt tries to find and parse a key in a map as int.
func GetMapKeyAsInt(m map[string]string, key string, context apiObject) (int, bool, error) {
	if str, exists := m[key]; exists {
		i, err := ParseInt(str)
		if err != nil {
			return 0, exists, fmt.Errorf("%s %v/%v '%s' contains invalid integer: %w, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key, err)
		}

		return i, exists, nil
	}

	return 0, false, nil
}

// GetMapKeyAsInt64 tries to find and parse a key in a map as int64.
func GetMapKeyAsInt64(m map[string]string, key string, context apiObject) (int64, bool, error) {
	if str, exists := m[key]; exists {
		i, err := ParseInt64(str)
		if err != nil {
			return 0, exists, fmt.Errorf("%s %v/%v '%s' contains invalid integer: %w, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key, err)
		}

		return i, exists, nil
	}

	return 0, false, nil
}

// GetMapKeyAsUint64 tries to find and parse a key in a map as uint64.
func GetMapKeyAsUint64(m map[string]string, key string, context apiObject, nonZero bool) (uint64, bool, error) {
	if str, exists := m[key]; exists {
		i, err := ParseUint64(str)
		if err != nil {
			return 0, exists, fmt.Errorf("%s %v/%v '%s' contains invalid uint64: %w, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key, err)
		}

		if nonZero && i == 0 {
			return 0, exists, fmt.Errorf("%s %v/%v '%s' must be greater than 0, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key)
		}

		return i, exists, nil
	}

	return 0, false, nil
}

// GetMapKeyAsStringSlice tries to find and parse a key in the map as string slice splitting it on delimiter.
func GetMapKeyAsStringSlice(m map[string]string, key string, _ apiObject, delimiter string) ([]string, bool) {
	if str, exists := m[key]; exists {
		slice := strings.Split(str, delimiter)
		return slice, exists
	}
	return nil, false
}

// ParseLBMethod parses method and matches it to a corresponding load balancing method in NGINX. An error is returned if method is not valid.
func ParseLBMethod(method string) (string, error) {
	method = strings.TrimSpace(method)

	if method == "round_robin" {
		return "", nil
	}

	if strings.HasPrefix(method, "hash") {
		method, err := validateHashLBMethod(method)
		return method, err
	}

	if _, exists := nginxLBValidInput[method]; exists {
		return method, nil
	}

	return "", fmt.Errorf("invalid load balancing method: %q", method)
}

var nginxLBValidInput = map[string]bool{
	"least_conn":            true,
	"ip_hash":               true,
	"random":                true,
	"random two":            true,
	"random two least_conn": true,
}

var nginxPlusLBValidInput = map[string]bool{
	"least_conn":                      true,
	"ip_hash":                         true,
	"random":                          true,
	"random two":                      true,
	"random two least_conn":           true,
	"random two least_time=header":    true,
	"random two least_time=last_byte": true,
	"least_time header":               true,
	"least_time last_byte":            true,
	"least_time header inflight":      true,
	"least_time last_byte inflight":   true,
}

// ParseLBMethodForPlus parses method and matches it to a corresponding load balancing method in NGINX Plus. An error is returned if method is not valid.
func ParseLBMethodForPlus(method string) (string, error) {
	method = strings.TrimSpace(method)

	if method == "round_robin" {
		return "", nil
	}

	if strings.HasPrefix(method, "hash") {
		method, err := validateHashLBMethod(method)
		return method, err
	}

	if _, exists := nginxPlusLBValidInput[method]; exists {
		return method, nil
	}

	return "", fmt.Errorf("invalid load balancing method: %q", method)
}

func validateHashLBMethod(method string) (string, error) {
	keyWords := strings.Split(method, " ")

	if keyWords[0] == "hash" {
		if len(keyWords) == 2 || (len(keyWords) == 3 && keyWords[2] == "consistent") {
			return method, nil
		}
	}

	return "", fmt.Errorf("invalid load balancing method: %q", method)
}

// ParseBool ensures that the string value is a valid bool
func ParseBool(s string) (bool, error) {
	return strconv.ParseBool(s)
}

// ParseInt ensures that the string value is a valid int
func ParseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

// ParseInt64 ensures that the string value is a valid int64
func ParseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// ParseUint64 ensures that the string value is a valid uint64
func ParseUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// ParseFloat64 ensures that the string value is a valid float64
func ParseFloat64(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// timeRegexp http://nginx.org/en/docs/syntax.html
var timeRegexp = regexp.MustCompile(`^(\d+y)??\s*(\d+M)??\s*(\d+w)??\s*(\d+d)??\s*(\d+h)??\s*(\d+m)??\s*(\d+s?)??\s*(\d+ms)??$`)

// ParseTime ensures that the string value in the annotation is a valid time.
func ParseTime(s string) (string, error) {
	if s == "" || strings.TrimSpace(s) == "" || !timeRegexp.MatchString(s) {
		return "", errors.New("invalid time string")
	}
	units := timeRegexp.FindStringSubmatch(s)
	years := units[1]
	months := units[2]
	weeks := units[3]
	days := units[4]
	hours := units[5]
	mins := units[6]
	secs := units[7]
	if secs != "" && !strings.HasSuffix(secs, "s") {
		secs = secs + "s"
	}
	millis := units[8]
	return fmt.Sprintf("%s%s%s%s%s%s%s%s", years, months, weeks, days, hours, mins, secs, millis), nil
}

// OffsetFmt http://nginx.org/en/docs/syntax.html
const OffsetFmt = `\d+[kKmMgG]?`

var offsetRegexp = regexp.MustCompile("^" + OffsetFmt + "$")

// ParseOffset ensures that the string value is a valid offset
func ParseOffset(s string) (string, error) {
	s = strings.TrimSpace(s)

	if offsetRegexp.MatchString(s) {
		return s, nil
	}
	return "", errors.New("invalid offset string")
}

// SizeFmt http://nginx.org/en/docs/syntax.html
const SizeFmt = `\d+[kKmM]?`

var sizeRegexp = regexp.MustCompile("^" + SizeFmt + "$")

// ParseSize ensures that the string value is a valid size
func ParseSize(s string) (string, error) {
	s = strings.TrimSpace(s)

	if sizeRegexp.MatchString(s) {
		return s, nil
	}
	return "", errors.New("invalid size string")
}

var rateRegexp = regexp.MustCompile(`^(\d+)(r/s|r/m)$`)

// ParseRequestRate ensures that the string value is a valid request rate in r/s or r/m and > 0
func ParseRequestRate(s string) (string, error) {
	s = strings.TrimSpace(s)

	match := rateRegexp.FindStringSubmatch(s)

	if match == nil {
		return "", errors.New("string does not match rate-pattern: ^(\\d+)(r/s|r/m)$")
	}

	number, err := strconv.Atoi(match[1])
	if err != nil {
		return "", errors.New("string does not match rate-pattern")
	}

	if number <= 0 {
		return "", errors.New("rate must be >0")
	}

	return s, nil
}

// https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffers
var proxyBuffersRegexp = regexp.MustCompile(`^\d+ \d+[kKmM]?$`)

// ParseProxyBuffersSpec ensures that the string value is a valid proxy buffer spec
func ParseProxyBuffersSpec(s string) (string, error) {
	s = strings.TrimSpace(s)

	if proxyBuffersRegexp.MatchString(s) {
		return s, nil
	}
	return "", errors.New("invalid proxy buffers string")
}

// parseProxySetHeaders ensures that the string colon-separated list of headers and values
func parseProxySetHeaders(proxySetHeaders []string) []version2.Header {
	var headers []version2.Header
	for _, header := range proxySetHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 1 {
			headers = append(headers, version2.Header{Name: parts[0], Value: ""})
		} else {
			headers = append(headers, version2.Header{Name: parts[0], Value: parts[1]})
		}
	}
	return headers
}

// ParsePortList ensures that the string is a comma-separated list of port numbers
func ParsePortList(s string) ([]int, error) {
	var ports []int
	for _, value := range strings.Split(s, ",") {
		port, err := parsePort(value)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unable to parse port as integer: %w", err)
	}

	if port <= 0 {
		return 0, fmt.Errorf("port number should be greater than zero: %q", port)
	}

	return int(port), nil
}

// ParseServiceList ensures that the string is a comma-separated list of services
func ParseServiceList(s string) map[string]bool {
	services := make(map[string]bool)
	for _, part := range strings.Split(s, ",") {
		services[part] = true
	}
	return services
}

// ParseRewriteList ensures that the string is a semicolon-separated list of services
func ParseRewriteList(s string) (map[string]string, error) {
	rewrites := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		serviceName, rewrite, err := parseRewrites(part)
		if err != nil {
			return nil, err
		}
		rewrites[serviceName] = rewrite
	}
	return rewrites, nil
}

// ParseStickyServiceList ensures that the string is a semicolon-separated list of sticky services
func ParseStickyServiceList(s string) (map[string]string, error) {
	services := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		serviceName, service, err := parseStickyService(part)
		if err != nil {
			return nil, err
		}
		services[serviceName] = service
	}
	return services, nil
}

func parseStickyService(service string) (serviceName string, stickyCookie string, err error) {
	parts := strings.SplitN(service, " ", 2)

	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid sticky-cookie service format: %s. Must be a semicolon-separated list of sticky services", service)
	}

	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 {
		return "", "", fmt.Errorf("invalid sticky-cookie service format: %s", svcNameParts)
	}

	stickyCookieParameters := parts[1]
	if !stickyCookieRegex.MatchString(stickyCookieParameters) {
		return "", "", fmt.Errorf("invalid sticky-cookie parameters: %s", stickyCookieParameters)
	}

	return svcNameParts[1], parts[1], nil
}

func parseRewrites(service string) (serviceName string, rewrite string, err error) {
	parts := strings.SplitN(strings.TrimSpace(service), " ", 2)

	if len(parts) != 2 {
		return "", "", fmt.Errorf("'%s' is not a valid rewrite format, e.g. 'serviceName=tea-svc rewrite=/'", service)
	}

	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 || svcNameParts[0] != "serviceName" {
		return "", "", fmt.Errorf("'%s' is not a valid serviceName format, e.g. 'serviceName=tea-svc'", parts[0])
	}

	rwPathParts := strings.Split(parts[1], "=")
	if len(rwPathParts) != 2 || rwPathParts[0] != "rewrite" {
		return "", "", fmt.Errorf("'%s' is not a valid rewrite path format, e.g. 'rewrite=/tea'", parts[1])
	}

	if !VerifyPath(rwPathParts[1]) {
		return "", "", fmt.Errorf("path must start with '/' and must not include any whitespace character, '{', '}' or '$': '%s'", rwPathParts[1])
	}

	return svcNameParts[1], rwPathParts[1], nil
}

var (
	threshEx          = regexp.MustCompile(`high=([1-9]|[1-9][0-9]|100) low=([1-9]|[1-9][0-9]|100)\b`)
	threshExR         = regexp.MustCompile(`low=([1-9]|[1-9][0-9]|100) high=([1-9]|[1-9][0-9]|100)\b`)
	pathRegexp        = regexp.MustCompile("^" + `/[^\s{};$]*` + "$")
	stickyCookieRegex = regexp.MustCompile("^" + `([^"$\\]|\\[^$])*` + "$")
)

// VerifyAppProtectThresholds ensures that threshold values are set correctly
func VerifyAppProtectThresholds(value string) bool {
	return threshEx.MatchString(value) || threshExR.MatchString(value)
}

// VerifyPath ensures that rewrite paths are in the correct format
func VerifyPath(s string) bool {
	return pathRegexp.MatchString(s)
}
