package configs

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	internalvalidation "github.com/nginx/kubernetes-ingress/internal/validation"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
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
	"least_conn":                    true,
	"ip_hash":                       true,
	"random":                        true,
	"random two":                    true,
	"random two least_conn":         true,
	"least_time header":             true,
	"least_time last_byte":          true,
	"least_time header inflight":    true,
	"least_time last_byte inflight": true,
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
	if err := internalvalidation.ValidateDirectiveValue(method); err != nil {
		return "", fmt.Errorf("invalid load balancing method: %q: %w", method, err)
	}
	if strings.Contains(method, "\t") {
		return "", fmt.Errorf("invalid load balancing method: %q", method)
	}
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

const (
	addHeaderInheritOn    = "on"
	addHeaderInheritOff   = "off"
	addHeaderInheritMerge = "merge"
)

// ParseAddHeaderInherit validates the add_header_inherit directive mode.
func ParseAddHeaderInherit(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case addHeaderInheritOn, addHeaderInheritOff, addHeaderInheritMerge:
		return value, nil
	default:
		return "", fmt.Errorf("must be one of: '%s', '%s' or '%s'", addHeaderInheritOn, addHeaderInheritOff, addHeaderInheritMerge)
	}
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

// ParseKeepaliveTimeout validates the timeout and optional header_timeout
// arguments accepted by the keepalive_timeout directive.
func ParseKeepaliveTimeout(s string) (string, error) {
	values := strings.Fields(s)
	if len(values) == 0 || len(values) > 2 {
		return "", errors.New("keepalive timeout must contain one or two time values")
	}

	parsed := make([]string, 0, len(values))
	for _, value := range values {
		timeValue, err := ParseTime(value)
		if err != nil {
			return "", err
		}
		parsed = append(parsed, timeValue)
	}
	return strings.Join(parsed, " "), nil
}

// ParseUnsignedInteger validates an NGINX number while retaining its original
// decimal representation.
func ParseUnsignedInteger(s string) (string, error) {
	s = strings.TrimSpace(s)
	if _, err := ParseUint64(s); err != nil {
		return "", err
	}
	return s, nil
}

// ParseLogFormatEscaping validates the escape argument of log_format.
func ParseLogFormatEscaping(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "default", "json", "none":
		return s, nil
	default:
		return "", errors.New("must be one of: 'default', 'json' or 'none'")
	}
}

// ParseErrorLogLevel validates the level argument of error_log.
func ParseErrorLogLevel(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "debug", "info", "notice", "warn", "error", "crit", "alert", "emerg":
		return s, nil
	default:
		return "", errors.New("invalid error log level")
	}
}

var appProtectCookieSeedRegexp = regexp.MustCompile(`^[A-Za-z0-9]{20,1000}$`)

// ParseAppProtectCookieSeed validates the alphanumeric seed grammar accepted
// by app_protect_cookie_seed.
func ParseAppProtectCookieSeed(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !appProtectCookieSeedRegexp.MatchString(s) {
		return "", errors.New("must contain 20 to 1000 alphanumeric characters")
	}
	return s, nil
}

// ParseWorkerCPUAffinity validates the cpumask list and auto forms accepted by
// worker_cpu_affinity.
func ParseWorkerCPUAffinity(s string) (string, error) {
	values := strings.Fields(s)
	if len(values) == 0 {
		return "", errors.New("worker CPU affinity must not be empty")
	}
	if values[0] == "auto" {
		if len(values) > 2 {
			return "", errors.New("auto accepts at most one CPU mask")
		}
		if len(values) == 1 {
			return "auto", nil
		}
		values = values[1:]
	}
	for _, value := range values {
		if value == "" || strings.Trim(value, "01") != "" {
			return "", fmt.Errorf("invalid CPU mask %q", value)
		}
	}
	return strings.Join(strings.Fields(s), " "), nil
}

// ParseHeaderList validates a comma-separated list of HTTP header names and
// returns the trimmed names. The caller reports the key and the raw value, so
// only the reason is returned here.
func ParseHeaderList(s string) ([]string, error) {
	names, msgs := internalvalidation.ValidateHeaderNameList(s)
	if len(msgs) != 0 {
		return nil, errors.New(strings.Join(msgs, "; "))
	}
	return names, nil
}

// ParseResolverAddresses validates the address list accepted by resolver.
// Addresses may be separated by commas, NGINX whitespace, or both, and empty
// entries are dropped: before validation existed the list was joined with
// spaces, so "a,b," and "a b" both rendered a resolver NGINX loads.
func ParseResolverAddresses(s string) ([]string, error) {
	values := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(values) == 0 {
		return nil, errors.New("must contain at least one address")
	}
	for _, value := range values {
		if err := validateHostOrIP(value); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// ParseSetRealIPFrom validates addresses, CIDRs, hostnames, and the special
// unix: value accepted by set_real_ip_from.
func ParseSetRealIPFrom(s string) ([]string, error) {
	values := strings.Split(s, ",")
	parsed := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "unix:" {
			parsed = append(parsed, value)
			continue
		}
		if _, err := netip.ParsePrefix(value); err != nil {
			if address, addrErr := netip.ParseAddr(value); addrErr == nil && address.Zone() == "" {
				parsed = append(parsed, value)
				continue
			}
			if strings.Contains(value, ":") || validateHostname(value) != nil {
				return nil, fmt.Errorf("invalid set-real-ip-from address %q", value)
			}
		}
		parsed = append(parsed, value)
	}
	return parsed, nil
}

// ParseFQDN validates and trims a fully qualified domain name.
func ParseFQDN(s string) (string, error) {
	s = strings.TrimSpace(s)
	if err := validateHostname(s); err != nil {
		return "", err
	}
	return s, nil
}

// validateHostOrIP accepts the address forms the NGINX resolver directive takes:
// a host, a bare IP, a bracketed IPv6 literal, and any of those with a port. The
// error from ValidateHost is returned when none of them match, because it
// describes the most common mistake.
func validateHostOrIP(value string) error {
	value = strings.TrimSpace(value)
	hostErr := internalvalidation.ValidateHost(value)
	if hostErr == nil {
		return nil
	}
	if isUnzonedIP(value) || isBracketedUnzonedIP(value) || isUnzonedIPPort(value) || isDNSNameWithOptionalPort(value) {
		return nil
	}
	return hostErr
}

// isUnzonedIP reports whether value is an IP literal carrying no zone. A zone is
// meaningful only to the local host, so NGINX does not accept one here.
func isUnzonedIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == ""
}

func isBracketedUnzonedIP(value string) bool {
	if len(value) <= 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return false
	}
	return isUnzonedIP(value[1 : len(value)-1])
}

func isUnzonedIPPort(value string) bool {
	addrPort, err := netip.ParseAddrPort(value)
	if err != nil {
		return false
	}
	return addrPort.Addr().Zone() == "" && internalvalidation.ValidatePort(int(addrPort.Port())) == nil
}

func isDNSNameWithOptionalPort(value string) bool {
	host := value
	if splitHost, port, err := net.SplitHostPort(value); err == nil {
		portNumber, parseErr := strconv.Atoi(port)
		if parseErr != nil || internalvalidation.ValidatePort(portNumber) != nil {
			return false
		}
		host = splitHost
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return len(k8svalidation.IsDNS1123Subdomain(host)) == 0
}

func validateHostname(value string) error {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if host == "" || len(k8svalidation.IsDNS1123Subdomain(host)) != 0 {
		return fmt.Errorf("invalid hostname %q", value)
	}
	return nil
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
var (
	proxyBuffersRegexp            = regexp.MustCompile(`^\d+ \d+[kKmM]?$`)
	proxyBuffersWithAnyUnitRegexp = regexp.MustCompile(`^(\d+) (\d+)([a-zA-Z]?)$`)
)

// ParseProxyBuffersSpec ensures that the string value is a valid proxy buffer spec
func ParseProxyBuffersSpec(s string) (string, error) {
	s = strings.TrimSpace(s)

	// First check if it's already a valid proxy buffer spec
	if proxyBuffersRegexp.MatchString(s) {
		return s, nil
	}

	// Check if it matches number + space + number + any letter pattern for auto-adjustment
	match := proxyBuffersWithAnyUnitRegexp.FindStringSubmatch(s)
	if match != nil {
		bufferCount := match[1]
		bufferSize := match[2]
		unit := strings.ToLower(match[3])

		// If unit is empty or valid, use as-is
		if unit == "" || unit == "k" || unit == "m" {
			return bufferCount + " " + bufferSize + unit, nil
		}
	}

	return "", errors.New("invalid proxy buffers string")
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
		return 0, fmt.Errorf("port number should be greater than zero: %d", port)
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
	thresholdValueFmt = `(?:100|[1-9]?[0-9])`
	threshEx          = regexp.MustCompile(`^high=` + thresholdValueFmt + ` low=` + thresholdValueFmt + `$`)
	threshExR         = regexp.MustCompile(`^low=` + thresholdValueFmt + ` high=` + thresholdValueFmt + `$`)
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

// customHTTPErrorMaxCodes bounds the number of expanded status codes emitted
// on the generated error_page directive. 3xx + 4xx + 5xx together is exactly
// 300, which is the effective upper bound in normal use.
const customHTTPErrorMaxCodes = 300

// nginxErrorPageRejectedCodes lists status codes that NGINX itself rejects in
// the error_page directive at config-parse time.
var nginxErrorPageRejectedCodes = map[int]bool{
	499: true,
}

func expandHTTPErrorRange(start, end int, set map[int]struct{}) {
	for c := start; c <= end; c++ {
		if !nginxErrorPageRejectedCodes[c] {
			set[c] = struct{}{}
		}
	}
}

func parseCustomHTTPErrorToken(token string, set map[int]struct{}) error {
	switch strings.ToLower(token) {
	case "4xx":
		expandHTTPErrorRange(400, 499, set)
		return nil
	case "5xx":
		expandHTTPErrorRange(500, 599, set)
		return nil
	}
	if !isASCIIDigits(token) {
		return fmt.Errorf("invalid status code %q: must be an integer, '4xx', or '5xx'", token)
	}
	code, err := strconv.Atoi(token)
	if err != nil {
		return fmt.Errorf("invalid status code %q: must be an integer, '4xx', or '5xx'", token)
	}
	if code < 300 || code > 599 {
		return fmt.Errorf("invalid status code %d: must be in the range [300, 599]", code)
	}
	if nginxErrorPageRejectedCodes[code] {
		return fmt.Errorf("invalid status code %d: NGINX rejects this code in the error_page directive", code)
	}
	set[code] = struct{}{}
	return nil
}

// ParseCustomHTTPErrors parses the nginx.org/custom-http-errors annotation
// value into a sorted, deduplicated slice of HTTP status codes.
//
// Empty entries between commas are skipped. An empty (or whitespace-only)
// input string is an error, as is a value that yields no codes after parsing.
func ParseCustomHTTPErrors(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("value must not be empty")
	}
	set := make(map[int]struct{})
	for _, raw := range strings.Split(value, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		if err := parseCustomHTTPErrorToken(token, set); err != nil {
			return nil, err
		}
	}
	if len(set) == 0 {
		return nil, errors.New("no valid status codes found")
	}
	if len(set) > customHTTPErrorMaxCodes {
		return nil, fmt.Errorf("too many status codes (%d), maximum is %d", len(set), customHTTPErrorMaxCodes)
	}
	codes := make([]int, 0, len(set))
	for c := range set {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	return codes, nil
}

// isASCIIDigits reports whether s is non-empty and made up entirely of ASCII
// decimal digits.
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
