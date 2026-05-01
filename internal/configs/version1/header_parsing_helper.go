package version1

import (
	"regexp"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	escapedStringsFmt    = `([^"\\]|\\.)*`
	escapedStringsErrMsg = `must have all '"' (double quotes) escaped and must not end with an unescaped '\' (backslash)`
)

var escapedStringsFmtRegexp = regexp.MustCompile("^" + escapedStringsFmt + "$")

// ValidateAddHeaderName validates that name is a legal HTTP header name,
// using the same rules as the nginx.org/add-header annotation.
// Returns error messages (empty when valid).
func ValidateAddHeaderName(name string) []string {
	return k8svalidation.IsHTTPHeaderName(name)
}

// ValidateAddHeaderValue validates a header value for use in an NGINX
// add_header directive. It rejects:
//   - '$' characters (expanded by NGINX as variable references)
//   - newline / carriage-return characters (break config line structure)
//   - unescaped double-quotes or trailing backslashes (invalid in the quoted
//     value the template emits via Go's %q verb)
//
// Returns error messages (empty when valid). Messages are intentionally
// identical to those produced by the nginx.org/add-header annotation
// validator so both paths behave consistently.
func ValidateAddHeaderValue(value string) []string {
	var msgs []string
	if strings.ContainsAny(value, "\n\r") {
		msgs = append(msgs, "value must not contain newline or carriage-return characters")
	}
	if strings.Contains(value, "$") {
		msgs = append(msgs, "invalid character in header value: $")
	}
	if !escapedStringsFmtRegexp.MatchString(value) {
		msgs = append(msgs, k8svalidation.RegexError(escapedStringsErrMsg, escapedStringsFmt))
	}
	return msgs
}

// ParseProxySetHeaders splits a comma-separated proxy-set-headers annotation
// value into name/value pairs, trimming whitespace from each component.
// When no value is provided for a header (no colon separator), it derives
// the default NGINX $http_ variable value from the header name
// (e.g. "X-Forwarded-ABC" → "$http_x_forwarded_abc").
func ParseProxySetHeaders(annotation string) []version2.Header {
	var headers []version2.Header
	for _, entry := range strings.Split(annotation, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		var value string
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		} else {
			// Derive default value: X-Forwarded-ABC → $http_x_forwarded_abc
			value = "$http_" + strings.ToLower(strings.ReplaceAll(name, "-", "_"))
		}
		headers = append(headers, version2.Header{Name: name, Value: value})
	}
	return headers
}

// MergeProxySetHeaders combines minion and master proxy-set-headers,
// with minion headers taking priority over master headers of the same name.
func MergeProxySetHeaders(masterAnnotation, minionAnnotation string) []version2.Header {
	minionHeaders := ParseProxySetHeaders(minionAnnotation)
	masterHeaders := ParseProxySetHeaders(masterAnnotation)

	seen := make(map[string]bool)
	var merged []version2.Header

	for _, h := range minionHeaders {
		key := strings.ToLower(h.Name)
		seen[key] = true
		merged = append(merged, h)
	}

	for _, h := range masterHeaders {
		key := strings.ToLower(h.Name)
		if !seen[key] {
			merged = append(merged, h)
		}
	}

	return merged
}

// ParseAddHeaders parses a comma-separated add-header annotation or ConfigMap value into
// a slice of AddHeader structs. Each entry has the format:
//
//	Name:Value         — emits: add_header Name "Value";
//	Name:Value:always  — emits: add_header Name "Value" always;
//
// Whitespace around each component is trimmed. Entries with an empty name are skipped.
func ParseAddHeaders(annotation string) []version2.AddHeader {
	var headers []version2.AddHeader
	for _, entry := range strings.Split(annotation, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		var value string
		if len(parts) >= 2 {
			value = strings.TrimSpace(parts[1])
		}
		always := len(parts) == 3 && strings.EqualFold(strings.TrimSpace(parts[2]), "always")
		headers = append(headers, version2.AddHeader{
			Header: version2.Header{Name: name, Value: value},
			Always: always,
		})
	}
	return headers
}
