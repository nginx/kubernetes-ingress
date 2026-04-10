package version1

import (
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
)

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
