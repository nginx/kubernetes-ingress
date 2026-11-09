package configs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"k8s.io/apimachinery/pkg/runtime"
)

// newAuthResponseHeaders returns the response headers that an ExternalAuth Policy forwards, or nil
// when it lists none.
func newAuthResponseHeaders(policyKey string, names []string) *version2.AuthResponseHeaders {
	if len(names) == 0 {
		return nil
	}
	headers := make([]version2.AuthResponseHeader, 0, len(names))
	for _, name := range names {
		suffix := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
		headers = append(headers, version2.AuthResponseHeader{
			Name:     name,
			Variable: "$auth_resp_" + suffix,
			Source:   "$upstream_http_" + suffix,
		})
	}
	return &version2.AuthResponseHeaders{Policy: policyKey, Headers: headers}
}

// forwardedAuthResponseHeaders returns the response headers of the ExternalAuth whose auth_request
// runs in a location: the location's own, or else the server's, unless another feature renders an
// auth_request in the location, which replaces the server's.
func forwardedAuthResponseHeaders(own, server *version2.ExternalAuth, otherAuthRequest bool) *version2.AuthResponseHeaders {
	if own != nil {
		return own.ResponseHeaders
	}
	if otherAuthRequest || server == nil {
		return nil
	}
	return server.ResponseHeaders
}

// withoutForwardedHeaders returns headers without the entries that the forwarded headers replace,
// and the names it removed. It never modifies headers: Ingress locations share one slice.
func withoutForwardedHeaders(headers []version2.Header, forwarded *version2.AuthResponseHeaders) ([]version2.Header, []string) {
	var kept []version2.Header
	var removed []string
	for _, h := range headers {
		if forwarded.Has(h.Name) {
			removed = append(removed, h.Name)
			continue
		}
		kept = append(kept, h)
	}
	if len(removed) == 0 {
		return headers, nil
	}
	return kept, removed
}

// authResponseHeaderNames returns the names that any of the locations forwards, deduplicated and
// sorted ignoring case, or nil when no location forwards headers.
func authResponseHeaderNames(locations []version1.Location) []string {
	seen := make(map[string]bool)
	var names []string
	for _, loc := range locations {
		if loc.AuthResponseHeaders == nil {
			continue
		}
		for _, h := range loc.AuthResponseHeaders.Headers {
			if key := strings.ToLower(h.Name); !seen[key] {
				seen[key] = true
				names = append(names, h.Name)
			}
		}
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	return names
}

// headerWarnings adds each warning about a replaced header once per resource, however many hosts,
// splits, or locations repeat it.
type headerWarnings struct {
	warnings Warnings
	added    map[headerWarning]bool
}

type headerWarning struct {
	owner runtime.Object
	msg   string
}

func newHeaderWarnings(warnings Warnings) *headerWarnings {
	return &headerWarnings{warnings: warnings, added: make(map[headerWarning]bool)}
}

func (h *headerWarnings) addf(owner runtime.Object, msgFmt string, args ...interface{}) {
	w := headerWarning{owner: owner, msg: fmt.Sprintf(msgFmt, args...)}
	if h.added[w] {
		return
	}
	h.added[w] = true
	h.warnings.AddWarning(owner, w.msg)
}
