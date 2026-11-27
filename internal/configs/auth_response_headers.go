package configs

import (
	"fmt"
	"slices"
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

// listedAuthResponseHeaderNames returns every name that the ExternalAuth Policies list, deduplicated and sorted
// ignoring case, or nil when they list none. A nil Policy lists nothing.
func listedAuthResponseHeaderNames(policies []*version2.ExternalAuth) []string {
	seen := make(map[string]bool)
	var names []string
	for _, policy := range policies {
		if policy == nil || policy.ResponseHeaders == nil {
			continue
		}
		for _, h := range policy.ResponseHeaders.Headers {
			if key := strings.ToLower(h.Name); !seen[key] {
				seen[key] = true
				names = append(names, h.Name)
			}
		}
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	return names
}

// strippedAuthResponseHeaders returns the listed names whose client copies a location removes: the names it neither
// forwards, nor sets through its rendered request headers in set, nor gets from another feature in skip.
func strippedAuthResponseHeaders(listed []string, forwarded *version2.AuthResponseHeaders, set []version2.Header,
	skip []string,
) []string {
	var stripped []string
	for _, name := range listed {
		sameName := func(other string) bool { return strings.EqualFold(other, name) }
		if forwarded.Has(name) || slices.ContainsFunc(skip, sameName) ||
			slices.ContainsFunc(set, func(h version2.Header) bool { return sameName(h.Name) }) {
			continue
		}
		stripped = append(stripped, name)
	}
	return stripped
}

// listPolicy returns the Policy of an ExternalAuth's list, or "" when it lists no headers. The same Policy always has
// the same list, so different results mean different Policies.
func listPolicy(externalAuth *version2.ExternalAuth) string {
	if externalAuth == nil || externalAuth.ResponseHeaders == nil {
		return ""
	}
	return externalAuth.ResponseHeaders.Policy
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

// resolveAuthResponseHeaders sets the auth response headers that each location of a VirtualServer
// forwards and the ones it strips, and removes the requestHeaders.set entries that forwarded headers
// replace. authLocationPolicies records, for each internal auth path, the Policy its generated auth
// location was built for. Call it after every location exists.
func (vsc *virtualServerConfigurator) resolveAuthResponseHeaders(vsEx *VirtualServerEx, server *version2.ExternalAuth,
	oidc *version2.OIDC, locations []version2.Location, authLocationPolicies map[string]string,
) {
	listed := listedAuthResponseHeaderNames(vsExternalAuths(server, locations))
	warnings := newHeaderWarnings(vsc.warnings)
	for i := range locations {
		loc := &locations[i]
		loc.AuthResponseHeaders = nil
		loc.StrippedAuthResponseHeaders = nil
		if !proxiesToBackend(loc) {
			continue
		}
		forwarded := forwardedAuthResponseHeaders(loc.ExternalAuth, server, loc.APIKey != nil)
		// A location forwards its own Policy's list only where that Policy's auth location was generated for it.
		if forwarded != nil && loc.ExternalAuth != nil &&
			authLocationPolicies[loc.ExternalAuth.URI.InternalPath] != forwarded.Policy {
			forwarded = nil
		}
		if forwarded != nil {
			loc.AuthResponseHeaders = forwarded
			replaceRequestHeaders(loc, forwarded, oidc, locationOwner(vsEx, loc), warnings)
		}
		var skip []string
		if loc.OIDC {
			skip = oidcHeaderNames(oidc)
		}
		loc.StrippedAuthResponseHeaders = strippedAuthResponseHeaders(listed, forwarded, loc.ProxySetHeaders, skip)
	}
}

// vsExternalAuths returns the ExternalAuth of a VirtualServer's server and the own ExternalAuth of each location.
func vsExternalAuths(server *version2.ExternalAuth, locations []version2.Location) []*version2.ExternalAuth {
	policies := []*version2.ExternalAuth{server}
	for i := range locations {
		policies = append(policies, locations[i].ExternalAuth)
	}
	return policies
}

// replaceRequestHeaders removes the requestHeaders.set entries of a location that the forwarded headers
// replace, and reports them and the legacy OIDC headers that the forwarded headers replace.
func replaceRequestHeaders(loc *version2.Location, forwarded *version2.AuthResponseHeaders, oidc *version2.OIDC,
	owner runtime.Object, warnings *headerWarnings,
) {
	var removed []string
	loc.ProxySetHeaders, removed = withoutForwardedHeaders(loc.ProxySetHeaders, forwarded)
	for _, name := range removed {
		warnings.addf(owner, "Header %s in requestHeaders.set is replaced by the auth response header of ExternalAuth policy %s",
			name, forwarded.Policy)
	}

	if !loc.OIDC {
		return
	}
	for _, name := range oidcHeaderNames(oidc) {
		if forwarded.Has(name) {
			warnings.addf(owner, "Header %s set by OIDC policy %s is replaced by the auth response header of ExternalAuth policy %s",
				name, oidc.PolicyName, forwarded.Policy)
		}
	}
}

// proxiesToBackend reports whether a VirtualServer location passes client requests to a backend.
// DisableWAF marks the internal auth location, the only auth subrequest target among them.
func proxiesToBackend(loc *version2.Location) bool {
	if loc.DisableWAF || loc.AuthRequestOff || loc.ACMEChallenge {
		return false
	}
	return loc.ProxyPass != "" || loc.GRPCPass != ""
}

// oidcHeaderNames returns the headers that the legacy OIDC policy sets in its locations.
func oidcHeaderNames(oidc *version2.OIDC) []string {
	if oidc == nil {
		return nil
	}
	if oidc.AccessTokenEnable {
		return []string{"username", "Authorization"}
	}
	return []string{"username"}
}

// locationOwner returns the VirtualServerRoute that defines a location, or else the VirtualServer.
func locationOwner(vsEx *VirtualServerEx, loc *version2.Location) runtime.Object {
	if loc.IsVSR {
		for _, vsr := range vsEx.VirtualServerRoutes {
			if vsr.Namespace == loc.VSRNamespace && vsr.Name == loc.VSRName {
				return vsr
			}
		}
	}
	return vsEx.VirtualServer
}

// resolveIngressAuthResponseHeaders sets the auth response headers that each location of an Ingress
// server forwards and the ones it strips, and removes the nginx.org/proxy-set-headers entries that
// forwarded headers replace. It returns the names that @custom_default_backend removes. owner returns
// the Ingress that a location belongs to.
func resolveIngressAuthResponseHeaders(locations []version1.Location, server *version2.ExternalAuth,
	owner func(*version1.Location) runtime.Object, warnings *headerWarnings,
) []string {
	listed := listedAuthResponseHeaderNames(ingressExternalAuths(server, locations))
	for i := range locations {
		loc := &locations[i]
		loc.AuthResponseHeaders = nil
		loc.StrippedAuthResponseHeaders = nil
		// Internal marks the internal auth location, and AuthRequestOff also the OAuth2 sign-in location.
		if loc.Internal || loc.AuthRequestOff || loc.ACMEChallenge {
			continue
		}
		// Ingress has no APIKey Policy, so no other feature renders an auth_request.
		forwarded := forwardedAuthResponseHeaders(loc.ExternalAuth, server, false)
		// A location forwards its own Policy's list only where that Policy has its own generated auth location.
		if forwarded != nil && sharesServerAuthLocation(loc.ExternalAuth, server) {
			forwarded = nil
		}
		loc.AuthResponseHeaders = forwarded
		// The gRPC branch of the Ingress templates does not render ProxySetHeaders.
		var set []version2.Header
		if !loc.GRPC {
			set = replaceAnnotationHeaders(loc, forwarded, owner(loc), warnings)
		}
		loc.StrippedAuthResponseHeaders = strippedAuthResponseHeaders(listed, forwarded, set, nil)
	}
	return listed
}

// ingressExternalAuths returns the ExternalAuth of an Ingress server and the own ExternalAuth of each location.
func ingressExternalAuths(server *version2.ExternalAuth, locations []version1.Location) []*version2.ExternalAuth {
	policies := []*version2.ExternalAuth{server}
	for i := range locations {
		policies = append(policies, locations[i].ExternalAuth)
	}
	return policies
}

// sharesServerAuthLocation reports whether a location's own ExternalAuth resolves to the server's generated
// auth location rather than its own: they have the same internal auth path but belong to different Policies.
func sharesServerAuthLocation(own, server *version2.ExternalAuth) bool {
	return own != nil && server != nil && own.URI.InternalPath == server.URI.InternalPath &&
		listPolicy(own) != listPolicy(server)
}

// replaceAnnotationHeaders removes the nginx.org/proxy-set-headers entries of a location that the
// forwarded headers replace, reports them, and returns the entries that remain.
func replaceAnnotationHeaders(loc *version1.Location, forwarded *version2.AuthResponseHeaders, owner runtime.Object,
	warnings *headerWarnings,
) []version2.Header {
	var removed []string
	loc.ProxySetHeaders, removed = withoutForwardedHeaders(loc.ProxySetHeaders, forwarded)
	for _, name := range removed {
		warnings.addf(owner, "Header %s in annotation %s is replaced by the auth response header of ExternalAuth policy %s",
			name, ProxySetHeadersAnnotation, forwarded.Policy)
	}
	return loc.ProxySetHeaders
}

// mergeableLocationOwner returns the original minion that a location of a mergeable Ingress comes from, or else the
// master. minions holds the original minions by namespace/name.
func mergeableLocationOwner(minions map[string]runtime.Object, master runtime.Object) func(*version1.Location) runtime.Object {
	return func(loc *version1.Location) runtime.Object {
		if loc.MinionIngress != nil {
			if minion, ok := minions[loc.MinionIngress.Namespace+"/"+loc.MinionIngress.Name]; ok {
				return minion
			}
		}
		return master
	}
}
