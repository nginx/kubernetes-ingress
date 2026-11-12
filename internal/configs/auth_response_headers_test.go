package configs

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestNewAuthResponseHeaders(t *testing.T) {
	t.Parallel()

	for _, names := range [][]string{nil, {}} {
		if got := newAuthResponseHeaders("default/p", names); got != nil {
			t.Errorf("newAuthResponseHeaders(%q) = %+v, want nil", names, got)
		}
	}

	got := newAuthResponseHeaders("default/p", []string{"X-Session-ID", "tenant-uuid"})
	want := &version2.AuthResponseHeaders{
		Policy: "default/p",
		Headers: []version2.AuthResponseHeader{
			{Name: "X-Session-ID", Variable: "$auth_resp_x_session_id", Source: "$upstream_http_x_session_id"},
			{Name: "tenant-uuid", Variable: "$auth_resp_tenant_uuid", Source: "$upstream_http_tenant_uuid"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("newAuthResponseHeaders() mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthResponseHeadersHas(t *testing.T) {
	t.Parallel()

	list := newAuthResponseHeaders("default/p", []string{"X-Session-ID"})
	if !list.Has("x-session-id") {
		t.Error("Has() did not find a listed name spelled in another letter case")
	}
	if list.Has("Tenant-UUID") {
		t.Error("Has() found a name that is not listed")
	}
	var none *version2.AuthResponseHeaders
	if none.Has("X-Session-ID") {
		t.Error("Has() found a name in a nil list")
	}
}

func TestForwardedAuthResponseHeaders(t *testing.T) {
	t.Parallel()

	serverList := newAuthResponseHeaders("default/server", []string{"Tenant-UUID"})
	ownList := newAuthResponseHeaders("default/route", []string{"X-Session-ID"})
	server := &version2.ExternalAuth{ResponseHeaders: serverList}

	tests := []struct {
		name             string
		own              *version2.ExternalAuth
		server           *version2.ExternalAuth
		otherAuthRequest bool
		want             *version2.AuthResponseHeaders
	}{
		{name: "the location's own list wins", own: &version2.ExternalAuth{ResponseHeaders: ownList}, server: server, want: ownList},
		{name: "the location's own list wins over another auth_request", own: &version2.ExternalAuth{ResponseHeaders: ownList}, otherAuthRequest: true, want: ownList},
		{name: "an own ExternalAuth without a list forwards nothing", own: &version2.ExternalAuth{}, server: server},
		{name: "the server's list applies to a location without its own", server: server, want: serverList},
		{name: "another auth_request replaces the server's", server: server, otherAuthRequest: true},
		{name: "no ExternalAuth forwards nothing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := forwardedAuthResponseHeaders(tc.own, tc.server, tc.otherAuthRequest); got != tc.want {
				t.Errorf("forwardedAuthResponseHeaders() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestWithoutForwardedHeaders(t *testing.T) {
	t.Parallel()

	forwarded := newAuthResponseHeaders("default/p", []string{"User-UUID", "X-Session-ID"})
	headers := []version2.Header{
		{Name: "Host", Value: "$host"},
		{Name: "user-uuid", Value: "anonymous"},
		{Name: "X-Other", Value: "1"},
		{Name: "X-SESSION-ID", Value: "s"},
	}
	original := slices.Clone(headers)

	kept, removed := withoutForwardedHeaders(headers, forwarded)
	if diff := cmp.Diff([]version2.Header{{Name: "Host", Value: "$host"}, {Name: "X-Other", Value: "1"}}, kept); diff != "" {
		t.Errorf("withoutForwardedHeaders() kept mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"user-uuid", "X-SESSION-ID"}, removed); diff != "" {
		t.Errorf("withoutForwardedHeaders() removed mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(original, headers); diff != "" {
		t.Errorf("withoutForwardedHeaders() modified its input, which Ingress locations share (-want +got):\n%s", diff)
	}

	unrelated := []version2.Header{{Name: "X-Other", Value: "1"}}
	kept, removed = withoutForwardedHeaders(unrelated, forwarded)
	if len(kept) != 1 || &kept[0] != &unrelated[0] || removed != nil {
		t.Errorf("withoutForwardedHeaders() = %v, %v; want the input slice itself and no removed names", kept, removed)
	}

	kept, removed = withoutForwardedHeaders(headers, nil)
	if diff := cmp.Diff(original, kept); diff != "" || removed != nil {
		t.Errorf("withoutForwardedHeaders() with no list removed %v (-want +got):\n%s", removed, diff)
	}
}

func TestListedAuthResponseHeaderNames(t *testing.T) {
	t.Parallel()

	policies := []*version2.ExternalAuth{
		{ResponseHeaders: newAuthResponseHeaders("default/a", []string{"X-Session-ID", "Tenant-UUID"})},
		nil,
		{},
		{ResponseHeaders: newAuthResponseHeaders("default/b", []string{"tenant-uuid", "Accept-Groups"})},
	}
	if diff := cmp.Diff([]string{"Accept-Groups", "Tenant-UUID", "X-Session-ID"}, listedAuthResponseHeaderNames(policies)); diff != "" {
		t.Errorf("listedAuthResponseHeaderNames() mismatch (-want +got):\n%s", diff)
	}
	if got := listedAuthResponseHeaderNames([]*version2.ExternalAuth{nil, {}}); got != nil {
		t.Errorf("listedAuthResponseHeaderNames() = %q for Policies that list nothing, want nil", got)
	}
}

func TestStrippedAuthResponseHeaders(t *testing.T) {
	t.Parallel()

	listed := []string{"Authorization", "Tenant-UUID", "username", "X-Session-ID"}
	forwarded := newAuthResponseHeaders("default/q", []string{"x-session-id"})
	set := []version2.Header{{Name: "Host", Value: "$host"}, {Name: "TENANT-UUID", Value: "static"}}

	tests := []struct {
		name      string
		forwarded *version2.AuthResponseHeaders
		set       []version2.Header
		skip      []string
		want      []string
	}{
		{name: "a location that forwards nothing strips every listed name", want: listed},
		{
			name:      "forwarded names, names the location sets, and names another feature sets stay",
			forwarded: forwarded,
			set:       set,
			skip:      []string{"Username"},
			want:      []string{"Authorization"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, strippedAuthResponseHeaders(listed, tc.forwarded, tc.set, tc.skip)); diff != "" {
				t.Errorf("strippedAuthResponseHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSharesServerAuthLocation(t *testing.T) {
	t.Parallel()

	externalAuth := func(path, policy string, names ...string) *version2.ExternalAuth {
		return &version2.ExternalAuth{
			URI:             &version2.AuthURI{InternalPath: path},
			ResponseHeaders: newAuthResponseHeaders(policy, names),
		}
	}
	server := externalAuth("/_external_auth/auth", "default/p", "Tenant-UUID")

	tests := []struct {
		name        string
		own, server *version2.ExternalAuth
		want        bool
	}{
		{name: "another Policy with the server's auth URI", own: externalAuth("/_external_auth/auth", "default/q", "X-Session-ID"), server: server, want: true},
		{
			name:   "a Policy with a list and the auth URI of a server Policy without one",
			own:    externalAuth("/_external_auth/auth", "default/q", "X-Session-ID"),
			server: externalAuth("/_external_auth/auth", "default/p"),
			want:   true,
		},
		{name: "the server's Policy", own: externalAuth("/_external_auth/auth", "default/p", "Tenant-UUID"), server: server},
		{name: "another auth URI", own: externalAuth("/_external_auth/auth2", "default/q", "X-Session-ID"), server: server},
		{name: "no server ExternalAuth", own: externalAuth("/_external_auth/auth", "default/q", "X-Session-ID")},
		{name: "no own ExternalAuth", server: server},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sharesServerAuthLocation(tc.own, tc.server); got != tc.want {
				t.Errorf("sharesServerAuthLocation() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHeaderWarningsAddsOnce(t *testing.T) {
	t.Parallel()

	vs := &conf_v1.VirtualServer{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "cafe"}}
	vsr := &conf_v1.VirtualServerRoute{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "tea"}}
	warnings := newWarnings()
	headerWarnings := newHeaderWarnings(warnings)
	for _, owner := range []runtime.Object{vs, vsr, vs, vsr} {
		headerWarnings.addf(owner, "Header %s is replaced", "User-UUID")
	}
	headerWarnings.addf(vs, "Header %s is replaced", "X-Session-ID")

	if diff := cmp.Diff([]string{"Header User-UUID is replaced", "Header X-Session-ID is replaced"}, warnings[vs]); diff != "" {
		t.Errorf("warnings of the VirtualServer mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"Header User-UUID is replaced"}, warnings[vsr]); diff != "" {
		t.Errorf("warnings of the VirtualServerRoute mismatch (-want +got):\n%s", diff)
	}
	if len(warnings) != 2 {
		t.Errorf("got warnings for %d resources, want 2", len(warnings))
	}
}

// describeAuthResponseHeaders returns the Policy and the names of a forwarded list, for example
// "default/p: Tenant-UUID, User-UUID".
func describeAuthResponseHeaders(headers *version2.AuthResponseHeaders) string {
	names := make([]string, 0, len(headers.Headers))
	for _, h := range headers.Headers {
		names = append(names, h.Name)
	}
	return headers.Policy + ": " + strings.Join(names, ", ")
}

// authResponseHeaderWarnings returns the warnings of a resource about auth response headers.
func authResponseHeaderWarnings(warnings Warnings, owner runtime.Object) []string {
	var msgs []string
	for _, w := range warnings[owner] {
		if strings.Contains(strings.ToLower(w), "auth response header") {
			msgs = append(msgs, w)
		}
	}
	return msgs
}
