package configs

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const jwtTestSecretPath = "/etc/nginx/secrets/default-jwk"

// jwtPolicy returns a JWKS policy, which needs no secret resolution.
func jwtPolicy(name string, authz *conf_v1.JWTAuthorization) *conf_v1.Policy {
	return &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: conf_v1.PolicySpec{
			JWTAuth: &conf_v1.JWTAuth{
				Realm:         "API",
				JwksURI:       "https://idp.example.com/keys",
				KeyCache:      "1h",
				Authorization: authz,
			},
		},
	}
}

func rateLimitJWTPolicy(name, claim string) *conf_v1.Policy {
	return &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: conf_v1.PolicySpec{
			RateLimit: &conf_v1.RateLimit{
				Rate:     "1r/s",
				ZoneSize: "10M",
				Key:      "${jwt_claim_sub}",
				Condition: &conf_v1.RateLimitCondition{
					JWT: &conf_v1.JWTCondition{Claim: claim, Match: "Premium"},
				},
			},
		},
	}
}

func authzForClaims(claims ...conf_v1.JWTClaim) *conf_v1.JWTAuthorization {
	return &conf_v1.JWTAuthorization{Rules: []conf_v1.JWTAuthorizationRule{{Claims: claims}}}
}

func claimEq(name string, values ...string) conf_v1.JWTClaim {
	return conf_v1.JWTClaim{Name: name, Values: values}
}

func claimWithHeader(name, header string, values ...string) conf_v1.JWTClaim {
	return conf_v1.JWTClaim{Name: name, Values: values, ProxySetHeader: header}
}

func jwtVS(specPolicies []string, routePolicies map[string][]string, policies ...*conf_v1.Policy) VirtualServerEx {
	refs := func(names []string) []conf_v1.PolicyReference {
		var r []conf_v1.PolicyReference
		for _, n := range names {
			r = append(r, conf_v1.PolicyReference{Name: n, Namespace: "default"})
		}
		return r
	}

	routes := []conf_v1.Route{
		{Path: "/tea", Action: &conf_v1.Action{Pass: "tea"}, Policies: refs(routePolicies["/tea"])},
		{Path: "/coffee", Action: &conf_v1.Action{Pass: "coffee"}, Policies: refs(routePolicies["/coffee"])},
	}

	vsEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{Name: "cafe", Namespace: "default"},
			Spec: conf_v1.VirtualServerSpec{
				Host:     "cafe.example.com",
				Policies: refs(specPolicies),
				Upstreams: []conf_v1.Upstream{
					{Name: "tea", Service: "tea-svc", Port: 80},
					{Name: "coffee", Service: "coffee-svc", Port: 80},
				},
				Routes: routes,
			},
		},
		Policies:  map[string]*conf_v1.Policy{},
		Endpoints: map[string][]string{"default/tea-svc:80": {"10.0.0.1:80"}, "default/coffee-svc:80": {"10.0.0.2:80"}},
	}
	for _, p := range policies {
		vsEx.Policies[p.Namespace+"/"+p.Name] = p
	}
	return vsEx
}

func generateJWTTestConfig(t *testing.T, vsEx VirtualServerEx) (version2.VirtualServerConfig, Warnings) {
	t.Helper()

	cfgParams := ConfigParams{Context: context.Background(), ServerTokens: "off", Keepalive: 16}
	vsc := newVirtualServerConfigurator(&cfgParams, true, false, &StaticConfigParams{}, false, &fakeBV)
	return vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)
}

func locationByPath(t *testing.T, cfg version2.VirtualServerConfig, path string) version2.Location {
	t.Helper()
	for _, l := range cfg.Server.Locations {
		if l.Path == path {
			return l
		}
	}
	t.Fatalf("no location %q in %v", path, locationPaths(cfg))
	return version2.Location{}
}

func locationPaths(cfg version2.VirtualServerConfig) []string {
	var paths []string
	for _, l := range cfg.Server.Locations {
		paths = append(paths, l.Path)
	}
	return paths
}

func mapVariables(cfg version2.VirtualServerConfig) map[string]bool {
	vars := map[string]bool{}
	for _, m := range cfg.Maps {
		vars[m.Variable] = true
	}
	return vars
}

func headerNames(headers []version2.Header) []string {
	var names []string
	for _, h := range headers {
		names = append(names, h.Name)
	}
	return names
}

func warningsText(w Warnings) string {
	var parts []string
	for _, msgs := range w {
		parts = append(parts, msgs...)
	}
	return strings.Join(parts, "\n")
}

func TestVirtualServerJWTAuthorization_SpecLevel(t *testing.T) {
	t.Parallel()

	vsEx := jwtVS([]string{"jwt"}, nil, jwtPolicy("jwt", &conf_v1.JWTAuthorization{
		ErrorCode: new(401),
		Rules: []conf_v1.JWTAuthorizationRule{{Claims: []conf_v1.JWTClaim{
			claimEq("iss", "https://login.example.com"),
			claimWithHeader("scope", "X-Token-Scope", "read"),
		}}},
	}))

	cfg, warnings := generateJWTTestConfig(t, vsEx)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	policyVar := "$jwt_authz_default_cafe_vs_default_jwt"

	if got := cfg.Server.JWTAuth; got == nil || got.RequireVariable != policyVar || got.RequireErrorCode != 401 {
		t.Errorf("Server.JWTAuth = %+v, want RequireVariable %s and error code 401", got, policyVar)
	}

	wantClaimSets := []version2.AuthJWTClaimSet{
		{Variable: "$jwt_default_cafe_vs_iss", Claim: "iss"},
		{Variable: "$jwt_default_cafe_vs_scope", Claim: "scope"},
	}
	if diff := cmp.Diff(wantClaimSets, cfg.AuthJWTClaimSets); diff != "" {
		t.Errorf("AuthJWTClaimSets mismatch (-want +got):\n%s", diff)
	}

	vars := mapVariables(cfg)
	for _, v := range []string{policyVar, policyVar + "_r0", policyVar + "_r0_c0", policyVar + "_r0_c1"} {
		if !vars[v] {
			t.Errorf("missing map for %s, have %v", v, vars)
		}
	}

	// Locations replace the server's proxy_set_header, so each needs the inherited header.
	for _, path := range []string{"/tea", "/coffee"} {
		names := headerNames(locationByPath(t, cfg, path).ProxySetHeaders)
		if diff := cmp.Diff([]string{"X-Token-Scope", "Host"}, names); diff != "" {
			t.Errorf("%s proxy headers mismatch (-want +got):\n%s", path, diff)
		}
		if reset := locationByPath(t, cfg, path).JWTRequireReset; reset != "" {
			t.Errorf("%s inherits the server's JWT policy and must not reset it, got %q", path, reset)
		}
	}
	if vars["$jwt_authz_none_default_cafe"] {
		t.Error("the reset map must only be emitted when a location needs it")
	}
}

func TestVirtualServerJWTAuthorization_PolicyWithoutAuthorizationIsUnchanged(t *testing.T) {
	t.Parallel()

	cfg, warnings := generateJWTTestConfig(t, jwtVS([]string{"jwt"}, nil, jwtPolicy("jwt", nil)))
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	if got := cfg.Server.JWTAuth; got == nil || got.RequireVariable != "" || got.RequireErrorCode != 0 || len(got.ProxySetHeaders) != 0 {
		t.Errorf("Server.JWTAuth = %+v, a policy without authorization must carry no requirement", got)
	}
	if len(cfg.AuthJWTClaimSets) != 0 || len(cfg.Maps) != 0 {
		t.Errorf("claim sets %v and maps %v must be empty without authorization", cfg.AuthJWTClaimSets, cfg.Maps)
	}
	for _, l := range cfg.Server.Locations {
		if l.JWTRequireReset != "" {
			t.Errorf("%s: unexpected reset %q", l.Path, l.JWTRequireReset)
		}
		if diff := cmp.Diff([]string{"Host"}, headerNames(l.ProxySetHeaders)); diff != "" {
			t.Errorf("%s: headers changed without authorization (-want +got):\n%s", l.Path, diff)
		}
	}
}

func TestVirtualServerJWTAuthorization_RouteLevel(t *testing.T) {
	t.Parallel()

	vsEx := jwtVS(nil, map[string][]string{"/tea": {"tea-jwt"}},
		jwtPolicy("tea-jwt", authzForClaims(claimWithHeader("tier", "X-Tier", "Gold"))))

	cfg, warnings := generateJWTTestConfig(t, vsEx)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	tea := locationByPath(t, cfg, "/tea")
	if tea.JWTAuth == nil || tea.JWTAuth.RequireVariable != "$jwt_authz_default_cafe_vs_default_tea_jwt" || tea.JWTAuth.RequireErrorCode != 403 {
		t.Errorf("/tea JWTAuth = %+v", tea.JWTAuth)
	}
	if diff := cmp.Diff([]string{"X-Tier", "Host"}, headerNames(tea.ProxySetHeaders)); diff != "" {
		t.Errorf("/tea headers mismatch (-want +got):\n%s", diff)
	}

	coffee := locationByPath(t, cfg, "/coffee")
	if coffee.JWTAuth != nil {
		t.Errorf("/coffee JWTAuth = %+v, want none", coffee.JWTAuth)
	}
	if diff := cmp.Diff([]string{"Host"}, headerNames(coffee.ProxySetHeaders)); diff != "" {
		t.Errorf("/coffee headers mismatch (-want +got):\n%s", diff)
	}

	if cfg.Server.JWTAuth != nil {
		t.Errorf("Server.JWTAuth = %+v, want none", cfg.Server.JWTAuth)
	}
	if len(cfg.AuthJWTClaimSets) != 1 || cfg.AuthJWTClaimSets[0].Variable != "$jwt_default_cafe_vs_tier" {
		t.Errorf("AuthJWTClaimSets = %v", cfg.AuthJWTClaimSets)
	}
	if !mapVariables(cfg)["$jwt_authz_default_cafe_vs_default_tea_jwt"] {
		t.Error("the route policy's maps are missing")
	}
}

func TestVirtualServerJWTAuthorization_RoutePolicyWithoutAuthorizationResetsServerRequirement(t *testing.T) {
	t.Parallel()

	spec := jwtPolicy("spec-jwt", authzForClaims(claimWithHeader("iss", "X-Issuer", "a")))
	routeNoAuthz := jwtPolicy("route-plain", nil)
	cfg, warnings := generateJWTTestConfig(t, jwtVS([]string{"spec-jwt"}, map[string][]string{"/tea": {"route-plain"}}, spec, routeNoAuthz))
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	tea := locationByPath(t, cfg, "/tea")
	if tea.JWTRequireReset != "$jwt_authz_none_default_cafe" {
		t.Errorf("/tea JWTRequireReset = %q, the route is not gated by the server's authorization", tea.JWTRequireReset)
	}
	if tea.JWTAuth == nil || tea.JWTAuth.RequireVariable != "" {
		t.Errorf("/tea JWTAuth = %+v, want the route's own policy without a requirement", tea.JWTAuth)
	}
	if diff := cmp.Diff([]string{"Host"}, headerNames(tea.ProxySetHeaders)); diff != "" {
		t.Errorf("/tea headers mismatch (-want +got):\n%s", diff)
	}

	coffee := locationByPath(t, cfg, "/coffee")
	if coffee.JWTRequireReset != "" || coffee.JWTAuth != nil {
		t.Errorf("/coffee inherits the server policy: reset %q, JWTAuth %+v", coffee.JWTRequireReset, coffee.JWTAuth)
	}
	if diff := cmp.Diff([]string{"X-Issuer", "Host"}, headerNames(coffee.ProxySetHeaders)); diff != "" {
		t.Errorf("/coffee headers mismatch (-want +got):\n%s", diff)
	}

	if !mapVariables(cfg)["$jwt_authz_none_default_cafe"] {
		t.Error("the reset map must be emitted when a location uses it")
	}
}

func TestVirtualServerJWTAuthorization_RouteAuthorizationReplacesServerRequirement(t *testing.T) {
	t.Parallel()

	spec := jwtPolicy("spec-jwt", authzForClaims(claimWithHeader("iss", "X-Issuer", "a")))
	routeAuthz := jwtPolicy("route-authz", authzForClaims(claimWithHeader("tier", "X-Tier", "Gold")))
	cfg, warnings := generateJWTTestConfig(t, jwtVS([]string{"spec-jwt"}, map[string][]string{"/tea": {"route-authz"}}, spec, routeAuthz))
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	tea := locationByPath(t, cfg, "/tea")
	if tea.JWTRequireReset != "" {
		t.Errorf("/tea has its own requirement and must not be reset, got %q", tea.JWTRequireReset)
	}
	if tea.JWTAuth == nil || tea.JWTAuth.RequireVariable != "$jwt_authz_default_cafe_vs_default_route_authz" {
		t.Errorf("/tea JWTAuth = %+v", tea.JWTAuth)
	}
	if diff := cmp.Diff([]string{"X-Tier", "Host"}, headerNames(tea.ProxySetHeaders)); diff != "" {
		t.Errorf("/tea headers mismatch (-want +got):\n%s", diff)
	}
	if mapVariables(cfg)["$jwt_authz_none_default_cafe"] {
		t.Error("no location needs the reset map")
	}
}

func TestVirtualServerJWTAuthorization_RouteAuthorizationOnly(t *testing.T) {
	t.Parallel()

	routeAuthz := jwtPolicy("route-authz", authzForClaims(claimWithHeader("tier", "X-Tier", "Gold")))
	cfg, _ := generateJWTTestConfig(t, jwtVS([]string{"plain"}, map[string][]string{"/tea": {"route-authz"}}, jwtPolicy("plain", nil), routeAuthz))

	if tea := locationByPath(t, cfg, "/tea"); tea.JWTAuth == nil || tea.JWTAuth.RequireVariable == "" {
		t.Errorf("/tea JWTAuth = %+v, want the route's requirement", tea.JWTAuth)
	}
	if coffee := locationByPath(t, cfg, "/coffee"); coffee.JWTRequireReset != "" || coffee.JWTAuth != nil {
		t.Errorf("/coffee = reset %q, JWTAuth %+v", coffee.JWTRequireReset, coffee.JWTAuth)
	}
	if mapVariables(cfg)["$jwt_authz_none_default_cafe"] {
		t.Error("the server policy has no requirement, so nothing needs a reset")
	}
}

func TestVirtualServerJWTAuthorization_OIDCLocationResetsServerRequirement(t *testing.T) {
	t.Parallel()

	oidcPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Name: "oidc", Namespace: "default"},
		Spec: conf_v1.PolicySpec{
			OIDC: &conf_v1.OIDC{
				AuthEndpoint:  "https://idp.example.com/auth",
				TokenEndpoint: "https://idp.example.com/token",
				JWKSURI:       "https://idp.example.com/keys",
				ClientID:      "client",
				ClientSecret:  "oidc-secret",
				Scope:         "openid",
			},
		},
	}
	vsEx := jwtVS([]string{"spec-jwt"}, map[string][]string{"/tea": {"oidc"}},
		jwtPolicy("spec-jwt", authzForClaims(claimEq("iss", "a"))), oidcPolicy)
	vsEx.SecretRefs = map[secrets.SecretRefKey]*secrets.SecretReference{
		secrets.RefKey("default/oidc-secret", secrets.RoleOIDC): {
			Secret: &api_v1.Secret{Data: map[string][]byte{"client-secret": []byte("c2VjcmV0")}},
		},
	}

	cfg, warnings := generateJWTTestConfig(t, vsEx)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	tea := locationByPath(t, cfg, "/tea")
	if !tea.OIDC {
		t.Fatalf("the OIDC policy was not applied to /tea, so this test would prove nothing: %+v", tea)
	}
	if tea.JWTRequireReset != "$jwt_authz_none_default_cafe" {
		t.Errorf("OIDC location JWTRequireReset = %q: it runs auth_jwt and would inherit the server's claim requirement", tea.JWTRequireReset)
	}
}

func TestVirtualServerJWTAuthorization_PolicySharedByTwoVirtualServers(t *testing.T) {
	t.Parallel()

	pol := jwtPolicy("shared", authzForClaims(claimEq("iss", "a")))

	cfg1, _ := generateJWTTestConfig(t, jwtVS([]string{"shared"}, nil, pol))

	vs2 := jwtVS([]string{"shared"}, nil, pol)
	vs2.VirtualServer.Name = "tea"
	vs2.VirtualServer.Spec.Host = "tea.example.com"
	cfg2, _ := generateJWTTestConfig(t, vs2)

	// VirtualServers share one http context, so a variable emitted by both fails nginx -t as a duplicate.
	vars1, vars2 := mapVariables(cfg1), mapVariables(cfg2)
	for v := range vars1 {
		if vars2[v] {
			t.Errorf("both VirtualServers emit the map variable %s", v)
		}
	}
	for _, cs1 := range cfg1.AuthJWTClaimSets {
		for _, cs2 := range cfg2.AuthJWTClaimSets {
			if cs1.Variable == cs2.Variable {
				t.Errorf("both VirtualServers emit auth_jwt_claim_set %s", cs1.Variable)
			}
		}
	}
}

func TestVirtualServerJWTAuthorization_ResetVariableIsPerVirtualServer(t *testing.T) {
	t.Parallel()

	build := func(name string) version2.VirtualServerConfig {
		vsEx := jwtVS([]string{"spec-jwt"}, map[string][]string{"/tea": {"route-plain"}},
			jwtPolicy("spec-jwt", authzForClaims(claimEq("iss", "a"))), jwtPolicy("route-plain", nil))
		vsEx.VirtualServer.Name = name
		cfg, _ := generateJWTTestConfig(t, vsEx)
		return cfg
	}

	a, b := build("cafe"), build("tea")
	if !mapVariables(a)["$jwt_authz_none_default_cafe"] || !mapVariables(b)["$jwt_authz_none_default_tea"] {
		t.Fatalf("each VirtualServer must emit its own reset map: %v / %v", mapVariables(a), mapVariables(b))
	}
}

func TestVirtualServerJWTAuthorization_VSRSubroute(t *testing.T) {
	t.Parallel()

	vsEx := jwtVS(nil, nil, jwtPolicy("sub-jwt", authzForClaims(claimWithHeader("tier", "X-Tier", "Gold"))))
	vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{{Path: "/tea", Route: "default/tea-vsr"}}
	vsEx.VirtualServerRoutes = []*conf_v1.VirtualServerRoute{{
		ObjectMeta: meta_v1.ObjectMeta{Name: "tea-vsr", Namespace: "default"},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host:      "cafe.example.com",
			Upstreams: []conf_v1.Upstream{{Name: "tea", Service: "tea-svc", Port: 80}},
			Subroutes: []conf_v1.Route{{
				Path:     "/tea",
				Action:   &conf_v1.Action{Pass: "tea"},
				Policies: []conf_v1.PolicyReference{{Name: "sub-jwt", Namespace: "default"}},
			}},
		},
	}}

	cfg, warnings := generateJWTTestConfig(t, vsEx)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	tea := locationByPath(t, cfg, "/tea")
	// A VSR policy resolves to the parent VirtualServer.
	wantVar := "$jwt_authz_default_cafe_vs_default_sub_jwt"
	if tea.JWTAuth == nil || tea.JWTAuth.RequireVariable != wantVar {
		t.Errorf("subroute JWTAuth = %+v, want RequireVariable %s", tea.JWTAuth, wantVar)
	}
	if diff := cmp.Diff([]string{"X-Tier", "Host"}, headerNames(tea.ProxySetHeaders)); diff != "" {
		t.Errorf("subroute headers mismatch (-want +got):\n%s", diff)
	}
	if len(cfg.AuthJWTClaimSets) != 1 || cfg.AuthJWTClaimSets[0].Variable != "$jwt_default_cafe_vs_tier" {
		t.Errorf("AuthJWTClaimSets = %v", cfg.AuthJWTClaimSets)
	}
	if !mapVariables(cfg)[wantVar] {
		t.Errorf("the subroute policy's maps are missing, have %v", mapVariables(cfg))
	}
}

func TestVirtualServerJWTAuthorization_SplitsAndMatchesForwardHeaders(t *testing.T) {
	t.Parallel()

	pol := jwtPolicy("jwt", authzForClaims(claimWithHeader("tier", "X-Tier", "Gold")))

	t.Run("splits", func(t *testing.T) {
		t.Parallel()
		vsEx := jwtVS([]string{"jwt"}, nil, pol)
		vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{{
			Path: "/tea",
			Splits: []conf_v1.Split{
				{Weight: 90, Action: &conf_v1.Action{Pass: "tea"}},
				{Weight: 10, Action: &conf_v1.Action{Pass: "coffee"}},
			},
		}}
		cfg, _ := generateJWTTestConfig(t, vsEx)

		var proxied int
		for _, l := range cfg.Server.Locations {
			if l.ProxyPass == "" {
				continue
			}
			proxied++
			if diff := cmp.Diff([]string{"X-Tier", "Host"}, headerNames(l.ProxySetHeaders)); diff != "" {
				t.Errorf("split location %s headers mismatch (-want +got):\n%s", l.Path, diff)
			}
		}
		if proxied != 2 {
			t.Errorf("proxied split locations = %d, want 2", proxied)
		}
	})

	t.Run("matches", func(t *testing.T) {
		t.Parallel()
		vsEx := jwtVS([]string{"jwt"}, nil, pol)
		vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{{
			Path: "/tea",
			Matches: []conf_v1.Match{{
				Conditions: []conf_v1.Condition{{Header: "x-version", Value: "v2"}},
				Action:     &conf_v1.Action{Pass: "coffee"},
			}},
			Action: &conf_v1.Action{Pass: "tea"},
		}}
		cfg, _ := generateJWTTestConfig(t, vsEx)

		var proxied int
		for _, l := range cfg.Server.Locations {
			if l.ProxyPass == "" {
				continue
			}
			proxied++
			if diff := cmp.Diff([]string{"X-Tier", "Host"}, headerNames(l.ProxySetHeaders)); diff != "" {
				t.Errorf("match location %s headers mismatch (-want +got):\n%s", l.Path, diff)
			}
		}
		if proxied != 2 {
			t.Errorf("proxied match locations = %d, want 2", proxied)
		}
	})
}

// Each route shape reaches the header merge through a different call path.
func TestVirtualServerJWTAuthorization_AllRouteShapesForwardHeaders(t *testing.T) {
	t.Parallel()

	pol := jwtPolicy("jwt", authzForClaims(claimWithHeader("tier", "X-Tier", "Gold")))
	want := []string{"X-Tier", "Host"}

	twoSplits := []conf_v1.Split{
		{Weight: 90, Action: &conf_v1.Action{Pass: "tea"}},
		{Weight: 10, Action: &conf_v1.Action{Pass: "coffee"}},
	}
	cond := []conf_v1.Condition{{Header: "x-version", Value: "v2"}}

	tests := []struct {
		name    string
		route   conf_v1.Route
		proxied int
	}{
		{
			name:    "plain action",
			route:   conf_v1.Route{Path: "/tea", Action: &conf_v1.Action{Pass: "tea"}},
			proxied: 1,
		},
		{
			name:    "default splits",
			route:   conf_v1.Route{Path: "/tea", Splits: twoSplits},
			proxied: 2,
		},
		{
			name: "match with an action, default action",
			route: conf_v1.Route{
				Path:    "/tea",
				Matches: []conf_v1.Match{{Conditions: cond, Action: &conf_v1.Action{Pass: "coffee"}}},
				Action:  &conf_v1.Action{Pass: "tea"},
			},
			proxied: 2,
		},
		{
			name: "match with nested splits, default action",
			route: conf_v1.Route{
				Path:    "/tea",
				Matches: []conf_v1.Match{{Conditions: cond, Splits: twoSplits}},
				Action:  &conf_v1.Action{Pass: "tea"},
			},
			proxied: 3,
		},
		{
			name: "match with an action, default splits",
			route: conf_v1.Route{
				Path:    "/tea",
				Matches: []conf_v1.Match{{Conditions: cond, Action: &conf_v1.Action{Pass: "coffee"}}},
				Splits:  twoSplits,
			},
			proxied: 3,
		},
	}

	for _, tc := range tests {
		t.Run("VirtualServer route: "+tc.name, func(t *testing.T) {
			t.Parallel()
			vsEx := jwtVS([]string{"jwt"}, nil, pol)
			vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{tc.route}

			cfg, warnings := generateJWTTestConfig(t, vsEx)
			if len(warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", warnings)
			}
			assertProxiedHeaders(t, cfg, tc.proxied, want)
		})

		t.Run("VSR subroute: "+tc.name, func(t *testing.T) {
			t.Parallel()
			vsEx := jwtVS([]string{"jwt"}, nil, pol)
			vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{{Path: "/tea", Route: "default/tea-vsr"}}
			vsEx.VirtualServerRoutes = []*conf_v1.VirtualServerRoute{{
				ObjectMeta: meta_v1.ObjectMeta{Name: "tea-vsr", Namespace: "default"},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{Name: "tea", Service: "tea-svc", Port: 80},
						{Name: "coffee", Service: "coffee-svc", Port: 80},
					},
					Subroutes: []conf_v1.Route{tc.route},
				},
			}}

			cfg, warnings := generateJWTTestConfig(t, vsEx)
			if len(warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", warnings)
			}
			assertProxiedHeaders(t, cfg, tc.proxied, want)
		})
	}
}

func assertProxiedHeaders(t *testing.T, cfg version2.VirtualServerConfig, wantProxied int, want []string) {
	t.Helper()

	var proxied int
	for _, l := range cfg.Server.Locations {
		if l.ProxyPass == "" {
			continue
		}
		proxied++
		if diff := cmp.Diff(want, headerNames(l.ProxySetHeaders)); diff != "" {
			t.Errorf("location %s headers mismatch (-want +got):\n%s", l.Path, diff)
		}
	}
	if proxied != wantProxied {
		t.Errorf("proxied locations = %d, want %d (locations: %v)", proxied, wantProxied, locationPaths(cfg))
	}
}

func TestVirtualServerJWTAuthorization_RouteRequestHeadersWinOverPolicy(t *testing.T) {
	t.Parallel()

	vsEx := jwtVS([]string{"jwt"}, nil, jwtPolicy("jwt", authzForClaims(
		claimWithHeader("tier", "X-Tier", "Gold"),
		claimWithHeader("tenant", "Host", "acme"),
	)))
	vsEx.VirtualServer.Spec.Routes[0].Action = &conf_v1.Action{Proxy: &conf_v1.ActionProxy{
		Upstream: "tea",
		RequestHeaders: &conf_v1.ProxyRequestHeaders{Set: []conf_v1.Header{
			{Name: "x-tier", Value: "from-route"},
			{Name: "Host", Value: "route.example.com"},
		}},
	}}

	cfg, _ := generateJWTTestConfig(t, vsEx)

	got := locationByPath(t, cfg, "/tea").ProxySetHeaders
	want := []version2.Header{{Name: "x-tier", Value: "from-route"}, {Name: "Host", Value: "route.example.com"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("/tea headers mismatch (-want +got):\n%s", diff)
	}

	// The other route sets no Host, so the policy's is used and no fallback is added.
	coffee := locationByPath(t, cfg, "/coffee").ProxySetHeaders
	wantCoffee := []version2.Header{
		{Name: "X-Tier", Value: "$jwt_authz_default_cafe_vs_default_jwt_r0_c0_hdr"},
		{Name: "Host", Value: "$jwt_authz_default_cafe_vs_default_jwt_r0_c1_hdr"},
	}
	if diff := cmp.Diff(wantCoffee, coffee); diff != "" {
		t.Errorf("/coffee headers mismatch (-want +got):\n%s", diff)
	}
}

// Colliding claims: authorization is rejected, a rate limit is never rejected and is only reported
// when it collides with an authorization claim.
func TestVirtualServerJWTAuthorization_ClaimVariableCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		specPolicies []string
		routes       map[string][]string
		policies     []*conf_v1.Policy
		rejected     []string
		reported     []string
		variable     string
		extracted    string
	}{
		{
			name:         "authorization a_b after rate limit a.b: authorization is rejected",
			specPolicies: []string{"rate", "authz"},
			policies: []*conf_v1.Policy{
				rateLimitJWTPolicy("rate", "a.b"),
				jwtPolicy("authz", authzForClaims(claimEq("a_b", "x"))),
			},
			rejected: []string{"authz"},
		},
		{
			name:         "rate limit a.b after authorization a_b: rate limit is accepted, reported, and authorization keeps the claim",
			specPolicies: []string{"authz", "rate"},
			policies: []*conf_v1.Policy{
				jwtPolicy("authz", authzForClaims(claimEq("a_b", "x"))),
				rateLimitJWTPolicy("rate", "a.b"),
			},
			reported:  []string{"rate"},
			variable:  "$jwt_default_cafe_vs_a_b",
			extracted: "a_b",
		},
		{
			name:         "authorization claims Role and role in different policies collide",
			specPolicies: []string{"one"},
			routes:       map[string][]string{"/tea": {"two"}},
			policies: []*conf_v1.Policy{
				jwtPolicy("one", authzForClaims(claimEq("Role", "x"))),
				jwtPolicy("two", authzForClaims(claimEq("role", "y"))),
			},
			rejected: []string{"two"},
		},
		{
			name:         "a.b and a-b collide across spec and route",
			specPolicies: []string{"one"},
			routes:       map[string][]string{"/coffee": {"two"}},
			policies: []*conf_v1.Policy{
				jwtPolicy("one", authzForClaims(claimEq("a.b", "x"))),
				jwtPolicy("two", authzForClaims(claimEq("a-b", "y"))),
			},
			rejected: []string{"two"},
		},
		{
			name:         "the same claim in two policies is fine and is extracted once",
			specPolicies: []string{"one"},
			routes:       map[string][]string{"/tea": {"two"}},
			policies: []*conf_v1.Policy{
				jwtPolicy("one", authzForClaims(claimEq("iss", "x"))),
				jwtPolicy("two", authzForClaims(claimEq("iss", "y"))),
			},
		},
		{
			name:         "authorization and rate limiting on the same claim path are fine",
			specPolicies: []string{"rate", "authz"},
			policies: []*conf_v1.Policy{
				rateLimitJWTPolicy("rate", "user.level"),
				jwtPolicy("authz", authzForClaims(claimEq("user.level", "Premium"))),
			},
		},
		{
			name:         "two rate limits that collide keep their old behavior: accepted, nothing reported, first claim kept",
			specPolicies: []string{"first", "second"},
			policies: []*conf_v1.Policy{
				rateLimitJWTPolicy("first", "a.b"),
				rateLimitJWTPolicy("second", "a_b"),
			},
			variable:  "$jwt_default_cafe_vs_a_b",
			extracted: "a b",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, warnings := generateJWTTestConfig(t, jwtVS(tc.specPolicies, tc.routes, tc.policies...))
			text := warningsText(warnings)

			assertCollisionWarnings(t, text, tc.rejected, tc.reported)
			if len(tc.rejected) == 0 {
				assertNoErrorReturn(t, cfg)
			}

			byVar := assertOneClaimPerVariable(t, cfg)
			if tc.variable != "" {
				want := generateAuthJwtClaimSetClaim(tc.extracted)
				if got := byVar[strings.ToLower(tc.variable)]; got != want {
					t.Errorf("claim extracted for %s = %q, want %q", tc.variable, got, want)
				}
			}
		})
	}
}

func assertCollisionWarnings(t *testing.T, text string, rejected, reported []string) {
	t.Helper()

	for _, name := range rejected {
		if !strings.Contains(text, "default/"+name+" is rejected") || !strings.Contains(text, "same NGINX variable") {
			t.Errorf("policy %s must be rejected with a collision warning, got:\n%s", name, text)
		}
	}
	for _, name := range reported {
		if !strings.Contains(text, "default/"+name+" keys on a claim that collides with a JWT authorization claim") {
			t.Errorf("rate limit %s must be reported, got:\n%s", name, text)
		}
		if strings.Contains(text, "default/"+name+" is rejected") {
			t.Errorf("rate limit %s must never be rejected, got:\n%s", name, text)
		}
	}
	if len(rejected) == 0 && len(reported) == 0 && text != "" {
		t.Errorf("unexpected warnings: %s", text)
	}
}

func assertNoErrorReturn(t *testing.T, cfg version2.VirtualServerConfig) {
	t.Helper()

	for _, l := range cfg.Server.Locations {
		if l.PoliciesErrorReturn != nil {
			t.Errorf("%s: unexpected error return %+v", l.Path, l.PoliciesErrorReturn)
		}
	}
	if cfg.Server.PoliciesErrorReturn != nil {
		t.Errorf("unexpected server error return %+v", cfg.Server.PoliciesErrorReturn)
	}
}

// assertOneClaimPerVariable fails if a variable is extracted for two different claims, and returns
// the claim extracted for each variable. This is the bypass check.
func assertOneClaimPerVariable(t *testing.T, cfg version2.VirtualServerConfig) map[string]string {
	t.Helper()

	byVar := map[string]string{}
	for _, cs := range cfg.AuthJWTClaimSets {
		key := strings.ToLower(cs.Variable)
		if prev, ok := byVar[key]; ok && prev != cs.Claim {
			t.Errorf("variable %s is extracted for both %q and %q", cs.Variable, prev, cs.Claim)
		}
		byVar[key] = cs.Claim
	}
	return byVar
}

// Claims that differ only in case share one NGINX variable. Whichever policy comes first owns it,
// and the claim sets are not de-duplicated case-insensitively, so only one may be emitted.
func TestVirtualServerJWTAuthorization_ClaimsDifferingInCaseEmitOneClaimSet(t *testing.T) {
	t.Parallel()

	authz := jwtPolicy("authz", authzForClaims(claimEq("role", "admin")))
	rate := rateLimitJWTPolicy("rate", "Role")
	variable := "$jwt_default_cafe_vs_role"

	tests := []struct {
		name         string
		specPolicies []string
		routes       map[string][]string
		rejected     []string
		reported     []string
		wantClaim    string
	}{
		{"authorization then rate limit on the spec", []string{"authz", "rate"}, nil, nil, []string{"rate"}, "role"},
		{"authorization on the spec, rate limit on a route", []string{"authz"}, map[string][]string{"/tea": {"rate"}}, nil, []string{"rate"}, "role"},
		{"authorization then rate limit on one route", nil, map[string][]string{"/tea": {"authz", "rate"}}, nil, []string{"rate"}, "role"},
		{"rate limit then authorization on the spec", []string{"rate", "authz"}, nil, []string{"authz"}, nil, ""},
		{"rate limit on the spec, authorization on a route", []string{"rate"}, map[string][]string{"/tea": {"authz"}}, []string{"authz"}, nil, "Role"},
		{"rate limit then authorization on one route", nil, map[string][]string{"/tea": {"rate", "authz"}}, []string{"authz"}, nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, warnings := generateJWTTestConfig(t, jwtVS(tc.specPolicies, tc.routes, authz, rate))

			assertCollisionWarnings(t, warningsText(warnings), tc.rejected, tc.reported)

			var extracted []string
			for _, cs := range cfg.AuthJWTClaimSets {
				if strings.EqualFold(cs.Variable, variable) {
					extracted = append(extracted, cs.Claim)
				}
			}
			// When the rejected policy shares a call with the rate limit, the whole context fails
			// closed with a 500, so nothing is extracted. Otherwise exactly the first claim is.
			want := []string{tc.wantClaim}
			if tc.wantClaim == "" {
				want = nil
			}
			if diff := cmp.Diff(want, extracted); diff != "" {
				t.Errorf("claims extracted for %s (-want +got):\n%s", variable, diff)
			}
		})
	}
}

// The authorization claim must be extracted whatever the policy order, since de-duplication keeps
// the first claim set per variable.
func TestVirtualServerJWTAuthorization_AuthorizationClaimWinsExtractionWhateverTheOrder(t *testing.T) {
	t.Parallel()

	authz := jwtPolicy("authz", authzForClaims(claimEq("a_b", "x")))
	rate := rateLimitJWTPolicy("rate", "a.b")
	variable := "$jwt_default_cafe_vs_a_b"

	tests := []struct {
		name         string
		specPolicies []string
		routes       map[string][]string
	}{
		{"both on the spec, authorization first", []string{"authz", "rate"}, nil},
		{"rate limit on the spec, authorization on a route", []string{"rate"}, map[string][]string{"/tea": {"authz"}}},
		{"authorization on the spec, rate limit on a route", []string{"authz"}, map[string][]string{"/tea": {"rate"}}},
		{"both on the same route", nil, map[string][]string{"/tea": {"authz", "rate"}}},
		{"on different routes", nil, map[string][]string{"/tea": {"rate"}, "/coffee": {"authz"}}},
		{"on different routes, reversed", nil, map[string][]string{"/tea": {"authz"}, "/coffee": {"rate"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, _ := generateJWTTestConfig(t, jwtVS(tc.specPolicies, tc.routes, authz, rate))

			var extracted []string
			for _, cs := range cfg.AuthJWTClaimSets {
				if strings.EqualFold(cs.Variable, variable) {
					extracted = append(extracted, cs.Claim)
				}
			}
			if len(extracted) != 1 {
				t.Fatalf("claims extracted for %s = %v, want exactly one", variable, extracted)
			}

			authzAccepted := false
			for _, l := range cfg.Server.Locations {
				if l.JWTAuth != nil && l.JWTAuth.RequireVariable != "" {
					authzAccepted = true
				}
			}
			if cfg.Server.JWTAuth != nil && cfg.Server.JWTAuth.RequireVariable != "" {
				authzAccepted = true
			}
			if authzAccepted && extracted[0] != "a_b" {
				t.Errorf("authorization is in effect but the claim extracted is %q, so its check would read the wrong claim", extracted[0])
			}
		})
	}
}

// Same rule for a VSR subroute, which appends claim sets separately.
func TestVirtualServerJWTAuthorization_AuthorizationClaimWinsExtractionOnVSRSubroute(t *testing.T) {
	t.Parallel()

	authz := jwtPolicy("authz", authzForClaims(claimEq("a_b", "x")))
	rate := rateLimitJWTPolicy("rate", "a.b")
	variable := "$jwt_default_cafe_vs_a_b"

	for _, order := range [][]string{{"authz", "rate"}, {"rate", "authz"}} {
		name := strings.Join(order, " then ")
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			vsEx := jwtVS(nil, nil, authz, rate)
			vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{{Path: "/tea", Route: "default/tea-vsr"}}
			var refs []conf_v1.PolicyReference
			for _, n := range order {
				refs = append(refs, conf_v1.PolicyReference{Name: n, Namespace: "default"})
			}
			vsEx.VirtualServerRoutes = []*conf_v1.VirtualServerRoute{{
				ObjectMeta: meta_v1.ObjectMeta{Name: "tea-vsr", Namespace: "default"},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host:      "cafe.example.com",
					Upstreams: []conf_v1.Upstream{{Name: "tea", Service: "tea-svc", Port: 80}},
					Subroutes: []conf_v1.Route{{Path: "/tea", Action: &conf_v1.Action{Pass: "tea"}, Policies: refs}},
				},
			}}

			cfg, _ := generateJWTTestConfig(t, vsEx)

			var extracted []string
			for _, cs := range cfg.AuthJWTClaimSets {
				if strings.EqualFold(cs.Variable, variable) {
					extracted = append(extracted, cs.Claim)
				}
			}

			tea := locationByPath(t, cfg, "/tea")
			authzAccepted := tea.JWTAuth != nil && tea.JWTAuth.RequireVariable != ""

			if name == "authz then rate" {
				if !authzAccepted {
					t.Fatal("authorization registered first and must be accepted")
				}
				if len(extracted) != 1 || extracted[0] != "a_b" {
					t.Errorf("claims extracted for %s = %v, want exactly [a_b]", variable, extracted)
				}
				return
			}

			// Authorization is rejected and the subroute fails closed, rendering no claim sets.
			if authzAccepted {
				t.Fatal("authorization collides with an earlier rate limit and must be rejected")
			}
			if tea.PoliciesErrorReturn == nil || tea.PoliciesErrorReturn.Code != 500 {
				t.Errorf("PoliciesErrorReturn = %+v, a rejected authorization policy must fail the subroute closed", tea.PoliciesErrorReturn)
			}
			if len(extracted) != 0 {
				t.Errorf("a failed subroute extracted %v, want none", extracted)
			}
		})
	}
}

// The registry is shared with subroutes: one that collides with the spec or a route must be rejected.
func TestVirtualServerJWTAuthorization_ClaimRegistryIsSharedWithSubroutes(t *testing.T) {
	t.Parallel()

	authzDot := jwtPolicy("authz-dot", authzForClaims(claimEq("a.b", "x")))
	authzUnderscore := jwtPolicy("authz-underscore", authzForClaims(claimEq("a_b", "y")))

	subroutePolicy := func(name string) []*conf_v1.VirtualServerRoute {
		return []*conf_v1.VirtualServerRoute{{
			ObjectMeta: meta_v1.ObjectMeta{Name: "tea-vsr", Namespace: "default"},
			Spec: conf_v1.VirtualServerRouteSpec{
				Host:      "cafe.example.com",
				Upstreams: []conf_v1.Upstream{{Name: "tea", Service: "tea-svc", Port: 80}},
				Subroutes: []conf_v1.Route{{
					Path:     "/tea",
					Action:   &conf_v1.Action{Pass: "tea"},
					Policies: []conf_v1.PolicyReference{{Name: name, Namespace: "default"}},
				}},
			},
		}}
	}

	tests := []struct {
		name   string
		spec   []string
		routes map[string][]string
	}{
		{"first on the spec", []string{"authz-dot"}, nil},
		{"first on a route", nil, map[string][]string{"/coffee": {"authz-dot"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vsEx := jwtVS(tc.spec, tc.routes, authzDot, authzUnderscore)
			vsEx.VirtualServer.Spec.Routes = append(vsEx.VirtualServer.Spec.Routes[:0:0], conf_v1.Route{Path: "/tea", Route: "default/tea-vsr"})
			if len(tc.routes) > 0 {
				vsEx.VirtualServer.Spec.Routes = append(vsEx.VirtualServer.Spec.Routes, conf_v1.Route{
					Path:     "/coffee",
					Action:   &conf_v1.Action{Pass: "coffee"},
					Policies: []conf_v1.PolicyReference{{Name: "authz-dot", Namespace: "default"}},
				})
			}
			vsEx.VirtualServerRoutes = subroutePolicy("authz-underscore")

			cfg, warnings := generateJWTTestConfig(t, vsEx)

			text := warningsText(warnings)
			if !strings.Contains(text, "default/authz-underscore is rejected") || !strings.Contains(text, "same NGINX variable") {
				t.Errorf("the subroute policy must be rejected for colliding with the earlier claim, got:\n%s", text)
			}

			tea := locationByPath(t, cfg, "/tea")
			if tea.PoliciesErrorReturn == nil || tea.PoliciesErrorReturn.Code != 500 {
				t.Errorf("/tea PoliciesErrorReturn = %+v, the rejected subroute must fail closed", tea.PoliciesErrorReturn)
			}
		})
	}
}

func TestVirtualServerJWTAuthorization_RejectedPolicyFailsClosed(t *testing.T) {
	t.Parallel()

	cfg, _ := generateJWTTestConfig(t, jwtVS([]string{"rate"}, map[string][]string{"/tea": {"authz"}},
		rateLimitJWTPolicy("rate", "a.b"),
		jwtPolicy("authz", authzForClaims(claimEq("a_b", "x")))))

	tea := locationByPath(t, cfg, "/tea")
	if tea.PoliciesErrorReturn == nil || tea.PoliciesErrorReturn.Code != 500 {
		t.Errorf("/tea PoliciesErrorReturn = %+v, a rejected policy must fail closed with 500", tea.PoliciesErrorReturn)
	}
	if tea.JWTAuth != nil && tea.JWTAuth.RequireVariable != "" {
		t.Error("a rejected policy must not leave a requirement behind")
	}
	for _, cs := range cfg.AuthJWTClaimSets {
		if cs.Claim == "a b" && cs.Variable == "$jwt_default_cafe_vs_a_b" {
			continue // the rate-limit claim that registered first
		}
		t.Errorf("unexpected claim set %+v from the rejected policy", cs)
	}
}

// A failed policy list renders none of its claims, so they must not make a later policy collide.
func TestVirtualServerJWTAuthorization_FailedPolicyCallDoesNotRegisterItsClaims(t *testing.T) {
	t.Parallel()

	// /tea fails on a missing policy, so its a_b is never rendered. /coffee uses a.b, which collides
	// only if the failed call leaked a_b into the registry.
	vsEx := jwtVS(nil, map[string][]string{
		"/tea":    {"authz-ab", "does-not-exist"},
		"/coffee": {"authz-dot"},
	},
		jwtPolicy("authz-ab", authzForClaims(claimEq("a_b", "x"))),
		jwtPolicy("authz-dot", authzForClaims(claimEq("a.b", "y"))),
	)

	cfg, warnings := generateJWTTestConfig(t, vsEx)
	text := warningsText(warnings)

	if !strings.Contains(text, "does-not-exist") {
		t.Fatalf("the test needs /tea to fail on the missing policy, got:\n%s", text)
	}
	if strings.Contains(text, "authz-dot is rejected") {
		t.Errorf("/coffee was rejected because of a claim that /tea never rendered:\n%s", text)
	}

	coffee := locationByPath(t, cfg, "/coffee")
	if coffee.PoliciesErrorReturn != nil {
		t.Errorf("/coffee PoliciesErrorReturn = %+v, want none", coffee.PoliciesErrorReturn)
	}
	if coffee.JWTAuth == nil || coffee.JWTAuth.RequireVariable == "" {
		t.Errorf("/coffee JWTAuth = %+v, want its own requirement", coffee.JWTAuth)
	}

	tea := locationByPath(t, cfg, "/tea")
	if tea.PoliciesErrorReturn == nil || tea.PoliciesErrorReturn.Code != 500 {
		t.Errorf("/tea PoliciesErrorReturn = %+v, a failed policy list must fail closed", tea.PoliciesErrorReturn)
	}
}

func TestVirtualServerJWTAuthorization_RateLimitWithoutCollisionUnchanged(t *testing.T) {
	t.Parallel()

	cfg, warnings := generateJWTTestConfig(t, jwtVS([]string{"rate"}, nil, rateLimitJWTPolicy("rate", "user_details.level")))
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_details_level", Claim: "user_details level"}}
	if diff := cmp.Diff(want, cfg.AuthJWTClaimSets); diff != "" {
		t.Errorf("AuthJWTClaimSets mismatch (-want +got):\n%s", diff)
	}
}

func TestAddJWTAuthConfig_SecretBasedPolicyCarriesAuthorization(t *testing.T) {
	t.Parallel()

	authz := &conf_v1.JWTAuthorization{
		ErrorCode: new(403),
		Rules:     []conf_v1.JWTAuthorizationRule{{Claims: []conf_v1.JWTClaim{claimWithHeader("iss", "X-Iss", "a")}}},
	}
	cfg := &policiesCfg{}
	secretRefs := map[secrets.SecretRefKey]*secrets.SecretReference{
		secrets.RefKey("default/jwk", secrets.RoleJWK): {Secret: &api_v1.Secret{}, Path: jwtTestSecretPath},
	}
	jwt := &conf_v1.JWTAuth{Realm: "API", Secret: "jwk", Authorization: authz}
	res := cfg.addJWTAuthConfig(jwt, "default/pol", "default", "pol", secretRefs, jwtOwner("default", "cafe"), jwtClaimRegistry{})

	if res.isError || len(res.warnings) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if cfg.JWTAuth.Auth.Secret != jwtTestSecretPath {
		t.Errorf("Secret = %q", cfg.JWTAuth.Auth.Secret)
	}
	if cfg.JWTAuth.Auth.RequireVariable != "$jwt_authz_default_cafe_vs_default_pol" || cfg.JWTAuth.Auth.RequireErrorCode != 403 {
		t.Errorf("Auth = %+v", cfg.JWTAuth.Auth)
	}
	if len(cfg.JWTAuth.Maps) == 0 || len(cfg.JWTAuth.ClaimSets) != 1 {
		t.Errorf("maps %d, claim sets %d", len(cfg.JWTAuth.Maps), len(cfg.JWTAuth.ClaimSets))
	}
}

func TestAddJWTAuthConfig_SecondJWTPolicyIsIgnoredAndLeavesNoAuthorization(t *testing.T) {
	t.Parallel()

	cfg := &policiesCfg{}
	first := jwtPolicy("first", authzForClaims(claimEq("iss", "a"))).Spec.JWTAuth
	second := jwtPolicy("second", authzForClaims(claimEq("tier", "b"))).Spec.JWTAuth
	owner := jwtOwner("default", "cafe")
	registry := jwtClaimRegistry{}

	cfg.addJWTAuthConfig(first, "default/first", "default", "first", nil, owner, registry)
	res := cfg.addJWTAuthConfig(second, "default/second", "default", "second", nil, owner, registry)

	if len(res.warnings) != 1 || !strings.Contains(res.warnings[0], "Multiple jwt policies") {
		t.Errorf("warnings = %v", res.warnings)
	}
	if cfg.JWTAuth.Auth.RequireVariable != "$jwt_authz_default_cafe_vs_default_first" {
		t.Errorf("the second policy replaced the first: %+v", cfg.JWTAuth.Auth)
	}
	for _, cs := range cfg.JWTAuth.ClaimSets {
		if cs.Claim == "tier" {
			t.Error("the ignored policy's claims must not be extracted")
		}
	}
	if conflict := registry.claimAuthorization([]version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_tier", Claim: "tier_other"}}); conflict != "" {
		t.Errorf("the ignored policy registered its claim: %s", conflict)
	}
}

// Rate limits with colliding claims behave as before this feature: accepted, silent, first claim
// extracted. Expected values come from running these scenarios on the branch's merge base.
func TestRateLimitWithCollidingClaimsKeepsItsBehaviour(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		specPolicies  []string
		routes        map[string][]string
		policies      []*conf_v1.Policy
		wantClaimSets []version2.AuthJWTClaimSet
	}{
		{
			name:          "documented tiered example, same claim",
			specPolicies:  []string{"p", "b"},
			policies:      []*conf_v1.Policy{rateLimitJWTPolicy("p", "user_details.level"), rateLimitJWTPolicy("b", "user_details.level")},
			wantClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_details_level", Claim: "user_details level"}},
		},
		{
			name:          "dot vs dash on the spec",
			specPolicies:  []string{"p", "b"},
			policies:      []*conf_v1.Policy{rateLimitJWTPolicy("p", "a.b"), rateLimitJWTPolicy("b", "a-b")},
			wantClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_a_b", Claim: "a b"}},
		},
		{
			name:          "dot vs underscore on the spec",
			specPolicies:  []string{"p", "b"},
			policies:      []*conf_v1.Policy{rateLimitJWTPolicy("p", "a.b"), rateLimitJWTPolicy("b", "a_b")},
			wantClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_a_b", Claim: "a b"}},
		},
		{
			name:          "spec vs route",
			specPolicies:  []string{"p"},
			routes:        map[string][]string{"/tea": {"b"}},
			policies:      []*conf_v1.Policy{rateLimitJWTPolicy("p", "a.b"), rateLimitJWTPolicy("b", "a_b")},
			wantClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_a_b", Claim: "a b"}},
		},
		{
			name:          "two routes",
			routes:        map[string][]string{"/tea": {"p"}, "/coffee": {"b"}},
			policies:      []*conf_v1.Policy{rateLimitJWTPolicy("p", "a.b"), rateLimitJWTPolicy("b", "a-b")},
			wantClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_a_b", Claim: "a b"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, warnings := generateJWTTestConfig(t, jwtVS(tc.specPolicies, tc.routes, tc.policies...))

			if len(warnings) != 0 {
				t.Errorf("rate limits that collide were never reported, got: %v", warnings)
			}
			if cfg.Server.PoliciesErrorReturn != nil {
				t.Errorf("a rate limit must never be rejected, server error return %+v", cfg.Server.PoliciesErrorReturn)
			}
			for _, l := range cfg.Server.Locations {
				if l.PoliciesErrorReturn != nil {
					t.Errorf("a rate limit must never be rejected, %s error return %+v", l.Path, l.PoliciesErrorReturn)
				}
			}
			if diff := cmp.Diff(tc.wantClaimSets, cfg.AuthJWTClaimSets); diff != "" {
				t.Errorf("AuthJWTClaimSets mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
