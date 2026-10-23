package version2

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

const (
	jwtAuthzServerVar = "$jwt_authz_default_cafe_vs_default_shop_jwt"
	jwtAuthzRouteVar  = "$jwt_authz_default_cafe_vs_default_route_jwt"
	jwtAuthzNoneVar   = "$jwt_authz_none_default_cafe"
)

func jwtAuthzSecretAuth(realm, secret, requireVar string, errorCode int) *JWTAuth {
	return &JWTAuth{
		Realm:            realm,
		Secret:           secret,
		RequireVariable:  requireVar,
		RequireErrorCode: errorCode,
	}
}

func jwtAuthzJWKSAuth(key, requireVar string, errorCode int) *JWTAuth {
	return &JWTAuth{
		Key:              key,
		Realm:            "api",
		Token:            "$http_token",
		KeyCache:         "1h",
		JwksURI:          JwksURI{JwksScheme: "https", JwksHost: "idp.example.com", JwksPath: "/keys"},
		RequireVariable:  requireVar,
		RequireErrorCode: errorCode,
	}
}

func jwtAuthzLocation(path string) Location {
	return Location{
		Path:                path,
		ProxyConnectTimeout: "30s",
		ProxyReadTimeout:    "31s",
		ProxySendTimeout:    "32s",
		ClientMaxBodySize:   "1m",
		ProxyPass:           "http://coffee-v1",
		ServiceName:         "coffee-svc",
		ProxySetHeaders:     []Header{{Name: "Host", Value: "$host"}},
	}
}

func jwtAuthzCfg(server *JWTAuth, locations ...Location) VirtualServerConfig {
	return VirtualServerConfig{
		Upstreams: []Upstream{{Name: "coffee-v1", Servers: []UpstreamServer{{Address: "10.0.0.31:8001"}}}},
		Server: Server{
			ServerName:  "cafe.example.com",
			StatusZone:  "cafe.example.com",
			VSNamespace: "default",
			VSName:      "cafe",
			JWTAuth:     server,
			Locations:   locations,
		},
	}
}

func executeJWTAuthzTemplate(t *testing.T, cfg VirtualServerConfig) string {
	t.Helper()

	data, err := newTmplExecutorNGINXPlus(t).ExecuteVirtualServerTemplate(&cfg)
	if err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}
	return string(data)
}

func TestVirtualServerForNginxPlusJWTAuthorizationServerLevel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		auth      *JWTAuth
		errorCode int
	}{
		{"secret, 403", jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 403), 403},
		{"secret, 401", jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 401), 401},
		{"jwks, 403", jwtAuthzJWKSAuth("default/shop-jwt", jwtAuthzServerVar, 403), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := executeJWTAuthzTemplate(t, jwtAuthzCfg(tc.auth, jwtAuthzLocation("/coffee")))

			want := "auth_jwt_require " + jwtAuthzServerVar + " error=" + strconv.Itoa(tc.errorCode) + ";"
			assertCount(t, conf, want, 1)
			assertCount(t, conf, "auth_jwt_require", 1)

			// auth_jwt_require sits with the auth_jwt it belongs to, and the location inherits it.
			coffee := locationBlock(t, conf, `"/coffee"`)
			assertCount(t, coffee, "auth_jwt", 0)
			assertCount(t, coffee, "auth_jwt_require", 0)

			snaps.MatchSnapshot(t, conf)
		})
	}
}

func TestVirtualServerForNginxPlusJWTAuthorizationRouteLevel(t *testing.T) {
	t.Parallel()

	coffee := jwtAuthzLocation("/coffee")
	coffee.JWTAuth = jwtAuthzSecretAuth("route", "/etc/nginx/secrets/default-route-jwk", jwtAuthzRouteVar, 401)
	tea := jwtAuthzLocation("/tea")

	conf := executeJWTAuthzTemplate(t, jwtAuthzCfg(nil, coffee, tea))

	block := locationBlock(t, conf, `"/coffee"`)
	assertCount(t, block, `auth_jwt "route";`, 1)
	assertCount(t, block, "auth_jwt_require "+jwtAuthzRouteVar+" error=401;", 1)
	assertCount(t, locationBlock(t, conf, `"/tea"`), "auth_jwt", 0)
	assertCount(t, conf, "auth_jwt_require", 1)

	snaps.MatchSnapshot(t, conf)
}

// A route policy replaces the server's auth_jwt, but auth_jwt_require is inherited and has no "off",
// so the location resets it. A route policy with its own authorization sets its own requirement.
func TestVirtualServerForNginxPlusJWTAuthorizationMixedPolicies(t *testing.T) {
	t.Parallel()

	plain := jwtAuthzLocation("/plain")
	plain.JWTAuth = jwtAuthzSecretAuth("plain", "/etc/nginx/secrets/default-plain-jwk", "", 0)
	plain.JWTRequireReset = jwtAuthzNoneVar

	own := jwtAuthzLocation("/own")
	own.JWTAuth = jwtAuthzSecretAuth("own", "/etc/nginx/secrets/default-own-jwk", jwtAuthzRouteVar, 401)

	inherits := jwtAuthzLocation("/inherits")

	cfg := jwtAuthzCfg(jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 403), plain, own, inherits)
	cfg.Maps = []Map{{Source: "$uri", Variable: jwtAuthzNoneVar, Parameters: []Parameter{{Value: "default", Result: "1"}}}}
	conf := executeJWTAuthzTemplate(t, cfg)

	assertCount(t, conf, "map $uri "+jwtAuthzNoneVar+" {", 1)

	plainBlock := locationBlock(t, conf, `"/plain"`)
	assertCount(t, plainBlock, `auth_jwt "plain";`, 1)
	assertCount(t, plainBlock, "auth_jwt_require "+jwtAuthzNoneVar+";", 1)
	assertCount(t, plainBlock, "error=", 0)

	ownBlock := locationBlock(t, conf, `"/own"`)
	assertCount(t, ownBlock, "auth_jwt_require "+jwtAuthzRouteVar+" error=401;", 1)
	assertCount(t, ownBlock, jwtAuthzNoneVar, 0)

	inheritsBlock := locationBlock(t, conf, `"/inherits"`)
	assertCount(t, inheritsBlock, "auth_jwt", 0)

	snaps.MatchSnapshot(t, conf)
}

// The legacy OIDC location runs auth_jwt on the session token, which carries IdP claims and not the
// claims the server policy requires, so it resets the inherited requirement.
func TestVirtualServerForNginxPlusJWTAuthorizationWithOIDCLocation(t *testing.T) {
	t.Parallel()

	oidc := jwtAuthzLocation("/login")
	oidc.OIDC = true
	oidc.JWTRequireReset = jwtAuthzNoneVar

	cfg := jwtAuthzCfg(jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 403), oidc, jwtAuthzLocation("/coffee"))
	cfg.Server.OIDC = &OIDC{
		PolicyName: "default/oidc", AuthEndpoint: "https://idp.example.com/auth", TokenEndpoint: "https://idp.example.com/token",
		JwksURI: "https://idp.example.com/keys", ClientID: "client", ClientSecret: "secret", Scope: "openid", RedirectURI: "/_codexch",
	}
	cfg.Maps = []Map{{Source: "$uri", Variable: jwtAuthzNoneVar, Parameters: []Parameter{{Value: "default", Result: "1"}}}}
	conf := executeJWTAuthzTemplate(t, cfg)

	login := locationBlock(t, conf, `"/login"`)
	assertCount(t, login, `auth_jwt "" token=$session_jwt;`, 1)
	assertCount(t, login, "auth_jwt_require "+jwtAuthzNoneVar+";", 1)
	assertCount(t, locationBlock(t, conf, `"/coffee"`), "auth_jwt", 0)

	snaps.MatchSnapshot(t, conf)
}

// ACME challenge locations render auth_jwt off, which disables the module, so auth_jwt_require is
// never evaluated and must not be emitted next to it. The JWKS location is reached by subrequest.
func TestVirtualServerForNginxPlusJWTAuthorizationACMEAndJWKSLocations(t *testing.T) {
	t.Parallel()

	// A reset on the challenge location must not be rendered either, whatever the generator sets.
	acme := acmeChallengeTestLocation()
	acme.JWTRequireReset = jwtAuthzNoneVar
	cfg := acmeChallengeTestCfg(jwtAuthzCfg(jwtAuthzJWKSAuth("default/shop-jwt", jwtAuthzServerVar, 403)), acme)
	cfg.Server.JWTAuthList = map[string]*JWTAuth{"default/shop-jwt": jwtAuthzJWKSAuth("default/shop-jwt", jwtAuthzServerVar, 403)}
	cfg.Server.JWKSAuthEnabled = true
	conf := executeJWTAuthzTemplate(t, cfg)

	challenge := locationBlock(t, conf, acmeChallengeTestLocArg)
	assertCount(t, challenge, "auth_jwt off;", 1)
	assertCount(t, challenge, "auth_jwt_require", 0)

	jwks := locationBlock(t, conf, "= /_jwks_uri_server_default/shop-jwt")
	assertCount(t, jwks, "auth_jwt", 0)

	assertCount(t, conf, "auth_jwt_require", 1)
	snaps.MatchSnapshot(t, conf)
}

func TestVirtualServerForNginxPlusJWTAuthorizationClaimHeaders(t *testing.T) {
	t.Parallel()

	// The generator produces per-claim sanitizing maps (source=claim var, variable=claimVar_hdr)
	// that strip CR/LF before the value is forwarded. Locations use the _hdr variable.
	sanitisingMaps := []Map{
		{
			Source:   "$jwt_default_cafe_vs_scope",
			Variable: "$jwt_authz_r0_c0_hdr",
			Parameters: []Parameter{
				{Value: `"~[\r\n]"`, Result: `""`},
				{Value: "default", Result: "$jwt_default_cafe_vs_scope"},
			},
		},
		{
			Source:   "$jwt_default_cafe_vs_ip",
			Variable: "$jwt_authz_r0_c1_hdr",
			Parameters: []Parameter{
				{Value: `"~[\r\n]"`, Result: `""`},
				{Value: "default", Result: "$jwt_default_cafe_vs_ip"},
			},
		},
		{
			Source:   "$jwt_default_cafe_vs_tenant",
			Variable: "$jwt_authz_r0_c2_hdr",
			Parameters: []Parameter{
				{Value: `"~[\r\n]"`, Result: `""`},
				{Value: "default", Result: "$jwt_default_cafe_vs_tenant"},
			},
		},
	}

	http := jwtAuthzLocation("/http")
	http.ProxySetHeaders = []Header{
		{Name: "X-Token-Scope", Value: "$jwt_authz_r0_c0_hdr"},
		{Name: "X-Real-IP", Value: "$jwt_authz_r0_c1_hdr"},
		{Name: "Host", Value: "$jwt_authz_r0_c2_hdr"},
	}

	grpc := jwtAuthzLocation("/grpc")
	grpc.ProxyPass = ""
	grpc.GRPCPass = "grpc://coffee-v1"
	grpc.ProxySetHeaders = []Header{{Name: "X-Token-Scope", Value: "$jwt_authz_r0_c0_hdr"}}

	cfg := jwtAuthzCfg(jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 403), http, grpc)
	cfg.Maps = sanitisingMaps
	conf := executeJWTAuthzTemplate(t, cfg)

	httpBlock := locationBlock(t, conf, `"/http"`)
	assertCount(t, httpBlock, `proxy_set_header X-Token-Scope "$jwt_authz_r0_c0_hdr";`, 1)
	// A policy X-Real-IP is in the list the template checks, so the NIC default is not emitted next to it.
	assertCount(t, httpBlock, "proxy_set_header X-Real-IP", 1)
	assertCount(t, httpBlock, `proxy_set_header X-Real-IP "$jwt_authz_r0_c1_hdr";`, 1)
	// A policy Host replaces the fallback Host.
	assertCount(t, httpBlock, "proxy_set_header Host", 1)
	// The sanitizing maps are rendered before the server block.
	assertCount(t, conf, `"~[\r\n]" "";`, 3)

	grpcBlock := locationBlock(t, conf, `"/grpc"`)
	assertCount(t, grpcBlock, `grpc_set_header X-Token-Scope "$jwt_authz_r0_c0_hdr";`, 1)
	assertCount(t, grpcBlock, "proxy_set_header X-Token-Scope", 0)

	snaps.MatchSnapshot(t, conf)
}

func TestVirtualServerForNginxPlusJWTAuthorizationMapChain(t *testing.T) {
	t.Parallel()

	cfg := jwtAuthzCfg(jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 403), jwtAuthzLocation("/coffee"))
	cfg.AuthJWTClaimSets = []AuthJWTClaimSet{
		{Variable: "$jwt_default_cafe_vs_aud", Claim: "aud"},
		{Variable: "$jwt_default_cafe_vs_realm_access_roles", Claim: "realm_access roles"},
	}
	cfg.Maps = []Map{
		{Source: "$jwt_default_cafe_vs_aud", Variable: jwtAuthzServerVar + "_r0_c0", Parameters: []Parameter{
			{Value: `""`, Result: "0"},
			{Value: `"~(^|[ ,])(orders-api)([ ,]|\\z)"`, Result: "1"},
			{Value: "default", Result: "0"},
		}},
		{Source: "$jwt_default_cafe_vs_realm_access_roles", Variable: jwtAuthzServerVar + "_r0_c1", Parameters: []Parameter{
			{Value: `""`, Result: "0"},
			{Value: `"~(^|[ ,])(guest)([ ,]|\\z)"`, Result: "0"},
			{Value: "default", Result: "1"},
		}},
		{Source: jwtAuthzServerVar + "_r0_c0" + jwtAuthzServerVar + "_r0_c1", Variable: jwtAuthzServerVar + "_r0", Parameters: []Parameter{
			{Value: `"~^1+$"`, Result: "1"},
			{Value: "default", Result: "0"},
		}},
		{Source: jwtAuthzServerVar + "_r0", Variable: jwtAuthzServerVar, Parameters: []Parameter{
			{Value: `"~^1+$"`, Result: "1"},
			{Value: "default", Result: "0"},
		}},
	}
	conf := executeJWTAuthzTemplate(t, cfg)

	assertCount(t, conf, "auth_jwt_claim_set $jwt_default_cafe_vs_aud aud;", 1)
	assertCount(t, conf, "auth_jwt_claim_set $jwt_default_cafe_vs_realm_access_roles realm_access roles;", 1)
	assertCount(t, conf, `"~(^|[ ,])(orders-api)([ ,]|\\z)" 1;`, 1)

	// The claim sets and maps are defined before the server that reads them.
	if strings.Index(conf, "map "+jwtAuthzServerVar+"_r0 ") > strings.Index(conf, "server {") {
		t.Error("the rule and policy maps must be defined before the server block")
	}
	snaps.MatchSnapshot(t, conf)
}

// A JWT policy without authorization must render exactly as before: no auth_jwt_require.
func TestVirtualServerForNginxPlusJWTWithoutAuthorizationHasNoRequire(t *testing.T) {
	t.Parallel()

	route := jwtAuthzLocation("/route")
	route.JWTAuth = jwtAuthzSecretAuth("route", "/etc/nginx/secrets/default-route-jwk", "", 0)

	conf := executeJWTAuthzTemplate(t, jwtAuthzCfg(jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", "", 0), route, jwtAuthzLocation("/coffee")))

	assertCount(t, conf, "auth_jwt_require", 0)
	assertCount(t, conf, "error=0", 0)
	assertCount(t, conf, `auth_jwt "api";`, 1)
	assertCount(t, conf, `auth_jwt "route";`, 1)
}

// The OSS template has no JWT support, so nothing from this feature may appear in it.
func TestVirtualServerForNginxOSSIgnoresJWTAuthorization(t *testing.T) {
	t.Parallel()

	loc := jwtAuthzLocation("/coffee")
	loc.JWTRequireReset = jwtAuthzNoneVar
	cfg := jwtAuthzCfg(jwtAuthzSecretAuth("api", "/etc/nginx/secrets/default-jwk", jwtAuthzServerVar, 403), loc)

	data, err := newTmplExecutorNGINX(t).ExecuteVirtualServerTemplate(&cfg)
	if err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}
	conf := string(data)

	assertCount(t, conf, "auth_jwt", 0)
	assertCount(t, conf, "jwt_authz", 0)
}
