package configs

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestGenerateVirtualServerConfigJWKSPolicy(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Policies: []conf_v1.PolicyReference{
					{
						Name: "jwt-policy",
					},
				},
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
						Policies: []conf_v1.PolicyReference{
							{
								Name: "jwt-policy-route",
							},
						},
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
						Policies: []conf_v1.PolicyReference{
							{
								Name: "jwt-policy-route",
							},
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/jwt-policy": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwt-policy",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					JWTAuth: &conf_v1.JWTAuth{
						Realm:      "Spec Realm API",
						JwksURI:    "https://idp.spec.example.com:443/spec-keys",
						KeyCache:   "1h",
						SNIEnabled: true,
						SNIName:    "idp.spec.example.com",
					},
				},
			},
			"default/jwt-policy-route": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwt-policy-route",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					JWTAuth: &conf_v1.JWTAuth{
						Realm:    "Route Realm API",
						JwksURI:  "http://idp.route.example.com:80/route-keys",
						KeyCache: "1h",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
		},
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			JWTAuthList: map[string]*version2.JWTAuth{
				"default/jwt-policy": {
					Key:      "default/jwt-policy",
					Realm:    "Spec Realm API",
					KeyCache: "1h",
					JwksURI: version2.JwksURI{
						JwksScheme:     "https",
						JwksHost:       "idp.spec.example.com",
						JwksPort:       "443",
						JwksPath:       "/spec-keys",
						JwksSNIEnabled: true,
						JwksSNIName:    "idp.spec.example.com",
						SSLVerify:      false,
						TrustedCert:    "",
						SSLVerifyDepth: 1,
					},
				},
				"default/jwt-policy-route": {
					Key:      "default/jwt-policy-route",
					Realm:    "Route Realm API",
					KeyCache: "1h",
					JwksURI: version2.JwksURI{
						JwksScheme:     "http",
						JwksHost:       "idp.route.example.com",
						JwksPort:       "80",
						JwksPath:       "/route-keys",
						SSLVerify:      false,
						TrustedCert:    "",
						SSLVerifyDepth: 1,
					},
				},
			},
			JWTAuth: &version2.JWTAuth{
				Key:      "default/jwt-policy",
				Realm:    "Spec Realm API",
				KeyCache: "1h",
				JwksURI: version2.JwksURI{
					JwksScheme:     "https",
					JwksHost:       "idp.spec.example.com",
					JwksPort:       "443",
					JwksPath:       "/spec-keys",
					JwksSNIName:    "idp.spec.example.com",
					JwksSNIEnabled: true,
					SSLVerify:      false,
					TrustedCert:    "",
					SSLVerifyDepth: 1,
				},
			},
			JWKSAuthEnabled: true,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
					JWTAuth: &version2.JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						KeyCache: "1h",
						JwksURI: version2.JwksURI{
							JwksScheme:     "http",
							JwksHost:       "idp.route.example.com",
							JwksPort:       "80",
							JwksPath:       "/route-keys",
							SSLVerify:      false,
							TrustedCert:    "",
							SSLVerifyDepth: 1,
						},
					},
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					JWTAuth: &version2.JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						KeyCache: "1h",
						JwksURI: version2.JwksURI{
							JwksScheme:     "http",
							JwksHost:       "idp.route.example.com",
							JwksPort:       "80",
							JwksPath:       "/route-keys",
							SSLVerify:      false,
							TrustedCert:    "",
							SSLVerifyDepth: 1,
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

// TestGenerateVirtualServerConfigExternalAuthPolicyPlusRoute tests ExternalAuth policy applied at the route level
// with NGINX Plus. ExternalAuth functionality is interchangeable between OSS and Plus — the isPlus flag does not
// affect ExternalAuth configuration generation.
func TestGenerateVirtualServerConfigExternalAuthPolicyPlusRoute(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
						Policies: []conf_v1.PolicyReference{
							{
								Name:      "external-auth-policy-route",
								Namespace: "default",
							},
						},
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/external-auth-policy-route": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "external-auth-policy-route",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					ExternalAuth: &conf_v1.ExternalAuth{
						AuthURL:       "http://auth-server:8080/auth",
						AuthSigninURL: "http://auth-server:8080/signin?rd=$scheme://$host$request_uri",
						AuthSnippets:  "proxy_set_header X-Custom-Header \"custom-value\";",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
			"default/auth-server:8080": {
				"10.0.0.40:80",
			},
		},
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "auth-server",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_pol_exauth_default_cafe_default_external_auth_policy_route",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "auth-server",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_pol_exauth_signin_default_cafe_default_external_auth_policy_route",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			Locations: []version2.Location{
				{
					Path:                    "/pol_exauth_default_cafe_default_external_auth_policy_route",
					Internal:                true,
					Snippets:                []string{`proxy_set_header X-Custom-Header "custom-value";`},
					ProxyPass:               "http://vs_default_cafe_pol_exauth_default_cafe_default_external_auth_policy_route",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders: []version2.Header{
						{Name: "Content-Length", Value: "0"},
					},
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ServiceName:              "auth-server",
					ClientMaxBodySize:        "0",
				},
				{
					Path:                    "/pol_exauth_signin_default_cafe_default_external_auth_policy_route",
					Internal:                true,
					ProxyPass:               "http://vs_default_cafe_pol_exauth_signin_default_cafe_default_external_auth_policy_route",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders: []version2.Header{
						{Name: "Content-Length", Value: "0"},
					},
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ServiceName:              "auth-server",
					ClientMaxBodySize:        "0",
				},
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ProxyInterceptErrors:     true,
					HasKeepalive:             true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "/pol_exauth_signin_default_cafe_default_external_auth_policy_route",
							Codes:        "401",
							ResponseCode: -1,
						},
					},
					ProxySSLName:            "tea-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "tea-svc",
					ExternalAuth: &version2.ExternalAuth{
						ProxyURL: "/pol_exauth_default_cafe_default_external_auth_policy_route",
						URI: version2.AuthURI{
							Scheme: "http",
							Host:   "auth-server",
							Port:   "8080",
							Path:   "/auth",
						},
						SigninURL: version2.AuthURI{
							Scheme: "http",
							Host:   "auth-server",
							Port:   "8080",
							Path:   "/signin",
						},
						SigninProxyURL: "/pol_exauth_signin_default_cafe_default_external_auth_policy_route",
						Snippets:       "proxy_set_header X-Custom-Header \"custom-value\";",
					},
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	isPlus := true
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

// TestGenerateVirtualServerConfigExternalAuthPolicyPlusSubroute tests ExternalAuth policy applied at the subroute
// level (VirtualServerRoute) with NGINX Plus. ExternalAuth functionality is interchangeable between OSS and Plus —
// the isPlus flag does not affect ExternalAuth configuration generation.
func TestGenerateVirtualServerConfigExternalAuthPolicyPlusSubroute(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path:  "/tea",
						Route: "default/tea-vsr",
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
					},
				},
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tea-vsr",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "tea-v1",
							Service: "tea-v1-svc",
							Port:    80,
						},
						{
							Name:    "tea-v2",
							Service: "tea-v2-svc",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/tea/v1",
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "external-auth-policy-subroute",
									Namespace: "default",
								},
							},
							Action: &conf_v1.Action{
								Pass: "tea-v1",
							},
						},
						{
							Path: "/tea/v2",
							Action: &conf_v1.Action{
								Pass: "tea-v2",
							},
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/external-auth-policy-subroute": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "external-auth-policy-subroute",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					ExternalAuth: &conf_v1.ExternalAuth{
						AuthURL:       "http://auth-server:8080/auth",
						AuthSigninURL: "http://auth-server:8080/signin?rd=$scheme://$host$request_uri",
						AuthSnippets:  "proxy_set_header X-Custom-Header \"custom-value\";",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
			"default/tea-v1-svc:80": {
				"10.0.0.21:80",
			},
			"default/tea-v2-svc:80": {
				"10.0.0.22:80",
			},
			"default/auth-server:8080": {
				"10.0.0.40:80",
			},
		},
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "auth-server",
					ResourceType:      "virtualserverroute",
					ResourceName:      "tea-vsr",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_tea-vsr_pol_exauth_default_tea_vsr_default_external_auth_policy_subroute",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "auth-server",
					ResourceType:      "virtualserverroute",
					ResourceName:      "tea-vsr",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_tea-vsr_pol_exauth_signin_default_tea_vsr_default_external_auth_policy_subroute",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-v1-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "tea-vsr",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_tea-vsr_tea-v1",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.21:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-v2-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "tea-vsr",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_tea-vsr_tea-v2",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.22:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			Locations: []version2.Location{
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
				},
				{
					Path:                    "/pol_exauth_default_tea_vsr_default_external_auth_policy_subroute",
					Internal:                true,
					Snippets:                []string{`proxy_set_header X-Custom-Header "custom-value";`},
					ProxyPass:               "http://vs_default_cafe_vsr_default_tea-vsr_pol_exauth_default_tea_vsr_default_external_auth_policy_subroute",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders: []version2.Header{
						{Name: "Content-Length", Value: "0"},
					},
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ServiceName:              "auth-server",
					ClientMaxBodySize:        "0",
				},
				{
					Path:                    "/pol_exauth_signin_default_tea_vsr_default_external_auth_policy_subroute",
					Internal:                true,
					ProxyPass:               "http://vs_default_cafe_vsr_default_tea-vsr_pol_exauth_signin_default_tea_vsr_default_external_auth_policy_subroute",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders: []version2.Header{
						{Name: "Content-Length", Value: "0"},
					},
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ServiceName:              "auth-server",
					ClientMaxBodySize:        "0",
				},
				{
					Path:                     "/tea/v1",
					ProxyPass:                "http://vs_default_cafe_vsr_default_tea-vsr_tea-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ProxyInterceptErrors:     true,
					HasKeepalive:             true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "/pol_exauth_signin_default_tea_vsr_default_external_auth_policy_subroute",
							Codes:        "401",
							ResponseCode: -1,
						},
					},
					ProxySSLName:            "tea-v1-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "tea-v1-svc",
					IsVSR:                   true,
					VSRName:                 "tea-vsr",
					VSRNamespace:            "default",
					ExternalAuth: &version2.ExternalAuth{
						ProxyURL: "/pol_exauth_default_tea_vsr_default_external_auth_policy_subroute",
						URI: version2.AuthURI{
							Scheme: "http",
							Host:   "auth-server",
							Port:   "8080",
							Path:   "/auth",
						},
						SigninURL: version2.AuthURI{
							Scheme: "http",
							Host:   "auth-server",
							Port:   "8080",
							Path:   "/signin",
						},
						SigninProxyURL: "/pol_exauth_signin_default_tea_vsr_default_external_auth_policy_subroute",
						Snippets:       "proxy_set_header X-Custom-Header \"custom-value\";",
					},
				},
				{
					Path:                     "/tea/v2",
					ProxyPass:                "http://vs_default_cafe_vsr_default_tea-vsr_tea-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-v2-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-v2-svc",
					IsVSR:                    true,
					VSRName:                  "tea-vsr",
					VSRNamespace:             "default",
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	isPlus := true
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigJWTSSLVerifyDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		sslVerifyDepth *int
		expectedDepth  int
		description    string
	}{
		{
			name:           "default_depth",
			sslVerifyDepth: nil, // Not specified - should default to 1
			expectedDepth:  1,
			description:    "When SSLVerifyDepth is not specified, it should default to 1",
		},
		{
			name:           "explicit_depth",
			sslVerifyDepth: createPointerFromInt(3), // Explicitly set to 3
			expectedDepth:  3,
			description:    "When SSLVerifyDepth is explicitly set, it should respect that value",
		},
		{
			name:           "explicit_zero_depth",
			sslVerifyDepth: createPointerFromInt(0), // Explicitly set to 0
			expectedDepth:  0,
			description:    "When SSLVerifyDepth is explicitly set to 0, it should respect that value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			virtualServerEx := VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "jwt-ssl-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/jwt-ssl-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "jwt-ssl-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							JWTAuth: &conf_v1.JWTAuth{
								Realm:          "SSL Test API",
								JwksURI:        "https://idp.example.com/keys",
								SSLVerify:      true,
								SSLVerifyDepth: tt.sslVerifyDepth,
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
				},
			}

			expected := version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
						Keepalive: 16,
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				Server: version2.Server{
					JWTAuthList: map[string]*version2.JWTAuth{
						"default/jwt-ssl-policy": {
							Key:   "default/jwt-ssl-policy",
							Realm: "SSL Test API",
							JwksURI: version2.JwksURI{
								JwksScheme:     "https",
								JwksHost:       "idp.example.com",
								JwksPath:       "/keys",
								SSLVerify:      true,
								SSLVerifyDepth: tt.expectedDepth,
							},
						},
					},
					JWTAuth: &version2.JWTAuth{
						Key:   "default/jwt-ssl-policy",
						Realm: "SSL Test API",
						JwksURI: version2.JwksURI{
							JwksScheme:     "https",
							JwksHost:       "idp.example.com",
							JwksPath:       "/keys",
							SSLVerify:      true,
							SSLVerifyDepth: tt.expectedDepth,
						},
					},
					JWKSAuthEnabled: true,
					ServerName:      "cafe.example.com",
					StatusZone:      "cafe.example.com",
					ProxyProtocol:   true,
					ServerTokens:    "off",
					RealIPHeader:    "X-Real-IP",
					SetRealIPFrom:   []string{"0.0.0.0/0"},
					RealIPRecursive: true,
					Snippets:        []string{"# server snippet"},
					VSNamespace:     "default",
					VSName:          "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							HasKeepalive:             true,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
					},
				},
			}

			isPlus := false
			isResolverConfigured := false
			isWildcardEnabled := false
			vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{}, isWildcardEnabled, &fakeBV)

			result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

			if diff := cmp.Diff(expected, result); diff != "" {
				t.Errorf("%s: GenerateVirtualServerConfig() mismatch (-want +got):\n%s", tt.description, diff)
			}

			if len(warnings) != 0 {
				t.Errorf("%s: GenerateVirtualServerConfig returned warnings: %v", tt.description, vsc.warnings)
			}
		})
	}
}

func TestGenerateVirtualServerConfigAPIKeyPolicy(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		SecretRefs: map[string]*secrets.SecretReference{
			"default/api-key-secret-spec": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"clientSpec": []byte("password"),
					},
				},
			},
			"default/api-key-secret-route": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"clientRoute": []byte("password2"),
					},
				},
			},
		},
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Policies: []conf_v1.PolicyReference{
					{
						Name: "api-key-policy-spec",
					},
				},
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
						Policies: []conf_v1.PolicyReference{
							{
								Name: "api-key-policy-route",
							},
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/api-key-policy-spec": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-spec",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Header: []string{"X-API-Key"},
							Query:  []string{"apikey"},
						},
						ClientSecret: "api-key-secret-spec",
					},
				},
			},
			"default/api-key-policy-route": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-route",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Query: []string{"api-key"},
						},
						ClientSecret: "api-key-secret-route",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
		},
	}

	expected := version2.VirtualServerConfig{
		Maps: []version2.Map{
			{
				Source:   "$apikey_auth_token",
				Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy_route",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: `""`,
					},
					{
						Value:  `"6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4"`,
						Result: `"clientRoute"`,
					},
				},
			},
			{
				Source:   "$apikey_auth_token",
				Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy_spec",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: `""`,
					},
					{
						Value:  `"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"`,
						Result: `"clientSpec"`,
					},
				},
			},
		},
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			JWTAuthList:     nil,
			JWTAuth:         nil,
			JWKSAuthEnabled: false,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			APIKeyEnabled:   true,
			APIKey: &version2.APIKey{
				Header:  []string{"X-API-Key"},
				Query:   []string{"apikey"},
				MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy_spec",
			},
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					APIKey: &version2.APIKey{
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy_route",
						Query:   []string{"api-key"},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	sort.Slice(result.Maps, func(i, j int) bool {
		return result.Maps[i].Variable < result.Maps[j].Variable
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigAPIKeyClientMaps(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		SecretRefs: map[string]*secrets.SecretReference{
			"default/api-key-secret-1": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"client1": []byte("password"),
					},
				},
			},
			"default/api-key-secret-2": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"client2": []byte("password2"),
					},
				},
			},
		},
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/api-key-policy-1": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-1",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Header: []string{"X-API-Key"},
							Query:  []string{"apikey"},
						},
						ClientSecret: "api-key-secret-1",
					},
				},
			},
			"default/api-key-policy-2": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-2",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Header: []string{"api-key"},
						},
						ClientSecret: "api-key-secret-2",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
		},
	}

	expectedAPIKey1 := &version2.APIKey{
		MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy_1",
		Header:  []string{"X-API-Key"},
		Query:   []string{"apikey"},
	}

	expectedAPIKey2 := &version2.APIKey{
		MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy_2",
		Header:  []string{"api-key"},
	}

	expectedMap1 := version2.Map{
		Source:   "$apikey_auth_token",
		Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy_1",
		Parameters: []version2.Parameter{
			{
				Value:  "default",
				Result: `""`,
			},
			{
				Value:  `"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"`,
				Result: `"client1"`,
			},
		},
	}

	expectedMap2 := version2.Map{
		Source:   "$apikey_auth_token",
		Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy_2",
		Parameters: []version2.Parameter{
			{
				Value:  "default",
				Result: `""`,
			},
			{
				Value:  `"6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4"`,
				Result: `"client2"`,
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	tests := []struct {
		specPolicies         []conf_v1.PolicyReference
		route1Policies       []conf_v1.PolicyReference
		route2Policies       []conf_v1.PolicyReference
		expectedSpecAPIKey   *version2.APIKey
		expectedRoute1APIKey *version2.APIKey
		expectedRoute2APIKey *version2.APIKey
		expectedMapList      []version2.Map
		name                 string
	}{
		{
			specPolicies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-1",
				},
			},
			route1Policies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-2",
				},
			},
			route2Policies:       nil,
			expectedSpecAPIKey:   expectedAPIKey1,
			expectedRoute1APIKey: expectedAPIKey2,
			expectedRoute2APIKey: nil,
			expectedMapList:      []version2.Map{expectedMap1, expectedMap2},
			name:                 "policy in spec, route 1 and route 2",
		},
		{
			specPolicies: nil,
			route1Policies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-1",
				},
			},
			route2Policies:     nil,
			expectedSpecAPIKey: nil,

			expectedRoute1APIKey: expectedAPIKey1,
			expectedRoute2APIKey: nil,
			expectedMapList:      []version2.Map{expectedMap1},
			name:                 "policy in route 1 only",
		},
		{
			specPolicies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-2",
				},
			},
			route1Policies:       nil,
			route2Policies:       nil,
			expectedSpecAPIKey:   expectedAPIKey2,
			expectedRoute1APIKey: nil,
			expectedRoute2APIKey: nil,
			expectedMapList:      []version2.Map{expectedMap2},
			name:                 "policy in spec only",
		},
		{
			specPolicies:         nil,
			route1Policies:       nil,
			route2Policies:       nil,
			expectedRoute1APIKey: nil,
			expectedRoute2APIKey: nil,
			expectedMapList:      nil,
			name:                 "no policies",
		},
	}

	invalidTests := []struct {
		specPolicies     []conf_v1.PolicyReference
		teaPolicies      []conf_v1.PolicyReference
		coffeePolicies   []conf_v1.PolicyReference
		expectedMapList  []version2.Map
		expectedWarnings Warnings
		name             string
	}{
		{
			specPolicies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-3",
				},
			},
			coffeePolicies: nil,
			teaPolicies:    nil,
			// expectedTeaPolicy:    expectedAPIKey2,
			// expectedCoffeePolicy: expectedAPIKey1,
			expectedMapList: nil,
			expectedWarnings: Warnings{
				nil: {
					"Policy default/api-key-policy-3 is missing or invalid",
				},
			},
			name: "policy does not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			virtualServerEx.VirtualServer.Spec.Policies = tc.specPolicies
			virtualServerEx.VirtualServer.Spec.Routes[0].Policies = tc.route1Policies
			virtualServerEx.VirtualServer.Spec.Routes[1].Policies = tc.route2Policies
			vsConf, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

			sort.Slice(vsConf.Maps, func(i, j int) bool {
				return vsConf.Maps[i].Variable < vsConf.Maps[j].Variable
			})

			if !cmp.Equal(tc.expectedSpecAPIKey, vsConf.Server.APIKey) {
				t.Error(cmp.Diff(tc.expectedSpecAPIKey, vsConf.Server.APIKey))
			}

			if !cmp.Equal(tc.expectedRoute1APIKey, vsConf.Server.Locations[0].APIKey) {
				t.Error(cmp.Diff(tc.expectedRoute1APIKey, vsConf.Server.Locations[0].APIKey))
			}

			if !cmp.Equal(tc.expectedRoute2APIKey, vsConf.Server.Locations[1].APIKey) {
				t.Error(cmp.Diff(tc.expectedRoute2APIKey, vsConf.Server.Locations[1].APIKey))
			}

			if !cmp.Equal(tc.expectedMapList, vsConf.Maps) {
				t.Error(cmp.Diff(tc.expectedMapList, vsConf.Maps))
			}

			if len(warnings) != 0 {
				t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
			}
		})

		for _, tc := range invalidTests {
			t.Run(tc.name, func(t *testing.T) {
				virtualServerEx.VirtualServer.Spec.Policies = tc.specPolicies
				virtualServerEx.VirtualServer.Spec.Routes[0].Policies = tc.teaPolicies
				virtualServerEx.VirtualServer.Spec.Routes[1].Policies = tc.coffeePolicies
				_, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

				if len(warnings) == 0 {
					t.Errorf("GenerateVirtualServerConfig() does not return the expected error %v", tc.expectedWarnings)
				}
			})
		}
	}
}

func TestGenerateVirtualServerConfigRateLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg             string
		virtualServerEx VirtualServerEx
		expected        version2.VirtualServerConfig
	}{
		{
			msg: "rate limits at vs spec level with zone sync enabled",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "rate-limit-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$binary_remote_addr",
								ZoneSize: "10M",
								Rate:     "10r/s",
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				ZoneSync: true,
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:      "$binary_remote_addr",
						ZoneName: "pol_rl_default_rate_limit_policy_default_cafe_vs_sync",
						ZoneSize: "10M",
						Rate:     "10r/s",
						Sync:     true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_rate_limit_policy_default_cafe_vs_sync", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "rate limits at vs spec level without zone sync",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "rate-limit-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$binary_remote_addr",
								ZoneSize: "10M",
								Rate:     "10r/s",
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:      "$binary_remote_addr",
						ZoneName: "pol_rl_default_rate_limit_policy_default_cafe_vs",
						ZoneSize: "10M",
						Rate:     "10r/s",
						Sync:     false,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:      context.Background(),
		ServerTokens: "off",
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{},
		false,
		&fakeBV,
	)

	for _, test := range tests {
		result, warnings := vsc.GenerateVirtualServerConfig(&test.virtualServerEx, nil, nil)

		sort.Slice(result.Maps, func(i, j int) bool {
			return result.Maps[i].Variable < result.Maps[j].Variable
		})

		sort.Slice(test.expected.Maps, func(i, j int) bool {
			return test.expected.Maps[i].Variable < test.expected.Maps[j].Variable
		})

		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
			t.Error(test.msg)
		}

		if len(warnings) != 0 {
			t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
		}
	}
}

func TestGenerateVirtualServerConfigCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg             string
		virtualServerEx VirtualServerEx
		expected        version2.VirtualServerConfig
	}{
		{
			msg: "cache policy at vs spec level",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "cache-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/cache-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "cache-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							Cache: &conf_v1.Cache{
								CacheZoneName: "my-cache",
								CacheZoneSize: "10m",
								Time:          "1h",
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				CacheZones: []version2.CacheZone{
					{
						Name:   "default_cafe_vs_my-cache",
						Size:   "10m",
						Path:   "/var/cache/nginx/default_cafe_vs_my-cache",
						Levels: "",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Cache: &version2.Cache{
						ZoneName:              "default_cafe_vs_my-cache",
						ZoneSize:              "10m",
						Time:                  "1h",
						Valid:                 map[string]string{},
						AllowedMethods:        nil,
						CachePurgeAllow:       nil,
						OverrideUpstreamCache: false,
						Levels:                "",
						CacheKey:              "$scheme$proxy_host$request_uri",
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "cache policy at route level",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Policies: []conf_v1.PolicyReference{
									{
										Name: "route-cache-policy",
									},
								},
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/route-cache-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "route-cache-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							Cache: &conf_v1.Cache{
								CacheZoneName: "route-cache",
								CacheZoneSize: "5m",
								Time:          "30m",
								AllowedCodes: []intstr.IntOrString{
									intstr.FromInt(200),
									intstr.FromInt(404),
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				CacheZones: []version2.CacheZone{
					{
						Name:   "default_cafe_vs_route-cache",
						Size:   "5m",
						Path:   "/var/cache/nginx/default_cafe_vs_route-cache",
						Levels: "",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							Cache: &version2.Cache{
								ZoneName:              "default_cafe_vs_route-cache",
								ZoneSize:              "5m",
								Time:                  "30m",
								Valid:                 map[string]string{"200": "30m", "404": "30m"},
								AllowedMethods:        nil,
								CachePurgeAllow:       nil,
								OverrideUpstreamCache: false,
								Levels:                "",
								CacheKey:              "$scheme$proxy_host$request_uri",
							},
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "cache policy at VSR subroute level",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path:  "/tea",
								Route: "default/tea-vsr",
							},
						},
					},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea-vsr",
							Namespace: "default",
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea-v1",
									Service: "tea-v1-svc",
									Port:    80,
								},
								{
									Name:    "tea-v2",
									Service: "tea-v2-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea/v1",
									Policies: []conf_v1.PolicyReference{
										{
											Name: "vsr-cache-policy",
										},
									},
									Action: &conf_v1.Action{
										Pass: "tea-v1",
									},
								},
								{
									Path: "/tea/v2",
									Action: &conf_v1.Action{
										Pass: "tea-v2",
									},
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/vsr-cache-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "vsr-cache-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							Cache: &conf_v1.Cache{
								CacheZoneName:         "vsr-cache",
								CacheZoneSize:         "20m",
								Time:                  "2h",
								OverrideUpstreamCache: true,
								CachePurgeAllow:       []string{"127.0.0.1"},
								CacheKey:              "$scheme$proxy_host$request_uri$is_args$args",
								CacheBackgroundUpdate: true,
								CacheUseStale:         []string{"error", "timeout", "http_503"},
								Levels:                "2:2",
								MinFree:               "100m",
								Conditions: &conf_v1.CacheConditions{
									NoCache: []string{"$http_pragma", "$http_authorization"},
									Bypass:  []string{"$cookie_nocache", "$arg_nocache"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/tea-v1-svc:80": {
						"10.0.0.21:80",
					},
					"default/tea-v2-svc:80": {
						"10.0.0.22:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-v1-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea-vsr",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_tea-vsr_tea-v1",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.21:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-v2-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea-vsr",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_tea-vsr_tea-v2",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.22:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				CacheZones: []version2.CacheZone{
					{
						Name:    "default_cafe_vs_default_tea-vsr_vsr-cache",
						Size:    "20m",
						Path:    "/var/cache/nginx/default_cafe_vs_default_tea-vsr_vsr-cache",
						Levels:  "2:2",
						MinFree: "100m",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea/v1",
							ProxyPass:                "http://vs_default_cafe_vsr_default_tea-vsr_tea-v1",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-v1-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-v1-svc",
							IsVSR:                    true,
							VSRName:                  "tea-vsr",
							VSRNamespace:             "default",
							Cache: &version2.Cache{
								ZoneName:              "default_cafe_vs_default_tea-vsr_vsr-cache",
								ZoneSize:              "20m",
								Time:                  "2h",
								Valid:                 map[string]string{},
								AllowedMethods:        nil,
								CachePurgeAllow:       []string{"127.0.0.1"},
								OverrideUpstreamCache: true,
								Levels:                "2:2",
								MinFree:               "100m",
								CacheKey:              "$scheme$proxy_host$request_uri$is_args$args",
								CacheBackgroundUpdate: true,
								CacheUseStale:         []string{"error", "timeout", "http_503"},
								NoCacheConditions:     []string{"$http_pragma", "$http_authorization"},
								CacheBypassConditions: []string{"$cookie_nocache", "$arg_nocache"},
							},
						},
						{
							Path:                     "/tea/v2",
							ProxyPass:                "http://vs_default_cafe_vsr_default_tea-vsr_tea-v2",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-v2-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-v2-svc",
							IsVSR:                    true,
							VSRName:                  "tea-vsr",
							VSRNamespace:             "default",
						},
					},
				},
			},
		},
		{
			msg: "cache policy with extended fields",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "extended-cache",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cache.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "extended-cache-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "backend",
								Service: "backend-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/api",
								Action: &conf_v1.Action{
									Pass: "backend",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/extended-cache-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "extended-cache-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							Cache: &conf_v1.Cache{
								CacheZoneName: "extended-cache",
								CacheZoneSize: "100m",
								CacheKey:      "$scheme$host$request_uri$args",
								CacheMinUses:  createPointerFromInt(3),
								UseTempPath:   false,
								MaxSize:       "2g",
								Inactive:      "7d",
								Manager: &conf_v1.CacheManager{
									Files:     createPointerFromInt(500),
									Sleep:     "200ms",
									Threshold: "1s",
								},
								Lock: &conf_v1.CacheLock{
									Enable:  true,
									Timeout: "60s",
								},
								Conditions: &conf_v1.CacheConditions{
									NoCache: []string{"$cookie_admin"},
									Bypass:  []string{"$http_cache_control"},
								},
								AllowedCodes: []intstr.IntOrString{
									intstr.FromString("200"),
									intstr.FromString("404"),
									intstr.FromString("any"),
								},
								Time:                  "1h",
								CacheBackgroundUpdate: true,
								CacheRevalidate:       true,
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/backend-svc:80": {
						"10.0.0.40:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "backend-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "extended-cache",
							ResourceNamespace: "default",
						},
						Name: "vs_default_extended-cache_backend",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.40:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				CacheZones: []version2.CacheZone{
					{
						Name:             "default_extended-cache_vs_extended-cache",
						Size:             "100m",
						Path:             "/var/cache/nginx/default_extended-cache_vs_extended-cache",
						Levels:           "",
						Inactive:         "7d",
						UseTempPath:      false,
						MaxSize:          "2g",
						MinFree:          "",
						ManagerFiles:     createPointerFromInt(500),
						ManagerSleep:     "200ms",
						ManagerThreshold: "1s",
					},
				},
				Server: version2.Server{
					ServerName:   "cache.example.com",
					StatusZone:   "cache.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "extended-cache",
					Cache: &version2.Cache{
						ZoneName:              "default_extended-cache_vs_extended-cache",
						ZoneSize:              "100m",
						Levels:                "",
						Inactive:              "7d",
						UseTempPath:           false,
						MaxSize:               "2g",
						MinFree:               "",
						ManagerFiles:          createPointerFromInt(500),
						ManagerSleep:          "200ms",
						ManagerThreshold:      "1s",
						CacheKey:              "$scheme$host$request_uri$args",
						OverrideUpstreamCache: false,
						Time:                  "1h",
						Valid:                 map[string]string{"200": "1h", "404": "1h", "any": "1h"},
						AllowedMethods:        nil,
						CacheUseStale:         nil,
						CacheRevalidate:       true,
						CacheBackgroundUpdate: true,
						CacheMinUses:          createPointerFromInt(3),
						CachePurgeAllow:       nil,
						CacheLock:             true,
						CacheLockTimeout:      "60s",
						CacheLockAge:          "",
						NoCacheConditions:     []string{"$cookie_admin"},
						CacheBypassConditions: []string{"$http_cache_control"},
					},
					Locations: []version2.Location{
						{
							Path:                     "/api",
							ProxyPass:                "http://vs_default_extended-cache_backend",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "backend-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "backend-svc",
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:      context.Background(),
		ServerTokens: "off",
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{},
		false,
		&fakeBV,
	)

	for _, test := range tests {
		result, warnings := vsc.GenerateVirtualServerConfig(&test.virtualServerEx, nil, nil)

		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
			t.Error(test.msg)
		}

		if len(warnings) != 0 {
			t.Errorf("GenerateVirtualServerConfig returned warnings: %v", warnings)
		}
	}
}

func TestGenerateVirtualServerConfigWithOIDCTLSVerifyOn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg             string
		virtualServerEx VirtualServerEx
		expected        version2.VirtualServerConfig
	}{
		{
			msg: "oidc at vs spec level with TLSVerify & zone sync enabled",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "oidc-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/oidc-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "oidc-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							OIDC: &conf_v1.OIDC{
								AuthEndpoint:       "https://auth.example.com",
								TokenEndpoint:      "https://token.example.com",
								JWKSURI:            "https://jwks.example.com",
								EndSessionEndpoint: "https://logout.example.com",
								ClientID:           "example-client-id",
								ClientSecret:       "example-client-secret",
								Scope:              "openid+profile+email",
								SSLVerify:          true,
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				SecretRefs: map[string]*secrets.SecretReference{
					"default/example-client-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeOIDC,
							Data: map[string][]byte{
								"client-secret": []byte("c2VjcmV0"),
							},
						},
					},
				},
				ZoneSync: true,
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							OIDC:                     true,
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							OIDC:                     true,
						},
					},
					OIDC: &version2.OIDC{
						AuthEndpoint:          "https://auth.example.com",
						TokenEndpoint:         "https://token.example.com",
						JwksURI:               "https://jwks.example.com",
						EndSessionEndpoint:    "https://logout.example.com",
						ClientID:              "example-client-id",
						ClientSecret:          "c2VjcmV0",
						Scope:                 "openid+profile+email",
						TLSVerify:             true,
						VerifyDepth:           1,
						CAFile:                "/etc/ssl/certs/ca-certificate.crt",
						ZoneSyncLeeway:        200,
						RedirectURI:           "/_codexch",
						PostLogoutRedirectURI: "/_logout",
						PolicyName:            "default/oidc-policy",
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:      context.Background(),
		ServerTokens: "off",
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{
			DefaultCABundle: "/etc/ssl/certs/ca-certificate.crt",
		},
		false,
		&fakeBV,
	)

	for _, test := range tests {
		result, warnings := vsc.GenerateVirtualServerConfig(&test.virtualServerEx, nil, nil)

		sort.Slice(result.Maps, func(i, j int) bool {
			return result.Maps[i].Variable < result.Maps[j].Variable
		})

		sort.Slice(test.expected.Maps, func(i, j int) bool {
			return test.expected.Maps[i].Variable < test.expected.Maps[j].Variable
		})

		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
			t.Error(test.msg)
		}

		if len(warnings) != 0 {
			t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
		}
	}
}

func TestGenerateVirtualServerConfigWithOIDCTLSCASecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg             string
		virtualServerEx VirtualServerEx
		expected        version2.VirtualServerConfig
	}{
		{
			msg: "oidc at vs spec level with TLSVerify, custom ca cert & zone sync enabled",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "oidc-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/oidc-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "oidc-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							OIDC: &conf_v1.OIDC{
								AuthEndpoint:       "https://auth.example.com",
								TokenEndpoint:      "https://token.example.com",
								JWKSURI:            "https://jwks.example.com",
								EndSessionEndpoint: "https://logout.example.com",
								ClientID:           "example-client-id",
								ClientSecret:       "example-client-secret",
								Scope:              "openid+profile+email",
								SSLVerify:          true,
								TrustedCertSecret:  "example-ca-secret",
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				SecretRefs: map[string]*secrets.SecretReference{
					"default/example-client-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeOIDC,
							Data: map[string][]byte{
								"client-secret": []byte("c2VjcmV0"),
							},
						},
					},
					"default/example-ca-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
							Data: map[string][]byte{
								"ca.crt": []byte("ca-certificate-data"),
							},
						},
						Path: "/etc/nginx/secrets/default-example-ca-secret-ca.crt",
					},
				},
				ZoneSync: true,
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							OIDC:                     true,
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							OIDC:                     true,
						},
					},
					OIDC: &version2.OIDC{
						AuthEndpoint:          "https://auth.example.com",
						TokenEndpoint:         "https://token.example.com",
						JwksURI:               "https://jwks.example.com",
						EndSessionEndpoint:    "https://logout.example.com",
						ClientID:              "example-client-id",
						ClientSecret:          "c2VjcmV0",
						Scope:                 "openid+profile+email",
						TLSVerify:             true,
						VerifyDepth:           1,
						CAFile:                "/etc/nginx/secrets/default-example-ca-secret-ca.crt",
						ZoneSyncLeeway:        200,
						RedirectURI:           "/_codexch",
						PostLogoutRedirectURI: "/_logout",
						PolicyName:            "default/oidc-policy",
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:      context.Background(),
		ServerTokens: "off",
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{
			DefaultCABundle: "/etc/ssl/certs/ca-certificate.crt",
		},
		false,
		&fakeBV,
	)

	for _, test := range tests {
		result, warnings := vsc.GenerateVirtualServerConfig(&test.virtualServerEx, nil, nil)

		sort.Slice(result.Maps, func(i, j int) bool {
			return result.Maps[i].Variable < result.Maps[j].Variable
		})

		sort.Slice(test.expected.Maps, func(i, j int) bool {
			return test.expected.Maps[i].Variable < test.expected.Maps[j].Variable
		})

		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
			t.Error(test.msg)
		}

		if len(warnings) != 0 {
			t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
		}
	}
}

func TestGenerateVirtualServerConfigWithRouteSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg             string
		virtualServerEx VirtualServerEx
		expected        version2.VirtualServerConfig
	}{
		{
			msg: "basic route selector",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Routes: []conf_v1.Route{
							{
								Path: "/",
								RouteSelector: &meta_v1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "cafe",
									},
								},
							},
						},
					},
				},
				VirtualServerSelectorRoutes: map[string][]string{
					"app=cafe": {"default/coffee"},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "coffee",
							Namespace: "default",
							Labels: map[string]string{
								"app": "cafe",
							},
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "coffee",
									Service: "coffee-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/coffee",
									Action: &conf_v1.Action{
										Pass: "coffee",
									},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "coffee",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_coffee_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							IsVSR:                    true,
							VSRName:                  "coffee",
							VSRNamespace:             "default",
						},
					},
				},
			},
		},
		{
			msg: "cross namespace route selector",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Routes: []conf_v1.Route{
							{
								Path: "/",
								RouteSelector: &meta_v1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "cafe",
									},
								},
							},
						},
					},
				},
				VirtualServerSelectorRoutes: map[string][]string{
					"app=cafe": {"coffee/coffee,tea/tea"},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "coffee",
							Namespace: "coffee",
							Labels: map[string]string{
								"app": "cafe",
							},
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "coffee",
									Service: "coffee-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/coffee",
									Action: &conf_v1.Action{
										Pass: "coffee",
									},
								},
							},
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea",
							Namespace: "tea",
							Labels: map[string]string{
								"app": "cafe",
							},
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea",
									Service: "tea-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea",
									Action: &conf_v1.Action{
										Pass: "tea",
									},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"coffee/coffee-svc:80": {
						"10.0.0.30:80",
					},
					"tea/tea-svc:80": {
						"10.0.0.20:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "coffee",
							ResourceNamespace: "coffee",
						},
						Name: "vs_default_cafe_vsr_coffee_coffee_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea",
							ResourceNamespace: "tea",
						},
						Name: "vs_default_cafe_vsr_tea_tea_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets:  []string{},
				LimitReqZones: []version2.LimitReqZone{},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_vsr_coffee_coffee_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.coffee.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							IsVSR:                    true,
							VSRName:                  "coffee",
							VSRNamespace:             "coffee",
						},
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_vsr_tea_tea_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.tea.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							IsVSR:                    true,
							VSRName:                  "tea",
							VSRNamespace:             "tea",
						},
					},
				},
			},
		},
		{
			msg: "cross namespace route selector with policies",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Routes: []conf_v1.Route{
							{
								Path: "/",
								RouteSelector: &meta_v1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "cafe",
									},
								},
							},
						},
						Policies: []conf_v1.PolicyReference{
							{
								Name:      "api-key-policy",
								Namespace: "cafe",
							},
						},
					},
				},
				SecretRefs: map[string]*secrets.SecretReference{
					"cafe/api-key-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"clientSpec": []byte("password"),
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"cafe/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "cafe",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"apikey"},
								},
								ClientSecret: "api-key-secret",
							},
						},
					},
					"policy/rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "rate-limit-policy",
							Namespace: "policy",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$binary_remote_addr",
								ZoneSize: "10M",
								Rate:     "10r/s",
							},
						},
					},
				},
				VirtualServerSelectorRoutes: map[string][]string{
					"app=cafe": {"coffee/coffee,tea/tea"},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "coffee",
							Namespace: "coffee",
							Labels: map[string]string{
								"app": "cafe",
							},
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "coffee",
									Service: "coffee-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/coffee",
									Policies: []conf_v1.PolicyReference{
										{
											Name:      "rate-limit-policy",
											Namespace: "policy",
										},
									},
									Action: &conf_v1.Action{
										Pass: "coffee",
									},
								},
							},
						},
					},
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea",
							Namespace: "tea",
							Labels: map[string]string{
								"app": "cafe",
							},
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea",
									Service: "tea-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea",
									Action: &conf_v1.Action{
										Pass: "tea",
									},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"coffee/coffee-svc:80": {
						"10.0.0.30:80",
					},
					"tea/tea-svc:80": {
						"10.0.0.20:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "coffee",
							ResourceNamespace: "coffee",
						},
						Name: "vs_default_cafe_vsr_coffee_coffee_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea",
							ResourceNamespace: "tea",
						},
						Name: "vs_default_cafe_vsr_tea_tea_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				Maps: []version2.Map{
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"`,
								Result: `"clientSpec"`,
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:      "$binary_remote_addr",
						ZoneName: "pol_rl_policy_rate_limit_policy_default_cafe_vs",
						ZoneSize: "10M",
						Rate:     "10r/s",
					},
				},
				Server: version2.Server{
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"apikey"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_vsr_coffee_coffee_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.coffee.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							IsVSR:                    true,
							VSRName:                  "coffee",
							VSRNamespace:             "coffee",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_policy_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_vsr_tea_tea_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.tea.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							IsVSR:                    true,
							VSRName:                  "tea",
							VSRNamespace:             "tea",
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:      context.Background(),
		ServerTokens: "off",
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{
			DefaultCABundle: "/etc/ssl/certs/ca-certificate.crt",
		},
		false,
		&fakeBV,
	)

	for _, test := range tests {
		result, warnings := vsc.GenerateVirtualServerConfig(&test.virtualServerEx, nil, nil)

		sort.Slice(result.Maps, func(i, j int) bool {
			return result.Maps[i].Variable < result.Maps[j].Variable
		})

		sort.Slice(test.expected.Maps, func(i, j int) bool {
			return test.expected.Maps[i].Variable < test.expected.Maps[j].Variable
		})

		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
			t.Error(test.msg)
		}

		if len(warnings) != 0 {
			t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
		}
	}
}

func TestGenerateVirtualServerConfigExternalAuthPolicy(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Policies: []conf_v1.PolicyReference{
					{
						Name:      "external-auth-policy",
						Namespace: "default",
					},
				},
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/external-auth-policy": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "external-auth-policy",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					ExternalAuth: &conf_v1.ExternalAuth{
						AuthURL:       "http://auth-server:8080/auth",
						AuthSigninURL: "http://auth-server:8080/signin?rd=$scheme://$host$request_uri",
						AuthSnippets:  "proxy_set_header X-Custom-Header \"custom-value\";",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
			"default/auth-server:8080": {
				"10.0.0.40:80",
			},
		},
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "auth-server",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_external_auth",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "auth-server",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_external_auth_signin",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			ExternalAuth: &version2.ExternalAuth{
				ProxyURL: "/pol_exauth_default_cafe_default_external_auth_policy",
				URI: version2.AuthURI{
					Scheme: "http",
					Host:   "auth-server",
					Port:   "8080",
					Path:   "/auth",
				},
				SigninURL: version2.AuthURI{
					Scheme: "http",
					Host:   "auth-server",
					Port:   "8080",
					Path:   "/signin",
				},
				SigninProxyURL: "/pol_exauth_signin_default_cafe_default_external_auth_policy",
				Snippets:       "proxy_set_header X-Custom-Header \"custom-value\";",
			},
			ErrorPages: []version2.ErrorPage{
				{
					Name:         "/pol_exauth_signin_default_cafe_default_external_auth_policy",
					Codes:        "401",
					ResponseCode: -1,
				},
			},
			Locations: []version2.Location{
				{
					Path:                     "/pol_exauth_default_cafe_default_external_auth_policy",
					Internal:                 true,
					Snippets:                 []string{`proxy_set_header X-Custom-Header "custom-value";`},
					ProxyPass:                "http://vs_default_cafe_external_auth",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Content-Length", Value: "0"}},
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ServiceName:              "auth-server",
					ClientMaxBodySize:        "0",
				},
				{
					Path:                     "/pol_exauth_signin_default_cafe_default_external_auth_policy",
					Internal:                 true,
					ProxyPass:                "http://vs_default_cafe_external_auth_signin",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Content-Length", Value: "0"}},
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ServiceName:              "auth-server",
					ClientMaxBodySize:        "0",
				},
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}
