package configs

import (
	"context"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	acmeTestChallengePath     = "/.well-known/acme-challenge/tok"
	acmeTestSolverService     = "cm-acme-http-solver-abcde"
	acmeTestSolverIngress     = "cm-acme-http-solver-xyz12"
	acmeTestSolverEndpoint    = "10.0.0.99:8089"
	acmeTestChallengeUpstream = "vs_default_cafe_vsr_default_cm-acme-http-solver-xyz12_challenge"
)

// newACMETestChallengeRoute returns a synthetic VirtualServerRoute as built from a cert-manager solver Ingress.
func newACMETestChallengeRoute() *conf_v1.VirtualServerRoute {
	return &conf_v1.VirtualServerRoute{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      acmeTestSolverIngress,
			Namespace: "default",
		},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host: "cafe.example.com",
			Upstreams: []conf_v1.Upstream{
				{
					Name:    "challenge",
					Service: acmeTestSolverService,
					Port:    8089,
				},
			},
			Subroutes: []conf_v1.Route{
				{
					Path:   acmeTestChallengePath,
					Action: &conf_v1.Action{Pass: "challenge"},
				},
			},
		},
	}
}

// newACMETestVirtualServerEx returns a VirtualServerEx with TLS redirect and a spec-level basic-auth policy.
func newACMETestVirtualServerEx(challengeRoutes []*conf_v1.VirtualServerRoute) VirtualServerEx {
	return VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				TLS: &conf_v1.TLS{
					Secret:   "cafe-secret",
					Redirect: &conf_v1.TLSRedirect{Enable: true},
				},
				Policies: []conf_v1.PolicyReference{
					{Name: "basic-auth-policy"},
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
						Path:   "/tea",
						Action: &conf_v1.Action{Pass: "tea"},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/basic-auth-policy": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "basic-auth-policy",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					BasicAuth: &conf_v1.BasicAuth{
						Realm:  "test",
						Secret: "htpasswd-secret",
					},
				},
			},
		},
		SecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
			secrets.RefKey("default/cafe-secret", secrets.RoleTLS): {
				Secret: &api_v1.Secret{Type: api_v1.SecretTypeTLS},
				Path:   "/etc/nginx/secrets/default-cafe-secret",
			},
			secrets.RefKey("default/htpasswd-secret", secrets.RoleHtpasswd): {
				Secret: &api_v1.Secret{},
				Path:   "/etc/nginx/secrets/default-htpasswd-secret",
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80":                         {"10.0.0.20:80"},
			"default/" + acmeTestSolverService + ":8089": {acmeTestSolverEndpoint},
		},
		ChallengeRoutes: challengeRoutes,
	}
}

func TestGenerateVirtualServerConfigACMEChallengeRoute(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, _ := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	if !result.Server.ACMEChallengeActive {
		t.Error("want Server.ACMEChallengeActive true, got false")
	}
	if result.Server.TLSRedirect == nil {
		t.Error("want Server.TLSRedirect set, got nil")
	}
	if result.Server.BasicAuth == nil {
		t.Error("want server-level BasicAuth set, got nil")
	}

	loc := findSingleACMEChallengeLocation(t, result.Server.Locations)
	if loc.Path != acmeTestChallengePath {
		t.Errorf("want challenge location path %q, got %q", acmeTestChallengePath, loc.Path)
	}
	assertNoAuthOnChallengeLocation(t, loc)
	assertChallengeUpstream(t, result.Upstreams)
}

// findSingleACMEChallengeLocation returns the only location marked ACMEChallenge, failing the test otherwise.
func findSingleACMEChallengeLocation(t *testing.T, locations []version2.Location) version2.Location {
	t.Helper()
	var challengeLocs []version2.Location
	for _, loc := range locations {
		if loc.ACMEChallenge {
			challengeLocs = append(challengeLocs, loc)
		}
	}
	if len(challengeLocs) != 1 {
		t.Fatalf("want exactly 1 ACMEChallenge location, got %d: %+v", len(challengeLocs), challengeLocs)
	}
	return challengeLocs[0]
}

// assertNoAuthOnChallengeLocation checks that no auth policy is applied to the challenge location.
func assertNoAuthOnChallengeLocation(t *testing.T, loc version2.Location) {
	t.Helper()
	if loc.BasicAuth != nil {
		t.Errorf("want challenge location BasicAuth nil, got %+v", loc.BasicAuth)
	}
	if loc.JWTAuth != nil {
		t.Errorf("want challenge location JWTAuth nil, got %+v", loc.JWTAuth)
	}
	if loc.ExternalAuth != nil {
		t.Errorf("want challenge location ExternalAuth nil, got %+v", loc.ExternalAuth)
	}
	if loc.APIKey != nil {
		t.Errorf("want challenge location APIKey nil, got %+v", loc.APIKey)
	}
	if loc.OIDC {
		t.Error("want challenge location OIDC false, got true")
	}
	if loc.OIDCProviderName != "" {
		t.Errorf("want challenge location OIDCProviderName empty, got %q", loc.OIDCProviderName)
	}
}

// assertChallengeUpstream checks that the challenge upstream exists and points at the solver endpoint.
func assertChallengeUpstream(t *testing.T, upstreams []version2.Upstream) {
	t.Helper()
	var found bool
	for _, u := range upstreams {
		if u.Name != acmeTestChallengeUpstream {
			continue
		}
		found = true
		if len(u.Servers) != 1 || u.Servers[0].Address != acmeTestSolverEndpoint {
			t.Errorf("want challenge upstream servers [%s], got %+v", acmeTestSolverEndpoint, u.Servers)
		}
	}
	if !found {
		t.Errorf("want upstream %q in result.Upstreams, got %+v", acmeTestChallengeUpstream, upstreams)
	}
}

func TestGenerateVirtualServerConfigACMEChallengeRouteNoGlobalSnippets(t *testing.T) {
	t.Parallel()

	snippet := `auth_basic "x";`
	cfgParams := baseCfgParams
	cfgParams.LocationSnippets = []string{snippet}

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
	vsc := newVirtualServerConfigurator(&cfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, _ := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	var sawChallenge, sawTea bool
	for _, loc := range result.Server.Locations {
		switch {
		case loc.ACMEChallenge:
			sawChallenge = true
			if len(loc.Snippets) != 0 {
				t.Errorf("want no snippets on challenge location, got %q", loc.Snippets)
			}
		case loc.Path == "/tea":
			sawTea = true
			if len(loc.Snippets) != 1 || loc.Snippets[0] != snippet {
				t.Errorf("want global location snippet %q on /tea, got %q", snippet, loc.Snippets)
			}
		}
	}
	if !sawChallenge {
		t.Error("want a challenge location, got none")
	}
	if !sawTea {
		t.Error("want a /tea location, got none")
	}
}

func TestGenerateVirtualServerConfigNoChallengeUnchanged(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx(nil)
	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, _ := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	if result.Server.ACMEChallengeActive {
		t.Error("want Server.ACMEChallengeActive false, got true")
	}
	for _, loc := range result.Server.Locations {
		if loc.ACMEChallenge {
			t.Errorf("want no ACMEChallenge location, got %+v", loc)
		}
	}
	for _, u := range result.Upstreams {
		if u.Name == acmeTestChallengeUpstream {
			t.Errorf("want no challenge upstream, got %+v", u)
		}
	}
}

func TestCreateUpstreamsForPlusIncludesChallengeRoutes(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})

	result := createUpstreamsForPlus(&vsEx, &ConfigParams{Context: context.Background()}, &StaticConfigParams{})

	var found bool
	for _, u := range result {
		if u.Name != acmeTestChallengeUpstream {
			continue
		}
		found = true
		if len(u.Servers) != 1 || u.Servers[0].Address != acmeTestSolverEndpoint {
			t.Errorf("want challenge upstream servers [%s], got %+v", acmeTestSolverEndpoint, u.Servers)
		}
	}
	if !found {
		t.Errorf("want upstream %q in createUpstreamsForPlus result, got %+v", acmeTestChallengeUpstream, result)
	}
}
