package configs

import (
	"context"
	"strings"
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
	if loc.Path != acmeTestChallengeExactPath {
		t.Errorf("want challenge location path %q, got %q", acmeTestChallengeExactPath, loc.Path)
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

const acmeTestChallengeExactPath = "= " + acmeTestChallengePath

func TestGenerateVirtualServerConfigACMEChallengeRouteIsExactMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		syntheticPath string
	}{
		{name: "plain path", syntheticPath: acmeTestChallengePath},
		{name: "exact path with space", syntheticPath: "= " + acmeTestChallengePath},
		{name: "exact path without space", syntheticPath: "=" + acmeTestChallengePath},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cr := newACMETestChallengeRoute()
			cr.Spec.Subroutes[0].Path = tc.syntheticPath
			vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{cr})
			vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

			result, _ := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

			loc := findSingleACMEChallengeLocation(t, result.Server.Locations)
			if loc.Path != acmeTestChallengeExactPath {
				t.Errorf("want challenge location path %q, got %q", acmeTestChallengeExactPath, loc.Path)
			}
			if !result.Server.ACMEChallengeActive {
				t.Error("want Server.ACMEChallengeActive true, got false")
			}
		})
	}
}

func TestGenerateVirtualServerConfigACMEChallengeWithRegexCatchAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		specLevelPolicy bool
	}{
		{name: "route-level policy only", specLevelPolicy: false},
		// Mirrors tests/data/acme-pebble/virtual-server-basic-auth.yaml.
		{name: "spec-level and route-level policy", specLevelPolicy: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
			if !tc.specLevelPolicy {
				vsEx.VirtualServer.Spec.Policies = nil
			}
			vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{
				{
					Path:     "~ ^/",
					Policies: []conf_v1.PolicyReference{{Name: "basic-auth-policy"}},
					Action:   &conf_v1.Action{Pass: "tea"},
				},
			}
			vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

			result, _ := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

			loc := findSingleACMEChallengeLocation(t, result.Server.Locations)
			if loc.Path != acmeTestChallengeExactPath {
				t.Errorf("want challenge location path %q, got %q", acmeTestChallengeExactPath, loc.Path)
			}
			assertNoAuthOnChallengeLocation(t, loc)
			if !result.Server.ACMEChallengeActive {
				t.Error("want Server.ACMEChallengeActive true, got false")
			}
			if gotServerAuth := result.Server.BasicAuth != nil; gotServerAuth != tc.specLevelPolicy {
				t.Errorf("want server-level BasicAuth set=%t, got %+v", tc.specLevelPolicy, result.Server.BasicAuth)
			}

			var sawRegex bool
			for _, l := range result.Server.Locations {
				if l.Path != `~ "^/"` {
					continue
				}
				sawRegex = true
				if l.BasicAuth == nil {
					t.Error("want BasicAuth on the regex route location, got nil")
				}
			}
			if !sawRegex {
				t.Errorf("want a regex location %q, got %+v", `~ "^/"`, result.Server.Locations)
			}
		})
	}
}

func TestGenerateVirtualServerConfigACMEChallengeExactCollision(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
	vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{
		{
			Path:   "=" + acmeTestChallengePath,
			Action: &conf_v1.Action{Pass: "tea"},
		},
	}
	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	var exact int
	for _, l := range result.Server.Locations {
		if l.ACMEChallenge {
			t.Errorf("want no ACMEChallenge location on collision, got %+v", l)
		}
		if l.Path == acmeTestChallengeExactPath {
			exact++
		}
	}
	if exact != 1 {
		t.Errorf("want exactly 1 location with path %q, got %d", acmeTestChallengeExactPath, exact)
	}
	if result.Server.ACMEChallengeActive {
		t.Error("want Server.ACMEChallengeActive false when no challenge location is rendered, got true")
	}

	vsWarnings := warnings[vsEx.VirtualServer]
	if len(vsWarnings) != 1 || !strings.Contains(vsWarnings[0], acmeTestChallengeExactPath) {
		t.Errorf("want 1 VirtualServer warning mentioning %q, got %q", acmeTestChallengeExactPath, vsWarnings)
	}
}

func TestGenerateVirtualServerConfigACMEChallengeExactCollisionWithSplitsRoute(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
	vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{
		{
			Path: "=" + acmeTestChallengePath,
			Splits: []conf_v1.Split{
				{Weight: 50, Action: &conf_v1.Action{Pass: "tea"}},
				{Weight: 50, Action: &conf_v1.Action{Pass: "tea"}},
			},
		},
	}
	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	for _, l := range result.Server.Locations {
		if l.ACMEChallenge {
			t.Errorf("want no ACMEChallenge location on collision with an internal redirect location, got %+v", l)
		}
	}
	if result.Server.ACMEChallengeActive {
		t.Error("want Server.ACMEChallengeActive false, got true")
	}
	if len(warnings[vsEx.VirtualServer]) != 1 {
		t.Errorf("want 1 VirtualServer warning, got %q", warnings[vsEx.VirtualServer])
	}
}

func TestGenerateVirtualServerConfigACMEChallengePrefixRouteNoCollision(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
	vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{
		{
			Path:   acmeTestChallengePath,
			Action: &conf_v1.Action{Pass: "tea"},
		},
	}
	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	loc := findSingleACMEChallengeLocation(t, result.Server.Locations)
	if loc.Path != acmeTestChallengeExactPath {
		t.Errorf("want challenge location path %q, got %q", acmeTestChallengeExactPath, loc.Path)
	}
	var sawPrefix bool
	for _, l := range result.Server.Locations {
		if l.Path == acmeTestChallengePath && !l.ACMEChallenge {
			sawPrefix = true
		}
	}
	if !sawPrefix {
		t.Errorf("want the user's prefix location %q, got %+v", acmeTestChallengePath, result.Server.Locations)
	}
	if !result.Server.ACMEChallengeActive {
		t.Error("want Server.ACMEChallengeActive true, got false")
	}
	if len(warnings[vsEx.VirtualServer]) != 0 {
		t.Errorf("want no VirtualServer warnings, got %q", warnings[vsEx.VirtualServer])
	}
}

func TestGenerateVirtualServerConfigACMEChallengeExactCollisionWithVSRSubroute(t *testing.T) {
	t.Parallel()

	vsEx := newACMETestVirtualServerEx([]*conf_v1.VirtualServerRoute{newACMETestChallengeRoute()})
	vsEx.VirtualServer.Spec.Routes = []conf_v1.Route{
		{
			Path:  "=" + acmeTestChallengePath,
			Route: "default/acme-exact",
		},
	}
	vsEx.VirtualServerRoutes = []*conf_v1.VirtualServerRoute{
		{
			ObjectMeta: meta_v1.ObjectMeta{Name: "acme-exact", Namespace: "default"},
			Spec: conf_v1.VirtualServerRouteSpec{
				Host:      "cafe.example.com",
				Upstreams: []conf_v1.Upstream{{Name: "tea", Service: "tea-svc", Port: 80}},
				Subroutes: []conf_v1.Route{
					{
						Path:   "=" + acmeTestChallengePath,
						Action: &conf_v1.Action{Pass: "tea"},
					},
				},
			},
		},
	}
	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&vsEx, nil, nil)

	var exact []version2.Location
	for _, l := range result.Server.Locations {
		if l.ACMEChallenge {
			t.Errorf("want no ACMEChallenge location on collision with a VSR subroute, got %+v", l)
		}
		if l.Path == acmeTestChallengeExactPath {
			exact = append(exact, l)
		}
	}
	if len(exact) != 1 {
		t.Fatalf("want exactly 1 location with path %q, got %d", acmeTestChallengeExactPath, len(exact))
	}
	if !exact[0].IsVSR || exact[0].VSRName != "acme-exact" {
		t.Errorf("want the %q location to come from VSR acme-exact, got IsVSR=%t VSRName=%q",
			acmeTestChallengeExactPath, exact[0].IsVSR, exact[0].VSRName)
	}
	if result.Server.ACMEChallengeActive {
		t.Error("want Server.ACMEChallengeActive false when no challenge location is rendered, got true")
	}

	vsWarnings := warnings[vsEx.VirtualServer]
	if len(vsWarnings) != 1 || !strings.Contains(vsWarnings[0], acmeTestChallengeExactPath) {
		t.Errorf("want 1 VirtualServer warning mentioning %q, got %q", acmeTestChallengeExactPath, vsWarnings)
	}
}
