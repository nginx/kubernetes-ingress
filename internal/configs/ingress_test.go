package configs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGenerateNginxCfg(t *testing.T) {
	t.Parallel()
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                new(createCafeIngressEx()),
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForJWT(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations[JWTKeyAnnotation] = "cafe-jwk"
	cafeIngressEx.Ingress.Annotations[JWTRealmAnnotation] = "Cafe App"
	cafeIngressEx.Ingress.Annotations[JWTTokenAnnotation] = "$cookie_auth_token"
	cafeIngressEx.Ingress.Annotations[JWTLoginURLAnnotation] = "https://login.example.com"
	cafeIngressEx.SecretRefs["cafe-jwk"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeJWK,
		},
		Path: "/etc/nginx/secrets/default-cafe-jwk",
	}

	isPlus := true
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].JWTAuth = &version1.JWTAuth{
		Key:                  "/etc/nginx/secrets/default-cafe-jwk",
		Realm:                "Cafe App",
		Token:                "$cookie_auth_token",
		RedirectLocationName: "@login_url_default-cafe-ingress",
	}
	expected.Servers[0].JWTRedirectLocations = []version1.JWTRedirectLocation{
		{
			Name:     "@login_url_default-cafe-ingress",
			LoginURL: "https://login.example.com",
		},
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               true,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if !reflect.DeepEqual(result.Servers[0].JWTAuth, expected.Servers[0].JWTAuth) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.Servers[0].JWTAuth, expected.Servers[0].JWTAuth)
	}
	if !reflect.DeepEqual(result.Servers[0].JWTRedirectLocations, expected.Servers[0].JWTRedirectLocations) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.Servers[0].JWTRedirectLocations, expected.Servers[0].JWTRedirectLocations)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForBasicAuth(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/basic-auth-secret"] = "cafe-htpasswd"
	cafeIngressEx.Ingress.Annotations["nginx.org/basic-auth-realm"] = "Cafe App"
	cafeIngressEx.SecretRefs["cafe-htpasswd"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeHtpasswd,
		},
		Path: "/etc/nginx/secrets/default-cafe-htpasswd",
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].BasicAuth = &version1.BasicAuth{
		Secret: "/etc/nginx/secrets/default-cafe-htpasswd",
		Realm:  "Cafe App",
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               true,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if !reflect.DeepEqual(result.Servers[0].BasicAuth, expected.Servers[0].BasicAuth) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.Servers[0].BasicAuth, expected.Servers[0].BasicAuth)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForAppRoot(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/app-root"] = "/coffee"

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].AppRoot = "/coffee"

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if result.Servers[0].AppRoot != expected.Servers[0].AppRoot {
		t.Errorf("generateNginxCfg returned AppRoot %v, but expected %v", result.Servers[0].AppRoot, expected.Servers[0].AppRoot)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForCORSPolicy(t *testing.T) {
	t.Parallel()

	allowCredentials := true
	maxAge := 3600

	tests := []struct {
		name           string
		allowOrigin    []string
		wantMap        bool
		wantOrigin     string
		wantVaryHeader bool
	}{
		{
			// Single exact origin should produce direct header value (no map).
			name:           "single origin without map",
			allowOrigin:    []string{"https://example.com"},
			wantMap:        false,
			wantOrigin:     "https://example.com",
			wantVaryHeader: true,
		},
		{
			// Multiple/wildcard origins should be validated through a generated map variable.
			name:           "multiple origins with map",
			allowOrigin:    []string{"https://example.com", "https://*.example.com"},
			wantMap:        true,
			wantVaryHeader: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cafeIngressEx := createCafeIngressEx()
			cafeIngressEx.Ingress.Annotations["nginx.org/policies"] = "cors-policy"
			cafeIngressEx.Policies = map[string]*conf_v1.Policy{
				"default/cors-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cors-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						CORS: &conf_v1.CORS{
							AllowOrigin:      test.allowOrigin,
							AllowMethods:     []string{"GET", "POST", "OPTIONS"},
							AllowHeaders:     []string{"Authorization", "Content-Type"},
							AllowCredentials: &allowCredentials,
							MaxAge:           &maxAge,
						},
					},
				},
			}

			isPlus := false
			configParams := NewDefaultConfigParams(context.Background(), isPlus)
			result, warnings := generateNginxCfg(NginxCfgParams{
				staticParams:         &StaticConfigParams{},
				ingEx:                &cafeIngressEx,
				isPlus:               isPlus,
				BaseCfgParams:        configParams,
				isResolverConfigured: false,
				isWildcardEnabled:    false,
			})

			if len(warnings) != 0 {
				t.Fatalf("generateNginxCfg() returned warnings: %v", warnings)
			}

			if test.wantMap && len(result.Maps) != 1 {
				t.Fatalf("expected 1 CORS map, got %d", len(result.Maps))
			}
			if !test.wantMap && len(result.Maps) != 0 {
				t.Fatalf("expected no CORS map, got %d", len(result.Maps))
			}

			originValue := test.wantOrigin
			if test.wantMap {
				if result.Maps[0].Source != "$http_origin" {
					t.Fatalf("unexpected map source: %s", result.Maps[0].Source)
				}
				originValue = result.Maps[0].Variable
			}

			for _, server := range result.Servers {
				for _, loc := range server.Locations {
					if !loc.CORSEnabled {
						t.Fatalf("location %s should have CORS enabled", loc.Path)
					}

					originHeader, ok := getHeaderValue(loc.AddHeaders, "Access-Control-Allow-Origin")
					if !ok {
						t.Fatalf("location %s missing Access-Control-Allow-Origin header", loc.Path)
					}
					if originHeader != originValue {
						t.Fatalf("location %s origin header = %q, want %q", loc.Path, originHeader, originValue)
					}

					_, hasVary := getHeaderValue(loc.AddHeaders, "Vary")
					if hasVary != test.wantVaryHeader {
						t.Fatalf("location %s vary header present = %v, want %v", loc.Path, hasVary, test.wantVaryHeader)
					}
				}
			}
		})
	}
}

func TestGenerateNginxCfgForMergeableIngressesCORSPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		masterOrigin         string
		coffeeMinionOrigin   string
		expectCoffeeFromMin  bool
		expectedTeaOriginVal string
	}{
		{
			// Master policy should flow to minion locations when minion has no CORS policy.
			name:                 "inherits master cors in all minions",
			masterOrigin:         "https://master.example.com",
			expectCoffeeFromMin:  false,
			expectedTeaOriginVal: "https://master.example.com",
		},
		{
			// Minion policy should override master fallback for that minion only.
			name:                 "keeps minion cors when configured",
			masterOrigin:         "https://master.example.com",
			coffeeMinionOrigin:   "https://coffee.example.com",
			expectCoffeeFromMin:  true,
			expectedTeaOriginVal: "https://master.example.com",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mergeableIngresses := createMergeableCafeIngress()
			mergeableIngresses.Master.Ingress.Annotations["nginx.org/policies"] = "master-cors"
			mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{
				"default/master-cors": {
					ObjectMeta: meta_v1.ObjectMeta{Name: "master-cors", Namespace: "default"},
					Spec: conf_v1.PolicySpec{
						CORS: &conf_v1.CORS{AllowOrigin: []string{test.masterOrigin}},
					},
				},
			}

			if test.coffeeMinionOrigin != "" {
				mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/policies"] = "coffee-cors"
				mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
					"default/coffee-cors": {
						ObjectMeta: meta_v1.ObjectMeta{Name: "coffee-cors", Namespace: "default"},
						Spec: conf_v1.PolicySpec{
							CORS: &conf_v1.CORS{AllowOrigin: []string{test.coffeeMinionOrigin}},
						},
					},
				}
			}

			isPlus := false
			configParams := NewDefaultConfigParams(context.Background(), isPlus)
			result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
				mergeableIngs:        mergeableIngresses,
				BaseCfgParams:        configParams,
				isPlus:               isPlus,
				isResolverConfigured: false,
				staticParams:         &StaticConfigParams{},
				isWildcardEnabled:    false,
			})

			if len(warnings) != 0 {
				t.Fatalf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
			}

			if len(result.Maps) != 0 {
				t.Fatalf("expected no CORS maps for single-origin policies, got %d", len(result.Maps))
			}

			for _, loc := range result.Servers[0].Locations {
				if !loc.CORSEnabled {
					t.Fatalf("location %s should have CORS enabled", loc.Path)
				}

				originHeader, ok := getHeaderValue(loc.AddHeaders, "Access-Control-Allow-Origin")
				if !ok {
					t.Fatalf("location %s missing Access-Control-Allow-Origin header", loc.Path)
				}

				switch loc.MinionIngress.Name {
				case "cafe-ingress-coffee-minion":
					expectedCoffeeOrigin := test.masterOrigin
					if test.expectCoffeeFromMin {
						expectedCoffeeOrigin = test.coffeeMinionOrigin
					}
					if originHeader != expectedCoffeeOrigin {
						t.Fatalf("coffee minion origin = %q, want %q", originHeader, expectedCoffeeOrigin)
					}
				case "cafe-ingress-tea-minion":
					if originHeader != test.expectedTeaOriginVal {
						t.Fatalf("tea minion origin = %q, want %q", originHeader, test.expectedTeaOriginVal)
					}
				default:
					t.Fatalf("unexpected minion %s", loc.MinionIngress.Name)
				}
			}
		})
	}
}

func getHeaderValue(headers []version2.AddHeader, headerName string) (string, bool) {
	for _, header := range headers {
		if header.Name == headerName {
			return header.Value, true
		}
	}

	return "", false
}

func TestFilterIngressPolicyRefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		annotationValue string
		policies        map[string]*conf_v1.Policy
		policyRefs      []conf_v1.PolicyReference
		expectedRefs    []conf_v1.PolicyReference
		warningSubstr   string
	}{
		{
			name:            "filters waf policy from nginx org policies",
			annotationValue: "waf-policy",
			policies: map[string]*conf_v1.Policy{
				"default/waf-policy": {
					ObjectMeta: meta_v1.ObjectMeta{Name: "waf-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{WAF: &conf_v1.WAF{Enable: true, ApPolicy: "dataguard-alarm"}},
				},
			},
			policyRefs:    []conf_v1.PolicyReference{{Name: "waf-policy"}},
			expectedRefs:  []conf_v1.PolicyReference{},
			warningSubstr: "WAF policy default/waf-policy is not supported in annotation nginx.org/policies",
		},
		{
			name:            "keeps non plus policy from nginx org policies",
			annotationValue: "cors-policy",
			policies: map[string]*conf_v1.Policy{
				"default/cors-policy": {
					ObjectMeta: meta_v1.ObjectMeta{Name: "cors-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{CORS: &conf_v1.CORS{AllowOrigin: []string{"https://example.com"}}},
				},
			},
			policyRefs:   []conf_v1.PolicyReference{{Name: "cors-policy"}},
			expectedRefs: []conf_v1.PolicyReference{{Name: "cors-policy"}},
		},
		{
			name:            "keeps plus annotation ref when same policy is referenced there",
			annotationValue: "other-policy",
			policies: map[string]*conf_v1.Policy{
				"default/waf-policy": {
					ObjectMeta: meta_v1.ObjectMeta{Name: "waf-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{WAF: &conf_v1.WAF{Enable: true, ApPolicy: "dataguard-alarm"}},
				},
			},
			policyRefs:   []conf_v1.PolicyReference{{Name: "waf-policy"}},
			expectedRefs: []conf_v1.PolicyReference{{Name: "waf-policy"}},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ingEx := createCafeIngressEx()
			ingEx.Ingress.Annotations[PoliciesAnnotation] = test.annotationValue
			ingEx.Policies = test.policies

			result, warnings := filterIngressPolicyRefs(test.policyRefs, &ingEx)
			if diff := cmp.Diff(test.expectedRefs, result); diff != "" {
				t.Fatalf("filterIngressPolicyRefs() returned unexpected refs (-want +got):\n%s", diff)
			}

			ingressWarnings := warnings[ingEx.Ingress]
			if test.warningSubstr == "" {
				if len(ingressWarnings) != 0 {
					t.Fatalf("expected no warnings, got %v", ingressWarnings)
				}
				return
			}

			if len(ingressWarnings) != 1 || !strings.Contains(ingressWarnings[0], test.warningSubstr) {
				t.Fatalf("expected warning containing %q, got %v", test.warningSubstr, ingressWarnings)
			}
		})
	}
}

func TestGetIngressPolicyRefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		ingEx        *IngressEx
		expectedRefs []conf_v1.PolicyReference
	}{
		{
			name:         "nil ingress ex returns nil",
			ingEx:        nil,
			expectedRefs: nil,
		},
		{
			name: "merges annotations and de duplicates normalized refs",
			ingEx: func() *IngressEx {
				ingEx := createCafeIngressEx()
				ingEx.Ingress.Annotations[PoliciesAnnotation] = "cors-policy, other-ns/other-policy, dup-policy"
				ingEx.Ingress.Annotations[PoliciesAnnotationPlus] = "default/dup-policy, waf-ns/waf-policy, cors-policy"
				return &ingEx
			}(),
			expectedRefs: []conf_v1.PolicyReference{
				{Name: "cors-policy", Namespace: "default"},
				{Name: "other-policy", Namespace: "other-ns"},
				{Name: "dup-policy", Namespace: "default"},
				{Name: "waf-policy", Namespace: "waf-ns"},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := getIngressPolicyRefs(test.ingEx)
			if diff := cmp.Diff(test.expectedRefs, result); diff != "" {
				t.Fatalf("getIngressPolicyRefs() returned unexpected refs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveIngressAppProtectResources(t *testing.T) {
	t.Parallel()

	baseResources := &AppProtectResources{
		AppProtectPolicy:   "policy.json",
		AppProtectLogconfs: []string{"log.json stderr"},
	}

	tests := []struct {
		name              string
		ingEx             *IngressEx
		policyCfg         policiesCfg
		expectedResources *AppProtectResources
		warningSubstr     string
	}{
		{
			name:              "returns original resources when waf policy is absent",
			ingEx:             &IngressEx{Ingress: createCafeIngressEx().Ingress},
			policyCfg:         policiesCfg{},
			expectedResources: baseResources,
		},
		{
			name:              "returns original resources when ingress has no app protect annotations",
			ingEx:             &IngressEx{Ingress: createCafeIngressEx().Ingress},
			policyCfg:         policiesCfg{WAF: &version2.WAF{Enable: "on"}},
			expectedResources: baseResources,
		},
		{
			name: "policy waf takes precedence over app protect annotations",
			ingEx: func() *IngressEx {
				ingEx := createCafeIngressEx()
				ingEx.Ingress.Annotations[AppProtectPolicyAnnotation] = "default/ap-policy"
				return &ingEx
			}(),
			policyCfg:         policiesCfg{WAF: &version2.WAF{Enable: "on"}},
			expectedResources: &AppProtectResources{},
			warningSubstr:     "WAF cannot be configured through both Policy and App Protect annotations",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, warnings := resolveIngressAppProtectResources(test.ingEx, baseResources, test.policyCfg)
			if diff := cmp.Diff(test.expectedResources, result); diff != "" {
				t.Fatalf("resolveIngressAppProtectResources() returned unexpected resources (-want +got):\n%s", diff)
			}

			ingressWarnings := warnings[test.ingEx.Ingress]
			if test.warningSubstr == "" {
				if len(ingressWarnings) != 0 {
					t.Fatalf("expected no warnings, got %v", ingressWarnings)
				}
				return
			}

			if len(ingressWarnings) != 1 || !strings.Contains(ingressWarnings[0], test.warningSubstr) {
				t.Fatalf("expected warning containing %q, got %v", test.warningSubstr, ingressWarnings)
			}
		})
	}
}

func TestGenerateNginxCfgForAccessControl(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/policies"] = "my-test-policy"
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/my-test-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "my-test-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				AccessControl: &conf_v1.AccessControl{
					Allow: []string{"10.1.0.0/24"},
				},
			},
		},
	}
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].Allow = []string{"10.1.0.0/24"}
	expected.Ingress.Annotations["nginx.org/policies"] = "my-test-policy"

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:  &StaticConfigParams{},
		ingEx:         &cafeIngressEx,
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForEgressMTLSPolicy(t *testing.T) {
	t.Parallel()

	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations[PoliciesAnnotation] = "egress-mtls-policy"
	cafeIngressEx.Ingress.Annotations["nginx.org/ssl-services"] = "coffee-svc,tea-svc"
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/egress-mtls-policy": newEgressMTLSPolicy(
			"egress-mtls-policy",
			"egress-mtls-secret",
			"egress-trusted-ca-secret",
			"secure-app.example.com",
			true,
			2,
		),
	}
	addEgressMTLSSecretRefs(cafeIngressEx.SecretRefs)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		isPlus:               false,
		BaseCfgParams:        NewDefaultConfigParams(context.Background(), false),
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if len(warnings) != 0 {
		t.Fatalf("generateNginxCfg() returned warnings: %v", warnings)
	}

	expectedEgressMTLS := expectedEgressMTLSConfig(
		"/etc/nginx/secrets/default-egress-mtls-secret",
		"/etc/nginx/secrets/default-egress-trusted-ca-secret",
		"secure-app.example.com",
		true,
		2,
	)

	for _, server := range result.Servers {
		if diff := cmp.Diff(expectedEgressMTLS, server.EgressMTLS); diff != "" {
			t.Fatalf("server %s egress mTLS mismatch (-want +got):\n%s", server.Name, diff)
		}

		for _, loc := range server.Locations {
			if loc.EgressMTLS != nil {
				t.Fatalf("location %s should inherit egress mTLS from server context", loc.Path)
			}
			if !loc.SSL {
				t.Fatalf("location %s should proxy to a TLS upstream", loc.Path)
			}
			if !strings.HasPrefix(loc.ProxyPass, "https://") {
				t.Fatalf("location %s proxy pass = %q, want https upstream", loc.Path, loc.ProxyPass)
			}
		}
	}
}

func TestGenerateNginxCfgForWAFPolicyApPolicy(t *testing.T) {
	t.Parallel()

	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations[PoliciesAnnotationPlus] = "waf-policy"
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/waf-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "waf-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				WAF: &conf_v1.WAF{
					Enable:   true,
					ApPolicy: "dataguard-alarm",
					SecurityLogs: []*conf_v1.SecurityLog{
						{
							Enable:    true,
							ApLogConf: "logconf",
							LogDest:   "syslog:server=127.0.0.1:514",
						},
					},
				},
			},
		},
	}
	cafeIngressEx.ApPolRefs = map[string]*unstructured.Unstructured{
		"default/dataguard-alarm": {
			Object: map[string]interface{}{},
		},
	}
	cafeIngressEx.ApPolRefs["default/dataguard-alarm"].SetNamespace("default")
	cafeIngressEx.ApPolRefs["default/dataguard-alarm"].SetName("dataguard-alarm")
	cafeIngressEx.LogConfRefs = map[string]*unstructured.Unstructured{
		"default/logconf": {
			Object: map[string]interface{}{},
		},
	}
	cafeIngressEx.LogConfRefs["default/logconf"].SetNamespace("default")
	cafeIngressEx.LogConfRefs["default/logconf"].SetName("logconf")

	configParams := NewDefaultConfigParams(context.Background(), true)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		isPlus:               true,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	expectedWAF := &version2.WAF{
		Enable:              "on",
		ApPolicy:            "/etc/nginx/waf/nac-policies/default_dataguard-alarm",
		ApSecurityLogEnable: true,
		ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514"},
	}

	if diff := cmp.Diff(expectedWAF, result.Servers[0].WAF); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected WAF config (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgRejectsPoliciesRequiringPlusAnnotationFromNginxOrgPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		annotations      map[string]string
		expectWarning    bool
		expectWAFApplied bool
	}{
		{
			name: "waf policy via nginx.org/policies is rejected",
			annotations: map[string]string{
				PoliciesAnnotation: "waf-policy",
			},
			expectWarning:    true,
			expectWAFApplied: false,
		},
		{
			name: "waf policy via both annotations is rejected",
			annotations: map[string]string{
				PoliciesAnnotation:     "waf-policy",
				PoliciesAnnotationPlus: "waf-policy",
			},
			expectWarning:    true,
			expectWAFApplied: false,
		},
		{
			name: "waf policy via nginx.com/policies is accepted",
			annotations: map[string]string{
				PoliciesAnnotationPlus: "waf-policy",
			},
			expectWarning:    false,
			expectWAFApplied: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			cafeIngressEx := createCafeIngressEx()
			for key, value := range test.annotations {
				cafeIngressEx.Ingress.Annotations[key] = value
			}
			cafeIngressEx.Policies = map[string]*conf_v1.Policy{
				"default/waf-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "dataguard-alarm",
						},
					},
				},
			}
			cafeIngressEx.ApPolRefs = map[string]*unstructured.Unstructured{
				"default/dataguard-alarm": {
					Object: map[string]interface{}{},
				},
			}
			cafeIngressEx.ApPolRefs["default/dataguard-alarm"].SetNamespace("default")
			cafeIngressEx.ApPolRefs["default/dataguard-alarm"].SetName("dataguard-alarm")

			result, warnings := generateNginxCfg(NginxCfgParams{
				staticParams:         &StaticConfigParams{},
				ingEx:                &cafeIngressEx,
				isPlus:               true,
				BaseCfgParams:        NewDefaultConfigParams(context.Background(), true),
				isResolverConfigured: false,
				isWildcardEnabled:    false,
			})

			ingressWarnings := warnings[cafeIngressEx.Ingress]
			if test.expectWarning {
				if len(ingressWarnings) != 1 {
					t.Fatalf("expected 1 ingress warning, got %d: %v", len(ingressWarnings), ingressWarnings)
				}
				if !strings.Contains(ingressWarnings[0], "WAF policy default/waf-policy is not supported in annotation nginx.org/policies") {
					t.Fatalf("expected nginx.org/policies warning, got: %v", ingressWarnings[0])
				}
			} else if len(ingressWarnings) != 0 {
				t.Fatalf("expected no ingress warnings, got: %v", ingressWarnings)
			}

			hasWAF := result.Servers[0].WAF != nil
			if hasWAF != test.expectWAFApplied {
				t.Fatalf("expected WAF applied=%v, got %v", test.expectWAFApplied, hasWAF)
			}
		})
	}
}

func TestGenerateNginxCfgAppliesWAFAndCORSFromDifferentPolicyAnnotations(t *testing.T) {
	t.Parallel()

	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations[PoliciesAnnotation] = "cors-policy"
	cafeIngressEx.Ingress.Annotations[PoliciesAnnotationPlus] = "waf-policy"
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/cors-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cors-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				CORS: &conf_v1.CORS{
					AllowOrigin: []string{"https://example.com"},
				},
			},
		},
		"default/waf-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "waf-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				WAF: &conf_v1.WAF{
					Enable:   true,
					ApPolicy: "dataguard-alarm",
				},
			},
		},
	}
	cafeIngressEx.ApPolRefs = map[string]*unstructured.Unstructured{
		"default/dataguard-alarm": {
			Object: map[string]interface{}{},
		},
	}
	cafeIngressEx.ApPolRefs["default/dataguard-alarm"].SetNamespace("default")
	cafeIngressEx.ApPolRefs["default/dataguard-alarm"].SetName("dataguard-alarm")

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		isPlus:               true,
		BaseCfgParams:        NewDefaultConfigParams(context.Background(), true),
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if len(warnings) != 0 {
		t.Fatalf("generateNginxCfg() returned warnings: %v", warnings)
	}

	if result.Servers[0].WAF == nil {
		t.Fatal("expected WAF config to be generated")
	}
	if result.Servers[0].WAF.ApPolicy != "/etc/nginx/waf/nac-policies/default_dataguard-alarm" {
		t.Fatalf("expected WAF policy file path to be set, got %q", result.Servers[0].WAF.ApPolicy)
	}

	for _, loc := range result.Servers[0].Locations {
		if !loc.CORSEnabled {
			t.Fatalf("location %s should have CORS enabled", loc.Path)
		}
		originHeader, ok := getHeaderValue(loc.AddHeaders, "Access-Control-Allow-Origin")
		if !ok {
			t.Fatalf("location %s missing Access-Control-Allow-Origin header", loc.Path)
		}
		if originHeader != "https://example.com" {
			t.Fatalf("location %s origin header = %q, want %q", loc.Path, originHeader, "https://example.com")
		}
	}
}

func TestGenerateNginxCfgForWAFPolicyApBundle(t *testing.T) {
	t.Parallel()

	bundleDir := t.TempDir()
	bundleName := "wafv5.tgz"
	bundlePath := filepath.Join(bundleDir, bundleName)

	if err := os.WriteFile(bundlePath, []byte("bundle"), 0o600); err != nil {
		t.Fatalf("failed to create test bundle file: %v", err)
	}

	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations[PoliciesAnnotationPlus] = "waf-policy"
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/waf-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "waf-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				WAF: &conf_v1.WAF{
					Enable:   true,
					ApBundle: bundleName,
				},
			},
		},
	}

	configParams := NewDefaultConfigParams(context.Background(), true)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams: &StaticConfigParams{
			AppProtectBundlePath: bundleDir,
		},
		ingEx:                &cafeIngressEx,
		isPlus:               true,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if result.Servers[0].WAF == nil {
		t.Fatal("expected WAF config to be generated")
	}
	if result.Servers[0].WAF.ApBundle != bundlePath {
		t.Errorf("expected ApBundle %q, got %q", bundlePath, result.Servers[0].WAF.ApBundle)
	}
	if result.Servers[0].WAF.Enable != "on" {
		t.Errorf("expected WAF enable to be \"on\", got %q", result.Servers[0].WAF.Enable)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

// TestGenerateNginxCfgWithMissingOrInvalidPolicy verifies that a standard Ingress referencing a
// policy that is absent from the Policies map (either deleted or excluded by validation) sets
// Server.PoliciesErrorReturn to 500. Both missing and invalid policies converge to the same
// code path in generatePolicies because getPolicies excludes invalid policies from the map.
// This branch extends the same logic to nginx.com/policies without changing its current behavior.
func TestGenerateNginxCfgWithMissingOrInvalidPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
	}{
		{
			name:       "missing policy via nginx.org/policies",
			annotation: PoliciesAnnotation,
		},
		{
			name:       "missing policy via nginx.com/policies",
			annotation: PoliciesAnnotationPlus,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cafeIngressEx := createCafeIngressEx()
			cafeIngressEx.Ingress.Annotations[test.annotation] = "missing-policy"
			// Policies map is intentionally empty: the referenced policy is not present.
			cafeIngressEx.Policies = map[string]*conf_v1.Policy{}

			result, warnings := generateNginxCfg(NginxCfgParams{
				staticParams:  &StaticConfigParams{},
				ingEx:         &cafeIngressEx,
				isPlus:        true,
				BaseCfgParams: NewDefaultConfigParams(context.Background(), true),
			})

			expectedPoliciesErrorReturn := &version2.Return{Code: 500}
			if diff := cmp.Diff(expectedPoliciesErrorReturn, result.Servers[0].PoliciesErrorReturn); diff != "" {
				t.Errorf("Server.PoliciesErrorReturn mismatch (-want +got):\n%s", diff)
			}

			const expectedWarning = "Policy default/missing-policy is missing or invalid"
			if !warningsContain(warnings, expectedWarning) {
				t.Fatalf("expected warning containing %q, got %v", expectedWarning, warnings)
			}
		})
	}
}

func TestGenerateNginxCfgWithMissingTLSSecret(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.SecretRefs["cafe-secret"].Error = errors.New("secret doesn't exist")
	configParams := NewDefaultConfigParams(context.Background(), false)

	result, resultWarnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               false,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	expectedSSLRejectHandshake := true
	expectedWarnings := Warnings{
		cafeIngressEx.Ingress: {
			"TLS secret cafe-secret is invalid: secret doesn't exist",
		},
	}

	resultSSLRejectHandshake := result.Servers[0].SSLRejectHandshake
	if !reflect.DeepEqual(resultSSLRejectHandshake, expectedSSLRejectHandshake) {
		t.Errorf("generateNginxCfg returned SSLRejectHandshake %v,  but expected %v", resultSSLRejectHandshake, expectedSSLRejectHandshake)
	}
	if diff := cmp.Diff(expectedWarnings, resultWarnings); diff != "" {
		t.Errorf("generateNginxCfg returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestGenerateNginxCfgWithWildcardTLSSecret(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Spec.TLS[0].SecretName = ""
	configParams := NewDefaultConfigParams(context.Background(), false)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               false,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    true,
	})

	resultServer := result.Servers[0]
	if !reflect.DeepEqual(resultServer.SSLCertificate, pemFileNameForWildcardTLSSecret) {
		t.Errorf("generateNginxCfg returned SSLCertificate %v,  but expected %v", resultServer.SSLCertificate, pemFileNameForWildcardTLSSecret)
	}
	if !reflect.DeepEqual(resultServer.SSLCertificateKey, pemFileNameForWildcardTLSSecret) {
		t.Errorf("generateNginxCfg returned SSLCertificateKey %v,  but expected %v", resultServer.SSLCertificateKey, pemFileNameForWildcardTLSSecret)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgWithIPV6Disabled(t *testing.T) {
	t.Parallel()
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].DisableIPV6 = true

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{DisableIPV6: true},
		ingEx:                new(createCafeIngressEx()),
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if !cmp.Equal(expected, result) {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", cmp.Diff(expected, result))
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgSetsHasGRPCLocationsFalseWithoutGRPCServices(t *testing.T) {
	t.Parallel()

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	cafeIngressEx := createCafeIngressEx()
	expected := createExpectedConfigForCafeIngressEx(isPlus)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgSetsHasGRPCLocationsForMixedIngress(t *testing.T) {
	t.Parallel()

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/grpc-services"] = "coffee-svc"
	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].HasGRPCLocations = true
	expected.Servers[0].Locations[0].GRPC = true
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgSetsHasGRPCLocationsForGRPCOnlyIngress(t *testing.T) {
	t.Parallel()

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/grpc-services"] = "coffee-svc,tea-svc"
	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].GRPCOnly = true
	expected.Servers[0].HasGRPCLocations = true
	expected.Servers[0].Locations[0].GRPC = true
	expected.Servers[0].Locations[1].GRPC = true
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgSetsHasGRPCLocationsFalseForNonGRPCDefaultBackend(t *testing.T) {
	t.Parallel()

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Spec.Rules[0].HTTP.Paths = nil
	cafeIngressEx.Ingress.Annotations["nginx.org/grpc-services"] = "coffee-svc"
	cafeIngressEx.Ingress.Spec.DefaultBackend = &networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: "tea-svc",
			Port: networking.ServiceBackendPort{
				Number: 80,
			},
		},
	}
	expected := createExpectedConfigForCafeIngressEx(isPlus)
	defaultBackendUpstream := expected.Upstreams[1]
	defaultBackendUpstream.Name = getNameForUpstream(cafeIngressEx.Ingress, emptyHostName, cafeIngressEx.Ingress.Spec.DefaultBackend)
	defaultBackendLocation := expected.Servers[0].Locations[1]
	defaultBackendLocation.Path = "/"
	defaultBackendLocation.Upstream = defaultBackendUpstream
	defaultBackendLocation.ProxyPass = "http://" + defaultBackendUpstream.Name
	expected.Upstreams = []version1.Upstream{defaultBackendUpstream}
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].Locations = []version1.Location{defaultBackendLocation}
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgSetsHasGRPCLocationsForGRPCDefaultBackend(t *testing.T) {
	t.Parallel()

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Spec.Rules[0].HTTP.Paths = nil
	cafeIngressEx.Ingress.Spec.DefaultBackend = &networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: "tea-svc",
			Port: networking.ServiceBackendPort{
				Number: 80,
			},
		},
	}
	cafeIngressEx.Ingress.Annotations["nginx.org/grpc-services"] = "tea-svc"
	expected := createExpectedConfigForCafeIngressEx(isPlus)
	defaultBackendUpstream := expected.Upstreams[1]
	defaultBackendUpstream.Name = getNameForUpstream(cafeIngressEx.Ingress, emptyHostName, cafeIngressEx.Ingress.Spec.DefaultBackend)
	defaultBackendLocation := expected.Servers[0].Locations[1]
	defaultBackendLocation.Path = "/"
	defaultBackendLocation.Upstream = defaultBackendUpstream
	defaultBackendLocation.ProxyPass = "http://" + defaultBackendUpstream.Name
	defaultBackendLocation.GRPC = true
	expected.Upstreams = []version1.Upstream{defaultBackendUpstream}
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].GRPCOnly = true
	expected.Servers[0].HasGRPCLocations = true
	expected.Servers[0].Locations = []version1.Location{defaultBackendLocation}
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgSetsHasGRPCLocationsForMixedIngressWithGRPCDefaultBackend(t *testing.T) {
	t.Parallel()

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Spec.DefaultBackend = &networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: "tea-svc",
			Port: networking.ServiceBackendPort{
				Number: 80,
			},
		},
	}
	cafeIngressEx.Ingress.Annotations["nginx.org/grpc-services"] = "tea-svc"
	expected := createExpectedConfigForCafeIngressEx(isPlus)
	defaultBackendUpstream := expected.Upstreams[1]
	defaultBackendUpstream.Name = getNameForUpstream(cafeIngressEx.Ingress, emptyHostName, cafeIngressEx.Ingress.Spec.DefaultBackend)
	defaultBackendLocation := expected.Servers[0].Locations[1]
	defaultBackendLocation.Path = "/"
	defaultBackendLocation.Upstream = defaultBackendUpstream
	defaultBackendLocation.ProxyPass = "http://" + defaultBackendUpstream.Name
	defaultBackendLocation.GRPC = true
	expected.Upstreams = []version1.Upstream{defaultBackendUpstream, expected.Upstreams[0], expected.Upstreams[1]}
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].HasGRPCLocations = true
	expected.Servers[0].Locations[1].GRPC = true
	expected.Servers[0].Locations = append(expected.Servers[0].Locations, defaultBackendLocation)
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestPathOrDefaultReturnDefault(t *testing.T) {
	t.Parallel()
	path := ""
	expected := "/"
	if pathOrDefault(path) != expected {
		t.Errorf("pathOrDefault(%q) should return %q", path, expected)
	}
}

func TestPathOrDefaultReturnActual(t *testing.T) {
	t.Parallel()
	path := "/path/to/resource"
	if pathOrDefault(path) != path {
		t.Errorf("pathOrDefault(%q) should return %q", path, path)
	}
}

func TestGenerateIngressPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pathType *networking.PathType
		path     string
		expected string
	}{
		{
			pathType: new(networking.PathTypeExact),
			path:     "/path/to/resource",
			expected: "= /path/to/resource",
		},
		{
			pathType: new(networking.PathTypePrefix),
			path:     "/path/to/resource",
			expected: "/path/to/resource",
		},
		{
			pathType: new(networking.PathTypeImplementationSpecific),
			path:     "/path/to/resource",
			expected: "/path/to/resource",
		},
		{
			pathType: nil,
			path:     "/path/to/resource",
			expected: "/path/to/resource",
		},
	}
	for _, test := range tests {
		result := generateIngressPath(test.path, test.pathType)
		if result != test.expected {
			t.Errorf("generateIngressPath(%v, %v) returned %v, but expected %v", test.path, test.pathType, result, test.expected)
		}
	}
}

// warningsContain checks whether any warning message across all objects in the
// Warnings map contains the given substring. This avoids pointer-identity issues
// with runtime.Object keys when comparing mergeable ingress warnings.
func warningsContain(w Warnings, substr string) bool {
	for _, msgs := range w {
		for _, msg := range msgs {
			if strings.Contains(msg, substr) {
				return true
			}
		}
	}
	return false
}

func createExpectedConfigForCafeIngressEx(isPlus bool) version1.IngressNginxConfig {
	upstreamZoneSize := "256k"
	if isPlus {
		upstreamZoneSize = "512k"
	}

	coffeeUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-cafe.example.com-coffee-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.1:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	if isPlus {
		coffeeUpstream.UpstreamLabels = version1.UpstreamLabels{
			Service:           "coffee-svc",
			ResourceType:      "ingress",
			ResourceName:      "cafe-ingress",
			ResourceNamespace: "default",
		}
	}

	teaUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.2:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	if isPlus {
		teaUpstream.UpstreamLabels = version1.UpstreamLabels{
			Service:           "tea-svc",
			ResourceType:      "ingress",
			ResourceName:      "cafe-ingress",
			ResourceNamespace: "default",
		}
	}

	expected := version1.IngressNginxConfig{
		Upstreams: []version1.Upstream{
			coffeeUpstream,
			teaUpstream,
		},
		Servers: []version1.Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []version1.Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						ProxySSLName:        "coffee-svc.default.svc",
						ProxyPass:           "http://default-cafe-ingress-cafe.example.com-coffee-svc-80",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						ProxySSLName:        "tea-svc.default.svc",
						ProxyPass:           "http://default-cafe-ingress-cafe.example.com-tea-svc-80",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HTTPRedirectCode:  301,
				HealthChecks:      make(map[string]version1.HealthCheck),
			},
		},
		Ingress: version1.Ingress{
			Name:      "cafe-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
			},
		},
	}
	return expected
}

func createCafeIngressEx() IngressEx {
	cafeIngress := networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
			},
		},
		Spec: networking.IngressSpec{
			TLS: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			Rules: []networking.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path: "/coffee",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networking.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
								{
									Path: "/tea",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "tea-svc",
											Port: networking.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	cafeIngressEx := IngressEx{
		Ingress: &cafeIngress,
		Endpoints: map[string][]string{
			"coffee-svc80": {"10.0.0.1:80"},
			"tea-svc80":    {"10.0.0.2:80"},
		},
		ExternalNameSvcs: map[string]bool{},
		ValidHosts: map[string]bool{
			"cafe.example.com": true,
		},
		SecretRefs: map[string]*secrets.SecretReference{
			"cafe-secret": {
				Secret: &v1.Secret{
					Type: v1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-cafe-secret",
			},
		},
	}
	return cafeIngressEx
}

func TestGenerateNginxCfgForMergeableIngresses(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	isPlus := false
	expected := createExpectedConfigForMergeableCafeIngress(isPlus)

	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               false,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesSetsHasGRPCLocationsForMixedMinions(t *testing.T) {
	t.Parallel()

	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/grpc-services"] = mergeableIngresses.Minions[1].Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].HasGRPCLocations = true
	expected.Servers[0].Locations[1].GRPC = true
	expected.Servers[0].Locations[1].MinionIngress.Annotations["nginx.org/grpc-services"] = "tea-svc"

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               false,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesSetsGRPCOnlyForGRPCOnlyMinions(t *testing.T) {
	t.Parallel()

	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/grpc-services"] = mergeableIngresses.Minions[0].Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/grpc-services"] = mergeableIngresses.Minions[1].Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	configParams.HTTP2 = true

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].HTTP2 = true
	expected.Servers[0].GRPCOnly = true
	expected.Servers[0].HasGRPCLocations = true
	expected.Servers[0].Locations[0].GRPC = true
	expected.Servers[0].Locations[0].MinionIngress.Annotations["nginx.org/grpc-services"] = "coffee-svc"
	expected.Servers[0].Locations[1].GRPC = true
	expected.Servers[0].Locations[1].MinionIngress.Annotations["nginx.org/grpc-services"] = "tea-svc"

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               false,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxConfigForCrossNamespaceMergeableIngresses(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	// change the namespaces of the minions to be coffee and tea
	for i, m := range mergeableIngresses.Minions {
		if strings.Contains(m.Ingress.Name, "coffee") {
			mergeableIngresses.Minions[i].Ingress.Namespace = "coffee"
		} else {
			mergeableIngresses.Minions[i].Ingress.Namespace = "tea"
		}
	}

	expected := createExpectedConfigForCrossNamespaceMergeableCafeIngress()
	configParams := NewDefaultConfigParams(context.Background(), false)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               false,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesForJWT(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Master.Ingress.Annotations[JWTKeyAnnotation] = "cafe-jwk"
	mergeableIngresses.Master.Ingress.Annotations[JWTRealmAnnotation] = "Cafe"
	mergeableIngresses.Master.Ingress.Annotations[JWTTokenAnnotation] = "$cookie_auth_token"
	mergeableIngresses.Master.Ingress.Annotations[JWTLoginURLAnnotation] = "https://login.example.com"
	mergeableIngresses.Master.SecretRefs["cafe-jwk"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeJWK,
		},
		Path: "/etc/nginx/secrets/default-cafe-jwk",
	}

	mergeableIngresses.Minions[0].Ingress.Annotations[JWTKeyAnnotation] = "coffee-jwk"
	mergeableIngresses.Minions[0].Ingress.Annotations[JWTRealmAnnotation] = "Coffee"
	mergeableIngresses.Minions[0].Ingress.Annotations[JWTTokenAnnotation] = "$cookie_auth_token_coffee"
	mergeableIngresses.Minions[0].Ingress.Annotations[JWTLoginURLAnnotation] = "https://login.coffee.example.com"
	mergeableIngresses.Minions[0].SecretRefs["coffee-jwk"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeJWK,
		},
		Path: "/etc/nginx/secrets/default-coffee-jwk",
	}

	isPlus := true

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].JWTAuth = &version1.JWTAuth{
		Key:                  "/etc/nginx/secrets/default-cafe-jwk",
		Realm:                "Cafe",
		Token:                "$cookie_auth_token",
		RedirectLocationName: "@login_url_default-cafe-ingress-master",
	}
	expected.Servers[0].Locations[0].JWTAuth = &version1.JWTAuth{
		Key:                  "/etc/nginx/secrets/default-coffee-jwk",
		Realm:                "Coffee",
		Token:                "$cookie_auth_token_coffee",
		RedirectLocationName: "@login_url_default-cafe-ingress-coffee-minion",
	}
	expected.Servers[0].JWTRedirectLocations = []version1.JWTRedirectLocation{
		{
			Name:     "@login_url_default-cafe-ingress-master",
			LoginURL: "https://login.example.com",
		},
		{
			Name:     "@login_url_default-cafe-ingress-coffee-minion",
			LoginURL: "https://login.coffee.example.com",
		},
	}

	minionJwtKeyFileNames := make(map[string]string)
	minionJwtKeyFileNames[objectMetaToFileName(&mergeableIngresses.Minions[0].Ingress.ObjectMeta)] = "/etc/nginx/secrets/default-coffee-jwk"
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if !reflect.DeepEqual(result.Servers[0].JWTAuth, expected.Servers[0].JWTAuth) {
		t.Errorf("generateNginxCfgForMergeableIngresses returned \n%v,  but expected \n%v", result.Servers[0].JWTAuth, expected.Servers[0].JWTAuth)
	}
	if !reflect.DeepEqual(result.Servers[0].Locations[0].JWTAuth, expected.Servers[0].Locations[0].JWTAuth) {
		t.Errorf("generateNginxCfgForMergeableIngresses returned \n%v,  but expected \n%v", result.Servers[0].Locations[0].JWTAuth, expected.Servers[0].Locations[0].JWTAuth)
	}
	if !reflect.DeepEqual(result.Servers[0].JWTRedirectLocations, expected.Servers[0].JWTRedirectLocations) {
		t.Errorf("generateNginxCfgForMergeableIngresses returned \n%v,  but expected \n%v", result.Servers[0].JWTRedirectLocations, expected.Servers[0].JWTRedirectLocations)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesForBasicAuth(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/basic-auth-secret"] = "cafe-htpasswd"
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/basic-auth-realm"] = "Cafe"
	mergeableIngresses.Master.SecretRefs["cafe-htpasswd"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeHtpasswd,
		},
		Path: "/etc/nginx/secrets/default-cafe-htpasswd",
	}

	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/basic-auth-secret"] = "coffee-htpasswd"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/basic-auth-realm"] = "Coffee"
	mergeableIngresses.Minions[0].SecretRefs["coffee-htpasswd"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeHtpasswd,
		},
		Path: "/etc/nginx/secrets/default-coffee-htpasswd",
	}

	isPlus := false

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].BasicAuth = &version1.BasicAuth{
		Secret: "/etc/nginx/secrets/default-cafe-htpasswd",
		Realm:  "Cafe",
	}
	expected.Servers[0].Locations[0].BasicAuth = &version1.BasicAuth{
		Secret: "/etc/nginx/secrets/default-coffee-htpasswd",
		Realm:  "Coffee",
	}

	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if !reflect.DeepEqual(result.Servers[0].BasicAuth, expected.Servers[0].BasicAuth) {
		t.Errorf("generateNginxCfgForMergeableIngresses returned \n%v,  but expected \n%v", result.Servers[0].BasicAuth, expected.Servers[0].BasicAuth)
	}
	if !reflect.DeepEqual(result.Servers[0].Locations[0].BasicAuth, expected.Servers[0].Locations[0].BasicAuth) {
		t.Errorf("generateNginxCfgForMergeableIngresses returned \n%v,  but expected \n%v", result.Servers[0].Locations[0].BasicAuth, expected.Servers[0].Locations[0].BasicAuth)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesMasterWithAccessControl(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/policies"] = "my-test-policy"
	mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{
		"default/my-test-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "my-test-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				AccessControl: &conf_v1.AccessControl{
					Allow: []string{"10.0.0.1/24"},
				},
			},
		},
	}
	isPlus := false

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Ingress.Annotations["nginx.org/policies"] = "my-test-policy"
	expected.Servers[0].Allow = []string{"10.0.0.1/24"}

	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesMinionWithAccessControl(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	for i, m := range mergeableIngresses.Minions {
		if strings.Contains(m.Ingress.Name, "coffee") {
			mergeableIngresses.Minions[i].Ingress.Annotations["nginx.org/policies"] = "my-test-policy"
		}
	}

	mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
		"default/my-test-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "my-test-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				AccessControl: &conf_v1.AccessControl{
					Allow: []string{"10.0.0.1/24"},
				},
			},
		},
	}
	isPlus := false

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)

	for i := range expected.Servers[0].Locations {
		if expected.Servers[0].Locations[i].MinionIngress.Name == "cafe-ingress-coffee-minion" {
			expected.Servers[0].Locations[i].MinionIngress.Annotations["nginx.org/policies"] = "my-test-policy"
			expected.Servers[0].Locations[i].Allow = []string{"10.0.0.1/24"}
		}
	}

	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesEgressMTLSPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		configureMinionOverride bool
	}{
		{name: "inherits master policy"},
		{name: "minion policy overrides master", configureMinionOverride: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mergeableIngresses := createMergeableCafeIngress()
			mergeableIngresses.Master.Ingress.Annotations[PoliciesAnnotation] = "master-egress-mtls-policy"
			mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{
				"default/master-egress-mtls-policy": newEgressMTLSPolicy(
					"master-egress-mtls-policy",
					"egress-mtls-secret",
					"egress-trusted-ca-secret",
					"secure-app.example.com",
					true,
					2,
				),
			}
			addEgressMTLSSecretRefs(mergeableIngresses.Master.SecretRefs)

			for _, minion := range mergeableIngresses.Minions {
				minion.Ingress.Annotations["nginx.org/ssl-services"] = minion.Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name
				addEgressMTLSSecretRefs(minion.SecretRefs)
			}

			if test.configureMinionOverride {
				mergeableIngresses.Minions[0].Ingress.Annotations[PoliciesAnnotation] = "coffee-egress-mtls-policy"
				mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
					"default/coffee-egress-mtls-policy": newEgressMTLSPolicy(
						"coffee-egress-mtls-policy",
						"egress-mtls-secret-alt",
						"egress-trusted-ca-secret-alt",
						"coffee.example.com",
						false,
						4,
					),
				}
			}

			result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
				mergeableIngs:        mergeableIngresses,
				BaseCfgParams:        NewDefaultConfigParams(context.Background(), false),
				isPlus:               false,
				isResolverConfigured: false,
				staticParams:         &StaticConfigParams{},
				isWildcardEnabled:    false,
			})

			if len(warnings) != 0 {
				t.Fatalf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
			}

			masterEgressMTLS := expectedEgressMTLSConfig(
				"/etc/nginx/secrets/default-egress-mtls-secret",
				"/etc/nginx/secrets/default-egress-trusted-ca-secret",
				"secure-app.example.com",
				true,
				2,
			)
			coffeeOverrideEgressMTLS := expectedEgressMTLSConfig(
				"/etc/nginx/secrets/default-egress-mtls-secret-alt",
				"/etc/nginx/secrets/default-egress-trusted-ca-secret-alt",
				"coffee.example.com",
				false,
				4,
			)

			if diff := cmp.Diff(masterEgressMTLS, result.Servers[0].EgressMTLS); diff != "" {
				t.Fatalf("mergeable server egress mTLS mismatch (-want +got):\n%s", diff)
			}

			for _, loc := range result.Servers[0].Locations {
				if !loc.SSL {
					t.Fatalf("location %s should proxy to a TLS upstream", loc.Path)
				}

				var want *version2.EgressMTLS
				if test.configureMinionOverride && loc.MinionIngress.Name == "cafe-ingress-coffee-minion" {
					want = coffeeOverrideEgressMTLS
				}

				if diff := cmp.Diff(want, loc.EgressMTLS); diff != "" {
					t.Fatalf("location %s egress mTLS mismatch (-want +got):\n%s", loc.Path, diff)
				}
			}
		})
	}
}

func TestGenerateNginxCfgForMergeableIngressesGRPCEgressMTLSPolicyOnMinion(t *testing.T) {
	t.Parallel()

	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Minions[0].Ingress.Annotations[PoliciesAnnotation] = "coffee-egress-mtls-policy"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/grpc-services"] = mergeableIngresses.Minions[0].Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name
	mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
		"default/coffee-egress-mtls-policy": newEgressMTLSPolicy(
			"coffee-egress-mtls-policy",
			"egress-mtls-secret-alt",
			"egress-trusted-ca-secret-alt",
			"coffee.example.com",
			false,
			4,
		),
	}
	addEgressMTLSSecretRefs(mergeableIngresses.Minions[0].SecretRefs)
	configParams := NewDefaultConfigParams(context.Background(), false)
	configParams.HTTP2 = true

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		BaseCfgParams:        configParams,
		isPlus:               false,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if len(warnings) != 0 {
		t.Fatalf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}

	want := expectedEgressMTLSConfig(
		"/etc/nginx/secrets/default-egress-mtls-secret-alt",
		"/etc/nginx/secrets/default-egress-trusted-ca-secret-alt",
		"coffee.example.com",
		false,
		4,
	)

	found := false
	for _, loc := range result.Servers[0].Locations {
		if loc.MinionIngress == nil || loc.MinionIngress.Name != "cafe-ingress-coffee-minion" {
			continue
		}

		found = true
		if !loc.GRPC {
			t.Fatalf("location %s should be marked as gRPC", loc.Path)
		}
		if loc.SSL {
			t.Fatalf("location %s should not require ssl-services for this regression case", loc.Path)
		}
		if diff := cmp.Diff(want, loc.EgressMTLS); diff != "" {
			t.Fatalf("location %s egress mTLS mismatch (-want +got):\n%s", loc.Path, diff)
		}
	}

	if !found {
		t.Fatal("expected to find coffee minion location")
	}
}

// TestGenerateNginxCfgForMergeableIngressesMasterWithMissingOrInvalidPolicy verifies that a
// master Ingress referencing a policy absent from the Policies map sets Server.PoliciesErrorReturn
// to 500. Both missing and invalid policies converge to the same code path.
// This branch extends the same logic to nginx.com/policies without changing its current behavior.
func TestGenerateNginxCfgForMergeableIngressesMasterWithMissingOrInvalidPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
	}{
		{
			name:       "master missing policy via nginx.org/policies",
			annotation: PoliciesAnnotation,
		},
		{
			name:       "master missing policy via nginx.com/policies",
			annotation: PoliciesAnnotationPlus,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mergeableIngresses := createMergeableCafeIngress()
			mergeableIngresses.Master.Ingress.Annotations[test.annotation] = "missing-policy"
			mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{}

			result, resultWarnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
				mergeableIngs: mergeableIngresses,
				BaseCfgParams: NewDefaultConfigParams(context.Background(), true),
				isPlus:        true,
				staticParams:  &StaticConfigParams{},
			})

			expectedPoliciesErrorReturn := &version2.Return{Code: 500}
			if diff := cmp.Diff(expectedPoliciesErrorReturn, result.Servers[0].PoliciesErrorReturn); diff != "" {
				t.Errorf("Server.PoliciesErrorReturn mismatch (-want +got):\n%s", diff)
			}

			const expectedWarning = "Policy default/missing-policy is missing or invalid"
			if !warningsContain(resultWarnings, expectedWarning) {
				t.Fatalf("expected warning containing %q, got %v", expectedWarning, resultWarnings)
			}
		})
	}
}

// TestGenerateNginxCfgForMergeableIngressesMinionWithMissingOrInvalidPolicy verifies that a
// minion Ingress referencing a policy absent from the Policies map sets
// Location.PoliciesErrorReturn to 500 on the corresponding location.
// This branch extends the same logic to nginx.com/policies without changing its current behavior.
func TestGenerateNginxCfgForMergeableIngressesMinionWithMissingOrInvalidPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
	}{
		{
			name:       "minion missing policy via nginx.org/policies",
			annotation: PoliciesAnnotation,
		},
		{
			name:       "minion missing policy via nginx.com/policies",
			annotation: PoliciesAnnotationPlus,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mergeableIngresses := createMergeableCafeIngress()
			mergeableIngresses.Minions[0].Ingress.Annotations[test.annotation] = "missing-policy"
			mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{}

			result, resultWarnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
				mergeableIngs: mergeableIngresses,
				BaseCfgParams: NewDefaultConfigParams(context.Background(), true),
				isPlus:        true,
				staticParams:  &StaticConfigParams{},
			})

			expectedPoliciesErrorReturn := &version2.Return{Code: 500}
			var found bool
			for _, loc := range result.Servers[0].Locations {
				if loc.MinionIngress != nil && loc.MinionIngress.Name == "cafe-ingress-coffee-minion" {
					found = true
					if diff := cmp.Diff(expectedPoliciesErrorReturn, loc.PoliciesErrorReturn); diff != "" {
						t.Errorf("Location.PoliciesErrorReturn mismatch for coffee minion (-want +got):\n%s", diff)
					}
				}
			}
			if !found {
				t.Fatal("coffee minion location not found in result")
			}

			const expectedWarning = "Policy default/missing-policy is missing or invalid"
			if !warningsContain(resultWarnings, expectedWarning) {
				t.Fatalf("expected warning containing %q, got %v", expectedWarning, resultWarnings)
			}
		})
	}
}

func TestGenerateNginxCfgForMergeableIngressesWithUseClusterIP(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/use-cluster-ip"] = "true"

	isPlus := false

	expected := createExpectedConfigForMergeableCafeIngressWithUseClusterIP()
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func createExpectedConfigForMergeableCafeIngressWithUseClusterIP() version1.IngressNginxConfig {
	upstreamZoneSize := "256k"
	coffeeUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.1:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	teaUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.2:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	expected := version1.IngressNginxConfig{
		Upstreams: []version1.Upstream{
			coffeeUpstream,
			teaUpstream,
		},
		Servers: []version1.Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []version1.Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &version1.Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"kubernetes.io/ingress.class":      "nginx",
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/use-cluster-ip":         "true",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
						ProxyPass:    "http://default-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &version1.Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"kubernetes.io/ingress.class":      "nginx",
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
						ProxyPass:    "http://default-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HTTPRedirectCode:  301,
				HealthChecks:      make(map[string]version1.HealthCheck),
			},
		},
		Ingress: version1.Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	return expected
}

func createExpectedConfigForCafeIngressWithUseClusterIPNamedPorts() version1.IngressNginxConfig {
	upstreamZoneSize := "256k"

	coffeeUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-cafe.example.com-coffee-svc-custom-port-name",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.109.204.250:3000",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}

	teaUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.109.204.250:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}

	expected := version1.IngressNginxConfig{
		Upstreams: []version1.Upstream{
			coffeeUpstream,
			teaUpstream,
		},
		Servers: []version1.Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []version1.Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						ProxySSLName:        "coffee-svc.default.svc",
						ProxyPass:           "http://default-cafe-ingress-cafe.example.com-coffee-svc-custom-port-name",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						ProxySSLName:        "tea-svc.default.svc",
						ProxyPass:           "http://default-cafe-ingress-cafe.example.com-tea-svc-80",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HTTPRedirectCode:  301,
				HealthChecks:      make(map[string]version1.HealthCheck),
			},
		},
		Ingress: version1.Ingress{
			Name:      "cafe-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
				"nginx.org/use-cluster-ip":    "true",
			},
		},
	}
	return expected
}

func createExpectedConfigForCafeIngressWithUseClusterIP() version1.IngressNginxConfig {
	upstreamZoneSize := "256k"

	coffeeUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-cafe.example.com-coffee-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.1:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}

	teaUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.2:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}

	expected := version1.IngressNginxConfig{
		Upstreams: []version1.Upstream{
			coffeeUpstream,
			teaUpstream,
		},
		Servers: []version1.Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []version1.Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						ProxySSLName:        "coffee-svc.default.svc",
						ProxyPass:           "http://default-cafe-ingress-cafe.example.com-coffee-svc-80",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						ProxySSLName:        "tea-svc.default.svc",
						ProxyPass:           "http://default-cafe-ingress-cafe.example.com-tea-svc-80",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HTTPRedirectCode:  301,
				HealthChecks:      make(map[string]version1.HealthCheck),
			},
		},
		Ingress: version1.Ingress{
			Name:      "cafe-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
				"nginx.org/use-cluster-ip":    "true",
			},
		},
	}
	return expected
}

func TestGenerateNginxCfgWithUseClusterIP(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/use-cluster-ip"] = "true"
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressWithUseClusterIP()

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               false,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgWithUseClusterIPWithNamedPorts(t *testing.T) {
	t.Parallel()
	customPort := 3000
	customPortName := "custom-port-name"
	clusterIP := "10.109.204.250"
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/use-cluster-ip"] = "true"
	cafeIngressEx.Endpoints["coffee-svccustom-port-name"] = make([]string, 1)

	// coffee will use a named port
	cafeIngressEx.Endpoints["coffee-svccustom-port-name"][0] = fmt.Sprintf("%s:%d", clusterIP, customPort)

	// tea will not use a named port
	cafeIngressEx.Endpoints["tea-svc80"][0] = fmt.Sprintf("%s:%d", clusterIP, 80)

	// unset the port number and set the port name for the /coffee path
	cafeIngressEx.Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 0
	cafeIngressEx.Ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Name = customPortName

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressWithUseClusterIPNamedPorts()

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               false,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForLimitReq(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-rate"] = "200r/s"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-key"] = "${request_uri}"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-burst"] = "100"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-no-delay"] = "true"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-delay"] = "80"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-reject-code"] = "503"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-dry-run"] = "true"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-log-level"] = "info"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-zone-size"] = "11m"

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expectedZones := []version1.LimitReqZone{
		{
			Name: "default/cafe-ingress",
			Key:  "${request_uri}",
			Size: "11m",
			Rate: "200r/s",
		},
	}

	expectedReqs := &version1.LimitReq{
		Zone:       "default/cafe-ingress",
		Burst:      100,
		Delay:      80,
		NoDelay:    true,
		DryRun:     true,
		LogLevel:   "info",
		RejectCode: 503,
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		ingEx:         &cafeIngressEx,
		BaseCfgParams: configParams,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
	})

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}

	for _, server := range result.Servers {
		for _, location := range server.Locations {
			if !reflect.DeepEqual(location.LimitReq, expectedReqs) {
				t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
			}
		}
	}

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForLimitReqDefaults(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-rate"] = "200r/s"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-burst"] = "100"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-delay"] = "80"

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expectedZones := []version1.LimitReqZone{
		{
			Name: "default/cafe-ingress",
			Key:  "${binary_remote_addr}",
			Size: "10m",
			Rate: "200r/s",
		},
	}

	expectedReqs := &version1.LimitReq{
		Zone:       "default/cafe-ingress",
		Burst:      100,
		Delay:      80,
		LogLevel:   "error",
		RejectCode: 429,
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		ingEx:         &cafeIngressEx,
		BaseCfgParams: configParams,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
	})

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}

	for _, server := range result.Servers {
		for _, location := range server.Locations {
			if !reflect.DeepEqual(location.LimitReq, expectedReqs) {
				t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
			}
		}
	}

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForLimitReqZoneSync(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-rate"] = "200r/s"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-key"] = "${request_uri}"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-zone-size"] = "11m"

	cafeIngressEx.ZoneSync = true
	isPlus := true

	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expectedZones := []version1.LimitReqZone{
		{
			Name: "default/cafe-ingress_sync",
			Key:  "${request_uri}",
			Size: "11m",
			Rate: "200r/s",
			Sync: true,
		},
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		ingEx:         &cafeIngressEx,
		BaseCfgParams: configParams,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
	})

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesForLimitReq(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-rate"] = "200r/s"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-key"] = "${request_uri}"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-burst"] = "100"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-delay"] = "80"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-no-delay"] = "true"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-reject-code"] = "429"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-zone-size"] = "11m"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-dry-run"] = "true"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-log-level"] = "info"

	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-rate"] = "400r/s"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-burst"] = "200"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-delay"] = "160"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-reject-code"] = "503"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-zone-size"] = "12m"

	expectedZones := []version1.LimitReqZone{
		{
			Name: "default/cafe-ingress-coffee-minion",
			Key:  "${request_uri}",
			Size: "11m",
			Rate: "200r/s",
		},
		{
			Name: "default/cafe-ingress-tea-minion",
			Key:  "${binary_remote_addr}",
			Size: "12m",
			Rate: "400r/s",
		},
	}

	expectedReqs := map[string]*version1.LimitReq{
		"cafe-ingress-coffee-minion": {
			Zone:       "default/cafe-ingress-coffee-minion",
			Burst:      100,
			Delay:      80,
			LogLevel:   "info",
			RejectCode: 429,
			NoDelay:    true,
			DryRun:     true,
		},
		"cafe-ingress-tea-minion": {
			Zone:       "default/cafe-ingress-tea-minion",
			Burst:      200,
			Delay:      160,
			LogLevel:   "error",
			RejectCode: 503,
		},
	}

	isPlus := false

	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs: mergeableIngresses,
		BaseCfgParams: configParams,
		isPlus:        isPlus,
		staticParams:  &StaticConfigParams{},
	})

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}

	for _, server := range result.Servers {
		for _, location := range server.Locations {
			expectedLimitReq := expectedReqs[location.MinionIngress.Name]
			if !reflect.DeepEqual(location.LimitReq, expectedLimitReq) {
				t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", location.LimitReq, expectedLimitReq)
			}
		}
	}

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForLimitReqWithScaling(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-rate"] = "200r/s"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-key"] = "${request_uri}"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-burst"] = "100"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-no-delay"] = "true"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-delay"] = "80"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-reject-code"] = "503"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-dry-run"] = "true"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-log-level"] = "info"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-zone-size"] = "11m"
	cafeIngressEx.Ingress.Annotations["nginx.org/limit-req-scale"] = "true"

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expectedZones := []version1.LimitReqZone{
		{
			Name: "default/cafe-ingress",
			Key:  "${request_uri}",
			Size: "11m",
			Rate: "50r/s",
		},
	}

	expectedReqs := &version1.LimitReq{
		Zone:       "default/cafe-ingress",
		Burst:      100,
		Delay:      80,
		NoDelay:    true,
		DryRun:     true,
		LogLevel:   "info",
		RejectCode: 503,
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		ingEx:                     &cafeIngressEx,
		BaseCfgParams:             configParams,
		staticParams:              &StaticConfigParams{},
		isPlus:                    isPlus,
		ingressControllerReplicas: 4,
	})

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}

	for _, server := range result.Servers {
		for _, location := range server.Locations {
			if !reflect.DeepEqual(location.LimitReq, expectedReqs) {
				t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", location.LimitReq, expectedReqs)
			}
		}
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesForLimitReqWithScaling(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-rate"] = "200r/s"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-key"] = "${request_uri}"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-burst"] = "100"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-delay"] = "80"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-no-delay"] = "true"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-reject-code"] = "429"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-zone-size"] = "11m"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-dry-run"] = "true"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-log-level"] = "info"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/limit-req-scale"] = "true"

	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-rate"] = "400r/s"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-burst"] = "200"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-delay"] = "160"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-reject-code"] = "503"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-zone-size"] = "12m"
	mergeableIngresses.Minions[1].Ingress.Annotations["nginx.org/limit-req-scale"] = "true"

	expectedZones := []version1.LimitReqZone{
		{
			Name: "default/cafe-ingress-coffee-minion",
			Key:  "${request_uri}",
			Size: "11m",
			Rate: "100r/s",
		},
		{
			Name: "default/cafe-ingress-tea-minion",
			Key:  "${binary_remote_addr}",
			Size: "12m",
			Rate: "200r/s",
		},
	}

	expectedReqs := map[string]*version1.LimitReq{
		"cafe-ingress-coffee-minion": {
			Zone:       "default/cafe-ingress-coffee-minion",
			Burst:      100,
			Delay:      80,
			LogLevel:   "info",
			RejectCode: 429,
			NoDelay:    true,
			DryRun:     true,
		},
		"cafe-ingress-tea-minion": {
			Zone:       "default/cafe-ingress-tea-minion",
			Burst:      200,
			Delay:      160,
			LogLevel:   "error",
			RejectCode: 503,
		},
	}

	isPlus := false

	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:             mergeableIngresses,
		BaseCfgParams:             configParams,
		isPlus:                    isPlus,
		staticParams:              &StaticConfigParams{},
		ingressControllerReplicas: 2,
	})

	if !reflect.DeepEqual(result.LimitReqZones, expectedZones) {
		t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", result.LimitReqZones, expectedZones)
	}

	for _, server := range result.Servers {
		for _, location := range server.Locations {
			expectedLimitReq := expectedReqs[location.MinionIngress.Name]
			if !reflect.DeepEqual(location.LimitReq, expectedLimitReq) {
				t.Errorf("generateNginxCfg returned \n%v,  but expected \n%v", location.LimitReq, expectedLimitReq)
			}
		}
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg returned warnings: %v", warnings)
	}
}

func createMergeableCafeIngress() *MergeableIngresses {
	master := networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
		Spec: networking.IngressSpec{
			TLS: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			Rules: []networking.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{ // HTTP must not be nil for Master
							Paths: []networking.HTTPIngressPath{},
						},
					},
				},
			},
		},
	}

	coffeeMinion := networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe-ingress-coffee-minion",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "minion",
			},
		},
		Spec: networking.IngressSpec{
			Rules: []networking.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path: "/coffee",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networking.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	teaMinion := networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe-ingress-tea-minion",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "minion",
			},
		},
		Spec: networking.IngressSpec{
			Rules: []networking.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path: "/tea",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "tea-svc",
											Port: networking.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	mergeableIngresses := &MergeableIngresses{
		Master: &IngressEx{
			Ingress: &master,
			Endpoints: map[string][]string{
				"coffee-svc80": {"10.0.0.1:80"},
				"tea-svc80":    {"10.0.0.2:80"},
			},
			ValidHosts: map[string]bool{
				"cafe.example.com": true,
			},
			SecretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &v1.Secret{
						Type: v1.SecretTypeTLS,
					},
					Path:  "/etc/nginx/secrets/default-cafe-secret",
					Error: nil,
				},
			},
		},
		Minions: []*IngressEx{
			{
				Ingress: &coffeeMinion,
				Endpoints: map[string][]string{
					"coffee-svc80": {"10.0.0.1:80"},
				},
				ValidHosts: map[string]bool{
					"cafe.example.com": true,
				},
				ValidMinionPaths: map[string]bool{
					"/coffee": true,
				},
				SecretRefs: map[string]*secrets.SecretReference{},
			},
			{
				Ingress: &teaMinion,
				Endpoints: map[string][]string{
					"tea-svc80": {"10.0.0.2:80"},
				},
				ValidHosts: map[string]bool{
					"cafe.example.com": true,
				},
				ValidMinionPaths: map[string]bool{
					"/tea": true,
				},
				SecretRefs: map[string]*secrets.SecretReference{},
			},
		},
	}

	return mergeableIngresses
}

func createExpectedConfigForMergeableCafeIngress(isPlus bool) version1.IngressNginxConfig {
	upstreamZoneSize := "256k"
	if isPlus {
		upstreamZoneSize = "512k"
	}

	coffeeUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.1:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	if isPlus {
		coffeeUpstream.UpstreamLabels = version1.UpstreamLabels{
			Service:           "coffee-svc",
			ResourceType:      "ingress",
			ResourceName:      "cafe-ingress-coffee-minion",
			ResourceNamespace: "default",
		}
	}

	teaUpstream := version1.Upstream{
		Name:             "default-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: upstreamZoneSize,
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.2:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	if isPlus {
		teaUpstream.UpstreamLabels = version1.UpstreamLabels{
			Service:           "tea-svc",
			ResourceType:      "ingress",
			ResourceName:      "cafe-ingress-tea-minion",
			ResourceNamespace: "default",
		}
	}

	expected := version1.IngressNginxConfig{
		Upstreams: []version1.Upstream{
			coffeeUpstream,
			teaUpstream,
		},
		Servers: []version1.Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []version1.Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &version1.Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"kubernetes.io/ingress.class":      "nginx",
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
						ProxyPass:    "http://default-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &version1.Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"kubernetes.io/ingress.class":      "nginx",
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
						ProxyPass:    "http://default-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HTTPRedirectCode:  301,
				HealthChecks:      make(map[string]version1.HealthCheck),
			},
		},
		Ingress: version1.Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	return expected
}

func createExpectedConfigForCrossNamespaceMergeableCafeIngress() version1.IngressNginxConfig {
	coffeeUpstream := version1.Upstream{
		Name:             "coffee-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: "256k",
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.1:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	teaUpstream := version1.Upstream{
		Name:             "tea-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: "256k",
		UpstreamServers: []version1.UpstreamServer{
			{
				Address:     "10.0.0.2:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
	}
	expected := version1.IngressNginxConfig{
		Upstreams: []version1.Upstream{
			coffeeUpstream,
			teaUpstream,
		},
		Servers: []version1.Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []version1.Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &version1.Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "coffee",
							Annotations: map[string]string{
								"kubernetes.io/ingress.class":      "nginx",
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "coffee-svc.coffee.svc",
						ProxyPass:    "http://coffee-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstream,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &version1.Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "tea",
							Annotations: map[string]string{
								"kubernetes.io/ingress.class":      "nginx",
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.tea.svc",
						ProxyPass:    "http://tea-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HTTPRedirectCode:  301,
				HealthChecks:      make(map[string]version1.HealthCheck),
			},
		},
		Ingress: version1.Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":      "nginx",
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	return expected
}

func TestGenerateNginxCfgForSpiffe(t *testing.T) {
	t.Parallel()
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.SpiffeClientCerts = true
	for i := range expected.Servers[0].Locations {
		expected.Servers[0].Locations[i].SSL = true
		expected.Servers[0].Locations[i].ProxyPass = strings.Replace(expected.Servers[0].Locations[i].ProxyPass, "http://", "https://", 1)
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{NginxServiceMesh: true},
		ingEx:                new(createCafeIngressEx()),
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               false,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForInternalRoute(t *testing.T) {
	t.Parallel()
	internalRouteAnnotation := "nsm.nginx.com/internal-route"
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations[internalRouteAnnotation] = "true"
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].SpiffeCerts = true
	expected.Ingress.Annotations[internalRouteAnnotation] = "true"

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{NginxServiceMesh: true, EnableInternalRoutes: true},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               false,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForSSLCiphers(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/ssl-ciphers"] = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
	cafeIngressEx.Ingress.Annotations["nginx.org/ssl-prefer-server-ciphers"] = "true"
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].SSLCiphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
	expected.Servers[0].SSLPreferServerCiphers = true
	expected.Ingress.Annotations["nginx.org/ssl-ciphers"] = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
	expected.Ingress.Annotations["nginx.org/ssl-prefer-server-ciphers"] = "true"

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{},
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesSSLCiphers(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/ssl-ciphers"] = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/ssl-prefer-server-ciphers"] = "true"

	// Add SSL cipher annotations to minions - they should be ignored
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/ssl-ciphers"] = "INVALID_CIPHER"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/ssl-prefer-server-ciphers"] = "false"

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].SSLCiphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
	expected.Servers[0].SSLPreferServerCiphers = true
	expected.Ingress.Annotations["nginx.org/ssl-ciphers"] = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
	expected.Ingress.Annotations["nginx.org/ssl-prefer-server-ciphers"] = "true"

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         &StaticConfigParams{},
		isWildcardEnabled:    false,
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestIsSSLEnabled(t *testing.T) {
	t.Parallel()
	type testCase struct {
		IsSSLService,
		SpiffeServerCerts,
		NginxServiceMesh,
		Expected bool
	}
	testCases := []testCase{
		{
			IsSSLService:      false,
			SpiffeServerCerts: false,
			NginxServiceMesh:  false,
			Expected:          false,
		},
		{
			IsSSLService:      false,
			SpiffeServerCerts: true,
			NginxServiceMesh:  true,
			Expected:          false,
		},
		{
			IsSSLService:      false,
			SpiffeServerCerts: false,
			NginxServiceMesh:  true,
			Expected:          true,
		},
		{
			IsSSLService:      false,
			SpiffeServerCerts: true,
			NginxServiceMesh:  false,
			Expected:          false,
		},
		{
			IsSSLService:      true,
			SpiffeServerCerts: true,
			NginxServiceMesh:  true,
			Expected:          true,
		},
		{
			IsSSLService:      true,
			SpiffeServerCerts: false,
			NginxServiceMesh:  true,
			Expected:          true,
		},
		{
			IsSSLService:      true,
			SpiffeServerCerts: true,
			NginxServiceMesh:  false,
			Expected:          true,
		},
		{
			IsSSLService:      true,
			SpiffeServerCerts: false,
			NginxServiceMesh:  false,
			Expected:          true,
		},
	}
	for i, tc := range testCases {
		actual := isSSLEnabled(tc.IsSSLService, ConfigParams{SpiffeServerCerts: tc.SpiffeServerCerts}, &StaticConfigParams{NginxServiceMesh: tc.NginxServiceMesh})
		if actual != tc.Expected {
			t.Errorf("isSSLEnabled returned %v but expected %v for the case %v", actual, tc.Expected, i)
		}
	}
}

func TestAddSSLConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host              string
		tls               []networking.IngressTLS
		secretRefs        map[string]*secrets.SecretReference
		isWildcardEnabled bool
		expectedServer    version1.Server
		expectedWarnings  Warnings
		msg               string
	}{
		{
			host: "some.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &v1.Secret{
						Type: v1.SecretTypeTLS,
					},
					Path: "/etc/nginx/secrets/default-cafe-secret",
				},
			},
			isWildcardEnabled: false,
			expectedServer:    version1.Server{},
			expectedWarnings:  Warnings{},
			msg:               "TLS termination for different host",
		},
		{
			host: "cafe.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &v1.Secret{
						Type: v1.SecretTypeTLS,
					},
					Path: "/etc/nginx/secrets/default-cafe-secret",
				},
			},
			isWildcardEnabled: false,
			expectedServer: version1.Server{
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
			},
			expectedWarnings: Warnings{},
			msg:              "TLS termination",
		},
		{
			host: "cafe.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &v1.Secret{
						Type: v1.SecretTypeTLS,
					},
					Error: errors.New("invalid secret"),
				},
			},
			isWildcardEnabled: false,
			expectedServer: version1.Server{
				SSL:                true,
				SSLRejectHandshake: true,
			},
			expectedWarnings: Warnings{
				nil: {
					"TLS secret cafe-secret is invalid: invalid secret",
				},
			},
			msg: "invalid secret",
		},
		{
			host: "cafe.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeCA,
					},
					Path: "/etc/nginx/secrets/default-cafe-secret",
				},
			},
			isWildcardEnabled: false,
			expectedServer: version1.Server{
				SSL:                true,
				SSLRejectHandshake: true,
			},
			expectedWarnings: Warnings{
				nil: {
					"TLS secret cafe-secret is of a wrong type 'nginx.org/ca', must be 'kubernetes.io/tls'",
				},
			},
			msg: "secret of wrong type without error",
		},
		{
			host: "cafe.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "cafe-secret",
				},
			},
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-secret": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeCA,
					},
					Path:  "",
					Error: errors.New("CA secret must have the data field ca.crt"),
				},
			},
			isWildcardEnabled: false,
			expectedServer: version1.Server{
				SSL:                true,
				SSLRejectHandshake: true,
			},
			expectedWarnings: Warnings{
				nil: {
					"TLS secret cafe-secret is of a wrong type 'nginx.org/ca', must be 'kubernetes.io/tls'",
				},
			},
			msg: "secret of wrong type with error",
		},
		{
			host: "cafe.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "",
				},
			},
			isWildcardEnabled: true,
			expectedServer: version1.Server{
				SSL:               true,
				SSLCertificate:    pemFileNameForWildcardTLSSecret,
				SSLCertificateKey: pemFileNameForWildcardTLSSecret,
			},
			expectedWarnings: Warnings{},
			msg:              "no secret name with wildcard enabled",
		},
		{
			host: "cafe.example.com",
			tls: []networking.IngressTLS{
				{
					Hosts:      []string{"cafe.example.com"},
					SecretName: "",
				},
			},
			isWildcardEnabled: false,
			expectedServer: version1.Server{
				SSL:                true,
				SSLRejectHandshake: true,
			},
			expectedWarnings: Warnings{
				nil: {
					"TLS termination for host 'cafe.example.com' requires specifying a TLS secret or configuring a global wildcard TLS secret",
				},
			},
			msg: "no secret name with wildcard disabled",
		},
	}

	for _, test := range tests {
		var server version1.Server

		// it is ok to use nil as the owner
		warnings := addSSLConfig(&server, nil, test.host, test.tls, test.secretRefs, test.isWildcardEnabled)

		if diff := cmp.Diff(test.expectedServer, server); diff != "" {
			t.Errorf("addSSLConfig() '%s' mismatch (-want +got):\n%s", test.msg, diff)
		}
		if !reflect.DeepEqual(test.expectedWarnings, warnings) {
			t.Errorf("addSSLConfig() returned %v but expected %v for the case of %s", warnings, test.expectedWarnings, test.msg)
		}
	}
}

func newEgressMTLSPolicy(name string, tlsSecret string, trustedCertSecret string, sslName string, verifyServer bool, verifyDepth int) *conf_v1.Policy {
	return &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			EgressMTLS: &conf_v1.EgressMTLS{
				TLSSecret:         tlsSecret,
				TrustedCertSecret: trustedCertSecret,
				VerifyServer:      verifyServer,
				VerifyDepth:       &verifyDepth,
				ServerName:        true,
				SSLName:           sslName,
			},
		},
	}
}

func addEgressMTLSSecretRefs(secretRefs map[string]*secrets.SecretReference) {
	secretRefs["default/egress-mtls-secret"] = &secrets.SecretReference{
		Secret: &v1.Secret{Type: v1.SecretTypeTLS},
		Path:   "/etc/nginx/secrets/default-egress-mtls-secret",
	}
	secretRefs["default/egress-trusted-ca-secret"] = &secrets.SecretReference{
		Secret: &v1.Secret{Type: secrets.SecretTypeCA},
		Path:   "/etc/nginx/secrets/default-egress-trusted-ca-secret",
	}
	secretRefs["default/egress-mtls-secret-alt"] = &secrets.SecretReference{
		Secret: &v1.Secret{Type: v1.SecretTypeTLS},
		Path:   "/etc/nginx/secrets/default-egress-mtls-secret-alt",
	}
	secretRefs["default/egress-trusted-ca-secret-alt"] = &secrets.SecretReference{
		Secret: &v1.Secret{Type: secrets.SecretTypeCA},
		Path:   "/etc/nginx/secrets/default-egress-trusted-ca-secret-alt",
	}
}

func expectedEgressMTLSConfig(certificate string, trustedCert string, sslName string, verifyServer bool, verifyDepth int) *version2.EgressMTLS {
	return &version2.EgressMTLS{
		Certificate:    certificate,
		CertificateKey: certificate,
		TrustedCert:    trustedCert,
		Ciphers:        "DEFAULT",
		Protocols:      "TLSv1 TLSv1.1 TLSv1.2",
		VerifyServer:   verifyServer,
		VerifyDepth:    verifyDepth,
		SessionReuse:   true,
		ServerName:     true,
		SSLName:        sslName,
	}
}

func TestGenerateJWTConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secretRefs               map[string]*secrets.SecretReference
		cfgParams                *ConfigParams
		redirectLocationName     string
		expectedJWTAuth          *version1.JWTAuth
		expectedRedirectLocation *version1.JWTRedirectLocation
		expectedWarnings         Warnings
		msg                      string
	}{
		{
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-jwk": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeJWK,
					},
					Path: "/etc/nginx/secrets/default-cafe-jwk",
				},
			},
			cfgParams: &ConfigParams{
				JWTKey:   "cafe-jwk",
				JWTRealm: "cafe",
				JWTToken: "$http_token",
			},
			redirectLocationName: "@loc",
			expectedJWTAuth: &version1.JWTAuth{
				Key:   "/etc/nginx/secrets/default-cafe-jwk",
				Realm: "cafe",
				Token: "$http_token",
			},
			expectedRedirectLocation: nil,
			expectedWarnings:         Warnings{},
			msg:                      "normal case",
		},
		{
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-jwk": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeJWK,
					},
					Path: "/etc/nginx/secrets/default-cafe-jwk",
				},
			},
			cfgParams: &ConfigParams{
				JWTKey:      "cafe-jwk",
				JWTRealm:    "cafe",
				JWTToken:    "$http_token",
				JWTLoginURL: "http://cafe.example.com/login",
			},
			redirectLocationName: "@loc",
			expectedJWTAuth: &version1.JWTAuth{
				Key:                  "/etc/nginx/secrets/default-cafe-jwk",
				Realm:                "cafe",
				Token:                "$http_token",
				RedirectLocationName: "@loc",
			},
			expectedRedirectLocation: &version1.JWTRedirectLocation{
				Name:     "@loc",
				LoginURL: "http://cafe.example.com/login",
			},
			expectedWarnings: Warnings{},
			msg:              "normal case with login url",
		},
		{
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-jwk": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeJWK,
					},
					Path:  "/etc/nginx/secrets/default-cafe-jwk",
					Error: errors.New("invalid secret"),
				},
			},
			cfgParams: &ConfigParams{
				JWTKey:   "cafe-jwk",
				JWTRealm: "cafe",
				JWTToken: "$http_token",
			},
			redirectLocationName: "@loc",
			expectedJWTAuth: &version1.JWTAuth{
				Key:   "/etc/nginx/secrets/default-cafe-jwk",
				Realm: "cafe",
				Token: "$http_token",
			},
			expectedRedirectLocation: nil,
			expectedWarnings: Warnings{
				nil: {
					"JWK secret cafe-jwk is invalid: invalid secret",
				},
			},
			msg: "invalid secret",
		},
		{
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-jwk": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeCA,
					},
					Path: "/etc/nginx/secrets/default-cafe-jwk",
				},
			},
			cfgParams: &ConfigParams{
				JWTKey:   "cafe-jwk",
				JWTRealm: "cafe",
				JWTToken: "$http_token",
			},
			redirectLocationName: "@loc",
			expectedJWTAuth: &version1.JWTAuth{
				Key:   "/etc/nginx/secrets/default-cafe-jwk",
				Realm: "cafe",
				Token: "$http_token",
			},
			expectedRedirectLocation: nil,
			expectedWarnings: Warnings{
				nil: {
					"JWK secret cafe-jwk is of a wrong type 'nginx.org/ca', must be 'nginx.org/jwk'",
				},
			},
			msg: "secret of wrong type without error",
		},
		{
			secretRefs: map[string]*secrets.SecretReference{
				"cafe-jwk": {
					Secret: &v1.Secret{
						Type: secrets.SecretTypeCA,
					},
					Path:  "",
					Error: errors.New("CA secret must have the data field ca.crt"),
				},
			},
			cfgParams: &ConfigParams{
				JWTKey:   "cafe-jwk",
				JWTRealm: "cafe",
				JWTToken: "$http_token",
			},
			redirectLocationName: "@loc",
			expectedJWTAuth: &version1.JWTAuth{
				Key:   "",
				Realm: "cafe",
				Token: "$http_token",
			},
			expectedRedirectLocation: nil,
			expectedWarnings: Warnings{
				nil: {
					"JWK secret cafe-jwk is of a wrong type 'nginx.org/ca', must be 'nginx.org/jwk'",
				},
			},
			msg: "secret of wrong type with error",
		},
	}

	for _, test := range tests {
		jwtAuth, redirectLocation, warnings := generateJWTConfig(nil, test.secretRefs, test.cfgParams, test.redirectLocationName)

		if diff := cmp.Diff(test.expectedJWTAuth, jwtAuth); diff != "" {
			t.Errorf("generateJWTConfig() '%s' mismatch for jwtAuth (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedRedirectLocation, redirectLocation); diff != "" {
			t.Errorf("generateJWTConfig() '%s' mismatch for redirectLocation (-want +got):\n%s", test.msg, diff)
		}
		if !reflect.DeepEqual(test.expectedWarnings, warnings) {
			t.Errorf("generateJWTConfig() returned %v but expected %v for the case of %s", warnings, test.expectedWarnings, test.msg)
		}
	}
}

func TestGenerateNginxCfgForAppProtect(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["appprotect.f5.com/app-protect-enable"] = "True"
	cafeIngressEx.Ingress.Annotations["appprotect.f5.com/app-protect-security-log-enable"] = "True"
	cafeIngressEx.AppProtectPolicy = &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "dataguard-alarm",
			},
		},
	}
	cafeIngressEx.AppProtectLogs = []AppProtectLog{
		{
			LogConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"namespace": "default",
						"name":      "logconf",
					},
				},
			},
		},
	}

	isPlus := true

	configParams := NewDefaultConfigParams(context.Background(), isPlus)
	apResources := &AppProtectResources{
		AppProtectPolicy:   "/etc/nginx/waf/nac-policies/default_dataguard-alarm",
		AppProtectLogconfs: []string{"/etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514"},
	}
	staticCfgParams := &StaticConfigParams{
		MainAppProtectLoadModule: true,
	}

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].AppProtectEnable = "on"
	expected.Servers[0].AppProtectPolicy = "/etc/nginx/waf/nac-policies/default_dataguard-alarm"
	expected.Servers[0].AppProtectLogConfs = []string{"/etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514"}
	expected.Servers[0].AppProtectLogEnable = "on"
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         staticCfgParams,
		ingEx:                &cafeIngressEx,
		apResources:          apResources,
		dosResource:          nil,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesForAppProtect(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Master.Ingress.Annotations["appprotect.f5.com/app-protect-enable"] = "True"
	mergeableIngresses.Master.Ingress.Annotations["appprotect.f5.com/app-protect-security-log-enable"] = "True"
	mergeableIngresses.Master.AppProtectPolicy = &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "dataguard-alarm",
			},
		},
	}
	mergeableIngresses.Master.AppProtectLogs = []AppProtectLog{
		{
			LogConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"namespace": "default",
						"name":      "logconf",
					},
				},
			},
		},
	}

	isPlus := true
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	apResources := &AppProtectResources{
		AppProtectPolicy:   "/etc/nginx/waf/nac-policies/default_dataguard-alarm",
		AppProtectLogconfs: []string{"/etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514"},
	}
	staticCfgParams := &StaticConfigParams{
		MainAppProtectLoadModule: true,
	}

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].AppProtectEnable = "on"
	expected.Servers[0].AppProtectPolicy = "/etc/nginx/waf/nac-policies/default_dataguard-alarm"
	expected.Servers[0].AppProtectLogConfs = []string{"/etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514"}
	expected.Servers[0].AppProtectLogEnable = "on"
	expected.Ingress.Annotations = mergeableIngresses.Master.Ingress.Annotations

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          apResources,
		dosResource:          nil,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         staticCfgParams,
		isWildcardEnabled:    false,
	})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForAppProtectDos(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["appprotectdos.f5.com/app-protect-dos-resource"] = "dos-policy"

	isPlus := true
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	dosResource := &appProtectDosResource{
		AppProtectDosEnable:        "on",
		AppProtectDosName:          "dos.example.com",
		AppProtectDosMonitorURI:    "monitor-name",
		AppProtectDosAccessLogDst:  "access-log-dest",
		AppProtectDosPolicyFile:    "/etc/nginx/dos/policies/default_policy",
		AppProtectDosLogEnable:     true,
		AppProtectDosLogConfFile:   "/etc/nginx/dos/logconfs/default_logconf syslog:server=127.0.0.1:514",
		AppProtectDosAllowListPath: "/etc/nginx/dos/allowlist/default_dos",
	}
	staticCfgParams := &StaticConfigParams{
		MainAppProtectDosLoadModule: true,
	}

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].AppProtectDosEnable = "on"
	expected.Servers[0].AppProtectDosPolicyFile = "/etc/nginx/dos/policies/default_policy"
	expected.Servers[0].AppProtectDosLogConfFile = "/etc/nginx/dos/logconfs/default_logconf syslog:server=127.0.0.1:514"
	expected.Servers[0].AppProtectDosAllowListPath = "/etc/nginx/dos/allowlist/default_dos"
	expected.Servers[0].AppProtectDosLogEnable = true
	expected.Servers[0].AppProtectDosName = "dos.example.com"
	expected.Servers[0].AppProtectDosMonitorURI = "monitor-name"
	expected.Servers[0].AppProtectDosAccessLogDst = "access-log-dest"
	expected.Ingress.Annotations = cafeIngressEx.Ingress.Annotations

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         staticCfgParams,
		ingEx:                &cafeIngressEx,
		apResources:          nil,
		dosResource:          dosResource,
		isMinion:             false,
		isPlus:               isPlus,
		BaseCfgParams:        configParams,
		isResolverConfigured: false,
		isWildcardEnabled:    false,
	})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfg() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesForAppProtectDos(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()
	mergeableIngresses.Master.Ingress.Annotations["appprotectdos.f5.com/app-protect-dos-enable"] = "True"
	mergeableIngresses.Master.DosEx = &DosEx{
		DosPolicy: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "default",
					"name":      "policy",
				},
			},
		},
		DosLogConf: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "default",
					"name":      "logconf",
				},
			},
		},
	}

	isPlus := true
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	dosResource := &appProtectDosResource{
		AppProtectDosEnable:        "on",
		AppProtectDosName:          "dos.example.com",
		AppProtectDosMonitorURI:    "monitor-name",
		AppProtectDosAccessLogDst:  "access-log-dest",
		AppProtectDosPolicyFile:    "/etc/nginx/dos/policies/default_policy",
		AppProtectDosLogEnable:     true,
		AppProtectDosLogConfFile:   "/etc/nginx/dos/logconfs/default_logconf syslog:server=127.0.0.1:514",
		AppProtectDosAllowListPath: "/etc/nginx/dos/allowlist/default_dos",
	}
	staticCfgParams := &StaticConfigParams{
		MainAppProtectDosLoadModule: true,
	}

	expected := createExpectedConfigForMergeableCafeIngress(isPlus)
	expected.Servers[0].AppProtectDosEnable = "on"
	expected.Servers[0].AppProtectDosPolicyFile = "/etc/nginx/dos/policies/default_policy"
	expected.Servers[0].AppProtectDosLogConfFile = "/etc/nginx/dos/logconfs/default_logconf syslog:server=127.0.0.1:514"
	expected.Servers[0].AppProtectDosAllowListPath = "/etc/nginx/dos/allowlist/default_dos"
	expected.Servers[0].AppProtectDosLogEnable = true
	expected.Servers[0].AppProtectDosName = "dos.example.com"
	expected.Servers[0].AppProtectDosMonitorURI = "monitor-name"
	expected.Servers[0].AppProtectDosAccessLogDst = "access-log-dest"
	expected.Ingress.Annotations = mergeableIngresses.Master.Ingress.Annotations

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:        mergeableIngresses,
		apResources:          nil,
		dosResource:          dosResource,
		BaseCfgParams:        configParams,
		isPlus:               isPlus,
		isResolverConfigured: false,
		staticParams:         staticCfgParams,
		isWildcardEnabled:    false,
	})
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned unexpected result (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGetBackendPortAsString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		port     networking.ServiceBackendPort
		expected string
	}{
		{
			port: networking.ServiceBackendPort{
				Name: "test",
			},
			expected: "test",
		},
		{
			port: networking.ServiceBackendPort{
				Number: 80,
			},
			expected: "80",
		},
	}

	for _, test := range tests {
		result := GetBackendPortAsString(test.port)
		if result != test.expected {
			t.Errorf("GetBackendPortAsString(%+v) returned %q but expected %q", test.port, result, test.expected)
		}
	}
}

func TestScaleRatelimit(t *testing.T) {
	tests := []struct {
		input    string
		pods     int
		expected string
	}{
		{
			input:    "10r/s",
			pods:     0,
			expected: "10r/s",
		},
		{
			input:    "10r/s",
			pods:     1,
			expected: "10r/s",
		},
		{
			input:    "10r/s",
			pods:     2,
			expected: "5r/s",
		},
		{
			input:    "10r/s",
			pods:     3,
			expected: "3r/s",
		},
		{
			input:    "10r/s",
			pods:     10,
			expected: "1r/s",
		},
		{
			input:    "10r/s",
			pods:     20,
			expected: "30r/m",
		},
		{
			input:    "10r/m",
			pods:     0,
			expected: "10r/m",
		},
		{
			input:    "10r/m",
			pods:     1,
			expected: "10r/m",
		},
	}

	for _, testcase := range tests {
		scaled := scaleRatelimit(testcase.input, testcase.pods)
		if scaled != testcase.expected {
			t.Errorf("scaleRatelimit(%s,%d) returned %s but expected %s", testcase.input, testcase.pods, scaled, testcase.expected)
		}
	}
}

func TestGenerateNginxCfgForSSLRedirectDeprecationWarnings(t *testing.T) {
	t.Parallel()

	cafeIngressEx := createCafeIngressEx()

	tests := []struct {
		annotations      map[string]string
		expectedWarnings Warnings
		msg              string
	}{
		{
			annotations: map[string]string{
				"ingress.kubernetes.io/ssl-redirect": "true",
			},
			expectedWarnings: Warnings{
				cafeIngressEx.Ingress: {"The annotation 'ingress.kubernetes.io/ssl-redirect' is deprecated and will be removed. Please use 'nginx.org/ssl-redirect' instead."},
			},
			msg: "deprecated annotation generates warning",
		},
		{
			annotations: map[string]string{
				"nginx.org/ssl-redirect": "true",
			},
			expectedWarnings: Warnings{},
			msg:              "new annotation does not generate warning",
		},
		{
			annotations: map[string]string{
				"ingress.kubernetes.io/ssl-redirect": "true",
				"nginx.org/ssl-redirect":             "false",
			},
			expectedWarnings: Warnings{
				cafeIngressEx.Ingress: {"The annotation 'ingress.kubernetes.io/ssl-redirect' is deprecated and will be removed. Please use 'nginx.org/ssl-redirect' instead."},
			},
			msg: "both annotations present generates warning",
		},
		{
			annotations:      map[string]string{},
			expectedWarnings: Warnings{},
			msg:              "no ssl-redirect annotations",
		},
	}

	for _, test := range tests {
		cafeIngressEx.Ingress.Annotations = test.annotations
		configParams := NewDefaultConfigParams(context.Background(), false)

		_, warnings := generateNginxCfg(NginxCfgParams{
			staticParams:         &StaticConfigParams{},
			ingEx:                &cafeIngressEx,
			apResources:          nil,
			dosResource:          nil,
			isMinion:             false,
			isPlus:               false,
			BaseCfgParams:        configParams,
			isResolverConfigured: false,
			isWildcardEnabled:    false,
		})

		if !reflect.DeepEqual(test.expectedWarnings, warnings) {
			t.Errorf("generateNginxCfg() returned %v but expected %v for the case of %s", warnings, test.expectedWarnings, test.msg)
		}
	}
}

func TestCreateExternalAuthUpstream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		upsName   string
		endpoints []string
		expected  version1.Upstream
		warning   bool
	}{
		{
			name:      "no endpoints returns default server",
			upsName:   "ext_auth_default_my-auth",
			endpoints: nil,
			expected:  version1.NewUpstreamWithDefaultServer("ext_auth_default_my-auth"),
			warning:   true,
		},
		{
			name:      "empty endpoints returns default server",
			upsName:   "ext_auth_default_my-auth",
			endpoints: []string{},
			expected:  version1.NewUpstreamWithDefaultServer("ext_auth_default_my-auth"),
			warning:   true,
		},
		{
			name:      "single endpoint",
			upsName:   "ext_auth_default_my-auth",
			endpoints: []string{"10.0.0.1:8080"},
			expected: version1.Upstream{
				Name:             "ext_auth_default_my-auth",
				UpstreamZoneSize: "256k",
				UpstreamServers: []version1.UpstreamServer{
					{Address: "10.0.0.1:8080", MaxFails: 1, MaxConns: 0, FailTimeout: "10s"},
				},
			},
			warning: false,
		},
		{
			name:      "multiple endpoints sorted",
			upsName:   "ext_auth_default_my-auth",
			endpoints: []string{"10.0.0.3:8080", "10.0.0.1:8080", "10.0.0.2:8080"},
			expected: version1.Upstream{
				Name:             "ext_auth_default_my-auth",
				UpstreamZoneSize: "256k",
				UpstreamServers: []version1.UpstreamServer{
					{Address: "10.0.0.1:8080", MaxFails: 1, MaxConns: 0, FailTimeout: "10s"},
					{Address: "10.0.0.2:8080", MaxFails: 1, MaxConns: 0, FailTimeout: "10s"},
					{Address: "10.0.0.3:8080", MaxFails: 1, MaxConns: 0, FailTimeout: "10s"},
				},
			},
			warning: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, warning := createExternalAuthUpstream(test.upsName, test.endpoints)
			if diff := cmp.Diff(test.expected, result); diff != "" {
				t.Errorf("createExternalAuthUpstream() mismatch (-want +got):\n%s", diff)
			}
			if (warning != "") != test.warning {
				t.Errorf("createExternalAuthUpstream() warning mismatch (-want +got):\n%s", warning)
			}
		})
	}
}

func TestGenerateIngressExternalAuthLocation(t *testing.T) {
	t.Parallel()

	externalAuth := &version2.ExternalAuth{
		URI: &version2.AuthURI{
			Service:      "auth-svc",
			Upstream:     "ext_auth_default_my-auth",
			Path:         "/auth",
			InternalPath: "/_ext_auth_default_my-auth",
		},
		Snippets: "proxy_set_header X-Custom \"value\"",
	}

	cfg := &ConfigParams{
		Context:                  context.Background(),
		ProxyConnectTimeout:      "10s",
		ProxyReadTimeout:         "15s",
		ProxySendTimeout:         "15s",
		ProxyNextUpstreamTimeout: "5s",
	}

	result := generateIngressExternalAuthLocation(externalAuth, "ext_auth_default_my-auth", cfg)

	expected := version1.Location{
		Path:                     "/_ext_auth_default_my-auth",
		Internal:                 true,
		ProxyPass:                "http://ext_auth_default_my-auth/auth",
		ProxySetHeaders:          []version2.Header{{Name: "Content-Length", Value: "0"}, {Name: "X-Scheme", Value: "$scheme"}},
		ProxyConnectTimeout:      "10s",
		ProxyReadTimeout:         "15s",
		ProxySendTimeout:         "15s",
		ProxyPassRequestBody:     "off",
		ClientMaxBodySize:        "0",
		ProxyNextUpstream:        "error timeout",
		ProxyNextUpstreamTimeout: "5s",
		LocationSnippets:         []string{"proxy_set_header X-Custom \"value\""},
		ServiceName:              "auth-svc",
	}

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateIngressExternalAuthLocation() mismatch (-want +got):\n%s", diff)
	}
}

func TestGenerateIngressExternalAuthOAuth2Location(t *testing.T) {
	t.Parallel()

	externalAuth := &version2.ExternalAuth{
		URI: &version2.AuthURI{
			Service:      "auth-svc",
			Upstream:     "ext_auth_default_my-auth",
			Path:         "/oauth2/auth",
			InternalPath: "/_ext_auth_default_my-auth",
		},
		SigninURL:              "https://example.com/oauth2/start",
		SigninRedirectBasePath: "/oauth2",
		Snippets:               "proxy_set_header X-Custom \"value\"",
	}

	cfg := &ConfigParams{
		Context:                  context.Background(),
		ProxyConnectTimeout:      "10s",
		ProxyReadTimeout:         "15s",
		ProxySendTimeout:         "15s",
		ProxyNextUpstreamTimeout: "5s",
	}

	result := generateIngressExternalAuthOAuth2Location(externalAuth, "ext_auth_default_my-auth", cfg)

	expected := version1.Location{
		Path:                     "/oauth2",
		AuthRequestOff:           true,
		ProxyPass:                "http://ext_auth_default_my-auth",
		ProxySetHeaders:          []version2.Header{{Name: "X-Auth-Request-Redirect", Value: "$request_uri"}, {Name: "X-Scheme", Value: "$scheme"}},
		ProxyConnectTimeout:      "10s",
		ProxyReadTimeout:         "15s",
		ProxySendTimeout:         "15s",
		ProxyPassRequestHeaders:  "on",
		ClientMaxBodySize:        "0",
		ProxyNextUpstream:        "error timeout",
		ProxyNextUpstreamTimeout: "5s",
		LocationSnippets:         []string{"proxy_set_header X-Custom \"value\""},
		ServiceName:              "auth-svc",
	}

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateIngressExternalAuthOAuth2Location() mismatch (-want +got):\n%s", diff)
	}
}

func TestGetExternalAuthServicePort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		externalAuth    *version2.ExternalAuth
		expectedPort    uint16
		expectedWarning string
	}{
		{
			name: "port from ServicePorts",
			externalAuth: &version2.ExternalAuth{
				ServicePorts: []int{8080},
			},
			expectedPort:    8080,
			expectedWarning: "",
		},
		{
			name: "port from URI.Port",
			externalAuth: &version2.ExternalAuth{
				URI: &version2.AuthURI{
					Port: "9090",
				},
			},
			expectedPort:    9090,
			expectedWarning: "",
		},
		{
			name: "default port 80",
			externalAuth: &version2.ExternalAuth{
				URI: &version2.AuthURI{},
			},
			expectedPort:    80,
			expectedWarning: "",
		},
		{
			name: "invalid URI.Port returns warning",
			externalAuth: &version2.ExternalAuth{
				URI: &version2.AuthURI{
					Port: "invalid",
				},
			},
			expectedPort:    0,
			expectedWarning: "Invalid port in ExternalAuth URI",
		},
		{
			name: "ServicePorts takes precedence over URI.Port",
			externalAuth: &version2.ExternalAuth{
				URI: &version2.AuthURI{
					Port: "9090",
				},
				ServicePorts: []int{7070},
			},
			expectedPort:    7070,
			expectedWarning: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			port, warning := getExternalAuthServicePort(test.externalAuth)
			if port != test.expectedPort {
				t.Errorf("getExternalAuthServicePort() port = %d, want %d", port, test.expectedPort)
			}
			if test.expectedWarning != "" && !strings.Contains(warning, test.expectedWarning) {
				t.Errorf("getExternalAuthServicePort() warning = %q, want it to contain %q", warning, test.expectedWarning)
			}
			if test.expectedWarning == "" && warning != "" {
				t.Errorf("getExternalAuthServicePort() unexpected warning = %q", warning)
			}
		})
	}
}

func TestInternalAuthLocationInLocations(t *testing.T) {
	t.Parallel()

	locations := []version1.Location{
		{Path: "/_ext_auth_1", Internal: true},
		{Path: "/_ext_auth_2", Internal: true},
		{Path: "/coffee"},
	}

	found := false
	for _, loc := range locations {
		if loc.Path == "/_ext_auth_1" && loc.Internal {
			found = true
			break
		}
	}
	if !found {
		t.Error("should find internal auth location /_ext_auth_1 in locations")
	}

	found = false
	for _, loc := range locations {
		if loc.Path == "/_ext_auth_3" && loc.Internal {
			found = true
			break
		}
	}
	if found {
		t.Error("should not find internal auth location /_ext_auth_3 in locations")
	}
}

func TestGenerateNginxCfgForExternalAuth(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/policies"] = "my-ext-auth-policy"
	cafeIngressEx.Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/my-ext-auth-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "my-ext-auth-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "auth-svc",
					AuthServicePorts: []int{8080},
				},
			},
		},
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:  &StaticConfigParams{},
		ingEx:         &cafeIngressEx,
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	if result.Servers[0].ExternalAuth == nil {
		t.Fatal("generateNginxCfg() ExternalAuth should not be nil")
	}
	// Find the internal auth location in server.Locations
	var authLoc *version1.Location
	for i, loc := range result.Servers[0].Locations {
		if loc.Internal && loc.Path == result.Servers[0].ExternalAuth.URI.InternalPath {
			authLoc = &result.Servers[0].Locations[i]
			break
		}
	}
	if authLoc == nil {
		t.Fatal("generateNginxCfg() should have an internal auth location in Locations")
	}
	if authLoc.ProxyPassRequestBody != "off" {
		t.Errorf("auth location ProxyPassRequestBody = %q, want %q", authLoc.ProxyPassRequestBody, "off")
	}

	// There should be an auth upstream in the upstreams
	authUpstreamFound := false
	for _, ups := range result.Upstreams {
		if ups.Name == result.Servers[0].ExternalAuth.URI.Upstream {
			authUpstreamFound = true
			if len(ups.UpstreamServers) == 0 {
				t.Error("ExternalAuth upstream should have servers")
			}
			break
		}
	}
	if !authUpstreamFound {
		t.Error("ExternalAuth upstream not found in upstreams")
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForExternalAuthWithSignin(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.org/policies"] = "my-ext-auth-signin-policy"
	cafeIngressEx.Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	cafeIngressEx.Policies = map[string]*conf_v1.Policy{
		"default/my-ext-auth-signin-policy": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "my-ext-auth-signin-policy",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "auth-svc",
					AuthServicePorts: []int{8080},
					AuthSigninURI:    "/oauth2/start",
				},
			},
		},
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:  &StaticConfigParams{},
		ingEx:         &cafeIngressEx,
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	if result.Servers[0].ExternalAuth == nil {
		t.Fatal("generateNginxCfg() ExternalAuth should not be nil")
	}
	if result.Servers[0].ExternalAuth.SigninURL == "" {
		t.Error("generateNginxCfg() ExternalAuth.SigninURL should not be empty")
	}
	// Find the OAuth2 location in server.Locations (AuthRequestOff == true)
	var oauth2Loc *version1.Location
	for i, loc := range result.Servers[0].Locations {
		if loc.AuthRequestOff {
			oauth2Loc = &result.Servers[0].Locations[i]
			break
		}
	}
	if oauth2Loc == nil {
		t.Fatal("generateNginxCfg() should have an OAuth2 location in Locations")
	}
	if oauth2Loc.Path == "" {
		t.Error("OAuth2 location Path should not be empty")
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfg() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesWithExternalAuth(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	// Add ExternalAuth policy to the coffee minion
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/policies"] = "coffee-ext-auth"
	mergeableIngresses.Minions[0].Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
		"default/coffee-ext-auth": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "coffee-ext-auth",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "auth-svc",
					AuthServicePorts: []int{8080},
				},
			},
		},
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs: mergeableIngresses,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	server := result.Servers[0]

	// The coffee minion location should have ExternalAuth set
	coffeeLocFound := false
	for _, loc := range server.Locations {
		if loc.Path == "/coffee" {
			coffeeLocFound = true
			if loc.ExternalAuth == nil {
				t.Error("coffee location ExternalAuth should not be nil")
			}
			break
		}
	}
	if !coffeeLocFound {
		t.Error("coffee location not found")
	}

	// There should be an internal auth location in server.Locations from the minion
	authLocFound := false
	for _, loc := range server.Locations {
		if loc.Internal {
			authLocFound = true
			break
		}
	}
	if !authLocFound {
		t.Error("should have an internal auth location in Locations for mergeable ingresses with ExternalAuth")
	}

	// The tea minion location should NOT have ExternalAuth set
	for _, loc := range server.Locations {
		if loc.Path == "/tea" {
			if loc.ExternalAuth != nil {
				t.Error("tea location ExternalAuth should be nil")
			}
			break
		}
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesWithExternalAuthOnMaster(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	// Add ExternalAuth policy to the master
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/policies"] = "master-ext-auth"
	mergeableIngresses.Master.Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{
		"default/master-ext-auth": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "master-ext-auth",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "auth-svc",
					AuthServicePorts: []int{8080},
					AuthURI:          "/auth",
				},
			},
		},
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs: mergeableIngresses,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	server := result.Servers[0]

	// The server should have ExternalAuth set (server-level auth_request)
	if server.ExternalAuth == nil {
		t.Fatal("server ExternalAuth should not be nil when policy is on master")
	}

	// There should be an internal auth location preserved from the master
	authLocFound := false
	for _, loc := range server.Locations {
		if loc.Internal {
			authLocFound = true
			break
		}
	}
	if !authLocFound {
		t.Error("should have an internal auth location preserved from master for server-level auth_request")
	}

	// Minion locations should NOT have location-level ExternalAuth set
	// (they inherit the server-level auth_request directive)
	for _, loc := range server.Locations {
		if loc.Internal {
			continue
		}
		if loc.ExternalAuth != nil {
			t.Errorf("minion location %s should not have location-level ExternalAuth (inherits from server)", loc.Path)
		}
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesWithSameExternalAuthOnMasterAndMinion(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	extAuthPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "shared-ext-auth",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			ExternalAuth: &conf_v1.ExternalAuth{
				AuthServiceName:  "auth-svc",
				AuthServicePorts: []int{8080},
				AuthURI:          "/auth",
			},
		},
	}

	// Apply the same external auth policy on the master
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/policies"] = "shared-ext-auth"
	mergeableIngresses.Master.Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{
		"default/shared-ext-auth": extAuthPolicy,
	}

	// Apply the same external auth policy on the coffee minion
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/policies"] = "shared-ext-auth"
	mergeableIngresses.Minions[0].Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
		"default/shared-ext-auth": extAuthPolicy,
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs: mergeableIngresses,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	server := result.Servers[0]

	// Server should have ExternalAuth from the master
	if server.ExternalAuth == nil {
		t.Fatal("server ExternalAuth should not be nil when policy is on master")
	}

	// Count internal auth locations — should be exactly 1 (from master, not duplicated by minion)
	internalCount := 0
	for _, loc := range server.Locations {
		if loc.Internal {
			internalCount++
		}
	}
	if internalCount != 1 {
		t.Errorf("expected exactly 1 internal auth location, got %d", internalCount)
	}

	// The coffee minion location should NOT have location-level ExternalAuth
	// since it's the same policy as the master (deduped, inherits from server level)
	for _, loc := range server.Locations {
		if loc.Path == "/coffee" {
			if loc.ExternalAuth != nil {
				t.Error("coffee location should not have location-level ExternalAuth when same policy is on master")
			}
			break
		}
	}

	// The tea minion location should NOT have ExternalAuth either (no policy on tea minion)
	for _, loc := range server.Locations {
		if loc.Path == "/tea" {
			if loc.ExternalAuth != nil {
				t.Error("tea location should not have ExternalAuth")
			}
			break
		}
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesWithDifferentExternalAuthOnMasterAndMinion(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	// Master uses one external auth policy
	mergeableIngresses.Master.Ingress.Annotations["nginx.org/policies"] = "master-ext-auth"
	mergeableIngresses.Master.Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	mergeableIngresses.Master.Policies = map[string]*conf_v1.Policy{
		"default/master-ext-auth": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "master-ext-auth",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "auth-svc",
					AuthServicePorts: []int{8080},
					AuthURI:          "/auth",
				},
			},
		},
	}

	// Coffee minion uses a different external auth policy
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/policies"] = "minion-ext-auth"
	mergeableIngresses.Minions[0].Endpoints["default/other-auth-svc:9090"] = []string{"10.0.0.6:9090"}
	mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
		"default/minion-ext-auth": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "minion-ext-auth",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "other-auth-svc",
					AuthServicePorts: []int{9090},
					AuthURI:          "/verify",
				},
			},
		},
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs: mergeableIngresses,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	server := result.Servers[0]

	// Server should have ExternalAuth from the master
	if server.ExternalAuth == nil {
		t.Fatal("server ExternalAuth should not be nil")
	}

	// Should have 2 internal auth locations: one from master, one from minion (different policies)
	internalCount := 0
	for _, loc := range server.Locations {
		if loc.Internal {
			internalCount++
		}
	}
	if internalCount != 2 {
		t.Errorf("expected 2 internal auth locations (master + minion with different policies), got %d", internalCount)
	}

	// Coffee minion location should have its own location-level ExternalAuth (different policy)
	coffeeFound := false
	for _, loc := range server.Locations {
		if loc.Path == "/coffee" {
			coffeeFound = true
			if loc.ExternalAuth == nil {
				t.Error("coffee location should have its own ExternalAuth (different policy from master)")
			}
			break
		}
	}
	if !coffeeFound {
		t.Error("coffee location not found")
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}

func TestGenerateNginxCfgForMergeableIngressesWithExternalAuthAndProxySetHeaders(t *testing.T) {
	t.Parallel()
	mergeableIngresses := createMergeableCafeIngress()

	// Add proxy-set-headers annotation to the coffee minion
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/proxy-set-headers"] = "X-Forwarded-ABC: coffee"

	// Add ExternalAuth policy with signin URL to the coffee minion
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.org/policies"] = "coffee-ext-auth"
	mergeableIngresses.Minions[0].Endpoints["default/auth-svc:8080"] = []string{"10.0.0.5:8080"}
	mergeableIngresses.Minions[0].Policies = map[string]*conf_v1.Policy{
		"default/coffee-ext-auth": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "coffee-ext-auth",
				Namespace: "default",
			},
			Spec: conf_v1.PolicySpec{
				ExternalAuth: &conf_v1.ExternalAuth{
					AuthServiceName:  "auth-svc",
					AuthServicePorts: []int{8080},
					AuthSigninURI:    "/oauth2/start",
				},
			},
		},
	}

	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	result, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs: mergeableIngresses,
		staticParams:  &StaticConfigParams{},
		isPlus:        isPlus,
		BaseCfgParams: configParams,
	})

	server := result.Servers[0]

	// The coffee minion location should have the merged proxy-set-headers
	coffeeFound := false
	for _, loc := range server.Locations {
		if loc.Path == "/coffee" {
			coffeeFound = true
			expectedHeaders := []version2.Header{{Name: "X-Forwarded-ABC", Value: "coffee"}}
			if diff := cmp.Diff(expectedHeaders, loc.ProxySetHeaders); diff != "" {
				t.Errorf("coffee location ProxySetHeaders mismatch (-want +got):\n%s", diff)
			}
			break
		}
	}
	if !coffeeFound {
		t.Fatal("coffee location not found")
	}

	// The oauth2 location should retain its original headers, NOT the annotation headers
	oauth2Found := false
	for _, loc := range server.Locations {
		if loc.AuthRequestOff && !loc.Internal {
			oauth2Found = true
			expectedHeaders := []version2.Header{
				{Name: "X-Auth-Request-Redirect", Value: "$request_uri"},
				{Name: "X-Scheme", Value: "$scheme"},
			}
			if diff := cmp.Diff(expectedHeaders, loc.ProxySetHeaders); diff != "" {
				t.Errorf("oauth2 location ProxySetHeaders should not be overwritten by annotation (-want +got):\n%s", diff)
			}
			break
		}
	}
	if !oauth2Found {
		t.Fatal("oauth2 location not found")
	}

	// The internal auth location should retain its original headers
	internalAuthFound := false
	for _, loc := range server.Locations {
		if loc.Internal {
			internalAuthFound = true
			expectedHeaders := []version2.Header{
				{Name: "Content-Length", Value: "0"},
				{Name: "X-Scheme", Value: "$scheme"},
			}
			if diff := cmp.Diff(expectedHeaders, loc.ProxySetHeaders); diff != "" {
				t.Errorf("internal auth location ProxySetHeaders should not be overwritten by annotation (-want +got):\n%s", diff)
			}
			break
		}
	}
	if !internalAuthFound {
		t.Fatal("internal auth location not found")
	}

	if len(warnings) != 0 {
		t.Errorf("generateNginxCfgForMergeableIngresses() returned warnings: %v", warnings)
	}
}
