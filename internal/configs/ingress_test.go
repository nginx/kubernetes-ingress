package configs

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGenerateNginxCfg(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

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

func TestGenerateNginxCfgForJWT(t *testing.T) {
	t.Parallel()
	cafeIngressEx := createCafeIngressEx()
	cafeIngressEx.Ingress.Annotations["nginx.com/jwt-key"] = "cafe-jwk"
	cafeIngressEx.Ingress.Annotations["nginx.com/jwt-realm"] = "Cafe App"
	cafeIngressEx.Ingress.Annotations["nginx.com/jwt-token"] = "$cookie_auth_token"
	cafeIngressEx.Ingress.Annotations["nginx.com/jwt-login-url"] = "https://login.example.com"
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
	cafeIngressEx := createCafeIngressEx()
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.Servers[0].DisableIPV6 = true

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{DisableIPV6: true},
		ingEx:                &cafeIngressEx,
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
	exact := networking.PathTypeExact
	prefix := networking.PathTypePrefix
	impSpec := networking.PathTypeImplementationSpecific
	tests := []struct {
		pathType *networking.PathType
		path     string
		expected string
	}{
		{
			pathType: &exact,
			path:     "/path/to/resource",
			expected: "= /path/to/resource",
		},
		{
			pathType: &prefix,
			path:     "/path/to/resource",
			expected: "/path/to/resource",
		},
		{
			pathType: &impSpec,
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
	mergeableIngresses.Master.Ingress.Annotations["nginx.com/jwt-key"] = "cafe-jwk"
	mergeableIngresses.Master.Ingress.Annotations["nginx.com/jwt-realm"] = "Cafe"
	mergeableIngresses.Master.Ingress.Annotations["nginx.com/jwt-token"] = "$cookie_auth_token"
	mergeableIngresses.Master.Ingress.Annotations["nginx.com/jwt-login-url"] = "https://login.example.com"
	mergeableIngresses.Master.SecretRefs["cafe-jwk"] = &secrets.SecretReference{
		Secret: &v1.Secret{
			Type: secrets.SecretTypeJWK,
		},
		Path: "/etc/nginx/secrets/default-cafe-jwk",
	}

	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.com/jwt-key"] = "coffee-jwk"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.com/jwt-realm"] = "Coffee"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.com/jwt-token"] = "$cookie_auth_token_coffee"
	mergeableIngresses.Minions[0].Ingress.Annotations["nginx.com/jwt-login-url"] = "https://login.coffee.example.com"
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
	cafeIngressEx := createCafeIngressEx()
	isPlus := false
	configParams := NewDefaultConfigParams(context.Background(), isPlus)

	expected := createExpectedConfigForCafeIngressEx(isPlus)
	expected.SpiffeClientCerts = true
	for i := range expected.Servers[0].Locations {
		expected.Servers[0].Locations[i].SSL = true
	}

	result, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:         &StaticConfigParams{NginxServiceMesh: true},
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
