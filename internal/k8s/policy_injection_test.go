package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginx/kubernetes-ingress/internal/nginxconf"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// policyField names a string field of a Policy and the function that writes a
// value into it. Each setter starts from an otherwise valid policy of that type,
// so the payload is the only thing that could make the policy invalid.
type policyField struct {
	name string
	set  func(*conf_v1.PolicySpec, string)
	// benign is a harmless value of the shape this field requires. It defaults to
	// "value", which is fine for a free-form string but not for a field the CRD
	// constrains with a pattern: a baseline the API server would reject measures
	// the fixture rather than the field.
	benign string
	extra  []string
}

// plusOnly reports whether this field's policy type (jwt, oidc, waf) is refused
// by admission on OSS. Being unavailable is the protection there and there is no
// rendering to examine, so the OSS pass asserts the refusal and skips the field
// rather than reporting a broken fixture.
func (f policyField) plusOnly() bool {
	return strings.HasPrefix(f.name, "jwt.") ||
		strings.HasPrefix(f.name, "oidc.") ||
		strings.HasPrefix(f.name, "waf.") ||
		strings.HasPrefix(f.name, "rateLimit.condition.jwt.") ||
		f.name == "cache.cachePurgeAllow[0]"
}

func (f policyField) benignValue() string {
	if f.benign != "" {
		return f.benign
	}
	return "value"
}

// policyStringFields is every user-controlled string in a Policy that reaches
// generated configuration, excluding authSnippets, which is raw configuration by
// design and gated behind -enable-snippets.
var policyStringFields = []policyField{
	{"accessControl.allow[0]", func(s *conf_v1.PolicySpec, v string) {
		s.AccessControl = &conf_v1.AccessControl{Allow: []string{v}}
	}, "10.0.0.0/8", nil},
	{"accessControl.deny[0]", func(s *conf_v1.PolicySpec, v string) {
		s.AccessControl = &conf_v1.AccessControl{Deny: []string{v}}
	}, "10.0.0.0/8", nil},

	{"rateLimit.rate", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.Rate = v
	}, "10r/s", nil},
	{"rateLimit.key", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.Key = v
	}, "", []string{`${binary_remote_addr}";ip_hash;#"`}},
	{"rateLimit.zoneSize", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.ZoneSize = v
	}, "10M", nil},
	{"rateLimit.logLevel", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.LogLevel = v
	}, "error", nil},
	{"rateLimit.condition.jwt.claim", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.Condition = &conf_v1.RateLimitCondition{JWT: &conf_v1.JWTCondition{Claim: v, Match: "gold"}}
	}, "user", nil},
	{"rateLimit.condition.jwt.match", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.Condition = &conf_v1.RateLimitCondition{JWT: &conf_v1.JWTCondition{Claim: "user", Match: v}}
	}, "gold", nil},
	{"rateLimit.condition.variables[0].name", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.Condition = &conf_v1.RateLimitCondition{Variables: &[]conf_v1.VariableCondition{{Name: v, Match: "GET"}}}
	}, "$request_method", nil},
	{"rateLimit.condition.variables[0].match", func(s *conf_v1.PolicySpec, v string) {
		s.RateLimit = baseRateLimit()
		s.RateLimit.Condition = &conf_v1.RateLimitCondition{Variables: &[]conf_v1.VariableCondition{{Name: "$request_method", Match: v}}}
	}, "GET", nil},

	{"jwt.realm", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: v, Secret: "jwk-secret"}
	}, "", nil},
	{"jwt.secret", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: "api", Secret: v}
	}, "", nil},
	{"jwt.token", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: "api", Secret: "jwk-secret", Token: v}
	}, "$http_token", []string{`$http_token";ip_hash;#"`}},
	{"jwt.jwksURI", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: "api", JwksURI: v, KeyCache: "1h"}
	}, "https://idp.example.com/jwks", nil},
	{"jwt.keyCache", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: "api", JwksURI: "https://idp.example.com/jwks", KeyCache: v}
	}, "1h", nil},
	{"jwt.sniName", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: "api", JwksURI: "https://idp.example.com/jwks", KeyCache: "1h", SNIEnabled: true, SNIName: v}
	}, "idp.example.com", nil},
	{"jwt.trustedCertSecret", func(s *conf_v1.PolicySpec, v string) {
		s.JWTAuth = &conf_v1.JWTAuth{Realm: "api", JwksURI: "https://idp.example.com/jwks", KeyCache: "1h", SSLVerify: true, TrustedCertSecret: v}
	}, "jwt-ca-secret", nil},

	{"basicAuth.realm", func(s *conf_v1.PolicySpec, v string) {
		s.BasicAuth = &conf_v1.BasicAuth{Realm: v, Secret: "htpasswd-secret"}
	}, "", nil},
	{"basicAuth.secret", func(s *conf_v1.PolicySpec, v string) {
		s.BasicAuth = &conf_v1.BasicAuth{Realm: "api", Secret: v}
	}, "", nil},

	{"ingressMTLS.clientCertSecret", func(s *conf_v1.PolicySpec, v string) {
		s.IngressMTLS = &conf_v1.IngressMTLS{ClientCertSecret: v}
	}, "", nil},
	{"ingressMTLS.crlFileName", func(s *conf_v1.PolicySpec, v string) {
		s.IngressMTLS = &conf_v1.IngressMTLS{ClientCertSecret: "mtls-secret", CrlFileName: v}
	}, "", nil},
	{"ingressMTLS.verifyClient", func(s *conf_v1.PolicySpec, v string) {
		s.IngressMTLS = &conf_v1.IngressMTLS{ClientCertSecret: "mtls-secret", VerifyClient: v}
	}, "on", nil},

	{"egressMTLS.tlsSecret", func(s *conf_v1.PolicySpec, v string) {
		s.EgressMTLS = &conf_v1.EgressMTLS{TLSSecret: v}
	}, "", nil},
	{"egressMTLS.protocols", func(s *conf_v1.PolicySpec, v string) {
		s.EgressMTLS = &conf_v1.EgressMTLS{Protocols: v}
	}, "TLSv1.2", []string{`TLSv1.2";ip_hash;#"`, "TLSv1.2; ip_hash;"}},
	{"egressMTLS.ciphers", func(s *conf_v1.PolicySpec, v string) {
		s.EgressMTLS = &conf_v1.EgressMTLS{Ciphers: v}
	}, "", []string{`HIGH";ip_hash;#"`, "HIGH; ip_hash;"}},
	{"egressMTLS.sslName", func(s *conf_v1.PolicySpec, v string) {
		s.EgressMTLS = &conf_v1.EgressMTLS{SSLName: v}
	}, "", nil},
	{"egressMTLS.trustedCertSecret", func(s *conf_v1.PolicySpec, v string) {
		s.EgressMTLS = &conf_v1.EgressMTLS{TLSSecret: "egress-mtls-secret", TrustedCertSecret: v}
	}, "egress-ca-secret", nil},

	{"waf.apPolicy", func(s *conf_v1.PolicySpec, v string) {
		s.WAF = &conf_v1.WAF{Enable: true, ApPolicy: v}
	}, "", nil},
	{"waf.apBundle", func(s *conf_v1.PolicySpec, v string) {
		s.WAF = &conf_v1.WAF{Enable: true, ApBundle: v}
	}, "", nil},
	{"waf.securityLog.logDest", func(s *conf_v1.PolicySpec, v string) {
		s.WAF = &conf_v1.WAF{Enable: true, ApPolicy: "dataguard", SecurityLog: &conf_v1.SecurityLog{Enable: true, ApLogConf: "logconf", LogDest: v}}
	}, "syslog:server=localhost:514", nil},
	{"waf.securityLog.apLogConf", func(s *conf_v1.PolicySpec, v string) {
		s.WAF = &conf_v1.WAF{Enable: true, ApPolicy: "dataguard", SecurityLog: &conf_v1.SecurityLog{Enable: true, ApLogConf: v, LogDest: "syslog:server=localhost:514"}}
	}, "logconf", nil},
	{"waf.securityLog.apLogBundle", func(s *conf_v1.PolicySpec, v string) {
		s.WAF = &conf_v1.WAF{Enable: true, ApBundle: "bundle.tgz", SecurityLog: &conf_v1.SecurityLog{Enable: true, ApLogBundle: v, LogDest: "syslog:server=localhost:514"}}
	}, "logbundle.tgz", nil},

	{"apiKey.suppliedIn.header[0]", func(s *conf_v1.PolicySpec, v string) {
		s.APIKey = &conf_v1.APIKey{ClientSecret: "api-key-secret", SuppliedIn: &conf_v1.SuppliedIn{Header: []string{v}}}
	}, "", nil},
	{"apiKey.suppliedIn.query[0]", func(s *conf_v1.PolicySpec, v string) {
		s.APIKey = &conf_v1.APIKey{ClientSecret: "api-key-secret", SuppliedIn: &conf_v1.SuppliedIn{Query: []string{v}}}
	}, "", nil},
	{"apiKey.clientSecret", func(s *conf_v1.PolicySpec, v string) {
		s.APIKey = &conf_v1.APIKey{ClientSecret: v, SuppliedIn: &conf_v1.SuppliedIn{Header: []string{"X-API-Key"}}}
	}, "", nil},

	{"cache.cacheZoneName", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.CacheZoneName = v
	}, "zone", nil},
	{"cache.cacheZoneSize", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.CacheZoneSize = v
	}, "10m", nil},
	{"cache.cacheKey", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.CacheKey = v
	}, "", []string{`${scheme}";ip_hash;#"`}},
	{"cache.time", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Time = v
	}, "10m", nil},
	{"cache.levels", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Levels = v
	}, "1:2", nil},
	{"cache.inactive", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Inactive = v
	}, "10m", nil},
	{"cache.maxSize", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.MaxSize = v
	}, "10m", nil},
	{"cache.minFree", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.MinFree = v
	}, "10m", nil},
	{"cache.manager.sleep", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Manager = &conf_v1.CacheManager{Sleep: v}
	}, "200ms", nil},
	{"cache.manager.threshold", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Manager = &conf_v1.CacheManager{Threshold: v}
	}, "300ms", nil},
	{"cache.lock.timeout", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Lock = &conf_v1.CacheLock{Enable: true, Timeout: v}
	}, "5s", nil},
	{"cache.lock.age", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Lock = &conf_v1.CacheLock{Enable: true, Age: v}
	}, "5s", nil},
	{"cache.cachePurgeAllow[0]", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.CachePurgeAllow = []string{v}
	}, "192.168.1.1", nil},
	{"cache.allowedMethods[0]", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.AllowedMethods = []string{v}
	}, "GET", nil},
	{"cache.cacheUseStale[0]", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.CacheUseStale = []string{v}
	}, "error", nil},
	{"cache.conditions.noCache[0]", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Conditions = &conf_v1.CacheConditions{NoCache: []string{v}}
	}, "", nil},
	{"cache.conditions.bypass[0]", func(s *conf_v1.PolicySpec, v string) {
		s.Cache = baseCache()
		s.Cache.Conditions = &conf_v1.CacheConditions{Bypass: []string{v}}
	}, "", nil},

	{"cors.allowOrigin[0]", func(s *conf_v1.PolicySpec, v string) {
		s.CORS = &conf_v1.CORS{AllowOrigin: []string{v}}
	}, "https://example.com", nil},
	{"cors.allowMethods[0]", func(s *conf_v1.PolicySpec, v string) {
		s.CORS = &conf_v1.CORS{AllowOrigin: []string{"https://example.com"}, AllowMethods: []string{v}}
	}, "GET", nil},
	{"cors.allowHeaders[0]", func(s *conf_v1.PolicySpec, v string) {
		s.CORS = &conf_v1.CORS{AllowOrigin: []string{"https://example.com"}, AllowHeaders: []string{v}}
	}, "", nil},
	{"cors.exposeHeaders[0]", func(s *conf_v1.PolicySpec, v string) {
		s.CORS = &conf_v1.CORS{AllowOrigin: []string{"https://example.com"}, ExposeHeaders: []string{v}}
	}, "", nil},

	{"oidc.authEndpoint", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.AuthEndpoint = v
	}, "https://idp.example.com/auth", nil},
	{"oidc.tokenEndpoint", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.TokenEndpoint = v
	}, "https://idp.example.com/token", nil},
	{"oidc.jwksURI", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.JWKSURI = v
	}, "https://idp.example.com/jwks", nil},
	{"oidc.clientID", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.ClientID = v
	}, "", nil},
	{"oidc.clientSecret", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.ClientSecret = v
	}, "", nil},
	{"oidc.scope", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.Scope = v
	}, "openid", nil},
	{"oidc.redirectURI", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.RedirectURI = v
	}, "/redirect", nil},
	{"oidc.authExtraArgs[0]", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.AuthExtraArgs = []string{v}
	}, "", nil},
	{"oidc.endSessionEndpoint", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.EndSessionEndpoint = v
	}, "https://idp.example.com/logout", nil},
	{"oidc.postLogoutRedirectURI", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.EndSessionEndpoint = "https://idp.example.com/logout"
		s.OIDC.PostLogoutRedirectURI = v
	}, "/logout", nil},
	{"oidc.trustedCertSecret", func(s *conf_v1.PolicySpec, v string) {
		s.OIDC = baseOIDC()
		s.OIDC.SSLVerify = true
		s.OIDC.TrustedCertSecret = v
	}, "oidc-ca-secret", nil},
	{"spec.ingressClassName", func(s *conf_v1.PolicySpec, v string) {
		s.AccessControl = &conf_v1.AccessControl{Allow: []string{"10.0.0.0/8"}}
		s.IngressClass = v
	}, "nginx", nil},
}

func baseRateLimit() *conf_v1.RateLimit {
	return &conf_v1.RateLimit{Rate: "10r/s", Key: "${binary_remote_addr}", ZoneSize: "10M"}
}

func baseCache() *conf_v1.Cache {
	return &conf_v1.Cache{CacheZoneName: "zone", CacheZoneSize: "10m"}
}

func baseOIDC() *conf_v1.OIDC {
	return &conf_v1.OIDC{
		AuthEndpoint:  "https://idp.example.com/auth",
		TokenEndpoint: "https://idp.example.com/token",
		JWKSURI:       "https://idp.example.com/jwks",
		ClientID:      "client",
		ClientSecret:  "oidc-secret",
	}
}

// TestPolicyCannotInjectConfiguration asserts, for the Policy surface, the
// property already established for the other four: a value carrying NGINX syntax
// is either rejected at admission or rendered as data.
//
// Policies are rendered through the VirtualServer that references them, which is
// how they reach configuration in production, so this exercises the policy
// generators and the VirtualServer templates together.
func TestPolicyCannotInjectConfiguration(t *testing.T) {
	t.Parallel()

	// Policies are the surface where NGINX Plus adds the most: OIDC and JWT are
	// Plus-only, so the OSS pass mostly measures that they are refused.
	for _, isPlus := range []bool{false, true} {
		var byValidation, admitted int
		for _, field := range policyStringFields {
			benign := policyWithField(field, field.benignValue())

			// A Plus-only policy type cannot be admitted on OSS; its protection
			// there is unavailability. Assert admission refuses it and skip, so a
			// regression in that gate is caught rather than silently reducing
			// coverage.
			if field.plusOnly() && !isPlus {
				if validation.ValidatePolicy(benign, isPlus, true, true) == nil {
					t.Errorf("plus=%v field=%s: Plus-only policy admitted on OSS; the gate may have regressed", isPlus, field.name)
				}
				continue
			}

			// The benign value must survive admission, or every payload for this
			// field is rejected for the shape of the fixture rather than its
			// content and the field is never really tested.
			if err := validation.ValidatePolicy(benign, isPlus, true, true); err != nil {
				t.Errorf("plus=%v field=%s: the benign value %q is rejected at admission, so the fixture is wrong: %v",
					isPlus, field.name, field.benignValue(), err)
				continue
			}

			baseline, err := shapeForPolicy(t, benign, isPlus)
			if err != nil {
				t.Errorf("plus=%v field=%s: baseline configuration does not tokenize: %v", isPlus, field.name, err)
				continue
			}

			payloads := append(append([]string{}, annotationInjectionPayloads...), field.extra...)
			for _, payload := range payloads {
				policy := policyWithField(field, payload)

				if validation.ValidatePolicy(policy, isPlus, true, true) != nil {
					byValidation++
					continue
				}
				admitted++

				// Gate 2: whatever both gates let through must render as data.
				shape, err := shapeForPolicy(t, policy, isPlus)
				if err != nil {
					t.Errorf("plus=%v field=%s payload=%q was admitted and produced unparsable configuration: %v",
						isPlus, field.name, payload, err)
					continue
				}
				if diff := shapeAdditions(baseline, shape); diff != "" {
					t.Errorf("plus=%v field=%s payload=%q was admitted and added configuration:\n%s",
						isPlus, field.name, payload, diff)
				}
			}
		}

		if byValidation == 0 {
			t.Errorf("plus=%v: no payload was rejected by Go validation", isPlus)
		}
		if admitted == 0 {
			t.Errorf("plus=%v: every payload was rejected at admission, so the rendering was never exercised", isPlus)
		}
		t.Logf("plus=%v: %d rejected by Go validation, %d admitted and rendered as data", isPlus, byValidation, admitted)
	}
}

func policyWithField(field policyField, payload string) *conf_v1.Policy {
	policy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Name: "test-policy", Namespace: "default"},
	}
	field.set(&policy.Spec, payload)
	return policy
}

// shapeForPolicy renders the configuration for a VirtualServer that references
// this policy, and returns its directive structure.
func shapeForPolicy(t *testing.T, policy *conf_v1.Policy, isPlus bool) ([]string, error) {
	t.Helper()

	vs := baseVirtualServer()
	vs.Spec.Policies = []conf_v1.PolicyReference{{Name: policy.Name, Namespace: policy.Namespace}}
	if policy.Spec.IngressMTLS != nil {
		vs.Spec.TLS = &conf_v1.TLS{Secret: "server-tls"}
	}

	bundlePath := t.TempDir()
	if err := writeWAFBundles(bundlePath, policy); err != nil {
		return nil, err
	}
	cnf, manager := configuratorForInjectionTest(t, isPlus, &configs.StaticConfigParams{AppProtectBundlePath: bundlePath})

	secretRefs := secretRefsForPolicy(policy)
	if vs.Spec.TLS != nil {
		secretRefs["default/"+vs.Spec.TLS.Secret] = &secrets.SecretReference{
			Secret: &api_v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: vs.Spec.TLS.Secret, Namespace: "default"},
				Type:       api_v1.SecretTypeTLS,
			},
			Path: "/etc/nginx/secrets/default-" + vs.Spec.TLS.Secret,
		}
	}

	vsEx := &configs.VirtualServerEx{
		VirtualServer: vs,
		Endpoints:     map[string][]string{"default/tea-svc:80": {"10.0.0.20:80"}},
		Policies:      map[string]*conf_v1.Policy{"default/test-policy": policy},
		SecretRefs:    secretRefs,
	}
	vsEx.ApPolRefs, vsEx.LogConfRefs = wafReferencesForPolicy(policy)
	if _, err := cnf.AddOrUpdateVirtualServer(vsEx); err != nil {
		t.Fatalf("cannot generate VirtualServer configuration: %v", err)
	}

	var rendered string
	for _, content := range manager.configs {
		rendered = string(content)
	}
	if rendered == "" {
		t.Fatal("the Configurator wrote no configuration for the VirtualServer")
	}
	if strings.Contains(rendered, "return 500;") {
		switch {
		case policy.Spec.IngressMTLS != nil:
			return nil, fmt.Errorf("IngressMTLS policy rendering fell back to an error response")
		case policy.Spec.WAF != nil:
			return nil, fmt.Errorf("WAF policy rendering fell back to an error response")
		}
	}
	// A VirtualServer configuration is a fragment of an http {} block.
	conf := "http {\n" + rendered + "\n}\n"
	// The OIDC policy renders its own fragment through oidc.tmpl, included inside
	// a server {} block. Tokenize it in that context so values that reach
	// configuration only there, such as oidc.redirectURI, are exercised too.
	if len(manager.oidc) > 0 {
		conf += "http {\nserver {\n" + string(manager.oidc) + "\n}\n}\n"
	}
	return nginxconf.Shape(conf)
}

func wafReferencesForPolicy(policy *conf_v1.Policy) (map[string]*unstructured.Unstructured, map[string]*unstructured.Unstructured) {
	policies := make(map[string]*unstructured.Unstructured)
	logConfs := make(map[string]*unstructured.Unstructured)
	if policy.Spec.WAF == nil {
		return policies, logConfs
	}

	add := func(refs map[string]*unstructured.Unstructured, name string) {
		if name == "" {
			return
		}
		namespace, resourceName, hasNamespace := strings.Cut(name, "/")
		if !hasNamespace {
			namespace, resourceName = "default", name
		}
		refs[namespace+"/"+resourceName] = &unstructured.Unstructured{Object: map[string]interface{}{
			"metadata": map[string]interface{}{"namespace": namespace, "name": resourceName},
		}}
	}

	waf := policy.Spec.WAF
	add(policies, waf.ApPolicy)
	for _, log := range waf.SecurityLogs {
		add(logConfs, log.ApLogConf)
	}
	if waf.SecurityLog != nil {
		add(logConfs, waf.SecurityLog.ApLogConf)
	}
	return policies, logConfs
}

func writeWAFBundles(bundlePath string, policy *conf_v1.Policy) error {
	if policy.Spec.WAF == nil {
		return nil
	}

	write := func(name string) error {
		if name == "" || filepath.Base(name) != name {
			return nil
		}
		return os.WriteFile(filepath.Join(bundlePath, name), nil, 0o600)
	}

	waf := policy.Spec.WAF
	if err := write(waf.ApBundle); err != nil {
		return err
	}
	for _, log := range waf.SecurityLogs {
		if err := write(log.ApLogBundle); err != nil {
			return err
		}
	}
	if waf.SecurityLog != nil {
		return write(waf.SecurityLog.ApLogBundle)
	}
	return nil
}

// secretRefsForPolicy provides a reference for every secret a policy can name,
// because the policy generators dereference them without checking they exist.
// The controller resolves references before generating configuration, so this
// only matters for a policy assembled directly.
func secretRefsForPolicy(policy *conf_v1.Policy) map[string]*secrets.SecretReference {
	refs := make(map[string]*secrets.SecretReference)
	add := func(name string, secretType api_v1.SecretType) {
		if name == "" {
			return
		}
		refs["default/"+name] = &secrets.SecretReference{
			Secret: &api_v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: name, Namespace: "default"},
				Type:       secretType,
			},
			Path: "/etc/nginx/secrets/default-" + name,
		}
	}

	s := policy.Spec
	if s.JWTAuth != nil {
		add(s.JWTAuth.Secret, "nginx.org/jwk")
		add(s.JWTAuth.TrustedCertSecret, "nginx.org/ca")
	}
	if s.BasicAuth != nil {
		add(s.BasicAuth.Secret, "nginx.org/htpasswd")
	}
	if s.IngressMTLS != nil {
		add(s.IngressMTLS.ClientCertSecret, "nginx.org/ca")
	}
	if s.EgressMTLS != nil {
		add(s.EgressMTLS.TLSSecret, "kubernetes.io/tls")
		add(s.EgressMTLS.TrustedCertSecret, "nginx.org/ca")
	}
	if s.OIDC != nil {
		add(s.OIDC.ClientSecret, "nginx.org/oidc")
		add(s.OIDC.TrustedCertSecret, "nginx.org/ca")
	}
	if s.APIKey != nil {
		add(s.APIKey.ClientSecret, "nginx.org/apikey")
	}
	return refs
}
