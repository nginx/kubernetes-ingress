package k8s

import (
	"context"
	"strings"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	"github.com/nginx/kubernetes-ingress/internal/nginxconf"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// virtualServerField names a string field of a VirtualServer and the function
// that writes a value into it.
type virtualServerField struct {
	name string
	set  func(*conf_v1.VirtualServer, string)
	// benign is a harmless value of the shape this field requires. It defaults to
	// "value", which suits a free-form string but not a field the CRD constrains
	// with a pattern, where a baseline the API server would reject would measure
	// the fixture rather than the field.
	benign string
	// extra carries payloads shaped to pass this field's own grammar, for fields
	// whose generator only emits recognized forms. See the TransportServer test
	// for why a generic payload is not enough on its own.
	extra []string
}

// virtualServerStringFields is every user-controlled string in a VirtualServer
// that reaches generated configuration, excluding the snippets, which are raw
// configuration by design and gated behind -enable-snippets.
func (f virtualServerField) benignValue() string {
	if f.benign != "" {
		return f.benign
	}
	return "value"
}

// plusOnly reports whether this field's feature is refused by admission on OSS
// (active health checks, slow start and queue are Plus-only), so the OSS pass
// asserts the refusal and skips it rather than reporting a broken fixture.
func (f virtualServerField) plusOnly() bool {
	return strings.Contains(f.name, "healthCheck") ||
		strings.Contains(f.name, "slow-start") ||
		strings.Contains(f.name, "queue")
}

var virtualServerStringFields = []virtualServerField{
	{"spec.host", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Host = v }, "", nil},
	{"spec.ingressClassName", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.IngressClass = v }, "", nil},
	{"spec.tls.secret", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.TLS = &conf_v1.TLS{Secret: v}
	}, "", nil},
	{"spec.tls.redirect.basedOn", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.TLS = &conf_v1.TLS{Secret: "tls-secret", Redirect: &conf_v1.TLSRedirect{Enable: true, BasedOn: v}}
	}, "scheme", nil},

	// Upstream
	{"spec.upstreams[0].name", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].Name = v
		vs.Spec.Routes[0].Action.Pass = v
	}, "", nil},
	{"spec.upstreams[0].service", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].Service = v }, "", nil},
	{"spec.upstreams[0].lb-method", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].LBMethod = v }, "round_robin", []string{
		`hash $request_uri";ip_hash;#" consistent`,
		`hash $request_uri;ip_hash;# consistent`,
	}},
	{"spec.upstreams[0].fail-timeout", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].FailTimeout = v }, "10s", nil},
	{"spec.upstreams[0].connect-timeout", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].ProxyConnectTimeout = v }, "5s", nil},
	{"spec.upstreams[0].read-timeout", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].ProxyReadTimeout = v }, "5s", nil},
	{"spec.upstreams[0].send-timeout", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].ProxySendTimeout = v }, "5s", nil},
	{"spec.upstreams[0].next-upstream", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].ProxyNextUpstream = v }, "error timeout", nil},
	{"spec.upstreams[0].next-upstream-timeout", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].ProxyNextUpstreamTimeout = v
	}, "5s", nil},
	{"spec.upstreams[0].buffer-size", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].ProxyBufferSize = v }, "8k", nil},
	{"spec.upstreams[0].buffers.size", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].ProxyBuffers = &conf_v1.UpstreamBuffers{Number: 8, Size: v}
	}, "8k", nil},
	{"spec.upstreams[0].queue.timeout", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].Queue = &conf_v1.UpstreamQueue{Size: 10, Timeout: v}
	}, "30s", nil},
	{"spec.upstreams[0].busy-buffers-size", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].ProxyBusyBuffersSize = v
	}, "16k", nil},
	{"spec.upstreams[0].client-max-body-size", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].ClientMaxBodySize = v
	}, "1m", nil},
	{"spec.upstreams[0].client-body-buffer-size", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].ClientBodyBufferSize = v
	}, "8k", nil},
	{"spec.upstreams[0].slow-start", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].SlowStart = v }, "30s", nil},
	{"spec.upstreams[0].type", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Upstreams[0].Type = v }, "http", nil},
	{"spec.upstreams[0].backup", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Upstreams[0].Backup = v
		port := uint16(8081)
		vs.Spec.Upstreams[0].BackupPort = &port
	}, "backup-svc", nil},

	// Upstream health check
	{"spec.upstreams[0].healthCheck.path", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).Path = v
	}, "/health", nil},
	{"spec.upstreams[0].healthCheck.interval", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).Interval = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.jitter", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).Jitter = v
	}, "1s", nil},
	{"spec.upstreams[0].healthCheck.connect-timeout", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).ConnectTimeout = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.read-timeout", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).ReadTimeout = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.send-timeout", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).SendTimeout = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.headers[0].name", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).Headers = []conf_v1.Header{{Name: v, Value: "value"}}
	}, "", nil},
	{"spec.upstreams[0].healthCheck.headers[0].value", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).Headers = []conf_v1.Header{{Name: "X-Test", Value: v}}
	}, "", nil},
	{"spec.upstreams[0].healthCheck.statusMatch", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).StatusMatch = v
	}, "200", nil},
	{"spec.upstreams[0].healthCheck.grpcService", func(vs *conf_v1.VirtualServer, v string) {
		hc := ensureVSHealthCheck(vs)
		hc.GRPCService = v
		vs.Spec.Upstreams[0].Type = "grpc"
	}, "", nil},
	{"spec.upstreams[0].healthCheck.keepalive-time", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSHealthCheck(vs).KeepaliveTime = v
	}, "60s", nil},

	// Session cookie
	{"spec.upstreams[0].sessionCookie.name", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSSessionCookie(vs).Name = v
	}, "", nil},
	{"spec.upstreams[0].sessionCookie.path", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSSessionCookie(vs).Path = v
	}, "/", nil},
	{"spec.upstreams[0].sessionCookie.expires", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSSessionCookie(vs).Expires = v
	}, "1h", nil},
	{"spec.upstreams[0].sessionCookie.domain", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSSessionCookie(vs).Domain = v
	}, "", nil},
	{"spec.upstreams[0].sessionCookie.samesite", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSSessionCookie(vs).SameSite = v
	}, "strict", nil},

	// Route
	{"spec.routes[0].path", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Routes[0].Path = v }, "/coffee", []string{
		`~ ^/tea";ip_hash;#"$`,
		`= /tea";ip_hash;#"`,
	}},
	{"spec.routes[0].action.pass", func(vs *conf_v1.VirtualServer, v string) { vs.Spec.Routes[0].Action.Pass = v }, "tea", nil},
	{"spec.routes[0].action.proxy.upstream", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSProxy(vs).Upstream = v
	}, "tea", nil},
	{"spec.routes[0].action.proxy.rewritePath", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSProxy(vs).RewritePath = v
	}, "/", nil},
	{"spec.routes[0].action.proxy.requestHeaders.set[0].name", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSRequestHeader(vs).Name = v
	}, "", nil},
	{"spec.routes[0].action.proxy.requestHeaders.set[0].value", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSRequestHeader(vs).Value = v
	}, "", nil},
	{"spec.routes[0].action.proxy.responseHeaders.add[0].name", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSResponseHeader(vs).Name = v
	}, "", nil},
	{"spec.routes[0].action.proxy.responseHeaders.add[0].value", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSResponseHeader(vs).Value = v
	}, "", nil},
	{"spec.routes[0].action.proxy.responseHeaders.hide[0]", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSResponseHeaders(vs).Hide = []string{v}
	}, "", nil},
	{"spec.routes[0].action.proxy.responseHeaders.pass[0]", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSResponseHeaders(vs).Pass = []string{v}
	}, "", nil},
	{"spec.routes[0].action.proxy.responseHeaders.ignore[0]", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSResponseHeaders(vs).Ignore = []string{v}
	}, "Expires", nil},
	{"spec.routes[0].action.redirect.url", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].Action = &conf_v1.Action{Redirect: &conf_v1.ActionRedirect{URL: v, Code: 301}}
	}, "http://example.com", nil},
	{"spec.routes[0].action.return.type", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].Action = &conf_v1.Action{Return: &conf_v1.ActionReturn{Type: v, Body: "hello"}}
	}, "", nil},
	{"spec.routes[0].action.return.body", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].Action = &conf_v1.Action{Return: &conf_v1.ActionReturn{Body: v}}
	}, "", nil},
	{"spec.routes[0].action.return.headers[0].name", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].Action = &conf_v1.Action{Return: &conf_v1.ActionReturn{
			Body: "hello", Headers: []conf_v1.Header{{Name: v, Value: "value"}},
		}}
	}, "", nil},
	{"spec.routes[0].action.return.headers[0].value", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].Action = &conf_v1.Action{Return: &conf_v1.ActionReturn{
			Body: "hello", Headers: []conf_v1.Header{{Name: "X-Test", Value: v}},
		}}
	}, "", nil},

	// Matches
	{"spec.routes[0].matches[0].conditions[0].header", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSCondition(vs).Header = v
	}, "", nil},
	{"spec.routes[0].matches[0].conditions[0].cookie", func(vs *conf_v1.VirtualServer, v string) {
		c := ensureVSCondition(vs)
		c.Header = ""
		c.Cookie = v
	}, "", nil},
	{"spec.routes[0].matches[0].conditions[0].argument", func(vs *conf_v1.VirtualServer, v string) {
		c := ensureVSCondition(vs)
		c.Header = ""
		c.Argument = v
	}, "", nil},
	{"spec.routes[0].matches[0].conditions[0].variable", func(vs *conf_v1.VirtualServer, v string) {
		c := ensureVSCondition(vs)
		c.Header = ""
		c.Variable = v
	}, "$request_uri", []string{`$request_uri";ip_hash;#"`}},
	{"spec.routes[0].matches[0].conditions[0].value", func(vs *conf_v1.VirtualServer, v string) {
		ensureVSCondition(vs).Value = v
	}, "", nil},

	// Error pages
	{"spec.routes[0].errorPages[0].redirect.url", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].ErrorPages = []conf_v1.ErrorPage{{
			Codes:    []int{404},
			Redirect: &conf_v1.ErrorPageRedirect{ActionRedirect: conf_v1.ActionRedirect{URL: v, Code: 301}},
		}}
	}, "http://example.com", nil},
	{"spec.routes[0].errorPages[0].return.body", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].ErrorPages = []conf_v1.ErrorPage{{
			Codes:  []int{404},
			Return: &conf_v1.ErrorPageReturn{ActionReturn: conf_v1.ActionReturn{Body: v}},
		}}
	}, "", nil},
	{"spec.routes[0].errorPages[0].return.type", func(vs *conf_v1.VirtualServer, v string) {
		vs.Spec.Routes[0].ErrorPages = []conf_v1.ErrorPage{{
			Codes:  []int{404},
			Return: &conf_v1.ErrorPageReturn{ActionReturn: conf_v1.ActionReturn{Type: v, Body: "hello"}},
		}}
	}, "", nil},
}

// TestVirtualServerCannotInjectConfiguration asserts, for the VirtualServer
// surface, the property already established for ConfigMap keys, Ingress
// annotations and TransportServers: a value carrying NGINX syntax is either
// rejected at admission or rendered as data.
//
// VirtualServer is the largest of the four surfaces and the one a namespace user
// most often has access to, so it carries the most fields whose only protection
// is admission validation.
func TestVirtualServerCannotInjectConfiguration(t *testing.T) {
	t.Parallel()

	for _, isPlus := range []bool{false, true} {
		var byValidation, admitted int
		for _, field := range virtualServerStringFields {
			// The baseline is this field carrying a value with no NGINX syntax,
			// not the field left unset, because setting a field can add structure
			// legitimately. See the TransportServer test.
			benign := virtualServerWithField(field, field.benignValue())

			validator := validation.NewVirtualServerValidator(validation.IsPlus(isPlus))
			// A Plus-only feature cannot be admitted on OSS; its protection there
			// is unavailability. Assert admission refuses it and skip.
			if field.plusOnly() && !isPlus {
				if validator.ValidateVirtualServer(benign) == nil {
					t.Errorf("plus=%v field=%s: Plus-only field admitted on OSS; the gate may have regressed", isPlus, field.name)
				}
				continue
			}
			// The benign value must survive admission, or every payload is
			// rejected for the shape of the fixture rather than its content.
			if err := validator.ValidateVirtualServer(benign); err != nil {
				t.Errorf("plus=%v field=%s: the benign value %q is rejected at admission, so the fixture is wrong: %v",
					isPlus, field.name, field.benignValue(), err)
				continue
			}

			baseline, err := shapeForVirtualServer(t, benign, isPlus)
			if err != nil {
				t.Errorf("plus=%v field=%s: baseline configuration does not tokenize: %v", isPlus, field.name, err)
				continue
			}

			payloads := append(append([]string{}, annotationInjectionPayloads...), field.extra...)
			for _, payload := range payloads {
				vs := virtualServerWithField(field, payload)

				if validation.NewVirtualServerValidator(validation.IsPlus(isPlus)).ValidateVirtualServer(vs) != nil {
					byValidation++
					continue
				}
				admitted++

				shape, err := shapeForVirtualServer(t, vs, isPlus)
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

func ensureVSProxy(vs *conf_v1.VirtualServer) *conf_v1.ActionProxy {
	if vs.Spec.Routes[0].Action.Proxy == nil {
		vs.Spec.Routes[0].Action = &conf_v1.Action{Proxy: &conf_v1.ActionProxy{Upstream: "tea"}}
	}
	return vs.Spec.Routes[0].Action.Proxy
}

func ensureVSRequestHeader(vs *conf_v1.VirtualServer) *conf_v1.Header {
	proxy := ensureVSProxy(vs)
	if proxy.RequestHeaders == nil {
		proxy.RequestHeaders = &conf_v1.ProxyRequestHeaders{Set: []conf_v1.Header{{Name: "X-Test", Value: "value"}}}
	}
	return &proxy.RequestHeaders.Set[0]
}

func ensureVSResponseHeaders(vs *conf_v1.VirtualServer) *conf_v1.ProxyResponseHeaders {
	proxy := ensureVSProxy(vs)
	if proxy.ResponseHeaders == nil {
		proxy.ResponseHeaders = &conf_v1.ProxyResponseHeaders{}
	}
	return proxy.ResponseHeaders
}

func ensureVSResponseHeader(vs *conf_v1.VirtualServer) *conf_v1.Header {
	headers := ensureVSResponseHeaders(vs)
	if len(headers.Add) == 0 {
		headers.Add = []conf_v1.AddHeader{{Header: conf_v1.Header{Name: "X-Test", Value: "value"}}}
	}
	return &headers.Add[0].Header
}

func ensureVSHealthCheck(vs *conf_v1.VirtualServer) *conf_v1.HealthCheck {
	if vs.Spec.Upstreams[0].HealthCheck == nil {
		vs.Spec.Upstreams[0].HealthCheck = &conf_v1.HealthCheck{Enable: true}
	}
	return vs.Spec.Upstreams[0].HealthCheck
}

func ensureVSSessionCookie(vs *conf_v1.VirtualServer) *conf_v1.SessionCookie {
	if vs.Spec.Upstreams[0].SessionCookie == nil {
		vs.Spec.Upstreams[0].SessionCookie = &conf_v1.SessionCookie{Enable: true, Name: "srv_id"}
	}
	return vs.Spec.Upstreams[0].SessionCookie
}

func ensureVSCondition(vs *conf_v1.VirtualServer) *conf_v1.Condition {
	if len(vs.Spec.Routes[0].Matches) == 0 {
		vs.Spec.Routes[0].Matches = []conf_v1.Match{{
			Conditions: []conf_v1.Condition{{Header: "x-test", Value: "value"}},
			Action:     &conf_v1.Action{Pass: "tea"},
		}}
	}
	return &vs.Spec.Routes[0].Matches[0].Conditions[0]
}

// baseVirtualServer is a VirtualServer that generates valid configuration, so a
// payload in one field is the only difference from the baseline.
func baseVirtualServer() *conf_v1.VirtualServer {
	return &conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{Name: "cafe", Namespace: "default"},
		Spec: conf_v1.VirtualServerSpec{
			Host: "cafe.example.com",
			Upstreams: []conf_v1.Upstream{
				{Name: "tea", Service: "tea-svc", Port: 80},
			},
			Routes: []conf_v1.Route{
				{Path: "/tea", Action: &conf_v1.Action{Pass: "tea"}},
			},
		},
	}
}

func virtualServerWithField(field virtualServerField, payload string) *conf_v1.VirtualServer {
	vs := baseVirtualServer()
	field.set(vs, payload)
	return vs
}

// shapeForVirtualServer renders the configuration the controller would write for a
// VirtualServer and returns its directive structure.
func shapeForVirtualServer(t *testing.T, vs *conf_v1.VirtualServer, isPlus bool) ([]string, error) {
	t.Helper()

	cnf, manager := configuratorForInjectionTest(t, isPlus)

	secretRefs := make(map[string]*secrets.SecretReference)
	if vs.Spec.TLS != nil && vs.Spec.TLS.Secret != "" {
		secretRefs[vs.Namespace+"/"+vs.Spec.TLS.Secret] = &secrets.SecretReference{}
	}

	vsEx := &configs.VirtualServerEx{
		VirtualServer: vs,
		Endpoints: map[string][]string{
			"default/tea-svc:80": {"10.0.0.20:80"},
		},
		SecretRefs: secretRefs,
	}
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

	// A VirtualServer configuration is a fragment of an http {} block, so wrap it
	// to give the tokenizer a balanced file.
	return nginxconf.Shape("http {\n" + rendered + "\n}\n")
}

// configuratorForInjectionTest builds a Configurator writing to a recording
// manager, so a test can inspect the configuration NGINX would have been given.
func configuratorForInjectionTest(t *testing.T, isPlus bool, staticConfig ...*configs.StaticConfigParams) (*configs.Configurator, *recordingManager) {
	t.Helper()

	mainTmpl, ingressTmpl := "version1/nginx.tmpl", "version1/nginx.ingress.tmpl"
	vsTmpl, tsTmpl := "version2/nginx.virtualserver.tmpl", "version2/nginx.transportserver.tmpl"
	if isPlus {
		mainTmpl, ingressTmpl = "version1/nginx-plus.tmpl", "version1/nginx-plus.ingress.tmpl"
		vsTmpl, tsTmpl = "version2/nginx-plus.virtualserver.tmpl", "version2/nginx-plus.transportserver.tmpl"
	}
	templateExecutor, err := version1.NewTemplateExecutor("../configs/"+mainTmpl, "../configs/"+ingressTmpl)
	if err != nil {
		t.Fatalf("cannot build template executor: %v", err)
	}
	templateExecutorV2, err := version2.NewTemplateExecutor("../configs/"+vsTmpl, "../configs/"+tsTmpl,
		"../configs/version2/oidc.tmpl")
	if err != nil {
		t.Fatalf("cannot build v2 template executor: %v", err)
	}

	manager := newRecordingManager()
	staticCfg := &configs.StaticConfigParams{}
	if len(staticConfig) > 0 {
		staticCfg = staticConfig[0]
	}
	return configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:       manager,
		StaticCfgParams:    staticCfg,
		Config:             configs.NewDefaultConfigParams(context.Background(), isPlus),
		MGMTCfgParams:      configs.NewDefaultMGMTConfigParams(context.Background()),
		TemplateExecutor:   templateExecutor,
		TemplateExecutorV2: templateExecutorV2,
		IsPlus:             isPlus,
		NginxVersion:       nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)"),
	}), manager
}
