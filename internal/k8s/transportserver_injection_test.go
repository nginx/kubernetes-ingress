package k8s

import (
	"context"
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

// transportServerField names a string field of a TransportServer and the function
// that writes a value into it, so the property can be asserted field by field.
type transportServerField struct {
	name string
	set  func(*conf_v1.TransportServer, string)
	// benign is a harmless value of the shape this field requires. It defaults to
	// "value", which suits a free-form string but not a field the CRD constrains
	// with a pattern, where a baseline the API server would reject would measure
	// the fixture rather than the field.
	benign string
	// extra carries payloads shaped to pass this field's own grammar. A field
	// whose generator only emits recognized forms is never exercised by the
	// generic payloads: loadBalancingMethod reaches configuration only when the
	// value looks like "hash <key> [consistent]", so a payload that does not
	// would be silently dropped and the field would appear safe.
	extra []string
}

// transportServerStringFields is every user-controlled string in a
// TransportServer that reaches generated configuration, excluding the snippets,
// which are raw configuration by design and gated behind -enable-snippets.
//
// Fields typed as int, bool or pointer-to-int cannot carry NGINX syntax and are
// omitted; the Kubernetes API server rejects a non-integer before NIC sees it.
func (f transportServerField) benignValue() string {
	if f.benign != "" {
		return f.benign
	}
	return "value"
}

var transportServerStringFields = []transportServerField{
	// A non-TLS-Passthrough TransportServer requires spec.tls.secret when host is
	// set, so give the host a TLS companion; without it every payload is rejected
	// for the missing secret rather than for the host value.
	{"spec.host", func(ts *conf_v1.TransportServer, v string) {
		ts.Spec.TLS = &conf_v1.TransportServerTLS{Secret: "tls-secret"}
		ts.Spec.Host = v
	}, "cafe.example.com", nil},
	{"spec.listener.name", func(ts *conf_v1.TransportServer, v string) { ts.Spec.Listener.Name = v }, "", nil},
	{"spec.listener.protocol", func(ts *conf_v1.TransportServer, v string) { ts.Spec.Listener.Protocol = v }, "TCP", nil},
	{"spec.tls.secret", func(ts *conf_v1.TransportServer, v string) {
		ts.Spec.TLS = &conf_v1.TransportServerTLS{Secret: v}
	}, "", nil},
	{"spec.upstreams[0].name", func(ts *conf_v1.TransportServer, v string) {
		ts.Spec.Upstreams[0].Name = v
		ts.Spec.Action.Pass = v
	}, "", nil},
	{"spec.upstreams[0].service", func(ts *conf_v1.TransportServer, v string) { ts.Spec.Upstreams[0].Service = v }, "tcp-app-svc", nil},
	{"spec.upstreams[0].failTimeout", func(ts *conf_v1.TransportServer, v string) { ts.Spec.Upstreams[0].FailTimeout = v }, "10s", nil},
	{"spec.upstreams[0].loadBalancingMethod", func(ts *conf_v1.TransportServer, v string) {
		ts.Spec.Upstreams[0].LoadBalancingMethod = v
	}, "round_robin", []string{
		`hash $remote_addr";ip_hash;#" consistent`,
		`hash $remote_addr;ip_hash;# consistent`,
		`hash $remote_addr\ consistent`,
	}},
	{"spec.upstreams[0].backup", func(ts *conf_v1.TransportServer, v string) {
		ts.Spec.Upstreams[0].Backup = v
		port := uint16(5002)
		ts.Spec.Upstreams[0].BackupPort = &port
	}, "backup-svc", nil},
	{"spec.upstreams[0].healthCheck.interval", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerHealthCheck(ts).Interval = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.timeout", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerHealthCheck(ts).Timeout = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.jitter", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerHealthCheck(ts).Jitter = v
	}, "5s", nil},
	{"spec.upstreams[0].healthCheck.match.send", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerMatch(ts).Send = v
	}, "", nil},
	{"spec.upstreams[0].healthCheck.match.expect", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerMatch(ts).Expect = v
	}, "", nil},
	{"spec.upstreamParameters.connectTimeout", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerUpstreamParameters(ts).ConnectTimeout = v
	}, "10s", nil},
	{"spec.upstreamParameters.nextUpstreamTimeout", func(ts *conf_v1.TransportServer, v string) {
		ensureTransportServerUpstreamParameters(ts).NextUpstreamTimeout = v
	}, "10s", nil},
	{"spec.sessionParameters.timeout", func(ts *conf_v1.TransportServer, v string) {
		ts.Spec.SessionParameters = &conf_v1.SessionParameters{Timeout: v}
	}, "10s", nil},
	{"spec.action.pass", func(ts *conf_v1.TransportServer, v string) { ts.Spec.Action.Pass = v }, "tcp-app", nil},
	{"spec.ingressClassName", func(ts *conf_v1.TransportServer, v string) { ts.Spec.IngressClass = v }, "", nil},
}

// TestTransportServerCannotInjectConfiguration asserts, for the TransportServer
// surface, the property already established for ConfigMap keys and Ingress
// annotations: a value carrying NGINX syntax is either rejected at admission or
// rendered as data.
//
// A TransportServer writes into the stream {} context rather than http {}, so the
// directives available to an attacker differ, but the mechanism is identical: a
// semicolon that ends the host directive, a brace that opens a block.
func TestTransportServerCannotInjectConfiguration(t *testing.T) {
	t.Parallel()

	for _, isPlus := range []bool{false, true} {
		var byValidation, admitted int
		for _, field := range transportServerStringFields {
			// The baseline is this same field carrying a value with no NGINX
			// syntax in it, not the field left unset. Setting a field can add
			// structure legitimately: writing healthCheck.match.send produces a
			// match {} block that an empty TransportServer does not have. Comparing
			// against the unset form would report that as an injection. Every
			// payload begins with "value", so this isolates the syntax from the
			// presence of the field.
			benign := transportServerWithField(field, field.benignValue())

			// The benign value must survive admission, or every payload is
			// rejected for the shape of the fixture rather than its content.
			if err := validation.NewTransportServerValidator(false, false, isPlus).ValidateTransportServer(benign); err != nil {
				t.Errorf("plus=%v field=%s: the benign value %q is rejected at admission, so the fixture is wrong: %v",
					isPlus, field.name, field.benignValue(), err)
				continue
			}

			baseline, err := shapeForTransportServer(t, benign, isPlus)
			if err != nil {
				t.Errorf("plus=%v field=%s: baseline configuration does not tokenize: %v", isPlus, field.name, err)
				continue
			}

			payloads := append(append([]string{}, annotationInjectionPayloads...), field.extra...)
			for _, payload := range payloads {
				ts := transportServerWithField(field, payload)

				if validation.NewTransportServerValidator(false, false, isPlus).ValidateTransportServer(ts) != nil {
					byValidation++
					continue
				}
				admitted++

				// Layer 2. It was admitted, so the rendering has to make it data.
				shape, err := shapeForTransportServer(t, ts, isPlus)
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

func ensureTransportServerHealthCheck(ts *conf_v1.TransportServer) *conf_v1.TransportServerHealthCheck {
	if ts.Spec.Upstreams[0].HealthCheck == nil {
		ts.Spec.Upstreams[0].HealthCheck = &conf_v1.TransportServerHealthCheck{Enabled: true}
	}
	return ts.Spec.Upstreams[0].HealthCheck
}

func ensureTransportServerMatch(ts *conf_v1.TransportServer) *conf_v1.TransportServerMatch {
	hc := ensureTransportServerHealthCheck(ts)
	if hc.Match == nil {
		hc.Match = &conf_v1.TransportServerMatch{}
	}
	return hc.Match
}

func ensureTransportServerUpstreamParameters(ts *conf_v1.TransportServer) *conf_v1.UpstreamParameters {
	if ts.Spec.UpstreamParameters == nil {
		ts.Spec.UpstreamParameters = &conf_v1.UpstreamParameters{}
	}
	return ts.Spec.UpstreamParameters
}

// baseTransportServer is a TransportServer that generates valid configuration, so
// that a payload in one field is the only difference from the baseline.
func baseTransportServer() *conf_v1.TransportServer {
	return &conf_v1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{Name: "tcp-server", Namespace: "default"},
		Spec: conf_v1.TransportServerSpec{
			Listener: conf_v1.TransportServerListener{Name: "tcp-listener", Protocol: "TCP"},
			Upstreams: []conf_v1.TransportServerUpstream{
				{Name: "tcp-app", Service: "tcp-app-svc", Port: 5001},
			},
			Action: &conf_v1.TransportServerAction{Pass: "tcp-app"},
		},
	}
}

func transportServerWithField(field transportServerField, payload string) *conf_v1.TransportServer {
	ts := baseTransportServer()
	field.set(ts, payload)
	return ts
}

// shapeForTransportServer renders the configuration the controller would write for
// a TransportServer and returns its directive structure. A nil TransportServer
// renders the baseline.
func shapeForTransportServer(t *testing.T, ts *conf_v1.TransportServer, isPlus bool) ([]string, error) {
	t.Helper()

	if ts == nil {
		ts = baseTransportServer()
	}

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
	cnf := configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:       manager,
		StaticCfgParams:    &configs.StaticConfigParams{},
		Config:             configs.NewDefaultConfigParams(context.Background(), isPlus),
		MGMTCfgParams:      configs.NewDefaultMGMTConfigParams(context.Background()),
		TemplateExecutor:   templateExecutor,
		TemplateExecutorV2: templateExecutorV2,
		IsPlus:             isPlus,
		NginxVersion:       nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)"),
	})

	// generateSSLConfig dereferences the secret reference without checking it
	// exists, because the controller resolves references before generating
	// configuration. Provide one so a TransportServer carrying spec.tls.secret
	// reaches the generator rather than panicking on the way in.
	secretRefs := make(map[string]*secrets.SecretReference)
	if ts.Spec.TLS != nil {
		secretRefs[ts.Namespace+"/"+ts.Spec.TLS.Secret] = &secrets.SecretReference{}
	}

	tsEx := &configs.TransportServerEx{
		ListenerPort:    2020,
		TransportServer: ts,
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {"10.0.0.20:5001"},
		},
		SecretRefs: secretRefs,
	}
	if _, err := cnf.AddOrUpdateTransportServer(tsEx); err != nil {
		t.Fatalf("cannot generate TransportServer configuration: %v", err)
	}

	var rendered string
	for name, content := range manager.configs {
		if name != "" {
			rendered = string(content)
		}
	}
	if rendered == "" {
		t.Fatal("the Configurator wrote no configuration for the TransportServer")
	}

	// A TransportServer configuration is a fragment of a stream {} block, so wrap
	// it to give the tokenizer a balanced file.
	return nginxconf.Shape("stream {\n" + rendered + "\n}\n")
}
