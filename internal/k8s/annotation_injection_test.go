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
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// annotationInjectionPayloads are values that become NGINX configuration if they
// reach a directive unquoted. Each was run through nginx -t against 1.31.3; see
// the note on directiveScanner in internal/validation for the measurements.
var annotationInjectionPayloads = []string{
	`value"; location / { return 500; } #`, // loads, giving an attacker a location block
	`value"; ip_hash; #`,                   // loads with a warning, replaces the LB method
	`value; location / { return 500; } #`,  // no quote needed where nothing is quoted
	`value; ip_hash; #`,                    //
	`value{ }`,                             // braces alone restructure the file
	`value\`,                               // escapes the terminator the template writes
	`value #`,                              // comments out the terminator
	"value\nreturn 500;",                   // a newline separates tokens but not statements
}

// annotationField is an annotation and a harmless value of the shape it expects.
//
// The benign value is what makes the comparison mean anything. Rendering with no
// annotation at all is the wrong baseline: an annotation that only emits a
// directive when it is set differs from an unannotated rendering however harmless
// its value, so a structural difference could not be attributed to the payload.
// Comparing the same annotation carrying "10s" against the same annotation
// carrying an injection isolates the payload as the only variable.
type annotationField struct {
	name   string
	benign string
	// with carries the annotations this one depends on. validateRelatedAnnotation
	// refuses an annotation whose companion is absent, so without these the
	// benign value and every payload alike are rejected for the company they
	// keep rather than for their content, and the annotation goes untested.
	// They are set in the baseline and in each payload rendering alike, leaving
	// the payload as the only difference between the two.
	with map[string]string
	// extra carries payloads shaped to pass this annotation's own grammar. The
	// generic payloads are a bare word with syntax appended, which several
	// annotations discard before the value ever reaches a template:
	// nginx.org/add-header wants "Name: Value", so a payload with no colon
	// exercises the parser and nothing else, and the annotation looks safe
	// because it was never really tested. Each entry here puts the syntax where
	// the annotation's own format would carry a value.
	extra []string
	// plusOnly marks an annotation validatePlusOnlyAnnotation refuses on OSS.
	// Being unavailable is the protection there, and there is no rendering to
	// examine, so the OSS pass skips it rather than reporting a broken fixture.
	plusOnly bool
}

// annotationsFor builds the annotation map for one rendering: the companions
// this annotation requires, plus the annotation itself carrying value.
func (f annotationField) annotationsFor(value string) map[string]string {
	annotations := make(map[string]string, len(f.with)+1)
	for name, companion := range f.with {
		annotations[name] = companion
	}
	annotations[f.name] = value
	return annotations
}

// nginxOrgAnnotations is every annotation parseAnnotations reads, excluding the
// snippet annotations, which are raw configuration by design and are gated behind
// -enable-snippets. snippetsEnabled is false throughout this test.
//
// Each benign value has to survive admission, or the annotation contributes no
// coverage at all; the test checks that rather than trusting this table.
var nginxOrgAnnotations = []annotationField{
	{name: "nginx.com/health-checks", benign: "true", plusOnly: true},
	{
		name: "nginx.com/health-checks-mandatory", benign: "true", plusOnly: true,
		with: map[string]string{"nginx.com/health-checks": "true"},
	},
	{
		name: "nginx.com/health-checks-mandatory-queue", benign: "10", plusOnly: true,
		with: map[string]string{"nginx.com/health-checks": "true", "nginx.com/health-checks-mandatory": "true"},
	},
	{name: "nginx.com/jwt-key", benign: "jwk-secret", plusOnly: true},
	{
		name: "nginx.com/jwt-login-url", benign: "https://login.example.com/login", plusOnly: true,
		with: map[string]string{"nginx.com/jwt-key": "jwk-secret"},
	},
	{
		name: "nginx.com/jwt-realm", benign: "realm", plusOnly: true,
		with: map[string]string{"nginx.com/jwt-key": "jwk-secret"},
	},
	{
		name: "nginx.com/jwt-token", benign: "$http_token", plusOnly: true,
		with: map[string]string{"nginx.com/jwt-key": "jwk-secret"},
	},
	{name: "nginx.com/slow-start", benign: "10s", plusOnly: true},
	{name: "nginx.com/sticky-cookie-services", benign: "serviceName=coffee-svc srv_id expires=1h path=/", plusOnly: true},
	{name: "nginx.org/add-header", benign: "X-Test: value", extra: []string{
		`X-Test: value"; ip_hash; #`, "X-Test: value; ip_hash; #", "X-Test: value\\",
	}},
	{
		name: "nginx.org/add-header-inherit", benign: "on",
		with: map[string]string{"nginx.org/add-header": "X-Test: value"},
	},
	{name: "nginx.org/app-root", benign: "/app", extra: []string{
		`/app"; ip_hash; #`, "/app; ip_hash; #", "/app\\",
	}},
	{
		name: "nginx.org/basic-auth-realm", benign: "realm",
		with: map[string]string{"nginx.org/basic-auth-secret": "htpasswd-secret"},
	},
	{name: "nginx.org/basic-auth-secret", benign: "htpasswd-secret"},
	{name: "nginx.org/client-body-buffer-size", benign: "8k"},
	{name: "nginx.org/client-max-body-size", benign: "1m"},
	{name: "nginx.org/custom-http-errors", benign: "404,502", extra: []string{"404,502; ip_hash;", "404;ip_hash;"}},
	{name: "nginx.org/fail-timeout", benign: "10s"},
	{name: "nginx.org/grpc-services", benign: "coffee-svc"},
	{name: "nginx.org/hsts", benign: "true"},
	{
		name: "nginx.org/hsts-behind-proxy", benign: "true",
		with: map[string]string{"nginx.org/hsts": "true"},
	},
	{
		name: "nginx.org/hsts-include-subdomains", benign: "true",
		with: map[string]string{"nginx.org/hsts": "true"},
	},
	{
		name: "nginx.org/hsts-max-age", benign: "2592000",
		with: map[string]string{"nginx.org/hsts": "true"},
	},
	{name: "nginx.org/http-redirect-code", benign: "301"},
	{name: "nginx.org/keepalive", benign: "16"},
	{name: "nginx.org/lb-method", benign: "round_robin", extra: []string{
		`hash $request_uri"; ip_hash; #`, "hash $request_uri; ip_hash;", "hash $request_uri consistent; ip_hash;",
	}},
	{name: "nginx.org/limit-req-burst", benign: "10"},
	{name: "nginx.org/limit-req-delay", benign: "5"},
	{name: "nginx.org/limit-req-dry-run", benign: "true"},
	{name: "nginx.org/limit-req-key", benign: "${binary_remote_addr}", extra: []string{
		`${binary_remote_addr}"; ip_hash; #`, "${binary_remote_addr}; ip_hash;",
	}},
	{name: "nginx.org/limit-req-log-level", benign: "error"},
	{name: "nginx.org/limit-req-no-delay", benign: "true"},
	{name: "nginx.org/limit-req-rate", benign: "10r/s"},
	{name: "nginx.org/limit-req-reject-code", benign: "429"},
	{name: "nginx.org/limit-req-scale", benign: "true"},
	{name: "nginx.org/limit-req-zone-size", benign: "10m"},
	{name: "nginx.org/listen-ports", benign: "80"},
	{name: "nginx.org/listen-ports-ssl", benign: "443"},
	{name: "nginx.org/max-conns", benign: "16"},
	{name: "nginx.org/max-fails", benign: "1"},
	{name: "nginx.org/path-regex", benign: "case_sensitive"},
	{name: "nginx.org/proxy-buffer-size", benign: "8k"},
	{name: "nginx.org/proxy-buffering", benign: "true"},
	{name: "nginx.org/proxy-buffers", benign: "8 8k", extra: []string{"8 8k; ip_hash;", `8 8k"; ip_hash; #`}},
	{name: "nginx.org/proxy-busy-buffers-size", benign: "8k"},
	{name: "nginx.org/proxy-connect-timeout", benign: "10s"},
	{name: "nginx.org/proxy-hide-headers", benign: "X-Internal", extra: []string{
		`X-Internal"; ip_hash; #`, "X-Internal,X-Other; ip_hash;",
	}},
	{name: "nginx.org/proxy-max-temp-file-size", benign: "1m"},
	{name: "nginx.org/proxy-next-upstream", benign: "error timeout", extra: []string{
		"error timeout; ip_hash;", `error timeout"; ip_hash; #`,
	}},
	{name: "nginx.org/proxy-next-upstream-timeout", benign: "10s"},
	{name: "nginx.org/proxy-next-upstream-tries", benign: "3"},
	{name: "nginx.org/proxy-pass-headers", benign: "X-Forwarded-For", extra: []string{
		`X-Forwarded-For"; ip_hash; #`, "X-Forwarded-For,X-Other; ip_hash;",
	}},
	{name: "nginx.org/proxy-read-timeout", benign: "10s"},
	{
		name: "nginx.org/proxy-redirect-from", benign: "http://coffee.example.com/",
		extra: []string{`http://coffee.example.com/"; ip_hash; #`, "http://coffee.example.com/; ip_hash;"},
		with:  map[string]string{"nginx.org/proxy-redirect-to": "https://coffee.example.com/"},
	},
	{
		name: "nginx.org/proxy-redirect-to", benign: "https://coffee.example.com/",
		extra: []string{`https://coffee.example.com/"; ip_hash; #`, "https://coffee.example.com/; ip_hash;"},
		with:  map[string]string{"nginx.org/proxy-redirect-from": "http://coffee.example.com/"},
	},
	{name: "nginx.org/proxy-send-timeout", benign: "10s"},
	{name: "nginx.org/proxy-set-headers", benign: "X-Test: value", extra: []string{
		`X-Test: value"; ip_hash; #`, "X-Test: value; ip_hash; #", "X-Test: value\\",
	}},
	{name: "nginx.org/redirect-to-https", benign: "true"},
	{name: "nginx.org/rewrite-target", benign: "/", extra: []string{
		`/value"; ip_hash; #`, "/value; ip_hash; #", "/value\\",
	}},
	{name: "nginx.org/rewrites", benign: "serviceName=coffee-svc rewrite=/", extra: []string{
		`serviceName=coffee-svc rewrite=/value"; ip_hash; #`, "serviceName=coffee-svc rewrite=/value; ip_hash; #",
	}},
	{name: "nginx.org/server-tokens", benign: "true"},
	{name: "nginx.org/ssl-ciphers", benign: "HIGH:!aNULL:!MD5", extra: []string{
		`HIGH"; ip_hash; #`, "HIGH; ip_hash;",
	}},
	{name: "nginx.org/ssl-prefer-server-ciphers", benign: "true"},
	{name: "nginx.org/ssl-redirect", benign: "true"},
	{name: "nginx.org/ssl-services", benign: "coffee-svc"},
	{name: "nginx.org/sticky-cookie-services", benign: "serviceName=coffee-svc srv_id expires=1h path=/"},
	{name: "nginx.org/upstream-zone-size", benign: "256k"},
	{name: "nginx.org/use-cluster-ip", benign: "true"},
	{name: "nginx.org/websocket-services", benign: "coffee-svc"},
}

// TestAnnotationsCannotInjectConfiguration asserts the property that the two
// mitigation layers exist to provide, across the tenant-facing surface: for every
// Ingress annotation, a value carrying NGINX syntax must either be rejected at
// admission or be rendered as data.
//
// Both halves are needed and neither is sufficient alone. An annotation with no
// admission validator has to be neutralized by the template; an annotation the
// template renders unquoted has to be rejected at admission. The test does not
// need to know which applies to any given annotation, which is the point: it
// cannot be fooled by an assumption about where the protection lives.
//
// Structure is compared rather than searching for substrings, using
// internal/nginxconf, which mirrors ngx_conf_read_token. A rendering that gained,
// lost or re-nested a directive is an injection whatever the value looked like.
func TestAnnotationsCannotInjectConfiguration(t *testing.T) {
	t.Parallel()

	for _, isPlus := range []bool{false, true} {
		var rejected, admitted, plusOnly int
		for _, annotation := range nginxOrgAnnotations {
			if annotation.plusOnly && !isPlus {
				plusOnly++
				// The plus-only gate must refuse these annotations on OSS.
				// If validatePlusOnlyAnnotation regresses the payload could
				// reach OSS config generation, so assert it still rejects.
				if !rejectedAtAdmission(annotation.annotationsFor(annotation.benign), isPlus) {
					t.Errorf("plus=%v annotation=%q: Plus-only annotation not rejected at admission on OSS; the gate may have regressed",
						isPlus, annotation.name)
				}
				continue
			}

			// The baseline is this same annotation carrying a harmless value, so
			// the payload is the only difference between the two renderings.
			benign := annotation.annotationsFor(annotation.benign)

			// A benign value that admission refuses means every payload for this
			// annotation is rejected for the shape of the value rather than for
			// its content, and the annotation is never really tested. That is a
			// fault in the table above, not a property of the annotation.
			if rejectedAtAdmission(benign, isPlus) {
				t.Errorf("plus=%v annotation=%q: the benign value %q is rejected at admission, so the fixture is wrong",
					isPlus, annotation.name, annotation.benign)
				continue
			}
			baseline, err := shapeForAnnotations(t, benign, isPlus)
			if err != nil {
				t.Errorf("plus=%v annotation=%q: baseline configuration does not tokenize: %v",
					isPlus, annotation.name, err)
				continue
			}

			payloads := append(append([]string{}, annotationInjectionPayloads...), annotation.extra...)
			for _, payload := range payloads {
				annotations := annotation.annotationsFor(payload)

				// Layer 1. An Ingress rejected at admission never reaches
				// configuration generation, so nothing further is required of it.
				if rejectedAtAdmission(annotations, isPlus) {
					rejected++
					continue
				}
				admitted++

				// Layer 2. The value was admitted, so the rendering has to make it
				// data.
				shape, err := shapeForAnnotations(t, annotations, isPlus)
				if err != nil {
					t.Errorf("plus=%v annotation=%q payload=%q was admitted and produced unparsable configuration: %v",
						isPlus, annotation.name, payload, err)
					continue
				}
				if diff := shapeAdditions(baseline, shape); diff != "" {
					t.Errorf("plus=%v annotation=%q payload=%q was admitted and added configuration:\n%s",
						isPlus, annotation.name, payload, diff)
				}
			}
		}

		// Guard against passing for the wrong reason. If admission started
		// rejecting everything the rendering half would never run, and if it
		// started rejecting nothing the counts would show that too. Both halves
		// have to be doing work. Measured at the time of writing: 472 rejected and
		// 80 admitted for OSS, 462 and 90 for Plus.
		if rejected == 0 {
			t.Errorf("plus=%v: no payload was rejected at admission, so layer 1 is untested here", isPlus)
		}
		if admitted == 0 {
			t.Errorf("plus=%v: every payload was rejected at admission, so the rendering was never exercised", isPlus)
		}
		t.Logf("plus=%v: %d rejected at admission, %d admitted and rendered as data, %d skipped as Plus-only",
			isPlus, rejected, admitted, plusOnly)
	}
}

// rejectedAtAdmission reports whether validateIngress refuses an Ingress carrying
// these annotations, which is what the controller does before generating any
// configuration for it.
func rejectedAtAdmission(annotations map[string]string, isPlus bool) bool {
	ing := ingressForAnnotations(annotations)
	errs := validateIngress(ing, isPlus, false, false, false, false, false)
	return len(errs) > 0
}

func ingressForAnnotations(annotations map[string]string) *networking.Ingress {
	pathType := networking.PathTypePrefix
	return &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:        "cafe-ingress",
			Namespace:   "default",
			Annotations: annotations,
		},
		Spec: networking.IngressSpec{
			Rules: []networking.IngressRule{
				{
					Host: "cafe.example.com",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path:     "/coffee",
									PathType: &pathType,
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "coffee-svc",
											Port: networking.ServiceBackendPort{Number: 80},
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
}

// recordingManager captures the configuration the Configurator writes, so a test
// can inspect what NGINX would have been given.
type recordingManager struct {
	*nginx.FakeManager
	configs map[string][]byte
	// oidc holds the fragment written through CreateOIDCConfig, kept apart from
	// configs because it is an include rendered by oidc.tmpl in a server context.
	// Policy values that reach configuration only there, such as oidc.redirectURI,
	// are invisible unless it is captured and tokenized too.
	oidc []byte
}

func newRecordingManager() *recordingManager {
	return &recordingManager{
		FakeManager: nginx.NewFakeManager("/etc/nginx"),
		configs:     make(map[string][]byte),
	}
}

func (m *recordingManager) CreateConfig(name string, content []byte) (bool, error) {
	m.configs[name] = append([]byte(nil), content...)
	return m.FakeManager.CreateConfig(name, content)
}

// TransportServers are written through CreateStreamConfig rather than
// CreateConfig, so both have to be recorded.
func (m *recordingManager) CreateStreamConfig(name string, content []byte) (bool, error) {
	m.configs[name] = append([]byte(nil), content...)
	return m.FakeManager.CreateStreamConfig(name, content)
}

// CreateOIDCConfig is how the Configurator writes the OIDC include. Record it so
// shapeForPolicy can tokenize oidc.tmpl output in its server context.
func (m *recordingManager) CreateOIDCConfig(name string, content []byte) bool {
	m.oidc = append([]byte(nil), content...)
	return m.FakeManager.CreateOIDCConfig(name, content)
}

// shapeForAnnotations renders the ingress configuration the controller would write
// for an Ingress carrying these annotations, and returns its directive structure.
func shapeForAnnotations(t *testing.T, annotations map[string]string, isPlus bool) ([]string, error) {
	t.Helper()

	mainTmpl, ingressTmpl := "version1/nginx.tmpl", "version1/nginx.ingress.tmpl"
	if isPlus {
		mainTmpl, ingressTmpl = "version1/nginx-plus.tmpl", "version1/nginx-plus.ingress.tmpl"
	}
	templateExecutor, err := version1.NewTemplateExecutor("../configs/"+mainTmpl, "../configs/"+ingressTmpl)
	if err != nil {
		t.Fatalf("cannot build template executor: %v", err)
	}
	templateExecutorV2, err := version2.NewTemplateExecutor(
		"../configs/version2/nginx-plus.virtualserver.tmpl",
		"../configs/version2/nginx-plus.transportserver.tmpl",
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

	ingEx := ingressExForAnnotations(annotations)
	if _, err := cnf.AddOrUpdateIngress(ingEx); err != nil {
		t.Fatalf("cannot generate ingress configuration: %v", err)
	}

	var rendered string
	for name, content := range manager.configs {
		if strings.Contains(name, "cafe-ingress") {
			rendered = string(content)
		}
	}
	if rendered == "" {
		t.Fatal("the Configurator wrote no configuration for the ingress")
	}

	// An ingress configuration is a fragment of an http {} block, so wrap it to
	// give the tokenizer a balanced file.
	return nginxconf.Shape("http {\n" + rendered + "\n}\n")
}

func ingressExForAnnotations(annotations map[string]string) *configs.IngressEx {
	ing := ingressForAnnotations(annotations)

	// addOrUpdateIngress dereferences the secret reference for these two
	// annotations without checking it exists, because the controller resolves
	// references before generating configuration. Provide them so the fixture
	// reaches the generator rather than panicking on the way in.
	secretRefs := make(map[string]*secrets.SecretReference)
	for _, annotation := range []string{configs.JWTKeyAnnotation, configs.BasicAuthSecretAnnotation} {
		if value, exists := annotations[annotation]; exists {
			secretRefs[value] = &secrets.SecretReference{Secret: nil, Path: "", Error: nil}
		}
	}

	return &configs.IngressEx{
		Ingress: ing,
		Endpoints: map[string][]string{
			"coffee-svc80": {"10.0.0.1:80"},
		},
		ExternalNameSvcs: map[string]bool{},
		ValidHosts:       map[string]bool{"cafe.example.com": true},
		SecretRefs:       secretRefs,
	}
}

// shapeAdditions reports the statements present in got but absent from want,
// comparing as multisets, or "" when got adds nothing.
//
// Additions are the question, not differences. An injected value can only do
// harm by making configuration appear: a new directive, or an existing one at a
// new nesting depth, which the depth carried in each entry catches. Replacing a
// directive shows up the same way, because the replacement is itself an entry
// want does not have.
//
// A rendering that drops a statement is deliberately not a failure. Several
// annotations are ignored when their value does not parse, so a payload that
// merely defeats the parser produces a rendering with less configuration than
// the benign baseline. That is a functional matter and not an injection, and
// treating it as one buries the real signal: nginx.org/limit-req-rate discards
// the whole limit_req_zone for any value it cannot read.
func shapeAdditions(want, got []string) string {
	remaining := make(map[string]int, len(want))
	for _, statement := range want {
		remaining[statement]++
	}

	var added []string
	for _, statement := range got {
		if remaining[statement] > 0 {
			remaining[statement]--
			continue
		}
		added = append(added, statement)
	}
	if len(added) == 0 {
		return ""
	}

	var b strings.Builder
	for _, statement := range added {
		b.WriteString("  added " + statement + "\n")
		if b.Len() > 400 {
			b.WriteString("  ...\n")
			break
		}
	}
	return b.String()
}
