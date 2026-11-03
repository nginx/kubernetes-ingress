package configs

import (
	"context"
	"strings"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/nginxconf"
	v1 "k8s.io/api/core/v1"
)

// injectionPayloads are values that turn into NGINX configuration if they reach a
// directive unquoted. Each was run through nginx -t against 1.31.3.
//
// The quote in the first two is not the hazard and is only there because the
// audit reported it; the semicolon is what ends the host directive. The bare
// forms are included because a field may be reached without needing to escape a
// quoted argument first.
var injectionPayloads = []string{
	`value"; location / { return 500; } #`, // loads, giving an attacker a location block
	`value"; ip_hash; #`,                   // loads with a warning, replaces the LB method
	`value; location / { return 500; } #`,  // no quote needed where nothing is quoted
	`value; ip_hash; #`,                    //
	`value{ }`,                             // braces alone restructure the file
	`value\`,                               // escapes the terminator the template writes
	`value #`,                              // comments out the terminator
}

// configMapKey is a ConfigMap key the injection test drives, with a harmless
// value that differs from the default and any keys it needs to reach a
// template. Companions are set in every run for that key, so the comparison is
// against the same configuration with only the key under test changed.
type configMapKey struct {
	key        string
	benign     string
	companions map[string]string
}

var (
	otelEndpoint = map[string]string{"otel-exporter-endpoint": "https://otel.example.com:4317"}
	zoneSyncOn   = map[string]string{"zone-sync": "true"}
)

// configMapKeys is every key ParseConfigMap reads, except snippet and template
// keys, which are raw configuration by design.
var configMapKeys = []configMapKey{
	{key: "access-log", benign: "syslog:server=localhost:514"},
	{key: "access-log-off", benign: "true"},
	{key: "add-header", benign: "X-Test: value"},
	{key: "add-header-inherit", benign: "merge", companions: map[string]string{"add-header": "X-Test: value"}},
	{key: "app-protect-compressed-requests-action", benign: "drop"},
	{key: "app-protect-cookie-seed", benign: "abcdefghijklmnopqrstuvwxyz012345"},
	{key: "app-protect-cpu-thresholds", benign: "high=90 low=80"},
	{key: "app-protect-dos-arb-fqdn", benign: "arb.example.com"},
	{key: "app-protect-dos-log-format", benign: "$remote_addr"},
	{key: "app-protect-dos-log-format-escaping", benign: "json", companions: map[string]string{"app-protect-dos-log-format": "$remote_addr"}},
	{key: "app-protect-failure-mode-action", benign: "drop"},
	{key: "app-protect-physical-memory-util-thresholds", benign: "high=90 low=80"},
	{key: "app-protect-reconnect-period-seconds", benign: "10"},
	{key: "client-body-buffer-size", benign: "16k"},
	{key: "client-max-body-size", benign: "2m"},
	{key: "default-server-access-log-off", benign: "true"},
	{key: "default-server-return", benign: "302 https://example.com/#/home"},
	{key: "disable-forwarded-headers", benign: "true"},
	{key: "error-log-level", benign: "warn"},
	{key: "fail-timeout", benign: "20s"},
	{key: "hsts", benign: "true"},
	{key: "hsts-behind-proxy", benign: "true", companions: map[string]string{"hsts": "true"}},
	{key: "hsts-include-subdomains", benign: "true", companions: map[string]string{"hsts": "true"}},
	{key: "hsts-max-age", benign: "100", companions: map[string]string{"hsts": "true"}},
	{key: "http-redirect-code", benign: "308"},
	{key: "http2", benign: "true"},
	{key: "keepalive", benign: "32"},
	{key: "keepalive-requests", benign: "500"},
	{key: "keepalive-timeout", benign: "30s"},
	{key: "lb-method", benign: "least_conn"},
	{key: "log-format", benign: "$remote_addr"},
	{key: "log-format-escaping", benign: "json", companions: map[string]string{"log-format": "$remote_addr"}},
	{key: "map-hash-bucket-size", benign: "128"},
	{key: "map-hash-max-size", benign: "4096"},
	{key: "max-fails", benign: "3"},
	{key: "oidc-access-tokens-timeout", benign: "2h"},
	{key: "oidc-access-tokens-zone-size", benign: "2m"},
	{key: "oidc-id-tokens-timeout", benign: "2h"},
	{key: "oidc-id-tokens-zone-size", benign: "2m"},
	{key: "oidc-pkce-timeout", benign: "2m"},
	{key: "oidc-pkce-zone-size", benign: "2m"},
	{key: "oidc-refresh-tokens-timeout", benign: "2h"},
	{key: "oidc-refresh-tokens-zone-size", benign: "2m"},
	{key: "oidc-sids-timeout", benign: "2h"},
	{key: "oidc-sids-zone-size", benign: "2m"},
	{key: "otel-exporter-endpoint", benign: "https://otel.example.com:4317"},
	{key: "otel-exporter-header-name", benign: "X-Tenant", companions: map[string]string{"otel-exporter-endpoint": "https://otel.example.com:4317", "otel-exporter-header-value": "blue"}},
	{key: "otel-exporter-header-value", benign: "blue", companions: map[string]string{"otel-exporter-endpoint": "https://otel.example.com:4317", "otel-exporter-header-name": "X-Tenant"}},
	{key: "otel-service-name", benign: "nginx-ingress", companions: otelEndpoint},
	{key: "otel-trace-context", benign: "inject", companions: otelEndpoint},
	{key: "otel-trace-in-http", benign: "true", companions: otelEndpoint},
	{key: "proxy-buffer-size", benign: "8k"},
	{key: "proxy-buffering", benign: "false"},
	{key: "proxy-buffers", benign: "8 8k"},
	{key: "proxy-busy-buffers-size", benign: "16k"},
	{key: "proxy-connect-timeout", benign: "30s"},
	{key: "proxy-hide-headers", benign: "X-Hide"},
	{key: "proxy-max-temp-file-size", benign: "0"},
	{key: "proxy-pass-headers", benign: "X-Pass"},
	{key: "proxy-protocol", benign: "true"},
	{key: "proxy-read-timeout", benign: "30s"},
	{key: "proxy-send-timeout", benign: "30s"},
	{key: "real-ip-header", benign: "X-Forwarded-For"},
	{key: "real-ip-recursive", benign: "true"},
	{key: "redirect-to-https", benign: "true"},
	{key: "resolver-addresses", benign: "10.0.0.10"},
	{key: "resolver-ipv6", benign: "false", companions: map[string]string{"resolver-addresses": "10.0.0.10"}},
	{key: "resolver-timeout", benign: "10s"},
	{key: "resolver-valid", benign: "5m", companions: map[string]string{"resolver-addresses": "10.0.0.10"}},
	{key: "server-names-hash-bucket-size", benign: "512"},
	{key: "server-names-hash-max-size", benign: "2048"},
	{key: "server-tokens", benign: "off"},
	{key: "set-real-ip-from", benign: "10.0.0.0/8"},
	{key: "ssl-ciphers", benign: "HIGH:!aNULL:!MD5"},
	{key: "ssl-dhparam-file", benign: "dhparam"},
	{key: "ssl-prefer-server-ciphers", benign: "true"},
	{key: "ssl-protocols", benign: "TLSv1.3"},
	{key: "ssl-redirect", benign: "false"},
	{key: "stream-log-format", benign: "$remote_addr"},
	{key: "stream-log-format-escaping", benign: "json", companions: map[string]string{"stream-log-format": "$remote_addr"}},
	{key: "upstream-zone-size", benign: "1m"},
	{key: "use-forwarded-headers", benign: "true"},
	{key: "variables-hash-bucket-size", benign: "512"},
	{key: "variables-hash-max-size", benign: "2048"},
	{key: "worker-connections", benign: "2048"},
	{key: "worker-cpu-affinity", benign: "auto"},
	{key: "worker-processes", benign: "2"},
	{key: "worker-rlimit-nofile", benign: "65535"},
	{key: "worker-shutdown-timeout", benign: "30s"},
	{key: "zone-sync", benign: "true"},
	{key: "zone-sync-port", benign: "12346", companions: zoneSyncOn},
	{key: "zone-sync-resolver-addresses", benign: "10.0.0.10", companions: zoneSyncOn},
	{key: "zone-sync-resolver-ipv6", benign: "false", companions: zoneSyncOn},
	{key: "zone-sync-resolver-valid", benign: "10s", companions: zoneSyncOn},
}

// notRendered lists keys whose value never reaches the configurations this
// test renders, with the reason. Every other key must change the rendered
// output when set to its benign value, or the test fails: a key that renders
// nothing passes the shape comparison without proving anything.
var notRendered = map[string]string{
	"ssl-dhparam-file": "written to a file by the configurator; the template only references its path",
}

// TestConfigMapCannotInjectConfiguration asserts the property the two mitigation
// layers exist to provide: for every ConfigMap key, a value carrying NGINX syntax
// must not change the directive structure of the generated configuration.
//
// It compares shapes rather than looking for substrings, so it does not need to
// know which layer protects any given key. A key is safe if validation rejected
// the value and the default was kept, or if the template rendered it as data.
// So the shape of an injection run must match the run without the key, the run
// with its benign value, or the run with a plain invalid value. Anything else
// means the NGINX syntax in the payload gained, lost or re-nested a directive.
//
// internal/nginxconf mirrors ngx_conf_read_token, so "changed shape" means what
// NGINX would do, not what a regex guesses.
func TestConfigMapCannotInjectConfiguration(t *testing.T) {
	t.Parallel()

	// Most of these keys are per-server or per-location defaults that appear only
	// in a generated ingress configuration, so every output has to be checked.
	// Checking only the main configuration silently passes for every one of them.
	renders := []struct {
		name string
		fn   func(*testing.T, map[string]string, bool) string
	}{
		{"main", renderConfigMapMain},
		{"ingress", renderConfigMapIngress},
		{"default-server", renderConfigMapDefaultServer},
	}

	for _, k := range configMapKeys {
		rendered := false
		for _, nginxPlus := range []bool{false, true} {
			for _, render := range renders {
				data := func(value string) map[string]string {
					m := map[string]string{k.key: value}
					for ck, cv := range k.companions {
						m[ck] = cv
					}
					return m
				}

				baselineText := render.fn(t, k.companions, nginxPlus)
				benignText := render.fn(t, data(k.benign), nginxPlus)
				if baselineText != benignText {
					rendered = true
				}

				baseline := mustShape(t, baselineText, "plus=%v %s key=%q baseline", nginxPlus, render.name, k.key)
				benign := mustShape(t, benignText, "plus=%v %s key=%q benign=%q", nginxPlus, render.name, k.key, k.benign)
				// A plain word with no NGINX syntax. Some rejections switch off
				// more than the key (an HSTS error drops all HSTS settings), so
				// a payload is also safe if it does exactly what any invalid
				// value does: then its syntax had no effect.
				rejected := mustShape(t, render.fn(t, data("x"), nginxPlus), "plus=%v %s key=%q plain invalid value", nginxPlus, render.name, k.key)

				for _, payload := range injectionPayloads {
					shape, err := nginxconf.Shape(render.fn(t, data(payload), nginxPlus))
					if err != nil {
						// A value that makes the configuration untokenizable is as
						// bad as one that restructures it: NGINX would refuse to
						// load.
						t.Errorf("plus=%v %s key=%q payload=%q produced unparsable configuration: %v",
							nginxPlus, render.name, k.key, payload, err)
						continue
					}
					if shapeDiff(baseline, shape) != "" && shapeDiff(benign, shape) != "" && shapeDiff(rejected, shape) != "" {
						t.Errorf("plus=%v %s key=%q payload=%q changed the directive structure:\n%s",
							nginxPlus, render.name, k.key, payload, shapeDiff(baseline, shape))
					}
				}
			}
		}

		_, exempt := notRendered[k.key]
		if !rendered && !exempt {
			t.Errorf("key=%q benign=%q did not change any rendered configuration, so the injection checks for it prove nothing; add the companion keys it needs or list it in notRendered", k.key, k.benign)
		}
		if rendered && exempt {
			t.Errorf("key=%q is listed in notRendered but changes the rendered configuration; remove it from the list", k.key)
		}
	}
}

func mustShape(t *testing.T, conf string, format string, args ...any) []string {
	t.Helper()
	shape, err := nginxconf.Shape(conf)
	if err != nil {
		t.Fatalf(format+": configuration does not tokenize: %v", append(args, err)...)
	}
	return shape
}

// configParamsFromConfigMap runs a ConfigMap through the parser, which is where
// the validation layer applies.
//
// App Protect and App Protect DoS are Plus-only, and ParseConfigMap ignores their
// keys unless the feature is enabled, so the Plus run enables both. Otherwise
// those keys would pass by leaving the defaults unchanged rather than by being
// validated or rendered safely.
func configParamsFromConfigMap(data map[string]string, nginxPlus bool) *ConfigParams {
	cfgParams, _ := ParseConfigMap(context.Background(), &v1.ConfigMap{Data: data},
		nginxPlus, nginxPlus, nginxPlus, false, false, true, makeEventLogger())
	return cfgParams
}

// renderConfigMapMain renders the main configuration.
func renderConfigMapMain(t *testing.T, data map[string]string, nginxPlus bool) string {
	t.Helper()

	cfgParams := configParamsFromConfigMap(data, nginxPlus)

	staticCfgParams := &StaticConfigParams{
		HealthStatus:                   true,
		HealthStatusURI:                "/nginx-health",
		NginxStatus:                    true,
		NginxStatusAllowCIDRs:          []string{"127.0.0.1"},
		NginxStatusPort:                8080,
		StubStatusOverUnixSocketForOSS: true,
		EnableSnippets:                 false,
		// The OIDC keyval zones render only when OIDC is enabled.
		EnableOIDC: nginxPlus,
		// The App Protect and DoS directives render only when their modules load.
		MainAppProtectLoadModule:    nginxPlus,
		MainAppProtectDosLoadModule: nginxPlus,
	}

	mainCfg := GenerateNginxMainConfig(staticCfgParams, cfgParams, &MGMTConfigParams{})

	tmplPath := "version1/nginx.tmpl"
	if nginxPlus {
		tmplPath = "version1/nginx-plus.tmpl"
	}
	executor, err := version1.NewTemplateExecutor(tmplPath, "version1/nginx.ingress.tmpl")
	if err != nil {
		t.Fatalf("cannot build template executor: %v", err)
	}
	rendered, err := executor.ExecuteMainConfigTemplate(mainCfg)
	if err != nil {
		t.Fatalf("cannot render main configuration: %v", err)
	}
	return string(rendered)
}

// renderConfigMapIngress renders an ingress configuration built from the same
// ConfigMap defaults. Most ConfigMap keys are per-server or per-location
// defaults and appear only here.
func renderConfigMapIngress(t *testing.T, data map[string]string, nginxPlus bool) string {
	t.Helper()

	cfgParams := configParamsFromConfigMap(data, nginxPlus)
	ingEx := createCafeIngressEx()

	cfg, _ := generateNginxCfg(NginxCfgParams{
		staticParams:  &StaticConfigParams{},
		ingEx:         &ingEx,
		BaseCfgParams: cfgParams,
		isPlus:        nginxPlus,
	})

	tmplPath := "version1/nginx.ingress.tmpl"
	mainPath := "version1/nginx.tmpl"
	if nginxPlus {
		tmplPath = "version1/nginx-plus.ingress.tmpl"
		mainPath = "version1/nginx-plus.tmpl"
	}
	executor, err := version1.NewTemplateExecutor(mainPath, tmplPath)
	if err != nil {
		t.Fatalf("cannot build template executor: %v", err)
	}
	rendered, err := executor.ExecuteIngressConfigTemplate(&cfg)
	if err != nil {
		t.Fatalf("cannot render ingress configuration: %v", err)
	}
	// An ingress configuration is a fragment of an http {} block, so wrap it to
	// give the tokenizer a balanced file.
	return "http {\n" + string(rendered) + "\n}\n"
}

// renderConfigMapDefaultServer renders the fallback default server written to
// conf.d. Keys such as default-server-return reach configuration only here, so
// without this artifact the property holds trivially for them.
func renderConfigMapDefaultServer(t *testing.T, data map[string]string, nginxPlus bool) string {
	t.Helper()

	cfgParams := configParamsFromConfigMap(data, nginxPlus)
	staticCfgParams := &StaticConfigParams{
		DefaultHTTPListenerPort:  80,
		DefaultHTTPSListenerPort: 443,
	}
	cfg := GenerateDefaultServerConfig(staticCfgParams, cfgParams)

	tmplPath := "version1/nginx.ingress.tmpl"
	mainPath := "version1/nginx.tmpl"
	if nginxPlus {
		tmplPath = "version1/nginx-plus.ingress.tmpl"
		mainPath = "version1/nginx-plus.tmpl"
	}
	executor, err := version1.NewTemplateExecutor(mainPath, tmplPath)
	if err != nil {
		t.Fatalf("cannot build template executor: %v", err)
	}
	rendered, err := executor.ExecuteIngressConfigTemplate(&cfg)
	if err != nil {
		t.Fatalf("cannot render default server configuration: %v", err)
	}
	return "http {\n" + string(rendered) + "\n}\n"
}

// shapeDiff reports the first structural difference between two shapes, or "" if
// they match.
func shapeDiff(want, got []string) string {
	if len(want) == len(got) {
		same := true
		for i := range want {
			if want[i] != got[i] {
				same = false
				break
			}
		}
		if same {
			return ""
		}
	}

	var b strings.Builder
	for i := 0; i < len(want) || i < len(got); i++ {
		w, g := "", ""
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			b.WriteString("  want " + w + "\n  got  " + g + "\n")
			if b.Len() > 400 {
				break
			}
		}
	}
	return b.String()
}
