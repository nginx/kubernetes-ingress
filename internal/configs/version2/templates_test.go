package version2

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

func TestMain(m *testing.M) {
	v := m.Run()

	// After all tests have run `go-snaps` will sort snapshots
	snaps.Clean(m, snaps.CleanOpts{Sort: true})

	os.Exit(v)
}

func createPointerFromInt(n int) *int {
	return &n
}

func newTmplExecutorNGINXPlus(t *testing.T) *TemplateExecutor {
	t.Helper()
	executor, err := NewTemplateExecutor("nginx-plus.virtualserver.tmpl", "nginx-plus.transportserver.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func newTmplExecutorNGINX(t *testing.T) *TemplateExecutor {
	t.Helper()
	executor, err := NewTemplateExecutor("nginx.virtualserver.tmpl", "nginx.transportserver.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func TestVirtualServerForNginxPlus(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	data, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgPlus)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(data))
	t.Log(string(data))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithServerGunzipOn(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithGunzipOn)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Contains(got, []byte("gunzip on;")) {
		t.Error("want `gunzip on` directive, got no directive")
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithServerGunzipOff(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithGunzipOff)
	if err != nil {
		t.Error(err)
	}
	if bytes.Contains(got, []byte("gunzip on;")) {
		t.Error("want no directive, got `gunzip on`")
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithServerGunzipNotSet(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithGunzipNotSet)
	if err != nil {
		t.Error(err)
	}
	if bytes.Contains(got, []byte("gunzip on;")) {
		t.Error("want no directive, got `gunzip on` directive")
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithRateLimitJWTClaim(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithRateLimitJWTClaim)
	if err != nil {
		t.Error(err)
	}
	wantedStrings := []string{
		"auth_jwt_claim_set",
		"$rate_limit_default_webapp_group_consumer_group_type",
		"$jwt_default_webapp_group_consumer_group_type",
		"Group1",
		"Group2",
		"Group3",
		"$http_bronze",
		"$http_silver",
		"$http_gold",
	}
	for _, value := range wantedStrings {
		if !bytes.Contains(got, []byte(value)) {
			t.Errorf("didn't get `%s`", value)
		}
	}

	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithRateLimitVariableAPIKey(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithRateLimitVariableAPIKey)
	if err != nil {
		t.Error(err)
	}
	wantedStrings := []string{
		"limit_req_zone $pol_rl_default_basic_rate_limit_policy_default_cafe",
		"limit_req_zone $pol_rl_default_premium_rate_limit_policy_default_cafe",
		"$pol_rl_default_basic_rate_limit_policy_default_cafe {",
		"$pol_rl_default_premium_rate_limit_policy_default_cafe {",
		"$rl_default_cafe_variable_apikey_client_name",
		"default rl_default_cafe_match_basic_rate_limit_policy",
		"\"basic\" rl_default_cafe_match_basic_rate_limit_policy",
		"\"premium\" rl_default_cafe_match_premium_rate_limit_policy",
		"rl_default_cafe_match_basic_rate_limit_policy Val$apikey_client_name",
		"rl_default_cafe_match_premium_rate_limit_policy Val$apikey_client_name",
		"map $apikey_auth_token",
		"map $apikey_client_name",
	}
	for _, value := range wantedStrings {
		if !bytes.Contains(got, []byte(value)) {
			t.Errorf("didn't get `%s`", value)
		}
	}

	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithSessionCookieSameSite(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithSessionCookieSameSite)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Contains(got, []byte("samesite=strict")) {
		t.Error("want `samesite=strict` in generated template")
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListener(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithCustomListener)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 8082",
		"listen [::]:8082",
		"listen 8443 ssl",
		"listen [::]:8443 ssl",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerIP(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithCustomListenerIP)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 127.0.0.1:8082",
		"listen [::1]:8082",
		"listen 127.0.0.2:8443 ssl",
		"listen [::2]:8443 ssl",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerHTTPIPV4Only(t *testing.T) {
	t.Parallel()
	vsCfg := virtualServerCfgWithCustomListenerIP

	vsCfg.Server.HTTPIPv6 = ""
	vsCfg.Server.HTTPSIPv6 = ""
	vsCfg.Server.HTTPSIPv4 = ""
	vsCfg.Server.HTTPSPort = 0

	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&vsCfg)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 127.0.0.1:8082",
		"listen [::]:8082",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerHTTPIPV6Only(t *testing.T) {
	t.Parallel()
	vsCfg := virtualServerCfgWithCustomListenerIP

	vsCfg.Server.HTTPIPv4 = ""
	vsCfg.Server.HTTPSIPv6 = ""
	vsCfg.Server.HTTPSIPv4 = ""
	vsCfg.Server.HTTPSPort = 0

	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&vsCfg)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 8082",
		"listen [::1]:8082",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerHTTPSIPV4Only(t *testing.T) {
	t.Parallel()
	vsCfg := virtualServerCfgWithCustomListenerIP

	vsCfg.Server.HTTPIPv6 = ""
	vsCfg.Server.HTTPSIPv6 = ""
	vsCfg.Server.HTTPIPv4 = ""
	vsCfg.Server.HTTPPort = 0

	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&vsCfg)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 127.0.0.2:8443 ssl",
		"listen [::]:8443 ssl",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerHTTPSIPV6Only(t *testing.T) {
	t.Parallel()
	vsCfg := virtualServerCfgWithCustomListenerIP

	vsCfg.Server.HTTPIPv6 = ""
	vsCfg.Server.HTTPIPv4 = ""
	vsCfg.Server.HTTPSIPv4 = ""
	vsCfg.Server.HTTPPort = 0

	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&vsCfg)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 8443 ssl",
		"listen [::2]:8443 ssl",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerHTTPOnly(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithCustomListenerHTTPOnly)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 8082",
		"listen [::]:8082",
	}
	unwantStrings := []string{
		"listen 8443 ssl",
		"listen [::]:8443 ssl",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	for _, want := range unwantStrings {
		if bytes.Contains(got, []byte(want)) {
			t.Errorf("unwant  `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersTemplateWithCustomListenerHTTPSOnly(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithCustomListenerHTTPSOnly)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 8443 ssl",
		"listen [::]:8443 ssl",
	}
	unwantStrings := []string{
		"listen 8082",
		"listen [::]:8082",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	for _, want := range unwantStrings {
		if bytes.Contains(got, []byte(want)) {
			t.Errorf("want no `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersPlusTemplateWithHTTP2On(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithHTTP2On)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 443 ssl proxy_protocol;",
		"listen [::]:443 ssl proxy_protocol;",
		"http2 on;",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}

	unwantStrings := []string{
		"listen 443 ssl http2 proxy_protocol;",
		"listen [::]:443 ssl http2 proxy_protocol;",
	}

	for _, want := range unwantStrings {
		if bytes.Contains(got, []byte(want)) {
			t.Errorf("unwant  `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))

	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersPlusTemplateWithHTTP2Off(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithHTTP2Off)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 443 ssl proxy_protocol;",
		"listen [::]:443 ssl proxy_protocol;",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}

	unwantStrings := []string{
		"http2 on;",
	}

	for _, want := range unwantStrings {
		if bytes.Contains(got, []byte(want)) {
			t.Errorf("unwant  `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))

	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersOSSTemplateWithHTTP2On(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithHTTP2On)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 443 ssl proxy_protocol;",
		"listen [::]:443 ssl proxy_protocol;",
		"http2 on;",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}

	unwantStrings := []string{
		"listen 443 ssl http2 proxy_protocol;",
		"listen [::]:443 ssl http2 proxy_protocol;",
	}

	for _, want := range unwantStrings {
		if bytes.Contains(got, []byte(want)) {
			t.Errorf("unwant  `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))

	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_RendersOSSTemplateWithHTTP2Off(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithHTTP2Off)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 443 ssl proxy_protocol;",
		"listen [::]:443 ssl proxy_protocol;",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}

	unwantStrings := []string{
		"http2 on;",
	}

	for _, want := range unwantStrings {
		if bytes.Contains(got, []byte(want)) {
			t.Errorf("unwant  `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))

	t.Log(string(got))
}

func TestVirtualServerForNginxPlusWithWAFApBundle(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithWAFApBundle)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(got))

	t.Log(string(got))
}

func TestVirtualServerForNginx(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)
	data, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfg)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(data))
	t.Log(string(data))
}

func TestTransportServerForNginxPlus(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	data, err := executor.ExecuteTransportServerTemplate(&transportServerCfg)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	t.Log(string(data))
}

func TestExecuteTemplateForTransportServerWithResolver(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteTransportServerTemplate(&transportServerCfgWithResolver)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(got))
}

func TestExecuteTemplateForNGINXOSSTransportServerWithSNI(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)
	got, err := executor.ExecuteTransportServerTemplate(&transportServerCfgWithSNI)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(got))
}

func TestExecuteTemplateForNGINXPlusTransportServerWithSNI(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteTransportServerTemplate(&transportServerCfgWithSNI)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(got))
}

func TestTransportServerForNginx(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)
	data, err := executor.ExecuteTransportServerTemplate(&transportServerCfg)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(data))
	t.Log(string(data))
}

func TestExecuteTemplateForTransportServerWithTCPIPListener(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	customIPListenerTransportServerCfg := transportServerCfgWithSSL
	customIPListenerTransportServerCfg.Server.IPv4 = "127.0.0.1"
	customIPListenerTransportServerCfg.Server.IPv6 = "::1"

	got, err := executor.ExecuteTransportServerTemplate(&customIPListenerTransportServerCfg)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 127.0.0.1:1234 ssl udp;",
		"listen [::1]:1234 ssl udp;",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteTemplateForTransportServerWithUDPIPListener(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	customIPListenerTransportServerCfg := transportServerCfgWithSSL
	customIPListenerTransportServerCfg.Server.IPv4 = "127.0.0.1"
	customIPListenerTransportServerCfg.Server.IPv6 = "::1"
	customIPListenerTransportServerCfg.Server.UDP = false

	got, err := executor.ExecuteTransportServerTemplate(&customIPListenerTransportServerCfg)
	if err != nil {
		t.Error(err)
	}
	wantStrings := []string{
		"listen 127.0.0.1:1234 ssl;",
		"listen [::1]:1234 ssl;",
	}
	for _, want := range wantStrings {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want `%s` in generated template", want)
		}
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func tsConfig() TransportServerConfig {
	return TransportServerConfig{
		Upstreams: []StreamUpstream{
			{
				Name: "udp-upstream",
				Servers: []StreamUpstreamServer{
					{
						Address: "10.0.0.20:5001",
					},
				},
			},
		},
		Match: &Match{
			Name:                "match_udp-upstream",
			Send:                `GET / HTTP/1.0\r\nHost: localhost\r\n\r\n`,
			ExpectRegexModifier: "~*",
			Expect:              "200 OK",
		},
		Server: StreamServer{
			Port:                     1234,
			UDP:                      true,
			StatusZone:               "udp-app",
			ProxyRequests:            createPointerFromInt(1),
			ProxyResponses:           createPointerFromInt(2),
			ProxyPass:                "udp-upstream",
			ProxyTimeout:             "10s",
			ProxyConnectTimeout:      "10s",
			ProxyNextUpstream:        true,
			ProxyNextUpstreamTimeout: "10s",
			ProxyNextUpstreamTries:   5,
			HealthCheck: &StreamHealthCheck{
				Enabled:  false,
				Timeout:  "5s",
				Jitter:   "0",
				Port:     8080,
				Interval: "5s",
				Passes:   1,
				Fails:    1,
				Match:    "match_udp-upstream",
			},
		},
	}
}

func TestExecuteTemplateForTransportServerWithBackupServerForNGINXPlus(t *testing.T) {
	t.Parallel()

	tsCfg := tsConfig()
	tsCfg.Upstreams[0].BackupServers = []StreamUpstreamBackupServer{
		{
			Address: "clustertwo.corp.local:8080",
		},
	}
	e := newTmplExecutorNGINXPlus(t)
	got, err := e.ExecuteTransportServerTemplate(&tsCfg)
	if err != nil {
		t.Error(err)
	}

	want := fmt.Sprintf("server %s resolve backup;", tsCfg.Upstreams[0].BackupServers[0].Address)
	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("want backup %q in the transport server config", want)
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestTransportServerWithSSL(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	data, err := executor.ExecuteTransportServerTemplate(&transportServerCfgWithSSL)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(data))
	t.Log(string(data))
}

func TestTLSPassthroughHosts(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)

	unixSocketsCfg := TLSPassthroughHostsConfig{
		"app.example.com": "unix:/var/lib/nginx/passthrough-default_secure-app.sock",
	}

	data, err := executor.ExecuteTLSPassthroughHostsTemplate(&unixSocketsCfg)
	if err != nil {
		t.Errorf("Failed to execute template: %v", err)
	}
	snaps.MatchSnapshot(t, string(data))
	t.Log(string(data))
}

func TestExecuteVirtualServerTemplateWithJWKSWithToken(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithJWTPolicyJWKSWithToken)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Contains(got, []byte("token=$http_token")) {
		t.Error("want `token=$http_token` in generated template")
	}

	if !bytes.Contains(got, []byte("proxy_ssl_server_name on;")) {
		t.Error("want `proxy_ssl_server_name on;` in generated template")
	}

	if !bytes.Contains(got, []byte("proxy_ssl_name sni.idp.spec.example.com;")) {
		t.Error("want `proxy_ssl_name sni.idp.spec.example.com;` in generated template")
	}

	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplateWithJWKSWithoutToken(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithJWTPolicyJWKSWithoutToken)
	if err != nil {
		t.Error(err)
	}
	if bytes.Contains(got, []byte("token=$http_token")) {
		t.Error("want no `token=$http_token` string in generated template")
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplateWithBackupServerNGINXPlus(t *testing.T) {
	t.Parallel()

	externalName := "clustertwo.corp.local:8080"
	vscfg := vsConfig()
	vscfg.Upstreams[0].BackupServers = []UpstreamServer{
		{
			Address: externalName,
		},
	}

	e := newTmplExecutorNGINXPlus(t)
	got, err := e.ExecuteVirtualServerTemplate(&vscfg)
	if err != nil {
		t.Error(err)
	}

	want := fmt.Sprintf("server %s backup resolve;", externalName)
	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("want %q in generated template", want)
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplateWithAPIKeyPolicyNGINXPlus(t *testing.T) {
	t.Parallel()

	vscfg := vsConfig()
	vscfg.Server.APIKey = &APIKey{
		Header:  []string{"X-header-name", "other-header"},
		Query:   []string{"myQuery", "myOtherQuery"},
		MapName: "vs_default_cafe_apikey_policy",
	}

	e := newTmplExecutorNGINXPlus(t)
	got, err := e.ExecuteVirtualServerTemplate(&vscfg)
	if err != nil {
		t.Error(err)
	}

	want := "js_var $header_query_value \"${http_x_header_name}${http_other_header}${arg_myQuery}${arg_myOtherQuery}\";"

	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("want %q in generated template", want)
	}
	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplate_WithCustomOIDCRedirectLocation(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfg)
	if err != nil {
		t.Error(err)
	}

	expectedCustomLocation := "location = /custom-location {"
	if !bytes.Contains(got, []byte(expectedCustomLocation)) {
		t.Errorf("Custom redirectURI should generate location block: %s", expectedCustomLocation)
	}

	expectedDirectives := []string{
		"status_zone \"OIDC code exchange\";",
		"js_content oidc.codeExchange;",
		"error_page 500 502 504 @oidc_error;",
	}

	for _, directive := range expectedDirectives {
		if !bytes.Contains(got, []byte(directive)) {
			t.Errorf("Custom location should contain directive: %s", directive)
		}
	}

	expectedRedirVar := `set $redir_location "/custom-location";`
	if !bytes.Contains(got, []byte(expectedRedirVar)) {
		t.Errorf("Should set $redir_location to custom value: %s", expectedRedirVar)
	}
}

func TestExecuteVirtualServerTemplateWithOIDCAndPKCEPolicyNGINXPlus(t *testing.T) {
	t.Parallel()

	e := newTmplExecutorNGINXPlus(t)
	got, err := e.ExecuteVirtualServerTemplate(&virtualServerCfgWithOIDCAndPKCETurnedOn)
	if err != nil {
		t.Error(err)
	}

	want := "include oidc/oidc_pkce_supplements.conf"
	want2 := "include oidc/oidc.conf;"

	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("want %q in generated template", want)
	}

	if !bytes.Contains(got, []byte(want2)) {
		t.Errorf("want %q in generated template", want2)
	}

	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplateWithCachePolicyNGINXPlus(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINXPlus(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithCachePolicyNGINXPlus)
	if err != nil {
		t.Error(err)
	}

	// Check cache zone declaration
	expectedCacheZone := "proxy_cache_path /var/cache/nginx/test_cache_full_advanced levels=2:2 keys_zone=test_cache_full_advanced:50m;"
	if !bytes.Contains(got, []byte(expectedCacheZone)) {
		t.Errorf("Expected cache zone declaration: %s", expectedCacheZone)
	}

	// Check cache purge configuration for NGINX Plus
	expectedPurgeGeo := "geo $purge_allowed_test_cache_full_advanced {"
	if !bytes.Contains(got, []byte(expectedPurgeGeo)) {
		t.Errorf("Expected purge geo block: %s", expectedPurgeGeo)
	}

	expectedPurgeMap := "map $request_method $cache_purge_test_cache_full_advanced {"
	if !bytes.Contains(got, []byte(expectedPurgeMap)) {
		t.Errorf("Expected purge map block: %s", expectedPurgeMap)
	}

	// Check server-level cache configuration
	expectedServerCacheDirectives := []string{
		"proxy_cache test_cache_full_advanced;",
		"proxy_cache_key $scheme$proxy_host$request_uri;",
		"proxy_ignore_headers Cache-Control Expires Set-Cookie Vary X-Accel-Expires;",
		"proxy_cache_valid 200 2h;",
		"proxy_cache_valid 404 2h;",
		"proxy_cache_valid 301 2h;",
		"proxy_cache_methods GET HEAD POST;",
		"proxy_cache_purge $cache_purge_test_cache_full_advanced;",
	}

	for _, directive := range expectedServerCacheDirectives {
		if !bytes.Contains(got, []byte(directive)) {
			t.Errorf("Expected server cache directive: %s", directive)
		}
	}

	// Check location-level cache configuration
	expectedLocationCacheDirectives := []string{
		"proxy_cache test_cache_location_location_cache;",
		"proxy_cache_valid any 1h;",
		"proxy_cache_methods GET HEAD;",
	}

	for _, directive := range expectedLocationCacheDirectives {
		if !bytes.Contains(got, []byte(directive)) {
			t.Errorf("Expected location cache directive: %s", directive)
		}
	}

	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func TestExecuteVirtualServerTemplateWithCachePolicyOSS(t *testing.T) {
	t.Parallel()
	executor := newTmplExecutorNGINX(t)
	got, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfgWithCachePolicyOSS)
	if err != nil {
		t.Error(err)
	}

	// Check cache zone declaration
	expectedCacheZone := "proxy_cache_path /var/cache/nginx/test_cache_basic_cache levels=1:2 keys_zone=test_cache_basic_cache:10m;"
	if !bytes.Contains(got, []byte(expectedCacheZone)) {
		t.Errorf("Expected cache zone declaration: %s", expectedCacheZone)
	}

	// Ensure no purge configuration for OSS (cachePurgeAllow should be ignored)
	if bytes.Contains(got, []byte("geo $purge_allowed")) {
		t.Error("OSS template should not contain cache purge geo blocks")
	}

	if bytes.Contains(got, []byte("map $request_method $cache_purge")) {
		t.Error("OSS template should not contain cache purge map blocks")
	}

	if bytes.Contains(got, []byte("proxy_cache_purge")) {
		t.Error("OSS template should not contain proxy_cache_purge directive")
	}

	// Check server-level cache configuration
	expectedServerCacheDirectives := []string{
		"proxy_cache test_cache_basic_cache;",
		"proxy_cache_key $scheme$proxy_host$request_uri;",
		"proxy_ignore_headers Cache-Control Expires Set-Cookie Vary X-Accel-Expires;",
		"proxy_cache_valid any 1h;",
		"proxy_cache_methods GET HEAD;",
	}

	for _, directive := range expectedServerCacheDirectives {
		if !bytes.Contains(got, []byte(directive)) {
			t.Errorf("Expected server cache directive: %s", directive)
		}
	}

	// Check location-level cache configuration
	expectedLocationCacheDirectives := []string{
		"proxy_cache test_cache_location_simple_cache;",
		"proxy_cache_valid 200 30m;",
		"proxy_cache_valid 404 30m;",
	}

	for _, directive := range expectedLocationCacheDirectives {
		if !bytes.Contains(got, []byte(directive)) {
			t.Errorf("Expected location cache directive: %s", directive)
		}
	}

	snaps.MatchSnapshot(t, string(got))
	t.Log(string(got))
}

func vsConfig() VirtualServerConfig {
	return VirtualServerConfig{
		LimitReqZones: []LimitReqZone{
			{
				ZoneName: "pol_rl_test_test_test", Rate: "10r/s", ZoneSize: "10m", Key: "$url",
			},
		},
		Upstreams: []Upstream{
			{
				Name: "test-upstream",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:8001",
					},
				},
				LBMethod:         "random",
				Keepalive:        32,
				MaxFails:         4,
				FailTimeout:      "10s",
				MaxConns:         31,
				SlowStart:        "10s",
				UpstreamZoneSize: "256k",
				Queue:            &Queue{Size: 10, Timeout: "60s"},
				SessionCookie:    &SessionCookie{Enable: true, Name: "test", Path: "/tea", Expires: "25s"},
				NTLM:             true,
			},
			{
				Name: "coffee-v1",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.31:8001",
					},
				},
				MaxFails:         8,
				FailTimeout:      "15s",
				MaxConns:         2,
				UpstreamZoneSize: "256k",
			},
			{
				Name: "coffee-v2",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.32:8001",
					},
				},
				MaxFails:         12,
				FailTimeout:      "20s",
				MaxConns:         4,
				UpstreamZoneSize: "256k",
			},
		},
		SplitClients: []SplitClient{
			{
				Source:   "$request_id",
				Variable: "$split_0",
				Distributions: []Distribution{
					{
						Weight: "50%",
						Value:  "@loc0",
					},
					{
						Weight: "50%",
						Value:  "@loc1",
					},
				},
			},
		},
		Maps: []Map{
			{
				Source:   "$match_0_0",
				Variable: "$match",
				Parameters: []Parameter{
					{
						Value:  "~^1",
						Result: "@match_loc_0",
					},
					{
						Value:  "default",
						Result: "@match_loc_default",
					},
				},
			},
			{
				Source:   "$http_x_version",
				Variable: "$match_0_0",
				Parameters: []Parameter{
					{
						Value:  "v2",
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
		},
		HTTPSnippets: []string{"# HTTP snippet"},
		Server: Server{
			ServerName:    "example.com",
			StatusZone:    "example.com",
			ProxyProtocol: true,
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			TLSRedirect: &TLSRedirect{
				BasedOn: "$scheme",
				Code:    301,
			},
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Allow:           []string{"127.0.0.1"},
			Deny:            []string{"127.0.0.1"},
			LimitReqs: []LimitReq{
				{
					ZoneName: "pol_rl_test_test_test",
					Delay:    10,
					Burst:    5,
				},
			},
			LimitReqOptions: LimitReqOptions{
				LogLevel:   "error",
				RejectCode: 503,
			},
			JWTAuth: &JWTAuth{
				Realm:  "My Api",
				Secret: "jwk-secret",
			},
			IngressMTLS: &IngressMTLS{
				ClientCert:   "ingress-mtls-secret",
				VerifyClient: "on",
				VerifyDepth:  2,
			},
			WAF: &WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				Enable:              "on",
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			Dos: &Dos{
				Enable:                 "on",
				Name:                   "my-dos-coffee",
				ApDosMonitorURI:        "test.example.com",
				ApDosMonitorProtocol:   "http",
				ApDosAccessLogDest:     "svc.dns.com:123",
				ApDosPolicy:            "/test/policy.json",
				ApDosSecurityLogEnable: true,
				ApDosLogConf:           "/test/log.json",
				ApDosMonitorTimeout:    30,
				AllowListPath:          "/etc/nginx/dos/allowlist/default_test.example.com",
			},
			Snippets: []string{"# server snippet"},
			InternalRedirectLocations: []InternalRedirectLocation{
				{
					Path:        "/split",
					Destination: "@split_0",
				},
				{
					Path:        "/coffee",
					Destination: "@match",
				},
			},
			HealthChecks: []HealthCheck{
				{
					Name:          "coffee",
					URI:           "/",
					Interval:      "5s",
					Jitter:        "0s",
					Fails:         1,
					Passes:        1,
					Port:          50,
					ProxyPass:     "http://coffee-v2",
					Mandatory:     true,
					Persistent:    true,
					KeepaliveTime: "60s",
					IsGRPC:        false,
				},
				{
					Name:        "tea",
					Interval:    "5s",
					Jitter:      "0s",
					Fails:       1,
					Passes:      1,
					Port:        50,
					ProxyPass:   "http://tea-v2",
					GRPCPass:    "grpc://tea-v3",
					GRPCStatus:  createPointerFromInt(12),
					GRPCService: "tea-servicev2",
					IsGRPC:      true,
				},
			},
			Locations: []Location{
				{
					Path:     "/",
					Snippets: []string{"# location snippet"},
					Allow:    []string{"127.0.0.1"},
					Deny:     []string{"127.0.0.1"},
					LimitReqs: []LimitReq{
						{
							ZoneName: "loc_pol_rl_test_test_test",
						},
					},
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyBuffering:           true,
					ProxyBuffers:             "8 4k",
					ProxyBufferSize:          "4k",
					ProxyBusyBuffersSize:     "8k",
					ProxyMaxTempFileSize:     "1024m",
					ProxyPass:                "http://test-upstream",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
					Internal:                 true,
					ProxyPassRequestHeaders:  false,
					ProxyPassHeaders:         []string{"Host"},
					ProxyPassRewrite:         "$request_uri",
					ProxyHideHeaders:         []string{"Header"},
					ProxyIgnoreHeaders:       "Cache",
					Rewrites:                 []string{"$request_uri $request_uri", "$request_uri $request_uri"},
					AddHeaders: []AddHeader{
						{
							Header: Header{
								Name:  "Header-Name",
								Value: "Header Value",
							},
							Always: true,
						},
					},
					EgressMTLS: &EgressMTLS{
						Certificate:    "egress-mtls-secret.pem",
						CertificateKey: "egress-mtls-secret.pem",
						VerifyServer:   true,
						VerifyDepth:    1,
						Ciphers:        "DEFAULT",
						Protocols:      "TLSv1.3",
						TrustedCert:    "trusted-cert.pem",
						SessionReuse:   true,
						ServerName:     true,
					},
				},
				{
					Path:                     "@loc0",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
					ProxyInterceptErrors:     true,
					ErrorPages: []ErrorPage{
						{
							Name:         "@error_page_1",
							Codes:        "400 500",
							ResponseCode: 200,
						},
						{
							Name:         "@error_page_2",
							Codes:        "500",
							ResponseCode: 0,
						},
					},
				},
				{
					Path:                     "@loc1",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                "@loc2",
					ProxyConnectTimeout: "30s",
					ProxyReadTimeout:    "31s",
					ProxySendTimeout:    "32s",
					ClientMaxBodySize:   "1m",
					ProxyPass:           "http://coffee-v2",
					GRPCPass:            "grpc://coffee-v3",
				},
				{
					Path:                     "@match_loc_0",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                     "@match_loc_default",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                 "/return",
					ProxyInterceptErrors: true,
					ErrorPages: []ErrorPage{
						{
							Name:         "@return_0",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
			},
			ErrorPageLocations: []ErrorPageLocation{
				{
					Name:        "@vs_cafe_cafe_vsr_tea_tea_tea__tea_error_page_0",
					DefaultType: "application/json",
					Return: &Return{
						Code: 200,
						Text: "Hello World",
					},
					Headers: nil,
				},
				{
					Name:        "@vs_cafe_cafe_vsr_tea_tea_tea__tea_error_page_1",
					DefaultType: "",
					Return: &Return{
						Code: 200,
						Text: "Hello World",
					},
					Headers: []Header{
						{
							Name:  "Set-Cookie",
							Value: "cookie1=test",
						},
						{
							Name:  "Set-Cookie",
							Value: "cookie2=test; Secure",
						},
					},
				},
			},
			ReturnLocations: []ReturnLocation{
				{
					Name:        "@return_0",
					DefaultType: "text/html",
					Return: Return{
						Code: 200,
						Text: "Hello!",
					},
				},
			},
		},
	}
}

var (
	virtualServerCfg = VirtualServerConfig{
		LimitReqZones: []LimitReqZone{
			{
				ZoneName: "pol_rl_test_test_test", Rate: "10r/s", ZoneSize: "10m", Key: "$url",
			},
		},
		Upstreams: []Upstream{
			{
				Name: "test-upstream",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:8001",
					},
				},
				LBMethod:         "random",
				Keepalive:        32,
				MaxFails:         4,
				FailTimeout:      "10s",
				MaxConns:         31,
				SlowStart:        "10s",
				UpstreamZoneSize: "256k",
				Queue:            &Queue{Size: 10, Timeout: "60s"},
				SessionCookie:    &SessionCookie{Enable: true, Name: "test", Path: "/tea", Expires: "25s"},
				NTLM:             true,
			},
			{
				Name: "coffee-v1",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.31:8001",
					},
				},
				MaxFails:         8,
				FailTimeout:      "15s",
				MaxConns:         2,
				UpstreamZoneSize: "256k",
			},
			{
				Name: "coffee-v2",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.32:8001",
					},
				},
				MaxFails:         12,
				FailTimeout:      "20s",
				MaxConns:         4,
				UpstreamZoneSize: "256k",
			},
		},
		SplitClients: []SplitClient{
			{
				Source:   "$request_id",
				Variable: "$split_0",
				Distributions: []Distribution{
					{
						Weight: "50%",
						Value:  "@loc0",
					},
					{
						Weight: "50%",
						Value:  "@loc1",
					},
				},
			},
		},
		Maps: []Map{
			{
				Source:   "$match_0_0",
				Variable: "$match",
				Parameters: []Parameter{
					{
						Value:  "~^1",
						Result: "@match_loc_0",
					},
					{
						Value:  "default",
						Result: "@match_loc_default",
					},
				},
			},
			{
				Source:   "$http_x_version",
				Variable: "$match_0_0",
				Parameters: []Parameter{
					{
						Value:  "v2",
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
		},
		HTTPSnippets: []string{"# HTTP snippet"},
		Server: Server{
			ServerName:    "example.com",
			StatusZone:    "example.com",
			ProxyProtocol: true,
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			TLSRedirect: &TLSRedirect{
				BasedOn: "$scheme",
				Code:    301,
			},
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Allow:           []string{"127.0.0.1"},
			Deny:            []string{"127.0.0.1"},
			LimitReqs: []LimitReq{
				{
					ZoneName: "pol_rl_test_test_test",
					Delay:    10,
					Burst:    5,
				},
			},
			LimitReqOptions: LimitReqOptions{
				LogLevel:   "error",
				RejectCode: 503,
			},
			JWTAuth: &JWTAuth{
				Realm:  "My Api",
				Secret: "jwk-secret",
			},
			OIDC: &OIDC{
				AuthEndpoint:          "https://idp.example.com/auth",
				ClientID:              "test-client",
				ClientSecret:          "test-secret",
				JwksURI:               "https://idp.example.com/jwks",
				TokenEndpoint:         "https://idp.example.com/token",
				EndSessionEndpoint:    "https://idp.example.com/logout",
				RedirectURI:           "/custom-location",
				PostLogoutRedirectURI: "https://example.com/logout",
				ZoneSyncLeeway:        0,
				Scope:                 "openid+profile+email",
			},
			IngressMTLS: &IngressMTLS{
				ClientCert:   "ingress-mtls-secret",
				VerifyClient: "on",
				VerifyDepth:  2,
			},
			WAF: &WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				Enable:              "on",
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			Snippets: []string{"# server snippet"},
			InternalRedirectLocations: []InternalRedirectLocation{
				{
					Path:        "/split",
					Destination: "@split_0",
				},
				{
					Path:        "/coffee",
					Destination: "@match",
				},
			},
			HealthChecks: []HealthCheck{
				{
					Name:          "coffee",
					URI:           "/",
					Interval:      "5s",
					Jitter:        "0s",
					Fails:         1,
					Passes:        1,
					Port:          50,
					ProxyPass:     "http://coffee-v2",
					Mandatory:     true,
					Persistent:    true,
					KeepaliveTime: "60s",
					IsGRPC:        false,
				},
				{
					Name:        "tea",
					Interval:    "5s",
					Jitter:      "0s",
					Fails:       1,
					Passes:      1,
					Port:        50,
					ProxyPass:   "http://tea-v2",
					GRPCPass:    "grpc://tea-v3",
					GRPCStatus:  createPointerFromInt(12),
					GRPCService: "tea-servicev2",
					IsGRPC:      true,
				},
			},
			Locations: []Location{
				{
					Path:     "/",
					Snippets: []string{"# location snippet"},
					Allow:    []string{"127.0.0.1"},
					Deny:     []string{"127.0.0.1"},
					LimitReqs: []LimitReq{
						{
							ZoneName: "loc_pol_rl_test_test_test",
						},
					},
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyBuffering:           true,
					ProxyBuffers:             "8 4k",
					ProxyBufferSize:          "4k",
					ProxyBusyBuffersSize:     "8k",
					ProxyMaxTempFileSize:     "1024m",
					ProxyPass:                "http://test-upstream",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
					Internal:                 true,
					ProxyPassRequestHeaders:  false,
					ProxyPassHeaders:         []string{"Host"},
					ProxyPassRewrite:         "$request_uri",
					ProxyHideHeaders:         []string{"Header"},
					ProxyIgnoreHeaders:       "Cache",
					Rewrites:                 []string{"$request_uri $request_uri", "$request_uri $request_uri"},
					AddHeaders: []AddHeader{
						{
							Header: Header{
								Name:  "Header-Name",
								Value: "Header Value",
							},
							Always: true,
						},
					},
					EgressMTLS: &EgressMTLS{
						Certificate:    "egress-mtls-secret.pem",
						CertificateKey: "egress-mtls-secret.pem",
						VerifyServer:   true,
						VerifyDepth:    1,
						Ciphers:        "DEFAULT",
						Protocols:      "TLSv1.3",
						TrustedCert:    "trusted-cert.pem",
						SessionReuse:   true,
						ServerName:     true,
					},
				},
				{
					Path:                     "@loc0",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
					ProxyInterceptErrors:     true,
					ErrorPages: []ErrorPage{
						{
							Name:         "@error_page_1",
							Codes:        "400 500",
							ResponseCode: 200,
						},
						{
							Name:         "@error_page_2",
							Codes:        "500",
							ResponseCode: 0,
						},
					},
				},
				{
					Path:                     "@loc1",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                "@loc2",
					ProxyConnectTimeout: "30s",
					ProxyReadTimeout:    "31s",
					ProxySendTimeout:    "32s",
					ClientMaxBodySize:   "1m",
					ProxyPass:           "http://coffee-v2",
					GRPCPass:            "grpc://coffee-v3",
				},
				{
					Path:                     "@match_loc_0",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                     "@match_loc_default",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                 "/return",
					ProxyInterceptErrors: true,
					ErrorPages: []ErrorPage{
						{
							Name:         "@return_0",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
			},
			ErrorPageLocations: []ErrorPageLocation{
				{
					Name:        "@vs_cafe_cafe_vsr_tea_tea_tea__tea_error_page_0",
					DefaultType: "application/json",
					Return: &Return{
						Code: 200,
						Text: "Hello World",
					},
					Headers: nil,
				},
				{
					Name:        "@vs_cafe_cafe_vsr_tea_tea_tea__tea_error_page_1",
					DefaultType: "",
					Return: &Return{
						Code: 200,
						Text: "Hello World",
					},
					Headers: []Header{
						{
							Name:  "Set-Cookie",
							Value: "cookie1=test",
						},
						{
							Name:  "Set-Cookie",
							Value: "cookie2=test; Secure",
						},
					},
				},
			},
			ReturnLocations: []ReturnLocation{
				{
					Name:        "@return_0",
					DefaultType: "text/html",
					Return: Return{
						Code: 200,
						Text: "Hello!",
					},
				},
			},
		},
	}

	virtualServerCfgPlus = VirtualServerConfig{
		LimitReqZones: []LimitReqZone{
			{
				ZoneName: "pol_rl_test_test_test_sync", Rate: "10r/s", ZoneSize: "10m", Key: "$url", Sync: true,
			},
		},
		Upstreams: []Upstream{
			{
				Name: "test-upstream",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:8001",
					},
				},
				LBMethod:         "random",
				Keepalive:        32,
				MaxFails:         4,
				FailTimeout:      "10s",
				MaxConns:         31,
				SlowStart:        "10s",
				UpstreamZoneSize: "256k",
				Queue:            &Queue{Size: 10, Timeout: "60s"},
				SessionCookie:    &SessionCookie{Enable: true, Name: "test", Path: "/tea", Expires: "25s"},
				NTLM:             true,
			},
			{
				Name: "coffee-v1",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.31:8001",
					},
				},
				MaxFails:         8,
				FailTimeout:      "15s",
				MaxConns:         2,
				UpstreamZoneSize: "256k",
			},
			{
				Name: "coffee-v2",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.32:8001",
					},
				},
				MaxFails:         12,
				FailTimeout:      "20s",
				MaxConns:         4,
				UpstreamZoneSize: "256k",
			},
		},
		SplitClients: []SplitClient{
			{
				Source:   "$request_id",
				Variable: "$split_0",
				Distributions: []Distribution{
					{
						Weight: "50%",
						Value:  "@loc0",
					},
					{
						Weight: "50%",
						Value:  "@loc1",
					},
				},
			},
		},
		Maps: []Map{
			{
				Source:   "$match_0_0",
				Variable: "$match",
				Parameters: []Parameter{
					{
						Value:  "~^1",
						Result: "@match_loc_0",
					},
					{
						Value:  "default",
						Result: "@match_loc_default",
					},
				},
			},
			{
				Source:   "$http_x_version",
				Variable: "$match_0_0",
				Parameters: []Parameter{
					{
						Value:  "v2",
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
		},
		HTTPSnippets: []string{"# HTTP snippet"},
		Server: Server{
			ServerName:    "example.com",
			StatusZone:    "example.com",
			ProxyProtocol: true,
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			TLSRedirect: &TLSRedirect{
				BasedOn: "$scheme",
				Code:    301,
			},
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Allow:           []string{"127.0.0.1"},
			Deny:            []string{"127.0.0.1"},
			LimitReqs: []LimitReq{
				{
					ZoneName: "pol_rl_test_test_test_sync",
					Delay:    10,
					Burst:    5,
				},
			},
			LimitReqOptions: LimitReqOptions{
				LogLevel:   "error",
				RejectCode: 503,
			},
			JWTAuth: &JWTAuth{
				Realm:  "My Api",
				Secret: "jwk-secret",
			},
			IngressMTLS: &IngressMTLS{
				ClientCert:   "ingress-mtls-secret",
				VerifyClient: "on",
				VerifyDepth:  2,
			},
			WAF: &WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				Enable:              "on",
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			Snippets: []string{"# server snippet"},
			InternalRedirectLocations: []InternalRedirectLocation{
				{
					Path:        "/split",
					Destination: "@split_0",
				},
				{
					Path:        "/coffee",
					Destination: "@match",
				},
			},
			HealthChecks: []HealthCheck{
				{
					Name:          "coffee",
					URI:           "/",
					Interval:      "5s",
					Jitter:        "0s",
					Fails:         1,
					Passes:        1,
					Port:          50,
					ProxyPass:     "http://coffee-v2",
					Mandatory:     true,
					Persistent:    true,
					KeepaliveTime: "60s",
					IsGRPC:        false,
				},
				{
					Name:        "tea",
					Interval:    "5s",
					Jitter:      "0s",
					Fails:       1,
					Passes:      1,
					Port:        50,
					ProxyPass:   "http://tea-v2",
					GRPCPass:    "grpc://tea-v3",
					GRPCStatus:  createPointerFromInt(12),
					GRPCService: "tea-servicev2",
					IsGRPC:      true,
				},
			},
			Locations: []Location{
				{
					Path:     "/",
					Snippets: []string{"# location snippet"},
					Allow:    []string{"127.0.0.1"},
					Deny:     []string{"127.0.0.1"},
					LimitReqs: []LimitReq{
						{
							ZoneName: "loc_pol_rl_test_test_test_sync",
						},
					},
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyBuffering:           true,
					ProxyBuffers:             "8 4k",
					ProxyBufferSize:          "4k",
					ProxyBusyBuffersSize:     "8k",
					ProxyMaxTempFileSize:     "1024m",
					ProxyPass:                "http://test-upstream",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
					Internal:                 true,
					ProxyPassRequestHeaders:  false,
					ProxyPassHeaders:         []string{"Host"},
					ProxyPassRewrite:         "$request_uri",
					ProxyHideHeaders:         []string{"Header"},
					ProxyIgnoreHeaders:       "Cache",
					Rewrites:                 []string{"$request_uri $request_uri", "$request_uri $request_uri"},
					AddHeaders: []AddHeader{
						{
							Header: Header{
								Name:  "Header-Name",
								Value: "Header Value",
							},
							Always: true,
						},
					},
					EgressMTLS: &EgressMTLS{
						Certificate:    "egress-mtls-secret.pem",
						CertificateKey: "egress-mtls-secret.pem",
						VerifyServer:   true,
						VerifyDepth:    1,
						Ciphers:        "DEFAULT",
						Protocols:      "TLSv1.3",
						TrustedCert:    "trusted-cert.pem",
						SessionReuse:   true,
						ServerName:     true,
					},
				},
				{
					Path:                     "@loc0",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
					ProxyInterceptErrors:     true,
					ErrorPages: []ErrorPage{
						{
							Name:         "@error_page_1",
							Codes:        "400 500",
							ResponseCode: 200,
						},
						{
							Name:         "@error_page_2",
							Codes:        "500",
							ResponseCode: 0,
						},
					},
				},
				{
					Path:                     "@loc1",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                "@loc2",
					ProxyConnectTimeout: "30s",
					ProxyReadTimeout:    "31s",
					ProxySendTimeout:    "32s",
					ClientMaxBodySize:   "1m",
					ProxyPass:           "http://coffee-v2",
					GRPCPass:            "grpc://coffee-v3",
				},
				{
					Path:                     "@match_loc_0",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v2",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                     "@match_loc_default",
					ProxyConnectTimeout:      "30s",
					ProxyReadTimeout:         "31s",
					ProxySendTimeout:         "32s",
					ClientMaxBodySize:        "1m",
					ProxyPass:                "http://coffee-v1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "5s",
				},
				{
					Path:                 "/return",
					ProxyInterceptErrors: true,
					ErrorPages: []ErrorPage{
						{
							Name:         "@return_0",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
			},
			ErrorPageLocations: []ErrorPageLocation{
				{
					Name:        "@vs_cafe_cafe_vsr_tea_tea_tea__tea_error_page_0",
					DefaultType: "application/json",
					Return: &Return{
						Code: 200,
						Text: "Hello World",
					},
					Headers: nil,
				},
				{
					Name:        "@vs_cafe_cafe_vsr_tea_tea_tea__tea_error_page_1",
					DefaultType: "",
					Return: &Return{
						Code: 200,
						Text: "Hello World",
					},
					Headers: []Header{
						{
							Name:  "Set-Cookie",
							Value: "cookie1=test",
						},
						{
							Name:  "Set-Cookie",
							Value: "cookie2=test; Secure",
						},
					},
				},
			},
			ReturnLocations: []ReturnLocation{
				{
					Name:        "@return_0",
					DefaultType: "text/html",
					Return: Return{
						Code: 200,
						Text: "Hello!",
					},
				},
			},
		},
	}

	virtualServerCfgWithHTTP2On = VirtualServerConfig{
		Server: Server{
			ServerName:    "example.com",
			StatusZone:    "example.com",
			ProxyProtocol: true,
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithHTTP2Off = VirtualServerConfig{
		Server: Server{
			ServerName:    "example.com",
			StatusZone:    "example.com",
			ProxyProtocol: true,
			SSL: &SSL{
				HTTP2:          false,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithGunzipOn = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			Locations: []Location{
				{
					Path: "/",
				},
			},
			Gunzip: true,
		},
	}

	virtualServerCfgWithGunzipOff = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			Locations: []Location{
				{
					Path: "/",
				},
			},
			Gunzip: false,
		},
	}

	virtualServerCfgWithGunzipNotSet = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithRateLimitJWTClaim = VirtualServerConfig{
		LimitReqZones: []LimitReqZone{
			{
				ZoneName: "pol_rl_test_test_test", Rate: "10r/s", ZoneSize: "10m", Key: "$url",
			},
		},
		Upstreams: []Upstream{},
		AuthJWTClaimSets: []AuthJWTClaimSet{
			{
				Variable: "$jwt_default_webapp_group_consumer_group_type",
				Claim:    "consumer_group type",
			},
		},
		Maps: []Map{
			{
				Source:   "$jwt_default_webapp_group_consumer_group_type",
				Variable: "$rate_limit_default_webapp_group_consumer_group_type",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: "Group3",
					},
					{
						Value:  "Gold",
						Result: "Group1",
					},
					{
						Value:  "Silver",
						Result: "Group2",
					},
					{
						Value:  "Bronze",
						Result: "Group3",
					},
				},
			},
			{
				Source:   "$rate_limit_default_webapp_group_consumer_group_type",
				Variable: "$http_gold",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "Group1",
						Result: "$jwt_claim_sub",
					},
				},
			},
			{
				Source:   "$rate_limit_default_webapp_group_consumer_group_type",
				Variable: "$http_silver",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "Group2",
						Result: "$jwt_claim_sub",
					},
				},
			},
			{
				Source:   "$rate_limit_default_webapp_group_consumer_group_type",
				Variable: "$http_bronze",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "Group3",
						Result: "$jwt_claim_sub",
					},
				},
			},
		},
		HTTPSnippets: []string{"# HTTP snippet"},
		Server: Server{
			ServerName:   "example.com",
			StatusZone:   "example.com",
			ServerTokens: "off",
			LimitReqs: []LimitReq{
				{
					ZoneName: "pol_rl_test_test_test",
					Delay:    10,
					Burst:    5,
				},
			},
			LimitReqOptions: LimitReqOptions{
				LogLevel:   "error",
				RejectCode: 503,
			},
		},
	}

	virtualServerCfgWithRateLimitVariableAPIKey = VirtualServerConfig{
		LimitReqZones: []LimitReqZone{
			{
				Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe",
				ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe",
				ZoneSize:      "10M",
				Rate:          "10r/s",
				PolicyResult:  "$apikey_client_name",
				GroupVariable: "$rl_default_cafe_variable_apikey_client_name_route_L3RlYQ",
				PolicyValue:   "rl_default_cafe_match_premium_rate_limit_policy",
				GroupValue:    `"premium"`,
				GroupSource:   "$apikey_client_name",
			},
			{
				Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe",
				ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe",
				ZoneSize:      "20M",
				Rate:          "20r/s",
				PolicyResult:  "$apikey_client_name",
				GroupVariable: "$rl_default_cafe_variable_apikey_client_name_route_L3RlYQ",
				PolicyValue:   "rl_default_cafe_match_basic_rate_limit_policy",
				GroupValue:    `"basic"`,
				GroupSource:   "$apikey_client_name",
				GroupDefault:  true,
			},
		},
		Upstreams: []Upstream{},
		Maps: []Map{
			{
				Source:   "$apikey_client_name",
				Variable: "$rl_default_cafe_variable_apikey_client_name_route_L3RlYQ",
				Parameters: []Parameter{
					{
						Value:  `"basic"`,
						Result: "rl_default_cafe_match_basic_rate_limit_policy",
					},
					{
						Value:  "default",
						Result: "rl_default_cafe_match_basic_rate_limit_policy",
					},
					{
						Value:  `"premium"`,
						Result: "rl_default_cafe_match_premium_rate_limit_policy",
					},
				},
			},
			{
				Source:   "$rl_default_cafe_variable_apikey_client_name_route_L3RlYQ",
				Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "rl_default_cafe_match_premium_rate_limit_policy",
						Result: "Val$apikey_client_name",
					},
				},
			},
			{
				Source:   "$rl_default_cafe_variable_apikey_client_name_route_L3RlYQ",
				Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "rl_default_cafe_match_basic_rate_limit_policy",
						Result: "Val$apikey_client_name",
					},
				},
			},
			{
				Source:   "$apikey_auth_token",
				Variable: "$apikey_auth_client_name_default_cafe_api_key_policy",
				Parameters: []Parameter{
					{
						Value:  "default",
						Result: `""`,
					},
					{
						Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
						Result: `"premium"`,
					},
					{
						Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
						Result: `"basic"`,
					},
				},
			},
		},
		Server: Server{
			ServerName:   "cafe.example.com",
			StatusZone:   "cafe.example.com",
			ServerTokens: "off",
			VSNamespace:  "default",
			VSName:       "cafe",

			Locations: []Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
					LimitReqs: []LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
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
					ProxySetHeaders:          []Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
				},
			},
			APIKeyEnabled: true,
			APIKey: &APIKey{
				Header:  []string{"X-API-Key"},
				Query:   []string{"api-key"},
				MapName: "apikey_auth_client_name_default_cafe_api_key_policy",
			},
		},
	}

	virtualServerCfgWithWAFApBundle = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			WAF: &WAF{
				ApBundle:            "/fake/bundle/path/NginxDefaultPolicy.tgz",
				ApSecurityLogEnable: true,
				Enable:              "on",
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithSessionCookieSameSite = VirtualServerConfig{
		Upstreams: []Upstream{
			{
				Name: "test-upstream",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:8001",
					},
				},
				// SessionCookie set for test:
				SessionCookie: &SessionCookie{
					Enable:   true,
					Name:     "test",
					Path:     "/tea",
					Expires:  "25s",
					SameSite: "STRICT",
				},
			},
		},
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	// VirtualServer Config data for JWT Policy tests

	virtualServerCfgWithJWTPolicyJWKSWithToken = VirtualServerConfig{
		Upstreams: []Upstream{
			{
				UpstreamLabels: UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
		},
		Server: Server{
			JWTAuthList: map[string]*JWTAuth{
				"default/jwt-policy": {
					Key:      "default/jwt-policy",
					Realm:    "Spec Realm API",
					Token:    "$http_token",
					KeyCache: "1h",
					JwksURI: JwksURI{
						JwksScheme:     "https",
						JwksHost:       "idp.spec.example.com",
						JwksPort:       "443",
						JwksPath:       "/spec-keys",
						JwksSNIEnabled: true,
						JwksSNIName:    "sni.idp.spec.example.com",
					},
				},
				"default/jwt-policy-route": {
					Key:      "default/jwt-policy-route",
					Realm:    "Route Realm API",
					Token:    "$http_token",
					KeyCache: "1h",
					JwksURI: JwksURI{
						JwksScheme:     "http",
						JwksHost:       "idp.route.example.com",
						JwksPort:       "80",
						JwksPath:       "/route-keys",
						JwksSNIEnabled: true,
						JwksSNIName:    "sni.idp.spec.example.com",
					},
				},
			},
			JWTAuth: &JWTAuth{
				Key:      "default/jwt-policy",
				Realm:    "Spec Realm API",
				Token:    "$http_token",
				KeyCache: "1h",
				JwksURI: JwksURI{
					JwksScheme: "https",
					JwksHost:   "idp.spec.example.com",
					JwksPort:   "443",
					JwksPath:   "/spec-keys",
				},
			},
			JWKSAuthEnabled: true,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			Locations: []Location{
				{
					Path:        "/tea",
					ServiceName: "tea-svc",
					ProxyPass:   "http://vs_default_cafe_tea",
					JWTAuth: &JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						Token:    "$http_token",
						KeyCache: "1h",
						JwksURI: JwksURI{
							JwksScheme: "http",
							JwksHost:   "idp.route.example.com",
							JwksPort:   "80",
							JwksPath:   "/route-keys",
						},
					},
				},
				{
					Path:        "/coffee",
					ServiceName: "coffee-svc",
					ProxyPass:   "http://vs_default_cafe_coffee",
					JWTAuth: &JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						Token:    "$http_token",
						KeyCache: "1h",
						JwksURI: JwksURI{
							JwksScheme: "http",
							JwksHost:   "idp.route.example.com",
							JwksPort:   "80",
							JwksPath:   "/route-keys",
						},
					},
				},
			},
		},
	}

	virtualServerCfgWithJWTPolicyJWKSWithoutToken = VirtualServerConfig{
		Upstreams: []Upstream{
			{
				UpstreamLabels: UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
		},
		Server: Server{
			JWTAuthList: map[string]*JWTAuth{
				"default/jwt-policy": {
					Key:      "default/jwt-policy",
					Realm:    "Spec Realm API",
					KeyCache: "1h",
					JwksURI: JwksURI{
						JwksScheme: "https",
						JwksHost:   "idp.spec.example.com",
						JwksPort:   "443",
						JwksPath:   "/spec-keys",
					},
				},
				"default/jwt-policy-route": {
					Key:      "default/jwt-policy-route",
					Realm:    "Route Realm API",
					KeyCache: "1h",
					JwksURI: JwksURI{
						JwksScheme: "http",
						JwksHost:   "idp.route.example.com",
						JwksPort:   "80",
						JwksPath:   "/route-keys",
					},
				},
			},
			JWTAuth: &JWTAuth{
				Key:      "default/jwt-policy",
				Realm:    "Spec Realm API",
				KeyCache: "1h",
				JwksURI: JwksURI{
					JwksScheme: "https",
					JwksHost:   "idp.spec.example.com",
					JwksPort:   "443",
					JwksPath:   "/spec-keys",
				},
			},
			JWKSAuthEnabled: true,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			Locations: []Location{
				{
					Path:        "/tea",
					ProxyPass:   "http://vs_default_cafe_tea",
					ServiceName: "tea-svc",
					JWTAuth: &JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						KeyCache: "1h",
						JwksURI: JwksURI{
							JwksScheme: "http",
							JwksHost:   "idp.route.example.com",
							JwksPort:   "80",
							JwksPath:   "/route-keys",
						},
					},
				},
				{
					Path:        "/coffee",
					ProxyPass:   "http://vs_default_cafe_coffee",
					ServiceName: "coffee-svc",
					JWTAuth: &JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						KeyCache: "1h",
						JwksURI: JwksURI{
							JwksScheme: "http",
							JwksHost:   "idp.route.example.com",
							JwksPort:   "80",
							JwksPath:   "/route-keys",
						},
					},
				},
			},
		},
	}

	virtualServerCfgWithCustomListener = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			CustomListeners: true,
			HTTPPort:        8082,
			HTTPSPort:       8443,
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithCustomListenerIP = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			CustomListeners: true,
			HTTPPort:        8082,
			HTTPSPort:       8443,
			HTTPIPv4:        "127.0.0.1",
			HTTPIPv6:        "::1",
			HTTPSIPv4:       "127.0.0.2",
			HTTPSIPv6:       "::2",
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithCustomListenerHTTPOnly = VirtualServerConfig{
		Server: Server{
			ServerName:      "example.com",
			StatusZone:      "example.com",
			CustomListeners: true,
			HTTPPort:        8082,
			HTTPSPort:       0,
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithCustomListenerHTTPSOnly = VirtualServerConfig{
		Server: Server{
			ServerName: "example.com",
			StatusZone: "example.com",
			SSL: &SSL{
				HTTP2:          true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			CustomListeners: true,
			HTTPPort:        0,
			HTTPSPort:       8443,
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithOIDCAndPKCETurnedOn = VirtualServerConfig{
		Server: Server{
			ServerName:    "example.com",
			StatusZone:    "example.com",
			ProxyProtocol: true,
			OIDC: &OIDC{
				PKCEEnable: true,
			},
			Locations: []Location{
				{
					Path: "/",
				},
			},
		},
	}

	virtualServerCfgWithCachePolicyNGINXPlus = VirtualServerConfig{
		CacheZones: []CacheZone{
			{
				Name:   "test_cache_full_advanced",
				Size:   "50m",
				Path:   "/var/cache/nginx/test_cache_full_advanced",
				Levels: "2:2",
			},
			{
				Name:   "test_cache_location_location_cache",
				Size:   "20m",
				Path:   "/var/cache/nginx/test_cache_location_location_cache",
				Levels: "",
			},
		},
		Upstreams: []Upstream{
			{
				Name: "test-upstream",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:8001",
					},
				},
			},
		},
		Server: Server{
			ServerName:   "example.com",
			StatusZone:   "example.com",
			ServerTokens: "off",
			// Server-level cache policy with all advanced options (NGINX Plus)
			Cache: &Cache{
				ZoneName:              "test_cache_full_advanced",
				ZoneSize:              "50m",
				Time:                  "2h",
				Valid:                 map[string]string{"200": "2h", "404": "2h", "301": "2h"},
				AllowedMethods:        []string{"GET", "HEAD", "POST"},
				CachePurgeAllow:       []string{"127.0.0.1", "10.0.0.0/8", "192.168.1.0/24"},
				OverrideUpstreamCache: true,
				Levels:                "2:2",
			},
			Locations: []Location{
				{
					Path:      "/",
					ProxyPass: "http://test-upstream",
					// Location-level cache policy with basic options
					Cache: &Cache{
						ZoneName:              "test_cache_location_location_cache",
						ZoneSize:              "20m",
						Time:                  "1h",
						Valid:                 map[string]string{"any": "1h"},
						AllowedMethods:        []string{"GET", "HEAD"},
						CachePurgeAllow:       nil,
						OverrideUpstreamCache: false,
						Levels:                "",
					},
				},
			},
		},
	}

	virtualServerCfgWithCachePolicyOSS = VirtualServerConfig{
		CacheZones: []CacheZone{
			{
				Name:   "test_cache_basic_cache",
				Size:   "10m",
				Path:   "/var/cache/nginx/test_cache_basic_cache",
				Levels: "1:2",
			},
			{
				Name:   "test_cache_location_simple_cache",
				Size:   "5m",
				Path:   "/var/cache/nginx/test_cache_location_simple_cache",
				Levels: "",
			},
		},
		Upstreams: []Upstream{
			{
				Name: "test-upstream",
				Servers: []UpstreamServer{
					{
						Address: "10.0.0.20:8001",
					},
				},
			},
		},
		Server: Server{
			ServerName:   "example.com",
			StatusZone:   "example.com",
			ServerTokens: "off",
			// Server-level cache policy with basic options (OSS)
			Cache: &Cache{
				ZoneName:              "test_cache_basic_cache",
				ZoneSize:              "10m",
				Time:                  "1h",
				Valid:                 map[string]string{"any": "1h"},
				AllowedMethods:        []string{"GET", "HEAD"},
				CachePurgeAllow:       []string{"127.0.0.1"}, // This should be ignored for OSS
				OverrideUpstreamCache: true,
				Levels:                "1:2",
			},
			Locations: []Location{
				{
					Path:      "/",
					ProxyPass: "http://test-upstream",
					// Location-level cache policy with specific status codes
					Cache: &Cache{
						ZoneName:              "test_cache_location_simple_cache",
						ZoneSize:              "5m",
						Time:                  "30m",
						Valid:                 map[string]string{"200": "30m", "404": "30m"},
						AllowedMethods:        nil,
						CachePurgeAllow:       nil,
						OverrideUpstreamCache: false,
						Levels:                "",
					},
				},
			},
		},
	}

	transportServerCfg = TransportServerConfig{
		Upstreams: []StreamUpstream{
			{
				Name: "udp-upstream",
				Servers: []StreamUpstreamServer{
					{
						Address: "10.0.0.20:5001",
					},
				},
			},
		},
		Match: &Match{
			Name:                "match_udp-upstream",
			Send:                `GET / HTTP/1.0\r\nHost: localhost\r\n\r\n`,
			ExpectRegexModifier: "~*",
			Expect:              "200 OK",
		},
		Server: StreamServer{
			Port:                     1234,
			UDP:                      true,
			StatusZone:               "udp-app",
			ProxyRequests:            createPointerFromInt(1),
			ProxyResponses:           createPointerFromInt(2),
			ProxyPass:                "udp-upstream",
			ProxyTimeout:             "10s",
			ProxyConnectTimeout:      "10s",
			ProxyNextUpstream:        true,
			ProxyNextUpstreamTimeout: "10s",
			ProxyNextUpstreamTries:   5,
			HealthCheck: &StreamHealthCheck{
				Enabled:  false,
				Timeout:  "5s",
				Jitter:   "0",
				Port:     8080,
				Interval: "5s",
				Passes:   1,
				Fails:    1,
				Match:    "match_udp-upstream",
			},
		},
	}

	transportServerCfgWithResolver = TransportServerConfig{
		Upstreams: []StreamUpstream{
			{
				Name: "udp-upstream",
				Servers: []StreamUpstreamServer{
					{
						Address: "10.0.0.20:5001",
					},
				},
				Resolve: true,
			},
		},
		Match: &Match{
			Name:                "match_udp-upstream",
			Send:                `GET / HTTP/1.0\r\nHost: localhost\r\n\r\n`,
			ExpectRegexModifier: "~*",
			Expect:              "200 OK",
		},
		Server: StreamServer{
			Port:                     1234,
			UDP:                      true,
			StatusZone:               "udp-app",
			ProxyRequests:            createPointerFromInt(1),
			ProxyResponses:           createPointerFromInt(2),
			ProxyPass:                "udp-upstream",
			ProxyTimeout:             "10s",
			ProxyConnectTimeout:      "10s",
			ProxyNextUpstream:        true,
			ProxyNextUpstreamTimeout: "10s",
			ProxyNextUpstreamTries:   5,
			HealthCheck: &StreamHealthCheck{
				Enabled:  false,
				Timeout:  "5s",
				Jitter:   "0",
				Port:     8080,
				Interval: "5s",
				Passes:   1,
				Fails:    1,
				Match:    "match_udp-upstream",
			},
		},
	}

	transportServerCfgWithSNI = TransportServerConfig{
		Upstreams: []StreamUpstream{
			{
				Name: "cafe-upstream",
				Servers: []StreamUpstreamServer{
					{
						Address: "10.0.0.20:5001",
					},
				},
			},
		},
		Server: StreamServer{
			Port:           1234,
			ServerName:     "cafe.example.com",
			TLSPassthrough: false,
			SSL: &StreamSSL{
				Enabled:        true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
			ProxyRequests:            createPointerFromInt(1),
			ProxyResponses:           createPointerFromInt(2),
			ProxyPass:                "cafe-upstream",
			ProxyTimeout:             "10s",
			ProxyConnectTimeout:      "10s",
			ProxyNextUpstream:        true,
			ProxyNextUpstreamTimeout: "10s",
			ProxyNextUpstreamTries:   5,
		},
	}

	transportServerCfgWithSSL = TransportServerConfig{
		Upstreams: []StreamUpstream{
			{
				Name: "udp-upstream",
				Servers: []StreamUpstreamServer{
					{
						Address: "10.0.0.20:5001",
					},
				},
			},
		},
		Match: &Match{
			Name:                "match_udp-upstream",
			Send:                `GET / HTTP/1.0\r\nHost: localhost\r\n\r\n`,
			ExpectRegexModifier: "~*",
			Expect:              "200 OK",
		},
		Server: StreamServer{
			Port:                     1234,
			UDP:                      true,
			StatusZone:               "udp-app",
			ProxyRequests:            createPointerFromInt(1),
			ProxyResponses:           createPointerFromInt(2),
			ProxyPass:                "udp-upstream",
			ProxyTimeout:             "10s",
			ProxyConnectTimeout:      "10s",
			ProxyNextUpstream:        true,
			ProxyNextUpstreamTimeout: "10s",
			ProxyNextUpstreamTries:   5,
			HealthCheck: &StreamHealthCheck{
				Enabled:  false,
				Timeout:  "5s",
				Jitter:   "0",
				Port:     8080,
				Interval: "5s",
				Passes:   1,
				Fails:    1,
				Match:    "match_udp-upstream",
			},
			SSL: &StreamSSL{
				Enabled:        true,
				Certificate:    "cafe-secret.pem",
				CertificateKey: "cafe-secret.pem",
			},
		},
	}
)
