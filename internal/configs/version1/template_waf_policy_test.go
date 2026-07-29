package version1

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
)

func TestExecuteTemplate_ForIngressForNGINXPlusWithServerWAFPolicy(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	cfg := IngressNginxConfig{
		Ingress: Ingress{
			Name:      "ing",
			Namespace: "default",
		},
		Servers: []Server{
			{
				Name:         "example.com",
				ServerTokens: "on",
				StatusZone:   "example.com",
				Ports:        []int{80},
				SSLPorts:     []int{443},
				Locations: []Location{
					{
						Path:        "/",
						ServiceName: "svc",
						Upstream: Upstream{
							Name: "ups",
							UpstreamServers: []UpstreamServer{
								{Address: "127.0.0.1:80", MaxFails: 1, FailTimeout: "10s"},
							},
						},
						ProxyPass: "http://test",
					},
				},
				WAF: &version2.WAF{
					Enable:              "on",
					ApPolicy:            "/etc/nginx/waf/nac-policies/default_policy",
					ApSecurityLogEnable: true,
					ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514"},
				},
			},
		},
		Upstreams: []Upstream{
			{
				Name: "ups",
				UpstreamServers: []UpstreamServer{
					{Address: "127.0.0.1:80", MaxFails: 1, FailTimeout: "10s"},
				},
				UpstreamZoneSize: "512k",
			},
		},
	}

	err := tmpl.Execute(buf, cfg)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"app_protect_enable on;",
		"app_protect_policy_file /etc/nginx/waf/nac-policies/default_policy;",
		"app_protect_security_log_enable on;",
		"app_protect_security_log /etc/nginx/waf/nac-logconfs/default_logconf syslog:server=127.0.0.1:514;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	snaps.MatchSnapshot(t, out)
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithLocationWAFBundle(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	cfg := IngressNginxConfig{
		Ingress: Ingress{
			Name:      "ing",
			Namespace: "default",
		},
		Servers: []Server{
			{
				Name:         "example.com",
				ServerTokens: "on",
				StatusZone:   "example.com",
				Ports:        []int{80},
				SSLPorts:     []int{443},
				Locations: []Location{
					{
						Path:        "/",
						ServiceName: "svc",
						Upstream: Upstream{
							Name: "ups",
							UpstreamServers: []UpstreamServer{
								{Address: "127.0.0.1:80", MaxFails: 1, FailTimeout: "10s"},
							},
						},
						ProxyPass: "http://test",
						WAF: &version2.WAF{
							Enable:   "on",
							ApBundle: "/etc/nginx/waf/bundles/wafv5.tgz",
						},
					},
				},
			},
		},
		Upstreams: []Upstream{
			{
				Name: "ups",
				UpstreamServers: []UpstreamServer{
					{Address: "127.0.0.1:80", MaxFails: 1, FailTimeout: "10s"},
				},
				UpstreamZoneSize: "512k",
			},
		},
	}

	err := tmpl.Execute(buf, cfg)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"location /",
		"app_protect_enable on;",
		"app_protect_policy_file /etc/nginx/waf/bundles/wafv5.tgz;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	snaps.MatchSnapshot(t, out)
}
