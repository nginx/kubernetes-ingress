package configs

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

func TestParseConfigMapWithAppProtectCompressedRequestsAction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		action string
		expect string
		msg    string
	}{
		{
			action: "pass",
			expect: "pass",
			msg:    "valid action pass",
		},
		{
			action: "drop",
			expect: "drop",
			msg:    "valid action drop",
		},
		{
			action: "invalid",
			expect: "",
			msg:    "invalid action",
		},
		{
			action: "",
			expect: "",
			msg:    "empty action",
		},
	}
	nginxPlus := true
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := false
	for _, test := range tests {
		cm := &v1.ConfigMap{
			Data: map[string]string{
				"app-protect-compressed-requests-action": test.action,
			},
		}
		result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
		if result.MainAppProtectCompressedRequestsAction != test.expect {
			t.Errorf("ParseConfigMap() returned %q but expected %q for the case %s", result.MainAppProtectCompressedRequestsAction, test.expect, test.msg)
		}
	}
}

func TestParseConfigMapWithAppProtectReconnectPeriod(t *testing.T) {
	tests := []struct {
		period string
		expect string
		msg    string
	}{
		{
			period: "25",
			expect: "25",
			msg:    "valid period 25",
		},
		{
			period: "13.875",
			expect: "13.875",
			msg:    "valid period 13.875",
		},
		{
			period: "0.125",
			expect: "0.125",
			msg:    "valid period 0.125",
		},
		{
			period: "60",
			expect: "60",
			msg:    "valid period 60",
		},
		{
			period: "60.1",
			expect: "",
			msg:    "invalid period 60.1",
		},
		{
			period: "100",
			expect: "",
			msg:    "invalid period 100",
		},
		{
			period: "0",
			expect: "",
			msg:    "invalid period 0",
		},
		{
			period: "-5",
			expect: "",
			msg:    "invalid period -5",
		},
		{
			period: "",
			expect: "",
			msg:    "empty period",
		},
	}
	nginxPlus := true
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := false
	for _, test := range tests {
		cm := &v1.ConfigMap{
			Data: map[string]string{
				"app-protect-reconnect-period-seconds": test.period,
			},
		}
		result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
		if result.MainAppProtectReconnectPeriod != test.expect {
			t.Errorf("ParseConfigMap() returned %q but expected %q for the case %s", result.MainAppProtectReconnectPeriod, test.expect, test.msg)
		}
	}
}

func TestParseConfigMapWithTLSPassthroughProxyProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		realIPheader string
		want         string
		msg          string
	}{
		{
			realIPheader: "proxy_protocol",
			want:         "",
			msg:          "valid realIPheader proxy_protocol, ignored when TLS Passthrough is enabled",
		},
		{
			realIPheader: "X-Forwarded-For",
			want:         "",
			msg:          "invalid realIPheader X-Forwarded-For, ignored when TLS Passthrough is enabled",
		},
		{
			realIPheader: "",
			want:         "",
			msg:          "empty real-ip-header",
		},
	}
	nginxPlus := true
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := true
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"real-ip-header": test.realIPheader,
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if result.RealIPHeader != test.want {
				t.Errorf("want %q, got %q", test.want, result.RealIPHeader)
			}
		})
	}
}

func TestParseConfigMapWithoutTLSPassthroughProxyProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		realIPheader string
		want         string
		msg          string
	}{
		{
			realIPheader: "proxy_protocol",
			want:         "proxy_protocol",
			msg:          "valid real-ip-header proxy_protocol",
		},
		{
			realIPheader: "X-Forwarded-For",
			want:         "X-Forwarded-For",
			msg:          "valid real-ip-header X-Forwarded-For",
		},
		{
			realIPheader: "",
			want:         "",
			msg:          "empty real-ip-header",
		},
	}
	nginxPlus := true
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"real-ip-header": test.realIPheader,
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if result.RealIPHeader != test.want {
				t.Errorf("want %q, got %q", test.want, result.RealIPHeader)
			}
		})
	}
}

func TestParseConfigMapAccessLog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		accessLog    string
		accessLogOff string
		want         string
		msg          string
	}{
		{
			accessLogOff: "False",
			accessLog:    "syslog:server=localhost:514",
			want:         "syslog:server=localhost:514",
			msg:          "Non default access_log",
		},
		{
			accessLogOff: "False",
			accessLog:    "/tmp/nginx main",
			want:         "/dev/stdout main",
			msg:          "access_log to file is not allowed",
		},
		{
			accessLogOff: "True",
			accessLog:    "/dev/stdout main",
			want:         "off",
			msg:          "Disabled access_log",
		},
	}
	nginxPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"access-log":     test.accessLog,
					"access-log-off": test.accessLogOff,
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if result.MainAccessLog != test.want {
				t.Errorf("want %q, got %q", test.want, result.MainAccessLog)
			}
		})
	}
}

func TestParseConfigMapAccessLogDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		accessLog    string
		accessLogOff string
		want         string
		msg          string
	}{
		{
			want: "/dev/stdout main",
			msg:  "Default access_log",
		},
	}
	nginxPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"access-log-off": "False",
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if result.MainAccessLog != test.want {
				t.Errorf("want %q, got %q", test.want, result.MainAccessLog)
			}
		})
	}
}

func TestParseMGMTConfigMapError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "",
				},
			},
			msg: "Must have license-token-secret-name",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{},
			},
			msg: "Must have license-token-secret-name key",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, _, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())

			if err == nil {
				t.Errorf("Expected error, got nil")
			}
		})
	}
}

func TestParseMGMTConfigMapWarnings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"enforce-initial-report":    "7",
				},
			},
			msg: "enforce-initial-report is invalid",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"enforce-initial-report":    "",
				},
			},
			msg: "enforce-initial-report set empty",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "",
				},
			},
			msg: "usage-report-interval set empty",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1s",
				},
			},
			msg: "usage-report-interval set below allowed value",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1s",
				},
			},
			msg: "usage-report-interval set below allowed value",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"ssl-verify":                "10",
				},
			},
			msg: "ssl-verify set to an invalid int",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"ssl-verify":                "test",
				},
			},
			msg: "ssl-verify set to an invalid value",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"ssl-verify":                "",
				},
			},
			msg: "ssl-verify set to an empty string",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"resolver-ipv6":             "",
				},
			},
			msg: "resolver-ipv6 set to an empty string",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"resolver-ipv6":             "10",
				},
			},
			msg: "resolver-ipv6 set to an invalid int",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "10",
				},
			},
			msg: "usage-report-proxy-host set to an invalid host",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, configWarnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Errorf("expected nil, got err: %v", err)
			}
			if !configWarnings {
				t.Fatal("Expected warnings, got none")
			}
		})
	}
}

func TestParseMGMTConfigMapLicense(t *testing.T) {
	t.Parallel()
	test := struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		configMap: &v1.ConfigMap{
			Data: map[string]string{
				"license-token-secret-name": "license-token",
			},
		},
		want: &MGMTConfigParams{
			Secrets: MGMTSecrets{
				License: "license-token",
			},
		},
		msg: "Has only license-token-secret-name",
	}

	t.Run(test.msg, func(t *testing.T) {
		result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
		if err != nil {
			t.Fatal(err)
		}
		if warnings {
			t.Fatal("Unexpected warnings")
		}
		if result.Secrets.License != test.want.Secrets.License {
			t.Errorf("LicenseTokenSecretNane: want %q, got %q", test.want.Secrets.License, result.Secrets.License)
		}
	})
}

func TestParseMGMTConfigMapEnforceInitialReport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"enforce-initial-report":    "false",
				},
			},
			want: &MGMTConfigParams{
				EnforceInitialReport: commonhelpers.BoolToPointerBool(false),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "enforce-initial-report set to false",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"enforce-initial-report":    "true",
				},
			},
			want: &MGMTConfigParams{
				EnforceInitialReport: commonhelpers.BoolToPointerBool(true),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "enforce-initial-report set to true",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if result.EnforceInitialReport == nil {
				t.Errorf("EnforceInitialReport: want %v, got nil", *test.want.EnforceInitialReport)
			}
			if *result.EnforceInitialReport != *test.want.EnforceInitialReport {
				t.Errorf("EnforceInitialReport: want %v, got %v", *test.want.EnforceInitialReport, *result.EnforceInitialReport)
			}
		})
	}
}

func TestParseMGMTConfigMapSSLVerify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"ssl-verify":                "false",
				},
			},
			want: &MGMTConfigParams{
				SSLVerify: commonhelpers.BoolToPointerBool(false),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "ssl-verify set to false",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"ssl-verify":                "true",
				},
			},
			want: &MGMTConfigParams{
				SSLVerify: commonhelpers.BoolToPointerBool(true),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "ssl-verify set to true",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if result.SSLVerify == nil {
				t.Errorf("ssl-verify: want %v, got nil", *test.want.SSLVerify)
			}
			if *result.SSLVerify != *test.want.SSLVerify {
				t.Errorf("ssl-verify: want %v, got %v", *test.want.SSLVerify, *result.SSLVerify)
			}
		})
	}
}

func TestParseMGMTConfigMapUsageReportInterval(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "120s",
				},
			},
			want: &MGMTConfigParams{
				Interval: "120s",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "usage report interval set to 120s",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "20m",
				},
			},
			want: &MGMTConfigParams{
				Interval: "20m",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "usage report interval set to 20m",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1h",
				},
			},
			want: &MGMTConfigParams{
				Interval: "1h",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "usage report interval set to 1h",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "24h",
				},
			},
			want: &MGMTConfigParams{
				Interval: "24h",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "usage report interval set to 24h",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if result.Interval == "" {
				t.Errorf("UsageReportInterval: want %s, got empty string", test.want.Interval)
			}
			if result.Interval != test.want.Interval {
				t.Errorf("UsageReportInterval: want %v, got %v", test.want.Interval, result.Interval)
			}
		})
	}
}

func TestParseMGMTConfigMapResolverIPV6(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"resolver-ipv6":             "false",
				},
			},
			want: &MGMTConfigParams{
				ResolverIPV6: commonhelpers.BoolToPointerBool(false),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "resolver-ipv6 set to false",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"resolver-ipv6":             "true",
				},
			},
			want: &MGMTConfigParams{
				ResolverIPV6: commonhelpers.BoolToPointerBool(true),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "resolver-ipv6 set to true",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if result.ResolverIPV6 == nil {
				t.Errorf("resolver-ipv6: want %v, got nil", *test.want.ResolverIPV6)
			}
			if *result.ResolverIPV6 != *test.want.ResolverIPV6 {
				t.Errorf("resolver-ipv6: want %v, got %v", *test.want.ResolverIPV6, *result.ResolverIPV6)
			}
		})
	}
}

func TestParseMGMTConfigMapUsageReportEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-endpoint":     "product.connect.nginx.com",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "usage report endpoint set to product.connect.nginx.com",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-endpoint":     "product.connect.nginx.com:80",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com:80",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
			},
			msg: "usage report endpoint set to product.connect.nginx.com with port 80",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if result.Endpoint == "" {
				t.Errorf("UsageReportEndpoint: want %s, got empty string", test.want.Endpoint)
			}
			if result.Endpoint != test.want.Endpoint {
				t.Errorf("UsageReportEndpoint: want %v, got %v", test.want.Endpoint, result.Endpoint)
			}
		})
	}
}

func TestParseMGMTConfigMapUsageReportProxyHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "proxy.example.com",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "proxy.example.com",
			},
			msg: "usage report proxy-host set to proxy.example.com",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "proxy.example.com:3128",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "proxy.example.com:3128",
			},
			msg: "usage report proxy-host set to proxy.example.com with port 3128",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "proxy",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "proxy",
			},
			msg: "usage report proxy-host set to proxy",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "proxy:3128",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "proxy:3128",
			},
			msg: "usage report proxy-host set to proxy with port 3128",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "192.168.1.254",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "192.168.1.254",
			},
			msg: "usage report proxy-host set to 192.168.1.254",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "192.168.1.254:3128",
				},
			},
			want: &MGMTConfigParams{
				Endpoint: "product.connect.nginx.com",
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "192.168.1.254:3128",
			},
			msg: "usage report proxy-host set to 192.168.1.254 with port 3128",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if result.ProxyHost == "" {
				t.Errorf("UsageReportProxyHost: want %s, got empty string", test.want.ProxyHost)
			}
			if result.ProxyHost != test.want.ProxyHost {
				t.Errorf("UsageReportProxyHost: want %v, got %v", test.want.ProxyHost, result.ProxyHost)
			}
		})
	}
}

func TestParseMGMTConfigMapUsageReportProxyCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		user      string
		pass      string
		want      *MGMTConfigParams
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "proxy.example.com:3128",
				},
			},
			user: "user",
			pass: "pass",
			want: &MGMTConfigParams{
				Context: context.Background(),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "proxy.example.com:3128",
				ProxyUser: "user",
				ProxyPass: "pass",
			},
			msg: "usage report proxy user and pass set",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-proxy-host":   "proxy.example.com:3128",
				},
			},
			user: "user",
			pass: "",
			want: &MGMTConfigParams{
				Context: context.Background(),
				Secrets: MGMTSecrets{
					License: "license-token",
				},
				ProxyHost: "proxy.example.com:3128",
				ProxyUser: "user",
				ProxyPass: "",
			},
			msg: "usage report proxy user set with no pass",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			err := os.Setenv("PROXY_USER", test.user)
			if err != nil {
				t.Error(err)
			}

			err = os.Setenv("PROXY_PASS", test.pass)
			if err != nil {
				t.Error(err)
			}

			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Error(err)
			}
			if warnings {
				t.Error("Unexpected warnings")
			}

			if !reflect.DeepEqual(result, test.want) {
				t.Errorf("got %v, want %v", result, test.want)
			}
		})
	}
}

func TestParseZoneSync(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *ZoneSync
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync": "true",
				},
			},
			want: &ZoneSync{
				Enable: true,
				Port:   12345,
			},
			msg: "zone-sync set to true",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync": "false",
				},
			},
			want: &ZoneSync{
				Enable: false,
				Port:   0,
			},
			msg: "zone-sync set to false",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, _ := ParseConfigMap(context.Background(), test.configMap, true, false, false, false, makeEventLogger())
			if result.ZoneSync.Enable != test.want.Enable {
				t.Errorf("Enable: want %v, got %v", test.want.Enable, result.ZoneSync)
			}
		})
	}
}

func TestParseZoneSyncForOSS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *ZoneSync
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync": "true",
				},
			},
			want: &ZoneSync{
				Enable: true,
				Port:   12345,
			},
			msg: "zone-sync set to true",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync": "false",
				},
			},
			want: &ZoneSync{
				Enable: false,
				Port:   0,
			},
			msg: "zone-sync set to false",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, configOk := ParseConfigMap(context.Background(), test.configMap, false, false, false, false, makeEventLogger())
			if configOk {
				t.Errorf("Expected config not valid, got valid")
			}
		})
	}
}

func TestParseZoneSyncPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *ZoneSync
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":      "true",
					"zone-sync-port": "1234",
				},
			},
			want: &ZoneSync{
				Enable:            true,
				Port:              1234,
				Domain:            "",
				ResolverAddresses: []string{"add default one"},
				ResolverValid:     "5s",
			},
			msg: "zone-sync-port set to 1234",
		},
	}

	nginxPlus := true
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, _ := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if result.ZoneSync.Port != test.want.Port {
				t.Errorf("Port: want %v, got %v", test.want.Port, result.ZoneSync.Port)
			}
		})
	}
}

func TestZoneSyncPortSetToDefaultOnZoneSyncEnabledAndPortNotProvided(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *ZoneSync
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync": "true",
				},
			},
			want: &ZoneSync{
				Enable: true,
				Port:   12345,
			},
			msg: "zone-sync-port set to default value 12345",
		},
	}
	nginxPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if !configOk {
				t.Error("zone-sync: want configOk true, got configOk false ")
			}
			if result.ZoneSync.Port != test.want.Port {
				t.Errorf("Port: want %v, got %v", test.want.Port, result.ZoneSync.Port)
			}
		})
	}
}

func TestParseZoneSyncPortErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":      "true",
					"zone-sync-port": "0",
				},
			},
			msg: "port out of range (0)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":      "true",
					"zone-sync-port": "-1",
				},
			},
			msg: "port out of range (negative)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":      "true",
					"zone-sync-port": "65536",
				},
			},
			msg: "port out of range (greater than 65535)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":      "true",
					"zone-sync-port": "not-a-number",
				},
			},
			msg: "invalid non-numeric port",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":      "true",
					"zone-sync-port": "",
				},
			},
			msg: "empty string port",
		},
	}

	nginxPlus := true
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, ok := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if ok {
				t.Error("Expected config not valid, got valid")
			}
		})
	}
}

func TestParseZoneSyncResolverErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":                    "true",
					"zone-sync-resolver-addresses": "nginx",
				},
			},
			msg: "invalid resolver address",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":                    "true",
					"zone-sync-resolver-addresses": "nginx, example.com",
				},
			},
			msg: "one valid and one invalid resolver addresses",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":                "true",
					"zone-sync-resolver-valid": "10x",
				},
			},
			msg: "invalid resolver valid 10x",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":                "true",
					"zone-sync-resolver-valid": "nginx",
				},
			},
			msg: "invalid resolver valid string",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync": "nginx",
				},
			},
			msg: "zone-sync = nginx",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":               "true",
					"zone-sync-resolver-ipv6": "nginx",
				},
			},
			msg: "invalid resolver ipv6 string",
		},
	}

	nginxPlus := false
	hasAppProtect := true
	hasAppProtectDos := false
	hasTLSPassthrough := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, ok := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if ok {
				t.Error("Expected config not valid, got valid")
			}
		})
	}
}

func TestParseZoneSyncResolverIPV6MapResolverIPV6(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *ZoneSync
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync":                    "true",
					"zone-sync-resolver-ipv6":      "true",
					"zone-sync-resolver-addresses": "example.com",
				},
			},
			want: &ZoneSync{
				Enable:            true,
				Port:              12345,
				ResolverIPV6:      commonhelpers.BoolToPointerBool(true),
				ResolverAddresses: []string{"example.com"},
			},
			msg: "zone-sync-resolver-ipv6 set to true",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"zone-sync-port":               "12345",
					"zone-sync":                    "true",
					"zone-sync-resolver-ipv6":      "false",
					"zone-sync-resolver-addresses": "example.com",
				},
			},
			want: &ZoneSync{
				Enable:            true,
				Port:              12345,
				ResolverIPV6:      commonhelpers.BoolToPointerBool(false),
				ResolverAddresses: []string{"example.com"},
			},
			msg: "zone-sync-resolver-ipv6 set to false",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			nginxPlus := true
			hasAppProtect := false
			hasAppProtectDos := false
			hasTLSPassthrough := false

			result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())

			if !configOk {
				t.Errorf("zone-sync-resolver-ipv6: want configOk true, got configOk %v  ", configOk)
			}

			if result.ZoneSync.ResolverIPV6 == nil {
				t.Errorf("zone-sync-resolver-ipv6: want %v, got nil", *test.want.ResolverIPV6)
			}

			if *result.ZoneSync.ResolverIPV6 != *test.want.ResolverIPV6 {
				t.Errorf("zone-sync-resolver-ipv6: want %v, got %v", *test.want.ResolverIPV6, *result.ZoneSync.ResolverIPV6)
			}
		})
	}
}

func TestOpenTelemetryConfigurationSuccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap                   *v1.ConfigMap
		expectedLoadModule          bool
		expectedExporterEndpoint    string
		expectedExporterHeaderName  string
		expectedExporterHeaderValue string
		expectedServiceName         string
		expectedTraceInHTTP         bool
		msg                         string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "https://otel-collector:4317",
					"otel-service-name":      "nginx-ingress-controller:nginx",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			msg:                         "endpoint set, minimal config",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "subdomain.goes.on.and.on.and.on.and.on.example.com",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "subdomain.goes.on.and.on.and.on.and.on.example.com",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "endpoint set, complicated long subdomain",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "localhost:9933",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "localhost:9933",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "endpoint set, hostname and port no scheme",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint":     "https://otel-collector:4317",
					"otel-exporter-trusted-ca":   "otel-ca-secret",
					"otel-exporter-header-name":  "X-Custom-Header",
					"otel-exporter-header-value": "custom-value",
					"otel-service-name":          "nginx-ingress-controller:nginx",
					"otel-trace-in-http":         "true",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "X-Custom-Header",
			expectedExporterHeaderValue: "custom-value",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			expectedTraceInHTTP:         true,
			msg:                         "endpoint set, full config",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "no config",
		},
	}

	isPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	expectedConfigOk := true

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, isPlus,
				hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if configOk != expectedConfigOk {
				t.Errorf("configOk: want %v, got %v", expectedConfigOk, configOk)
			}
			if result.MainOtelLoadModule != test.expectedLoadModule {
				t.Errorf("MainOtelLoadModule: want %v, got %v", test.expectedLoadModule, result.MainOtelLoadModule)
			}
			if result.MainOtelExporterEndpoint != test.expectedExporterEndpoint {
				t.Errorf("MainOtelExporterEndpoint: want %q, got %q", test.expectedExporterEndpoint, result.MainOtelExporterEndpoint)
			}
			if result.MainOtelExporterHeaderName != test.expectedExporterHeaderName {
				t.Errorf("MainOtelExporterHeaderName: want %q, got %q", test.expectedExporterHeaderName, result.MainOtelExporterHeaderName)
			}
			if result.MainOtelExporterHeaderValue != test.expectedExporterHeaderValue {
				t.Errorf("MainOtelExporterHeaderValue: want %q, got %q", test.expectedExporterHeaderValue, result.MainOtelExporterHeaderValue)
			}
			if result.MainOtelServiceName != test.expectedServiceName {
				t.Errorf("MainOtelServiceName: want %q, got %q", test.expectedServiceName, result.MainOtelServiceName)
			}
			if result.MainOtelTraceInHTTP != test.expectedTraceInHTTP {
				t.Errorf("MainOtelTraceInHTTP: want %v, got %v", test.expectedTraceInHTTP, result.MainOtelTraceInHTTP)
			}
		})
	}
}

func TestOpenTelemetryConfigurationInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap                   *v1.ConfigMap
		expectedLoadModule          bool
		expectedExporterEndpoint    string
		expectedExporterHeaderName  string
		expectedExporterHeaderValue string
		expectedServiceName         string
		expectedTraceInHTTP         bool
		msg                         string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "",
					"otel-service-name":      "nginx-ingress-controller:nginx",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, endpoint missing, service name set",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-header-name":  "X-Custom-Header",
					"otel-exporter-header-value": "custom-value",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, endpoint missing, header name and value set",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint":    "https://otel-collector:4317",
					"otel-exporter-header-name": "X-Custom-Header",
					"otel-service-name":         "nginx-ingress-controller:nginx",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			expectedTraceInHTTP:         false,
			msg:                         "partially invalid, header value missing",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint":     "https://otel-collector:4317",
					"otel-exporter-header-value": "custom-value",
					"otel-service-name":          "nginx-ingress-controller:nginx",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			expectedTraceInHTTP:         false,
			msg:                         "partially invalid, header name missing",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint":     "https://otel-collector:4317",
					"otel-exporter-header-name":  "X-Custom-H$eader",
					"otel-exporter-header-value": "custom-value",
					"otel-service-name":          "nginx-ingress-controller:nginx",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			expectedTraceInHTTP:         false,
			msg:                         "partially invalid, header value invalid",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "https://otel-collector:4317",
					"otel-service-name":      "nginx-ingress-controller:nginx",
					"otel-trace-in-http":     "invalid",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			expectedTraceInHTTP:         false,
			msg:                         "partially invalid, trace flag invalid",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint":     "https://otel-collector:4317",
					"otel-exporter-header-value": "custom-value",
					"otel-service-name":          "nginx-ingress-controller:nginx",
					"otel-trace-in-http":         "true",
				},
			},
			expectedLoadModule:          true,
			expectedExporterEndpoint:    "https://otel-collector:4317",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "nginx-ingress-controller:nginx",
			expectedTraceInHTTP:         true,
			msg:                         "partially invalid, header name missing, trace in http set",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "something%invalid*30here",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, endpoint does not look like a host",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "localhost:0",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, port is outside of range down",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "localhost:99999",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, port is outside of range up",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "fe80::1",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, endpoint is an ipv6 address",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "thisisaverylongsubdomainthatexceedsatotalofsixtythreecharactersz.example.com",
				},
			},
			expectedLoadModule:          false,
			expectedExporterEndpoint:    "",
			expectedExporterHeaderName:  "",
			expectedExporterHeaderValue: "",
			expectedServiceName:         "",
			expectedTraceInHTTP:         false,
			msg:                         "invalid, subdomain is more than 63 characters long",
		},
	}

	isPlus := false
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	expectedConfigOk := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, isPlus,
				hasAppProtect, hasAppProtectDos, hasTLSPassthrough, makeEventLogger())
			if configOk != expectedConfigOk {
				t.Errorf("configOk: want %v, got %v", expectedConfigOk, configOk)
			}
			if result.MainOtelLoadModule != test.expectedLoadModule {
				t.Errorf("MainOtelLoadModule: want %v, got %v", test.expectedLoadModule, result.MainOtelLoadModule)
			}
			if result.MainOtelExporterEndpoint != test.expectedExporterEndpoint {
				t.Errorf("MainOtelExporterEndpoint: want %q, got %q", test.expectedExporterEndpoint, result.MainOtelExporterEndpoint)
			}
			if result.MainOtelExporterHeaderName != test.expectedExporterHeaderName {
				t.Errorf("MainOtelExporterHeaderName: want %q, got %q", test.expectedExporterHeaderName, result.MainOtelExporterHeaderName)
			}
			if result.MainOtelExporterHeaderValue != test.expectedExporterHeaderValue {
				t.Errorf("MainOtelExporterHeaderValue: want %q, got %q", test.expectedExporterHeaderValue, result.MainOtelExporterHeaderValue)
			}
			if result.MainOtelServiceName != test.expectedServiceName {
				t.Errorf("MainOtelServiceName: want %q, got %q", test.expectedServiceName, result.MainOtelServiceName)
			}
			if result.MainOtelTraceInHTTP != test.expectedTraceInHTTP {
				t.Errorf("MainOtelTraceInHTTP: want %v, got %v", test.expectedTraceInHTTP, result.MainOtelTraceInHTTP)
			}
		})
	}
}

func makeEventLogger() record.EventRecorder {
	return record.NewFakeRecorder(1024)
}
