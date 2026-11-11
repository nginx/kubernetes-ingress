package configs

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		cm := &v1.ConfigMap{
			Data: map[string]string{
				"app-protect-compressed-requests-action": test.action,
			},
		}
		result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		cm := &v1.ConfigMap{
			Data: map[string]string{
				"app-protect-reconnect-period-seconds": test.period,
			},
		}
		result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"real-ip-header": test.realIPheader,
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
			realIPheader: "X-Real-IP;return 204",
			want:         "",
			msg:          "invalid real-ip-header carrying NGINX syntax is rejected and ignored",
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"real-ip-header": test.realIPheader,
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"access-log":     test.accessLog,
					"access-log-off": test.accessLogOff,
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			cm := &v1.ConfigMap{
				Data: map[string]string{
					"access-log-off": "False",
				},
			}
			result, _ := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
			if result.MainAccessLog != test.want {
				t.Errorf("want %q, got %q", test.want, result.MainAccessLog)
			}
		})
	}
}

func TestParseConfigMapOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap *v1.ConfigMap
		want      *OIDC
		msg       string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{},
			},
			want: &OIDC{
				PKCETimeout:     "90s",
				PKCEZoneSize:    "128K",
				IDTokenTimeout:  "1h",
				IDTokenZoneSize: "1M",
				AccessTimeout:   "1h",
				AccessZoneSize:  "1M",
				RefreshTimeout:  "8h",
				RefreshZoneSize: "1M",
				SIDSTimeout:     "8h",
				SIDSZoneSize:    "1M",
			},
			msg: "default OIDC values",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-pkce-timeout":             "5m",
					"oidc-pkce-zone-size":           "256K",
					"oidc-id-tokens-timeout":        "2h",
					"oidc-id-tokens-zone-size":      "2M",
					"oidc-access-tokens-timeout":    "3h",
					"oidc-access-tokens-zone-size":  "2M",
					"oidc-refresh-tokens-timeout":   "48h",
					"oidc-refresh-tokens-zone-size": "2M",
					"oidc-sids-timeout":             "72h",
					"oidc-sids-zone-size":           "2M",
				},
			},
			want: &OIDC{
				PKCETimeout:     "5m",
				PKCEZoneSize:    "256k",
				IDTokenTimeout:  "2h",
				IDTokenZoneSize: "2m",
				AccessTimeout:   "3h",
				AccessZoneSize:  "2m",
				RefreshTimeout:  "48h",
				RefreshZoneSize: "2m",
				SIDSTimeout:     "72h",
				SIDSZoneSize:    "2m",
			},
			msg: "all timeout values custom",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-pkce-timeout": "15m",
				},
			},
			want: &OIDC{
				PKCETimeout: "15m",
			},
			msg: "custom PKCE timeout only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-id-tokens-timeout": "90m",
				},
			},
			want: &OIDC{
				IDTokenTimeout: "90m",
			},
			msg: "custom ID token timeout only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-access-tokens-timeout": "4h",
				},
			},
			want: &OIDC{
				AccessTimeout: "4h",
			},
			msg: "custom access token timeout only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-refresh-tokens-timeout": "16h",
				},
			},
			want: &OIDC{
				RefreshTimeout: "16h",
			},
			msg: "custom refresh token timeout only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-sids-timeout": "12h",
				},
			},
			want: &OIDC{
				SIDSTimeout: "12h",
			},
			msg: "custom SIDS timeout only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-pkce-zone-size": "1m",
				},
			},
			want: &OIDC{
				PKCEZoneSize: "1m",
			},
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-id-tokens-zone-size": "2m",
				},
			},
			want: &OIDC{
				IDTokenZoneSize: "2m",
			},
			msg: "custom ID token zone size only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-access-tokens-zone-size": "3m",
				},
			},
			want: &OIDC{
				AccessZoneSize: "3m",
			},
			msg: "custom access token zone size only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-refresh-tokens-zone-size": "4m",
				},
			},
			want: &OIDC{
				RefreshZoneSize: "4m",
			},
			msg: "custom refresh token zone size only",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-sids-zone-size": "5m",
				},
			},
			want: &OIDC{
				SIDSZoneSize: "5m",
			},
			msg: "custom SIDS zone size only",
		},
	}

	nginxPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
			if !configOk {
				t.Error("want configOk true, got configOk false")
			}

			// Check only the specific fields that are set in the test expectation
			if test.want.PKCETimeout != "" {
				assert.Equal(t, test.want.PKCETimeout, result.OIDC.PKCETimeout)
			}
			if test.want.IDTokenTimeout != "" {
				assert.Equal(t, test.want.IDTokenTimeout, result.OIDC.IDTokenTimeout)
			}
			if test.want.AccessTimeout != "" {
				assert.Equal(t, test.want.AccessTimeout, result.OIDC.AccessTimeout)
			}
			if test.want.RefreshTimeout != "" {
				assert.Equal(t, test.want.RefreshTimeout, result.OIDC.RefreshTimeout)
			}
			if test.want.SIDSTimeout != "" {
				assert.Equal(t, test.want.SIDSTimeout, result.OIDC.SIDSTimeout)
			}
		})
	}
}

func TestParseConfigMapOIDCErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap   *v1.ConfigMap
		expectedErr bool
		msg         string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-pkce-timeout": "invalid-time",
				},
			},
			expectedErr: true,
			msg:         "invalid PKCE timeout format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-id-tokens-timeout": "abc123",
				},
			},
			expectedErr: true,
			msg:         "invalid ID token timeout format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-access-tokens-timeout": "5x",
				},
			},
			expectedErr: true,
			msg:         "invalid access token timeout format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-refresh-tokens-timeout": "",
				},
			},
			expectedErr: true,
			msg:         "empty refresh token timeout",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-sids-timeout": "   ",
				},
			},
			expectedErr: true,
			msg:         "whitespace-only SIDS timeout",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-pkce-timeout": "-5m",
				},
			},
			expectedErr: true,
			msg:         "negative PKCE timeout",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-id-tokens-timeout": "1.5h",
				},
			},
			expectedErr: true,
			msg:         "decimal in ID token timeout",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-access-tokens-timeout": "5minutes",
				},
			},
			expectedErr: true,
			msg:         "invalid time unit format",
		},

		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-sids-timeout": "5s 10m",
				},
			},
			expectedErr: true,
			msg:         "multiple time values without proper format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-pkce-zone-size": "invalid-size",
				},
			},
			expectedErr: true,
			msg:         "invalid PKCE zone size format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-id-tokens-zone-size": "123abc",
				},
			},
			expectedErr: true,
			msg:         "invalid ID token zone size format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-access-tokens-zone-size": "1.5M",
				},
			},
			expectedErr: true,
			msg:         "invalid access token zone size format",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-refresh-tokens-zone-size": "",
				},
			},
			expectedErr: true,
			msg:         "empty refresh token zone size",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"oidc-sids-zone-size": "   ",
				},
			},
			expectedErr: true,
			msg:         "whitespace-only SIDS zone size",
		},
	}

	nginxPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())

			if test.expectedErr && configOk {
				t.Errorf("want configOk false, got configOk true for %s", test.msg)
			}
			if !test.expectedErr && !configOk {
				t.Errorf("want configOk true, got configOk false for %s", test.msg)
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
				EnforceInitialReport: new(false),
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
				EnforceInitialReport: new(true),
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
				SSLVerify: new(false),
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
				SSLVerify: new(true),
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

func TestParseMGMTConfigMapUsageReportIntervalMaximum(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap      *v1.ConfigMap
		expectWarnings bool
		expectInterval string
		msg            string
	}{
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "24h",
				},
			},
			expectWarnings: false,
			expectInterval: "24h",
			msg:            "24h should be accepted (maximum allowed)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "25h",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "25h should be rejected (exceeds maximum)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1440m",
				},
			},
			expectWarnings: false,
			expectInterval: "1440m",
			msg:            "1440m (24h) should be accepted",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1441m",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "1441m (>24h) should be rejected",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}

			if warnings != test.expectWarnings {
				t.Errorf("Expected warnings=%v, got warnings=%v", test.expectWarnings, warnings)
			}

			if result.Interval != test.expectInterval {
				t.Errorf("Expected interval=%q, got interval=%q", test.expectInterval, result.Interval)
			}
		})
	}
}

func TestParseMGMTConfigMapUsageReportIntervalEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configMap      *v1.ConfigMap
		expectWarnings bool
		expectInterval string
		msg            string
	}{
		// Test milliseconds (should be rejected due to unsupported unit)
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1000ms",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "1000ms should be rejected (ms unit not allowed)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "60000ms",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "60000ms should be rejected (ms unit not allowed)",
		},
		// Test that large ms values are also rejected for unit, not value
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "3600000ms",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "3600000ms (1h) should be rejected (ms unit not allowed)",
		},
		// Test days (should be rejected by Go's ParseDuration)
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "1d",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "1d should be rejected (Go doesn't support 'd' unit)",
		},
		// Test values > 24h (valid in Go but should be rejected by max check)
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "25h",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "25h should be rejected (exceeds 24h maximum)",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "48h",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "48h should be rejected (exceeds 24h maximum)",
		},
		// exactly 86400 seconds (24h)
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "86400s",
				},
			},
			expectWarnings: false,
			expectInterval: "86400s",
			msg:            "86400s (24h) should be accepted",
		},
		// 86401 seconds (24h + 1s)
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"license-token-secret-name": "license-token",
					"usage-report-interval":     "86401s",
				},
			},
			expectWarnings: true,
			expectInterval: "",
			msg:            "86401s (>24h) should be rejected",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, warnings, err := ParseMGMTConfigMap(context.Background(), test.configMap, makeEventLogger())
			if err != nil {
				t.Fatal(err)
			}

			if warnings != test.expectWarnings {
				t.Errorf("Expected warnings=%v, got warnings=%v", test.expectWarnings, warnings)
			}

			if result.Interval != test.expectInterval {
				t.Errorf("Expected interval=%q, got interval=%q", test.expectInterval, result.Interval)
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
				ResolverIPV6: new(false),
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
				ResolverIPV6: new(true),
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

func TestParseMGMTConfigMapRejectsProxyCredentialInjection(t *testing.T) {
	t.Setenv("PROXY_USER", "user\nssl_verify off")
	t.Setenv("PROXY_PASS", "pass\nssl_verify off")

	cfg, warnings, err := ParseMGMTConfigMap(context.Background(), &v1.ConfigMap{Data: map[string]string{
		"license-token-secret-name": "license-token",
		"usage-report-proxy-host":   "proxy.example.com:3128",
	}}, makeEventLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !warnings {
		t.Fatal("expected invalid proxy credentials to produce warnings")
	}
	if cfg.ProxyUser != "" || cfg.ProxyPass != "" {
		t.Fatalf("invalid proxy credentials were retained: user=%q pass=%q", cfg.ProxyUser, cfg.ProxyPass)
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
			result, _ := ParseConfigMap(context.Background(), test.configMap, true, false, false, false, true, true, makeEventLogger())
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
			_, configOk := ParseConfigMap(context.Background(), test.configMap, false, false, false, false, true, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, _ := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, ok := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
	directiveAutoadjustEnabled := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			_, ok := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
				ResolverIPV6:      new(true),
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
				ResolverIPV6:      new(false),
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
			directiveAutoadjustEnabled := false

			result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())

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
		expectedTraceContext        string
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

		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "https://otel-collector:4317",
					"otel-trace-context":     "extract",
				},
			},
			expectedLoadModule:       true,
			expectedExporterEndpoint: "https://otel-collector:4317",
			expectedTraceContext:     "extract",
			msg:                      "endpoint set with trace context extract",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-trace-context":     "inject",
					"otel-exporter-endpoint": "https://otel-collector:4317",
				},
			},
			expectedLoadModule:       true,
			expectedExporterEndpoint: "https://otel-collector:4317",
			expectedTraceContext:     "inject",
			msg:                      "trace context inject",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-trace-context":     "ignore",
					"otel-exporter-endpoint": "https://otel-collector:4317",
				},
			},
			expectedLoadModule:       true,
			expectedExporterEndpoint: "https://otel-collector:4317",
			expectedTraceContext:     "ignore",
			msg:                      "trace context ignore",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-trace-context":     "propagate",
					"otel-exporter-endpoint": "https://otel-collector:4317",
				},
			},
			expectedLoadModule:       true,
			expectedExporterEndpoint: "https://otel-collector:4317",
			expectedTraceContext:     "propagate",
			msg:                      "trace context propagate",
		},
	}

	isPlus := true
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false
	expectedConfigOk := true

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, isPlus,
				hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
			if result.MainOtelTraceContext != test.expectedTraceContext {
				t.Errorf("MainOtelTraceContext: want %q, got %q", test.expectedTraceContext, result.MainOtelTraceContext)
			}
		})
	}
}

func TestGenerateNginxMainConfigWithOtelTraceContext(t *testing.T) {
	t.Parallel()

	mainCfg := GenerateNginxMainConfig(
		&StaticConfigParams{},
		&ConfigParams{MainOtelTraceContext: "propagate"},
		nil,
	)

	if mainCfg.MainOtelTraceContext != "propagate" {
		t.Errorf("MainOtelTraceContext: want %q, got %q", "propagate", mainCfg.MainOtelTraceContext)
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
		expectedTraceContext        string
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
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-trace-context": "propagate",
				},
			},
			expectedLoadModule:       false,
			expectedExporterEndpoint: "",
			expectedTraceContext:     "",
			msg:                      "trace context set without an exporter endpoint",
		},
		{
			configMap: &v1.ConfigMap{
				Data: map[string]string{
					"otel-exporter-endpoint": "https://otel-collector:4317",
					"otel-trace-context":     "not-a-real-value",
				},
			},
			expectedExporterEndpoint: "https://otel-collector:4317",
			expectedLoadModule:       true,
			expectedTraceContext:     "",
			msg:                      "partially invalid, trace context value not recognized",
		},
	}

	isPlus := false
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false
	expectedConfigOk := false

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result, configOk := ParseConfigMap(context.Background(), test.configMap, isPlus,
				hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())
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
			if result.MainOtelTraceContext != test.expectedTraceContext {
				t.Errorf("MainOtelTraceContext: want %q, got %q", test.expectedTraceContext, result.MainOtelTraceContext)
			}
		})
	}
}

func TestParseProxyBuffers(t *testing.T) {
	t.Parallel()

	// Test with auto-adjust enabled - should use validation functions
	t.Run("with auto-adjust enabled", func(t *testing.T) {
		tests := []struct {
			name                         string
			configMap                    *v1.ConfigMap
			expectedProxyBuffers         string
			expectedProxyBufferSize      string
			expectedProxyBusyBuffersSize string
			description                  string
		}{
			{
				name: "all proxy buffer settings provided",
				configMap: &v1.ConfigMap{
					Data: map[string]string{
						"proxy-buffers":           "8 4k",
						"proxy-buffer-size":       "8k",
						"proxy-busy-buffers-size": "16k",
					},
				},
				expectedProxyBuffers:         "8 4k",
				expectedProxyBufferSize:      "8k",
				expectedProxyBusyBuffersSize: "16k",
				description:                  "should parse all proxy buffer settings correctly",
			},
			{
				name: "case insensitive units get normalized",
				configMap: &v1.ConfigMap{
					Data: map[string]string{
						"proxy-buffers":           "8 4K",
						"proxy-buffer-size":       "8K",
						"proxy-busy-buffers-size": "16K",
					},
				},
				expectedProxyBuffers:         "8 4k",
				expectedProxyBufferSize:      "8k",
				expectedProxyBusyBuffersSize: "16k",
				description:                  "should normalize case insensitive units",
			},
		}

		nginxPlus := true
		hasAppProtect := false
		hasAppProtectDos := false
		hasTLSPassthrough := false
		directiveAutoadjustEnabled := true

		for _, test := range tests {
			test := test // capture range variable

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				eventRecorder := makeEventLogger()
				result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, eventRecorder)

				if !configOk {
					t.Errorf("%s: expected config to be valid but got invalid", test.description)
				}

				if result.ProxyBuffers != test.expectedProxyBuffers {
					t.Errorf("%s: ProxyBuffers = %q, want %q", test.description, result.ProxyBuffers, test.expectedProxyBuffers)
				}

				if result.ProxyBufferSize != test.expectedProxyBufferSize {
					t.Errorf("%s: ProxyBufferSize = %q, want %q", test.description, result.ProxyBufferSize, test.expectedProxyBufferSize)
				}

				if result.ProxyBusyBuffersSize != test.expectedProxyBusyBuffersSize {
					t.Errorf("%s: ProxyBusyBuffersSize = %q, want %q", test.description, result.ProxyBusyBuffersSize, test.expectedProxyBusyBuffersSize)
				}

				fakeRecorder := eventRecorder.(*record.FakeRecorder)
				if len(fakeRecorder.Events) > 0 {
					t.Errorf("%s: unexpected warnings generated: %d events", test.description, len(fakeRecorder.Events))
				}
			})
		}
	})

	// Test with auto-adjust disabled - should preserve original strings
	t.Run("with auto-adjust disabled", func(t *testing.T) {
		tests := []struct {
			name                         string
			configMap                    *v1.ConfigMap
			expectedProxyBuffers         string
			expectedProxyBufferSize      string
			expectedProxyBusyBuffersSize string
			description                  string
		}{
			{
				name: "preserves original values exactly",
				configMap: &v1.ConfigMap{
					Data: map[string]string{
						"proxy-buffers":           "8 4K",
						"proxy-buffer-size":       "8K",
						"proxy-busy-buffers-size": "16K",
					},
				},
				expectedProxyBuffers:         "8 4K", // Original case preserved
				expectedProxyBufferSize:      "8K",   // Original case preserved
				expectedProxyBusyBuffersSize: "16K",  // Original case preserved
				description:                  "should preserve original case and format",
			},
			{
				name: "preserves unusual but valid formats",
				configMap: &v1.ConfigMap{
					Data: map[string]string{
						"proxy-buffers":           "16 8k",
						"proxy-buffer-size":       "16k",
						"proxy-busy-buffers-size": "32k",
					},
				},
				expectedProxyBuffers:         "16 8k",
				expectedProxyBufferSize:      "16k",
				expectedProxyBusyBuffersSize: "32k",
				description:                  "should preserve user's exact input",
			},
		}

		nginxPlus := true
		hasAppProtect := false
		hasAppProtectDos := false
		hasTLSPassthrough := false
		directiveAutoadjustEnabled := false

		for _, test := range tests {
			test := test // capture range variable

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				eventRecorder := makeEventLogger()
				result, configOk := ParseConfigMap(context.Background(), test.configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, eventRecorder)

				if !configOk {
					t.Errorf("%s: expected config to be valid but got invalid", test.description)
				}

				if result.ProxyBuffers != test.expectedProxyBuffers {
					t.Errorf("%s: ProxyBuffers = %q, want %q", test.description, result.ProxyBuffers, test.expectedProxyBuffers)
				}

				if result.ProxyBufferSize != test.expectedProxyBufferSize {
					t.Errorf("%s: ProxyBufferSize = %q, want %q", test.description, result.ProxyBufferSize, test.expectedProxyBufferSize)
				}

				if result.ProxyBusyBuffersSize != test.expectedProxyBusyBuffersSize {
					t.Errorf("%s: ProxyBusyBuffersSize = %q, want %q", test.description, result.ProxyBusyBuffersSize, test.expectedProxyBusyBuffersSize)
				}

				fakeRecorder := eventRecorder.(*record.FakeRecorder)
				if len(fakeRecorder.Events) > 0 {
					t.Errorf("%s: unexpected warnings generated: %d events", test.description, len(fakeRecorder.Events))
				}
			})
		}
	})
}

func TestParseProxyBuffersInvalidFormat(t *testing.T) {
	t.Parallel()

	// Test with auto-adjust enabled - should validate and potentially reject invalid formats
	t.Run("with auto-adjust enabled", func(t *testing.T) {
		tests := []struct {
			name         string
			proxyBuffers string
			expectValid  bool
			description  string
		}{
			{
				name:         "valid format",
				proxyBuffers: "4 8k",
				expectValid:  true,
				description:  "should accept valid 'count size' format",
			},
			{
				name:         "invalid - only size",
				proxyBuffers: "1k",
				expectValid:  false,
				description:  "should reject format with only size",
			},
			{
				name:         "invalid - only count",
				proxyBuffers: "4",
				expectValid:  false,
				description:  "should reject format with only count",
			},
			{
				name:         "invalid - three parts",
				proxyBuffers: "4 8k extra",
				expectValid:  false,
				description:  "should reject format with too many parts",
			},
			{
				name:         "empty string",
				proxyBuffers: "",
				expectValid:  false,
				description:  "should not accept empty string",
			},
		}

		nginxPlus := true
		hasAppProtect := false
		hasAppProtectDos := false
		hasTLSPassthrough := false
		directiveAutoadjustEnabled := true

		for _, test := range tests {
			test := test // capture range variable

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-configmap",
						Namespace: "default",
					},
					Data: map[string]string{
						"proxy-buffers": test.proxyBuffers,
					},
				}

				eventRecorder := makeEventLogger()
				result, configOk := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, eventRecorder)

				if configOk != test.expectValid {
					t.Errorf("%s: expected configOk=%v, got configOk=%v", test.description, test.expectValid, configOk)
				}

				if test.expectValid {
					// For valid configs, proxy buffers should be set or empty
					if test.proxyBuffers != "" && result.ProxyBuffers == "" {
						t.Errorf("%s: expected ProxyBuffers to be set, got empty", test.description)
					}
				} else {
					// For invalid configs, should have error events
					fakeRecorder := eventRecorder.(*record.FakeRecorder)
					if len(fakeRecorder.Events) == 0 {
						t.Errorf("%s: expected error event to be generated for invalid config", test.description)
					}
				}
			})
		}
	})

	// Test with auto-adjust disabled - should preserve original strings without validation
	t.Run("with auto-adjust disabled", func(t *testing.T) {
		tests := []struct {
			name         string
			proxyBuffers string
			description  string
		}{
			{
				name:         "valid format preserved",
				proxyBuffers: "4 8k",
				description:  "should preserve valid format exactly",
			},
		}

		nginxPlus := true
		hasAppProtect := false
		hasAppProtectDos := false
		hasTLSPassthrough := false
		directiveAutoadjustEnabled := false

		for _, test := range tests {
			test := test // capture range variable

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-configmap",
						Namespace: "default",
					},
					Data: map[string]string{
						"proxy-buffers": test.proxyBuffers,
					},
				}

				eventRecorder := makeEventLogger()
				result, configOk := ParseConfigMap(context.Background(), cm, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, eventRecorder)

				// When auto-adjust is disabled, config should always be valid since no validation occurs
				if !configOk {
					t.Errorf("%s: expected config to be valid with auto-adjust disabled, got invalid", test.description)
				}

				// Should preserve exact original value
				if result.ProxyBuffers != test.proxyBuffers {
					t.Errorf("%s: expected ProxyBuffers=%q, got %q", test.description, test.proxyBuffers, result.ProxyBuffers)
				}

				// Should not generate any events when auto-adjust is disabled
				fakeRecorder := eventRecorder.(*record.FakeRecorder)
				if len(fakeRecorder.Events) > 0 {
					t.Errorf("%s: unexpected events generated with auto-adjust disabled: %d events", test.description, len(fakeRecorder.Events))
				}
			})
		}
	})
}

func TestParseConfigMapClientBodyBufferSizeValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       string
		expected    string
		description string
	}{
		{
			name:        "valid size with k suffix",
			value:       "12k",
			expected:    "12k",
			description: "should accept valid size with k suffix",
		},
		{
			name:        "valid size with K suffix",
			value:       "16K",
			expected:    "16K",
			description: "should accept valid size with K suffix",
		},
		{
			name:        "valid size with m suffix",
			value:       "6m",
			expected:    "6m",
			description: "should accept valid size with m suffix",
		},
		{
			name:        "valid size with M suffix",
			value:       "8M",
			expected:    "8M",
			description: "should accept valid size with M suffix",
		},
		{
			name:        "valid size without suffix",
			value:       "1024",
			expected:    "1024",
			description: "should accept valid size without suffix",
		},
		{
			name:        "not set",
			value:       "",
			expected:    "", // no default value anymore
			description: "should use empty string when not set",
		},
	}

	nginxPlus := false
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "default",
				},
			}

			if tt.value != "" {
				cm.Data = map[string]string{
					"client-body-buffer-size": tt.value,
				}
			}

			result, configOk := ParseConfigMap(
				context.Background(),
				cm,
				nginxPlus,
				hasAppProtect,
				hasAppProtectDos,
				hasTLSPassthrough,
				directiveAutoadjustEnabled,
				true,
				makeEventLogger(),
			)

			// Should always pass validation for valid cases
			if !configOk {
				t.Errorf("ParseConfigMap() for %s should have passed validation but failed", tt.description)
			}

			if result.MainClientBodyBufferSize != tt.expected {
				t.Errorf("ParseConfigMap() for %s returned MainClientBodyBufferSize=%q, expected %q",
					tt.description, result.MainClientBodyBufferSize, tt.expected)
			}
		})
	}
}

func TestParseConfigMapClientBodyBufferSizeInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       string
		description string
	}{
		{
			name:        "invalid time unit h",
			value:       "4h",
			description: "should reject invalid time units",
		},
		{
			name:        "invalid random string",
			value:       "3cd2",
			description: "should reject invalid strings",
		},
		{
			name:        "invalid with g suffix",
			value:       "2g",
			description: "should reject unsupported g suffix",
		},
		{
			name:        "invalid with G suffix",
			value:       "1G",
			description: "should reject unsupported G suffix",
		},
		{
			name:        "invalid negative value",
			value:       "-16k",
			description: "should reject negative values",
		},
		{
			name:        "invalid whitespace only",
			value:       " ",
			description: "should reject whitespace-only values",
		},
		{
			name:        "invalid with text prefix",
			value:       "abc16k",
			description: "should reject values with text prefix",
		},
		{
			name:        "invalid with special characters",
			value:       "16@k",
			description: "should reject values with special characters",
		},
		{
			name:        "invalid decimal with unsupported suffix",
			value:       "16.5g",
			description: "should reject decimal values with unsupported suffix",
		},
	}

	nginxPlus := false
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "default",
				},
				Data: map[string]string{
					"client-body-buffer-size": tt.value,
				},
			}

			result, configOk := ParseConfigMap(
				context.Background(),
				cm,
				nginxPlus,
				hasAppProtect,
				hasAppProtectDos,
				hasTLSPassthrough,
				directiveAutoadjustEnabled,
				true,
				makeEventLogger(),
			)

			// Should always fail validation for invalid cases
			if configOk {
				t.Errorf("%s should have failed validation but passed", tt.name)
			}

			if result.MainClientBodyBufferSize != "" {
				t.Errorf(`%s returned MainClientBodyBufferSize=%q, expected ""`,
					tt.name, result.MainClientBodyBufferSize)
			}
		})
	}
}

func TestParseErrorLogLevelToVirtualServer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		level        string
		want         string
		wantConfigOk bool
	}{
		{level: "debug", want: "debug", wantConfigOk: true},
		{level: "error", want: "error", wantConfigOk: true},
		{level: "warn", want: "warn", wantConfigOk: true},
		{level: "warning", want: "notice", wantConfigOk: false},
		{level: "nonsense", want: "notice", wantConfigOk: false},
	}

	for _, test := range testCases {
		t.Run(fmt.Sprintf("setting log level to %s", test.level), func(t *testing.T) {
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "default",
				},
				Data: map[string]string{
					"error-log-level": test.level,
				},
			}

			eventRecorder := makeEventLogger()

			result, configOk := ParseConfigMap(context.Background(), cm, true, false, false, false, false, true, eventRecorder)

			if configOk != test.wantConfigOk {
				t.Errorf("configOk: want %v, got %v", test.wantConfigOk, configOk)
			}

			assert.Equal(t, test.want, result.MainErrorLogLevel)
		})
	}
}

func TestParseHTTPRedirectCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code    string
		expect  int
		isValid bool
		msg     string
	}{
		{
			code:    "301",
			expect:  301,
			isValid: true,
			msg:     "valid code 301",
		},
		{
			code:    "302",
			expect:  302,
			isValid: true,
			msg:     "valid code 302",
		},
		{
			code:    "307",
			expect:  307,
			isValid: true,
			msg:     "valid code 307",
		},
		{
			code:    "308",
			expect:  308,
			isValid: true,
			msg:     "valid code 308",
		},
		{
			code:    "200",
			expect:  0,
			isValid: false,
			msg:     "invalid code 200",
		},
		{
			code:    "404",
			expect:  0,
			isValid: false,
			msg:     "invalid code 404",
		},
		{
			code:    "invalid",
			expect:  0,
			isValid: false,
			msg:     "non-numeric code",
		},
		{
			code:    "",
			expect:  0,
			isValid: false,
			msg:     "empty code",
		},
	}

	for _, test := range tests {
		result, err := ParseHTTPRedirectCode(test.code)
		if test.isValid {
			assert.NoError(t, err, test.msg)
			assert.Equal(t, test.expect, result, test.msg)
		} else {
			assert.Error(t, err, test.msg)
		}
	}
}

func TestParseConfigMapWithHTTPRedirectCode(t *testing.T) {
	t.Parallel()
	nginxPlus := false
	hasAppProtect := false
	hasAppProtectDos := false
	hasTLSPassthrough := false
	directiveAutoadjustEnabled := false

	tests := []struct {
		configMap   map[string]string
		expected    int
		expectError bool
		msg         string
	}{
		{
			configMap: map[string]string{
				"http-redirect-code": "301",
			},
			expected:    301,
			expectError: false,
			msg:         "valid redirect code 301",
		},
		{
			configMap: map[string]string{
				"http-redirect-code": "302",
			},
			expected:    302,
			expectError: false,
			msg:         "valid redirect code 302",
		},
		{
			configMap: map[string]string{
				"http-redirect-code": "307",
			},
			expected:    307,
			expectError: false,
			msg:         "valid redirect code 307",
		},
		{
			configMap: map[string]string{
				"http-redirect-code": "308",
			},
			expected:    308,
			expectError: false,
			msg:         "valid redirect code 308",
		},
		{
			configMap: map[string]string{
				"http-redirect-code": "200",
			},
			expected:    301, // should fallback to default
			expectError: true,
			msg:         "invalid redirect code 200",
		},
		{
			configMap: map[string]string{
				"http-redirect-code": "invalid",
			},
			expected:    301, // should fallback to default
			expectError: true,
			msg:         "non-numeric redirect code",
		},
		{
			configMap:   map[string]string{},
			expected:    301, // default value
			expectError: false,
			msg:         "no redirect code specified",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			configMap := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-config",
					Namespace: "nginx-ingress",
				},
				Data: test.configMap,
			}

			result, configOK := ParseConfigMap(context.Background(), configMap, nginxPlus, hasAppProtect, hasAppProtectDos, hasTLSPassthrough, directiveAutoadjustEnabled, true, makeEventLogger())

			if test.expectError {
				assert.False(t, configOK, test.msg)
			} else {
				assert.True(t, configOK, test.msg)
			}

			assert.Equal(t, test.expected, result.HTTPRedirectCode, test.msg)
		})
	}
}

// TestParseAndValidateAddHeaders unit-tests the helper directly, covering all
// validation branches without going through ParseConfigMap.
func TestParseAndValidateAddHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantErr bool
	}{
		// Valid inputs
		{name: "single header", raw: "X-Frame-Options:DENY", wantLen: 1},
		{name: "header with always", raw: "X-Frame-Options:DENY:always", wantLen: 1},
		{name: "multiple headers", raw: "X-Frame-Options:DENY, X-Content-Type-Options:nosniff", wantLen: 2},
		{name: "empty string", raw: "", wantLen: 0},
		// Invalid header names
		{name: "name with space", raw: "X Bad:value", wantErr: true},
		{name: "name with @", raw: "X-He@der:value", wantErr: true},
		// Invalid header values
		{name: "value with $", raw: "X-Header:$nginx_var", wantErr: true},
		{name: "value with newline", raw: "X-Header:foo\nbar", wantErr: true},
		{name: "value with carriage return", raw: "X-Header:foo\rbar", wantErr: true},
		// All-or-nothing: first entry valid, second invalid → error
		{name: "mixed valid and invalid", raw: "X-Good:ok, X-Bad:$inject", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseAndValidateAddHeaders(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Errorf("want error, got nil (headers: %v)", got)
				}
				if len(got) != 0 {
					t.Errorf("want no headers on error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("want %d headers, got %d: %v", tc.wantLen, len(got), got)
			}
		})
	}
}

// TestParseConfigMapAddHeader verifies that the ConfigMap "add-header" key populates
// ConfigParams.MainAddHeaders in the http {} context and does not populate
// AddHeaders, which is reserved for the nginx.org/add-header annotation in server {} context.
func TestParseConfigMapAddHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		data            map[string]string
		wantMainHeaders []string // expected header names in MainAddHeaders
		wantNoHeaders   bool     // true when key is absent or all entries invalid
		wantConfigOk    bool
	}{
		{
			name:            "single header without always",
			data:            map[string]string{"add-header": "X-Frame-Options:DENY"},
			wantMainHeaders: []string{"X-Frame-Options"},
			wantConfigOk:    true,
		},
		{
			name:            "multiple headers",
			data:            map[string]string{"add-header": "X-Frame-Options:DENY, X-Content-Type-Options:nosniff"},
			wantMainHeaders: []string{"X-Frame-Options", "X-Content-Type-Options"},
			wantConfigOk:    true,
		},
		{
			name:          "key absent — MainAddHeaders stays nil",
			data:          map[string]string{},
			wantNoHeaders: true,
			wantConfigOk:  true,
		},
		{
			name:          "invalid header — configOk false, no headers set",
			data:          map[string]string{"add-header": "X-Bad:$inject"},
			wantNoHeaders: true,
			wantConfigOk:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cm := &v1.ConfigMap{Data: tc.data}
			result, configOk := ParseConfigMap(context.Background(), cm,
				false, false, false, false, false, true, makeEventLogger())

			if configOk != tc.wantConfigOk {
				t.Errorf("configOk: want %v, got %v", tc.wantConfigOk, configOk)
			}

			// ConfigMap "add-header" must populate MainAddHeaders (http {} context).
			if tc.wantNoHeaders {
				if len(result.MainAddHeaders) != 0 {
					t.Errorf("want MainAddHeaders empty, got %v", result.MainAddHeaders)
				}
				return
			}

			if len(result.MainAddHeaders) != len(tc.wantMainHeaders) {
				t.Fatalf("want %d MainAddHeaders, got %d: %v",
					len(tc.wantMainHeaders), len(result.MainAddHeaders), result.MainAddHeaders)
			}
			for i, want := range tc.wantMainHeaders {
				if got := result.MainAddHeaders[i].Name; got != want {
					t.Errorf("MainAddHeaders[%d].Name: want %q, got %q", i, want, got)
				}
			}

			// ConfigMap must never populate AddHeaders (annotation path → server {} context).
			if len(result.AddHeaders) != 0 {
				t.Errorf("ConfigMap must not populate AddHeaders (server context); got %v", result.AddHeaders)
			}
		})
	}
}

func makeEventLogger() record.EventRecorder {
	return record.NewFakeRecorder(1024)
}

func TestParseConfigMapWithAddHeaderInherit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value       string
		expect      string
		expectError bool
		msg         string
	}{
		{
			value:       "on",
			expect:      "on",
			expectError: false,
			msg:         "valid value on",
		},
		{
			value:       "off",
			expect:      "off",
			expectError: false,
			msg:         "valid value off",
		},
		{
			value:       "merge",
			expect:      "merge",
			expectError: false,
			msg:         "valid value merge",
		},
		{
			value:       "ON",
			expect:      "on",
			expectError: false,
			msg:         "invalid value ON (mixed case)",
		},
		{
			value:       "Merge",
			expect:      "merge",
			expectError: false,
			msg:         "invalid value Merge (mixed case)",
		},
		{
			value:       "MERGE",
			expect:      "merge",
			expectError: false,
			msg:         "invalid value MERGE (mixed case)",
		},
		{
			value:       "OFF",
			expect:      "off",
			expectError: false,
			msg:         "invalid value OFF (mixed case)",
		},
		{
			value:       "oFf",
			expect:      "off",
			expectError: false,
			msg:         "invalid value oFf (mixed case)",
		},
		{
			value:       "invalid",
			expect:      "",
			expectError: true,
			msg:         "invalid value",
		},
		{
			value:       "yes",
			expect:      "",
			expectError: true,
			msg:         "invalid value yes",
		},
		{
			value:       "",
			expect:      "",
			expectError: true,
			msg:         "empty value",
		},
	}
	for _, test := range tests {
		cm := &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-config",
				Namespace: "nginx-ingress",
			},
			Data: map[string]string{},
		}
		cm.Data["add-header-inherit"] = test.value
		result, configOK := ParseConfigMap(context.Background(), cm, false, false, false, false, false, true, makeEventLogger())
		if result.AddHeaderInherit != test.expect {
			t.Errorf("ParseConfigMap() returned AddHeaderInherit=%q but expected %q for the case: %s", result.AddHeaderInherit, test.expect, test.msg)
		}
		if test.expectError && configOK {
			t.Errorf("ParseConfigMap() returned configOK=true but expected false for the case: %s", test.msg)
		}
		if !test.expectError && !configOK {
			t.Errorf("ParseConfigMap() returned configOK=false but expected true for the case: %s", test.msg)
		}
	}
}

func TestParseConfigMapDisableForwardedHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		msg            string
		data           map[string]string
		enableSnippets bool
		wantDisabled   bool
		wantConfigOk   bool
	}{
		{
			msg:            "disable-forwarded-headers true with snippets enabled",
			data:           map[string]string{"disable-forwarded-headers": "true"},
			enableSnippets: true,
			wantDisabled:   true,
			wantConfigOk:   true,
		},
		{
			msg:            "disable-forwarded-headers false with snippets enabled",
			data:           map[string]string{"disable-forwarded-headers": "false"},
			enableSnippets: true,
			wantDisabled:   false,
			wantConfigOk:   true,
		},
		{
			msg:            "disable-forwarded-headers true with snippets disabled",
			data:           map[string]string{"disable-forwarded-headers": "true"},
			enableSnippets: false,
			wantDisabled:   false,
			wantConfigOk:   false,
		},
		{
			msg:            "disable-forwarded-headers invalid bool with snippets enabled",
			data:           map[string]string{"disable-forwarded-headers": "notabool"},
			enableSnippets: true,
			wantDisabled:   false,
			wantConfigOk:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			t.Parallel()
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "default",
				},
				Data: tc.data,
			}
			recorder := makeEventLogger()
			cfgParams, configOk := ParseConfigMap(context.Background(), cm, false, false, false, false, false, tc.enableSnippets, recorder)
			if configOk != tc.wantConfigOk {
				t.Errorf("configOk: want %v, got %v", tc.wantConfigOk, configOk)
			}
			if cfgParams.DisableForwardedHeaders != tc.wantDisabled {
				t.Errorf("DisableForwardedHeaders: want %v, got %v", tc.wantDisabled, cfgParams.DisableForwardedHeaders)
			}
		})
	}
}

func TestParseConfigMapUseForwardedHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		msg            string
		data           map[string]string
		enableSnippets bool
		wantUsed       bool
		wantConfigOk   bool
	}{
		{
			msg:          "use-forwarded-headers true",
			data:         map[string]string{"use-forwarded-headers": "true"},
			wantUsed:     true,
			wantConfigOk: true,
		},
		{
			msg:          "use-forwarded-headers false",
			data:         map[string]string{"use-forwarded-headers": "false"},
			wantUsed:     false,
			wantConfigOk: true,
		},
		{
			msg:          "use-forwarded-headers invalid bool",
			data:         map[string]string{"use-forwarded-headers": "notabool"},
			wantUsed:     false,
			wantConfigOk: false,
		},
		{
			msg: "use-forwarded-headers true and disable-forwarded-headers true mutually exclusive",
			data: map[string]string{
				"use-forwarded-headers":     "true",
				"disable-forwarded-headers": "true",
			},
			enableSnippets: true,
			wantUsed:       false,
			wantConfigOk:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			t.Parallel()
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "default",
				},
				Data: tc.data,
			}
			recorder := makeEventLogger()
			cfgParams, configOk := ParseConfigMap(context.Background(), cm, false, false, false, false, false, tc.enableSnippets, recorder)
			if configOk != tc.wantConfigOk {
				t.Errorf("configOk: want %v, got %v", tc.wantConfigOk, configOk)
			}
			if cfgParams.UseForwardedHeaders != tc.wantUsed {
				t.Errorf("UseForwardedHeaders: want %v, got %v", tc.wantUsed, cfgParams.UseForwardedHeaders)
			}
		})
	}
}

func TestParseConfigMap_SSLAndRealIPValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		data         map[string]string
		wantConfigOk bool
	}{
		{
			name: "valid ssl-ciphers and ssl-protocols and real-ip-header",
			data: map[string]string{
				"ssl-ciphers":    "DEFAULT:@SECLEVEL=2,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"ssl-protocols":  "TLSv1.2 TLSv1.3",
				"real-ip-header": "X-Forwarded-For",
			},
			wantConfigOk: true,
		},
		{
			name: "invalid ssl-ciphers with semicolon injection",
			data: map[string]string{
				"ssl-ciphers": "HIGH; return 500;",
			},
			wantConfigOk: false,
		},
		{
			name: "invalid ssl-protocols with newline injection",
			data: map[string]string{
				"ssl-protocols": "TLSv1.2\nserver_tokens off;",
			},
			wantConfigOk: false,
		},
		{
			name: "invalid real-ip-header with quote injection",
			data: map[string]string{
				"real-ip-header": "X-Real-IP\"; access_log /dev/null;",
			},
			wantConfigOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "default",
				},
				Data: tc.data,
			}
			recorder := makeEventLogger()
			cfg, configOk := ParseConfigMap(context.Background(), cm, false, false, false, false, false, false, recorder)
			if configOk != tc.wantConfigOk {
				t.Errorf("configOk: want %v, got %v", tc.wantConfigOk, configOk)
			}
			if value, ok := tc.data["ssl-ciphers"]; ok {
				if tc.wantConfigOk {
					assert.Equal(t, value, cfg.MainServerSSLCiphers)
				} else {
					assert.NotEqual(t, value, cfg.MainServerSSLCiphers)
				}
			}
			if value, ok := tc.data["ssl-protocols"]; ok {
				if tc.wantConfigOk {
					assert.Equal(t, value, cfg.MainServerSSLProtocols)
				} else {
					assert.NotEqual(t, value, cfg.MainServerSSLProtocols)
				}
			}
			if value, ok := tc.data["real-ip-header"]; ok {
				if tc.wantConfigOk {
					assert.Equal(t, value, cfg.RealIPHeader)
				} else {
					assert.NotEqual(t, value, cfg.RealIPHeader)
				}
			}
		})
	}
}

func TestParseConfigMapRawDirectiveValuesValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		data          map[string]string
		hasAppProtect bool
		hasDos        bool
		get           func(*ConfigParams) any
		want          any
	}{
		{name: "proxy connect timeout", data: map[string]string{"proxy-connect-timeout": "1h30m"}, get: func(p *ConfigParams) any { return p.ProxyConnectTimeout }, want: "1h30m"},
		{name: "proxy read timeout", data: map[string]string{"proxy-read-timeout": "5m"}, get: func(p *ConfigParams) any { return p.ProxyReadTimeout }, want: "5m"},
		{name: "proxy send timeout", data: map[string]string{"proxy-send-timeout": "600"}, get: func(p *ConfigParams) any { return p.ProxySendTimeout }, want: "600s"},
		{name: "worker shutdown timeout", data: map[string]string{"worker-shutdown-timeout": "30s"}, get: func(p *ConfigParams) any { return p.MainWorkerShutdownTimeout }, want: "30s"},
		{name: "keepalive timeout with header timeout", data: map[string]string{"keepalive-timeout": "75s 60s"}, get: func(p *ConfigParams) any { return p.MainKeepaliveTimeout }, want: "75s 60s"},
		{name: "fail timeout", data: map[string]string{"fail-timeout": "10s"}, get: func(p *ConfigParams) any { return p.FailTimeout }, want: "10s"},
		{name: "resolver timeout", data: map[string]string{"resolver-timeout": "30s"}, get: func(p *ConfigParams) any { return p.ResolverTimeout }, want: "30s"},
		{name: "resolver valid", data: map[string]string{"resolver-valid": "5m"}, get: func(p *ConfigParams) any { return p.ResolverValid }, want: "5m"},
		{name: "client max body size", data: map[string]string{"client-max-body-size": "2G"}, get: func(p *ConfigParams) any { return p.ClientMaxBodySize }, want: "2G"},
		{name: "proxy max temp file size zero", data: map[string]string{"proxy-max-temp-file-size": "0"}, get: func(p *ConfigParams) any { return p.ProxyMaxTempFileSize }, want: "0"},
		{name: "upstream zone size", data: map[string]string{"upstream-zone-size": "1m"}, get: func(p *ConfigParams) any { return p.UpstreamZoneSize }, want: "1m"},
		{name: "server names hash bucket size", data: map[string]string{"server-names-hash-bucket-size": "512"}, get: func(p *ConfigParams) any { return p.MainServerNamesHashBucketSize }, want: "512"},
		{name: "server names hash max size", data: map[string]string{"server-names-hash-max-size": "4096"}, get: func(p *ConfigParams) any { return p.MainServerNamesHashMaxSize }, want: "4096"},
		{name: "map hash bucket size", data: map[string]string{"map-hash-bucket-size": "128"}, get: func(p *ConfigParams) any { return p.MainMapHashBucketSize }, want: "128"},
		{name: "map hash max size", data: map[string]string{"map-hash-max-size": "8192"}, get: func(p *ConfigParams) any { return p.MainMapHashMaxSize }, want: "8192"},
		{name: "worker connections", data: map[string]string{"worker-connections": "2048"}, get: func(p *ConfigParams) any { return p.MainWorkerConnections }, want: "2048"},
		{name: "worker rlimit nofile", data: map[string]string{"worker-rlimit-nofile": "65535"}, get: func(p *ConfigParams) any { return p.MainWorkerRlimitNofile }, want: "65535"},
		{name: "proxy hide headers", data: map[string]string{"proxy-hide-headers": "X-Accel-Redirect, X-Custom-Header"}, get: func(p *ConfigParams) any { return p.ProxyHideHeaders }, want: []string{"X-Accel-Redirect", "X-Custom-Header"}},
		{name: "proxy pass headers", data: map[string]string{"proxy-pass-headers": "X-Accel-Expires, X-Accel-Limit-Rate"}, get: func(p *ConfigParams) any { return p.ProxyPassHeaders }, want: []string{"X-Accel-Expires", "X-Accel-Limit-Rate"}},
		{name: "set real ip from all forms", data: map[string]string{"set-real-ip-from": "10.0.0.0/8, 2001:db8::/32, unix:, realip.example.com"}, get: func(p *ConfigParams) any { return p.SetRealIPFrom }, want: []string{"10.0.0.0/8", "2001:db8::/32", "unix:", "realip.example.com"}},
		{name: "resolver addresses", data: map[string]string{"resolver-addresses": "10.0.0.10:53, [2001:db8::1]:5353, dns.example.com"}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string{"10.0.0.10:53", "[2001:db8::1]:5353", "dns.example.com"}},
		{name: "error log level", data: map[string]string{"error-log-level": "warn"}, get: func(p *ConfigParams) any { return p.MainErrorLogLevel }, want: "warn"},
		{name: "log format escaping", data: map[string]string{"log-format-escaping": "json"}, get: func(p *ConfigParams) any { return p.MainLogFormatEscaping }, want: "json"},
		{name: "stream log format escaping", data: map[string]string{"stream-log-format-escaping": "none"}, get: func(p *ConfigParams) any { return p.MainStreamLogFormatEscaping }, want: "none"},
		{name: "log format with variables and escaped quote", data: map[string]string{"log-format": `$remote_addr request=\'$request\'`}, get: func(p *ConfigParams) any { return p.MainLogFormat }, want: []string{`$remote_addr request=\'$request\'`}},
		{name: "stream log format with variables", data: map[string]string{"stream-log-format": `$remote_addr $protocol $status`}, get: func(p *ConfigParams) any { return p.MainStreamLogFormat }, want: []string{`$remote_addr $protocol $status`}},
		{name: "default server return quoted text", data: map[string]string{"default-server-return": `200 "healthy; ready"`}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: `200 "healthy; ready"`},
		{name: "default server return apostrophe", data: map[string]string{"default-server-return": "200 don't"}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "200 don't"},
		{name: "worker cpu affinity masks", data: map[string]string{"worker-cpu-affinity": "0001 0010 0100 1000"}, get: func(p *ConfigParams) any { return p.MainWorkerCPUAffinity }, want: "0001 0010 0100 1000"},
		{name: "worker cpu affinity auto mask", data: map[string]string{"worker-cpu-affinity": "auto 01010101"}, get: func(p *ConfigParams) any { return p.MainWorkerCPUAffinity }, want: "auto 01010101"},
		{name: "plus custom server tokens", data: map[string]string{"server-tokens": `NGINX Plus $hostname`}, get: func(p *ConfigParams) any { return p.ServerTokens }, want: `NGINX Plus $hostname`},
		// server-tokens is rendered with plain template quoting, so a quote in
		// the value must arrive already escaped for NGINX and is passed through
		// unchanged. Escaping it again here would make NGINX emit the
		// backslashes in the Server header.
		{name: "plus custom server tokens escaped quote", data: map[string]string{"server-tokens": `NGINX \"Plus\"`}, get: func(p *ConfigParams) any { return p.ServerTokens }, want: `NGINX \"Plus\"`},
		{name: "access log syslog parameters", data: map[string]string{"access-log": "syslog:server=unix:/var/run/nginx.sock,nohostname,tag=nginx main"}, get: func(p *ConfigParams) any { return p.MainAccessLog }, want: "syslog:server=unix:/var/run/nginx.sock,nohostname,tag=nginx main"},
		{name: "app protect cookie seed", data: map[string]string{"app-protect-cookie-seed": "abcdefghijklmnopqrstuvwxyz012345"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCookieSeed }, want: "abcdefghijklmnopqrstuvwxyz012345"},
		{name: "app protect dos fqdn", data: map[string]string{"app-protect-dos-arb-fqdn": "arb.example.com"}, hasDos: true, get: func(p *ConfigParams) any { return p.MainAppProtectDosArbFqdn }, want: "arb.example.com"},
		{name: "app protect dos log format", data: map[string]string{"app-protect-dos-log-format": `$remote_addr $app_protect_dos_outcome`}, hasDos: true, get: func(p *ConfigParams) any { return p.MainAppProtectDosLogFormat }, want: []string{`$remote_addr $app_protect_dos_outcome`}},
		{name: "app protect dos log format escaping", data: map[string]string{"app-protect-dos-log-format-escaping": "default"}, hasDos: true, get: func(p *ConfigParams) any { return p.MainAppProtectDosLogFormatEscaping }, want: "default"},
		{name: "otel header value", data: map[string]string{"otel-exporter-endpoint": "https://otel-collector:4317", "otel-exporter-header-name": "X-Tenant", "otel-exporter-header-value": `tenant \"blue\"`}, get: func(p *ConfigParams) any { return p.MainOtelExporterHeaderValue }, want: `tenant \"blue\"`},
		{name: "otel service name", data: map[string]string{"otel-exporter-endpoint": "https://otel-collector:4317", "otel-service-name": "nginx ingress controller"}, get: func(p *ConfigParams) any { return p.MainOtelServiceName }, want: "nginx ingress controller"},
		// '#' is a comment only at the start of a token; a URL fragment is data.
		{name: "default server return url fragment", data: map[string]string{"default-server-return": "302 https://example.com/#/home"}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "302 https://example.com/#/home"},
		// A YAML block scalar (key: |) leaves a trailing newline, which NGINX
		// reads as a token separator. These values loaded before validation was
		// added, so they are trimmed rather than rejected.
		{name: "real ip header trailing newline", data: map[string]string{"real-ip-header": "X-Forwarded-For\n"}, get: func(p *ConfigParams) any { return p.RealIPHeader }, want: "X-Forwarded-For"},
		{name: "access log trailing newline", data: map[string]string{"access-log": "syslog:server=localhost:514\n"}, get: func(p *ConfigParams) any { return p.MainAccessLog }, want: "syslog:server=localhost:514"},
		{name: "default server return trailing newline", data: map[string]string{"default-server-return": "302 https://example.com\n"}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "302 https://example.com"},
		{name: "app protect cookie seed trailing newline", data: map[string]string{"app-protect-cookie-seed": "abcdefghijklmnopqrstuvwxyz012345\n"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCookieSeed }, want: "abcdefghijklmnopqrstuvwxyz012345"},
		{name: "app protect cpu thresholds trailing newline", data: map[string]string{"app-protect-cpu-thresholds": "high=90 low=80\n"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCPUThresholds }, want: "high=90 low=80"},
		{name: "app protect memory thresholds surrounding space", data: map[string]string{"app-protect-physical-memory-util-thresholds": " low=70 high=95 "}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectPhysicalMemoryThresholds }, want: "low=70 high=95"},
		{name: "access log syslog tag with hash", data: map[string]string{"access-log": "syslog:server=localhost:514,tag=nginx#1 main"}, get: func(p *ConfigParams) any { return p.MainAccessLog }, want: "syslog:server=localhost:514,tag=nginx#1 main"},
		// A YAML block scalar (key: |) leaves a trailing newline, which NGINX
		// reads as a token separator. These values loaded before validation was
		// added, so they are trimmed rather than rejected.
		{name: "real ip header trailing newline", data: map[string]string{"real-ip-header": "X-Forwarded-For\n"}, get: func(p *ConfigParams) any { return p.RealIPHeader }, want: "X-Forwarded-For"},
		{name: "access log trailing newline", data: map[string]string{"access-log": "syslog:server=localhost:514\n"}, get: func(p *ConfigParams) any { return p.MainAccessLog }, want: "syslog:server=localhost:514"},
		{name: "default server return trailing newline", data: map[string]string{"default-server-return": "302 https://example.com\n"}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "302 https://example.com"},
		{name: "app protect cookie seed trailing newline", data: map[string]string{"app-protect-cookie-seed": "abcdefghijklmnopqrstuvwxyz012345\n"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCookieSeed }, want: "abcdefghijklmnopqrstuvwxyz012345"},
		{name: "app protect cpu thresholds trailing newline", data: map[string]string{"app-protect-cpu-thresholds": "high=90 low=80\n"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCPUThresholds }, want: "high=90 low=80"},
		{name: "app protect memory thresholds surrounding space", data: map[string]string{"app-protect-physical-memory-util-thresholds": " low=70 high=95 "}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectPhysicalMemoryThresholds }, want: "low=70 high=95"},
		// resolver accepts several space-separated addresses, and the list
		// used to be joined with spaces, so these forms loaded before.
		{name: "resolver addresses trailing comma", data: map[string]string{"resolver-addresses": "10.0.0.10,10.0.0.11,"}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string{"10.0.0.10", "10.0.0.11"}},
		{name: "resolver addresses space separated", data: map[string]string{"resolver-addresses": "10.0.0.10 10.0.0.11"}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string{"10.0.0.10", "10.0.0.11"}},
		{name: "resolver addresses trailing newline", data: map[string]string{"resolver-addresses": "10.0.0.10\n"}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string{"10.0.0.10"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg, configOk := ParseConfigMap(context.Background(), &v1.ConfigMap{Data: test.data}, true, test.hasAppProtect, test.hasDos, false, false, true, makeEventLogger())
			assert.True(t, configOk)
			assert.Equal(t, test.want, test.get(cfg))
		})
	}
}

func TestParseConfigMapRawDirectiveInjectionLeavesDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		data          map[string]string
		hasAppProtect bool
		hasDos        bool
		get           func(*ConfigParams) any
		want          any
	}{
		{name: "proxy connect timeout", data: map[string]string{"proxy-connect-timeout": "1s; return 200"}, get: func(p *ConfigParams) any { return p.ProxyConnectTimeout }, want: "60s"},
		{name: "proxy read timeout", data: map[string]string{"proxy-read-timeout": "1s\nreturn 200"}, get: func(p *ConfigParams) any { return p.ProxyReadTimeout }, want: "60s"},
		{name: "proxy send timeout", data: map[string]string{"proxy-send-timeout": "1s}"}, get: func(p *ConfigParams) any { return p.ProxySendTimeout }, want: "60s"},
		{name: "worker shutdown timeout", data: map[string]string{"worker-shutdown-timeout": "1s; daemon on"}, get: func(p *ConfigParams) any { return p.MainWorkerShutdownTimeout }, want: ""},
		{name: "keepalive timeout", data: map[string]string{"keepalive-timeout": "75s; access_log off"}, get: func(p *ConfigParams) any { return p.MainKeepaliveTimeout }, want: "75s"},
		{name: "fail timeout", data: map[string]string{"fail-timeout": "10s; down"}, get: func(p *ConfigParams) any { return p.FailTimeout }, want: "10s"},
		{name: "resolver timeout", data: map[string]string{"resolver-timeout": "30s; resolver 1.1.1.1"}, get: func(p *ConfigParams) any { return p.ResolverTimeout }, want: ""},
		{name: "resolver valid", data: map[string]string{"resolver-valid": "5m; ipv6=off"}, get: func(p *ConfigParams) any { return p.ResolverValid }, want: ""},
		{name: "client max body size", data: map[string]string{"client-max-body-size": "1m; return 413"}, get: func(p *ConfigParams) any { return p.ClientMaxBodySize }, want: "1m"},
		{name: "proxy max temp file size", data: map[string]string{"proxy-max-temp-file-size": "0; return 200"}, get: func(p *ConfigParams) any { return p.ProxyMaxTempFileSize }, want: ""},
		{name: "upstream zone size", data: map[string]string{"upstream-zone-size": "512k; zone evil"}, get: func(p *ConfigParams) any { return p.UpstreamZoneSize }, want: "512k"},
		{name: "server names hash bucket size", data: map[string]string{"server-names-hash-bucket-size": "512; return 200"}, get: func(p *ConfigParams) any { return p.MainServerNamesHashBucketSize }, want: "256"},
		{name: "server names hash max size", data: map[string]string{"server-names-hash-max-size": "4096\nreturn 200"}, get: func(p *ConfigParams) any { return p.MainServerNamesHashMaxSize }, want: "1024"},
		{name: "map hash bucket size", data: map[string]string{"map-hash-bucket-size": "128}"}, get: func(p *ConfigParams) any { return p.MainMapHashBucketSize }, want: "256"},
		{name: "map hash max size", data: map[string]string{"map-hash-max-size": "8192;"}, get: func(p *ConfigParams) any { return p.MainMapHashMaxSize }, want: "2048"},
		{name: "worker connections", data: map[string]string{"worker-connections": "2048; events {}"}, get: func(p *ConfigParams) any { return p.MainWorkerConnections }, want: "1024"},
		{name: "worker rlimit nofile", data: map[string]string{"worker-rlimit-nofile": "65535; daemon on"}, get: func(p *ConfigParams) any { return p.MainWorkerRlimitNofile }, want: ""},
		{name: "proxy hide headers", data: map[string]string{"proxy-hide-headers": "X-Good,X-Bad; return 200"}, get: func(p *ConfigParams) any { return p.ProxyHideHeaders }, want: []string(nil)},
		{name: "proxy pass headers", data: map[string]string{"proxy-pass-headers": "X-Good\nproxy_pass_header X-Evil"}, get: func(p *ConfigParams) any { return p.ProxyPassHeaders }, want: []string(nil)},
		{name: "set real ip from", data: map[string]string{"set-real-ip-from": "10.0.0.0/8; set_real_ip_from 0.0.0.0/0"}, get: func(p *ConfigParams) any { return p.SetRealIPFrom }, want: []string(nil)},
		{name: "resolver addresses", data: map[string]string{"resolver-addresses": "10.0.0.10; resolver 1.1.1.1"}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string(nil)},
		{name: "resolver addresses empty", data: map[string]string{"resolver-addresses": ""}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string(nil)},
		{name: "resolver addresses only separators", data: map[string]string{"resolver-addresses": " , "}, get: func(p *ConfigParams) any { return p.ResolverAddresses }, want: []string(nil)},
		{name: "default server return comment after whitespace", data: map[string]string{"default-server-return": "302 https://example.com/ #/home"}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "404"},
		{name: "error log level", data: map[string]string{"error-log-level": "info; access_log off"}, get: func(p *ConfigParams) any { return p.MainErrorLogLevel }, want: "notice"},
		{name: "log format escaping", data: map[string]string{"log-format-escaping": "json; access_log off"}, get: func(p *ConfigParams) any { return p.MainLogFormatEscaping }, want: ""},
		{name: "stream log format escaping", data: map[string]string{"stream-log-format-escaping": "none\nserver {}"}, get: func(p *ConfigParams) any { return p.MainStreamLogFormatEscaping }, want: ""},
		{name: "log format quote breakout", data: map[string]string{"log-format": `$remote_addr'; access_log off; '`}, get: func(p *ConfigParams) any { return p.MainLogFormat }, want: []string(nil)},
		{name: "stream log format quote breakout", data: map[string]string{"stream-log-format": `$remote_addr'; server {}; '`}, get: func(p *ConfigParams) any { return p.MainStreamLogFormat }, want: []string(nil)},
		{name: "default server return", data: map[string]string{"default-server-return": "404; return 200"}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "404"},
		{name: "default server return quote after braced variable", data: map[string]string{"default-server-return": `404 ${a}"; return 200; #"`}, get: func(p *ConfigParams) any { return p.DefaultServerReturn }, want: "404"},
		{name: "worker cpu affinity", data: map[string]string{"worker-cpu-affinity": "0001; daemon on"}, get: func(p *ConfigParams) any { return p.MainWorkerCPUAffinity }, want: ""},
		{name: "plus custom server tokens", data: map[string]string{"server-tokens": "off\";\nreturn 200;\n#"}, get: func(p *ConfigParams) any { return p.ServerTokens }, want: "on"},
		// An unescaped quote cannot be represented in a plainly quoted argument.
		// Before validation existed this emitted server_tokens "NGINX "Plus"";,
		// which NGINX rejects, so it is a config-test failure turned into a
		// rejection rather than a working value being taken away.
		{name: "plus custom server tokens unescaped quote", data: map[string]string{"server-tokens": `NGINX "Plus"`}, get: func(p *ConfigParams) any { return p.ServerTokens }, want: "on"},
		{name: "access log syslog", data: map[string]string{"access-log": "syslog:server=localhost:514; access_log off"}, get: func(p *ConfigParams) any { return p.MainAccessLog }, want: "/dev/stdout main"},
		{name: "access log comment", data: map[string]string{"access-log": "syslog:server=localhost:514 # disable terminator"}, get: func(p *ConfigParams) any { return p.MainAccessLog }, want: "/dev/stdout main"},
		{name: "app protect cookie seed", data: map[string]string{"app-protect-cookie-seed": "seed; app_protect_enable off"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCookieSeed }, want: ""},
		{name: "app protect cookie seed too short", data: map[string]string{"app-protect-cookie-seed": "short"}, hasAppProtect: true, get: func(p *ConfigParams) any { return p.MainAppProtectCookieSeed }, want: ""},
		{name: "app protect dos fqdn", data: map[string]string{"app-protect-dos-arb-fqdn": "arb.example.com; access_log off"}, hasDos: true, get: func(p *ConfigParams) any { return p.MainAppProtectDosArbFqdn }, want: ""},
		{name: "app protect dos log format quote breakout", data: map[string]string{"app-protect-dos-log-format": `$remote_addr'; access_log off; '`}, hasDos: true, get: func(p *ConfigParams) any { return p.MainAppProtectDosLogFormat }, want: []string(nil)},
		{name: "app protect dos log format escaping", data: map[string]string{"app-protect-dos-log-format-escaping": "json; access_log off"}, hasDos: true, get: func(p *ConfigParams) any { return p.MainAppProtectDosLogFormatEscaping }, want: ""},
		{name: "otel header control character", data: map[string]string{"otel-exporter-endpoint": "https://otel-collector:4317", "otel-exporter-header-name": "X-Tenant", "otel-exporter-header-value": "tenant\naccess_log off"}, get: func(p *ConfigParams) any { return p.MainOtelExporterHeaderValue }, want: ""},
		{name: "otel service name control character", data: map[string]string{"otel-exporter-endpoint": "https://otel-collector:4317", "otel-service-name": "nginx\naccess_log off"}, get: func(p *ConfigParams) any { return p.MainOtelServiceName }, want: ""},
		{name: "otel endpoint directive breakout", data: map[string]string{"otel-exporter-endpoint": "https://otel-collector:4317/path; access_log off"}, get: func(p *ConfigParams) any { return p.MainOtelExporterEndpoint }, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg, configOk := ParseConfigMap(context.Background(), &v1.ConfigMap{Data: test.data}, true, test.hasAppProtect, test.hasDos, false, false, true, makeEventLogger())
			assert.False(t, configOk)
			assert.Equal(t, test.want, test.get(cfg))
		})
	}
}

func TestParseMGMTConfigMapResolverValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		data          map[string]string
		wantWarnings  bool
		wantAddresses []string
		wantValid     string
	}{
		{
			name: "valid resolver grammar",
			data: map[string]string{
				"license-token-secret-name": "license-token",
				"resolver-addresses":        "10.0.0.10:53, [2001:db8::1]:5353, dns.example.com",
				"resolver-valid":            "5m",
			},
			wantAddresses: []string{"10.0.0.10:53", "[2001:db8::1]:5353", "dns.example.com"},
			wantValid:     "5m",
		},
		{
			name: "resolver addresses trailing comma",
			data: map[string]string{
				"license-token-secret-name": "license-token",
				"resolver-addresses":        "10.0.0.10,10.0.0.11,",
			},
			wantAddresses: []string{"10.0.0.10", "10.0.0.11"},
		},
		{
			name: "resolver addresses space separated",
			data: map[string]string{
				"license-token-secret-name": "license-token",
				"resolver-addresses":        "10.0.0.10 10.0.0.11",
			},
			wantAddresses: []string{"10.0.0.10", "10.0.0.11"},
		},
		{
			name: "resolver addresses only a comma",
			data: map[string]string{
				"license-token-secret-name": "license-token",
				"resolver-addresses":        ",",
			},
			wantWarnings: true,
		},
		{
			name: "resolver address injection",
			data: map[string]string{
				"license-token-secret-name": "license-token",
				"resolver-addresses":        "10.0.0.10; resolver 1.1.1.1",
			},
			wantWarnings: true,
		},
		{
			name: "resolver valid injection",
			data: map[string]string{
				"license-token-secret-name": "license-token",
				"resolver-valid":            "5m; ipv6=off",
			},
			wantWarnings: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg, warnings, err := ParseMGMTConfigMap(context.Background(), &v1.ConfigMap{Data: test.data}, makeEventLogger())
			assert.NoError(t, err)
			assert.Equal(t, test.wantWarnings, warnings)
			assert.Equal(t, test.wantAddresses, cfg.ResolverAddresses)
			assert.Equal(t, test.wantValid, cfg.ResolverValid)
		})
	}
}

// TestParseConfigMapDoesNotLeakSecrets asserts that a rejected value for a key
// that carries a secret never reaches the controller log or a Kubernetes Event,
// which are usually readable by far more people than the ConfigMap.
func TestParseConfigMapDoesNotLeakSecrets(t *testing.T) {
	t.Parallel()

	const secret = "Sup3rS3cretValue0123456789"
	tests := []struct {
		name string
		data map[string]string
	}{
		{
			// A near miss of the real seed. Surrounding whitespace is trimmed
			// and accepted, so use a character the grammar rejects.
			name: "app-protect-cookie-seed",
			data: map[string]string{"app-protect-cookie-seed": secret + "-"},
		},
		{
			name: "otel-exporter-header-value",
			data: map[string]string{
				"otel-exporter-endpoint":     "https://otel.example.com:4317",
				"otel-exporter-header-name":  "Authorization",
				"otel-exporter-header-value": "Bearer " + secret + `"`,
			},
		},
		{
			// url.Parse errors repeat the whole URL, credentials included.
			name: "otel-exporter-endpoint",
			data: map[string]string{"otel-exporter-endpoint": "https://user:" + secret + "@otel.example.com:43 17"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			ctx := nl.ContextWithLogger(context.Background(), slog.New(glog.New(&logs, nil)))
			recorder := record.NewFakeRecorder(1024)
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "nginx-config", Namespace: "nginx-ingress"},
				Data:       tc.data,
			}

			_, configOk := ParseConfigMap(ctx, cm, true, true, false, false, false, false, recorder)
			if configOk {
				t.Fatal("want the invalid value to be rejected")
			}

			close(recorder.Events)
			var events []string
			for e := range recorder.Events {
				events = append(events, e)
			}
			if len(events) == 0 {
				t.Fatal("want a warning Event for the rejected value")
			}
			for _, e := range events {
				if strings.Contains(e, secret) {
					t.Errorf("Event leaks the secret: %s", e)
				}
			}
			if logs.Len() == 0 {
				t.Fatal("want the rejection to be logged")
			}
			if strings.Contains(logs.String(), secret) {
				t.Errorf("log leaks the secret: %s", logs.String())
			}
		})
	}
}
