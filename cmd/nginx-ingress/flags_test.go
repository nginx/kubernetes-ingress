package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseNginxStatusAllowCIDRs(t *testing.T) {
	badCIDRs := []struct {
		input         string
		expectedError error
	}{
		{
			"earth, ,,furball",
			errors.New("invalid IP address: earth"),
		},
		{
			"127.0.0.1,10.0.1.0/24, ,,furball",
			errors.New("invalid CIDR address: an empty string is an invalid CIDR block or IP address"),
		},
		{
			"false",
			errors.New("invalid IP address: false"),
		},
	}
	for _, badCIDR := range badCIDRs {
		_, err := parseNginxStatusAllowCIDRs(badCIDR.input)
		if err == nil {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned no error when it should have returned error %q", badCIDR.input, badCIDR.expectedError)
		} else if err.Error() != badCIDR.expectedError.Error() {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned error %q when it should have returned error %q", badCIDR.input, err, badCIDR.expectedError)
		}
	}

	goodCIDRs := []struct {
		input    string
		expected []string
	}{
		{
			"127.0.0.1",
			[]string{"127.0.0.1"},
		},
		{
			"10.0.1.0/24",
			[]string{"10.0.1.0/24"},
		},
		{
			"127.0.0.1,10.0.1.0/24,68.121.233.214 , 24.24.24.24/32",
			[]string{"127.0.0.1", "10.0.1.0/24", "68.121.233.214", "24.24.24.24/32"},
		},
	}
	for _, goodCIDR := range goodCIDRs {
		result, err := parseNginxStatusAllowCIDRs(goodCIDR.input)
		if err != nil {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned an error when it should have returned no error: %q", goodCIDR.input, err)
		}

		if !reflect.DeepEqual(result, goodCIDR.expected) {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned %v expected %v: ", goodCIDR.input, result, goodCIDR.expected)
		}
	}
}

func TestValidateCIDRorIP(t *testing.T) {
	badCIDRs := []string{"localhost", "thing", "~", "!!!", "", " ", "-1"}
	for _, badCIDR := range badCIDRs {
		err := validateCIDRorIP(badCIDR)
		if err == nil {
			t.Errorf(`Expected error for invalid CIDR "%v"\n`, badCIDR)
		}
	}

	goodCIDRs := []string{"0.0.0.0/32", "0.0.0.0/0", "127.0.0.1/32", "127.0.0.0/24", "23.232.65.42"}
	for _, goodCIDR := range goodCIDRs {
		err := validateCIDRorIP(goodCIDR)
		if err != nil {
			t.Errorf("Error for valid CIDR: %v err: %v\n", goodCIDR, err)
		}
	}
}

func TestValidateLocation(t *testing.T) {
	badLocations := []string{
		"",
		"/",
		" /test",
		"/bad;",
	}
	for _, badLocation := range badLocations {
		err := validateLocation(badLocation)
		if err == nil {
			t.Errorf("validateLocation(%v) returned no error when it should have returned an error", badLocation)
		}
	}

	goodLocations := []string{
		"/test",
		"/test/subtest",
	}
	for _, goodLocation := range goodLocations {
		err := validateLocation(goodLocation)
		if err != nil {
			t.Errorf("validateLocation(%v) returned an error when it should have returned no error: %v", goodLocation, err)
		}
	}
}

func TestValidateLogLevel(t *testing.T) {
	badLogLevels := []string{
		"",
		"critical",
		"none",
		"info;",
	}
	for _, badLogLevel := range badLogLevels {
		err := validateLogLevel(badLogLevel)
		if err == nil {
			t.Errorf("validateLogLevel(%v) returned no error when it should have returned an error", badLogLevel)
		}
	}

	goodLogLevels := []string{
		"fatal",
		"Error",
		"WARN",
		"info",
		"debug",
		"trace",
	}
	for _, goodLogLevel := range goodLogLevels {
		err := validateLogLevel(goodLogLevel)
		if err != nil {
			t.Errorf("validateLogLevel(%v) returned an error when it should have returned no error: %v", goodLogLevel, err)
		}
	}
}

func TestValidateNamespaces(t *testing.T) {
	badNamespaces := []string{"watchns1, watchns2, watchns%$", "watchns1,watchns2,watchns%$"}
	for _, badNs := range badNamespaces {
		err := validateNamespaceNames(strings.Split(badNs, ","))
		if err == nil {
			t.Errorf("Expected error for invalid namespace %v\n", badNs)
		}
	}

	goodNamespaces := []string{"watched-namespace", "watched-namespace,", "watched-namespace1,watched-namespace2", "watched-namespace1, watched-namespace2"}
	for _, goodNs := range goodNamespaces {
		err := validateNamespaceNames(strings.Split(goodNs, ","))
		if err != nil {
			t.Errorf("Error for valid namespace:  %v err: %v\n", goodNs, err)
		}
	}
}

func TestValidateLogFormat(t *testing.T) {
	badLogFormats := []string{
		"",
		"jason",
		"txt",
		"gloog",
	}
	for _, badLogFormat := range badLogFormats {
		err := validateLogFormat(badLogFormat)
		if err == nil {
			t.Errorf("validateLogFormat(%v) returned no error when it should have returned an error", badLogFormat)
		}
	}

	goodLogFormats := []string{
		"json",
		"text",
		"glog",
	}
	for _, goodLogFormat := range goodLogFormats {
		err := validateLogFormat(goodLogFormat)
		if err != nil {
			t.Errorf("validateLogFormat(%v) returned an error when it should have returned no error: %v", goodLogFormat, err)
		}
	}
}

func TestValidatePLMSecretRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		value    string
		wantNS   string
		wantName string
		wantErr  bool
	}{
		{name: "empty is accepted", value: "", wantErr: false},
		{name: "namespace/name", value: "plm/seaweed-auth", wantNS: "plm", wantName: "seaweed-auth", wantErr: false},
		{name: "bare name rejected (must be namespace/name)", value: "seaweed-auth", wantErr: true},
		{name: "trailing slash rejected", value: "plm/", wantErr: true},
		{name: "leading slash rejected", value: "/seaweed-auth", wantErr: true},
		{name: "double slash rejected", value: "plm/foo/bar", wantErr: true},
		{name: "just slash rejected", value: "/", wantErr: true},
		{name: "uppercase name rejected (non DNS-1123)", value: "plm/Foo", wantErr: true},
		{name: "uppercase namespace rejected (non DNS-1123)", value: "PLM/seaweed-auth", wantErr: true},
		{name: "whitespace in value rejected", value: "plm/foo bar", wantErr: true},
		{name: "underscore in name rejected", value: "plm/foo_bar", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref, err := validatePLMSecretRef("plm-storage-credentials-secret", tc.value)
			if tc.wantErr {
				if err == nil {
					t.Errorf("validatePLMSecretRef(%q) expected error, got nil", tc.value)
				}
				return
			}
			if err != nil {
				t.Errorf("validatePLMSecretRef(%q) unexpected error: %v", tc.value, err)
			}
			if ref.Namespace != tc.wantNS || ref.Name != tc.wantName {
				t.Errorf("validatePLMSecretRef(%q) = %s/%s, want %s/%s", tc.value, ref.Namespace, ref.Name, tc.wantNS, tc.wantName)
			}
		})
	}
}

func TestValidatePLMStorageURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "http host", value: "http://seaweed.plm.svc.cluster.local:8333", wantErr: false},
		{name: "https host", value: "https://seaweed.plm.svc.cluster.local:8333/", wantErr: false},
		{name: "http with path", value: "http://seaweed:8333/bucket", wantErr: false},

		{name: "empty rejected", value: "", wantErr: true},
		{name: "scheme only rejected", value: "http://", wantErr: true},
		{name: "wrong scheme rejected", value: "ftp://seaweed:8333", wantErr: true},
		{name: "no scheme rejected", value: "seaweed:8333", wantErr: true},
		{name: "s3 scheme rejected", value: "s3://bucket/key", wantErr: true},
		{name: "userinfo rejected", value: "http://user:pass@evil/", wantErr: true},
		{name: "trailing space rejected", value: "http://seaweed:8333 ", wantErr: true},
		{name: "embedded CRLF rejected", value: "http://foo\r\nbar", wantErr: true},
		{name: "embedded tab rejected", value: "http://seaweed\t:8333", wantErr: true},
		{name: "ipv6 rejected", value: "http://[::1]:8333", wantErr: true},
		{name: "port out of range rejected", value: "http://seaweed:70000", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validatePLMStorageURL(tc.value)
			if tc.wantErr && err == nil {
				t.Errorf("validatePLMStorageURL(%q) expected error, got nil", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validatePLMStorageURL(%q) unexpected error: %v", tc.value, err)
			}
		})
	}
}

func TestValidatePLMFlags(t *testing.T) {
	t.Parallel()
	const goodURL = "http://seaweed.plm.svc.cluster.local:8333"

	tests := []struct {
		name               string
		url                string
		credentialsSecret  string
		caSecret           string
		clientSSLSecret    string
		insecureSkipVerify bool
		nginxPlus          bool
		appProtect         bool
		wantErr            bool
		wantErrContains    string
		wantWarn           bool
	}{
		{
			name:      "URL empty and no aux flags is a no-op",
			url:       "",
			nginxPlus: false, // even without prereqs, empty URL means no PLM
		},
		{
			name:              "URL empty but credentials-secret set fails",
			url:               "",
			credentialsSecret: "plm/seaweed-auth",
			wantErr:           true,
			wantErrContains:   "plm-storage-credentials-secret is set but plm-storage-url is not",
		},
		{
			name:            "URL empty but ca-secret set fails",
			url:             "",
			caSecret:        "plm/plm-ca",
			wantErr:         true,
			wantErrContains: "plm-storage-ca-secret is set but plm-storage-url is not",
		},
		{
			name:            "URL empty but client-ssl-secret set fails",
			url:             "",
			clientSSLSecret: "plm/plm-client",
			wantErr:         true,
			wantErrContains: "plm-storage-client-ssl-secret is set but plm-storage-url is not",
		},
		{
			name:               "URL empty but insecure-skip-verify set fails",
			url:                "",
			insecureSkipVerify: true,
			wantErr:            true,
			wantErrContains:    "plm-storage-insecure-skip-verify is set but plm-storage-url is not",
		},
		{
			name:            "URL set without nginx-plus fails",
			url:             goodURL,
			nginxPlus:       false,
			appProtect:      true,
			wantErr:         true,
			wantErrContains: "nginx-plus",
		},
		{
			name:            "URL set without app-protect fails",
			url:             goodURL,
			nginxPlus:       true,
			appProtect:      false,
			wantErr:         true,
			wantErrContains: "enable-app-protect",
		},
		{
			name:            "malformed URL fails",
			url:             "not-a-url",
			nginxPlus:       true,
			appProtect:      true,
			wantErr:         true,
			wantErrContains: "plm-storage-url",
		},
		{
			name:            "URL set without credentials-secret fails",
			url:             goodURL,
			nginxPlus:       true,
			appProtect:      true,
			wantErr:         true,
			wantErrContains: "plm-storage-credentials-secret must be set",
		},
		{
			name:              "invalid credentials secret ref fails",
			url:               goodURL,
			credentialsSecret: "PLM/Foo",
			nginxPlus:         true,
			appProtect:        true,
			wantErr:           true,
			wantErrContains:   "plm-storage-credentials-secret",
		},
		{
			name:              "invalid ca secret ref fails",
			url:               goodURL,
			credentialsSecret: "plm/seaweed-auth",
			caSecret:          "plm/",
			nginxPlus:         true,
			appProtect:        true,
			wantErr:           true,
			wantErrContains:   "plm-storage-ca-secret",
		},
		{
			name:              "invalid client-ssl secret ref fails",
			url:               goodURL,
			credentialsSecret: "plm/seaweed-auth",
			clientSSLSecret:   "/bad",
			nginxPlus:         true,
			appProtect:        true,
			wantErr:           true,
			wantErrContains:   "plm-storage-client-ssl-secret",
		},
		{
			name:              "valid config with all secrets is accepted",
			url:               goodURL,
			credentialsSecret: "plm/seaweed-auth",
			caSecret:          "plm/plm-ca",
			clientSSLSecret:   "plm/plm-client",
			nginxPlus:         true,
			appProtect:        true,
		},
		{
			name:               "insecure-skip-verify emits warning",
			url:                goodURL,
			credentialsSecret:  "plm/seaweed-auth",
			insecureSkipVerify: true,
			nginxPlus:          true,
			appProtect:         true,
			wantWarn:           true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			refs, warn, err := validatePLMFlags(
				tc.url,
				tc.credentialsSecret,
				tc.caSecret,
				tc.clientSSLSecret,
				tc.insecureSkipVerify,
				tc.nginxPlus,
				tc.appProtect,
			)
			if tc.wantErr {
				assertPLMFlagsError(t, err, tc.wantErrContains)
				return
			}
			if err != nil {
				t.Fatalf("validatePLMFlags: unexpected error: %v", err)
			}
			assertPLMFlagsWarn(t, warn, tc.wantWarn)
			if tc.url != "" {
				assertPLMFlagsRefs(t, refs, tc.credentialsSecret, tc.caSecret, tc.clientSSLSecret)
			}
		})
	}
}

// assertPLMFlagsError checks the error path of validatePLMFlags.
func assertPLMFlagsError(t *testing.T, err error, wantContains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("validatePLMFlags: expected error, got nil")
	}
	if wantContains != "" && !strings.Contains(err.Error(), wantContains) {
		t.Errorf("validatePLMFlags: error %q does not contain %q", err.Error(), wantContains)
	}
}

// assertPLMFlagsWarn checks the warning behavior of validatePLMFlags.
func assertPLMFlagsWarn(t *testing.T, warn string, wantWarn bool) {
	t.Helper()
	if wantWarn && warn == "" {
		t.Errorf("validatePLMFlags: expected a warning, got empty string")
	}
	if !wantWarn && warn != "" {
		t.Errorf("validatePLMFlags: unexpected warning: %q", warn)
	}
}

// assertPLMFlagsRefs checks that parsed secret refs match the input when PLM is enabled.
func assertPLMFlagsRefs(t *testing.T, refs plmSecretRefs, wantCredentials, wantCA, wantClientSSL string) {
	t.Helper()
	if got := refs.Credentials.String(); wantCredentials != "" && got != wantCredentials {
		t.Errorf("validatePLMFlags: Credentials = %q, want %q", got, wantCredentials)
	}
	if got := refs.CA.String(); wantCA != "" && got != wantCA {
		t.Errorf("validatePLMFlags: CA = %q, want %q", got, wantCA)
	}
	if got := refs.ClientSSL.String(); wantClientSSL != "" && got != wantClientSSL {
		t.Errorf("validatePLMFlags: ClientSSL = %q, want %q", got, wantClientSSL)
	}
}
