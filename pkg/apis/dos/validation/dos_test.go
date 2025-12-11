package validation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValidateDosProtectedResource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		protected *v1beta1.DosProtectedResource
		expectErr string
		msg       string
	}{
		{
			protected: &v1beta1.DosProtectedResource{},
			expectErr: "error validating DosProtectedResource:  missing value for field: name",
			msg:       "empty resource",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{},
			},
			expectErr: "error validating DosProtectedResource:  missing value for field: name",
			msg:       "empty spec",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "exabad-$%^$-example.com",
					},
				},
			},
			expectErr: "error validating DosProtectedResource:  invalid field: apDosMonitor err: app Protect Dos Monitor must have valid URL",
			msg:       "invalid apDosMonitor specified",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
				},
			},
			msg: "name, dosAccessLogDest and apDosMonitor specified",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "bad&$%^logdest",
				},
			},
			expectErr: "error validating DosProtectedResource:  invalid field: dosAccessLogDest err: invalid log destination: bad&$%^logdest, must follow format: <ip-address | localhost | dns name>:<port> or stderr",
			msg:       "invalid DosAccessLogDest specified",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
					ApDosPolicy:      "ns/name",
				},
			},
			expectErr: "",
			msg:       "required fields and apdospolicy specified",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
					ApDosPolicy:      "bad$%^name",
				},
			},
			expectErr: "error validating DosProtectedResource:  invalid field: apDosPolicy err: reference name is invalid: bad$%^name",
			msg:       "invalid apdospolicy specified",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
					DosSecurityLog:   &v1beta1.DosSecurityLog{},
				},
			},
			expectErr: "error validating DosProtectedResource:  invalid field: dosSecurityLog/dosLogDest err: invalid log destination: , must follow format: <ip-address | localhost | dns name>:<port> or stderr",
			msg:       "empty DosSecurityLog specified",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
					DosSecurityLog: &v1beta1.DosSecurityLog{
						DosLogDest: "service.org:123",
					},
				},
			},
			expectErr: "error validating DosProtectedResource:  invalid field: dosSecurityLog/apDosLogConf err: reference name is invalid: ",
			msg:       "DosSecurityLog with missing apDosLogConf",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
					DosSecurityLog: &v1beta1.DosSecurityLog{
						DosLogDest:   "service.org:123",
						ApDosLogConf: "bad$%^$%name",
					},
				},
			},
			expectErr: "error validating DosProtectedResource:  invalid field: dosSecurityLog/apDosLogConf err: reference name is invalid: bad$%^$%name",
			msg:       "DosSecurityLog with invalid apDosLogConf",
		},
		{
			protected: &v1beta1.DosProtectedResource{
				Spec: v1beta1.DosProtectedResourceSpec{
					Name: "name",
					ApDosMonitor: &v1beta1.ApDosMonitor{
						URI: "example.com",
					},
					DosAccessLogDest: "example.service.com:123",
					DosSecurityLog: &v1beta1.DosSecurityLog{
						DosLogDest:   "service.org:123",
						ApDosLogConf: "ns/name",
					},
				},
			},
			expectErr: "",
			msg:       "DosSecurityLog with valid apDosLogConf",
		},
	}
	for _, test := range tests {
		err := ValidateDosProtectedResource(test.protected)
		if err != nil {
			if test.expectErr == "" {
				t.Errorf("ValidateDosProtectedResource() returned unexpected error: '%v' for the case of: '%s'", err, test.msg)
				continue
			}
			if test.expectErr != err.Error() {
				t.Errorf("ValidateDosProtectedResource() returned error for the case of '%s', expected err: '%s' got err: '%s'", test.msg, test.expectErr, err.Error())
			}
		} else {
			if test.expectErr != "" {
				t.Errorf("ValidateDosProtectedResource() failed to return expected error: '%v' for the case of: '%s'", test.expectErr, test.msg)
			}
		}
	}
}

func TestValidateAppProtectDosAccessLogDest(t *testing.T) {
	t.Parallel()
	// Positive test cases
	posDstAntns := []string{
		"10.10.1.1:514",
		"localhost:514",
		"dns.test.svc.cluster.local:514",
		"cluster.local:514",
		"dash-test.cluster.local:514",
	}

	// Negative test cases item, expected error message
	negDstAntns := [][]string{
		{"NotValid", "invalid log destination: NotValid, must follow format: <ip-address | localhost | dns name>:<port> or stderr"},
		{"cluster.local", "invalid log destination: cluster.local, must follow format: <ip-address | localhost | dns name>:<port> or stderr"},
		{"-cluster.local:514", "invalid log destination: -cluster.local:514, must follow format: <ip-address | localhost | dns name>:<port> or stderr"},
		{"10.10.1.1:99999", "not a valid port number"},
	}

	for _, tCase := range posDstAntns {
		err := validateAppProtectDosLogDest(tCase)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	}
	for _, nTCase := range negDstAntns {
		err := validateAppProtectDosLogDest(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing '%s'", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got '%v', expected: '%s'", err, nTCase[1])
			}
		}
	}
}

func TestValidateAppProtectDosLogConf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		logConf    *unstructured.Unstructured
		expectErr  bool
		expectWarn bool
		msg        string
	}{
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"filter": map[string]interface{}{},
					},
				},
			},
			expectErr:  false,
			expectWarn: false,
			msg:        "valid log conf",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expectErr:  true,
			expectWarn: false,
			msg:        "invalid log conf with no filter field",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"something": map[string]interface{}{
						"filter": map[string]interface{}{},
					},
				},
			},
			expectErr:  true,
			expectWarn: false,
			msg:        "invalid log conf with no spec field",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"content": map[string]interface{}{
							"format": "user-defined",
						},
						"filter": map[string]interface{}{},
					},
				},
			},
			expectErr:  false,
			expectWarn: true,
			msg:        "Support only splunk format",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"filter": map[string]interface{}{},
						"content": map[string]interface{}{
							"format": "user-defined",
						},
					},
				},
			},
			expectErr:  false,
			expectWarn: true,
			msg:        "valid log conf with warning filter field",
		},
	}

	for _, test := range tests {
		warn, err := ValidateAppProtectDosLogConf(test.logConf)
		if test.expectErr && err == nil {
			t.Errorf("validateAppProtectDosLogConf() returned no error for the case of %s", test.msg)
		}
		if !test.expectErr && err != nil {
			t.Errorf("validateAppProtectDosLogConf() returned unexpected error %v for the case of %s", err, test.msg)
		}
		if test.expectWarn && warn == "" {
			t.Errorf("validateAppProtectDosLogConf() returned no warning for the case of %s", test.msg)
		}
		if !test.expectWarn && warn != "" {
			t.Errorf("validateAppProtectDosLogConf() returned unexpected warning: %s, for the case of %s", warn, test.msg)
		}
	}
}

func TestValidateAppProtectDosPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policy    *unstructured.Unstructured
		expectErr bool
		msg       string
	}{
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expectErr: false,
			msg:       "valid policy",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"something": map[string]interface{}{},
				},
			},
			expectErr: true,
			msg:       "invalid policy with no spec field",
		},
	}

	for _, test := range tests {
		err := ValidateAppProtectDosPolicy(test.policy)
		if test.expectErr && err == nil {
			t.Errorf("validateAppProtectPolicy() returned no error for the case of %s", test.msg)
		}
		if !test.expectErr && err != nil {
			t.Errorf("validateAppProtectPolicy() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateAppProtectDosName(t *testing.T) {
	t.Parallel()
	// Positive test cases
	posDstAntns := []string{"example.com", "\\\"example.com\\\""}

	// Negative test cases item, expected error message
	negDstAntns := [][]string{
		{"very very very very very very very very very very very very very very very very very very long Name", fmt.Sprintf(`app Protect Dos Name max length is %v`, maxNameLength)},
		{"example.com\\", "must have all '\"' (double quotes) escaped and must not end with an unescaped '\\' (backslash) (e.g. 'protected-object-one', regex used for validation is '([^\"\\\\]|\\\\.)*')"},
		{"\"example.com\"", "must have all '\"' (double quotes) escaped and must not end with an unescaped '\\' (backslash) (e.g. 'protected-object-one', regex used for validation is '([^\"\\\\]|\\\\.)*')"},
	}

	for _, tCase := range posDstAntns {
		err := validateAppProtectDosName(tCase)
		if err != nil {
			t.Errorf("got %v expected nil", err)
		}
	}

	for _, nTCase := range negDstAntns {
		err := validateAppProtectDosName(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing %s", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got '%v'\n expected: '%s'\n", err, nTCase[1])
			}
		}
	}
}

func TestValidateAppProtectDosMonitor(t *testing.T) {
	t.Parallel()
	// Positive test cases
	posDstAntns := []v1beta1.ApDosMonitor{
		{
			URI:      "example.com",
			Protocol: "http1",
			Timeout:  5,
		},
		{
			URI:      "https://example.com/good_path",
			Protocol: "http2",
			Timeout:  10,
		},
		{
			URI:      "https://example.com/good_path",
			Protocol: "grpc",
			Timeout:  10,
		},
		{
			URI:      "https://example.com/good_path",
			Protocol: "websocket",
			Timeout:  10,
		},
	}
	negDstAntns := []struct {
		apDosMonitor v1beta1.ApDosMonitor
		msg          string
	}{
		{
			apDosMonitor: v1beta1.ApDosMonitor{
				URI:      "http://example.com/%",
				Protocol: "http1",
				Timeout:  5,
			},
			msg: "app Protect Dos Monitor must have valid URL",
		},
		{
			apDosMonitor: v1beta1.ApDosMonitor{
				URI:      "http://example.com/\\",
				Protocol: "http1",
				Timeout:  5,
			},
			msg: "must have all '\"' (double quotes) escaped and must not end with an unescaped '\\' (backslash) (e.g. 'http://www.example.com', regex used for validation is '([^\"\\\\]|\\\\.)*')",
		},
		{
			apDosMonitor: v1beta1.ApDosMonitor{
				URI:      "example.com",
				Protocol: "http3",
				Timeout:  5,
			},
			msg: "app Protect Dos Monitor Protocol must be: dosMonitorProtocol: Invalid value: \"http3\": 'http3' contains an invalid NGINX parameter. Accepted parameters are:",
		},
	}

	for _, tCase := range posDstAntns {
		err := validateAppProtectDosMonitor(tCase)
		if err != nil {
			t.Errorf("got %v expected nil", err)
		}
	}

	for _, nTCase := range negDstAntns {
		err := validateAppProtectDosMonitor(nTCase.apDosMonitor)
		if err == nil {
			t.Errorf("got no error expected error containing %s", nTCase.msg)
		} else {
			if !strings.Contains(err.Error(), nTCase.msg) {
				t.Errorf("got: \n%v\n expected to contain: \n%s", err, nTCase.msg)
			}
		}
	}
}

func TestValidateAppProtectDosLogDest_ValidOnDestinationStdErr(t *testing.T) {
	t.Parallel()

	if err := validateAppProtectDosLogDest("stderr"); err != nil {
		t.Error(err)
	}
}

func TestValidateAppProtectDosAllowList(t *testing.T) {
	tests := []struct {
		name      string
		allowList []v1beta1.AllowListEntry
		wantErr   bool
	}{
		{
			name:      "Empty allow list",
			allowList: []v1beta1.AllowListEntry{},
			wantErr:   false,
		},
		{
			name: "Single valid IPv4 entry",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "192.168.1.1/32"},
			},
			wantErr: false,
		},
		{
			name: "Single valid IPv6 entry",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"},
			},
			wantErr: false,
		},
		{
			name: "Multiple valid entries",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "192.168.1.1/32"},
				{IPWithMask: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"},
			},
			wantErr: false,
		},
		{
			name: "Invalid IPv4 entry",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "192.168.1.1445/32"},
			},
			wantErr: true,
		},
		{
			name: "Invalid IPv6 entry",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "2001:0db8:85a3:0000:0000:8a2e:0370:7334:3454/128"},
			},
			wantErr: true,
		},
		{
			name: "Invalid subnet mask",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "192.168.1.1/abc"},
			},
			wantErr: true,
		},
		{
			name: "Invalid IPv6 subnet mask",
			allowList: []v1beta1.AllowListEntry{
				{IPWithMask: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/199"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAppProtectDosAllowList(tt.allowList)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAppProtectDosAllowList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidIPWithMask(t *testing.T) {
	tests := []struct {
		name       string
		ipWithMask string
		want       bool
	}{
		{
			name:       "Valid IPv4 address with mask",
			ipWithMask: "192.168.1.1/32",
			want:       true,
		},
		{
			name:       "Valid IPv6 address with mask",
			ipWithMask: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
			want:       true,
		},
		{
			name:       "Invalid IPv4 address with mask",
			ipWithMask: "192.168.1.14444/33",
			want:       false,
		},
		{
			name:       "Invalid IPv6 address with mask",
			ipWithMask: "2001:0db8:85a3:0000:0000:8a2e:0370:7334:343434/128",
			want:       false,
		},
		{
			name:       "Invalid subnet mask",
			ipWithMask: "192.168.1.1/abc",
			want:       false,
		},
		{
			name:       "No subnet mask",
			ipWithMask: "192.168.1.1",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIPWithMask(tt.ipWithMask)
			if got != tt.want {
				t.Errorf("isValidIPWithMask() = %v, want %v", got, tt.want)
			}
		})
	}
}
