package validation

import (
	"testing"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func createTransportServerValidator() *TransportServerValidator {
	return &TransportServerValidator{}
}

func TestValidateTransportServer(t *testing.T) {
	t.Parallel()

	ts := conf_v1.TransportServer{
		Spec: conf_v1.TransportServerSpec{
			Listener: conf_v1.TransportServerListener{
				Name:     "tcp-listener",
				Protocol: "TCP",
			},
			Upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    5501,
				},
			},
			Action: &conf_v1.TransportServerAction{
				Pass: "upstream1",
			},
		},
	}

	tsv := createTransportServerValidator()

	err := tsv.ValidateTransportServer(&ts)
	if err != nil {
		t.Errorf("ValidateTransportServer() returned error %v for valid input", err)
	}
}

func makeTransportServer() conf_v1.TransportServer {
	return conf_v1.TransportServer{
		Spec: conf_v1.TransportServerSpec{
			Listener: conf_v1.TransportServerListener{
				Name:     "tcp-listener",
				Protocol: "TCP",
			},
			Upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    5501,
				},
			},
			Action: &conf_v1.TransportServerAction{
				Pass: "upstream1",
			},
		},
	}
}

func TestValidateTransportServer_BackupService(t *testing.T) {
	t.Parallel()

	ts := makeTransportServer()
	ts.Spec.Upstreams[0].Backup = "backup-service"
	ts.Spec.Upstreams[0].BackupPort = createPointerFromUInt16(5505)

	tsv := createTransportServerValidator()

	err := tsv.ValidateTransportServer(&ts)
	if err != nil {
		t.Error(err)
	}
}

func TestValidateTransportServer_FailsOnMissingBackupName(t *testing.T) {
	t.Parallel()

	ts := makeTransportServer()
	// backup name not created, it's nil
	ts.Spec.Upstreams[0].BackupPort = createPointerFromUInt16(5505)

	tsv := createTransportServerValidator()

	err := tsv.ValidateTransportServer(&ts)
	if err == nil {
		t.Error("want error on missing backup name")
	}
}

func TestValidateTransportServer_FailsOnMissingBackupPort(t *testing.T) {
	t.Parallel()

	ts := makeTransportServer()
	ts.Spec.Upstreams[0].Backup = "backup-service-ts"
	// backup port not created, it's nil

	tsv := createTransportServerValidator()

	err := tsv.ValidateTransportServer(&ts)
	if err == nil {
		t.Error("want error on missing backup port")
	}
}

func TestValidateTransportServer_FailsOnNotSupportedLBMethodForBackup(t *testing.T) {
	t.Parallel()

	notSupportedLBMethods := []string{"hash", "hash_ip", "random", "random two least"}
	for _, lbMethod := range notSupportedLBMethods {
		lbMethod := lbMethod
		t.Run(lbMethod, func(t *testing.T) {
			t.Parallel()

			ts := makeTransportServer()
			ts.Spec.Upstreams[0].Backup = "backup-service"
			ts.Spec.Upstreams[0].BackupPort = createPointerFromUInt16(5505)
			ts.Spec.Upstreams[0].LoadBalancingMethod = lbMethod

			tsv := createTransportServerValidator()
			err := tsv.ValidateTransportServer(&ts)
			if err == nil {
				t.Errorf("want err on not supported load balancing method: %q, got nil", lbMethod)
			}
		})
	}
}

func TestValidateTransportServer_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	ts := conf_v1.TransportServer{
		Spec: conf_v1.TransportServerSpec{
			Listener: conf_v1.TransportServerListener{
				Name:     "tcp-listener",
				Protocol: "TCP",
			},
			Upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    5501,
				},
			},
			Action: nil,
		},
	}

	tsv := createTransportServerValidator()

	err := tsv.ValidateTransportServer(&ts)
	if err == nil {
		t.Errorf("ValidateTransportServer() returned no error for invalid input")
	}
}

func TestValidateTransportServerUpstreams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreams             []conf_v1.TransportServerUpstream
		expectedUpstreamNames sets.Set[string]
		msg                   string
	}{
		{
			upstreams:             []conf_v1.TransportServerUpstream{},
			expectedUpstreamNames: sets.Set[string]{},
			msg:                   "no upstreams",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    80,
				},
				{
					Name:    "upstream2",
					Service: "test-2",
					Port:    80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
				"upstream2": {},
			},
			msg: "2 valid upstreams",
		},
	}

	for _, test := range tests {
		allErrs, resultUpstreamNames := validateTransportServerUpstreams(test.upstreams, field.NewPath("upstreams"), true)
		if len(allErrs) > 0 {
			t.Fatalf("validateTransportServerUpstreams() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
		if !resultUpstreamNames.Equal(test.expectedUpstreamNames) {
			t.Errorf("validateTransportServerUpstreams() returned %v expected %v for the case of %s", resultUpstreamNames, test.expectedUpstreamNames, test.msg)
		}
	}
}

func TestValidateTransportServerUpstreams_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreams             []conf_v1.TransportServerUpstream
		expectedUpstreamNames sets.Set[string]
		msg                   string
	}{
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "@upstream1",
					Service: "test-1",
					Port:    80,
				},
			},
			expectedUpstreamNames: sets.Set[string]{},
			msg:                   "invalid upstream name",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "@test-1",
					Port:    80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid service",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    -80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid port",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    80,
				},
				{
					Name:    "upstream1",
					Service: "test-2",
					Port:    80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "duplicated upstreams",
		},
	}

	for _, test := range tests {
		allErrs, resultUpstreamNames := validateTransportServerUpstreams(test.upstreams, field.NewPath("upstreams"), true)
		if len(allErrs) == 0 {
			t.Fatalf("validateTransportServerUpstreams() returned no errors for the case of %s", test.msg)
		}
		if !resultUpstreamNames.Equal(test.expectedUpstreamNames) {
			t.Errorf("validateTransportServerUpstreams() returned %v expected %v for the case of %s", resultUpstreamNames, test.expectedUpstreamNames, test.msg)
		}
	}
}

func TestValidateTransportServerHost(t *testing.T) {
	t.Parallel()
	validCases := []struct {
		host                     string
		isTLSPassthroughListener bool
		protocol                 string
		tls                      *conf_v1.TransportServerTLS
	}{
		{
			host:                     "",
			isTLSPassthroughListener: false,
			protocol:                 "TCP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},

		{
			host:                     "nginx.org",
			isTLSPassthroughListener: false,
			protocol:                 "TCP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
	}

	for _, test := range validCases {
		allErrs := validateTransportServerHost(test.host, field.NewPath("host"), test.isTLSPassthroughListener, test.protocol, test.tls)
		if len(allErrs) > 0 {
			t.Errorf("validateTransportServerHost(%q, %v) returned errors %v for valid input", test.host, test.isTLSPassthroughListener, allErrs)
		}
	}

	invalidCases := []struct {
		host                     string
		isTLSPassthroughListener bool
		protocol                 string
		tls                      *conf_v1.TransportServerTLS
	}{
		// Invalid case: host is empty but isTLSPassthroughListener is true
		{
			host:                     "",
			isTLSPassthroughListener: true,
			protocol:                 "TLS_PASSTHROUGH",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
		{
			host:                     "nginx.org",
			isTLSPassthroughListener: false,
			protocol:                 "UDP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
		{
			host:                     "invalid host name",
			isTLSPassthroughListener: true,
			protocol:                 "TCP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
		{
			host:                     "nginx.org",
			isTLSPassthroughListener: true,
			protocol:                 "UDP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
		{
			host:                     "nginx.org",
			isTLSPassthroughListener: true,
			protocol:                 "TLS_PASSTHROUGH",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
	}

	for _, test := range invalidCases {
		allErrs := validateTransportServerHost(test.host, field.NewPath("host"), test.isTLSPassthroughListener, test.protocol, test.tls)
		if len(allErrs) == 0 {
			t.Errorf("validateTransportServerHost(%q, %v) returned no errors for invalid input", test.host, test.isTLSPassthroughListener)
		}
	}
}

func TestValidateTransportServerLoadBalancingMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method   string
		isPlus   bool
		hasError bool
	}{
		{
			method:   "",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "",
			isPlus:   true,
			hasError: false,
		},
		{
			method:   "hash",
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "hash ${remote_addr}",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "hash ${remote_addr}AAA",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   `hash ${remote_addr}"`,
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "hash ${invalid_var}",
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "hash not_var",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "hash ${remote_addr} toomany",
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "hash ${remote_addr} consistent",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "hash ${remote_addr} toomany consistent",
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "invalid",
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "least_conn",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "random",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "random two",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "random two least_conn",
			isPlus:   false,
			hasError: false,
		},
		{
			method:   "random two least_time",
			isPlus:   false,
			hasError: true,
		},
		{
			method:   "random two least_time",
			isPlus:   true,
			hasError: true,
		},
		{
			method:   "random two least_time=connect",
			isPlus:   true,
			hasError: true,
		},
	}

	for _, test := range tests {
		allErrs := validateLoadBalancingMethod(test.method, field.NewPath("method"), test.isPlus)
		if !test.hasError && len(allErrs) > 0 {
			t.Fatalf("validateLoadBalancingMethod(%q, %v) returned errors %v for valid input", test.method, test.isPlus, allErrs)
		}
		if test.hasError && len(allErrs) < 1 {
			t.Errorf("validateLoadBalancingMethod(%q, %v) failed to return an error for invalid input", test.method, test.isPlus)
		}
	}
}

func TestValidateTransportServerSnippet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		snippet           string
		isSnippetsEnabled bool
		expectError       bool
	}{
		{
			snippet:           "",
			isSnippetsEnabled: false,
			expectError:       false,
		},
		{
			snippet:           "deny 192.168.1.1;",
			isSnippetsEnabled: false,
			expectError:       true,
		},
		{
			snippet:           "deny 192.168.1.1;",
			isSnippetsEnabled: true,
			expectError:       false,
		},
	}

	for _, test := range tests {
		allErrs := validateSnippets(test.snippet, field.NewPath("serverSnippet"), test.isSnippetsEnabled)
		if test.expectError {
			if len(allErrs) < 1 {
				t.Errorf("validateSnippets(%q, %v) failed to return an error for invalid input", test.snippet, test.isSnippetsEnabled)
			}
		} else {
			if len(allErrs) > 0 {
				t.Errorf("validateSnippets(%q, %v) returned errors %v for valid input", test.snippet, test.isSnippetsEnabled, allErrs)
			}
		}
	}
}

func TestValidateTransportServerHost_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host                     string
		isTLSPassthroughListener bool
		protocol                 string
		tls                      *conf_v1.TransportServerTLS
	}{
		{
			host:                     "nginx.org",
			isTLSPassthroughListener: false,
			protocol:                 "TCP",
			tls:                      nil, // TLS and TLS.secret are required when not using tls passthrough and using a host
		},
		{
			host:                     "nginx.org",
			isTLSPassthroughListener: false,
			protocol:                 "TCP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "", // TLS and TLS.secret are required when not using tls passthrough and using a host
			},
		},
		{
			host:                     "",
			isTLSPassthroughListener: true,
			protocol:                 "TCP",
			tls: &conf_v1.TransportServerTLS{
				Secret: "secret-name",
			},
		},
	}

	for _, test := range tests {
		allErrs := validateTransportServerHost(test.host, field.NewPath("host"), test.isTLSPassthroughListener, test.protocol, test.tls)
		if len(allErrs) == 0 {
			t.Errorf("validateTransportServerHost(%q, %v) returned no errors for invalid input", test.host, test.isTLSPassthroughListener)
		}
	}
}

func TestValidateTransportListener(t *testing.T) {
	t.Parallel()
	tests := []struct {
		listener       *conf_v1.TransportServerListener
		tlsPassthrough bool
	}{
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tcp-listener",
				Protocol: "TCP",
			},
			tlsPassthrough: false,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tcp-listener",
				Protocol: "TCP",
			},
			tlsPassthrough: true,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tls-passthrough",
				Protocol: "TLS_PASSTHROUGH",
			},
			tlsPassthrough: true,
		},
	}

	for _, test := range tests {
		tsv := &TransportServerValidator{
			tlsPassthrough: test.tlsPassthrough,
		}

		allErrs := tsv.validateTransportListener(test.listener, field.NewPath("listener"))
		if len(allErrs) > 0 {
			t.Errorf("validateTransportListener() returned errors %v for valid input %+v when tlsPassthrough is %v", allErrs, test.listener, test.tlsPassthrough)
		}
	}
}

func TestValidateTransportListener_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		listener       *conf_v1.TransportServerListener
		tlsPassthrough bool
	}{
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tls-passthrough",
				Protocol: "TLS_PASSTHROUGH",
			},
			tlsPassthrough: false,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tls-passthrough",
				Protocol: "abc",
			},
			tlsPassthrough: true,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tls-passthrough",
				Protocol: "abc",
			},
			tlsPassthrough: false,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "abc",
				Protocol: "TLS_PASSTHROUGH",
			},
			tlsPassthrough: true,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "abc",
				Protocol: "TLS_PASSTHROUGH",
			},
			tlsPassthrough: false,
		},
	}

	for _, test := range tests {
		tsv := &TransportServerValidator{
			tlsPassthrough: test.tlsPassthrough,
		}

		allErrs := tsv.validateTransportListener(test.listener, field.NewPath("listener"))
		if len(allErrs) == 0 {
			t.Errorf("validateTransportListener() returned no errors for invalid input %+v when tlsPassthrough is %v", test.listener, test.tlsPassthrough)
		}
	}
}

func TestValidateIsPotentialTLSPassthroughListener(t *testing.T) {
	t.Parallel()
	tests := []struct {
		listener *conf_v1.TransportServerListener
		expected bool
	}{
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tls-passthrough",
				Protocol: "abc",
			},
			expected: true,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "abc",
				Protocol: "TLS_PASSTHROUGH",
			},
			expected: true,
		},
		{
			listener: &conf_v1.TransportServerListener{
				Name:     "tcp",
				Protocol: "TCP",
			},
			expected: false,
		},
	}

	for _, test := range tests {
		result := isPotentialTLSPassthroughListener(test.listener)
		if result != test.expected {
			t.Errorf("isPotentialTLSPassthroughListener(%+v) returned %v but expected %v", test.listener, result, test.expected)
		}
	}
}

func TestValidateListenerProtocol(t *testing.T) {
	t.Parallel()
	validProtocols := []string{
		"TCP",
		"UDP",
	}

	for _, p := range validProtocols {
		allErrs := validateListenerProtocol(p, field.NewPath("protocol"))
		if len(allErrs) > 0 {
			t.Errorf("validateListenerProtocol(%q) returned errors %v for valid input", p, allErrs)
		}
	}
}

func TestValidateTSUpstreamHealthChecks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		healthCheck *conf_v1.TransportServerHealthCheck
		msg         string
	}{
		{
			healthCheck: nil,
			msg:         "nil health check",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{},
			msg:         "non nil health check",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "30s",
				Jitter:   "5s",
				Port:     88,
				Interval: "10",
				Passes:   3,
				Fails:    4,
			},
			msg: "valid Health check",
		},
	}
	for _, test := range tests {
		allErrs := validateTSUpstreamHealthChecks(test.healthCheck, field.NewPath("healthCheck"))
		if len(allErrs) > 0 {
			t.Errorf("validateTSUpstreamHealthChecks() returned errors %v  for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateTSUpstreamHealthChecks_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		healthCheck *conf_v1.TransportServerHealthCheck
		msg         string
	}{
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "-30s",
				Jitter:   "5s",
				Port:     88,
				Interval: "10",
				Passes:   3,
				Fails:    4,
			},
			msg: "invalid timeout",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "30s",
				Jitter:   "5s",
				Port:     4000000000000000,
				Interval: "10",
				Passes:   3,
				Fails:    4,
			},
			msg: "invalid port number",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "30s",
				Jitter:   "5s",
				Port:     40,
				Interval: "10",
				Passes:   -3,
				Fails:    4,
			},
			msg: "invalid passes value",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "30s",
				Jitter:   "5s",
				Port:     40,
				Interval: "10",
				Passes:   3,
				Fails:    -4,
			},
			msg: "invalid fails value",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "30s",
				Jitter:   "5s",
				Port:     40,
				Interval: "ten",
				Passes:   3,
				Fails:    4,
			},
			msg: "invalid interval value",
		},
		{
			healthCheck: &conf_v1.TransportServerHealthCheck{
				Enabled:  true,
				Timeout:  "30s",
				Jitter:   "5sec",
				Port:     40,
				Interval: "10",
				Passes:   3,
				Fails:    4,
			},
			msg: "invalid jitter value",
		},
	}

	for _, test := range tests {
		allErrs := validateTSUpstreamHealthChecks(test.healthCheck, field.NewPath("healthCheck"))
		if len(allErrs) == 0 {
			t.Errorf("validateTSUpstreamHealthChecks() returned no error for invalid input %v", test.msg)
		}
	}
}

func TestValidateUpstreamParameters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		parameters *conf_v1.UpstreamParameters
		msg        string
	}{
		{
			parameters: nil,
			msg:        "nil parameters",
		},
		{
			parameters: &conf_v1.UpstreamParameters{},
			msg:        "Non-nil parameters",
		},
	}

	for _, test := range tests {
		allErrs := validateTransportServerUpstreamParameters(test.parameters, field.NewPath("upstreamParameters"), "UDP")
		if len(allErrs) > 0 {
			t.Errorf("validateTransportServerUpstreamParameters() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateSessionParameters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		parameters *conf_v1.SessionParameters
		msg        string
	}{
		{
			parameters: nil,
			msg:        "nil parameters",
		},
		{
			parameters: &conf_v1.SessionParameters{},
			msg:        "Non-nil parameters",
		},
		{
			parameters: &conf_v1.SessionParameters{
				Timeout: "60s",
			},
			msg: "valid parameters",
		},
	}

	for _, test := range tests {
		allErrs := validateSessionParameters(test.parameters, field.NewPath("sessionParameters"))
		if len(allErrs) > 0 {
			t.Errorf("validateSessionParameters() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateSessionParameters_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		parameters *conf_v1.SessionParameters
		msg        string
	}{
		{
			parameters: &conf_v1.SessionParameters{
				Timeout: "-1s",
			},
			msg: "invalid timeout",
		},
	}

	for _, test := range tests {
		allErrs := validateSessionParameters(test.parameters, field.NewPath("sessionParameters"))
		if len(allErrs) == 0 {
			t.Errorf("validateSessionParameters() returned no errors for invalid input: %v", test.msg)
		}
	}
}

func TestValidateUDPUpstreamParameter(t *testing.T) {
	t.Parallel()
	validInput := []struct {
		parameter *int
		protocol  string
	}{
		{
			parameter: nil,
			protocol:  "TCP",
		},
		{
			parameter: nil,
			protocol:  "UDP",
		},
		{
			parameter: createPointerFromInt(0),
			protocol:  "UDP",
		},
		{
			parameter: createPointerFromInt(1),
			protocol:  "UDP",
		},
	}

	for _, input := range validInput {
		allErrs := validateUDPUpstreamParameter(input.parameter, field.NewPath("parameter"), input.protocol)
		if len(allErrs) > 0 {
			t.Errorf("validateUDPUpstreamParameter(%v, %q) returned errors %v for valid input", input.parameter, input.protocol, allErrs)
		}
	}
}

func TestValidateUDPUpstreamParameter_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []struct {
		parameter *int
		protocol  string
	}{
		{
			parameter: createPointerFromInt(0),
			protocol:  "TCP",
		},
		{
			parameter: createPointerFromInt(-1),
			protocol:  "UDP",
		},
	}

	for _, input := range invalidInput {
		allErrs := validateUDPUpstreamParameter(input.parameter, field.NewPath("parameter"), input.protocol)
		if len(allErrs) == 0 {
			t.Errorf("validateUDPUpstreamParameter(%v, %q) returned no errors for invalid input", input.parameter, input.protocol)
		}
	}
}

func TestValidateTransportServerAction(t *testing.T) {
	t.Parallel()
	upstreamNames := map[string]sets.Empty{
		"test": {},
	}

	action := &conf_v1.TransportServerAction{
		Pass: "test",
	}

	allErrs := validateTransportServerAction(action, field.NewPath("action"), upstreamNames)
	if len(allErrs) > 0 {
		t.Errorf("validateTransportServerAction() returned errors %v for valid input", allErrs)
	}
}

func TestValidateTransportServerAction_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	upstreamNames := map[string]sets.Empty{}

	tests := []struct {
		action *conf_v1.TransportServerAction
		msg    string
	}{
		{
			action: &conf_v1.TransportServerAction{
				Pass: "",
			},
			msg: "missing pass field",
		},
		{
			action: &conf_v1.TransportServerAction{
				Pass: "non-existing",
			},
			msg: "pass references a non-existing upstream",
		},
	}

	for _, test := range tests {
		allErrs := validateTransportServerAction(test.action, field.NewPath("action"), upstreamNames)
		if len(allErrs) == 0 {
			t.Errorf("validateTransportServerAction() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateMatchSend(t *testing.T) {
	t.Parallel()
	validInput := []string{
		"",
		"abc",
		"hello${world}",
		`hello\x00`,
	}

	for _, send := range validInput {
		allErrs := validateMatchSend(send, field.NewPath("send"))
		if len(allErrs) > 0 {
			t.Errorf("validateMatchSend(%q) returned errors %v for valid input", send, allErrs)
		}
	}
}

func TestValidateMatchSend_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []string{
		`hello"world`,
		`\x1x`,
	}

	for _, send := range invalidInput {
		allErrs := validateMatchSend(send, field.NewPath("send"))
		if len(allErrs) == 0 {
			t.Errorf("validateMatchSend(%q) returned no errors for invalid input", send)
		}
	}
}

func TestValidateHexString(t *testing.T) {
	t.Parallel()
	validInput := []string{
		"",
		"abc",
		`\x00`,
		`\xaa`,
		`\xaA`,
		`\xff`,
		`\xaaFFabc\x12`,
	}

	for _, s := range validInput {
		err := validateHexString(s)
		if err != nil {
			t.Errorf("validateHexString(%q) returned error %v for valid input", s, err)
		}
	}
}

func TestValidateHexString_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []string{
		`\x`,
		`\x1`,
		`\xax`,
		`\x\b`,
		`\xaaFFabc\xx12`, // \xx1 is invalid
	}

	for _, s := range invalidInput {
		err := validateHexString(s)
		if err == nil {
			t.Errorf("validateHexString(%q) returned no error for invalid input", s)
		}
	}
}

func TestValidateMatchExpect(t *testing.T) {
	t.Parallel()
	validInput := []string{
		``,
		`abc`,
		`abc\x00`,
		`~* 200 OK`,
		`~ 2\d\d`,
		`~`,
		`~*`,
	}

	for _, input := range validInput {
		allErrs := validateMatchExpect(input, field.NewPath("expect"))
		if len(allErrs) > 0 {
			t.Errorf("validateMatchExpect(%q) returned errors %v for valid input", input, allErrs)
		}
	}
}

func TestValidateMatchExpect_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []string{
		`hello"world`,
		`~hello"world`,
		`~*hello"world`,
		`\x1x`,
		`~\x1x`,
		`~*\x1x`,
		`~[{`,
		`~{1}`,
	}

	for _, input := range invalidInput {
		allErrs := validateMatchExpect(input, field.NewPath("expect"))
		if len(allErrs) == 0 {
			t.Errorf("validateMatchExpect(%q) returned no errors for invalid input", input)
		}
	}
}

func TestValidateTsTLS(t *testing.T) {
	t.Parallel()

	type testCase struct {
		tls              *conf_v1.TransportServerTLS
		isTLSPassthrough bool
		hostSpecified    bool
	}

	validTestCases := []testCase{
		{
			tls:              nil,
			isTLSPassthrough: false,
			hostSpecified:    false,
		},
		{
			tls: &conf_v1.TransportServerTLS{
				Secret: "my-secret",
			},
			isTLSPassthrough: false,
			hostSpecified:    true,
		},
		{
			tls: &conf_v1.TransportServerTLS{
				Secret: "my-secret",
			},
			isTLSPassthrough: false,
			hostSpecified:    false,
		},
	}

	for _, tc := range validTestCases {
		allErrs := validateTLS(tc.tls, tc.isTLSPassthrough, field.NewPath("tls"), tc.hostSpecified)
		if len(allErrs) > 0 {
			t.Errorf("validateTLS() returned errors %v for valid input %+v", allErrs, tc)
		}
	}
}

func TestValidateTsTLS_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidTLSes := []struct {
		tls              *conf_v1.TransportServerTLS
		isTLSPassthrough bool
		hostSpecified    bool
	}{
		{
			tls: &conf_v1.TransportServerTLS{
				Secret: "-",
			},
			isTLSPassthrough: false,
			hostSpecified:    true,
		},
		{
			tls: &conf_v1.TransportServerTLS{
				Secret: "a/b",
			},
			isTLSPassthrough: false,
			hostSpecified:    true,
		},
		{
			tls: &conf_v1.TransportServerTLS{
				Secret: "my-secret",
			},
			isTLSPassthrough: true,
			hostSpecified:    true,
		},
		{
			tls: &conf_v1.TransportServerTLS{
				Secret: "",
			},
			isTLSPassthrough: false,
			hostSpecified:    true,
		},
	}

	for _, test := range invalidTLSes {
		allErrs := validateTLS(test.tls, test.isTLSPassthrough, field.NewPath("tls"), test.hostSpecified)
		if len(allErrs) == 0 {
			t.Errorf("validateTLS() returned no errors for invalid input %v", test)
		}
	}
}
