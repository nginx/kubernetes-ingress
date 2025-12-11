package validation

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func createGlobalConfigurationValidator() *GlobalConfigurationValidator {
	return &GlobalConfigurationValidator{}
}

func TestValidateGlobalConfiguration(t *testing.T) {
	t.Parallel()
	globalConfiguration := conf_v1.GlobalConfiguration{
		Spec: conf_v1.GlobalConfigurationSpec{
			Listeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener",
					Port:     53,
					Protocol: "TCP",
				},
				{
					Name:     "udp-listener",
					Port:     53,
					Protocol: "UDP",
				},
			},
		},
	}

	gcv := createGlobalConfigurationValidator()

	err := gcv.ValidateGlobalConfiguration(&globalConfiguration)
	if err != nil {
		t.Errorf("ValidateGlobalConfiguration() returned error %v for valid input", err)
	}
}

func TestValidateListenerPort(t *testing.T) {
	t.Parallel()
	forbiddenListenerPorts := map[int]bool{
		1234: true,
	}

	gcv := &GlobalConfigurationValidator{
		forbiddenListenerPorts: forbiddenListenerPorts,
	}

	allErrs := gcv.validateListenerPort("sample-listener", 5555, field.NewPath("port"))
	if len(allErrs) > 0 {
		t.Errorf("validateListenerPort() returned errors %v for valid input", allErrs)
	}

	allErrs = gcv.validateListenerPort("sample-listener", 1234, field.NewPath("port"))
	if len(allErrs) == 0 {
		t.Errorf("validateListenerPort() returned no errors for invalid input")
	}
}

func TestValidateListeners(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
		{
			Name:     "test-listener-ip",
			IPv4:     "127.0.0.1",
			IPv6:     "::1",
			Port:     8080,
			Protocol: "HTTP",
		},
	}

	gcv := createGlobalConfigurationValidator()

	_, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if len(allErrs) > 0 {
		t.Errorf("validateListeners() returned errors %v for valid input", allErrs)
	}
}

func TestValidateListeners_FailsOnInvalidIP(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		listeners []conf_v1.Listener
	}{
		{
			name: "Invalid IPv4 IP",
			listeners: []conf_v1.Listener{
				{Name: "test-listener-1", IPv4: "267.0.0.1", Port: 8082, Protocol: "HTTP"},
			},
		},
		{
			name: "Invalid IPv4 IP with missing octet",
			listeners: []conf_v1.Listener{
				{Name: "test-listener-2", IPv4: "127.0.0", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "Invalid IPv6 IP",
			listeners: []conf_v1.Listener{
				{Name: "test-listener-3", IPv6: "1200::AB00::1234", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "Valid and invalid IPs",
			listeners: []conf_v1.Listener{
				{Name: "test-listener-4", IPv4: "192.168.1.1", IPv6: "2001:0db1234123123", Port: 8080, Protocol: "HTTP"},
				{Name: "test-listener-5", IPv4: "256.256.256.256", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8081, Protocol: "HTTP"},
			},
		},
		{
			name: "Valid IPv4 and Invalid IPv6",
			listeners: []conf_v1.Listener{
				{Name: "test-listener-6", IPv4: "192.168.1.1", IPv6: "2001::85a3::8a2e:370:7334", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "Invalid IPv4 and Valid IPv6",
			listeners: []conf_v1.Listener{
				{Name: "test-listener-8", IPv4: "300.168.1.1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
			},
		},
	}

	gcv := createGlobalConfigurationValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, allErrs := gcv.getValidListeners(tc.listeners, field.NewPath("listeners"))
			if len(allErrs) == 0 {
				t.Errorf("Expected errors for invalid IPs, but got none")
			} else {
				for _, err := range allErrs {
					t.Logf("Caught expected error: %v", err)
				}
			}
		})
	}
}

func TestValidateListeners_FailsOnPortProtocolConflictsSameIP(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		listeners []conf_v1.Listener
	}{
		{
			name: "Same port used with the same protocol",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", IPv6: "::1", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv4: "192.168.1.1", IPv6: "::1", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "Same port used with different protocols",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", IPv6: "::1", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv4: "192.168.1.1", Port: 8080, Protocol: "TCP"},
			},
		},
		{
			name: "Same port used with the same protocol (IPv6)",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "Same port used with different protocols (IPv6)",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv4: "192.168.1.1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "TCP"},
			},
		},
	}

	gcv := createGlobalConfigurationValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, allErrs := gcv.getValidListeners(tc.listeners, field.NewPath("listeners"))
			if len(allErrs) == 0 {
				t.Errorf("Expected errors for port/protocol conflicts, but got none")
			} else {
				for _, err := range allErrs {
					t.Logf("Caught expected error: %v", err)
				}
			}
		})
	}
}

func TestValidateListeners_PassesOnValidIPListeners(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		listeners []conf_v1.Listener
	}{
		{
			name: "Different Ports and IPs",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv4: "192.168.1.2", IPv6: "::1", Port: 9090, Protocol: "HTTP"},
			},
		},
		{
			name: "Same IPs, Same Protocol and Different Port",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv4: "192.168.1.1", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 9090, Protocol: "HTTP"},
			},
		},
		{
			name: "Different Types of IPs",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "UDP and HTTP Listeners with Same Port",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "127.0.0.1", Port: 8080, Protocol: "UDP"},
				{Name: "listener-2", IPv4: "127.0.0.1", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "HTTP Listeners with Same Port but different IPv4 and IPv6 ip addresses",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "127.0.0.2", IPv6: "::1", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv4: "127.0.0.1", Port: 8080, Protocol: "HTTP"},
			},
		},
		{
			name: "UDP and TCP Listeners with Same Port",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "127.0.0.1", Port: 8080, Protocol: "UDP"},
				{Name: "listener-2", IPv4: "127.0.0.1", Port: 8080, Protocol: "TCP"},
			},
		},
	}

	gcv := createGlobalConfigurationValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, allErrs := gcv.getValidListeners(tc.listeners, field.NewPath("listeners"))
			if len(allErrs) != 0 {
				t.Errorf("Unexpected errors for valid listeners: %v", allErrs)
			}
		})
	}
}

func TestValidateListeners_FailsOnMixedInvalidIPs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		listeners []conf_v1.Listener
	}{
		{
			name: "Valid IPv4 and Invalid IPv6",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "192.168.1.1", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv6: "2001::85a3::8a2e:370:7334", Port: 9090, Protocol: "TCP"},
			},
		},
		{
			name: "Invalid IPv4 and Valid IPv6",
			listeners: []conf_v1.Listener{
				{Name: "listener-1", IPv4: "300.168.1.1", Port: 8080, Protocol: "HTTP"},
				{Name: "listener-2", IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", Port: 9090, Protocol: "TCP"},
			},
		},
	}

	gcv := createGlobalConfigurationValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, allErrs := gcv.getValidListeners(tc.listeners, field.NewPath("listeners"))
			if len(allErrs) == 0 {
				t.Errorf("Expected errors for mixed invalid IPs, but got none")
			} else {
				for _, err := range allErrs {
					t.Logf("Caught expected error: %v", err)
				}
			}
		})
	}
}

func TestValidateListenersFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		listeners     []conf_v1.Listener
		wantListeners []conf_v1.Listener
		msg           string
	}{
		{
			listeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener",
					Port:     2201,
					Protocol: "TCP",
				},
				{
					Name:     "tcp-listener",
					Port:     2202,
					Protocol: "TCP",
				},
			},
			wantListeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener",
					Port:     2201,
					Protocol: "TCP",
				},
			},
			msg: "duplicated name",
		},
		{
			listeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener-1",
					Port:     2201,
					Protocol: "TCP",
				},
				{
					Name:     "tcp-listener-2",
					Port:     2201,
					Protocol: "TCP",
				},
			},
			wantListeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener-1",
					Port:     2201,
					Protocol: "TCP",
				},
			},
			msg: "duplicated port/protocol combination",
		},
		{
			listeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener-1",
					Port:     2201,
					Protocol: "TCP",
				},
				{
					Name:     "tcp-listener-2",
					Port:     2201,
					Protocol: "TCP",
				},
				{
					Name:     "udp-listener-3",
					Port:     2201,
					Protocol: "UDP",
				},
			},
			wantListeners: []conf_v1.Listener{
				{
					Name:     "tcp-listener-1",
					Port:     2201,
					Protocol: "TCP",
				},
				{
					Name:     "udp-listener-3",
					Port:     2201,
					Protocol: "UDP",
				},
			},
			msg: "duplicated port/protocol combination",
		},
	}

	gcv := createGlobalConfigurationValidator()

	for _, test := range tests {
		listeners, allErrs := gcv.getValidListeners(test.listeners, field.NewPath("listeners"))
		if diff := cmp.Diff(listeners, test.wantListeners); diff != "" {
			t.Errorf("getValidListeners() returned unexpected result for the case of %s:(-want +got), %s", test.msg, diff)
		}

		if len(allErrs) == 0 {
			t.Errorf("validateListeners() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateListener(t *testing.T) {
	t.Parallel()
	listener := conf_v1.Listener{
		Name:     "tcp-listener",
		Port:     53,
		Protocol: "TCP",
	}

	gcv := createGlobalConfigurationValidator()

	allErrs := gcv.validateListener(listener, field.NewPath("listener"))
	if len(allErrs) > 0 {
		t.Errorf("validateListener() returned errors %v for valid input", allErrs)
	}
}

func TestValidateListenerFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Listener conf_v1.Listener
		msg      string
	}{
		{
			Listener: conf_v1.Listener{
				Name:     "@",
				Port:     2201,
				Protocol: "TCP",
			},
			msg: "invalid name",
		},
		{
			Listener: conf_v1.Listener{
				Name:     "tcp-listener",
				Port:     -1,
				Protocol: "TCP",
			},
			msg: "invalid port",
		},
		{
			Listener: conf_v1.Listener{
				Name:     "name",
				Port:     2201,
				Protocol: "IP",
			},
			msg: "invalid protocol",
		},
		{
			Listener: conf_v1.Listener{
				Name:     "tls-passthrough",
				Port:     2201,
				Protocol: "TCP",
			},
			msg: "name of a built-in listener",
		},
	}

	gcv := createGlobalConfigurationValidator()

	for _, test := range tests {
		allErrs := gcv.validateListener(test.Listener, field.NewPath("listener"))
		if len(allErrs) == 0 {
			t.Errorf("validateListener() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestGeneratePortProtocolKey(t *testing.T) {
	t.Parallel()
	port := 53
	protocol := "UDP"

	expected := "53/UDP"

	result := generatePortProtocolKey(port, protocol)

	if result != expected {
		t.Errorf("generatePortProtocolKey(%d, %q) returned %q but expected %q", port, protocol, result, expected)
	}
}

func TestValidateListenerProtocol_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidProtocols := []string{
		"",
		"udp",
		"UDP ",
	}

	for _, p := range invalidProtocols {
		allErrs := validateListenerProtocol(p, field.NewPath("protocol"))
		if len(allErrs) == 0 {
			t.Errorf("validateListenerProtocol(%q) returned no errors for invalid input", p)
		}
	}
}

func TestValidateListenerProtocol_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	validProtocols := []string{
		"TCP",
		"HTTP",
		"UDP",
	}

	for _, p := range validProtocols {
		allErrs := validateListenerProtocol(p, field.NewPath("protocol"))
		if len(allErrs) != 0 {
			t.Errorf("validateListenerProtocol(%q) returned errors for valid input", p)
		}
	}
}

func TestValidateListenerProtocol_PassesOnHttpListenerUsingDiffPortToTCPAndUDPListenerWithTCPAndUDPDefinedFirst(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
		{
			Name:     "http-listener",
			Port:     63,
			Protocol: "HTTP",
		},
	}

	gcv := createGlobalConfigurationValidator()

	_, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if len(allErrs) > 0 {
		t.Errorf("validateListeners() returned errors %v for valid input", allErrs)
	}
}

func TestValidateListenerProtocol_PassesOnHttpListenerUsingDiffPortToTCPAndUDPListenerWithHTTPDefinedFirst(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "http-listener",
			Port:     63,
			Protocol: "HTTP",
		},
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
	}

	gcv := createGlobalConfigurationValidator()

	_, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if len(allErrs) > 0 {
		t.Errorf("validateListeners() returned errors %v for valid input", allErrs)
	}
}

func TestValidateListenerProtocol_FailsOnHttpListenerUsingSamePortAsTCPListener(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
	}
	wantListeners := []conf_v1.Listener{
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
	}

	gcv := createGlobalConfigurationValidator()

	listeners, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if diff := cmp.Diff(listeners, wantListeners); diff != "" {
		t.Errorf("getValidListeners() returned unexpected result: (-want +got):\n%s", diff)
	}
	if len(allErrs) == 0 {
		t.Errorf("validateListeners() returned no errors %v for invalid input", allErrs)
	}
}

func TestValidateListenerProtocol_PassesOnHttpListenerUsingSamePortAsUDPListener(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
	}
	wantListeners := []conf_v1.Listener{
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
	}
	gcv := createGlobalConfigurationValidator()
	listeners, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if diff := cmp.Diff(listeners, wantListeners); diff != "" {
		t.Errorf("getValidListeners() returned unexpected result: (-want +got):\n%s", diff)
	}
	if len(allErrs) != 0 {
		t.Errorf("validateListeners() returned errors %v invalid input", allErrs)
	}
}

func TestValidateListenerProtocol_FailsOnHttpListenerUsingSamePortAsTCP(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
	}
	wantListeners := []conf_v1.Listener{
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
	}
	gcv := createGlobalConfigurationValidator()
	listeners, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if diff := cmp.Diff(listeners, wantListeners); diff != "" {
		t.Errorf("getValidListeners() returned unexpected result: (-want +got):\n%s", diff)
	}
	if len(allErrs) != 1 {
		t.Errorf("getValidListeners() returned unexpected number of errors. Got %d, want 1", len(allErrs))
	}
}

func TestValidateListenerProtocol_FailsOnTCPListenerUsingSamePortAsHTTPListener(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
		{
			Name:     "tcp-listener",
			Port:     53,
			Protocol: "TCP",
		},
	}
	wantListeners := []conf_v1.Listener{
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
	}

	gcv := createGlobalConfigurationValidator()

	listeners, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if diff := cmp.Diff(listeners, wantListeners); diff != "" {
		t.Errorf("getValidListeners() returned unexpected result: (-want +got):\n%s", diff)
	}
	if len(allErrs) == 0 {
		t.Errorf("validateListeners() returned no errors %v for invalid input", allErrs)
	}
}

func TestValidateListenerProtocol_PassesOnUDPListenerUsingSamePortAsHTTPListener(t *testing.T) {
	t.Parallel()
	listeners := []conf_v1.Listener{
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
	}
	wantListeners := []conf_v1.Listener{
		{
			Name:     "http-listener",
			Port:     53,
			Protocol: "HTTP",
		},
		{
			Name:     "udp-listener",
			Port:     53,
			Protocol: "UDP",
		},
	}

	gcv := createGlobalConfigurationValidator()

	listeners, allErrs := gcv.getValidListeners(listeners, field.NewPath("listeners"))
	if diff := cmp.Diff(listeners, wantListeners); diff != "" {
		t.Errorf("getValidListeners() returned unexpected result: (-want +got):\n%s", diff)
	}
	if len(allErrs) != 0 {
		t.Errorf("validateListeners() returned errors %v for valid input", allErrs)
	}
}
