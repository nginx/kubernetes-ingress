package k8s

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAddTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	ts := createTestTransportServer("transportserver", "tcp-7777", "TCP")

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	// Add TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportServer

	updatedTS := ts.DeepCopy()
	updatedTS.Generation++

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make TransportServer invalid

	invalidTS := updatedTS.DeepCopy()
	invalidTS.Generation++
	invalidTS.Spec.Upstreams = nil

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
			Error: `spec.action.pass: Not found: "myapp"`,
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(invalidTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerWithHost(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	secretName := "echo-secret"

	ts := createTestTransportServerWithHost("transportserver", "echo.example.com", "tcp-7777", secretName)

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	// Add TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportServer

	updatedTS := ts.DeepCopy()
	updatedTS.Generation++

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make TransportServer invalid

	invalidTS := updatedTS.DeepCopy()
	invalidTS.Generation++
	invalidTS.Spec.Upstreams = nil

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
			Error: `spec.action.pass: Not found: "myapp"`,
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(invalidTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: updatedTS,
			},
		},
	}

	changes, problems = configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerForTLSPassthrough(t *testing.T) {
	configuration := createTestConfiguration()

	ts := createTestTLSPassthroughTransportServer("transportserver", "foo.example.com")

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem

	// Add TransportServer

	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// DeleteTransportServer

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: ts,
			},
		},
	}

	changes, problems = configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestListenerFlip(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "tcp-8888",
			Port:     8888,
			Protocol: "TCP",
		},
	}
	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	ts := createTestTransportServer("transportserver", "tcp-7777", "TCP")

	// no problems are expected for all cases
	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	// Add TransportServer

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts,
			},
		},
	}

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportServer listener

	updatedListenerTS := ts.DeepCopy()
	updatedListenerTS.Generation++
	updatedListenerTS.Spec.Listener.Name = "tcp-8888"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: updatedListenerTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedListenerTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update TransportSever listener to TLS Passthrough

	updatedWithPassthroughTS := updatedListenerTS.DeepCopy()
	updatedWithPassthroughTS.Generation++
	updatedWithPassthroughTS.Spec.Listener.Name = "tls-passthrough"
	updatedWithPassthroughTS.Spec.Listener.Protocol = "TLS_PASSTHROUGH"
	updatedWithPassthroughTS.Spec.Host = "example.com"

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: updatedListenerTS,
			},
		},
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    0,
				TransportServer: updatedWithPassthroughTS,
			},
		},
	}

	changes, problems = configuration.AddOrUpdateTransportServer(updatedWithPassthroughTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddInvalidTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	ts := createTestTransportServer("transportserver", "", "TCP")

	expectedProblems := []ConfigurationProblem{
		{
			Object:  ts,
			IsError: true,
			Reason:  "Rejected",
			Message: "TransportServer default/transportserver was rejected with error: spec.listener.name: Required value",
		},
	}
	var expectedChanges []ResourceChange

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerWithIncorrectClass(t *testing.T) {
	configuration := createTestConfiguration()

	// Add TransportServer with incorrect class

	ts := createTestTLSPassthroughTransportServer("transportserver", "foo.example.com")
	ts.Spec.IngressClass = "someproxy"

	var expectedProblems []ConfigurationProblem
	var expectedChanges []ResourceChange

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class correct

	updatedTS := ts.DeepCopy()
	updatedTS.Generation++
	updatedTS.Spec.IngressClass = "nginx"

	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				TransportServer: updatedTS,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateTransportServer(updatedTS)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the class incorrect

	expectedChanges = []ResourceChange{
		{
			Op: Delete,
			Resource: &TransportServerConfiguration{
				TransportServer: updatedTS,
			},
		},
	}
	expectedProblems = nil

	changes, problems = configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestAddTransportServerWithNonExistingListener(t *testing.T) {
	configuration := createTestConfiguration()

	addOrUpdateGlobalConfiguration(t, configuration, []conf_v1.Listener{}, noChanges, noProblems)

	ts := createTestTransportServer("transportserver", "tcp-7777", "TCP")

	expectedProblems := []ConfigurationProblem{
		{
			Object:  ts,
			IsError: false,
			Reason:  "Rejected",
			Message: `Listener tcp-7777 doesn't exist`,
		},
	}
	var expectedChanges []ResourceChange

	changes, problems := configuration.AddOrUpdateTransportServer(ts)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteNonExistingTransportServer(t *testing.T) {
	configuration := createTestConfiguration()

	var expectedChanges []ResourceChange
	var expectedProblems []ConfigurationProblem

	changes, problems := configuration.DeleteTransportServer("default/transportserver")
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("DeleteTransportServer() returned unexpected result (-want +got):\n%s", diff)
	}
}

func createTestTransportServer(name string, listenerName string, listenerProtocol string) *conf_v1.TransportServer {
	return &conf_v1.TransportServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
			Generation:        1,
		},
		Spec: conf_v1.TransportServerSpec{
			Listener: conf_v1.TransportServerListener{
				Name:     listenerName,
				Protocol: listenerProtocol,
			},
			Upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:    "myapp",
					Service: "myapp-svc",
					Port:    1234,
				},
			},
			Action: &conf_v1.TransportServerAction{
				Pass: "myapp",
			},
		},
	}
}

func createTestTransportServerWithHost(name string, host string, listenerName string, secretName string) *conf_v1.TransportServer {
	ts := createTestTransportServer(name, listenerName, "TCP")
	ts.Spec.Host = host
	ts.Spec.TLS = &conf_v1.TransportServerTLS{Secret: secretName}

	return ts
}

func createTestTLSPassthroughTransportServer(name string, host string) *conf_v1.TransportServer {
	ts := createTestTransportServer(name, conf_v1.TLSPassthroughListenerName, conf_v1.TLSPassthroughListenerProtocol)
	ts.Spec.Host = host

	return ts
}

func TestGetTransportServerMetrics(t *testing.T) {
	t.Parallel()
	tsPass := createTestTLSPassthroughTransportServer("transportserver", "abc.example.com")
	tsTCP := createTestTransportServer("transportserver-tcp", "tcp-7777", "TCP")
	tsUDP := createTestTransportServer("transportserver-udp", "udp-7777", "UDP")

	tests := []struct {
		tses     []*conf_v1.TransportServer
		expected *TransportServerMetrics
		msg      string
	}{
		{
			tses: nil,
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 0,
				TotalTCP:            0,
				TotalUDP:            0,
			},
			msg: "no TransportServers",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsPass,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 1,
				TotalTCP:            0,
				TotalUDP:            0,
			},
			msg: "one TLSPassthrough TransportServer",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsTCP,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 0,
				TotalTCP:            1,
				TotalUDP:            0,
			},
			msg: "one TCP TransportServer",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsUDP,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 0,
				TotalTCP:            0,
				TotalUDP:            1,
			},
			msg: "one UDP TransportServer",
		},
		{
			tses: []*conf_v1.TransportServer{
				tsPass, tsTCP, tsUDP,
			},
			expected: &TransportServerMetrics{
				TotalTLSPassthrough: 1,
				TotalTCP:            1,
				TotalUDP:            1,
			},
			msg: "TLSPassthrough, TCP and UDP TransportServers",
		},
	}

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "udp-7777",
			Port:     7777,
			Protocol: "UDP",
		},
	}
	gc := createTestGlobalConfiguration(listeners)

	for _, test := range tests {
		configuration := createTestConfiguration()

		_, _, err := configuration.AddOrUpdateGlobalConfiguration(gc)
		if err != nil {
			t.Fatalf("AddOrUpdateGlobalConfiguration() returned unexpected error %v", err)
		}

		for _, ts := range test.tses {
			configuration.AddOrUpdateTransportServer(ts)
		}

		result := configuration.GetTransportServerMetrics()
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GetTransportServerMetrics() returned unexpected result for the case of %s (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestTransportServerListenerHostCollisions(t *testing.T) {
	configuration := createTestConfiguration()

	listeners := []conf_v1.Listener{
		{
			Name:     "tcp-7777",
			Port:     7777,
			Protocol: "TCP",
		},
		{
			Name:     "tcp-8888",
			Port:     8888,
			Protocol: "TCP",
		},
	}

	addOrUpdateGlobalConfiguration(t, configuration, listeners, noChanges, noProblems)

	// Create TransportServers with the same listener and host
	ts1 := createTestTransportServerWithHost("ts1", "example.com", "tcp-7777", "secret1")
	ts2 := createTestTransportServerWithHost("ts2", "example.com", "tcp-7777", "secret2") // same listener and host
	ts3 := createTestTransportServerWithHost("ts3", "example.org", "tcp-7777", "secret3") // different host
	ts4 := createTestTransportServer("ts4", "tcp-7777", "TCP")                            // No host same listener
	ts5 := createTestTransportServer("ts5", "tcp-7777", "TCP")                            // same as ts4 to induce error with empty host twice
	ts6 := createTestTransportServerWithHost("ts6", "example.com", "tcp-8888", "secret4") // different listener

	// Add ts1 to the configuration
	expectedChanges := []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts1,
			},
		},
	}
	changes, problems := configuration.AddOrUpdateTransportServer(ts1)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts1) returned unexpected result (-want +got):\n%s", diff)
	}
	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts1) returned problems %v", problems)
	}

	// Try to add ts2, should be rejected due to conflict
	changes, problems = configuration.AddOrUpdateTransportServer(ts2)
	expectedChanges = nil // No changes expected
	expectedProblems := []ConfigurationProblem{
		{
			Object:  ts2,
			IsError: false,
			Reason:  "Rejected",
			Message: "Listener tcp-7777 with host example.com is taken by another resource",
		},
	}

	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts2) returned unexpected changes (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts2) returned unexpected problems (-want +got):\n%s", diff)
	}

	// Add ts3 with a different host, should be accepted
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts3,
			},
		},
	}
	changes, problems = configuration.AddOrUpdateTransportServer(ts3)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts3) returned unexpected result (-want +got):\n%s", diff)
	}
	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts3) returned problems %v", problems)
	}

	// Add ts4 with no host, should be accepted
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    7777,
				TransportServer: ts4,
			},
		},
	}
	changes, problems = configuration.AddOrUpdateTransportServer(ts4)
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts4) returned unexpected result (-want +got):\n%s", diff)
	}
	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts4) returned problems %v", problems)
	}

	// Try to add ts5 with no host, should be rejected due to conflict
	changes, problems = configuration.AddOrUpdateTransportServer(ts5)
	expectedChanges = nil
	expectedProblems = []ConfigurationProblem{
		{
			Object:  ts5,
			IsError: false,
			Reason:  "Rejected",
			Message: "Listener tcp-7777 with host empty host is taken by another resource",
		},
	}

	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts5) returned unexpected changes (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedProblems, problems); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts5) returned unexpected problems (-want +got):\n%s", diff)
	}

	// Try to add ts6 with different listener, but same domain as initial ts, should be fine as different listener
	changes, problems = configuration.AddOrUpdateTransportServer(ts6)
	expectedChanges = []ResourceChange{
		{
			Op: AddOrUpdate,
			Resource: &TransportServerConfiguration{
				ListenerPort:    8888,
				TransportServer: ts6,
			},
		},
	}
	if diff := cmp.Diff(expectedChanges, changes); diff != "" {
		t.Errorf("AddOrUpdateTransportServer(ts6) returned unexpected changes (-want +got):\n%s", diff)
	}

	if len(problems) != 0 {
		t.Errorf("AddOrUpdateTransportServer(ts6) returned problems %v", problems)
	}
}
