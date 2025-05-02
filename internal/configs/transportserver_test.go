package configs

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpstreamNamerForTransportServer(t *testing.T) {
	t.Parallel()
	transportServer := conf_v1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "tcp-app",
			Namespace: "default",
		},
	}
	upstreamNamer := newUpstreamNamerForTransportServer(&transportServer)
	upstream := "test"

	expected := "ts_default_tcp-app_test"

	result := upstreamNamer.GetNameForUpstream(upstream)
	if result != expected {
		t.Errorf("GetNameForUpstream() returned %s but expected %v", result, expected)
	}
}

func TestTransportServerExString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    *TransportServerEx
		expected string
	}{
		{
			input: &TransportServerEx{
				TransportServer: &conf_v1.TransportServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "test-server",
						Namespace: "default",
					},
				},
			},
			expected: "default/test-server",
		},
		{
			input:    &TransportServerEx{},
			expected: "TransportServerEx has no TransportServer",
		},
		{
			input:    nil,
			expected: "<nil>",
		},
	}

	for _, test := range tests {
		result := test.input.String()
		if result != test.expected {
			t.Errorf("TransportServerEx.String() returned %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateTransportServerConfigForTCPSnippets(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:    "tcp-app",
						Service: "tcp-app-svc",
						Port:    5001,
					},
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
				ServerSnippets: "deny  192.168.1.1;\nallow 192.168.1.0/24;",
				StreamSnippets: "limit_conn_zone $binary_remote_addr zone=addr:10m;",
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     listenerPort,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "60s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			DisableIPV6:              false,
			ServerSnippets:           []string{"deny  192.168.1.1;", "allow 192.168.1.0/24;"},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{"limit_conn_zone $binary_remote_addr zone=addr:10m;"},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfigForIPV6Disabled(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:    "tcp-app",
						Service: "tcp-app-svc",
						Port:    5001,
					},
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: true,
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     listenerPort,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "60s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			DisableIPV6:              true,
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfigForIPV6Disabled() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfigForTCP(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    3,
						FailTimeout: "40s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfigForTCPMaxConnections(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						MaxConns:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:        "10.0.0.20:5001",
						MaxFails:       3,
						FailTimeout:    "40s",
						MaxConnections: 3,
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			DisableIPV6:              false,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfigForTLSPassthrough(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tls-passthrough",
					Protocol: "TLS_PASSTHROUGH",
				},
				Host: "example.com",
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:    "tcp-app",
						Service: "tcp-app-svc",
						Port:    5001,
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout:      "30s",
					NextUpstream:        false,
					NextUpstreamTries:   0,
					NextUpstreamTimeout: "",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			TLSPassthrough:           true,
			UnixSocket:               "unix:/var/lib/nginx/passthrough-default_tcp-server.sock",
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "example.com",
			ServerName:               "",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		DisableIPV6:    false,
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func tsEx() TransportServerEx {
	return TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tls-passthrough",
					Protocol: "TLS_PASSTHROUGH",
				},
				Host: "example.com",
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:    "tcp-app",
						Service: "tcp-app-svc",
						Port:    5001,
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout:      "30s",
					NextUpstream:        false,
					NextUpstreamTries:   0,
					NextUpstreamTimeout: "",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints:   map[string][]string{},
		DisableIPV6: false,
	}
}

func TestGenerateTransportServerConfigForBackupServiceNGINXPlus(t *testing.T) {
	t.Parallel()

	transportServerEx := tsEx()
	transportServerEx.TransportServer.Spec.Upstreams[0].LoadBalancingMethod = "least_conn"
	transportServerEx.TransportServer.Spec.Upstreams[0].Backup = "backup-svc"
	transportServerEx.TransportServer.Spec.Upstreams[0].BackupPort = createPointerFromUInt16(5090)
	transportServerEx.Endpoints = map[string][]string{
		"default/tcp-app-svc:5001": {
			"10.0.0.20:5001",
		},
		"default/backup-svc:5090": {
			"clustertwo.corp.local:5090",
		},
	}

	listenerPort := 2020

	want := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				BackupServers: []version2.StreamUpstreamBackupServer{
					{
						Address: "clustertwo.corp.local:5090",
					},
				},
				LoadBalancingMethod: "least_conn",
			},
		},
		Server: version2.StreamServer{
			TLSPassthrough:           true,
			UnixSocket:               "unix:/var/lib/nginx/passthrough-default_tcp-server.sock",
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "example.com",
			ServerName:               "",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		DisableIPV6:    false,
		StreamSnippets: []string{},
	}

	p := transportServerConfigParams{
		transportServerEx:    &transportServerEx,
		listenerPort:         listenerPort,
		isPlus:               true,
		isResolverConfigured: false,
	}

	got, warnings := generateTransportServerConfig(p)
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateTransportServerConfig_DoesNotGenerateBackupOnMissingBackupName(t *testing.T) {
	t.Parallel()

	transportServerEx := tsEx()
	transportServerEx.TransportServer.Spec.Upstreams[0].LoadBalancingMethod = "least_conn"
	transportServerEx.TransportServer.Spec.Upstreams[0].BackupPort = createPointerFromUInt16(5090)
	transportServerEx.Endpoints = map[string][]string{
		"default/tcp-app-svc:5001": {
			"10.0.0.20:5001",
		},
	}

	listenerPort := 2020

	want := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				BackupServers:       nil,
				LoadBalancingMethod: "least_conn",
			},
		},
		Server: version2.StreamServer{
			TLSPassthrough:           true,
			UnixSocket:               "unix:/var/lib/nginx/passthrough-default_tcp-server.sock",
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "example.com",
			ServerName:               "",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		DisableIPV6:    false,
		StreamSnippets: []string{},
	}

	p := transportServerConfigParams{
		transportServerEx:    &transportServerEx,
		listenerPort:         listenerPort,
		isPlus:               true,
		isResolverConfigured: false,
	}

	got, warnings := generateTransportServerConfig(p)
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateTransportServerConfig_DoesNotGenerateBackupOnMissingBackupPort(t *testing.T) {
	t.Parallel()

	transportServerEx := tsEx()
	transportServerEx.TransportServer.Spec.Upstreams[0].LoadBalancingMethod = "least_conn"
	transportServerEx.TransportServer.Spec.Upstreams[0].Backup = "clustertwo.corp.local"
	transportServerEx.TransportServer.Spec.Upstreams[0].BackupPort = nil
	transportServerEx.Endpoints = map[string][]string{
		"default/tcp-app-svc:5001": {
			"10.0.0.20:5001",
		},
	}

	listenerPort := 2020

	want := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				BackupServers:       nil,
				LoadBalancingMethod: "least_conn",
			},
		},
		Server: version2.StreamServer{
			TLSPassthrough:           true,
			UnixSocket:               "unix:/var/lib/nginx/passthrough-default_tcp-server.sock",
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "example.com",
			ServerName:               "",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		DisableIPV6:    false,
		StreamSnippets: []string{},
	}

	p := transportServerConfigParams{
		transportServerEx:    &transportServerEx,
		listenerPort:         listenerPort,
		isPlus:               true,
		isResolverConfigured: false,
	}

	got, warnings := generateTransportServerConfig(p)
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateTransportServerConfig_DoesNotGenerateBackupOnMissingBackupPortAndName(t *testing.T) {
	t.Parallel()

	transportServerEx := tsEx()
	transportServerEx.TransportServer.Spec.Upstreams[0].LoadBalancingMethod = "least_conn"
	transportServerEx.TransportServer.Spec.Upstreams[0].Backup = ""
	transportServerEx.TransportServer.Spec.Upstreams[0].BackupPort = nil
	transportServerEx.Endpoints = map[string][]string{
		"default/tcp-app-svc:5001": {
			"10.0.0.20:5001",
		},
	}

	listenerPort := 2020

	want := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				BackupServers:       nil,
				LoadBalancingMethod: "least_conn",
			},
		},
		Server: version2.StreamServer{
			TLSPassthrough:           true,
			UnixSocket:               "unix:/var/lib/nginx/passthrough-default_tcp-server.sock",
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "example.com",
			ServerName:               "",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		DisableIPV6:    false,
		StreamSnippets: []string{},
	}

	p := transportServerConfigParams{
		transportServerEx:    &transportServerEx,
		listenerPort:         listenerPort,
		isPlus:               true,
		isResolverConfigured: false,
	}

	got, warnings := generateTransportServerConfig(p)
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateTransportServerConfigForUDP(t *testing.T) {
	t.Parallel()
	udpRequests := 1
	udpResponses := 5

	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "udp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "udp-listener",
					Protocol: "UDP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "udp-app",
						Service:     "udp-app-svc",
						Port:        5001,
						HealthCheck: &conf_v1.TransportServerHealthCheck{},
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					UDPRequests:         &udpRequests,
					UDPResponses:        &udpResponses,
					ConnectTimeout:      "30s",
					NextUpstream:        true,
					NextUpstreamTimeout: "",
					NextUpstreamTries:   0,
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "udp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/udp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_udp-server_udp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    1,
						FailTimeout: "10s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "udp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "udp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      true,
			StatusZone:               "udp-listener",
			ProxyRequests:            &udpRequests,
			ProxyResponses:           &udpResponses,
			ProxyPass:                "ts_default_udp-server_udp-app",
			Name:                     "udp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        true,
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyTimeout:             "10m",
			HealthCheck:              nil,
			DisableIPV6:              false,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfig_ProducesValidConfigOnValidInputForExternalNameServiceAndConfiguredResolver(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		ExternalNameSvcs: map[string]bool{"default/tcp-app-svc": true},
	}
	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    3,
						FailTimeout: "40s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
				Resolve:             true,
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           2020,
		isPlus:                 true,
		isResolverConfigured:   true,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Error(cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfig_GeneratesWarningOnNotConfiguredResolver(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		ExternalNameSvcs: map[string]bool{"default/tcp-app-svc": true},
	}
	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name:    "ts_default_tcp-server_tcp-app",
				Servers: nil,
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
				Resolve:             true,
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           2020,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) == 0 {
		t.Errorf("want warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Error(cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfig_UsesNotExistignSocketOnNotPlusAndNoEndpoints(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints:        map[string][]string{},
		ExternalNameSvcs: map[string]bool{"default/tcp-app-svc": true},
	}
	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     nginxNonExistingUnixSocket,
						MaxFails:    3,
						FailTimeout: "40s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
				Resolve:             true,
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL:                      &version2.StreamSSL{},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           2020,
		isPlus:                 false,
		isResolverConfigured:   true,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Error(cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfigForTCPWithTLSWithHost(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Host: "cafe.example.com",
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				TLS: &conf_v1.TransportServerTLS{
					Secret: "my-secret",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
		SecretRefs: map[string]*secrets.SecretReference{
			"default/my-secret": {
				Secret: &api_v1.Secret{
					Type: api_v1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-my-secret",
			},
		},
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    3,
						FailTimeout: "40s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ServerName:               "cafe.example.com",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL: &version2.StreamSSL{
				Enabled:        true,
				Certificate:    "/etc/nginx/secrets/default-my-secret",
				CertificateKey: "/etc/nginx/secrets/default-my-secret",
			},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateTransportServerConfigForTCPWithTLS(t *testing.T) {
	t.Parallel()
	transportServerEx := TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name:     "tcp-listener",
					Protocol: "TCP",
				},
				TLS: &conf_v1.TransportServerTLS{
					Secret: "my-secret",
				},
				Upstreams: []conf_v1.TransportServerUpstream{
					{
						Name:        "tcp-app",
						Service:     "tcp-app-svc",
						Port:        5001,
						MaxFails:    intPointer(3),
						FailTimeout: "40s",
					},
				},
				UpstreamParameters: &conf_v1.UpstreamParameters{
					ConnectTimeout: "30s",
					NextUpstream:   false,
				},
				SessionParameters: &conf_v1.SessionParameters{
					Timeout: "50s",
				},
				Action: &conf_v1.TransportServerAction{
					Pass: "tcp-app",
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tcp-app-svc:5001": {
				"10.0.0.20:5001",
			},
		},
		DisableIPV6: false,
		SecretRefs: map[string]*secrets.SecretReference{
			"default/my-secret": {
				Secret: &api_v1.Secret{
					Type: api_v1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-my-secret",
			},
		},
	}

	listenerPort := 2020

	expected := &version2.TransportServerConfig{
		Upstreams: []version2.StreamUpstream{
			{
				Name: "ts_default_tcp-server_tcp-app",
				Servers: []version2.StreamUpstreamServer{
					{
						Address:     "10.0.0.20:5001",
						MaxFails:    3,
						FailTimeout: "40s",
					},
				},
				UpstreamLabels: version2.UpstreamLabels{
					ResourceName:      "tcp-server",
					ResourceType:      "transportserver",
					ResourceNamespace: "default",
					Service:           "tcp-app-svc",
				},
				LoadBalancingMethod: "random two least_conn",
			},
		},
		Server: version2.StreamServer{
			Port:                     2020,
			UDP:                      false,
			StatusZone:               "tcp-listener",
			ProxyPass:                "ts_default_tcp-server_tcp-app",
			Name:                     "tcp-server",
			Namespace:                "default",
			ProxyConnectTimeout:      "30s",
			ProxyNextUpstream:        false,
			ProxyNextUpstreamTries:   0,
			ProxyNextUpstreamTimeout: "0s",
			ProxyTimeout:             "50s",
			HealthCheck:              nil,
			ServerSnippets:           []string{},
			SSL: &version2.StreamSSL{
				Enabled:        true,
				Certificate:    "/etc/nginx/secrets/default-my-secret",
				CertificateKey: "/etc/nginx/secrets/default-my-secret",
			},
		},
		StreamSnippets: []string{},
		StaticSSLPath:  "/etc/nginx/secret",
	}

	result, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      &transportServerEx,
		listenerPort:           listenerPort,
		isPlus:                 true,
		isResolverConfigured:   false,
		isDynamicReloadEnabled: false,
		staticSSLPath:          "/etc/nginx/secret",
	})
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	if !cmp.Equal(expected, result) {
		t.Errorf("generateTransportServerConfig() mismatch (-want +got):\n%s", cmp.Diff(expected, result))
	}
}

func TestGenerateUnixSocket(t *testing.T) {
	t.Parallel()
	transportServerEx := &TransportServerEx{
		TransportServer: &conf_v1.TransportServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "tcp-server",
				Namespace: "default",
			},
			Spec: conf_v1.TransportServerSpec{
				Listener: conf_v1.TransportServerListener{
					Name: "tls-passthrough",
				},
			},
		},
	}

	expected := "unix:/var/lib/nginx/passthrough-default_tcp-server.sock"

	result := generateUnixSocket(transportServerEx)
	if result != expected {
		t.Errorf("generateUnixSocket() returned %q but expected %q", result, expected)
	}

	transportServerEx.TransportServer.Spec.Listener.Name = "some-listener"
	expected = ""

	result = generateUnixSocket(transportServerEx)
	if result != expected {
		t.Errorf("generateUnixSocket() returned %q but expected %q", result, expected)
	}
}

func TestGenerateTransportServerHealthChecks(t *testing.T) {
	t.Parallel()
	upstreamName := "dns-tcp"
	generatedUpsteamName := "ts_namespace_name_dns-tcp"

	tests := []struct {
		upstreams     []conf_v1.TransportServerUpstream
		expectedHC    *version2.StreamHealthCheck
		expectedMatch *version2.Match
		msg           string
	}{
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name: "dns-tcp",
					HealthCheck: &conf_v1.TransportServerHealthCheck{
						Enabled:  false,
						Timeout:  "30s",
						Jitter:   "30s",
						Port:     80,
						Interval: "20s",
						Passes:   4,
						Fails:    5,
					},
				},
			},
			expectedHC:    nil,
			expectedMatch: nil,
			msg:           "health checks disabled",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name:        "dns-tcp",
					HealthCheck: &conf_v1.TransportServerHealthCheck{},
				},
			},
			expectedHC:    nil,
			expectedMatch: nil,
			msg:           "empty health check",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name: "dns-tcp",
					HealthCheck: &conf_v1.TransportServerHealthCheck{
						Enabled:  true,
						Timeout:  "40s",
						Jitter:   "30s",
						Port:     88,
						Interval: "20s",
						Passes:   4,
						Fails:    5,
					},
				},
			},
			expectedHC: &version2.StreamHealthCheck{
				Enabled:  true,
				Timeout:  "40s",
				Jitter:   "30s",
				Port:     88,
				Interval: "20s",
				Passes:   4,
				Fails:    5,
			},
			expectedMatch: nil,
			msg:           "valid health checks",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name: "dns-tcp",
					HealthCheck: &conf_v1.TransportServerHealthCheck{
						Enabled:  true,
						Timeout:  "40s",
						Jitter:   "30s",
						Port:     88,
						Interval: "20s",
						Passes:   4,
						Fails:    5,
					},
				},
				{
					Name: "dns-tcp-2",
					HealthCheck: &conf_v1.TransportServerHealthCheck{
						Enabled:  false,
						Timeout:  "50s",
						Jitter:   "60s",
						Port:     89,
						Interval: "10s",
						Passes:   9,
						Fails:    7,
					},
				},
			},
			expectedHC: &version2.StreamHealthCheck{
				Enabled:  true,
				Timeout:  "40s",
				Jitter:   "30s",
				Port:     88,
				Interval: "20s",
				Passes:   4,
				Fails:    5,
			},
			expectedMatch: nil,
			msg:           "valid 2 health checks",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name: "dns-tcp",
					Port: 90,
					HealthCheck: &conf_v1.TransportServerHealthCheck{
						Enabled: true,
					},
				},
			},
			expectedHC: &version2.StreamHealthCheck{
				Enabled:  true,
				Timeout:  "5s",
				Jitter:   "0s",
				Interval: "5s",
				Passes:   1,
				Fails:    1,
			},
			expectedMatch: nil,
			msg:           "return default values for health check",
		},
		{
			upstreams: []conf_v1.TransportServerUpstream{
				{
					Name: "dns-tcp",
					Port: 90,
					HealthCheck: &conf_v1.TransportServerHealthCheck{
						Enabled: true,
						Match: &conf_v1.TransportServerMatch{
							Send:   `GET / HTTP/1.0\r\nHost: localhost\r\n\r\n`,
							Expect: "~*200 OK",
						},
					},
				},
			},
			expectedHC: &version2.StreamHealthCheck{
				Enabled:  true,
				Timeout:  "5s",
				Jitter:   "0s",
				Interval: "5s",
				Passes:   1,
				Fails:    1,
				Match:    "match_ts_namespace_name_dns-tcp",
			},
			expectedMatch: &version2.Match{
				Name:                "match_ts_namespace_name_dns-tcp",
				Send:                `GET / HTTP/1.0\r\nHost: localhost\r\n\r\n`,
				ExpectRegexModifier: "~*",
				Expect:              "200 OK",
			},
			msg: "health check with match",
		},
	}

	for _, test := range tests {
		hc, match := generateTransportServerHealthCheck(upstreamName, generatedUpsteamName, test.upstreams)
		if diff := cmp.Diff(test.expectedHC, hc); diff != "" {
			t.Errorf("generateTransportServerHealthCheck() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedMatch, match); diff != "" {
			t.Errorf("generateTransportServerHealthCheck() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGenerateHealthCheckMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		match    *conf_v1.TransportServerMatch
		expected *version2.Match
		msg      string
	}{
		{
			match: &conf_v1.TransportServerMatch{
				Send:   "",
				Expect: "",
			},
			expected: &version2.Match{
				Name:                "match",
				Send:                "",
				ExpectRegexModifier: "",
				Expect:              "",
			},
			msg: "match with empty fields",
		},
		{
			match: &conf_v1.TransportServerMatch{
				Send:   "xxx",
				Expect: "yyy",
			},
			expected: &version2.Match{
				Name:                "match",
				Send:                "xxx",
				ExpectRegexModifier: "",
				Expect:              "yyy",
			},
			msg: "match with all fields and no regexp",
		},
		{
			match: &conf_v1.TransportServerMatch{
				Send:   "xxx",
				Expect: "~yyy",
			},
			expected: &version2.Match{
				Name:                "match",
				Send:                "xxx",
				ExpectRegexModifier: "~",
				Expect:              "yyy",
			},
			msg: "match with all fields and case sensitive regexp",
		},
		{
			match: &conf_v1.TransportServerMatch{
				Send:   "xxx",
				Expect: "~*yyy",
			},
			expected: &version2.Match{
				Name:                "match",
				Send:                "xxx",
				ExpectRegexModifier: "~*",
				Expect:              "yyy",
			},
			msg: "match with all fields and case insensitive regexp",
		},
	}
	name := "match"

	for _, test := range tests {
		result := generateHealthCheckMatch(test.match, name)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("generateHealthCheckMatch() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func intPointer(value int) *int {
	return &value
}

func TestGenerateTsSSLConfig(t *testing.T) {
	t.Parallel()
	validTests := []struct {
		inputTLS        *conf_v1.TransportServerTLS
		inputSecretRefs map[string]*secrets.SecretReference
		expectedSSL     *version2.StreamSSL
		msg             string
	}{
		{
			inputTLS:        nil,
			inputSecretRefs: map[string]*secrets.SecretReference{},
			expectedSSL:     &version2.StreamSSL{Enabled: false},
			msg:             "no TLS field",
		},
		{
			inputTLS: &conf_v1.TransportServerTLS{
				Secret: "secret",
			},
			inputSecretRefs: map[string]*secrets.SecretReference{
				"default/secret": {
					Secret: &api_v1.Secret{
						Type: api_v1.SecretTypeTLS,
					},
					Path: "secret.pem",
				},
			},
			expectedSSL: &version2.StreamSSL{
				Enabled:        true,
				Certificate:    "secret.pem",
				CertificateKey: "secret.pem",
			},
			msg: "normal case with HTTPS",
		},
	}

	invalidTests := []struct {
		inputTLS         *conf_v1.TransportServerTLS
		inputSecretRefs  map[string]*secrets.SecretReference
		expectedSSL      *version2.StreamSSL
		expectedWarnings Warnings
		msg              string
	}{
		{
			inputTLS: &conf_v1.TransportServerTLS{
				Secret: "missing",
			},
			inputSecretRefs: map[string]*secrets.SecretReference{
				"default/missing": {
					Error: errors.New("missing doesn't exist"),
				},
			},
			expectedSSL: &version2.StreamSSL{
				Enabled:        false,
				Certificate:    "",
				CertificateKey: "",
			},
			msg: "missing doesn't exist in the cluster with HTTPS",
		},
		{
			inputTLS: &conf_v1.TransportServerTLS{
				Secret: "mistyped",
			},
			inputSecretRefs: map[string]*secrets.SecretReference{
				"default/mistyped": {
					Secret: &api_v1.Secret{
						Type: secrets.SecretTypeCA,
					},
				},
			},
			expectedSSL: &version2.StreamSSL{
				Enabled:        false,
				Certificate:    "",
				CertificateKey: "",
			},
			msg: "wrong secret type",
		},
	}

	namespace := "default"

	for _, test := range validTests {
		// it is ok to use nil as the owner
		result, warnings := generateSSLConfig(nil, test.inputTLS, namespace, test.inputSecretRefs)
		if !reflect.DeepEqual(result, test.expectedSSL) {
			t.Errorf("generateSSLConfig() returned %v but expected %v for the case of %s", result, test.expectedSSL, test.msg)
		}
		if len(warnings) != 0 {
			t.Errorf("want no warnings, got %v", warnings)
		}
	}
	for _, test := range invalidTests {
		// it is ok to use nil as the owner
		result, warnings := generateSSLConfig(nil, test.inputTLS, namespace, test.inputSecretRefs)
		if !reflect.DeepEqual(result, test.expectedSSL) {
			t.Errorf("generateSSLConfig() returned %v but expected %v for the case of %s", result, test.expectedSSL, test.msg)
		}
		if len(warnings) == 0 {
			t.Errorf("want warnings, got %v", warnings)
		}
	}
}
