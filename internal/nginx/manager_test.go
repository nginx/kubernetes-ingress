package nginx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/metadata"
	"github.com/nginx/nginx-plus-go-client/v3/client"
)

func TestFormatUpdateServersInPlusLog(t *testing.T) {
	tests := []struct {
		name     string
		input    []client.UpstreamServer
		expected string
	}{
		{
			name:     "Empty input",
			input:    []client.UpstreamServer{},
			expected: "[]",
		},
		{
			name: "Single server with all fields set",
			input: []client.UpstreamServer{
				{
					MaxConns:    new(100),
					MaxFails:    new(3),
					Backup:      new(true),
					Down:        new(false),
					Weight:      new(10),
					Server:      "192.168.1.1:8080",
					FailTimeout: "30s",
					SlowStart:   "10s",
					Route:       "route1",
					Service:     "serviceA",
					ID:          0,
					Drain:       true,
				},
			},
			expected: "[{MaxConns:100 MaxFails:3 Backup:true Down:false Weight:10 Server:192.168.1.1:8080 FailTimeout:30s SlowStart:10s Route:route1 Service:serviceA ID:0 Drain:true}]",
		},
		{
			name: "Multiple servers",
			input: []client.UpstreamServer{
				{
					MaxConns:    new(50),
					MaxFails:    new(2),
					Backup:      new(false),
					Down:        new(true),
					Weight:      new(5),
					Server:      "192.168.1.2:8080",
					FailTimeout: "20s",
					SlowStart:   "5s",
					Route:       "route2",
					Service:     "serviceB",
					ID:          1,
					Drain:       false,
				},
				{
					MaxConns:    new(150),
					MaxFails:    new(5),
					Backup:      new(true),
					Down:        new(false),
					Weight:      new(15),
					Server:      "192.168.1.3:8080",
					FailTimeout: "40s",
					SlowStart:   "20s",
					Route:       "route3",
					Service:     "serviceC",
					ID:          2,
					Drain:       true,
				},
			},
			expected: "[{MaxConns:50 MaxFails:2 Backup:false Down:true Weight:5 Server:192.168.1.2:8080 FailTimeout:20s SlowStart:5s Route:route2 Service:serviceB ID:1 Drain:false} {MaxConns:150 MaxFails:5 Backup:true Down:false Weight:15 Server:192.168.1.3:8080 FailTimeout:40s SlowStart:20s Route:route3 Service:serviceC ID:2 Drain:true}]",
		},
		{
			name: "Servers with nil pointer fields",
			input: []client.UpstreamServer{
				{
					MaxConns:    nil, // Should default to 0
					MaxFails:    new(4),
					Backup:      nil, // Should default to false
					Down:        new(true),
					Weight:      nil, // Should default to 0
					Server:      "192.168.1.4:8080",
					FailTimeout: "",
					SlowStart:   "",
					Route:       "",
					Service:     "",
					ID:          0,
					Drain:       false,
				},
			},
			expected: "[{MaxConns:0 MaxFails:4 Backup:false Down:true Weight:0 Server:192.168.1.4:8080 FailTimeout: SlowStart: Route: Service: ID:0 Drain:false}]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := formatUpdateServersInPlusLog(tc.input)
			if actual != tc.expected {
				t.Errorf("FormatUpdateServersInPlusLog() = %v, want %v", actual, tc.expected)
			}
		})
	}
}

func TestGetOSCABundlePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "Debian default",
			input: `
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
			`,
			expected: "/etc/ssl/certs/ca-certificates.crt",
		},
		{
			name: "Alpine with quotes",
			input: `
NAME="Alpine Linux"
ID="alpine"
VERSION_ID=3.22.2
PRETTY_NAME="Alpine Linux v3.22"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
			`,
			expected: "/etc/ssl/cert.pem",
		},
		{
			name: "Alpine without quotes",
			input: `
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.9
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
			`,
			expected: "/etc/ssl/cert.pem",
		},
		{
			name: "RHEL8 with quotes",
			input: `
NAME="Red Hat Enterprise Linux"
VERSION="8.10 (Ootpa)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="8.10"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Red Hat Enterprise Linux 8.10 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:8::baseos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8"
BUG_REPORT_URL="https://issues.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 8"
REDHAT_BUGZILLA_PRODUCT_VERSION=8.10
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="8.10"
			`,
			expected: "/etc/pki/tls/certs/ca-bundle.crt",
		},
		{
			name: "RHEL9 with quotes",
			input: `
NAME="Red Hat Enterprise Linux"
VERSION="9.7 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.7"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.7 (Plow)"
ANSI_COLOR="0;31"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9"
BUG_REPORT_URL="https://issues.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 9"
REDHAT_BUGZILLA_PRODUCT_VERSION=9.7
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.7"
			`,
			expected: "/etc/pki/tls/certs/ca-bundle.crt",
		},
		{
			name:     "Unknown OS",
			input:    `ID="ubuntu"`,
			expected: "/etc/ssl/certs/ca-certificates.crt",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "/etc/ssl/certs/ca-certificates.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getOSCABundlePath(tt.input)
			if result != tt.expected {
				t.Errorf("want %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestExtractAgentConfigLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string // empty means the config file does not exist
		want    map[string]string
		wantErr bool
	}{
		{name: "missing file"},
		{name: "no labels key", content: "log:\n  level: info\n"},
		{
			name:    "mixed scalar labels",
			content: "labels:\n  display-name: my-nic\n  port: 8080\n  enabled: true\n  unset:\n",
			want:    map[string]string{"display-name": "my-nic", "port": "8080", "enabled": "true", "unset": ""},
		},
		{name: "invalid YAML", content: "labels: [invalid", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfgPath := filepath.Join(t.TempDir(), "nginx-agent.conf")
			if tc.content != "" {
				if err := os.WriteFile(cfgPath, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := extractAgentConfigLabels(cfgPath)
			if (err != nil) != tc.wantErr {
				t.Fatalf("extractAgentConfigLabels() error = %v, wantErr %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("extractAgentConfigLabels() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildAgentLabels(t *testing.T) {
	t.Parallel()

	meta := &metadata.Labels{
		ProductType:           "nic",
		ProductVersion:        "5.8.0",
		ClusterID:             "cluster-123",
		InstallationID:        "install-456",
		InstallationName:      "my-nic",
		InstallationNamespace: "default",
	}
	base := "--labels=product-type=nic,product-version=5.8.0,cluster-id=cluster-123,installation-id=install-456," +
		"installation-name=my-nic,installation-namespace=default,control-id=install-456,control-name=my-nic,control-namespace=default"

	tests := []struct {
		name         string
		configLabels map[string]string
		wantFlag     string
		wantSkipped  []string
	}{
		{name: "no config labels", wantFlag: base},
		{
			name:         "custom labels appended sorted",
			configLabels: map[string]string{"env": "staging", "display-name": "my-nic", "port": "8080"},
			wantFlag:     base + ",display-name=my-nic,env=staging,port=8080",
		},
		{
			name: "reserved and invalid labels skipped",
			configLabels: map[string]string{
				"cluster-id":   "override",
				"comma":        "a,b",
				"space":        "my nic",
				"empty":        "",
				"bad,key":      "x",
				"display-name": "my-nic",
			},
			wantFlag:    base + ",display-name=my-nic",
			wantSkipped: []string{"bad,key", "cluster-id", "comma", "empty", "space"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotFlag, gotSkipped := buildAgentLabels(meta, tc.configLabels)
			if gotFlag != tc.wantFlag {
				t.Errorf("buildAgentLabels() flag = %q, want %q", gotFlag, tc.wantFlag)
			}
			if diff := cmp.Diff(tc.wantSkipped, gotSkipped); diff != "" {
				t.Errorf("buildAgentLabels() skipped mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
