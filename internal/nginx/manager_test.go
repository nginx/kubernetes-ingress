package nginx

import (
	"testing"

	"github.com/nginx/nginx-plus-go-client/v3/client"
)

// Helper functions to create pointers
func ptrInt(i int) *int    { return &i }
func ptrBool(b bool) *bool { return &b }

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
					MaxConns:    ptrInt(100),
					MaxFails:    ptrInt(3),
					Backup:      ptrBool(true),
					Down:        ptrBool(false),
					Weight:      ptrInt(10),
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
					MaxConns:    ptrInt(50),
					MaxFails:    ptrInt(2),
					Backup:      ptrBool(false),
					Down:        ptrBool(true),
					Weight:      ptrInt(5),
					Server:      "192.168.1.2:8080",
					FailTimeout: "20s",
					SlowStart:   "5s",
					Route:       "route2",
					Service:     "serviceB",
					ID:          1,
					Drain:       false,
				},
				{
					MaxConns:    ptrInt(150),
					MaxFails:    ptrInt(5),
					Backup:      ptrBool(true),
					Down:        ptrBool(false),
					Weight:      ptrInt(15),
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
					MaxFails:    ptrInt(4),
					Backup:      nil, // Should default to false
					Down:        ptrBool(true),
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
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
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
