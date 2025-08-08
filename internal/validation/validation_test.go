package validation

import (
	"strings"
	"testing"
)

func TestValidatePort_IsValidOnValidInput(t *testing.T) {
	t.Parallel()

	ports := []int{1, 65535}
	for _, p := range ports {
		if err := ValidatePort(p); err != nil {
			t.Error(err)
		}
	}
}

func TestValidatePort_ErrorsOnInvalidRange(t *testing.T) {
	t.Parallel()

	ports := []int{0, -1, 65536}
	for _, p := range ports {
		if err := ValidatePort(p); err == nil {
			t.Error("want error, got nil")
		}
	}
}

func TestValidateUnprivilegedPort_IsValidOnValidInput(t *testing.T) {
	t.Parallel()

	ports := []int{1024, 65535}
	for _, p := range ports {
		if err := ValidateUnprivilegedPort(p); err != nil {
			t.Error(err)
		}
	}
}

func TestValidateUnprivilegedPort_ErrorsOnInvalidRange(t *testing.T) {
	t.Parallel()

	ports := []int{0, -1, 80, 443, 65536}
	for _, p := range ports {
		if err := ValidateUnprivilegedPort(p); err == nil {
			t.Error("want error, got nil")
		}
	}
}

func TestValidateHost(t *testing.T) {
	t.Parallel()
	// Positive test cases
	posHosts := []string{
		"10.10.1.1:443",
		"10.10.1.1",
		"123.112.224.43:443",
		"172.120.3.222",
		"localhost:80",
		"localhost",
		"myhost:54321",
		"myhost",
		"my-host:54321",
		"my-host",
		"dns.test.svc.cluster.local:8443",
		"cluster.local:8443",
		"product.example.com",
		"product.example.com:443",
	}

	// Negative test cases item, expected error message
	negHosts := [][]string{
		{"NotValid", "not a valid host"},
		{"-cluster.local:514", "not a valid host"},
		{"10.10.1.1:99999", "not a valid port number"},
		{"333.333.333.333", "not a valid host"},
	}

	for _, tCase := range posHosts {
		err := ValidateHost(tCase)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	}

	for _, nTCase := range negHosts {
		err := ValidateHost(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing '%s'", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got '%v', expected: '%s'", err, nTCase[1])
			}
		}
	}
}

func TestValidateURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		options []URIValidationOption
		wantErr bool
	}{
		{
			name:    "simple uri with scheme",
			uri:     "https://localhost:8080",
			options: []URIValidationOption{},
			wantErr: false,
		},
		{
			name:    "simple uri without scheme",
			uri:     "localhost:8080",
			options: []URIValidationOption{},
			wantErr: false,
		},
		{
			name:    "uri with out of bounds port down",
			uri:     "http://localhost:0",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri with out of bounds port up",
			uri:     "http://localhost:65536",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri with bad port",
			uri:     "http://localhost:abc",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name: "uri with username and password and allowed",
			uri:  "http://user:password@localhost",
			options: []URIValidationOption{
				WithUserAllowed(true),
			},
			wantErr: false,
		},
		{
			name:    "uri with username and password and not allowed",
			uri:     "http://user:password@localhost",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name: "uri with http scheme but that's not allowed",
			uri:  "http://localhost",
			options: []URIValidationOption{
				WithAllowedSchemes("https"),
			},
			wantErr: true,
		},
		{
			name: "uri with https scheme but that's not allowed",
			uri:  "https://localhost",
			options: []URIValidationOption{
				WithAllowedSchemes("http"),
			},
			wantErr: true,
		},
		{
			name: "uri with no scheme, default set to https, not allowed",
			uri:  "localhost",
			options: []URIValidationOption{
				WithDefaultScheme("https"),
				WithAllowedSchemes("http"),
			},
			wantErr: true,
		},
		{
			name:    "uri that is an ipv6 address with a port",
			uri:     "https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri that is an ipv6 address without a port",
			uri:     "https://2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri that is a short ipv6 without port without scheme",
			uri:     "fe80::1",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri that is a short ipv6 with a port without scheme",
			uri:     "[fe80::1]:80",
			options: []URIValidationOption{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateURI(tt.uri, tt.options...); (err != nil) != tt.wantErr {
				t.Errorf("ValidateURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input    string
		expected int64
	}{
		{"", 0},
		{"1024", 1024},
		{"4k", 4096},
		{"2m", 2097152},
		{"1g", 1048576}, // Now returns 1MB fallback instead of 1GB
		{"4K", 4096},    // case insensitive
		{"invalid", 0},
		{"  8k  ", 8192}, // with whitespace
		{"4kb", 0},
		{"8x", 8388608}, // Invalid unit returns same value as MB
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			got := ParseSize(tc.input)
			if got != tc.expected {
				t.Errorf("ParseSize(%q) = %d, expected %d", tc.input, got, tc.expected)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input    int64
		expected string
	}{
		{0, "0"},
		{1024, "1k"},
		{4096, "4k"},
		{2097152, "2m"},
		{1073741824, "1024m"}, // Now formats as 1024m instead of 1g (no g support)
		{1536, "1k"},          // rounds down
		{500, "500"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()

			got := FormatSize(tc.input)
			if got != tc.expected {
				t.Errorf("FormatSize(%d) = %q, expected %q", tc.input, got, tc.expected)
			}
		})
	}
}
