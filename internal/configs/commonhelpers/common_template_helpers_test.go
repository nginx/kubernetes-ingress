package commonhelpers

import (
	"bytes"
	"html/template"
	"testing"
)

var helperFunctions = template.FuncMap{
	"makeSecretPath": MakeSecretPath,
}

func TestMakeSecretPath(t *testing.T) {
	t.Parallel()

	tmpl := newMakeSecretPathTemplate(t)
	testCases := []struct {
		Secret   string
		Path     string
		Variable string
		Enabled  bool
		expected string
	}{
		{
			Secret:   "/etc/nginx/secret/thing.crt",
			Path:     "/etc/nginx/secret",
			Variable: "$secrets_path",
			Enabled:  true,
			expected: "$secrets_path/thing.crt",
		},
		{
			Secret:   "/etc/nginx/secret/thing.crt",
			Path:     "/etc/nginx/secret",
			Variable: "$secrets_path",
			Enabled:  false,
			expected: "/etc/nginx/secret/thing.crt",
		},
		{
			Secret:   "/etc/nginx/secret/thing.crt",
			expected: "/etc/nginx/secret/thing.crt",
		},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got '%v' but expected '%v'.", buf.String(), tc.expected)
		}
	}
}

func newMakeSecretPathTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{makeSecretPath .Secret .Path .Variable .Enabled}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func TestMakeProxyBuffers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		proxyBuffers        string
		proxyBufferSize     string
		proxyBusyBufferSize string
		expectedOutput      string
	}{
		{
			name:                "Only buffer-size set",
			proxyBuffers:        "",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffer_size 4k;\n\t\tproxy_buffers 4 4k;",
		},
		{
			name:                "Only buffers set",
			proxyBuffers:        "4 16k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 16k;",
		},
		{
			name:                "Both set correctly",
			proxyBuffers:        "4 16k",
			proxyBufferSize:     "8k",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 8k;",
		},
		{
			name:                "Correct configuration unchanged",
			proxyBuffers:        "8 4k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 8 4k;\n\t\tproxy_buffer_size 4k;",
		},
		{
			name:                "All empty",
			proxyBuffers:        "",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "",
		},
		{
			name:                "Buffer-size smaller than individual buffer size",
			proxyBuffers:        "4 1m",
			proxyBufferSize:     "512k",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 4 1m;\n\t\tproxy_buffer_size 512k;",
		},
		{
			name:                "Only busy buffer size set",
			proxyBuffers:        "",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "8k",
			expectedOutput:      "proxy_busy_buffers_size 8k;",
		},
		{
			name:                "All three parameters set",
			proxyBuffers:        "8 4k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "16k",
			expectedOutput:      "proxy_buffers 8 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 16k;",
		},
		{
			name:                "Busy buffer size too large gets corrected",
			proxyBuffers:        "4 4k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "20k", // larger than (4*4k - 4k = 12k)
			expectedOutput:      "proxy_buffers 4 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 12k;",
		},
		{
			name:                "Buffer size with busy buffer calculates minimum buffers",
			proxyBuffers:        "",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "20k", // needs (20k + 4k) / 4k = 6 buffers
			expectedOutput:      "proxy_buffer_size 4k;\n\t\tproxy_buffers 6 4k;\n\t\tproxy_busy_buffers_size 20k;",
		},
		{
			name:                "Buffer size with busy buffer calculates minimum buffers with existing buffers",
			proxyBuffers:        "1 2k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 2 2k;\n\t\tproxy_buffer_size 2k;\n\t\tproxy_busy_buffers_size 2k;",
		},
		{
			name:                "Single buffer corrected to minimum 2 buffers",
			proxyBuffers:        "1 4k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:                "Single buffer with explicit buffer size corrected",
			proxyBuffers:        "1 8k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 2 8k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 8k;",
		},
		{
			name:                "Single buffer with larger buffer size gets corrected",
			proxyBuffers:        "1 2k",
			proxyBufferSize:     "8k",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 2 8k;\n\t\tproxy_buffer_size 8k;\n\t\tproxy_busy_buffers_size 8k;",
		},
		{
			name:                "Zero buffers corrected to minimum 2",
			proxyBuffers:        "0 4k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:                "Single buffer with explicit busy buffer size",
			proxyBuffers:        "1 4k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "6k",
			expectedOutput:      "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:                "Valid configuration with minimum buffers unchanged",
			proxyBuffers:        "2 4k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;",
		},
		{
			name:                "Large buffer count unchanged",
			proxyBuffers:        "16 1k",
			proxyBufferSize:     "",
			proxyBusyBufferSize: "",
			expectedOutput:      "proxy_buffers 16 1k;\n\t\tproxy_buffer_size 1k;",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := MakeProxyBuffers(tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBufferSize)

			if got != tc.expectedOutput {
				t.Errorf("Input: buffers=%q, bufferSize=%q, busyBufferSize=%q\nGot:      %q\nExpected: %q",
					tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBufferSize, got, tc.expectedOutput)
			}
		})
	}
}

func TestValidateProxyBusyBufferSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		proxyBuffers        string
		proxyBufferSize     string
		proxyBusyBufferSize string
		expected            string
	}{
		{
			name:                "Valid busy buffer size unchanged",
			proxyBuffers:        "8 4k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "16k",
			expected:            "16k",
		},
		{
			name:                "Busy buffer too small gets corrected",
			proxyBuffers:        "8 4k",
			proxyBufferSize:     "8k",
			proxyBusyBufferSize: "2k", // less than max(4k, 8k) = 8k
			expected:            "8k",
		},
		{
			name:                "Busy buffer too large gets corrected",
			proxyBuffers:        "4 4k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "20k", // larger than (4*4k - 4k = 12k)
			expected:            "12k",
		},
		{
			name:                "Empty busy buffer size returns empty",
			proxyBuffers:        "8 4k",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "",
			expected:            "",
		},
		{
			name:                "Invalid proxy buffers format returns original",
			proxyBuffers:        "invalid",
			proxyBufferSize:     "4k",
			proxyBusyBufferSize: "8k",
			expected:            "8k",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := validateBusyBufferSize(tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBufferSize)

			if got != tc.expected {
				t.Errorf("Input: buffers=%q, bufferSize=%q, busyBufferSize=%q\nGot:      %q\nExpected: %q",
					tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBufferSize, got, tc.expected)
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
		{"1g", 1073741824},
		{"4K", 4096}, // case insensitive
		{"invalid", 0},
		{"  8k  ", 8192}, // with whitespace
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
		{1073741824, "1g"},
		{1536, "1k"}, // rounds down
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
