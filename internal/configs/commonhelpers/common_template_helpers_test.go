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

	tests := []struct {
		name                 string
		proxyBuffers         string
		proxyBufferSize      string
		proxyBusyBuffersSize string
		expectedOutput       string
	}{
		{
			name:           "All empty",
			expectedOutput: "",
		},
		{
			name:            "buffer-size only",
			proxyBufferSize: "4k",
			expectedOutput:  "proxy_buffer_size 4k;\n\t\tproxy_buffers 4 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:           "buffers only",
			proxyBuffers:   "4 16k",
			expectedOutput: "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 16k;\n\t\tproxy_busy_buffers_size 16k;",
		},
		{
			name:            "Both buffers and buffer-size set ",
			proxyBuffers:    "4 16k",
			proxyBufferSize: "8k",
			expectedOutput:  "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 8k;\n\t\tproxy_busy_buffers_size 16k;",
		},
		{
			name:            "Invalid combination that should correct itself",
			proxyBuffers:    "8 1m",
			proxyBufferSize: "5m",
			expectedOutput:  "proxy_buffers 8 1m;\n\t\tproxy_buffer_size 5m;\n\t\tproxy_busy_buffers_size 5m;",
		},
		{
			name:            "Buffer-size smaller than individual buffer size",
			proxyBuffers:    "4 1m",
			proxyBufferSize: "512k",
			expectedOutput:  "proxy_buffers 4 1m;\n\t\tproxy_buffer_size 512k;\n\t\tproxy_busy_buffers_size 1m;",
		},
		{
			name:            "Minimum buffers configuration",
			proxyBuffers:    "2 4k",
			proxyBufferSize: "4k",
			expectedOutput:  "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:                 "All three parameters set",
			proxyBuffers:         "8 4k",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "16k",
			expectedOutput:       "proxy_buffers 8 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 16k;",
		},
		{
			name:                 "Busy buffer too large  - reduces in size",
			proxyBuffers:         "4 8k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "40k",
			expectedOutput:       "proxy_buffers 4 8k;\n\t\tproxy_buffer_size 8k;\n\t\tproxy_busy_buffers_size 24k;",
		},
		{
			name:                 "Busy buffer wrong format",
			proxyBuffers:         "4 4k",
			proxyBusyBuffersSize: "invalid",
			expectedOutput:       "proxy_buffers 4 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:           "Empty/zero values - corrected to minimum",
			proxyBuffers:   "0 4k",
			expectedOutput: "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:            "Extreme values - autocorrect",
			proxyBuffers:    "1000000 1k",
			proxyBufferSize: "999m",
			expectedOutput:  "proxy_buffers 1024 1k;\n\t\tproxy_buffer_size 511k;\n\t\tproxy_busy_buffers_size 511k;",
		},
		{
			name:            "Autocorrect buffer size and buffers",
			proxyBuffers:    "8 4k",
			proxyBufferSize: "64k",
			expectedOutput:  "proxy_buffers 8 4k;\n\t\tproxy_buffer_size 14k;\n\t\tproxy_busy_buffers_size 22k;",
		},
		{
			name:                 "Buffer size with busy buffer calculates minimum buffers",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "20k",
			expectedOutput:       "proxy_buffer_size 4k;\n\t\tproxy_buffers 6 4k;\n\t\tproxy_busy_buffers_size 20k;",
		},
		{
			name:           "Single buffer corrected to minimum count",
			proxyBuffers:   "1 2k",
			expectedOutput: "proxy_buffers 2 2k;\n\t\tproxy_buffer_size 2k;\n\t\tproxy_busy_buffers_size 2k;",
		},
		{
			name:            "Single buffer with larger buffer size gets corrected",
			proxyBuffers:    "1 2k",
			proxyBufferSize: "8k",
			expectedOutput:  "proxy_buffers 2 2k;\n\t\tproxy_buffer_size 2k;\n\t\tproxy_busy_buffers_size 2k;",
		},
		{
			name:           "Zero buffers corrected to minimum 2",
			proxyBuffers:   "0 4k",
			expectedOutput: "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:           "Large buffer count unchanged",
			proxyBuffers:   "16 1k",
			expectedOutput: "proxy_buffers 16 1k;\n\t\tproxy_buffer_size 1k;\n\t\tproxy_busy_buffers_size 3k;",
		},
		{
			name:                 "Only busy buffer size set",
			proxyBusyBuffersSize: "8k",
			expectedOutput:       "proxy_busy_buffers_size 8k;",
		},
		{
			name:            "Very small buffers with large buffer size",
			proxyBuffers:    "2 1k",
			proxyBufferSize: "2k",
			expectedOutput:  "proxy_buffers 2 1k;\n\t\tproxy_buffer_size 1k;\n\t\tproxy_busy_buffers_size 1k;",
		},
		{
			name:                 "Busy buffer exactly at limit",
			proxyBuffers:         "4 4k",
			proxyBusyBuffersSize: "12k",
			expectedOutput:       "proxy_buffers 4 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 12k;",
		},
		{
			name:                 "Busy buffer too small - gets adjusted",
			proxyBuffers:         "4 8k",
			proxyBufferSize:      "16k",
			proxyBusyBuffersSize: "4k",
			expectedOutput:       "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 16k;\n\t\tproxy_busy_buffers_size 16k;",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := MakeProxyBuffers(tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBuffersSize)

			if got != tc.expectedOutput {
				t.Errorf("Input: buffers=%q, bufferSize=%q, busyBufferSize=%q\nGot:      %q\nExpected: %q",
					tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBuffersSize, got, tc.expectedOutput)
			}
		})
	}
}

func TestValidateBusyBufferSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		proxyBuffers         string
		proxyBufferSize      string
		proxyBusyBuffersSize string
		expected             string
	}{
		{
			name:     "All empty",
			expected: "",
		},
		{
			name:         "No busy buffer size set",
			proxyBuffers: "4 16k",
			expected:     "",
		},
		{
			name:            "No busy buffer size with buffer size set",
			proxyBuffers:    "4 16k",
			proxyBufferSize: "8k",
			expected:        "",
		},
		{
			name:                 "Valid busy buffer size within limits",
			proxyBuffers:         "4 16k",
			proxyBusyBuffersSize: "32k",
			expected:             "32k",
		},
		{
			name:                 "Valid busy buffer size with buffer size",
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "32k",
			expected:             "32k",
		},
		{
			name:                 "Valid configuration",
			proxyBuffers:         "8 4k",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "16k",
			expected:             "16k",
		},
		{
			name:                 "Busy buffer too large, gets clamped",
			proxyBuffers:         "4 4k",
			proxyBusyBuffersSize: "20k",
			expected:             "12k",
		},
		{
			name:                 "Busy buffer too small, gets adjusted",
			proxyBuffers:         "4 8k",
			proxyBufferSize:      "16k",
			proxyBusyBuffersSize: "4k",
			expected:             "16k",
		},
		{
			name:                 "Buffer size larger than individual",
			proxyBuffers:         "4 8k",
			proxyBufferSize:      "16k",
			proxyBusyBuffersSize: "12k",
			expected:             "16k",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := validateBusyBufferSize(tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBuffersSize)

			if got != tc.expected {
				t.Errorf("Input: buffers=%q, bufferSize=%q, busyBufferSize=%q\nGot:      %q\nExpected: %q",
					tc.proxyBuffers, tc.proxyBufferSize, tc.proxyBusyBuffersSize, got, tc.expected)
			}
		})
	}
}
