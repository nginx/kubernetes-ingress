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
		name                 string
		proxyBuffers         string
		proxyBufferSize      string
		proxyBusyBuffersSize string
		expectedOutput       string
	}{
		{
			name:                 "All empty",
			proxyBuffers:         "",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expectedOutput:       "",
		},
		{
			name:                 "Only buffer-size set",
			proxyBuffers:         "",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffer_size 4k;\n\t\tproxy_buffers 4 4k;",
		},
		{
			name:                 "Only buffers set",
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 16k;",
		},
		{
			name:                 "Both buffers and buffer-size set correctly",
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 4 16k;\n\t\tproxy_buffer_size 8k;",
		},
		{
			name:                 "Buffer-size smaller than individual buffer size",
			proxyBuffers:         "4 1m",
			proxyBufferSize:      "512k",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 4 1m;\n\t\tproxy_buffer_size 512k;",
		},
		{
			name:                 "Only busy buffer size set",
			proxyBuffers:         "",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "8k",
			expectedOutput:       "proxy_busy_buffers_size 8k;",
		},
		{
			name:                 "All three parameters set",
			proxyBuffers:         "8 4k",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "16k",
			expectedOutput:       "proxy_buffers 8 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 16k;",
		},
		{
			name:                 "Buffer size with busy buffer calculates minimum buffers",
			proxyBuffers:         "",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "20k", // needs (20k + 4k) / 4k = 6 buffers
			expectedOutput:       "proxy_buffer_size 4k;\n\t\tproxy_buffers 6 4k;\n\t\tproxy_busy_buffers_size 20k;",
		},
		{
			name:                 "Single buffer corrected to minimum count",
			proxyBuffers:         "1 2k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 2 2k;\n\t\tproxy_buffer_size 2k;\n\t\tproxy_busy_buffers_size 2k;",
		},
		{
			name:                 "Single buffer with larger buffer size gets corrected",
			proxyBuffers:         "1 2k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 2 8k;\n\t\tproxy_buffer_size 8k;\n\t\tproxy_busy_buffers_size 8k;",
		},
		{
			name:                 "Zero buffers corrected to minimum 2",
			proxyBuffers:         "0 4k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;\n\t\tproxy_busy_buffers_size 4k;",
		},
		{
			name:                 "Valid configuration with minimum buffers unchanged",
			proxyBuffers:         "2 4k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 2 4k;\n\t\tproxy_buffer_size 4k;",
		},
		{
			name:                 "Large buffer count unchanged",
			proxyBuffers:         "16 1k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expectedOutput:       "proxy_buffers 16 1k;\n\t\tproxy_buffer_size 1k;",
		},
	}

	for _, tc := range testCases {
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

	testCases := []struct {
		name                 string
		proxyBuffers         string
		proxyBufferSize      string
		proxyBusyBuffersSize string
		expected             string
	}{
		{
			proxyBuffers:         "",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expected:             "",
		},
		{
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "",
			expected:             "4 16k",
		},
		{
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "",
			expected:             "4 16k",
		},
		{
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "8k",
			expected:             "4 16k",
		},
		{
			proxyBuffers:         "4 16k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "12k",
			expected:             "4 16k",
		},
		{
			proxyBuffers:         "8 4k",
			proxyBufferSize:      "4k",
			proxyBusyBuffersSize: "16k",
			expected:             "8 4k",
		},
		{
			proxyBuffers:         "1 2k",
			proxyBufferSize:      "",
			proxyBusyBuffersSize: "20k", // larger than (4*4k - 4k = 12k)
			expected:             "4 4k",
		},
		{
			proxyBuffers:         "1 2k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "",
			expected:             "2 8k",
		},
		{
			proxyBuffers:         "1 2k",
			proxyBufferSize:      "8k",
			proxyBusyBuffersSize: "16k",
			expected:             "2 8k",
		},
	}

	for _, tc := range testCases {
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
