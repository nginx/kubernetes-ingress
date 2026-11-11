package configs

import "testing"

func TestResolveProxyHTTPVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		configured  string
		appProtocol string
		want        string
	}{
		{
			name: "nothing configured leaves the directive unset",
			want: "",
		},
		{
			name:        "h2c appProtocol infers HTTP/2",
			appProtocol: "kubernetes.io/h2c",
			want:        "2",
		},
		{
			name:        "non-h2c appProtocol is ignored",
			appProtocol: "http",
			want:        "",
		},
		{
			name:        "https appProtocol is ignored",
			appProtocol: "https",
			want:        "",
		},
		{
			name:       "explicit 1.0 is used",
			configured: "1.0",
			want:       "1.0",
		},
		{
			name:       "explicit 1.1 is used",
			configured: "1.1",
			want:       "1.1",
		},
		{
			name:       "explicit 2 is used",
			configured: "2",
			want:       "2",
		},
		{
			name:        "explicit value wins over h2c appProtocol",
			configured:  "1.1",
			appProtocol: "kubernetes.io/h2c",
			want:        "1.1",
		},
		{
			name:        "explicit 2 agrees with h2c appProtocol",
			configured:  "2",
			appProtocol: "kubernetes.io/h2c",
			want:        "2",
		},
		{
			name:        "explicit 1.0 wins over h2c appProtocol",
			configured:  "1.0",
			appProtocol: "kubernetes.io/h2c",
			want:        "1.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := resolveProxyHTTPVersion(test.configured, test.appProtocol)
			if got != test.want {
				t.Errorf("resolveProxyHTTPVersion(%q, %q) = %q; want %q",
					test.configured, test.appProtocol, got, test.want)
			}
		})
	}
}
