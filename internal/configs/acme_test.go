package configs

import "testing"

func TestIsACMEChallengeLocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		serviceName string
		want        bool
	}{
		{
			name:        "challenge path with solver service",
			path:        "/.well-known/acme-challenge/tok",
			serviceName: "cm-acme-http-solver-abcde",
			want:        true,
		},
		{
			name:        "exact match location",
			path:        "= /.well-known/acme-challenge/tok",
			serviceName: "cm-acme-http-solver-abcde",
			want:        true,
		},
		{
			name:        "challenge path prefix only",
			path:        "/.well-known/acme-challenge/",
			serviceName: "cm-acme-http-solver-abcde",
			want:        true,
		},
		{
			name:        "no trailing slash is not the RFC 8555 path",
			path:        "/.well-known/acme-challenge",
			serviceName: "cm-acme-http-solver-abcde",
			want:        false,
		},
		{
			name:        "non-solver service",
			path:        "/.well-known/acme-challenge/tok",
			serviceName: "tea-svc",
			want:        false,
		},
		{
			name:        "service name is only the solver prefix",
			path:        "/.well-known/acme-challenge/tok",
			serviceName: "cm-acme-http-solver-",
			want:        false,
		},
		{
			name:        "service name missing trailing dash",
			path:        "/.well-known/acme-challenge/tok",
			serviceName: "cm-acme-http-solver",
			want:        false,
		},
		{
			name:        "empty service name",
			path:        "/.well-known/acme-challenge/tok",
			serviceName: "",
			want:        false,
		},
		{
			name:        "non-challenge path",
			path:        "/tea",
			serviceName: "cm-acme-http-solver-abcde",
			want:        false,
		},
		{
			name:        "regex location",
			path:        "~ ^/.well-known/acme-challenge/",
			serviceName: "cm-acme-http-solver-abcde",
			want:        false,
		},
		{
			name:        "empty path and service name",
			path:        "",
			serviceName: "",
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := IsACMEChallengeLocation(tc.path, tc.serviceName)
			if got != tc.want {
				t.Errorf("IsACMEChallengeLocation(%q, %q) = %v, want %v", tc.path, tc.serviceName, got, tc.want)
			}
		})
	}
}
