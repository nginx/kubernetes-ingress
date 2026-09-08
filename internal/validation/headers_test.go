package validation

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidateHeaderName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "simple", input: "X-Frame-Options"},
		{name: "with numbers", input: "X-Custom-123"},
		{name: "single character", input: "A"},
		{name: "space in name", input: "X Bad", wantErr: true},
		{name: "at sign", input: "X-He@der", wantErr: true},
		{name: "dollar sign", input: "$bad", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "directive terminator", input: "X-Bad; return 200", wantErr: true},
		{name: "comment", input: "X-Bad#comment", wantErr: true},
		{name: "quote", input: `X-Bad"`, wantErr: true},
		{name: "opening brace", input: "{X-Bad", wantErr: true},
		// Underscore and dot are legal RFC 9110 tchar characters that NGINX
		// itself accepts, but IsHTTPHeaderName rejects them. Broadening that is
		// a change in accepted configuration, not in structure, so these cases
		// record the current behavior rather than endorsing it.
		{name: "underscore", input: "X_Custom", wantErr: true},
		{name: "dot", input: "X.Custom", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := ValidateHeaderName(tc.input)
			if tc.wantErr && len(msgs) == 0 {
				t.Errorf("ValidateHeaderName(%q): want error messages, got none", tc.input)
			}
			if !tc.wantErr && len(msgs) != 0 {
				t.Errorf("ValidateHeaderName(%q): want no messages, got %v", tc.input, msgs)
			}
		})
	}
}

func TestSplitHeaderNameList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "single", input: "X-A", want: []string{"X-A"}},
		{name: "multiple", input: "X-A,X-B", want: []string{"X-A", "X-B"}},
		{name: "multiple with spaces", input: "X-A, X-B , X-C", want: []string{"X-A", "X-B", "X-C"}},
		{name: "surrounding whitespace", input: "\tX-A\n", want: []string{"X-A"}},
		{name: "empty entry preserved", input: "X-A,,X-B", want: []string{"X-A", "", "X-B"}},
		{name: "empty", input: "", want: []string{""}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := SplitHeaderNameList(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("SplitHeaderNameList(%q) mismatch (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestValidateHeaderNameList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantNames []string
		wantErr   bool
	}{
		{name: "single", input: "X-A", wantNames: []string{"X-A"}},
		{name: "multiple", input: "X-A,X-B", wantNames: []string{"X-A", "X-B"}},
		{name: "names are trimmed", input: "X-A, X-B", wantNames: []string{"X-A", "X-B"}},
		{name: "one invalid entry", input: "X-A,$bad", wantNames: []string{"X-A", "$bad"}, wantErr: true},
		{name: "trailing comma", input: "X-A,", wantNames: []string{"X-A", ""}, wantErr: true},
		{name: "empty entry", input: "X-A,,X-B", wantNames: []string{"X-A", "", "X-B"}, wantErr: true},
		{name: "directive terminator", input: "X-A,X-B; return 200", wantNames: []string{"X-A", "X-B; return 200"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			names, msgs := ValidateHeaderNameList(tc.input)
			if diff := cmp.Diff(tc.wantNames, names); diff != "" {
				t.Errorf("ValidateHeaderNameList(%q) names mismatch (-want +got):\n%s", tc.input, diff)
			}
			if tc.wantErr && len(msgs) == 0 {
				t.Errorf("ValidateHeaderNameList(%q): want error messages, got none", tc.input)
			}
			if !tc.wantErr && len(msgs) != 0 {
				t.Errorf("ValidateHeaderNameList(%q): want no messages, got %v", tc.input, msgs)
			}
		})
	}
}

func TestValidateRealIPHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "header name", input: "X-Forwarded-For"},
		{name: "proxy_protocol literal", input: "proxy_protocol"},
		// Only the exact literal is exempt from header-name rules; the
		// underscore would otherwise be rejected.
		{name: "proxy_protocol with suffix", input: "proxy_protocol_x", wantErr: true},
		{name: "directive terminator", input: "X-Real-IP; return 200", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := ValidateRealIPHeader(tc.input)
			if tc.wantErr && len(msgs) == 0 {
				t.Errorf("ValidateRealIPHeader(%q): want error messages, got none", tc.input)
			}
			if !tc.wantErr && len(msgs) != 0 {
				t.Errorf("ValidateRealIPHeader(%q): want no messages, got %v", tc.input, msgs)
			}
		})
	}
}
