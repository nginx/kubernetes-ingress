package version1

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
)

func TestParseProxySetHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
		want       []version2.Header
	}{
		{
			name:       "header with custom value",
			annotation: "abc:def",
			want:       []version2.Header{{Name: "abc", Value: "def"}},
		},
		{
			name:       "header without value derives $http_ default",
			annotation: "X-Forwarded-ABC",
			want:       []version2.Header{{Name: "X-Forwarded-ABC", Value: "$http_x_forwarded_abc"}},
		},
		{
			name:       "multiple headers comma-separated",
			annotation: "X-Forwarded-ABC,BVC: test",
			want: []version2.Header{
				{Name: "X-Forwarded-ABC", Value: "$http_x_forwarded_abc"},
				{Name: "BVC", Value: "test"},
			},
		},
		{
			name:       "whitespace is trimmed from name and value",
			annotation: "  X-Header  :  myvalue  ",
			want:       []version2.Header{{Name: "X-Header", Value: "myvalue"}},
		},
		{
			name:       "empty entries are skipped",
			annotation: "Header-1,,Header-2",
			want: []version2.Header{
				{Name: "Header-1", Value: "$http_header_1"},
				{Name: "Header-2", Value: "$http_header_2"},
			},
		},
		{
			name:       "empty annotation returns nil",
			annotation: "",
			want:       nil,
		},
		{
			name:       "commas only returns nil",
			annotation: ",,,",
			want:       nil,
		},
		{
			name:       "colon with no name is skipped",
			annotation: ": value",
			want:       nil,
		},
		{
			name:       "header with empty value after colon",
			annotation: "X-Header:",
			want:       []version2.Header{{Name: "X-Header", Value: ""}},
		},
		{
			name:       "value with colons preserved",
			annotation: "X-Header: val:with:colons",
			want:       []version2.Header{{Name: "X-Header", Value: "val:with:colons"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseProxySetHeaders(tc.annotation)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseProxySetHeaders(%q) mismatch (-want +got):\n%s", tc.annotation, diff)
			}
		})
	}
}

func TestMergeProxySetHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		masterAnnotation string
		minionAnnotation string
		want             []version2.Header
	}{
		{
			name:             "minion overrides master header of same name",
			masterAnnotation: "X-Forwarded-ABC: master",
			minionAnnotation: "X-Forwarded-ABC: minion",
			want:             []version2.Header{{Name: "X-Forwarded-ABC", Value: "minion"}},
		},
		{
			name:             "master fills in headers not defined by minion",
			masterAnnotation: "X-Master: masterval",
			minionAnnotation: "X-Minion: minionval",
			want: []version2.Header{
				{Name: "X-Minion", Value: "minionval"},
				{Name: "X-Master", Value: "masterval"},
			},
		},
		{
			name:             "only master annotation",
			masterAnnotation: "X-Header: val",
			minionAnnotation: "",
			want:             []version2.Header{{Name: "X-Header", Value: "val"}},
		},
		{
			name:             "only minion annotation",
			masterAnnotation: "",
			minionAnnotation: "X-Header: val",
			want:             []version2.Header{{Name: "X-Header", Value: "val"}},
		},
		{
			name:             "both empty returns nil",
			masterAnnotation: "",
			minionAnnotation: "",
			want:             nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := MergeProxySetHeaders(tc.masterAnnotation, tc.minionAnnotation)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("MergeProxySetHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseAddHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
		want       []version2.AddHeader
	}{
		{
			name:       "single header without always",
			annotation: "X-Frame-Options:DENY",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Frame-Options", Value: "DENY"}, Always: false}},
		},
		{
			name:       "single header with always flag",
			annotation: "X-Frame-Options:DENY:always",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Frame-Options", Value: "DENY"}, Always: true}},
		},
		{
			name:       "always flag is case-insensitive",
			annotation: "X-Header:val:ALWAYS",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Header", Value: "val"}, Always: true}},
		},
		{
			name:       "multiple headers comma-separated",
			annotation: "X-Frame-Options:DENY, X-Content-Type:nosniff",
			want: []version2.AddHeader{
				{Header: version2.Header{Name: "X-Frame-Options", Value: "DENY"}, Always: false},
				{Header: version2.Header{Name: "X-Content-Type", Value: "nosniff"}, Always: false},
			},
		},
		{
			name:       "mixed always and non-always",
			annotation: "X-Frame-Options:DENY:always, X-Content-Type:nosniff",
			want: []version2.AddHeader{
				{Header: version2.Header{Name: "X-Frame-Options", Value: "DENY"}, Always: true},
				{Header: version2.Header{Name: "X-Content-Type", Value: "nosniff"}, Always: false},
			},
		},
		{
			name:       "whitespace trimmed around name, value, and flag",
			annotation: "  X-Header  :  myvalue  :  always  ",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Header", Value: "myvalue"}, Always: true}},
		},
		{
			name:       "empty entries are skipped",
			annotation: "X-Header:val,,X-Other:val2",
			want: []version2.AddHeader{
				{Header: version2.Header{Name: "X-Header", Value: "val"}, Always: false},
				{Header: version2.Header{Name: "X-Other", Value: "val2"}, Always: false},
			},
		},
		{
			name:       "header with empty value",
			annotation: "X-Header:",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Header", Value: ""}, Always: false}},
		},
		{
			name:       "invalid always flag produces non-always (parser is permissive; validator rejects)",
			annotation: "X-Header:val:badFlag",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Header", Value: "val"}, Always: false}},
		},
		{
			name:       "empty annotation returns nil",
			annotation: "",
			want:       nil,
		},
		{
			name:       "commas only returns nil",
			annotation: ",,,",
			want:       nil,
		},
		{
			name:       "name-only entry treated as name with empty value",
			annotation: "X-Header",
			want:       []version2.AddHeader{{Header: version2.Header{Name: "X-Header", Value: ""}, Always: false}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseAddHeaders(tc.annotation)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseAddHeaders(%q) mismatch (-want +got):\n%s", tc.annotation, diff)
			}
		})
	}
}

func TestValidateAddHeaderName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid simple", input: "X-Frame-Options", wantErr: false},
		{name: "valid with numbers", input: "X-Custom-123", wantErr: false},
		{name: "space in name", input: "X Bad", wantErr: true},
		{name: "at sign", input: "X-He@der", wantErr: true},
		{name: "dollar sign", input: "$bad", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := ValidateAddHeaderName(tc.input)
			if tc.wantErr && len(msgs) == 0 {
				t.Errorf("ValidateAddHeaderName(%q): want error messages, got none", tc.input)
			}
			if !tc.wantErr && len(msgs) != 0 {
				t.Errorf("ValidateAddHeaderName(%q): want no messages, got %v", tc.input, msgs)
			}
		})
	}
}

func TestValidateAddHeaderValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantMsgs []string // substrings that must appear in the returned messages
	}{
		{name: "valid plain value", input: "DENY", wantMsgs: nil},
		{name: "valid escaped quote", input: `val\"ue`, wantMsgs: nil},
		{name: "dollar sign", input: "$nginx_var", wantMsgs: []string{"invalid character in header value: $"}},
		{name: "newline", input: "foo\nbar", wantMsgs: []string{"newline"}},
		{name: "carriage return", input: "foo\rbar", wantMsgs: []string{"carriage-return"}},
		{name: "unescaped double quote", input: `"unquoted"`, wantMsgs: []string{"must have all"}},
		{name: "trailing backslash", input: `value\`, wantMsgs: []string{"must have all"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := ValidateAddHeaderValue(tc.input)
			if len(tc.wantMsgs) == 0 {
				if len(msgs) != 0 {
					t.Errorf("ValidateAddHeaderValue(%q): want no messages, got %v", tc.input, msgs)
				}
				return
			}
			combined := strings.Join(msgs, " ")
			for _, want := range tc.wantMsgs {
				if !strings.Contains(combined, want) {
					t.Errorf("ValidateAddHeaderValue(%q): want message containing %q, got %v", tc.input, want, msgs)
				}
			}
		})
	}
}
