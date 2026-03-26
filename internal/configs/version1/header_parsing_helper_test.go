package version1

import (
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
