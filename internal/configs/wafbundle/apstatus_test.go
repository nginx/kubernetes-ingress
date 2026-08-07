package wafbundle

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// makeAPCR builds an unstructured object for the given kind. A nil status
// omits the status field entirely.
func makeAPCR(kind string, status map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "appprotect.f5.com/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      "test",
			"namespace": "plm",
		},
	}
	if status != nil {
		obj["status"] = status
	}
	return &unstructured.Unstructured{Object: obj}
}

func TestParseAPPolicyStatus(t *testing.T) {
	t.Parallel()
	runParseAPStatusTests(t, "APPolicy", func(obj *unstructured.Unstructured) (*BundleStatus, error) {
		s, err := ParseAPPolicyStatus(obj)
		if err != nil {
			return nil, err
		}
		return s.Bundle, nil
	})
}

func TestParseAPLogConfStatus(t *testing.T) {
	t.Parallel()
	runParseAPStatusTests(t, "APLogConf", func(obj *unstructured.Unstructured) (*BundleStatus, error) {
		s, err := ParseAPLogConfStatus(obj)
		if err != nil {
			return nil, err
		}
		return s.Bundle, nil
	})
}

func runParseAPStatusTests(t *testing.T, kind string, parse func(*unstructured.Unstructured) (*BundleStatus, error)) {
	t.Helper()
	tests := []struct {
		obj       *unstructured.Unstructured
		want      *BundleStatus
		name      string
		wantErr   string
		expectErr bool
	}{
		{
			name: "ready status with all fields",
			obj: makeAPCR(kind, map[string]any{
				"bundle": map[string]any{
					"state":              "ready",
					"location":           "s3://bundles/x.tgz",
					"sha256":             "deadbeef",
					"compilerVersion":    "1.0",
					"observedGeneration": int64(5),
				},
			}),
			want: &BundleStatus{
				State:              "ready",
				Location:           "s3://bundles/x.tgz",
				SHA256:             "deadbeef",
				CompilerVersion:    "1.0",
				ObservedGeneration: 5,
			},
		},
		{
			name: "pending status without location",
			obj: makeAPCR(kind, map[string]any{
				"bundle": map[string]any{"state": "pending"},
			}),
			want: &BundleStatus{State: "pending"},
		},
		{
			name: "status without bundle field yields nil bundle",
			obj:  makeAPCR(kind, map[string]any{}),
			want: nil,
		},
		{
			name:      "no status returns error",
			obj:       makeAPCR(kind, nil),
			expectErr: true,
			wantErr:   "has no status",
		},
		{
			name:      "wrong kind returns error",
			obj:       makeAPCR(otherAPKind(kind), map[string]any{"bundle": map[string]any{"state": "ready"}}),
			expectErr: true,
			wantErr:   "expected kind",
		},
		{
			name: "unknown fields are ignored",
			obj: makeAPCR(kind, map[string]any{
				"bundle": map[string]any{"state": "ready", "unknown": "x"},
				"extra":  "ignored",
			}),
			want: &BundleStatus{State: "ready"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parse(tc.obj)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bundleStatusEqual(got, tc.want) {
				t.Errorf("bundle mismatch: got %+v want %+v", got, tc.want)
			}
		})
	}
}

func otherAPKind(kind string) string {
	if kind == "APPolicy" {
		return "APLogConf"
	}
	return "APPolicy"
}

func bundleStatusEqual(a, b *BundleStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func TestBundleStatusIsReady(t *testing.T) {
	t.Parallel()
	tests := []struct {
		bundle *BundleStatus
		name   string
		want   bool
	}{
		{name: "nil is not ready", bundle: nil, want: false},
		{name: "state ready with location and sha256", bundle: &BundleStatus{State: "ready", Location: "s3://b/k", SHA256: "abc"}, want: true},
		{name: "state ready without location", bundle: &BundleStatus{State: "ready", SHA256: "abc"}, want: false},
		{name: "state ready without sha256", bundle: &BundleStatus{State: "ready", Location: "s3://b/k"}, want: false},
		{name: "state pending", bundle: &BundleStatus{State: "pending", Location: "s3://b/k", SHA256: "abc"}, want: false},
		{name: "state processing", bundle: &BundleStatus{State: "processing", Location: "s3://b/k", SHA256: "abc"}, want: false},
		{name: "state invalid", bundle: &BundleStatus{State: "invalid", Location: "s3://b/k", SHA256: "abc"}, want: false},
		{name: "empty state", bundle: &BundleStatus{Location: "s3://b/k", SHA256: "abc"}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.bundle.IsReady(); got != tc.want {
				t.Errorf("IsReady() = %v want %v", got, tc.want)
			}
		})
	}
}
