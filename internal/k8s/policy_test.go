package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs/wafbundle"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

func TestBundleNeedsFetch(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		Logger: nl.LoggerFromContext(context.Background()),
	}

	dir := t.TempDir()
	bundle := []byte("compiled-bundle-bytes")
	sum := wafbundle.ComputeChecksum(bundle)

	existing := filepath.Join(dir, "existing.tgz")
	if err := os.WriteFile(existing, bundle, 0o600); err != nil {
		t.Fatalf("failed to write test bundle: %v", err)
	}
	missing := filepath.Join(dir, "missing.tgz")

	tests := []struct {
		name      string
		path      string
		plmStatus *wafbundle.BundleStatus
		want      bool
	}{
		{
			name: "non-PLM missing file needs fetch",
			path: missing,
			want: true,
		},
		{
			name: "non-PLM existing file does not need fetch",
			path: existing,
			want: false,
		},
		{
			name:      "PLM missing file needs fetch",
			path:      missing,
			plmStatus: &wafbundle.BundleStatus{SHA256: sum},
			want:      true,
		},
		{
			name:      "PLM matching checksum does not need fetch",
			path:      existing,
			plmStatus: &wafbundle.BundleStatus{SHA256: sum},
			want:      false,
		},
		{
			name:      "PLM changed checksum needs re-fetch",
			path:      existing,
			plmStatus: &wafbundle.BundleStatus{SHA256: "0000"},
			want:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := lbc.bundleNeedsFetch(tc.path, tc.plmStatus); got != tc.want {
				t.Errorf("bundleNeedsFetch(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
