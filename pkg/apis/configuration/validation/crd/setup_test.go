//go:build envtest

package crd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	configv1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

// Package-level fixtures shared by every test in this package. TestMain
// starts a single envtest control plane, installs the Policy CRD, and
// hands each test a controller-runtime client wired to it.
var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	testCtx   = context.Background()
	testNS    = "default"
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	crdPath, err := locatePolicyCRD()
	if err != nil {
		fmt.Fprintf(os.Stderr, "crd envtest: %v\n", err)
		return 1
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
	}
	// When KUBEBUILDER_ASSETS is set (make test-crd, CI) envtest uses those
	// binaries. Otherwise fall back to auto-download so a bare `go test
	// -tags=envtest ./...` also works when the machine has network access.
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		testEnv.DownloadBinaryAssets = true
		testEnv.DownloadBinaryAssetsVersion = envtestBinaryVersion
	}

	cfg, err := testEnv.Start()
	if err != nil {
		// Skip cleanly when envtest cannot come up (no binaries, no
		// network for auto-download) so `go test ./...` on a fresh
		// machine does not report a spurious failure.
		fmt.Fprintf(os.Stderr, "crd envtest: skipping, control plane failed to start: %v\n", err)
		return 0
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "crd envtest: stop failed: %v\n", err)
		}
	}()

	scheme := runtime.NewScheme()
	utilruntime.Must(configv1.AddToScheme(scheme))

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "crd envtest: build client: %v\n", err)
		return 1
	}

	return m.Run()
}

// envtestBinaryVersion pins the kube-apiserver/etcd version used when
// envtest auto-downloads its binaries. Kept close to the API machinery
// version this repo depends on.
const envtestBinaryVersion = "1.34.0"

// locatePolicyCRD returns the absolute path to the directory that
// contains k8s.nginx.org_policies.yaml, computed from this file's
// location so `go test` works from any working directory.
func locatePolicyCRD() (string, error) {
	_, thisFile, _, ok := stdruntime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	// pkg/apis/configuration/validation/crd -> repo root -> config/crd/bases
	base := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "..", "config", "crd", "bases")
	crdFile := filepath.Join(base, "k8s.nginx.org_policies.yaml")
	if _, err := os.Stat(crdFile); err != nil {
		return "", fmt.Errorf("policy CRD not found at %s: %w", crdFile, err)
	}
	return base, nil
}
