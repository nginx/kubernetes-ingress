package configs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestBundleFetcher_FetchNow_Downloads(t *testing.T) {
	t.Parallel()

	bundleContent := []byte("fake-bundle-content-v1")
	etag := `"v1"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		w.Write(bundleContent) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	localPath, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("FetchNow() returned error: %v", err)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if string(data) != string(bundleContent) {
		t.Errorf("got content %q, want %q", string(data), string(bundleContent))
	}
}

func TestBundleFetcher_ETag304(t *testing.T) {
	t.Parallel()

	etag := `"v1"`
	callCount := atomic.Int32{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bundle-data")) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	// First fetch should download
	_, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("first FetchNow() error: %v", err)
	}

	// Second fetch should get 304
	_, err = fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("second FetchNow() error: %v", err)
	}

	if callCount.Load() != 2 {
		t.Errorf("expected 2 server calls, got %d", callCount.Load())
	}
}

func TestBundleFetcher_ETagChange_TriggersUpdate(t *testing.T) {
	t.Parallel()

	currentEtag := atomic.Value{}
	currentEtag.Store(`"v1"`)
	currentContent := atomic.Value{}
	currentContent.Store("bundle-v1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := currentEtag.Load().(string)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(currentContent.Load().(string))) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	// Initial fetch
	localPath, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("initial FetchNow() error: %v", err)
	}

	// Change the remote bundle
	currentEtag.Store(`"v2"`)
	currentContent.Store("bundle-v2")

	// Fetch again — should get new content
	_, err = fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("second FetchNow() error: %v", err)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != "bundle-v2" {
		t.Errorf("got content %q, want %q", string(data), "bundle-v2")
	}
}

func TestBundleFetcher_FetchError_KeepsStaleBundle(t *testing.T) {
	t.Parallel()

	failMode := atomic.Bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("good-bundle")) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	// Initial successful fetch
	localPath, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("initial FetchNow() error: %v", err)
	}

	// Enable failure mode
	failMode.Store(true)

	// Fetch should return error but stale file remains
	_, err = fetcher.FetchNow(context.Background(), key)
	if err == nil {
		t.Fatal("expected error from failed fetch")
	}

	// Original file should still be intact
	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("reading stale file: %v", err)
	}
	if string(data) != "good-bundle" {
		t.Errorf("stale bundle corrupted: got %q, want %q", string(data), "good-bundle")
	}
}

func TestBundleFetcher_Unregister_CleansUpFile(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bundle-data")) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	localPath, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("FetchNow() error: %v", err)
	}

	// File should exist
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		t.Fatal("bundle file should exist before unregister")
	}

	fetcher.Unregister(key)

	// File should be removed
	if _, err := os.Stat(localPath); !os.IsNotExist(err) {
		t.Error("bundle file should be removed after unregister")
	}
}

func TestBundleFetcher_UnregisteredKey_ReturnsError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	_, err := fetcher.FetchNow(context.Background(), "non/existent/key")
	if err == nil {
		t.Error("expected error for unregistered key")
	}
}

func TestBundleFetcher_GetLocalPath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	tests := []struct {
		key      string
		url      string
		expected string
	}{
		{
			key:      "default/my-policy/policy",
			url:      "https://server.example.com/bundles/compiled_policy.tgz",
			expected: filepath.Join(tmpDir, "default-my-policy-policy.tgz"),
		},
		{
			key:      "prod/waf-pol/log-0",
			url:      "https://server.example.com/logs/my-log-profile.tgz",
			expected: filepath.Join(tmpDir, "prod-waf-pol-log-0.tgz"),
		},
	}

	for _, tt := range tests {
		fetcher.Register(tt.key, tt.url, nil, time.Minute, 0)
		got := fetcher.GetLocalPath(tt.key)
		if got != tt.expected {
			t.Errorf("GetLocalPath(%q) = %q, want %q", tt.key, got, tt.expected)
		}
	}
}

func TestBundleFetcher_GetLocalPath_Unregistered(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	got := fetcher.GetLocalPath("non/existent/key")
	if got != "" {
		t.Errorf("GetLocalPath for unregistered key = %q, want empty string", got)
	}
}

func TestBundleFetcher_PollLoop_CallsOnChange(t *testing.T) {
	t.Parallel()

	requestCount := atomic.Int32{}
	currentEtag := atomic.Value{}
	currentEtag.Store(`"v1"`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		etag := currentEtag.Load().(string)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bundle-" + etag)) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	updateCh := make(chan string, 10)
	fetcher := NewBundleFetcher(tmpDir, func(key string) {
		updateCh <- key
	})

	key := "default/my-policy/policy"
	// Very short poll interval for testing
	fetcher.Register(key, srv.URL, nil, 100*time.Millisecond, 0)

	// Initial fetch
	_, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("FetchNow() error: %v", err)
	}

	// Start polling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetcher.Start(ctx)

	// Wait for a few poll cycles with no change — should get 304s
	time.Sleep(350 * time.Millisecond)

	// Change the ETag — next poll should detect the change
	currentEtag.Store(`"v2"`)

	// Wait for the update callback.
	// Allow bundleReloadDelay (2s) + poll interval (100ms) + margin.
	select {
	case updatedKey := <-updateCh:
		if updatedKey != key {
			t.Errorf("onChange called with key %q, want %q", updatedKey, key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for onChange callback")
	}

	fetcher.Stop()
}

func TestBundleFetcher_AtomicWrite_NoPartialFiles(t *testing.T) {
	t.Parallel()

	largeContent := make([]byte, 1024*1024) // 1 MiB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		w.Write(largeContent) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	localPath, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("FetchNow() error: %v", err)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	if len(data) != len(largeContent) {
		t.Errorf("file size %d, want %d", len(data), len(largeContent))
	}

	// No temp files should remain
	entries, _ := os.ReadDir(tmpDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file %q not cleaned up", e.Name())
		}
	}
}

func TestBuildHTTPClient_WithMTLS(t *testing.T) {
	t.Parallel()

	// Generate a self-signed CA and client cert
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	secretData := map[string][]byte{
		"tls.crt": clientCertPEM,
		"tls.key": clientKeyPEM,
		"ca.crt":  caCertPEM,
	}

	client := buildHTTPClient(secretData)
	if client == nil {
		t.Fatal("buildHTTPClient returned nil")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("TLS config should not be nil")
	}

	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Errorf("expected 1 client cert, got %d", len(transport.TLSClientConfig.Certificates))
	}

	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs should be set when ca.crt is provided")
	}

	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("MinVersion should be TLS 1.2")
	}
}

func TestBuildHTTPClient_WithoutSecretData(t *testing.T) {
	t.Parallel()

	client := buildHTTPClient(nil)
	if client == nil {
		t.Fatal("buildHTTPClient returned nil")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	if len(transport.TLSClientConfig.Certificates) != 0 {
		t.Error("should have no client certs when secretData is nil")
	}

	if transport.TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs should be nil without ca.crt")
	}
}

func TestBundleFetcher_ReRegister_UpdatesTLSConfig(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bundle")) //nolint:errcheck
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	fetcher := NewBundleFetcher(tmpDir, nil)

	key := "default/my-policy/policy"

	// Register with no TLS
	fetcher.Register(key, srv.URL, nil, time.Minute, 0)

	// Re-register with same URL but different secret data — should not panic
	fetcher.Register(key, srv.URL, map[string][]byte{"tls.crt": {}, "tls.key": {}}, time.Minute, 0)

	// Should still be able to fetch
	_, err := fetcher.FetchNow(context.Background(), key)
	if err != nil {
		t.Fatalf("FetchNow() error after re-register: %v", err)
	}
}
