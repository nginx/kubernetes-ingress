package wafbundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseS3URL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		url        string
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{name: "bucket + single-segment key", url: "s3://bucket/key.tgz", wantBucket: "bucket", wantKey: "key.tgz"},
		{name: "bucket + nested key", url: "s3://plm-bundles/policies/prod/v1.tgz", wantBucket: "plm-bundles", wantKey: "policies/prod/v1.tgz"},
		{name: "trailing slash trims to bucket", url: "s3://bucket/", wantErr: true},
		{name: "no key", url: "s3://bucket", wantErr: true},
		{name: "no bucket", url: "s3:///key.tgz", wantErr: true},
		{name: "wrong scheme https", url: "https://bucket/key.tgz", wantErr: true},
		{name: "wrong scheme empty", url: "//bucket/key.tgz", wantErr: true},
		{name: "empty url", url: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bucket, key, err := parseS3URL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseS3URL(%q) expected error, got bucket=%q key=%q", tc.url, bucket, key)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseS3URL(%q) unexpected error: %v", tc.url, err)
			}
			if bucket != tc.wantBucket || key != tc.wantKey {
				t.Errorf("parseS3URL(%q) = (%q,%q), want (%q,%q)", tc.url, bucket, key, tc.wantBucket, tc.wantKey)
			}
		})
	}
}

func TestS3ConfigValidate(t *testing.T) {
	t.Parallel()
	base := S3Config{
		Endpoint:        "http://seaweed:8333",
		AccessKeyID:     "admin",
		SecretAccessKey: "s3cret",
	}
	tests := []struct {
		name    string
		mutate  func(c *S3Config)
		wantErr bool
	}{
		{name: "valid minimal", mutate: func(*S3Config) {}},
		{name: "empty endpoint", mutate: func(c *S3Config) { c.Endpoint = "" }, wantErr: true},
		{name: "empty access key", mutate: func(c *S3Config) { c.AccessKeyID = "" }, wantErr: true},
		{name: "empty secret key", mutate: func(c *S3Config) { c.SecretAccessKey = "" }, wantErr: true},
		{name: "client cert without key rejected", mutate: func(c *S3Config) { c.ClientCert = []byte("x") }, wantErr: true},
		{name: "client key without cert rejected", mutate: func(c *S3Config) { c.ClientKey = []byte("x") }, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := base
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate() expected error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestS3FetcherFetchPolicyBundleSuccess(t *testing.T) {
	t.Parallel()
	body := []byte("bundle-bytes")
	wantSum := sha256Hex(body)
	srv := newTestS3Server(t, map[string][]byte{"/bundles/prod.tgz": body})
	defer srv.Close()

	f := NewS3Fetcher()
	res, err := f.FetchPolicyBundle(context.Background(), &Request{
		Type:             SourceTypePLM,
		URL:              "s3://bundles/prod.tgz",
		ExpectedChecksum: wantSum,
		Timeout:          2 * time.Second,
		RetryAttempts:    1,
	}, testS3Config(srv.URL))
	if err != nil {
		t.Fatalf("FetchPolicyBundle failed: %v", err)
	}
	if string(res.Data) != string(body) {
		t.Errorf("Data mismatch: got %q want %q", res.Data, body)
	}
	if res.Checksum != wantSum {
		t.Errorf("Checksum mismatch: got %q want %q", res.Checksum, wantSum)
	}
}

func TestS3FetcherFetchLogProfileBundleSuccess(t *testing.T) {
	t.Parallel()
	body := []byte("log-bundle")
	srv := newTestS3Server(t, map[string][]byte{"/bundles/log.tgz": body})
	defer srv.Close()

	f := NewS3Fetcher()
	res, err := f.FetchLogProfileBundle(context.Background(), &Request{
		Type:          SourceTypePLM,
		URL:           "s3://bundles/log.tgz",
		Timeout:       2 * time.Second,
		RetryAttempts: 1,
	}, testS3Config(srv.URL))
	if err != nil {
		t.Fatalf("FetchLogProfileBundle failed: %v", err)
	}
	if string(res.Data) != string(body) {
		t.Errorf("Data mismatch: got %q want %q", res.Data, body)
	}
}

func TestS3FetcherSHAMismatchIsNonTransient(t *testing.T) {
	t.Parallel()
	body := []byte("real-bytes")

	// Track request count to prove retry did NOT happen for a non-transient error.
	var reqCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewS3Fetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{
		Type:             SourceTypePLM,
		URL:              "s3://bundles/prod.tgz",
		ExpectedChecksum: "0000000000000000000000000000000000000000000000000000000000000000",
		Timeout:          2 * time.Second,
		RetryAttempts:    3,
	}, testS3Config(srv.URL))
	if err == nil {
		t.Fatalf("expected sha mismatch error, got nil")
	}
	if !isNonTransient(err) {
		t.Errorf("sha mismatch should be non-transient, got %v", err)
	}
	if got := reqCount.Load(); got != 1 {
		t.Errorf("expected 1 request (no retry on non-transient), got %d", got)
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("error message should mention sha256 mismatch, got %q", err)
	}
}

func TestS3FetcherRejectsNonPLMRequestType(t *testing.T) {
	t.Parallel()
	srv := newTestS3Server(t, nil)
	defer srv.Close()

	f := NewS3Fetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{
		Type:    SourceTypeHTTPS,
		URL:     "s3://bundles/x.tgz",
		Timeout: 2 * time.Second,
	}, testS3Config(srv.URL))
	if err == nil {
		t.Fatalf("expected non-transient error for wrong request type")
	}
	if !isNonTransient(err) {
		t.Errorf("wrong request type should be non-transient, got %v", err)
	}
}

func TestS3FetcherRejectsInvalidS3Config(t *testing.T) {
	t.Parallel()
	f := NewS3Fetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{
		Type:          SourceTypePLM,
		URL:           "s3://bundles/x.tgz",
		Timeout:       2 * time.Second,
		RetryAttempts: 1,
	}, S3Config{}) // zero-value fails Validate
	if err == nil {
		t.Fatalf("expected error for zero S3Config")
	}
	if !isNonTransient(err) {
		t.Errorf("invalid config should be non-transient, got %v", err)
	}
}

func TestS3FetcherOversizedBundleRejected(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, MaxBundleSize+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	f := NewS3Fetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{
		Type:          SourceTypePLM,
		URL:           "s3://bundles/big.tgz",
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
	}, testS3Config(srv.URL))
	if err == nil {
		t.Fatalf("expected oversize rejection, got nil")
	}
	if !isNonTransient(err) {
		t.Errorf("oversize should be non-transient, got %v", err)
	}
}

// --- helpers ---

func testS3Config(endpoint string) S3Config {
	return S3Config{
		Endpoint:        endpoint,
		AccessKeyID:     "admin",
		SecretAccessKey: "s3cret",
	}
}

// newTestS3Server serves path-style GetObject: "GET /<bucket>/<key>".
// Missing paths return 404 with a SeaweedFS-shaped XML body.
func newTestS3Server(t *testing.T, objects map[string][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, ok := objects[r.URL.Path]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
