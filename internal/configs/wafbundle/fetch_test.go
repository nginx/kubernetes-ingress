package wafbundle

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// HTTPS source tests
func TestFetchHTTPSDownloads(t *testing.T) {
	t.Parallel()
	content := []byte("bundle-content-v1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	req := &Request{Type: SourceTypeHTTPS, URL: srv.URL}
	result, err := f.FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != string(content) {
		t.Errorf("got %q, want %q", result.Data, content)
	}
	if result.ETag != `"v1"` {
		t.Errorf("got ETag %q, want %q", result.ETag, `"v1"`)
	}
}

func TestFetchHTTPS304NotModified(t *testing.T) {
	t.Parallel()
	callCount := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	req := &Request{Type: SourceTypeHTTPS, URL: srv.URL, ETag: `"v1"`}
	result, err := f.FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Unchanged {
		t.Error("expected Unchanged=true for 304")
	}
	if callCount.Load() != 1 {
		t.Errorf("expected 1 call, got %d", callCount.Load())
	}
}

func TestFetchHTTPS4xxNonTransient(t *testing.T) {
	t.Parallel()
	callCount := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	req := &Request{Type: SourceTypeHTTPS, URL: srv.URL, RetryAttempts: 3}
	_, err := f.FetchPolicyBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !isNonTransient(err) {
		t.Error("401 should be non-transient")
	}
	if callCount.Load() != 1 {
		t.Errorf("non-transient should not retry: got %d calls", callCount.Load())
	}
}

func TestFetchHTTPS5xxRetries(t *testing.T) {
	t.Parallel()
	callCount := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if callCount.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	req := &Request{Type: SourceTypeHTTPS, URL: srv.URL, RetryAttempts: 3}
	result, err := f.FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if string(result.Data) != "recovered" {
		t.Errorf("got %q, want %q", result.Data, "recovered")
	}
}

func TestFetchHTTPSRefusesRedirect(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should not reach"))
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{Type: SourceTypeHTTPS, URL: srv.URL})
	if err == nil {
		t.Fatal("expected error when redirect refused")
	}
}

func TestFetchHTTPSEmptyBodyNonTransient(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{Type: SourceTypeHTTPS, URL: srv.URL})
	if err == nil || !isNonTransient(err) {
		t.Error("empty body should be non-transient error")
	}
}

func TestFetchHTTPSInsecureSkipVerify(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	f := NewHTTPFetcher()

	_, err := f.FetchPolicyBundle(context.Background(), &Request{Type: SourceTypeHTTPS, URL: srv.URL})
	if err == nil {
		t.Fatal("expected TLS verification error with self-signed cert")
	}

	res, err := f.FetchPolicyBundle(context.Background(), &Request{Type: SourceTypeHTTPS, URL: srv.URL, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("expected success with InsecureSkipVerify=true, got: %v", err)
	}
	if string(res.Data) != "ok" {
		t.Fatalf("unexpected body: %q", string(res.Data))
	}
}

func TestFetchHTTPSCustomTLSCA(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	leaf := srv.Certificate()
	if leaf == nil {
		t.Fatal("expected tls server certificate")
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if _, err := x509.ParseCertificate(leaf.Raw); err != nil {
		t.Fatalf("failed to parse test server cert: %v", err)
	}

	f := NewHTTPFetcher()
	res, err := f.FetchPolicyBundle(context.Background(), &Request{Type: SourceTypeHTTPS, URL: srv.URL, TLSCA: caPEM})
	if err != nil {
		t.Fatalf("expected success with custom CA, got: %v", err)
	}
	if string(res.Data) != "ok" {
		t.Fatalf("unexpected body: %q", string(res.Data))
	}
}

// N1C source tests
const (
	testNS           = "test-namespace"
	testPolicyName   = "TestPolicy"
	testPolicyObjID  = "pol_abc123"
	testVersionObjID = "pv_v1"
	testNAPRelease   = "5.13.1"
	testAPIToken     = "test-dataplane-token"
	testBundleData   = "fake-bundle-tgz-content"
)

func requireAPIToken(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "APIToken "+testAPIToken {
		t.Errorf("wrong Authorization header: %q", got)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func n1cTestRequest() *Request {
	return &Request{
		Type:            SourceTypeN1C,
		URL:             "", // set per test
		PolicyName:      testPolicyName,
		PolicyNamespace: testNS,
		NAPRelease:      testNAPRelease,
		Auth:            &BundleAuth{APIToken: testAPIToken},
	}
}

func TestN1CFetchFullFlow(t *testing.T) {
	t.Parallel()
	compileCalled := atomic.Int32{}
	downloadCalled := atomic.Int32{}
	expectedChecksum := ComputeChecksum([]byte(testBundleData))

	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	compilePath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies/%s/versions/%s/compile",
		testNS, testPolicyObjID, testVersionObjID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAPIToken(t, r)
		switch r.URL.Path {
		case policiesPath:
			writeJSON(w, n1cPagedResult[n1cPolicyItem]{
				Items: []n1cPolicyItem{{
					Name:     testPolicyName,
					ObjectID: testPolicyObjID,
					Latest: struct {
						ObjectID string `json:"object_id"`
					}{testVersionObjID},
				}},
			})
		case compilePath:
			if r.URL.Query().Get("download") == "true" {
				downloadCalled.Add(1)
				_, _ = w.Write([]byte(testBundleData))
			} else {
				compileCalled.Add(1)
				writeJSON(w, n1cCompileStatus{Status: "succeeded", Hash: expectedChecksum})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	result, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != testBundleData {
		t.Errorf("got %q, want %q", result.Data, testBundleData)
	}
	if result.Checksum != expectedChecksum {
		t.Errorf("checksum mismatch")
	}
	if compileCalled.Load() != 1 || downloadCalled.Load() != 1 {
		t.Errorf("compile=%d download=%d, want 1 each", compileCalled.Load(), downloadCalled.Load())
	}
}

func TestN1CFetchHashUnchangedSkipsDownload(t *testing.T) {
	t.Parallel()
	downloadCalled := atomic.Int32{}
	existingHash := ComputeChecksum([]byte(testBundleData))

	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	compilePath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies/%s/versions/%s/compile",
		testNS, testPolicyObjID, testVersionObjID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case policiesPath:
			writeJSON(w, n1cPagedResult[n1cPolicyItem]{
				Items: []n1cPolicyItem{{
					Name:     testPolicyName,
					ObjectID: testPolicyObjID,
					Latest: struct {
						ObjectID string `json:"object_id"`
					}{testVersionObjID},
				}},
			})
		case compilePath:
			if r.URL.Query().Get("download") == "true" {
				downloadCalled.Add(1)
				_, _ = w.Write([]byte(testBundleData))
			} else {
				writeJSON(w, n1cCompileStatus{Status: "succeeded", Hash: existingHash})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	req.LastHash = existingHash
	result, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Unchanged {
		t.Error("expected Unchanged=true when hash matches")
	}
	if downloadCalled.Load() != 0 {
		t.Errorf("download should not be called, called %d times", downloadCalled.Load())
	}
}

func TestN1CFetchPolicyNotFound(t *testing.T) {
	t.Parallel()
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == policiesPath {
			writeJSON(w, n1cPagedResult[n1cPolicyItem]{})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	req.PolicyName = "NonExistent"
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil || !isNonTransient(err) {
		t.Error("policy not found should be non-transient error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

func TestN1CFetchCompileFailedNonTransient(t *testing.T) {
	t.Parallel()
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	compilePath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies/%s/versions/%s/compile",
		testNS, testPolicyObjID, testVersionObjID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case policiesPath:
			writeJSON(w, n1cPagedResult[n1cPolicyItem]{
				Items: []n1cPolicyItem{{
					Name:     testPolicyName,
					ObjectID: testPolicyObjID,
					Latest: struct {
						ObjectID string `json:"object_id"`
					}{testVersionObjID},
				}},
			})
		case compilePath:
			writeJSON(w, n1cCompileStatus{Status: "failed"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil || !isNonTransient(err) {
		t.Error("compile failed should be non-transient error")
	}
}

func TestN1CFetchCompilePendingThenSucceeds(t *testing.T) {
	t.Parallel()
	statusCallCount := atomic.Int32{}
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	compilePath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies/%s/versions/%s/compile",
		testNS, testPolicyObjID, testVersionObjID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case policiesPath:
			writeJSON(w, n1cPagedResult[n1cPolicyItem]{
				Items: []n1cPolicyItem{{
					Name:     testPolicyName,
					ObjectID: testPolicyObjID,
					Latest: struct {
						ObjectID string `json:"object_id"`
					}{testVersionObjID},
				}},
			})
		case compilePath:
			if r.URL.Query().Get("download") == "true" {
				_, _ = w.Write([]byte(testBundleData))
				return
			}
			n := statusCallCount.Add(1)
			if n < 3 {
				writeJSON(w, n1cCompileStatus{Status: "pending"})
			} else {
				writeJSON(w, n1cCompileStatus{Status: "succeeded", Hash: ComputeChecksum([]byte(testBundleData))})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := NewHTTPFetcher().FetchPolicyBundle(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Data) == 0 {
		t.Error("expected non-empty bundle data")
	}
}

func TestN1CFetchPagination(t *testing.T) {
	t.Parallel()
	const totalItems = 150
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	targetPolicy := "policy-125"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAPIToken(t, r)
		if r.URL.Path == policiesPath {
			pageToken := r.URL.Query().Get("page_token")
			offset := 0
			_, _ = fmt.Sscanf(pageToken, "%d", &offset)
			var items []n1cPolicyItem
			for i := offset; i < offset+100 && i < totalItems; i++ {
				items = append(items, n1cPolicyItem{
					Name:     fmt.Sprintf("policy-%d", i),
					ObjectID: fmt.Sprintf("pol_%d", i),
					Latest: struct {
						ObjectID string `json:"object_id"`
					}{fmt.Sprintf("pv_%d", i)},
				})
			}
			writeJSON(w, n1cPagedResult[n1cPolicyItem]{Items: items, Total: totalItems})
			return
		}
		if strings.Contains(r.URL.Path, "compile") {
			if r.URL.Query().Get("download") == "true" {
				_, _ = w.Write([]byte(testBundleData))
				return
			}
			writeJSON(w, n1cCompileStatus{Status: "succeeded", Hash: ComputeChecksum([]byte(testBundleData))})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	req.PolicyName = targetPolicy
	result, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Data) == 0 {
		t.Error("expected non-empty bundle data")
	}
}

func TestN1CFetchLogProfile(t *testing.T) {
	t.Parallel()
	const profileName = "log_all"
	const profileObjID = "lp_xyz789"

	profilesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/log-profiles", testNS)
	compilePath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/log-profiles/%s/compile",
		testNS, profileObjID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAPIToken(t, r)
		switch r.URL.Path {
		case profilesPath:
			writeJSON(w, n1cPagedResult[n1cLogProfileItem]{
				Items: []n1cLogProfileItem{{Name: profileName, ObjectID: profileObjID}},
			})
		case compilePath:
			_, _ = w.Write([]byte("log-profile-bundle"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	req.PolicyName = profileName
	result, err := NewHTTPFetcher().FetchLogProfileBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != "log-profile-bundle" {
		t.Errorf("got %q, want %q", result.Data, "log-profile-bundle")
	}
}

func TestN1CFetch401NonTransient(t *testing.T) {
	t.Parallel()
	callCount := atomic.Int32{}
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == policiesPath {
			callCount.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	req.Auth = &BundleAuth{APIToken: "wrong-token"}
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil || !isNonTransient(err) {
		t.Error("401 should be non-transient")
	}
	if callCount.Load() != 1 {
		t.Errorf("should not retry on 401: got %d calls", callCount.Load())
	}
}

// NIM source tests

const (
	testNIMPolicyName = "ngfBlocking"
	testNIMPolicyUID  = "uid-abc-123"
	testNIMToken      = "test-nim-bearer-token"
	testNIMBundleB64  = "ZmFrZS1uaW0tYnVuZGxl" // base64("fake-nim-bundle")
)

func nimTestRequest(srvURL string) *Request {
	return &Request{
		Type:       SourceTypeNIM,
		URL:        srvURL,
		PolicyName: testNIMPolicyName,
		Auth:       &BundleAuth{BearerToken: testNIMToken},
	}
}

func TestNIMFetchFullFlow(t *testing.T) {
	t.Parallel()
	bundleData := "fake-nim-bundle"
	bundleB64 := base64.StdEncoding.EncodeToString([]byte(bundleData))
	bundleHash := ComputeChecksum([]byte(bundleData))

	bundlesPath := "/api/platform/v1/security/policies/bundles"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testNIMToken {
			t.Errorf("wrong auth header: %q", got)
		}
		if r.URL.Path != bundlesPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("includeBundleContent") == "false" {
			// Metadata-only request
			_ = json.NewEncoder(w).Encode(nimResponse{
				Items: []nimBundleItem{{
					Metadata: struct {
						Hash      string `json:"hash"`
						Created   string `json:"created"`
						PolicyUID string `json:"policyUID"`
					}{Hash: bundleHash, Created: "2026-01-01T00:00:00Z", PolicyUID: testNIMPolicyUID},
				}},
			})
			return
		}
		// Full content request
		_ = json.NewEncoder(w).Encode(nimResponse{
			Items: []nimBundleItem{{
				Content: bundleB64,
				Metadata: struct {
					Hash      string `json:"hash"`
					Created   string `json:"created"`
					PolicyUID string `json:"policyUID"`
				}{Hash: bundleHash, Created: "2026-01-01T00:00:00Z", PolicyUID: testNIMPolicyUID},
			}},
		})
	}))
	defer srv.Close()

	req := nimTestRequest(srv.URL)
	result, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != bundleData {
		t.Errorf("got data %q, want %q", result.Data, bundleData)
	}
	if result.Checksum != bundleHash {
		t.Errorf("checksum mismatch")
	}
}

func TestNIMFetchPolicyNotFound(t *testing.T) {
	t.Parallel()
	bundlesPath := "/api/platform/v1/security/policies/bundles"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == bundlesPath {
			_ = json.NewEncoder(w).Encode(nimResponse{Items: []nimBundleItem{}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	req := nimTestRequest(srv.URL)
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil || !isNonTransient(err) {
		t.Error("expected non-transient error for empty items")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

func TestNIMFetchMultipleCompilationsPicksLatest(t *testing.T) {
	t.Parallel()
	bundleData := "latest-bundle"
	bundleB64 := base64.StdEncoding.EncodeToString([]byte(bundleData))
	bundleHash := ComputeChecksum([]byte(bundleData))

	bundlesPath := "/api/platform/v1/security/policies/bundles"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != bundlesPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("includeBundleContent") == "false" {
			_ = json.NewEncoder(w).Encode(nimResponse{
				Items: []nimBundleItem{
					{Metadata: struct {
						Hash      string `json:"hash"`
						Created   string `json:"created"`
						PolicyUID string `json:"policyUID"`
					}{Hash: "old", Created: "2025-01-01T00:00:00Z", PolicyUID: "uid-old"}},
					{Metadata: struct {
						Hash      string `json:"hash"`
						Created   string `json:"created"`
						PolicyUID string `json:"policyUID"`
					}{Hash: bundleHash, Created: "2026-06-01T00:00:00Z", PolicyUID: "uid-latest"}},
					{Metadata: struct {
						Hash      string `json:"hash"`
						Created   string `json:"created"`
						PolicyUID string `json:"policyUID"`
					}{Hash: "middle", Created: "2026-03-01T00:00:00Z", PolicyUID: "uid-middle"}},
				},
			})
			return
		}
		// Full content — should be called with uid-latest
		if r.URL.Query().Get("policyUID") != "uid-latest" {
			t.Errorf("expected policyUID=uid-latest, got %s", r.URL.Query().Get("policyUID"))
		}
		_ = json.NewEncoder(w).Encode(nimResponse{
			Items: []nimBundleItem{{
				Content: bundleB64,
				Metadata: struct {
					Hash      string `json:"hash"`
					Created   string `json:"created"`
					PolicyUID string `json:"policyUID"`
				}{Hash: bundleHash, PolicyUID: "uid-latest"},
			}},
		})
	}))
	defer srv.Close()

	req := nimTestRequest(srv.URL)
	result, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != bundleData {
		t.Errorf("got data %q, want %q", result.Data, bundleData)
	}
}

func TestNIMFetchLogProfile(t *testing.T) {
	t.Parallel()
	logData := "log-profile-bundle"
	logB64 := base64.StdEncoding.EncodeToString([]byte(logData))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/nap-compiler/versions/latest"):
			_ = json.NewEncoder(w).Encode(nimCompilerVersionResponse{Version: "5.13.1"})
		case strings.Contains(r.URL.Path, "/logprofiles/"):
			_ = json.NewEncoder(w).Encode(nimLogProfileBundleResponse{CompiledBundle: logB64})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	req := &Request{
		Type:       SourceTypeNIM,
		URL:        srv.URL,
		PolicyName: "log_all",
		Auth:       &BundleAuth{BearerToken: testNIMToken},
	}
	result, err := NewHTTPFetcher().FetchLogProfileBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != logData {
		t.Errorf("got %q, want %q", result.Data, logData)
	}
}

func TestNIMFetchBasicAuth(t *testing.T) {
	t.Parallel()
	bundleData := "basic-auth-bundle"
	bundleB64 := base64.StdEncoding.EncodeToString([]byte(bundleData))
	bundleHash := ComputeChecksum([]byte(bundleData))

	bundlesPath := "/api/platform/v1/security/policies/bundles"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == bundlesPath {
			_ = json.NewEncoder(w).Encode(nimResponse{
				Items: []nimBundleItem{{
					Content: bundleB64,
					Metadata: struct {
						Hash      string `json:"hash"`
						Created   string `json:"created"`
						PolicyUID string `json:"policyUID"`
					}{Hash: bundleHash, Created: "2026-01-01T00:00:00Z", PolicyUID: "uid-1"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	req := &Request{
		Type:       SourceTypeNIM,
		URL:        srv.URL,
		PolicyName: testNIMPolicyName,
		Auth:       &BundleAuth{Username: "admin", Password: "secret"},
	}
	result, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != bundleData {
		t.Errorf("got %q, want %q", result.Data, bundleData)
	}
}

func TestNIMFetch401NonTransient(t *testing.T) {
	t.Parallel()
	bundlesPath := "/api/platform/v1/security/policies/bundles"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()

	_ = bundlesPath
	req := nimTestRequest(srv.URL)
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil || !isNonTransient(err) {
		t.Error("401 should be non-transient")
	}
}

// Retry and EOF detection tests

func TestN1CFetchEOFBecomesNonTransient(t *testing.T) {
	t.Parallel()
	callCount := atomic.Int32{}
	// Server that immediately closes the connection (simulates EOF)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	req.NAPRelease = "5.13.2"
	req.RetryAttempts = 2
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for EOF")
	}
	if !isNonTransient(err) {
		t.Errorf("EOF after retries should be non-transient, got: %v", err)
	}
	if !strings.Contains(err.Error(), "5.13.2") {
		t.Errorf("error should mention NAP release, got: %v", err)
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 retry attempts, got %d", callCount.Load())
	}
}

func TestN1CGetErrorBodyIncluded(t *testing.T) {
	t.Parallel()
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == policiesPath {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("unsupported nap_release value"))
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if !strings.Contains(err.Error(), "unsupported nap_release value") {
		t.Errorf("error should include response body, got: %v", err)
	}
}

func TestN1CGetAuthErrorMentionsSecret(t *testing.T) {
	t.Parallel()
	policiesPath := fmt.Sprintf("/api/nginx/one/namespaces/%s/app-protect/policies", testNS)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == policiesPath {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	req := n1cTestRequest()
	req.URL = srv.URL
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "verify the API token") {
		t.Errorf("error should mention checking Secret, got: %v", err)
	}
}

func TestFetchHTTPSTruncatedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Advertise Content-Length of 1000 bytes but only send 5.
		// Go's HTTP client detects the mismatch and returns "unexpected EOF".
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	}))
	defer srv.Close()

	f := NewHTTPFetcher()
	_, err := f.FetchPolicyBundle(context.Background(), &Request{Type: SourceTypeHTTPS, URL: srv.URL})
	if err == nil {
		t.Fatal("expected error for truncated response")
	}
	// Go's HTTP client catches Content-Length vs actual body mismatch as "unexpected EOF"
	if !strings.Contains(err.Error(), "EOF") {
		t.Errorf("truncated response should produce EOF error, got: %v", err)
	}
}

func TestIsEOFError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"io.EOF", fmt.Errorf("request: %w", io.EOF), true},
		{"io.ErrUnexpectedEOF", fmt.Errorf("read: %w", io.ErrUnexpectedEOF), true},
		{"string contains EOF", fmt.Errorf("connection closed: unexpected EOF"), true},
		{"normal error", fmt.Errorf("timeout exceeded"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEOFError(tt.err); got != tt.want {
				t.Errorf("isEOFError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// Helper tests
func TestComputeChecksumDeterministic(t *testing.T) {
	t.Parallel()
	s1 := ComputeChecksum([]byte("hello"))
	s2 := ComputeChecksum([]byte("hello"))
	if s1 != s2 || len(s1) != 64 {
		t.Errorf("checksum not deterministic or wrong length: %q %q", s1, s2)
	}
}

func TestFetchedBundleFilename(t *testing.T) {
	t.Parallel()
	tests := []struct{ ns, name, suffix, want string }{
		{"default", "waf-policy", "policy", "fetched_default_waf-policy_policy.tgz"},
		{"prod", "strict", "log_0", "fetched_prod_strict_log_0.tgz"},
	}
	for _, tt := range tests {
		if got := FetchedBundleFilename(tt.ns, tt.name, tt.suffix); got != tt.want {
			t.Errorf("FetchedBundleFilename(%q,%q,%q) = %q, want %q", tt.ns, tt.name, tt.suffix, got, tt.want)
		}
	}
}
