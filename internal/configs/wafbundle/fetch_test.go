package wafbundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// HTTPS source tests
func TestFetchHTTPS_Downloads(t *testing.T) {
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

func TestFetchHTTPS_304NotModified(t *testing.T) {
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

func TestFetchHTTPS_4xx_NonTransient(t *testing.T) {
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

func TestFetchHTTPS_5xx_Retries(t *testing.T) {
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

func TestFetchHTTPS_RefusesRedirect(t *testing.T) {
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

func TestFetchHTTPS_EmptyBody_NonTransient(t *testing.T) {
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

func TestN1CFetch_FullFlow(t *testing.T) {
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

func TestN1CFetch_HashUnchanged_SkipsDownload(t *testing.T) {
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

func TestN1CFetch_PolicyNotFound(t *testing.T) {
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

func TestN1CFetch_CompileFailed_NonTransient(t *testing.T) {
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

func TestN1CFetch_CompilePending_ThenSucceeds(t *testing.T) {
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

func TestN1CFetch_Pagination(t *testing.T) {
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

func TestN1CFetch_LogProfile(t *testing.T) {
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

func TestN1CFetch_401_NonTransient(t *testing.T) {
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

func TestNIM_ReturnsNotImplemented(t *testing.T) {
	t.Parallel()
	_, err := NewHTTPFetcher().FetchPolicyBundle(context.Background(),
		&Request{Type: SourceTypeNIM, URL: "https://nim.example.com", PolicyName: "P"})
	if err == nil || !isNonTransient(err) {
		t.Error("NIM should return non-transient not-implemented error")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should say 'not yet implemented': %v", err)
	}
}

// Helper tests
func TestComputeChecksum_Deterministic(t *testing.T) {
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
