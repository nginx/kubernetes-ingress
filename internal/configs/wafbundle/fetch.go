package wafbundle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Fetcher fetches WAF policy and log profile bundles from remote sources.
type Fetcher interface {
	FetchPolicyBundle(ctx context.Context, req *Request) (Result, error)
	FetchLogProfileBundle(ctx context.Context, req *Request) (Result, error)
}

// HTTPFetcher implements Fetcher over HTTPS for HTTPS, N1C, and NIM source types.
type HTTPFetcher struct{}

// NewHTTPFetcher creates a new HTTPFetcher.
func NewHTTPFetcher() *HTTPFetcher { return &HTTPFetcher{} }

// FetchPolicyBundle dispatches to the appropriate source-specific fetch implementation.
func (f *HTTPFetcher) FetchPolicyBundle(ctx context.Context, req *Request) (Result, error) {
	client, err := f.buildClient(req)
	if err != nil {
		return Result{}, err
	}
	switch req.Type {
	case SourceTypeN1C:
		return fetchN1CPolicyBundle(ctx, client, req)
	case SourceTypeNIM:
		// TODO: expand NIM implementation here
		return Result{}, &nonTransientError{fmt.Errorf("NIM source type is not yet implemented")}
	default: // HTTPS
		return fetchHTTPSBundle(ctx, client, req)
	}
}

// FetchLogProfileBundle dispatches to the appropriate source-specific fetch implementation.
func (f *HTTPFetcher) FetchLogProfileBundle(ctx context.Context, req *Request) (Result, error) {
	client, err := f.buildClient(req)
	if err != nil {
		return Result{}, err
	}
	switch req.Type {
	case SourceTypeN1C:
		return fetchN1CLogProfileBundle(ctx, client, req)
	case SourceTypeNIM:
		// TODO: expand NIM implementation here
		return Result{}, &nonTransientError{fmt.Errorf("NIM source type is not yet implemented")}
	default: // HTTPS
		return fetchHTTPSBundle(ctx, client, req)
	}
}

// buildClient constructs an *http.Client with TLS configured for the request.
func (f *HTTPFetcher) buildClient(req *Request) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if req.Auth != nil {
		if req.Auth.TLSCA != nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(req.Auth.TLSCA)
			tlsCfg.RootCAs = pool
		}
		if req.Auth.TLSCert != nil && req.Auth.TLSKey != nil {
			cert, err := tls.X509KeyPair(req.Auth.TLSCert, req.Auth.TLSKey)
			if err != nil {
				return &http.Client{}, fmt.Errorf("invalid TLS client cert/key: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}
	return &http.Client{
		Timeout:   effectiveTimeout(req),
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		// Refuse redirects to prevent SSRF.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// HTTPS source implementation
func fetchHTTPSBundle(ctx context.Context, client *http.Client, req *Request) (Result, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("building request: %w", err)
	}

	if req.Auth != nil {
		switch {
		case req.Auth.APIToken != "":
			httpReq.Header.Set("Authorization", "APIToken "+req.Auth.APIToken)
		case req.Auth.BearerToken != "":
			httpReq.Header.Set("Authorization", "Bearer "+req.Auth.BearerToken)
		case req.Auth.Username != "":
			httpReq.SetBasicAuth(req.Auth.Username, req.Auth.Password)
		}
	}
	if req.ETag != "" {
		httpReq.Header.Set("If-None-Match", req.ETag)
	}
	if req.LastModified != "" {
		httpReq.Header.Set("If-Modified-Since", req.LastModified)
	}

	var result Result
	var fetchErr error
	for attempt := 0; attempt < effectiveRetries(req); attempt++ {
		result, fetchErr = doHTTPSFetch(client, httpReq, req)
		if fetchErr == nil || isNonTransient(fetchErr) {
			break
		}
		if attempt < effectiveRetries(req)-1 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return result, fetchErr
}

func doHTTPSFetch(client *http.Client, req *http.Request, bundleReq *Request) (result Result, err error) {
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return Result{Unchanged: true}, nil
	case resp.StatusCode == http.StatusOK:
		// fall through
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return Result{}, &nonTransientError{fmt.Errorf("HTTP %d from %s", resp.StatusCode, bundleReq.URL)}
	default:
		return Result{}, fmt.Errorf("HTTP %d from %s", resp.StatusCode, bundleReq.URL)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBundleSize+1))
	if err != nil {
		return Result{}, fmt.Errorf("reading response: %w", err)
	}
	if int64(len(data)) > MaxBundleSize {
		return Result{}, &nonTransientError{fmt.Errorf("bundle exceeds maximum size of %d bytes", MaxBundleSize)}
	}
	if len(data) == 0 {
		return Result{}, &nonTransientError{fmt.Errorf("empty response from %s", bundleReq.URL)}
	}

	checksum := ComputeChecksum(data)
	if bundleReq.VerifyChecksum && bundleReq.LastHash != "" && checksum == bundleReq.LastHash {
		return Result{Unchanged: true}, nil
	}
	return Result{
		Data: data, Checksum: checksum,
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// NGINX One Console (N1C) implementation
type n1cPagedResult[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

type n1cPolicyItem struct {
	Name     string `json:"name"`
	ObjectID string `json:"object_id"`
	Latest   struct {
		ObjectID string `json:"object_id"`
	} `json:"latest"`
}

type n1cLogProfileItem struct {
	Name     string `json:"name"`
	ObjectID string `json:"object_id"`
}

type n1cCompileStatus struct {
	Status string `json:"status"`
	Hash   string `json:"hash"`
}

func fetchN1CPolicyBundle(ctx context.Context, client *http.Client, req *Request) (Result, error) {
	token := n1cToken(req)

	pol, err := findN1CPolicy(ctx, client, req.URL, req.PolicyNamespace, req.PolicyName, token)
	if err != nil {
		return Result{}, err
	}

	statusURL := buildN1CCompileStatusURL(req.URL, req.PolicyNamespace, pol.ObjectID, pol.Latest.ObjectID, req.NAPRelease)
	status, err := pollN1CCompileStatus(ctx, client, statusURL, token)
	if err != nil {
		return Result{}, err
	}

	if status.Hash != "" && status.Hash == req.LastHash {
		return Result{Unchanged: true}, nil
	}

	downloadURL := buildN1CCompileDownloadURL(req.URL, req.PolicyNamespace, pol.ObjectID, pol.Latest.ObjectID, req.NAPRelease)
	data, err := n1cDownload(ctx, client, downloadURL, token)
	if err != nil {
		return Result{}, err
	}

	checksum := ComputeChecksum(data)
	if status.Hash != "" && checksum != status.Hash {
		return Result{}, &nonTransientError{
			fmt.Errorf("N1C bundle checksum mismatch: got %s, expected %s", checksum, status.Hash),
		}
	}
	return Result{Data: data, Checksum: checksum}, nil
}

func fetchN1CLogProfileBundle(ctx context.Context, client *http.Client, req *Request) (Result, error) {
	token := n1cToken(req)

	profileObjID, err := findN1CLogProfile(ctx, client, req.URL, req.PolicyNamespace, req.PolicyName, token)
	if err != nil {
		return Result{}, err
	}

	downloadURL := buildN1CLogProfileCompileURL(req.URL, req.PolicyNamespace, profileObjID, req.NAPRelease)
	data, err := n1cDownload(ctx, client, downloadURL, token)
	if err != nil {
		return Result{}, err
	}

	checksum := ComputeChecksum(data)
	if checksum == req.LastHash {
		return Result{Unchanged: true}, nil
	}
	return Result{Data: data, Checksum: checksum}, nil
}

func findN1CPolicy(ctx context.Context, client *http.Client, baseURL, ns, name, token string) (n1cPolicyItem, error) {
	item, found, err := paginatedSearch(ctx, client, token,
		func(pageToken string, pageSize int) string {
			return buildN1CPoliciesURL(baseURL, ns, pageToken, pageSize)
		},
		func(item n1cPolicyItem) bool { return item.Name == name },
	)
	if err != nil {
		return n1cPolicyItem{}, err
	}
	if !found {
		return n1cPolicyItem{}, &nonTransientError{fmt.Errorf("policy %q not found in N1C namespace %q", name, ns)}
	}
	return item, nil
}

func findN1CLogProfile(ctx context.Context, client *http.Client, baseURL, ns, name, token string) (string, error) {
	item, found, err := paginatedSearch(ctx, client, token,
		func(pageToken string, pageSize int) string {
			return buildN1CLogProfilesURL(baseURL, ns, pageToken, pageSize)
		},
		func(item n1cLogProfileItem) bool { return item.Name == name },
	)
	if err != nil {
		return "", err
	}
	if !found {
		return "", &nonTransientError{fmt.Errorf("log profile %q not found in N1C namespace %q", name, ns)}
	}
	return item.ObjectID, nil
}

func paginatedSearch[T any](
	ctx context.Context,
	client *http.Client,
	token string,
	urlFn func(pageToken string, pageSize int) string,
	matchFn func(T) bool,
) (T, bool, error) {
	const pageSize = 100
	var zero T
	pageToken := ""

	for {
		body, err := n1cGet(ctx, client, urlFn(pageToken, pageSize), token)
		if err != nil {
			return zero, false, err
		}
		var page n1cPagedResult[T]
		if err := json.Unmarshal(body, &page); err != nil {
			return zero, false, fmt.Errorf("parsing N1C list response: %w", err)
		}
		for _, item := range page.Items {
			if matchFn(item) {
				return item, true, nil
			}
		}
		if len(page.Items) < pageSize {
			return zero, false, nil
		}
		pageToken = strconv.Itoa(len(page.Items))
	}
}

func pollN1CCompileStatus(ctx context.Context, client *http.Client, statusURL, token string) (n1cCompileStatus, error) {
	for {
		body, err := n1cGet(ctx, client, statusURL, token)
		if err != nil {
			return n1cCompileStatus{}, err
		}
		var status n1cCompileStatus
		if err := json.Unmarshal(body, &status); err != nil {
			return n1cCompileStatus{}, fmt.Errorf("parsing compile status: %w", err)
		}
		switch strings.ToLower(status.Status) {
		case "succeeded":
			return status, nil
		case "failed":
			return n1cCompileStatus{}, &nonTransientError{fmt.Errorf("N1C policy compilation failed")}
		case "pending", "accepted", "running":
			// still in progress
		default:
			return n1cCompileStatus{}, fmt.Errorf("N1C compile status unknown: %q", status.Status)
		}
		select {
		case <-ctx.Done():
			return n1cCompileStatus{}, ctx.Err()
		case <-time.After(n1cCompilePollInterval):
		}
	}
}

func n1cDownload(ctx context.Context, client *http.Client, downloadURL, token string) ([]byte, error) {
	body, err := n1cGet(ctx, client, downloadURL, token)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, &nonTransientError{fmt.Errorf("empty bundle from N1C download endpoint")}
	}
	return body, nil
}

func n1cGet(ctx context.Context, client *http.Client, targetURL, token string) (data []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building N1C request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "APIToken "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("N1C request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted:
		// 200 OK — normal response. 202 Accepted — async compilation in progress (valid for compile status polling).
	case resp.StatusCode == http.StatusNotFound:
		return nil, &nonTransientError{fmt.Errorf("N1C resource not found (404)")}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &nonTransientError{fmt.Errorf("N1C auth failure (%d)", resp.StatusCode)}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, &nonTransientError{fmt.Errorf("N1C client error %d", resp.StatusCode)}
	default:
		return nil, fmt.Errorf("N1C server error %d", resp.StatusCode)
	}

	data, err = io.ReadAll(io.LimitReader(resp.Body, MaxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading N1C response: %w", err)
	}
	if int64(len(data)) > MaxBundleSize {
		return nil, &nonTransientError{fmt.Errorf("N1C response exceeds maximum size")}
	}
	return data, nil
}

func n1cToken(req *Request) string {
	if req.Auth != nil {
		return req.Auth.APIToken
	}
	return ""
}

// N1C URL builders
func buildN1CPoliciesURL(baseURL, ns, pageToken string, pageSize int) string {
	u := fmt.Sprintf("%s/api/nginx/one/namespaces/%s/app-protect/policies",
		strings.TrimRight(baseURL, "/"), url.PathEscape(ns))
	params := url.Values{}
	params.Set("page_size", strconv.Itoa(pageSize))
	if pageToken != "" {
		params.Set("page_token", pageToken)
	}
	return u + "?" + params.Encode()
}

func buildN1CCompileStatusURL(baseURL, ns, policyObjID, versionObjID, napRelease string) string {
	return buildN1CCompileBase(baseURL, ns, policyObjID, versionObjID, napRelease, false)
}

func buildN1CCompileDownloadURL(baseURL, ns, policyObjID, versionObjID, napRelease string) string {
	return buildN1CCompileBase(baseURL, ns, policyObjID, versionObjID, napRelease, true)
}

func buildN1CCompileBase(baseURL, ns, policyObjID, versionObjID, napRelease string, download bool) string {
	u := fmt.Sprintf("%s/api/nginx/one/namespaces/%s/app-protect/policies/%s/versions/%s/compile",
		strings.TrimRight(baseURL, "/"),
		url.PathEscape(ns), url.PathEscape(policyObjID), url.PathEscape(versionObjID))
	params := url.Values{}
	if napRelease != "" {
		params.Set("nap_release", napRelease)
	}
	if download {
		params.Set("download", "true")
	}
	if len(params) > 0 {
		return u + "?" + params.Encode()
	}
	return u
}

func buildN1CLogProfilesURL(baseURL, ns, pageToken string, pageSize int) string {
	u := fmt.Sprintf("%s/api/nginx/one/namespaces/%s/app-protect/log-profiles",
		strings.TrimRight(baseURL, "/"), url.PathEscape(ns))
	params := url.Values{}
	params.Set("page_size", strconv.Itoa(pageSize))
	if pageToken != "" {
		params.Set("page_token", pageToken)
	}
	return u + "?" + params.Encode()
}

func buildN1CLogProfileCompileURL(baseURL, ns, profileObjID, napRelease string) string {
	u := fmt.Sprintf("%s/api/nginx/one/namespaces/%s/app-protect/log-profiles/%s/compile",
		strings.TrimRight(baseURL, "/"),
		url.PathEscape(ns), url.PathEscape(profileObjID))
	params := url.Values{}
	if napRelease != "" {
		params.Set("nap_release", napRelease)
	}
	params.Set("download", "true")
	return u + "?" + params.Encode()
}
