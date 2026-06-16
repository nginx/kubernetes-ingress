package wafbundle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
		return fetchNIMPolicyBundle(ctx, client, req)
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
		return fetchNIMLogProfileBundle(ctx, client, req)
	default: // HTTPS
		return fetchHTTPSBundle(ctx, client, req)
	}
}

// buildClient constructs an *http.Client with TLS configured for the request.
func (f *HTTPFetcher) buildClient(req *Request) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	tlsCfg.InsecureSkipVerify = req.InsecureSkipVerify //nolint:gosec // configurable for test or private environments.

	if req.TLSCA != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(req.TLSCA) {
			return &http.Client{}, fmt.Errorf("failed to parse CA certificate bundle")
		}
		tlsCfg.RootCAs = pool
	}

	if req.Auth != nil {
		if req.Auth.TLSCert != nil && req.Auth.TLSKey != nil {
			cert, err := tls.X509KeyPair(req.Auth.TLSCert, req.Auth.TLSKey)
			if err != nil {
				return &http.Client{}, fmt.Errorf("invalid TLS client cert/key: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		// Refuse redirects to prevent SSRF.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// HTTPS source
func fetchHTTPSBundle(ctx context.Context, client *http.Client, req *Request) (Result, error) {
	var result Result
	var fetchErr error
	for attempt := 0; attempt < effectiveRetries(req); attempt++ {
		httpReq, err := newHTTPSRequest(ctx, req)
		if err != nil {
			return Result{}, err
		}
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

// newHTTPSRequest builds a fresh *http.Request for an HTTPS bundle fetch.
func newHTTPSRequest(ctx context.Context, req *Request) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
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
	return httpReq, nil
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

	if r, statusErr := checkHTTPSStatus(resp, bundleReq.URL); statusErr != nil || r != nil {
		if r != nil {
			return *r, nil
		}
		return Result{}, statusErr
	}

	data, err := readBundleBody(resp, bundleReq.URL)
	if err != nil {
		return Result{}, err
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

// checkHTTPSStatus returns a non-nil *Result for 304 (unchanged) or a non-nil error for non-200 codes.
// Both nil means "200 OK, continue reading the body".
func checkHTTPSStatus(resp *http.Response, reqURL string) (*Result, error) {
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return &Result{Unchanged: true}, nil
	case resp.StatusCode == http.StatusOK:
		return nil, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, &nonTransientError{fmt.Errorf("HTTP %d redirect from %s (redirects are not followed)", resp.StatusCode, reqURL)}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, &nonTransientError{fmt.Errorf("HTTP %d from %s", resp.StatusCode, reqURL)}
	default:
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, reqURL)
	}
}

// readBundleBody reads and validates the response body.
func readBundleBody(resp *http.Response, reqURL string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if int64(len(data)) > MaxBundleSize {
		return nil, &nonTransientError{fmt.Errorf("bundle exceeds maximum size of %d bytes", MaxBundleSize)}
	}
	if len(data) == 0 {
		return nil, &nonTransientError{fmt.Errorf("empty response from %s", reqURL)}
	}
	return data, nil
}

// NGINX One Console (N1C)
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
	item, found, err := paginatedSearch(
		ctx, client, token,
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
	item, found, err := paginatedSearch(
		ctx, client, token,
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
	offset := 0

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
		offset += len(page.Items)
		pageToken = strconv.Itoa(offset)
	}
}

func pollN1CCompileStatus(ctx context.Context, client *http.Client, statusURL, token string) (n1cCompileStatus, error) {
	for attempt := 0; attempt < maxN1CCompilePolls; attempt++ {
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
	return n1cCompileStatus{}, &nonTransientError{fmt.Errorf("N1C policy compilation did not complete after %d polls", maxN1CCompilePolls)}
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

// NGINX Instance Manager (NIM)

// nimBundleItem is a single entry in the NIM bundles API response.
type nimBundleItem struct {
	Content  string `json:"content"`
	Metadata struct {
		Hash      string `json:"hash"`
		Created   string `json:"created"`
		PolicyUID string `json:"policyUID"`
	} `json:"metadata"`
}

// nimResponse is the JSON envelope returned by the NIM bundles API.
type nimResponse struct {
	Items []nimBundleItem `json:"items"`
}

// nimCompilerVersionResponse is returned by the NIM compiler version endpoint.
type nimCompilerVersionResponse struct {
	Version string `json:"version"`
}

// nimLogProfileBundleResponse is returned by the NIM log profile bundle endpoint.
type nimLogProfileBundleResponse struct {
	CompiledBundle string `json:"compiledBundle"`
}

// unixEpochRFC3339 is sent as startTime to retrieve all policies regardless of age.
// NIM defaults startTime to now-24h when omitted, which silently excludes older compilations.
var unixEpochRFC3339 = time.Unix(0, 0).UTC().Format(time.RFC3339)

// fetchNIMPolicyBundle resolves the latest compilation for the named policy.
// It first fetches metadata only (no bundle content) to check if the hash has
// changed. The full bundle is downloaded only when a new version is detected,
// avoiding unnecessary data transfer on each poll cycle.
func fetchNIMPolicyBundle(ctx context.Context, client *http.Client, req *Request) (Result, error) {
	auth := nimAuth(req)

	policyUID, metadataHash, err := resolveLatestNIMPolicy(ctx, client, req.URL, req.PolicyName, auth)
	if err != nil {
		return Result{}, err
	}

	// If the metadata hash matches the last known hash, the bundle has not changed.
	// Skip the full download to avoid unnecessary data transfer.
	if metadataHash != "" && req.LastHash != "" && strings.ToLower(metadataHash) == req.LastHash {
		return Result{Unchanged: true}, nil
	}

	bundleURL := buildNIMBundlesURL(req.URL, "", policyUID, true)
	body, err := nimGet(ctx, client, bundleURL, auth)
	if err != nil {
		return Result{}, fmt.Errorf("failed to fetch NIM bundle: %w", err)
	}

	var resp nimResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Result{}, fmt.Errorf("failed to parse NIM response: %w", err)
	}
	if len(resp.Items) == 0 {
		return Result{}, &nonTransientError{fmt.Errorf("NIM response contains no items for policy UID %q", policyUID)}
	}

	item := resp.Items[0]
	data, err := base64.StdEncoding.DecodeString(item.Content)
	if err != nil {
		return Result{}, fmt.Errorf("failed to base64-decode NIM bundle: %w", err)
	}

	checksum := ComputeChecksum(data)

	if item.Metadata.Hash != "" && checksum != strings.ToLower(item.Metadata.Hash) {
		return Result{}, &nonTransientError{
			fmt.Errorf("NIM bundle integrity check failed: expected %s, got %s", item.Metadata.Hash, checksum),
		}
	}

	if checksum == req.LastHash {
		return Result{Unchanged: true}, nil
	}

	return Result{Data: data, Checksum: checksum}, nil
}

// fetchNIMLogProfileBundle fetches a compiled log profile bundle from NIM.
// It first looks up the latest compiler version, then fetches the log profile for that version.
func fetchNIMLogProfileBundle(ctx context.Context, client *http.Client, req *Request) (Result, error) {
	auth := nimAuth(req)

	compilerVersionURL := strings.TrimRight(req.URL, "/") + "/api/platform/v1/security/nap-compiler/versions/latest"
	body, err := nimGet(ctx, client, compilerVersionURL, auth)
	if err != nil {
		return Result{}, fmt.Errorf("failed to fetch NIM compiler version: %w", err)
	}

	var versionResp nimCompilerVersionResponse
	if err := json.Unmarshal(body, &versionResp); err != nil {
		return Result{}, fmt.Errorf("failed to parse NIM compiler version response: %w", err)
	}

	logProfileURL := fmt.Sprintf("%s/api/platform/v1/security/logprofiles/%s/%s/bundle",
		strings.TrimRight(req.URL, "/"), url.PathEscape(req.PolicyName), url.PathEscape(versionResp.Version))
	body, err = nimGet(ctx, client, logProfileURL, auth)
	if err != nil {
		return Result{}, fmt.Errorf("failed to fetch NIM log profile bundle: %w", err)
	}

	var logResp nimLogProfileBundleResponse
	if err := json.Unmarshal(body, &logResp); err != nil {
		return Result{}, fmt.Errorf("failed to parse NIM log profile response: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(logResp.CompiledBundle)
	if err != nil {
		return Result{}, fmt.Errorf("failed to base64-decode NIM log profile bundle: %w", err)
	}

	checksum := ComputeChecksum(data)
	if checksum == req.LastHash {
		return Result{Unchanged: true}, nil
	}

	return Result{Data: data, Checksum: checksum}, nil
}

// resolveLatestNIMPolicy performs a metadata-only request to find all compilations
// for the given policy name. It returns the policyUID and metadata hash of the most
// recently compiled bundle. The hash can be compared against LastHash to skip the
// full bundle download when nothing has changed.
func resolveLatestNIMPolicy(ctx context.Context, client *http.Client, baseURL, policyName string, auth *BundleAuth) (policyUID, hash string, err error) {
	metadataURL := buildNIMBundlesURL(baseURL, policyName, "", false)
	body, err := nimGet(ctx, client, metadataURL, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch NIM bundle metadata: %w", err)
	}

	var resp nimResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", fmt.Errorf("failed to parse NIM metadata response: %w", err)
	}
	if len(resp.Items) == 0 {
		return "", "", &nonTransientError{fmt.Errorf("NIM policy %q not found", policyName)}
	}

	latest := latestNIMItem(resp.Items)
	if latest.Metadata.PolicyUID == "" {
		return "", "", fmt.Errorf("NIM metadata contains no policyUID for policy %q", policyName)
	}

	return latest.Metadata.PolicyUID, latest.Metadata.Hash, nil
}

// latestNIMItem returns the item with the most recent metadata.created timestamp.
// Falls back to the last item if no timestamps are parseable.
func latestNIMItem(items []nimBundleItem) nimBundleItem {
	best := len(items) - 1
	var bestTime time.Time

	for i, item := range items {
		t, err := time.Parse(time.RFC3339Nano, item.Metadata.Created)
		if err != nil {
			continue
		}
		if t.After(bestTime) {
			bestTime = t
			best = i
		}
	}

	return items[best]
}

// setNIMAuth applies authentication credentials to an HTTP request.
func setNIMAuth(req *http.Request, auth *BundleAuth) {
	if auth == nil {
		return
	}
	switch {
	case auth.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+auth.BearerToken)
	case auth.Username != "":
		req.SetBasicAuth(auth.Username, auth.Password)
	}
}

// nimGet performs an HTTP GET with NIM authentication (Bearer token or Basic Auth).
func nimGet(ctx context.Context, client *http.Client, targetURL string, auth *BundleAuth) (data []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building NIM request: %w", err)
	}
	setNIMAuth(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NIM request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return nil, &nonTransientError{fmt.Errorf("NIM resource not found (404)")}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &nonTransientError{fmt.Errorf("NIM auth failure (%d)", resp.StatusCode)}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, &nonTransientError{fmt.Errorf("NIM client error %d", resp.StatusCode)}
	default:
		return nil, fmt.Errorf("NIM server error %d", resp.StatusCode)
	}

	data, err = io.ReadAll(io.LimitReader(resp.Body, MaxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading NIM response: %w", err)
	}
	if int64(len(data)) > MaxBundleSize {
		return nil, &nonTransientError{fmt.Errorf("NIM response exceeds maximum size")}
	}
	return data, nil
}

// nimAuth extracts auth credentials from the request.
func nimAuth(req *Request) *BundleAuth {
	return req.Auth
}

// buildNIMBundlesURL constructs the NIM bundles API URL.
// When includeBundleContent is true, the response includes base64-encoded bundle content.
// Exactly one of policyName or policyUID must be non-empty.
func buildNIMBundlesURL(baseURL, policyName, policyUID string, includeBundleContent bool) string {
	u := strings.TrimRight(baseURL, "/") + "/api/platform/v1/security/policies/bundles"
	params := url.Values{}
	if includeBundleContent {
		params.Set("includeBundleContent", "true")
	} else {
		params.Set("includeBundleContent", "false")
	}
	params.Set("startTime", unixEpochRFC3339)
	if policyUID != "" {
		params.Set("policyUID", policyUID)
	} else {
		params.Set("policyName", policyName)
	}
	return u + "?" + params.Encode()
}
