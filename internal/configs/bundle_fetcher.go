package configs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

const (
	defaultPollInterval       = 1 * time.Minute
	initialFetchTimeout       = 30 * time.Second
	maxBundleSize       int64 = 256 << 20 // 256 MiB

	// bundleReloadDelay is a stabilization window inserted between an atomic bundle
	// file replacement and the NGINX reload triggered by onChange. APP_PROTECT v5's
	// waf-config-mgr detects the new inode and performs its own internal re-read;
	// triggering a reload before that completes causes a transient "File Not Found".
	bundleReloadDelay = 2 * time.Second
)

// BundleFetcher manages remote bundle fetching with ETag-based polling.
type BundleFetcher interface {
	// Register adds or updates a remote bundle entry. The key uniquely identifies the entry
	// (e.g. "namespace/policyName/policy" or "namespace/policyName/log-0").
	// secretData may be nil if no mTLS is needed; otherwise it should contain
	// "tls.crt", "tls.key", and optionally "ca.crt" entries.
	// timeout is the per-request HTTP fetch timeout; 0 means use the default (60s).
	Register(key, remoteURL string, secretData map[string][]byte, pollInterval, timeout time.Duration)

	// Unregister removes a bundle entry and cleans up its local file.
	Unregister(key string)

	// GetLocalPath returns the on-disk path where the bundle for key is (or will be) stored.
	GetLocalPath(key string) string

	// FetchNow performs an immediate synchronous fetch for the given key.
	// Returns the local path and any error. Used for initial fetch on policy sync.
	FetchNow(ctx context.Context, key string) (string, error)

	// Start begins background polling for all registered entries.
	Start(ctx context.Context)

	// Stop cancels all background polling.
	Stop()
}

// OnBundleUpdate is called when a remote bundle is successfully updated.
// key is the bundle entry key (e.g. "namespace/policyName/policy").
type OnBundleUpdate func(key string)

// NewBundleFetcher creates a new BundleFetcher that downloads bundles to bundlePath.
// onChange is called whenever a bundle is updated during polling (not on initial fetch).
func NewBundleFetcher(bundlePath string, onChange OnBundleUpdate) BundleFetcher {
	return &remoteBundleFetcher{
		bundlePath: bundlePath,
		entries:    make(map[string]*fetchEntry),
		onChange:   onChange,
	}
}

type fetchEntry struct {
	url          string
	etag         string
	localPath    string
	pollInterval time.Duration
	timeout      time.Duration
	client       *http.Client
	cancel       context.CancelFunc
}

type remoteBundleFetcher struct {
	bundlePath string
	mu         sync.Mutex
	entries    map[string]*fetchEntry
	onChange   OnBundleUpdate
	ctx        context.Context
	cancel     context.CancelFunc
	started    bool
}

func (f *remoteBundleFetcher) Register(key, remoteURL string, secretData map[string][]byte, pollInterval, timeout time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// If entry exists with same key parameters, just update TLS config
	if existing, ok := f.entries[key]; ok {
		if existing.url == remoteURL && existing.pollInterval == pollInterval && existing.timeout == timeout {
			existing.client = buildHTTPClient(secretData)
			return
		}
		// Parameters changed — stop old poller
		if existing.cancel != nil {
			existing.cancel()
		}
	}

	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}

	entry := &fetchEntry{
		url:          remoteURL,
		localPath:    localPathFromKey(f.bundlePath, key),
		pollInterval: pollInterval,
		timeout:      timeout,
		client:       buildHTTPClient(secretData),
	}
	f.entries[key] = entry

	// If already started, launch a new poller for this entry
	if f.started && f.ctx != nil {
		entryCtx, entryCancel := context.WithCancel(f.ctx)
		entry.cancel = entryCancel
		go f.pollLoop(entryCtx, key, entry)
	}
}

func (f *remoteBundleFetcher) Unregister(key string) {
	f.mu.Lock()
	entry, ok := f.entries[key]
	if ok {
		if entry.cancel != nil {
			entry.cancel()
		}
		delete(f.entries, key)
	}
	f.mu.Unlock()

	if ok {
		// Clean up local file
		os.Remove(entry.localPath) //nolint:errcheck
	}
}

func (f *remoteBundleFetcher) GetLocalPath(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	if entry, ok := f.entries[key]; ok {
		return entry.localPath
	}
	return ""
}

func (f *remoteBundleFetcher) FetchNow(ctx context.Context, key string) (string, error) {
	f.mu.Lock()
	entry, ok := f.entries[key]
	f.mu.Unlock()

	if !ok {
		return "", fmt.Errorf("bundle entry %q not registered", key)
	}

	l := nl.LoggerFromContext(ctx)
	nl.Infof(l, "Fetching remote bundle for %s from %s", key, entry.url)

	fetchCtx, cancel := context.WithTimeout(ctx, initialFetchTimeout)
	defer cancel()

	updated, err := f.fetch(fetchCtx, key, entry)
	if err != nil {
		return entry.localPath, err
	}
	if updated {
		nl.Infof(l, "Remote bundle fetched successfully for %s -> %s", key, entry.localPath)
	} else {
		nl.Infof(l, "Remote bundle unchanged for %s (304 Not Modified)", key)
	}
	return entry.localPath, nil
}

func (f *remoteBundleFetcher) Start(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ctx, f.cancel = context.WithCancel(ctx)
	f.started = true

	for key, entry := range f.entries {
		entryCtx, entryCancel := context.WithCancel(f.ctx)
		entry.cancel = entryCancel
		go f.pollLoop(entryCtx, key, entry)
	}
}

func (f *remoteBundleFetcher) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cancel != nil {
		f.cancel()
	}
	f.started = false
}

func (f *remoteBundleFetcher) pollLoop(ctx context.Context, key string, entry *fetchEntry) {
	l := nl.LoggerFromContext(ctx)
	nl.Infof(l, "Starting bundle poll loop for %s (interval=%s, url=%s)", key, entry.pollInterval, entry.url)
	ticker := time.NewTicker(entry.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			nl.Debugf(l, "Bundle poll loop stopped for %s", key)
			return
		case <-ticker.C:
			nl.Debugf(l, "Polling remote bundle for %s from %s", key, entry.url)
			updated, err := f.fetch(ctx, key, entry)
			if err != nil {
				nl.Warnf(l, "Bundle fetch failed for %s from %s: %v (keeping stale bundle)", key, entry.url, err)
				continue
			}
			if updated {
				nl.Infof(l, "Remote bundle updated for %s -> %s (new ETag detected)", key, entry.localPath)
				// Wait for waf-config-mgr to stabilize after the atomic file replacement
				// before triggering the NGINX reload via onChange.
				select {
				case <-time.After(bundleReloadDelay):
				case <-ctx.Done():
					return
				}
				if f.onChange != nil {
					f.onChange(key)
				}
			} else {
				nl.Infof(l, "Remote bundle unchanged for %s (304 Not Modified)", key)
			}
		}
	}
}

// fetch performs a conditional GET. Returns (true, nil) if the bundle was updated,
// (false, nil) if unchanged (304), or (false, err) on failure.
func (f *remoteBundleFetcher) fetch(ctx context.Context, key string, entry *fetchEntry) (bool, error) {
	if entry.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, entry.timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.url, nil)
	if err != nil {
		return false, fmt.Errorf("creating request: %w", err)
	}

	f.mu.Lock()
	etag := entry.etag
	f.mu.Unlock()

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := entry.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
		return f.handleDownload(key, entry, resp)
	default:
		return false, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, entry.url)
	}
}

func (f *remoteBundleFetcher) handleDownload(key string, entry *fetchEntry, resp *http.Response) (bool, error) {
	// Write to a temp file first for atomic replacement
	tmpFile, err := os.CreateTemp(f.bundlePath, "bundle-*.tmp")
	if err != nil {
		return false, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup on failure
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath) //nolint:errcheck
		}
	}()

	// Limit read size to prevent resource exhaustion
	limitedReader := io.LimitReader(resp.Body, maxBundleSize+1)
	written, err := io.Copy(tmpFile, limitedReader)
	if err != nil {
		tmpFile.Close()
		return false, fmt.Errorf("writing bundle data: %w", err)
	}
	if written > maxBundleSize {
		tmpFile.Close()
		return false, fmt.Errorf("bundle exceeds maximum size of %d bytes", maxBundleSize)
	}
	if err := tmpFile.Close(); err != nil {
		return false, fmt.Errorf("closing temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, entry.localPath); err != nil {
		return false, fmt.Errorf("renaming temp file to %s: %w", entry.localPath, err)
	}
	success = true

	// Update ETag
	newETag := resp.Header.Get("ETag")
	f.mu.Lock()
	entry.etag = newETag
	f.mu.Unlock()

	return true, nil
}

// localPathFromKey derives a stable, unique on-disk filename from the bundle key.
// For example, key "default/waf-policy/policy" -> "{bundlePath}/default-waf-policy-policy.tgz".
// Using the key (not the URL) avoids collisions when two bundles share the same URL path
// component or when using NIM/N1C base URLs that have no meaningful filename.
func localPathFromKey(bundlePath, key string) string {
	safe := strings.NewReplacer("/", "-").Replace(key)
	return path.Join(bundlePath, safe+".tgz")
}

func buildHTTPClient(secretData map[string][]byte) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if secretData != nil {
		// Load client certificate for mTLS
		certPEM, certOK := secretData["tls.crt"]
		keyPEM, keyOK := secretData["tls.key"]
		if certOK && keyOK {
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		// Load custom CA if present
		if caPEM, ok := secretData["ca.crt"]; ok {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caPEM)
			tlsConfig.RootCAs = pool
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 60 * time.Second,
	}
}

// NewFakeBundleFetcher returns a no-op BundleFetcher for testing.
func NewFakeBundleFetcher(bundlePath string) BundleFetcher {
	return &fakeBundleFetcherImpl{bundlePath: bundlePath}
}

type fakeBundleFetcherImpl struct {
	bundlePath string
}

func (f *fakeBundleFetcherImpl) Register(_ string, _ string, _ map[string][]byte, _, _ time.Duration) {
}
func (f *fakeBundleFetcherImpl) Unregister(string) {}
func (f *fakeBundleFetcherImpl) GetLocalPath(key string) string {
	// For tests, derive a stable path from the key since there's no real URL.
	safe := strings.ReplaceAll(key, "/", "-")
	return path.Join(f.bundlePath, safe+".tgz")
}

func (f *fakeBundleFetcherImpl) FetchNow(_ context.Context, key string) (string, error) {
	return f.GetLocalPath(key), nil
}
func (f *fakeBundleFetcherImpl) Start(context.Context) {}
func (f *fakeBundleFetcherImpl) Stop()                 {}
