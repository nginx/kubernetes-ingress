package wafbundle

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// Mutex (sync.Mutex) prevents data races when multiple goroutines access the same data.
// Without it, concurrent reads and writes to the same field can corrupt data.

// Manager manages the lifecycle of per-Policy bundle pollers.
type Manager interface {
	ReconcilePoller(polKey string, sources []PollSource)
	StopPoller(polKey string)
	StopAll()
}

// PollSource describes one bundle to be fetched and kept current by a poller.
// mu protects concurrent access: poller goroutines and sync queue workers both read/write Req and disabled.
type PollSource struct {
	mu       sync.Mutex
	Filename string
	Kind     BundleType
	Req      Request
	Interval time.Duration
	disabled bool // set when a non-transient error is encountered; skips future polls
}

// SyncCallback is called after a successful bundle update to trigger a policy re-sync.
type SyncCallback func(polKey string)

// RefreshErrorCallback is called when a background re-fetch fails.
// Implementations can surface warnings without interrupting active traffic.
type RefreshErrorCallback func(polKey string, err error)

type pollerManager struct {
	mu         sync.Mutex
	pollers    map[string]*activePoller
	fetcher    Fetcher
	bundlePath string
	syncCb     SyncCallback
	errorCb    RefreshErrorCallback
	logger     *slog.Logger
}

// activePoller represents a running poller goroutine for a single Policy.
// It holds cancel to stop the poller and sources to poll.
type activePoller struct {
	cancel  context.CancelFunc
	sources []PollSource
}

// NewPollerManager creates a Manager that orchestrates background polling of WAF bundles.
// It manages one poller goroutine per Policy, each polling one or more bundle sources
// at configured intervals. When a bundle is successfully fetched and differs from the
// previous version, the poller invokes syncCb to trigger policy re-sync. Non-transient
// fetch errors invoke errorCb to allow the caller to surface warnings.
func NewPollerManager(fetcher Fetcher, bundlePath string, syncCb SyncCallback, errorCb RefreshErrorCallback, logger *slog.Logger) Manager {
	return &pollerManager{
		pollers:    make(map[string]*activePoller),
		fetcher:    fetcher,
		bundlePath: bundlePath,
		syncCb:     syncCb,
		errorCb:    errorCb,
		logger:     logger,
	}
}

// ReconcilePoller creates or updates a background poller for the given Policy key.
// If a poller already exists for this key:
//   - It compares the new sources against the existing ones (ignoring runtime-mutable
//     fields like LastHash, ETag, LastModified so that config changes trigger restart)
//   - If config has changed, it stops the old poller and starts a new one
//   - If config is unchanged, it returns without restarting (preserves poller state)
//
// If no poller exists, it creates a new one.
// Sources are polled on configured intervals; successful updates trigger syncCb.
func (m *pollerManager) ReconcilePoller(polKey string, sources []PollSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.pollers[polKey]; ok {
		if pollSourcesEqual(existing.sources, sources) {
			return
		}
		existing.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.pollers[polKey] = &activePoller{cancel: cancel, sources: sources}
	go m.runPoller(ctx, polKey, sources)
}

// StopPoller stops the background poller for the given Policy key (if running).
func (m *pollerManager) StopPoller(polKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ap, ok := m.pollers[polKey]; ok {
		ap.cancel()
		delete(m.pollers, polKey)
	}
}

// StopAll stops all running pollers and cleans up the manager.
func (m *pollerManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, ap := range m.pollers {
		ap.cancel()
		delete(m.pollers, key)
	}
}

// runPoller coordinates background polling of multiple bundle sources for a single Policy.
// It maintains one ticker per source at the configured interval. When a ticker fires,
// pollSource is invoked to fetch that bundle. The poller runs until ctx is canceled.
func (m *pollerManager) runPoller(ctx context.Context, polKey string, sources []PollSource) {
	if len(sources) == 0 {
		return
	}
	type tick struct{ idx int }
	tickCh := make(chan tick, len(sources))

	tickers := make([]*time.Ticker, len(sources))
	for i := range sources {
		interval := sources[i].Interval
		if interval <= 0 {
			interval = DefaultPollInterval
		}
		t := time.NewTicker(interval)
		tickers[i] = t
		go func(i int, t *time.Ticker) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					select {
					case tickCh <- tick{idx: i}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(i, t)
	}
	defer func() {
		for _, t := range tickers {
			t.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case tk := <-tickCh:
			m.pollSource(ctx, polKey, &sources[tk.idx])
		}
	}
}

// pollSource fetches one bundle from its configured source and updates it on disk if changed.
// It handles transient fetch errors gracefully (logs warning, keeps existing bundle) and
// permanent errors by marking the source as disabled (stops future polls).
// Thread-safe: acquires src.mu when reading LastHash/ETag/LastModified and when writing updates.
// After a successful fetch and write:
//  1. Updates src.Req tracking fields (LastHash, ETag, LastModified) under lock
//  2. Waits for BundleReloadDelay (stabilization window for NGINX to re-read inode)
//  3. Invokes syncCb to trigger policy re-sync
func (m *pollerManager) pollSource(ctx context.Context, polKey string, src *PollSource) {
	src.mu.Lock()
	if src.disabled {
		src.mu.Unlock()
		return
	}
	// Copy Req under lock to safely read fields that poller might mutate.
	// Fetch outside lock to avoid blocking other pollers.
	reqCopy := src.Req
	src.mu.Unlock()
	fetchCtx, cancel := context.WithTimeout(ctx, effectiveTimeout(&reqCopy))
	defer cancel()

	var result Result
	var err error
	if src.Kind == LogProfileBundle {
		result, err = m.fetcher.FetchLogProfileBundle(fetchCtx, &reqCopy)
	} else {
		result, err = m.fetcher.FetchPolicyBundle(fetchCtx, &reqCopy)
	}

	if err != nil {
		if isNonTransient(err) {
			nl.Warnf(m.logger, "permanent fetch failure for policy %s file %s — stopping poll (re-apply policy to retry): %v",
				polKey, src.Filename, err)
			// Mark disabled under lock to prevent data race with sync queue.
			src.mu.Lock()
			src.disabled = true
			src.mu.Unlock()
		} else {
			nl.Warnf(m.logger, "bundle re-fetch failed for policy %s file %s (keeping existing bundle): %v",
				polKey, src.Filename, err)
		}
		if m.errorCb != nil {
			m.errorCb(polKey, err)
		}
		return
	}
	if result.Unchanged {
		return
	}

	destPath := filepath.Join(m.bundlePath, src.Filename)
	if err := writeAtomic(destPath, result.Data); err != nil {
		nl.Errorf(m.logger, "failed to write bundle to disk for policy %s path %s: %v",
			polKey, destPath, err)
		return
	}

	// Update tracking fields under lock so sync queue sees consistent state.
	src.mu.Lock()
	src.Req.LastHash = result.Checksum
	if result.ETag != "" {
		src.Req.ETag = result.ETag
	}
	if result.LastModified != "" {
		src.Req.LastModified = result.LastModified
	}
	src.mu.Unlock()

	if reloadDelay := bundleReloadDelay(); reloadDelay > 0 {
		select {
		case <-time.After(reloadDelay):
		case <-ctx.Done():
			return
		}
	}

	nl.Infof(m.logger, "bundle updated for policy %s file %s, triggering policy re-sync",
		polKey, src.Filename)
	m.syncCb(polKey)
}

// writeAtomic writes data to a temporary file, then atomically renames it to dst.
// This prevents partial writes or reads of incomplete bundle files if the process
// crashes mid-write or NGINX reloads before the write completes.
func writeAtomic(dst string, data []byte) error {
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temp bundle file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming bundle to %s: %w", dst, err)
	}
	return nil
}

// pollSourcesEqual compares two PollSource slices for config equality.
// Mutable fields are zeroed before comparison so only config changes trigger restart.
func pollSourcesEqual(a, b []PollSource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		// Extract fields under lock to safely read without concurrent mutations.
		a[i].mu.Lock()
		aFilename, aKind, aReq, aInterval, aDisabled := a[i].Filename, a[i].Kind, a[i].Req, a[i].Interval, a[i].disabled
		a[i].mu.Unlock()

		b[i].mu.Lock()
		bFilename, bKind, bReq, bInterval, bDisabled := b[i].Filename, b[i].Kind, b[i].Req, b[i].Interval, b[i].disabled
		b[i].mu.Unlock()

		// Zero mutable fields before comparing so runtime state changes don't trigger restart.
		aReq.LastHash, bReq.LastHash = "", ""
		aReq.ETag, bReq.ETag = "", ""
		aReq.LastModified, bReq.LastModified = "", ""

		// Compare fields.
		if aFilename != bFilename || aKind != bKind || aInterval != bInterval || aDisabled != bDisabled ||
			!reflect.DeepEqual(aReq, bReq) {
			return false
		}
	}
	return true
}
