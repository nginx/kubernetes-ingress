package wafbundle

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// Manager manages the lifecycle of per-Policy bundle pollers.
type Manager interface {
	ReconcilePoller(polKey string, sources []PollSource)
	StopPoller(polKey string)
	StopAll()
}

// PollSource describes one bundle to be fetched and kept current by a poller.
type PollSource struct {
	Filename string
	Kind     BundleType
	Req      Request
	Interval time.Duration
}

// SyncCallback is called after a successful bundle update to trigger a policy re-sync.
type SyncCallback func(polKey string)

type pollerManager struct {
	mu         sync.Mutex
	pollers    map[string]*activePoller
	fetcher    Fetcher
	bundlePath string
	syncCb     SyncCallback
	logger     *slog.Logger
}

type activePoller struct {
	cancel  context.CancelFunc
	sources []PollSource
}

// NewPollerManager creates a Manager.
func NewPollerManager(fetcher Fetcher, bundlePath string, syncCb SyncCallback, logger *slog.Logger) Manager {
	return &pollerManager{
		pollers:    make(map[string]*activePoller),
		fetcher:    fetcher,
		bundlePath: bundlePath,
		syncCb:     syncCb,
		logger:     logger,
	}
}

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

func (m *pollerManager) StopPoller(polKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ap, ok := m.pollers[polKey]; ok {
		ap.cancel()
		delete(m.pollers, polKey)
	}
}

func (m *pollerManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, ap := range m.pollers {
		ap.cancel()
		delete(m.pollers, key)
	}
}

func (m *pollerManager) runPoller(ctx context.Context, polKey string, sources []PollSource) {
	if len(sources) == 0 {
		return
	}
	type tick struct{ idx int }
	tickCh := make(chan tick, len(sources))

	tickers := make([]*time.Ticker, len(sources))
	for i, src := range sources {
		interval := src.Interval
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

func (m *pollerManager) pollSource(ctx context.Context, polKey string, src *PollSource) {
	fetchCtx, cancel := context.WithTimeout(ctx, effectiveTimeout(&src.Req))
	defer cancel()

	var result Result
	var err error
	if src.Kind == LogProfileBundle {
		result, err = m.fetcher.FetchLogProfileBundle(fetchCtx, &src.Req)
	} else {
		result, err = m.fetcher.FetchPolicyBundle(fetchCtx, &src.Req)
	}

	if err != nil {
		nl.Warnf(m.logger, "bundle re-fetch failed for policy %s file %s (keeping existing bundle): %v",
			polKey, src.Filename, err)
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

	src.Req.LastHash = result.Checksum
	if result.ETag != "" {
		src.Req.ETag = result.ETag
	}
	if result.LastModified != "" {
		src.Req.LastModified = result.LastModified
	}

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

func pollSourcesEqual(a, b []PollSource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Filename != b[i].Filename ||
			a[i].Kind != b[i].Kind ||
			a[i].Interval != b[i].Interval ||
			a[i].Req.URL != b[i].Req.URL ||
			a[i].Req.Type != b[i].Req.Type ||
			a[i].Req.PolicyName != b[i].Req.PolicyName ||
			a[i].Req.PolicyNamespace != b[i].Req.PolicyNamespace {
			return false
		}
	}
	return true
}
