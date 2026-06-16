package wafbundle

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeFetcher struct {
	mu           sync.Mutex
	policyResult Result
	policyErr    error
	callCount    atomic.Int32
}

func (f *fakeFetcher) FetchPolicyBundle(_ context.Context, _ *Request) (Result, error) {
	f.callCount.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policyResult, f.policyErr
}

func (f *fakeFetcher) FetchLogProfileBundle(_ context.Context, _ *Request) (Result, error) {
	f.callCount.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policyResult, f.policyErr
}

func (f *fakeFetcher) set(r Result, err error) {
	f.mu.Lock()
	f.policyResult = r
	f.policyErr = err
	f.mu.Unlock()
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func init() {
	// Skip the 2s waf-config-mgr stabilization delay in tests.
	zero := time.Duration(0)
	testBundleReloadDelay = &zero
}

func TestPoller_WritesBundle_OnUpdate(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	data := []byte("updated-bundle")
	ff := &fakeFetcher{}
	ff.set(Result{Data: data, Checksum: ComputeChecksum(data)}, nil)

	syncCalled := make(chan string, 1)
	mgr := NewPollerManager(ff, tmpDir, func(key string) { syncCalled <- key }, nil, testLogger())

	const polKey = "default/waf-policy"
	filename := FetchedBundleFilename("default", "waf-policy", "policy")
	mgr.ReconcilePoller(polKey, []PollSource{{
		Filename: filename, Kind: PolicyBundle,
		Req:      Request{Type: SourceTypeHTTPS, URL: "https://example.com/b.tgz"},
		Interval: 50 * time.Millisecond,
	}})
	defer mgr.StopAll()

	select {
	case key := <-syncCalled:
		if key != polKey {
			t.Errorf("got sync key %q, want %q", key, polKey)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for syncCallback")
	}

	/* #nosec G304 */
	got, err := os.ReadFile(filepath.Join(tmpDir, filename))
	if err != nil {
		t.Fatalf("bundle file not written: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestPoller_NoSync_WhenUnchanged(t *testing.T) {
	t.Parallel()
	ff := &fakeFetcher{}
	ff.set(Result{Unchanged: true}, nil)
	synced := atomic.Int32{}
	mgr := NewPollerManager(ff, t.TempDir(), func(_ string) { synced.Add(1) }, nil, testLogger())
	mgr.ReconcilePoller("ns/pol", []PollSource{{
		Filename: FetchedBundleFilename("ns", "pol", "policy"), Kind: PolicyBundle,
		Req: Request{Type: SourceTypeHTTPS}, Interval: 30 * time.Millisecond,
	}})
	time.Sleep(200 * time.Millisecond)
	mgr.StopAll()
	if synced.Load() != 0 {
		t.Errorf("syncCallback called %d times, want 0", synced.Load())
	}
}

func TestPoller_NoSync_OnFetchError(t *testing.T) {
	t.Parallel()
	ff := &fakeFetcher{}
	ff.set(Result{}, &nonTransientError{cause: simpleErr("server down")})
	synced := atomic.Int32{}
	refreshErr := make(chan struct{}, 1)
	mgr := NewPollerManager(
		ff,
		t.TempDir(),
		func(_ string) { synced.Add(1) },
		func(_ string, err error) {
			if err != nil {
				select {
				case refreshErr <- struct{}{}:
				default:
				}
			}
		},
		testLogger(),
	)
	mgr.ReconcilePoller("ns/pol", []PollSource{{
		Filename: FetchedBundleFilename("ns", "pol", "policy"), Kind: PolicyBundle,
		Req: Request{Type: SourceTypeHTTPS}, Interval: 30 * time.Millisecond,
	}})
	time.Sleep(200 * time.Millisecond)
	mgr.StopAll()
	if synced.Load() != 0 {
		t.Errorf("syncCallback called %d times on error, want 0", synced.Load())
	}
	select {
	case <-refreshErr:
	case <-time.After(1 * time.Second):
		t.Fatal("expected refresh error callback to be called")
	}
}

func TestPoller_StopPoller_CancelsGoroutine(t *testing.T) {
	t.Parallel()
	ff := &fakeFetcher{}
	ff.set(Result{Unchanged: true}, nil)
	mgr := NewPollerManager(ff, t.TempDir(), func(_ string) {}, nil, testLogger())
	mgr.ReconcilePoller("ns/pol", []PollSource{{
		Filename: FetchedBundleFilename("ns", "pol", "policy"),
		Kind:     PolicyBundle,
		Req:      Request{Type: SourceTypeHTTPS},
		Interval: 50 * time.Millisecond,
	}})
	// Let it fire a few times to confirm it's running.
	time.Sleep(200 * time.Millisecond)
	mgr.StopPoller("ns/pol")
	// Give the goroutine time to see the cancellation.
	time.Sleep(20 * time.Millisecond)
	before := ff.callCount.Load()
	// Wait well past one interval — no new calls should occur.
	time.Sleep(200 * time.Millisecond)
	after := ff.callCount.Load()
	if after != before {
		t.Errorf("fetcher called after StopPoller: before=%d after=%d", before, after)
	}
}

func TestPoller_ReconcilePoller_ReplacesOnChange(t *testing.T) {
	t.Parallel()
	ff := &fakeFetcher{}
	ff.set(Result{Unchanged: true}, nil)
	mgr := NewPollerManager(ff, t.TempDir(), func(_ string) {}, nil, testLogger())
	defer mgr.StopAll()
	src1 := []PollSource{{
		Filename: FetchedBundleFilename("ns", "pol", "policy"), Kind: PolicyBundle,
		Req: Request{Type: SourceTypeHTTPS, URL: "https://example.com/v1.tgz"}, Interval: 30 * time.Millisecond,
	}}
	src2 := []PollSource{{
		Filename: FetchedBundleFilename("ns", "pol", "policy"), Kind: PolicyBundle,
		Req: Request{Type: SourceTypeHTTPS, URL: "https://example.com/v2.tgz"}, Interval: 30 * time.Millisecond,
	}}
	mgr.ReconcilePoller("ns/pol", src1)
	time.Sleep(50 * time.Millisecond)
	mgr.ReconcilePoller("ns/pol", src2) // should replace cleanly
}

func TestPoller_WriteAtomic_NoTempFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, "bundle.tgz")
	if err := writeAtomic(dst, []byte("content")); err != nil {
		t.Fatalf("writeAtomic error: %v", err)
	}
	/* #nosec G304 */
	got, _ := os.ReadFile(dst)
	if string(got) != "content" {
		t.Errorf("got %q", got)
	}
	entries, _ := os.ReadDir(tmpDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
