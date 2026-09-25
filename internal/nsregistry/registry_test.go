package nsregistry

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// testInformer stands in for the informer group each consumer registers. The
// registry never looks inside it.
type testInformer struct {
	namespace string
}

func TestGetReturnsNilForUnwatchedNamespace(t *testing.T) {
	t.Parallel()

	r := New[testInformer]()
	r.Set("watched", &testInformer{namespace: "watched"})

	if got := r.Get("watched"); got == nil {
		t.Fatal("Get(watched) returned nil, want the registered informer")
	}
	if got := r.Get("not-watched"); got != nil {
		t.Errorf("Get(not-watched) = %v, want nil", got)
	}
}

func TestGetPrefersGlobalNamespace(t *testing.T) {
	t.Parallel()

	global := &testInformer{}
	r := New[testInformer]()
	r.Set("", global)

	// A registry holding the global entry watches every namespace, so any
	// lookup must resolve to it rather than reporting the namespace unwatched.
	for _, ns := range []string{"", "anything", "other"} {
		if got := r.Get(ns); got != global {
			t.Errorf("Get(%q) = %v, want the global informer", ns, got)
		}
	}
}

func TestWithInformerReportsWatchedState(t *testing.T) {
	t.Parallel()

	r := New[testInformer]()
	r.Set("watched", &testInformer{namespace: "watched"})

	var seen string
	if ok := r.WithInformer("watched", func(nsi *testInformer) { seen = nsi.namespace }); !ok {
		t.Error("WithInformer(watched) = false, want true")
	}
	if seen != "watched" {
		t.Errorf("callback saw namespace %q, want \"watched\"", seen)
	}

	called := false
	if ok := r.WithInformer("not-watched", func(*testInformer) { called = true }); ok {
		t.Error("WithInformer(not-watched) = true, want false")
	}
	if called {
		t.Error("callback ran for an unwatched namespace")
	}
}

func TestRemoveReturnsInformerAndUnregisters(t *testing.T) {
	t.Parallel()

	r := New[testInformer]()
	doomed := &testInformer{namespace: "doomed"}
	r.Set("doomed", doomed)

	if got := r.Remove("doomed"); got != doomed {
		t.Errorf("Remove returned %v, want the registered informer", got)
	}
	if got := r.Get("doomed"); got != nil {
		t.Errorf("Get after Remove = %v, want nil", got)
	}
	if got := r.Len(); got != 0 {
		t.Errorf("Len after Remove = %d, want 0", got)
	}
	if got := r.Remove("doomed"); got != nil {
		t.Errorf("second Remove returned %v, want nil", got)
	}
}

func TestForEachVisitsEveryInformer(t *testing.T) {
	t.Parallel()

	r := New[testInformer]()
	r.Set("one", &testInformer{namespace: "one"})
	r.Set("two", &testInformer{namespace: "two"})

	seen := map[string]bool{}
	r.ForEach(func(nsi *testInformer) { seen[nsi.namespace] = true })

	if len(seen) != 2 || !seen["one"] || !seen["two"] {
		t.Errorf("ForEach visited %v, want one and two", seen)
	}
}

// TestRemoveWaitsForInFlightReader is the reason WithInformer exists: an
// informer must not be removed, and so must not be stopped by the caller, while
// a reader is still inside it. The callback blocks here to make the ordering
// observable, which a real caller must not do.
func TestRemoveWaitsForInFlightReader(t *testing.T) {
	t.Parallel()

	r := New[testInformer]()
	r.Set("ns", &testInformer{namespace: "ns"})

	entered := make(chan struct{})
	release := make(chan struct{})
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)
		r.WithInformer("ns", func(*testInformer) {
			close(entered)
			<-release
		})
	}()
	<-entered

	removed := make(chan *testInformer, 1)
	go func() { removed <- r.Remove("ns") }()

	select {
	case <-removed:
		t.Fatal("Remove returned while a reader was still inside WithInformer")
	case <-time.After(100 * time.Millisecond):
		// still blocked, which is the behavior under test
	}

	close(release)
	<-readerDone

	select {
	case nsi := <-removed:
		if nsi == nil {
			t.Error("Remove returned nil, want the registered informer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Remove did not return after the reader released")
	}
}

// TestConcurrentAccess exercises the registry under simultaneous reads and
// writes, mirroring how the consumers use it. Run under -race.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	const namespaces = 32
	const reads = 2000
	const workers = 10

	r := New[testInformer]()

	var writer, readers sync.WaitGroup
	stop := make(chan struct{})

	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ns := fmt.Sprintf("ns-%d", i%namespaces)
			r.Set(ns, &testInformer{namespace: ns})
			r.Remove(ns)
		}
	}()

	for w := 0; w < workers; w++ {
		readers.Add(1)
		go func(worker int) {
			defer readers.Done()
			for i := 0; i < reads; i++ {
				ns := fmt.Sprintf("ns-%d", (i+worker)%namespaces)
				r.Get(ns)
				r.WithInformer(ns, func(*testInformer) {})
				r.ForEach(func(*testInformer) {})
				r.Len()
			}
		}(w)
	}

	readers.Wait()
	close(stop)
	writer.Wait()
}
