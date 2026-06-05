//go:build debug

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"k8s.io/client-go/rest"
)

// apiStatsCollector aggregates K8s API call statistics across all clients.
var apiStats = &apiStatsCollector{
	stats:   make(map[string]*callStats),
	started: time.Now(),
}

func init() {
	http.HandleFunc("/debug/api-stats", apiStats.serveHTTP)
	http.HandleFunc("/debug/api-stats/reset", apiStats.serveReset)
}

// wrapTransportWithDebugTracking instruments the rest.Config transport to
// record per-verb, per-resource API call counts and latencies.
// In release builds this is a no-op (see debug_transport_release.go).
func wrapTransportWithDebugTracking(config *rest.Config) {
	existing := config.WrapTransport
	config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if existing != nil {
			rt = existing(rt)
		}
		return &trackingTransport{inner: rt, collector: apiStats}
	}
}

// trackingTransport wraps an http.RoundTripper and records stats for each request.
type trackingTransport struct {
	inner     http.RoundTripper
	collector *apiStatsCollector
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.inner.RoundTrip(req)
	elapsed := time.Since(start)

	isErr := err != nil || (resp != nil && resp.StatusCode >= 400)
	verb, resource, group := classifyRequest(req)
	t.collector.record(verb, resource, group, elapsed, isErr)

	return resp, err
}

// callStats holds per-verb/resource aggregate statistics.
type callStats struct {
	Verb      string
	Resource  string
	Group     string
	Count     int64
	Errors    int64
	TotalTime time.Duration
	MinTime   time.Duration
	MaxTime   time.Duration
	LastCall  time.Time
}

// apiStatsCollector is the shared, concurrency-safe stats store.
type apiStatsCollector struct {
	mu      sync.Mutex
	stats   map[string]*callStats
	total   atomic.Int64
	started time.Time
}

func (c *apiStatsCollector) record(verb, resource, group string, elapsed time.Duration, isErr bool) {
	c.total.Add(1)
	key := verb + " " + resource

	c.mu.Lock()
	defer c.mu.Unlock()

	s, ok := c.stats[key]
	if !ok {
		s = &callStats{
			Verb:     verb,
			Resource: resource,
			Group:    group,
			MinTime:  elapsed,
		}
		c.stats[key] = s
	}
	s.Count++
	s.TotalTime += elapsed
	s.LastCall = time.Now()
	if elapsed < s.MinTime {
		s.MinTime = elapsed
	}
	if elapsed > s.MaxTime {
		s.MaxTime = elapsed
	}
	if isErr {
		s.Errors++
	}
}

func (c *apiStatsCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats = make(map[string]*callStats)
	c.total.Store(0)
	c.started = time.Now()
}

func (c *apiStatsCollector) snapshot() ([]callStats, int64, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]callStats, 0, len(c.stats))
	for _, s := range c.stats {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count
	})
	return out, c.total.Load(), c.started
}

// classifyRequest extracts verb, resource, and API group from a K8s API request.
func classifyRequest(req *http.Request) (verb, resource, group string) {
	path := strings.Trim(req.URL.Path, "/")
	parts := strings.Split(path, "/")

	// Determine API group and skip version prefix.
	//   /api/v1/...               -> group="core",  skip 2
	//   /apis/networking.k8s.io/v1/... -> group="networking.k8s.io", skip 3
	var idx int
	switch {
	case len(parts) >= 2 && parts[0] == "api":
		group = "core"
		idx = 2
	case len(parts) >= 3 && parts[0] == "apis":
		group = parts[1]
		idx = 3
	default:
		return req.Method, path, ""
	}

	if idx >= len(parts) {
		return req.Method, path, group
	}

	// Remaining: [namespaces, <ns>, <resource>, <name>] or [<resource>, <name>]
	remaining := parts[idx:]
	if len(remaining) >= 2 && remaining[0] == "namespaces" {
		remaining = remaining[2:]
	}

	if len(remaining) == 0 {
		return req.Method, path, group
	}
	resource = remaining[0]
	hasName := len(remaining) > 1

	// Classify the verb.
	verb = req.Method
	if req.URL.Query().Get("watch") == "true" {
		verb = "WATCH"
	} else if req.Method == http.MethodGet && !hasName {
		verb = "LIST"
	}

	return verb, resource, group
}

// --- HTTP handlers (served on the pprof :6060 mux) ---

// serveHTTP returns stats as JSON (default) or plain text (?format=text).
func (c *apiStatsCollector) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, total, started := c.snapshot()
	uptime := time.Since(started)

	if r.URL.Query().Get("format") == "text" {
		c.writeText(w, stats, total, uptime)
		return
	}
	c.writeJSON(w, stats, total, uptime)
}

func (c *apiStatsCollector) serveReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST to reset", http.StatusMethodNotAllowed)
		return
	}
	c.reset()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "stats reset")
}

type jsonOutput struct {
	Uptime       string      `json:"uptime"`
	UptimeSec    float64     `json:"uptime_seconds"`
	TotalCalls   int64       `json:"total_calls"`
	APICallStats []jsonEntry `json:"calls"`
}

type jsonEntry struct {
	Verb     string  `json:"verb"`
	Resource string  `json:"resource"`
	Group    string  `json:"group"`
	Count    int64   `json:"count"`
	Errors   int64   `json:"errors"`
	TotalMs  float64 `json:"total_ms"`
	AvgMs    float64 `json:"avg_ms"`
	MinMs    float64 `json:"min_ms"`
	MaxMs    float64 `json:"max_ms"`
	LastCall string  `json:"last_call"`
}

func (c *apiStatsCollector) writeJSON(w http.ResponseWriter, stats []callStats, total int64, uptime time.Duration) {
	entries := make([]jsonEntry, 0, len(stats))
	for _, s := range stats {
		avg := float64(0)
		if s.Count > 0 {
			avg = float64(s.TotalTime.Microseconds()) / float64(s.Count) / 1000
		}
		entries = append(entries, jsonEntry{
			Verb:     s.Verb,
			Resource: s.Resource,
			Group:    s.Group,
			Count:    s.Count,
			Errors:   s.Errors,
			TotalMs:  float64(s.TotalTime.Microseconds()) / 1000,
			AvgMs:    avg,
			MinMs:    float64(s.MinTime.Microseconds()) / 1000,
			MaxMs:    float64(s.MaxTime.Microseconds()) / 1000,
			LastCall: s.LastCall.Format(time.RFC3339),
		})
	}
	out := jsonOutput{
		Uptime:       uptime.Round(time.Second).String(),
		UptimeSec:    uptime.Seconds(),
		TotalCalls:   total,
		APICallStats: entries,
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func (c *apiStatsCollector) writeText(w http.ResponseWriter, stats []callStats, total int64, uptime time.Duration) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	fmt.Fprintf(w, "K8s API Call Statistics\n")
	fmt.Fprintf(w, "Uptime: %s | Total calls: %d\n\n", uptime.Round(time.Second), total)

	if len(stats) == 0 {
		fmt.Fprintln(w, "(no calls recorded)")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VERB\tRESOURCE\tGROUP\tCOUNT\tERRORS\tAVG\tMIN\tMAX\tLAST CALL")
	fmt.Fprintln(tw, "----\t--------\t-----\t-----\t------\t---\t---\t---\t---------")
	for _, s := range stats {
		avg := time.Duration(0)
		if s.Count > 0 {
			avg = s.TotalTime / time.Duration(s.Count)
		}
		ago := time.Since(s.LastCall).Round(time.Second)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s ago\n",
			s.Verb, s.Resource, s.Group,
			s.Count, s.Errors,
			fmtDuration(avg), fmtDuration(s.MinTime), fmtDuration(s.MaxTime),
			ago,
		)
	}
	tw.Flush()
}

// fmtDuration formats a duration in a compact, human-readable way.
func fmtDuration(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.0fus", float64(d.Microseconds()))
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return d.Round(time.Millisecond).String()
	}
}
