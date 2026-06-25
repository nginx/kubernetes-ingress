package collectors

import (
	"context"
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestLatencyMetricsCollector() *LatencyMetricsCollector {
	return &LatencyMetricsCollector{
		upstreamServerLabels:         make(map[string][]string),
		upstreamServerPeerLabels:     make(map[string][]string),
		metricsPublishedMap:          make(metricsPublishedMap),
		upstreamServerLabelNames:     []string{"service", "resource_type", "resource_name", "resource_namespace"},
		upstreamServerPeerLabelNames: []string{"pod_name"},
	}
}

func TestParseMessageWithValidInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		msg         string
		expectedErr bool
		expected    latencyMetric
	}{
		{
			msg:         `nginx: {"upstreamAddress":"10.0.0.1", "upstreamResponseTime":"0.003", "proxyHost":"upstream-1", "upstreamStatus": "200"}`,
			expectedErr: false,
			expected: latencyMetric{
				Upstream: "upstream-1",
				Server:   "10.0.0.1",
				Latency:  0.003,
				Code:     "200",
			},
		},
		{
			msg:         `nginx: {"upstreamAddress":"127.0.0.1:6001, 127.0.0.1:6002, 127.0.0.1:8001", "upstreamResponseTime":"0.9, 0.99, 0.1", "proxyHost":"upstream-1", "upstreamStatus": "500, 500, 200"}`,
			expectedErr: false,
			expected: latencyMetric{
				Upstream: "upstream-1",
				Server:   "127.0.0.1:8001",
				Latency:  0.1,
				Code:     "200",
			},
		},
		{
			msg:         `nginx: {"upstreamAddress":"upstream-1", "upstreamResponseTime":"0.0", "proxyHost":"upstream-1", "upstreamStatus": "404"}`,
			expectedErr: true,
		},
		{
			msg:         `nginx: {"upstreamAddress":"-", "upstreamResponseTime":"0.0", "proxyHost":"-", "upstreamStatus": "404"}`,
			expectedErr: true,
		},
		{
			msg:         `nginx: {"upstreamAddress":"10.0.0.1", "upstreamResponseTime":"not-a-float", "proxyHost":"upstream-1", "upstreamStatus": "404"}`,
			expectedErr: true,
		},
		{
			msg:         `wrong format`,
			expectedErr: true,
		},
		{
			msg:         `nginx: {"badJson}`,
			expectedErr: true,
		},
	}
	for _, test := range tests {
		actual, err := parseMessage(test.msg)
		if test.expectedErr {
			if err == nil {
				t.Errorf("parseMessage should return an error, got nil")
			}
		} else {
			if err != nil {
				t.Fatalf("parseMessage returned an unexpected error: %v", err)
			}
			if actual != test.expected {
				t.Errorf("parseMessage returned: %+v, expected: %+v", actual, test.expected)
			}
		}
	}
}

func TestCreateLatencyLabelNames(t *testing.T) {
	t.Parallel()
	expected := []string{"upstream", "server", "code", "one", "two", "three", "four", "five"}
	actual := createLatencyLabelNames([]string{"one", "two", "three"}, []string{"four", "five"})
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("createLatencyLabelNames returned: %v, expected: %v", actual, expected)
	}
}

func TestCreateLatencyLabelNamesWithNilInputs(t *testing.T) {
	t.Parallel()
	expected := []string{"upstream", "server", "code"}
	actual := createLatencyLabelNames(nil, nil)
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("createLatencyLabelNames returned: %v, expected: %v", actual, expected)
	}
}

func TestCreateLatencyLabelValuesWithCorrectNumberOfLabels(t *testing.T) {
	t.Parallel()
	collector := newTestLatencyMetricsCollector()
	collector.upstreamServerLabels["upstream-1"] = []string{"service-1", "ingress", "ingress-1", "default"}
	collector.upstreamServerPeerLabels["upstream-1/10.0.0.1"] = []string{"pod-1"}

	lm := latencyMetric{
		Upstream: "upstream-1",
		Server:   "10.0.0.1",
		Code:     "200",
	}
	expected := []string{"upstream-1", "10.0.0.1", "200", "service-1", "ingress", "ingress-1", "default", "pod-1"}
	actual, err := collector.createLatencyLabelValues(lm)
	if err != nil {
		t.Fatalf("createLatencyLabelValues returned unexpected error: %v", err)
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("createLatencyLabelValues returned: %v, expected: %v", actual, expected)
	}
}

func TestCreateLatencyLabelValuesWithNoUpstreamServerLabels(t *testing.T) {
	t.Parallel()
	collector := newTestLatencyMetricsCollector()
	collector.upstreamServerPeerLabels["upstream-1/10.0.0.1"] = []string{"pod-1"}
	lm := latencyMetric{
		Upstream: "upstream-1",
		Server:   "10.0.0.1",
		Code:     "200",
	}
	_, err := collector.createLatencyLabelValues(lm)
	if err == nil {
		t.Error("createLatencyLabelValues should have returned an error, got nil")
	}
}

func TestCreateLatencyLabelValuesWithNoUpstreamPeerServerLabels(t *testing.T) {
	t.Parallel()
	collector := newTestLatencyMetricsCollector()
	collector.upstreamServerLabels["upstream-1"] = []string{"service-1", "ingress", "ingress-1", "default"}
	lm := latencyMetric{
		Upstream: "upstream-1",
		Server:   "10.0.0.1",
		Code:     "200",
	}
	_, err := collector.createLatencyLabelValues(lm)
	if err == nil {
		t.Error("createLatencyLabelValues should have returned an error, got nil")
	}
}

func TestCreateLatencyLabelValuesWithNoLabels(t *testing.T) {
	t.Parallel()
	collector := newTestLatencyMetricsCollector()
	lm := latencyMetric{
		Upstream: "upstream-1",
		Server:   "10.0.0.1",
		Code:     "200",
	}
	_, err := collector.createLatencyLabelValues(lm)
	if err == nil {
		t.Error("createLatencyLabelValues should have returned an error, got nil")
	}
}

func TestMetricsPublished(t *testing.T) {
	t.Parallel()
	collector := newTestLatencyMetricsCollector()
	labelValueList1 := []string{"label-value-1", "label-value-2", "label-value-3"}
	labelValueList2 := []string{"new-label-value-1", "new-label-value-2", "new-label-value-3"}
	// add metric for upstream-1
	collector.updateMetricsPublished("upstream-1", "10.0.0.0:80", labelValueList1)
	// add the same metric
	collector.updateMetricsPublished("upstream-1", "10.0.0.0:80", labelValueList1)
	// add a new metric for upstream-1
	collector.updateMetricsPublished("upstream-1", "10.0.0.0:80", labelValueList2)
	// add metric for upstream-2
	collector.updateMetricsPublished("upstream-2", "10.0.0.0:80", labelValueList1)

	if l := len(collector.metricsPublishedMap); l != 2 {
		t.Errorf("updateMetricsPublished did not update metricsPublishedMap map correctly, length is %d expected 2", l)
	}

	// verify metrics for upstream-1 are correct
	upstream1Metrics, ok := collector.metricsPublishedMap["upstream-1/10.0.0.0:80"]
	if !ok {
		t.Fatal("updateMetricsPublished did not add upstream-1 as key to map")
	}
	if l := len(upstream1Metrics); l != 2 {
		t.Errorf("updateMetricsPublished did not update upstream-1 map correctly, length is %d expected 2", l)
	}

	// call list and delete
	labelValuesUpstream1 := collector.listAndDeleteMetricsPublished("upstream-1/10.0.0.0:80")
	if l := len(labelValuesUpstream1); l != 2 {
		t.Errorf("listAndDeleteMetricsPublished return a list of length %d for upstream-1, expected 2", l)
	}
	if !contains(labelValueList1, labelValuesUpstream1) {
		t.Errorf("listAndDeleteMetricsPublished did not return metric labels %v in list %v", labelValueList1, labelValuesUpstream1)
	}
	if !contains(labelValueList2, labelValuesUpstream1) {
		t.Errorf("listAndDeleteMetricsPublished did not return metric labels %v in list %v", labelValueList2, labelValuesUpstream1)
	}
	if _, ok := collector.metricsPublishedMap["upstream-1/10.0.0.0:80"]; ok {
		t.Errorf("listAndDeleteMetricsPublished did not delete upstream-1 from map")
	}

	// verify metrics for upstream-2 are correct
	upstream2Metrics, ok := collector.metricsPublishedMap["upstream-2/10.0.0.0:80"]
	if !ok {
		t.Fatal("updateMetricsPublished did not add upstream-2 as key to map")
	}
	if l := len(upstream2Metrics); l != 1 {
		t.Errorf("updateMetricsPublished did not update upstream-2 map correctly, length is %d expected 1", l)
	}

	// call list and delete
	labelValuesUpstream2 := collector.listAndDeleteMetricsPublished("upstream-2/10.0.0.0:80")
	if l := len(labelValuesUpstream2); l != 1 {
		t.Errorf("listAndDeleteMetricsPublished return a list of length %d for upstream-2, expected 1", l)
	}
	if !reflect.DeepEqual(labelValuesUpstream2[0], labelValueList1) {
		t.Errorf("listAndDeleteMetricsPublished returned %v for upstream-2, expected: %v", labelValueList1, labelValuesUpstream2[0])
	}
	if _, ok := collector.metricsPublishedMap["upstream-2/10.0.0.0:80"]; ok {
		t.Errorf("listAndDeleteMetricsPublished did not delete upstream-2 from map")
	}

	// double check map is empty
	if l := len(collector.metricsPublishedMap); l != 0 {
		t.Errorf("listAndDeleteMetricsPublished did not delete upstreams from map")
	}
}

func contains(x []string, y [][]string) bool {
	for _, l := range y {
		if reflect.DeepEqual(x, l) {
			return true
		}
	}
	return false
}

// gatherLatencyBucketBounds builds a LatencyMetricsCollector with the given
// buckets, records a single observation and returns the upper bounds of the
// resulting upstream_server_response_latency_ms histogram.
func gatherLatencyBucketBounds(t *testing.T, buckets []float64) []float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	lc := NewLatencyMetricsCollector(context.Background(), nil, nil, nil, buckets)
	if err := lc.Register(registry); err != nil {
		t.Fatalf("could not register latency collector: %v", err)
	}
	lc.RecordLatency(`nginx:{"proxyHost":"upstream1","upstreamAddress":"10.0.0.1:80","upstreamStatus":"200","upstreamResponseTime":"0.05"}`)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("could not gather metrics: %v", err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			h := m.GetHistogram()
			if h == nil {
				continue
			}
			bounds := make([]float64, 0, len(h.GetBucket()))
			for _, b := range h.GetBucket() {
				bounds = append(bounds, b.GetUpperBound())
			}
			return bounds
		}
	}
	t.Fatal("no histogram metric was collected")
	return nil
}

func TestNewLatencyMetricsCollectorUsesCustomBuckets(t *testing.T) {
	t.Parallel()
	custom := []float64{10, 100, 1000}
	got := gatherLatencyBucketBounds(t, custom)
	if !reflect.DeepEqual(got, custom) {
		t.Errorf("expected custom buckets %v, got %v", custom, got)
	}
}

func TestNewLatencyMetricsCollectorFallsBackToDefaultBuckets(t *testing.T) {
	t.Parallel()
	got := gatherLatencyBucketBounds(t, nil)
	if !reflect.DeepEqual(got, DefaultLatencyBuckets) {
		t.Errorf("expected default buckets %v, got %v", DefaultLatencyBuckets, got)
	}
}
