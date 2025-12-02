package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
)

const nginxSeparator = "nginx:"

var latencyBucketsMilliSeconds = []float64{
	1,
	2,
	3,
	4,
	5,
	10,
	20,
	30,
	40,
	50,
	100,
	200,
	300,
	400,
	500,
	1000,
	2000,
	3000,
	4000,
	5000,
	10000,
	20000,
	30000,
	40000,
	50000,
}

// LatencyCollector is an interface for latency metrics
type LatencyCollector interface {
	RecordLatency(string)
	UpdateUpstreamServerLabels(map[string][]string)
	DeleteUpstreamServerLabels([]string)
	UpdateUpstreamServerPeerLabels(map[string][]string)
	DeleteUpstreamServerPeerLabels([]string)
	DeleteMetrics([]string)
	Register(*prometheus.Registry) error
}

// metricsPublishedMap is a map of upstream server peers (upstream/server) to a metricsSet.
// This map is used to keep track of all the metrics published for each upstream server peer,
// so that the metrics can be deleted when the upstream server peers are deleted.
type metricsPublishedMap map[string]metricsSet

// metricsSet is a set of metrics published.
// The keys are string representations of the lists of label values for a published metric.
// The list of label values is joined with the "+" symbol. For example, a metric produced with the label values
// ["one", "two", "three"] is added to the set with the key "one+two+three".
type metricsSet map[string]struct{}

// LatencyMetricsCollector implements the LatencyCollector interface and prometheus.Collector interface
type LatencyMetricsCollector struct {
	httpLatency                  *prometheus.HistogramVec
	upstreamServerLabelNames     []string
	upstreamServerPeerLabelNames []string
	upstreamServerLabels         map[string][]string
	upstreamServerPeerLabels     map[string][]string
	metricsPublishedMap          metricsPublishedMap
	metricsPublishedMutex        sync.Mutex
	variableLabelsMutex          sync.RWMutex
	logger                       *slog.Logger
}

// NewLatencyMetricsCollector creates a new LatencyMetricsCollector
func NewLatencyMetricsCollector(
	ctx context.Context,
	constLabels map[string]string,
	upstreamServerLabelNames []string,
	upstreamServerPeerLabelNames []string,
) *LatencyMetricsCollector {
	return &LatencyMetricsCollector{
		httpLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   metricsNamespace,
			Name:        "upstream_server_response_latency_ms",
			Help:        "Bucketed response times from when NGINX establishes a connection to an upstream server to when the last byte of the response body is received by NGINX",
			ConstLabels: constLabels,
			Buckets:     latencyBucketsMilliSeconds,
		},
			createLatencyLabelNames(upstreamServerLabelNames, upstreamServerPeerLabelNames),
		),
		upstreamServerLabels:         make(map[string][]string),
		upstreamServerPeerLabels:     make(map[string][]string),
		metricsPublishedMap:          make(metricsPublishedMap),
		upstreamServerLabelNames:     upstreamServerLabelNames,
		upstreamServerPeerLabelNames: upstreamServerPeerLabelNames,
		logger:                       nl.LoggerFromContext(ctx),
	}
}

// UpdateUpstreamServerPeerLabels updates the Upstream Server Peer Labels
func (l *LatencyMetricsCollector) UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels map[string][]string) {
	l.variableLabelsMutex.Lock()
	for k, v := range upstreamServerPeerLabels {
		l.upstreamServerPeerLabels[k] = v
	}
	l.variableLabelsMutex.Unlock()
}

// DeleteUpstreamServerPeerLabels deletes the Upstream Server Peer Labels
func (l *LatencyMetricsCollector) DeleteUpstreamServerPeerLabels(peers []string) {
	l.variableLabelsMutex.Lock()
	for _, k := range peers {
		delete(l.upstreamServerPeerLabels, k)
	}
	l.variableLabelsMutex.Unlock()
}

// UpdateUpstreamServerLabels updates the upstream server label map
func (l *LatencyMetricsCollector) UpdateUpstreamServerLabels(newLabelValues map[string][]string) {
	l.variableLabelsMutex.Lock()
	for k, v := range newLabelValues {
		l.upstreamServerLabels[k] = v
	}
	l.variableLabelsMutex.Unlock()
}

// DeleteUpstreamServerLabels deletes upstream server labels
func (l *LatencyMetricsCollector) DeleteUpstreamServerLabels(upstreamNames []string) {
	l.variableLabelsMutex.Lock()
	for _, k := range upstreamNames {
		delete(l.upstreamServerLabels, k)
	}
	l.variableLabelsMutex.Unlock()
}

// DeleteMetrics deletes all metrics published associated with the given upstream server peer names.
func (l *LatencyMetricsCollector) DeleteMetrics(upstreamServerPeerNames []string) {
	for _, name := range upstreamServerPeerNames {
		for _, labelValues := range l.listAndDeleteMetricsPublished(name) {
			success := l.httpLatency.DeleteLabelValues(labelValues...)
			if !success {
				nl.Warnf(l.logger, "could not delete metric for upstream server peer: %s with values: %v", name, labelValues)
			}
		}
	}
}

func (l *LatencyMetricsCollector) getUpstreamServerPeerLabelValues(peer string) []string {
	l.variableLabelsMutex.RLock()
	defer l.variableLabelsMutex.RUnlock()
	return l.upstreamServerPeerLabels[peer]
}

func (l *LatencyMetricsCollector) getUpstreamServerLabels(upstreamName string) []string {
	l.variableLabelsMutex.RLock()
	defer l.variableLabelsMutex.RUnlock()
	return l.upstreamServerLabels[upstreamName]
}

// Register registers all the metrics of the collector
func (l *LatencyMetricsCollector) Register(registry *prometheus.Registry) error {
	return registry.Register(l)
}

// Describe implements prometheus.Collector interface Describe method
func (l *LatencyMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	l.httpLatency.Describe(ch)
}

// Collect implements the prometheus.Collector interface Collect method
func (l *LatencyMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	l.httpLatency.Collect(ch)
}

// RecordLatency parses a syslog message and records latency
func (l *LatencyMetricsCollector) RecordLatency(syslogMsg string) {
	lm, err := parseMessage(syslogMsg)
	if err != nil {
		nl.Debugf(l.logger, "could not parse syslog message: %v", err)
		return
	}

	// Upstream for gRPC service is not implemented yet.
	// This is a temp solution to avoid spamming error logs.
	// Ref:
	// https://github.com/nginx/kubernetes-ingress/issues/5010
	// https://github.com/nginx/kubernetes-ingress/issues/6124
	if lm.Upstream == "-" {
		nl.Debugf(l.logger, "latency metrics for gRPC upstreams: %v", lm)
		return
	}

	labelValues, err := l.createLatencyLabelValues(lm)
	if err != nil {
		nl.Errorf(l.logger, "cannot record latency for upstream %s and server %s: %v", lm.Upstream, lm.Server, err)
		return
	}
	l.httpLatency.WithLabelValues(labelValues...).Observe(lm.Latency * 1000)
	l.updateMetricsPublished(lm.Upstream, lm.Server, labelValues)
}

func (l *LatencyMetricsCollector) updateMetricsPublished(upstreamName, server string, labelValues []string) {
	l.metricsPublishedMutex.Lock()
	key := fmt.Sprintf("%s/%s", upstreamName, server)
	if _, ok := l.metricsPublishedMap[key]; !ok {
		l.metricsPublishedMap[key] = make(metricsSet)
	}
	l.metricsPublishedMap[key][strings.Join(labelValues, "+")] = struct{}{}
	l.metricsPublishedMutex.Unlock()
}

func (l *LatencyMetricsCollector) listAndDeleteMetricsPublished(key string) (metricsPublished [][]string) {
	l.metricsPublishedMutex.Lock()
	defer l.metricsPublishedMutex.Unlock()
	for labelValues := range l.metricsPublishedMap[key] {
		metricsPublished = append(metricsPublished, strings.Split(labelValues, "+"))
	}
	delete(l.metricsPublishedMap, key)
	return metricsPublished
}

func (l *LatencyMetricsCollector) createLatencyLabelValues(lm latencyMetric) ([]string, error) {
	labelValues := []string{lm.Upstream, lm.Server, lm.Code}
	upstreamServerLabelValues := l.getUpstreamServerLabels(lm.Upstream)
	if len(l.upstreamServerLabelNames) != len(upstreamServerLabelValues) {
		return nil, fmt.Errorf("wrong number of labels for upstream %v. For labels %v, got values: %v",
			lm.Upstream, l.upstreamServerLabelNames, upstreamServerLabelValues)
	}
	labelValues = append(labelValues, upstreamServerLabelValues...)
	peerServerLabelValues := l.getUpstreamServerPeerLabelValues(fmt.Sprintf("%v/%v", lm.Upstream, lm.Server))
	if len(l.upstreamServerPeerLabelNames) != len(peerServerLabelValues) {
		return nil, fmt.Errorf("wrong number of labels for upstream peer %v. For labels %v, got values: %v",
			lm.Server, l.upstreamServerPeerLabelNames, peerServerLabelValues)
	}
	labelValues = append(labelValues, peerServerLabelValues...)
	return labelValues, nil
}

func createLatencyLabelNames(upstreamServerLabelNames, upstreamServerPeerLabelNames []string) []string {
	return append(append([]string{"upstream", "server", "code"}, upstreamServerLabelNames...), upstreamServerPeerLabelNames...)
}

type syslogMsg struct {
	ProxyHost            string `json:"proxyHost"`
	UpstreamAddr         string `json:"upstreamAddress"`
	UpstreamStatus       string `json:"upstreamStatus"`
	UpstreamResponseTime string `json:"upstreamResponseTime"`
}

type latencyMetric struct {
	Upstream string
	Server   string
	Code     string
	Latency  float64
}

func parseMessage(msg string) (latencyMetric, error) {
	msgParts := strings.Split(msg, nginxSeparator)
	if len(msgParts) != 2 {
		return latencyMetric{}, fmt.Errorf("wrong message format: %s, expected message to start with \"%s\"", msg, nginxSeparator)
	}
	var sm syslogMsg
	info := msgParts[1]
	if err := json.Unmarshal([]byte(info), &sm); err != nil {
		return latencyMetric{}, fmt.Errorf("could not unmarshal %s: %w", msg, err)
	}
	if sm.UpstreamAddr == sm.ProxyHost {
		// no upstream connected so don't publish a metric
		return latencyMetric{}, fmt.Errorf("nginx could not connect to upstream")
	}
	server := parseMultipartResponse(sm.UpstreamAddr)
	latency, err := strconv.ParseFloat(parseMultipartResponse(sm.UpstreamResponseTime), 64)
	if err != nil {
		return latencyMetric{}, fmt.Errorf("could not parse float from upstream response time %s: %w", sm.UpstreamResponseTime, err)
	}
	code := parseMultipartResponse(sm.UpstreamStatus)
	lm := latencyMetric{
		Upstream: sm.ProxyHost,
		Server:   server,
		Code:     code,
		Latency:  latency,
	}

	return lm, nil
}

// parseMultipartResponse checks if the input string contains commas.
// If it does it returns the last item of the list, otherwise it returns input.
func parseMultipartResponse(input string) string {
	parts := strings.Split(input, ",")
	if l := len(parts); l > 1 {
		return strings.TrimLeft(parts[l-1], " ")
	}
	return input
}

// LatencyFakeCollector is a fake collector that implements the LatencyCollector interface
type LatencyFakeCollector struct{}

// DeleteMetrics implements a fake DeleteMetrics
func (l *LatencyFakeCollector) DeleteMetrics([]string) {}

// UpdateUpstreamServerPeerLabels implements a fake UpdateUpstreamServerPeerLabels
func (l *LatencyFakeCollector) UpdateUpstreamServerPeerLabels(map[string][]string) {}

// DeleteUpstreamServerPeerLabels implements a fake DeleteUpstreamServerPeerLabels
func (l *LatencyFakeCollector) DeleteUpstreamServerPeerLabels([]string) {}

// UpdateUpstreamServerLabels implements a fake UpdateUpstreamServerLabels
func (l *LatencyFakeCollector) UpdateUpstreamServerLabels(map[string][]string) {}

// DeleteUpstreamServerLabels implements a fake DeleteUpstreamServerLabels
func (l *LatencyFakeCollector) DeleteUpstreamServerLabels([]string) {}

// NewLatencyFakeCollector creates a fake collector that implements the LatencyCollector interface
func NewLatencyFakeCollector() *LatencyFakeCollector {
	return &LatencyFakeCollector{}
}

// Register implements a fake Register
func (l *LatencyFakeCollector) Register(_ *prometheus.Registry) error { return nil }

// RecordLatency implements a fake RecordLatency
func (l *LatencyFakeCollector) RecordLatency(_ string) {}
