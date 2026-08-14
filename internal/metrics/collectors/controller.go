package collectors

import "github.com/prometheus/client_golang/prometheus"

var labelNamesController = []string{"type"}

// ControllerCollector is an interface for the metrics of the Controller
type ControllerCollector interface {
	SetIngresses(ingressType string, count int)
	SetVirtualServers(count int)
	SetVirtualServerRoutes(count int)
	SetTransportServers(tlsPassthroughCount, tcpCount, udpCount int)
	Register(registry *prometheus.Registry) error
}

// ControllerMetricsCollector implements the ControllerCollector interface and prometheus.Collector interface
type ControllerMetricsCollector struct {
	crdsEnabled              bool
	ingressesTotal           *prometheus.GaugeVec
	virtualServersTotal      prometheus.Gauge
	virtualServerRoutesTotal prometheus.Gauge
	transportServersTotal    *prometheus.GaugeVec
}

// NewControllerMetricsCollector creates a new ControllerMetricsCollector
func NewControllerMetricsCollector(crdsEnabled bool, constLabels map[string]string) *ControllerMetricsCollector {
	ingResTotal := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:        "ingress_resources_total",
			Namespace:   metricsNamespace,
			Help:        "Number of handled ingress resources",
			ConstLabels: constLabels,
		},
		labelNamesController,
	)

	var vsResTotal, vsrResTotal prometheus.Gauge
	var tsResTotal *prometheus.GaugeVec

	if crdsEnabled {
		vsResTotal = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:        "virtualserver_resources_total",
				Namespace:   metricsNamespace,
				Help:        "Number of handled VirtualServer resources",
				ConstLabels: constLabels,
			},
		)

		vsrResTotal = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:        "virtualserverroute_resources_total",
				Namespace:   metricsNamespace,
				Help:        "Number of handled VirtualServerRoute resources",
				ConstLabels: constLabels,
			},
		)

		tsResTotal = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "transportserver_resources_total",
				Namespace:   metricsNamespace,
				Help:        "Number of handled TransportServer resources",
				ConstLabels: constLabels,
			},
			labelNamesController,
		)
	}

	c := &ControllerMetricsCollector{
		crdsEnabled:              crdsEnabled,
		ingressesTotal:           ingResTotal,
		virtualServersTotal:      vsResTotal,
		virtualServerRoutesTotal: vsrResTotal,
		transportServersTotal:    tsResTotal,
	}

	// if we don't set to 0 metrics with the label type, the metrics will not be created initially

	c.SetIngresses("regular", 0)
	c.SetIngresses("master", 0)
	c.SetIngresses("minion", 0)

	if crdsEnabled {
		c.SetTransportServers(0, 0, 0)
	}

	return c
}

// SetIngresses sets the value of the ingress resources gauge for a given type
func (cc *ControllerMetricsCollector) SetIngresses(ingressType string, count int) {
	cc.ingressesTotal.WithLabelValues(ingressType).Set(float64(count))
}

// SetVirtualServers sets the value of the VirtualServer resources gauge
func (cc *ControllerMetricsCollector) SetVirtualServers(count int) {
	if cc.virtualServersTotal == nil {
		return
	}
	cc.virtualServersTotal.Set(float64(count))
}

// SetVirtualServerRoutes sets the value of the VirtualServerRoute resources gauge
func (cc *ControllerMetricsCollector) SetVirtualServerRoutes(count int) {
	if cc.virtualServerRoutesTotal == nil {
		return
	}
	cc.virtualServerRoutesTotal.Set(float64(count))
}

// SetTransportServers sets the value of the TransportServer resources gauge
func (cc *ControllerMetricsCollector) SetTransportServers(tlsPassthroughCount, tcpCount, udpCount int) {
	if cc.transportServersTotal == nil {
		return
	}
	cc.transportServersTotal.WithLabelValues("passthrough").Set(float64(tlsPassthroughCount))
	cc.transportServersTotal.WithLabelValues("tcp").Set(float64(tcpCount))
	cc.transportServersTotal.WithLabelValues("udp").Set(float64(udpCount))
}

// Describe implements prometheus.Collector interface Describe method
func (cc *ControllerMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	cc.ingressesTotal.Describe(ch)
	if cc.crdsEnabled {
		cc.virtualServersTotal.Describe(ch)
		cc.virtualServerRoutesTotal.Describe(ch)
		cc.transportServersTotal.Describe(ch)
	}
}

// Collect implements the prometheus.Collector interface Collect method
func (cc *ControllerMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	cc.ingressesTotal.Collect(ch)
	if cc.crdsEnabled {
		cc.virtualServersTotal.Collect(ch)
		cc.virtualServerRoutesTotal.Collect(ch)
		cc.transportServersTotal.Collect(ch)
	}
}

// Register registers all the metrics of the collector
func (cc *ControllerMetricsCollector) Register(registry *prometheus.Registry) error {
	return registry.Register(cc)
}

// ControllerFakeCollector is a fake collector that implements the ControllerCollector interface
type ControllerFakeCollector struct{}

// NewControllerFakeCollector creates a fake collector that implements the ControllerCollector interface
func NewControllerFakeCollector() *ControllerFakeCollector {
	return &ControllerFakeCollector{}
}

// Register implements a fake Register
func (cc *ControllerFakeCollector) Register(_ *prometheus.Registry) error { return nil }

// SetIngresses implements a fake SetIngresses
func (cc *ControllerFakeCollector) SetIngresses(_ string, _ int) {}

// SetVirtualServers implements a fake SetVirtualServers
func (cc *ControllerFakeCollector) SetVirtualServers(_ int) {}

// SetVirtualServerRoutes implements a fake SetVirtualServerRoutes
func (cc *ControllerFakeCollector) SetVirtualServerRoutes(_ int) {}

// SetTransportServers implements a fake SetTransportServers
func (cc *ControllerFakeCollector) SetTransportServers(int, int, int) {}
