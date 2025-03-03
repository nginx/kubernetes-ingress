package configs

import (
	"context"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
)

// ConfigParams holds NGINX configuration parameters that affect the main NGINX config
// as well as configs for Ingress resources.
type ConfigParams struct {
	Context                                context.Context
	ClientMaxBodySize                      string
	DefaultServerAccessLogOff              bool
	DefaultServerReturn                    string
	FailTimeout                            string
	HealthCheckEnabled                     bool
	HealthCheckMandatory                   bool
	HealthCheckMandatoryQueue              int64
	HSTS                                   bool
	HSTSBehindProxy                        bool
	HSTSIncludeSubdomains                  bool
	HSTSMaxAge                             int64
	HTTP2                                  bool
	Keepalive                              int
	LBMethod                               string
	LocationSnippets                       []string
	MainAccessLog                          string
	MainErrorLogLevel                      string
	MainHTTPSnippets                       []string
	MainKeepaliveRequests                  int64
	MainKeepaliveTimeout                   string
	MainLogFormat                          []string
	MainLogFormatEscaping                  string
	MainMainSnippets                       []string
	MainOpenTracingEnabled                 bool
	MainOpenTracingLoadModule              bool
	MainOpenTracingTracer                  string
	MainOpenTracingTracerConfig            string
	MainServerNamesHashBucketSize          string
	MainServerNamesHashMaxSize             string
	MainStreamLogFormat                    []string
	MainStreamLogFormatEscaping            string
	MainStreamSnippets                     []string
	MainMapHashBucketSize                  string
	MainMapHashMaxSize                     string
	MainWorkerConnections                  string
	MainWorkerCPUAffinity                  string
	MainWorkerProcesses                    string
	MainWorkerRlimitNofile                 string
	MainWorkerShutdownTimeout              string
	MaxConns                               int
	MaxFails                               int
	AppProtectEnable                       string
	AppProtectPolicy                       string
	AppProtectLogConf                      string
	AppProtectLogEnable                    string
	MainAppProtectFailureModeAction        string
	MainAppProtectCompressedRequestsAction string
	MainAppProtectCookieSeed               string
	MainAppProtectCPUThresholds            string
	MainAppProtectPhysicalMemoryThresholds string
	MainAppProtectReconnectPeriod          string
	AppProtectDosResource                  string
	MainAppProtectDosLogFormat             []string
	MainAppProtectDosLogFormatEscaping     string
	MainAppProtectDosArbFqdn               string
	ProxyBuffering                         bool
	ProxyBuffers                           string
	ProxyBufferSize                        string
	ProxyConnectTimeout                    string
	ProxyHideHeaders                       []string
	ProxyMaxTempFileSize                   string
	ProxyPassHeaders                       []string
	ProxySetHeaders                        []version2.Header
	ProxyProtocol                          bool
	ProxyReadTimeout                       string
	ProxySendTimeout                       string
	RedirectToHTTPS                        bool
	ResolverAddresses                      []string
	ResolverIPV6                           bool
	ResolverTimeout                        string
	ResolverValid                          string
	ServerSnippets                         []string
	ServerTokens                           string
	SlowStart                              string
	SSLRedirect                            bool
	UpstreamZoneSize                       string
	UseClusterIP                           bool
	VariablesHashBucketSize                uint64
	VariablesHashMaxSize                   uint64
	ZoneSync                               ZoneSync

	RealIPHeader    string
	RealIPRecursive bool
	SetRealIPFrom   []string

	MainServerSSLCiphers             string
	MainServerSSLDHParam             string
	MainServerSSLDHParamFileContent  *string
	MainServerSSLPreferServerCiphers bool
	MainServerSSLProtocols           string

	IngressTemplate         *string
	VirtualServerTemplate   *string
	MainTemplate            *string
	TransportServerTemplate *string

	JWTKey      string
	JWTLoginURL string
	JWTRealm    string
	JWTToken    string

	BasicAuthSecret string
	BasicAuthRealm  string

	Ports    []int
	SSLPorts []int

	SpiffeServerCerts bool

	LimitReqRate       string
	LimitReqKey        string
	LimitReqZoneSize   string
	LimitReqDelay      int
	LimitReqNoDelay    bool
	LimitReqBurst      int
	LimitReqDryRun     bool
	LimitReqLogLevel   string
	LimitReqRejectCode int
	LimitReqScale      bool
}

// StaticConfigParams holds immutable NGINX configuration parameters that affect the main NGINX config.
type StaticConfigParams struct {
	DisableIPV6                    bool
	DefaultHTTPListenerPort        int
	DefaultHTTPSListenerPort       int
	HealthStatus                   bool
	HealthStatusURI                string
	NginxStatus                    bool
	NginxStatusAllowCIDRs          []string
	NginxStatusPort                int
	StubStatusOverUnixSocketForOSS bool
	TLSPassthrough                 bool
	TLSPassthroughPort             int
	EnableSnippets                 bool
	NginxServiceMesh               bool
	EnableInternalRoutes           bool
	MainAppProtectLoadModule       bool
	MainAppProtectV5LoadModule     bool
	MainAppProtectDosLoadModule    bool
	MainAppProtectV5EnforcerAddr   string
	InternalRouteServerName        string
	EnableLatencyMetrics           bool
	EnableOIDC                     bool
	SSLRejectHandshake             bool
	EnableCertManager              bool
	DynamicSSLReload               bool
	StaticSSLPath                  string
	DynamicWeightChangesReload     bool
	NginxVersion                   nginx.Version
	AppProtectBundlePath           string
}

// GlobalConfigParams holds global configuration parameters. For now, it only holds listeners.
// GlobalConfigParams should replace ConfigParams in the future.
type GlobalConfigParams struct {
	Listeners map[string]Listener
}

// Listener represents a listener that can be used in a TransportServer resource.
type Listener struct {
	Port     int
	Protocol string
}

// ZoneSync holds zone sync values for state sharing.
type ZoneSync struct {
	Enable            bool
	Port              int
	Domain            string
	ResolverAddresses []string
	ResolverValid     string
	ResolverIPV6      *bool
}

// MGMTSecrets holds mgmt block secret names
type MGMTSecrets struct {
	License     string
	ClientAuth  string
	TrustedCert string
	TrustedCRL  string
}

// MGMTConfigParams holds mgmt block parameters.
type MGMTConfigParams struct {
	Context              context.Context
	SSLVerify            *bool
	ResolverAddresses    []string
	ResolverIPV6         *bool
	ResolverValid        string
	EnforceInitialReport *bool
	Endpoint             string
	Interval             string
	Secrets              MGMTSecrets
}

// NewDefaultConfigParams creates a ConfigParams with default values.
func NewDefaultConfigParams(ctx context.Context, isPlus bool) *ConfigParams {
	upstreamZoneSize := "256k"
	if isPlus {
		upstreamZoneSize = "512k"
	}

	return &ConfigParams{
		Context:                       ctx,
		DefaultServerReturn:           "404",
		ServerTokens:                  "on",
		ProxyConnectTimeout:           "60s",
		ProxyReadTimeout:              "60s",
		ProxySendTimeout:              "60s",
		ClientMaxBodySize:             "1m",
		SSLRedirect:                   true,
		MainAccessLog:                 "/dev/stdout main",
		MainServerNamesHashBucketSize: "256",
		MainServerNamesHashMaxSize:    "1024",
		MainMapHashBucketSize:         "256",
		MainMapHashMaxSize:            "2048",
		ProxyBuffering:                true,
		MainWorkerProcesses:           "auto",
		MainWorkerConnections:         "1024",
		HSTSMaxAge:                    2592000,
		Ports:                         []int{80},
		SSLPorts:                      []int{443},
		MaxFails:                      1,
		MaxConns:                      0,
		UpstreamZoneSize:              upstreamZoneSize,
		FailTimeout:                   "10s",
		LBMethod:                      "random two least_conn",
		MainErrorLogLevel:             "notice",
		ResolverIPV6:                  true,
		MainKeepaliveTimeout:          "75s",
		MainKeepaliveRequests:         1000,
		VariablesHashBucketSize:       256,
		VariablesHashMaxSize:          1024,
		LimitReqKey:                   "${binary_remote_addr}",
		LimitReqZoneSize:              "10m",
		LimitReqLogLevel:              "error",
		LimitReqRejectCode:            429,
	}
}

// NewDefaultMGMTConfigParams creates a ConfigParams with mgmt values.
func NewDefaultMGMTConfigParams(ctx context.Context) *MGMTConfigParams {
	return &MGMTConfigParams{
		Context:              ctx,
		SSLVerify:            nil,
		EnforceInitialReport: nil,
		Secrets:              MGMTSecrets{},
	}
}
