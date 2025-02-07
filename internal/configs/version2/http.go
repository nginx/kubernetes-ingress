package version2

import "fmt"

// UpstreamLabels describes the Prometheus labels for an NGINX upstream.
type UpstreamLabels struct {
	Service           string
	ResourceType      string
	ResourceName      string
	ResourceNamespace string
}

// VirtualServerConfig holds NGINX configuration for a VirtualServer.
type VirtualServerConfig struct {
	HTTPSnippets            []string
	TwoWaySplitClients      []TwoWaySplitClients
	KeyValZones             []KeyValZone
	KeyVals                 []KeyVal
	LimitReqZones           []LimitReqZone
	Maps                    []Map
	AuthJWTClaimSets        []AuthJWTClaimSet
	Server                  Server
	SpiffeCerts             bool
	SpiffeClientCerts       bool
	SplitClients            []SplitClient
	StatusMatches           []StatusMatch
	Upstreams               []Upstream
	DynamicSSLReloadEnabled bool
	StaticSSLPath           string
}

// AuthJWTClaimSet defines the values for the `auth_jwt_claim_set` directive
type AuthJWTClaimSet struct {
	Variable string
	Claim    string
}

// Upstream defines an upstream.
type Upstream struct {
	Name             string
	Servers          []UpstreamServer
	LBMethod         string
	Resolve          bool
	Keepalive        int
	MaxFails         int
	MaxConns         int
	SlowStart        string
	FailTimeout      string
	UpstreamZoneSize string
	Queue            *Queue
	SessionCookie    *SessionCookie
	UpstreamLabels   UpstreamLabels
	NTLM             bool
	BackupServers    []UpstreamServer
}

// UpstreamServer defines an upstream server.
type UpstreamServer struct {
	Address string
}

// Server defines a server.
type Server struct {
	ServerName                string
	StatusZone                string
	CustomListeners           bool
	HTTPIPv4                  string
	HTTPIPv6                  string
	HTTPSIPv4                 string
	HTTPSIPv6                 string
	HTTPPort                  int
	HTTPSPort                 int
	ProxyProtocol             bool
	SSL                       *SSL
	ServerTokens              string
	RealIPHeader              string
	SetRealIPFrom             []string
	RealIPRecursive           bool
	Snippets                  []string
	InternalRedirectLocations []InternalRedirectLocation
	Locations                 []Location
	ErrorPageLocations        []ErrorPageLocation
	ReturnLocations           []ReturnLocation
	HealthChecks              []HealthCheck
	TLSRedirect               *TLSRedirect
	TLSPassthrough            bool
	Allow                     []string
	Deny                      []string
	LimitReqOptions           LimitReqOptions
	LimitReqs                 []LimitReq
	JWTAuth                   *JWTAuth
	JWTAuthList               map[string]*JWTAuth
	JWKSAuthEnabled           bool
	BasicAuth                 *BasicAuth
	IngressMTLS               *IngressMTLS
	EgressMTLS                *EgressMTLS
	OIDC                      *OIDC
	APIKey                    *APIKey
	APIKeyEnabled             bool
	WAF                       *WAF
	Dos                       *Dos
	PoliciesErrorReturn       *Return
	VSNamespace               string
	VSName                    string
	DisableIPV6               bool
	Gunzip                    bool
}

// SSL defines SSL configuration for a server.
type SSL struct {
	HTTP2           bool
	Certificate     string
	CertificateKey  string
	RejectHandshake bool
}

// IngressMTLS defines TLS configuration for a server. This is a subset of TLS specifically for clients auth.
type IngressMTLS struct {
	ClientCert   string
	ClientCrl    string
	VerifyClient string
	VerifyDepth  int
}

// EgressMTLS defines TLS configuration for a location.
type EgressMTLS struct {
	Certificate    string
	CertificateKey string
	VerifyServer   bool
	VerifyDepth    int
	Ciphers        string
	Protocols      string
	TrustedCert    string
	SessionReuse   bool
	ServerName     bool
	SSLName        string
}

// OIDC holds OIDC configuration data.
type OIDC struct {
	AuthEndpoint          string
	ClientID              string
	ClientSecret          string
	JwksURI               string
	Scope                 string
	TokenEndpoint         string
	EndSessionEndpoint    string
	RedirectURI           string
	PostLogoutRedirectURI string
	ZoneSyncLeeway        int
	AuthExtraArgs         string
	AccessTokenEnable     bool
}

// APIKey holds API key configuration.
type APIKey struct {
	Header  []string
	Query   []string
	MapName string
}

// WAF defines WAF configuration.
type WAF struct {
	Enable              string
	ApPolicy            string
	ApBundle            string
	ApSecurityLogEnable bool
	ApLogConf           []string
}

// Dos defines Dos configuration.
type Dos struct {
	Enable                 string
	Name                   string
	AllowListPath          string
	ApDosPolicy            string
	ApDosSecurityLogEnable bool
	ApDosLogConf           string
	ApDosMonitorURI        string
	ApDosMonitorProtocol   string
	ApDosMonitorTimeout    uint64
	ApDosAccessLogDest     string
}

// Location defines a location.
type Location struct {
	Path                     string
	Internal                 bool
	Snippets                 []string
	ProxyConnectTimeout      string
	ProxyReadTimeout         string
	ProxySendTimeout         string
	ClientMaxBodySize        string
	ProxyMaxTempFileSize     string
	ProxyBuffering           bool
	ProxyBuffers             string
	ProxyBufferSize          string
	ProxyPass                string
	ProxyNextUpstream        string
	ProxyNextUpstreamTimeout string
	ProxyNextUpstreamTries   int
	ProxyInterceptErrors     bool
	ProxyPassRequestHeaders  bool
	ProxySetHeaders          []Header
	ProxyHideHeaders         []string
	ProxyPassHeaders         []string
	ProxyIgnoreHeaders       string
	ProxyPassRewrite         string
	AddHeaders               []AddHeader
	Rewrites                 []string
	HasKeepalive             bool
	ErrorPages               []ErrorPage
	ProxySSLName             string
	InternalProxyPass        string
	Allow                    []string
	Deny                     []string
	LimitReqOptions          LimitReqOptions
	LimitReqs                []LimitReq
	JWTAuth                  *JWTAuth
	BasicAuth                *BasicAuth
	EgressMTLS               *EgressMTLS
	OIDC                     bool
	APIKey                   *APIKey
	WAF                      *WAF
	Dos                      *Dos
	PoliciesErrorReturn      *Return
	ServiceName              string
	IsVSR                    bool
	VSRName                  string
	VSRNamespace             string
	GRPCPass                 string
}

// ReturnLocation defines a location for returning a fixed response.
type ReturnLocation struct {
	Name        string
	DefaultType string
	Return      Return
	Headers     []Header
}

// SplitClient defines a split_clients.
type SplitClient struct {
	Source        string
	Variable      string
	Distributions []Distribution
}

// Return defines a Return directive used for redirects and canned responses.
type Return struct {
	Code int
	Text string
}

// ErrorPage defines an error_page of a location.
type ErrorPage struct {
	Name         string
	Codes        string
	ResponseCode int
}

// ErrorPageLocation defines a named location for an error_page directive.
type ErrorPageLocation struct {
	Name        string
	DefaultType string
	Return      *Return
	Headers     []Header
}

// Header defines a header to use with add_header directive.
type Header struct {
	Name  string
	Value string
}

// AddHeader defines a header to use with add_header directive with an optional Always field.
type AddHeader struct {
	Header
	Always bool
}

// HealthCheck defines a HealthCheck for an upstream in a Server.
type HealthCheck struct {
	Name                string
	URI                 string
	Interval            string
	Jitter              string
	Fails               int
	Passes              int
	Port                int
	ProxyPass           string
	ProxyConnectTimeout string
	ProxyReadTimeout    string
	ProxySendTimeout    string
	Headers             map[string]string
	Match               string
	GRPCPass            string
	GRPCStatus          *int
	GRPCService         string
	Mandatory           bool
	Persistent          bool
	KeepaliveTime       string
	IsGRPC              bool
}

// TLSRedirect defines a redirect in a Server.
type TLSRedirect struct {
	Code    int
	BasedOn string
}

// SessionCookie defines a session cookie for an upstream.
type SessionCookie struct {
	Enable   bool
	Name     string
	Path     string
	Expires  string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite string
}

// Distribution maps weight to a value in a SplitClient.
type Distribution struct {
	Weight string
	Value  string
}

// InternalRedirectLocation defines a location for internally redirecting requests to named locations.
type InternalRedirectLocation struct {
	Path        string
	Destination string
}

// Map defines a map.
type Map struct {
	Source     string
	Variable   string
	Parameters []Parameter
}

// Parameter defines a Parameter in a Map.
type Parameter struct {
	Value  string
	Result string
}

// StatusMatch defines a Match block for status codes.
type StatusMatch struct {
	Name string
	Code string
}

// Queue defines a queue in upstream.
type Queue struct {
	Size    int
	Timeout string
}

// LimitReqZone defines a rate limit shared memory zone.
type LimitReqZone struct {
	Key           string
	ZoneName      string
	ZoneSize      string
	Rate          string
	GroupName     string
	GroupVariable string
	GroupKey      string
	GroupDefault  bool
}

func (rlz LimitReqZone) String() string {
	return fmt.Sprintf("{Key %q, ZoneName %q, ZoneSize %v, Rate %q, GroupName %q, GroupVariable %q}", rlz.Key, rlz.ZoneName, rlz.ZoneSize, rlz.Rate, rlz.GroupName, rlz.GroupVariable)
}

// LimitReq defines a rate limit.
type LimitReq struct {
	ZoneName string
	Burst    int
	NoDelay  bool
	Delay    int
}

func (rl LimitReq) String() string {
	return fmt.Sprintf("{ZoneName %q, Burst %q, NoDelay %v, Delay %q}", rl.ZoneName, rl.Burst, rl.NoDelay, rl.Delay)
}

// LimitReqOptions defines rate limit options.
type LimitReqOptions struct {
	DryRun     bool
	LogLevel   string
	RejectCode int
}

func (rl LimitReqOptions) String() string {
	return fmt.Sprintf("{DryRun %v, LogLevel %q, RejectCode %q}", rl.DryRun, rl.LogLevel, rl.RejectCode)
}

// JWTAuth holds JWT authentication configuration.
type JWTAuth struct {
	Key      string
	Secret   string
	Realm    string
	Token    string
	KeyCache string
	JwksURI  JwksURI
}

// JwksURI defines the components of a JwksURI
type JwksURI struct {
	JwksScheme string
	JwksHost   string
	JwksPort   string
	JwksPath   string
}

// BasicAuth refers to basic HTTP authentication mechanism options
type BasicAuth struct {
	Secret string
	Realm  string
}

// KeyValZone defines a keyval zone.
type KeyValZone struct {
	Name  string
	Size  string
	State string
}

// KeyVal defines a keyval.
type KeyVal struct {
	Key      string
	Variable string
	ZoneName string
}

// TwoWaySplitClients defines split clients for two way split
type TwoWaySplitClients struct {
	Key               string
	Variable          string
	ZoneName          string
	Weights           []int
	SplitClientsIndex int
}

// Variable defines an nginx variable.
type Variable struct {
	Name  string
	Value string
}
