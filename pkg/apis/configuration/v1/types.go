package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// StateWarning is used when the resource has been validated and accepted but it might work in a degraded state.
	StateWarning = "Warning"
	// StateValid is used when the resource has been validated and accepted and is working as expected.
	StateValid = "Valid"
	// StateInvalid is used when the resource failed validation or NGINX failed to reload the corresponding config.
	StateInvalid = "Invalid"
	// HTTPProtocol defines a constant for the HTTP protocol in GlobalConfinguration.
	HTTPProtocol = "HTTP"
	// TLSPassthroughListenerName is the name of a built-in TLS Passthrough listener.
	TLSPassthroughListenerName = "tls-passthrough"
	// TLSPassthroughListenerProtocol is the protocol of a built-in TLS Passthrough listener.
	TLSPassthroughListenerProtocol = "TLS_PASSTHROUGH"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:resource:shortName=vs
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`,description="Current state of the VirtualServer. If the resource has a valid status, it means it has been validated and accepted by the Ingress Controller."
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.status.externalEndpoints[*].ip`
// +kubebuilder:printcolumn:name="ExternalHostname",priority=1,type=string,JSONPath=`.status.externalEndpoints[*].hostname`
// +kubebuilder:printcolumn:name="Ports",type=string,JSONPath=`.status.externalEndpoints[*].ports`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VirtualServer defines the VirtualServer resource.
type VirtualServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualServerSpec   `json:"spec"`
	Status VirtualServerStatus `json:"status"`
}

// VirtualServerSpec is the spec of the VirtualServer resource.
type VirtualServerSpec struct {
	IngressClass   string                 `json:"ingressClassName"`
	Host           string                 `json:"host"`
	Listener       *VirtualServerListener `json:"listener"`
	TLS            *TLS                   `json:"tls"`
	Gunzip         bool                   `json:"gunzip"`
	Policies       []PolicyReference      `json:"policies"`
	Upstreams      []Upstream             `json:"upstreams"`
	Routes         []Route                `json:"routes"`
	HTTPSnippets   string                 `json:"http-snippets"`
	ServerSnippets string                 `json:"server-snippets"`
	Dos            string                 `json:"dos"`
	ExternalDNS    ExternalDNS            `json:"externalDNS"`
	// InternalRoute allows for the configuration of internal routing.
	InternalRoute bool `json:"internalRoute"`
}

// VirtualServerListener references a custom http and/or https listener defined in GlobalConfiguration.
type VirtualServerListener struct {
	HTTP  string `json:"http"`
	HTTPS string `json:"https"`
}

// ExternalDNS defines externaldns sub-resource of a virtual server.
type ExternalDNS struct {
	Enable     bool   `json:"enable"`
	RecordType string `json:"recordType,omitempty"`
	// TTL for the record
	RecordTTL int64 `json:"recordTTL,omitempty"`
	// Labels stores labels defined for the Endpoint
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// ProviderSpecific stores provider specific config
	// +optional
	ProviderSpecific ProviderSpecific `json:"providerSpecific,omitempty"`
}

// ProviderSpecific is a list of properties.
type ProviderSpecific []ProviderSpecificProperty

// ProviderSpecificProperty defines specific property
// for using with ExternalDNS sub-resource.
type ProviderSpecificProperty struct {
	// Name of the property
	Name string `json:"name,omitempty"`
	// Value of the property
	Value string `json:"value,omitempty"`
}

// PolicyReference references a policy by name and an optional namespace.
type PolicyReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Upstream defines an upstream.
type Upstream struct {
	Name                     string            `json:"name"`
	Service                  string            `json:"service"`
	Subselector              map[string]string `json:"subselector"`
	Port                     uint16            `json:"port"`
	LBMethod                 string            `json:"lb-method"`
	FailTimeout              string            `json:"fail-timeout"`
	MaxFails                 *int              `json:"max-fails"`
	MaxConns                 *int              `json:"max-conns"`
	Keepalive                *int              `json:"keepalive"`
	ProxyConnectTimeout      string            `json:"connect-timeout"`
	ProxyReadTimeout         string            `json:"read-timeout"`
	ProxySendTimeout         string            `json:"send-timeout"`
	ProxyNextUpstream        string            `json:"next-upstream"`
	ProxyNextUpstreamTimeout string            `json:"next-upstream-timeout"`
	ProxyNextUpstreamTries   int               `json:"next-upstream-tries"`
	ProxyBuffering           *bool             `json:"buffering"`
	ProxyBuffers             *UpstreamBuffers  `json:"buffers"`
	ProxyBufferSize          string            `json:"buffer-size"`
	ClientMaxBodySize        string            `json:"client-max-body-size"`
	TLS                      UpstreamTLS       `json:"tls"`
	HealthCheck              *HealthCheck      `json:"healthCheck"`
	SlowStart                string            `json:"slow-start"`
	Queue                    *UpstreamQueue    `json:"queue"`
	SessionCookie            *SessionCookie    `json:"sessionCookie"`
	UseClusterIP             bool              `json:"use-cluster-ip"`
	NTLM                     bool              `json:"ntlm"`
	Type                     string            `json:"type"`
	Backup                   string            `json:"backup"`
	BackupPort               *uint16           `json:"backupPort"`
}

// UpstreamBuffers defines Buffer Configuration for an Upstream.
type UpstreamBuffers struct {
	Number int    `json:"number"`
	Size   string `json:"size"`
}

// UpstreamTLS defines a TLS configuration for an Upstream.
type UpstreamTLS struct {
	Enable bool `json:"enable"`
}

// HealthCheck defines the parameters for active Upstream HealthChecks.
type HealthCheck struct {
	Enable         bool         `json:"enable"`
	Path           string       `json:"path"`
	Interval       string       `json:"interval"`
	Jitter         string       `json:"jitter"`
	Fails          int          `json:"fails"`
	Passes         int          `json:"passes"`
	Port           int          `json:"port"`
	TLS            *UpstreamTLS `json:"tls"`
	ConnectTimeout string       `json:"connect-timeout"`
	ReadTimeout    string       `json:"read-timeout"`
	SendTimeout    string       `json:"send-timeout"`
	Headers        []Header     `json:"headers"`
	StatusMatch    string       `json:"statusMatch"`
	GRPCStatus     *int         `json:"grpcStatus"`
	GRPCService    string       `json:"grpcService"`
	Mandatory      bool         `json:"mandatory"`
	Persistent     bool         `json:"persistent"`
	KeepaliveTime  string       `json:"keepalive-time"`
}

// Header defines an HTTP Header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SessionCookie defines the parameters for session persistence.
type SessionCookie struct {
	Enable   bool   `json:"enable"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Expires  string `json:"expires"`
	Domain   string `json:"domain"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"samesite"`
}

// Route defines a route.
type Route struct {
	Path             string            `json:"path"`
	Policies         []PolicyReference `json:"policies"`
	Route            string            `json:"route"`
	Action           *Action           `json:"action"`
	Splits           []Split           `json:"splits"`
	Matches          []Match           `json:"matches"`
	ErrorPages       []ErrorPage       `json:"errorPages"`
	LocationSnippets string            `json:"location-snippets"`
	Dos              string            `json:"dos"`
}

// Action defines an action.
type Action struct {
	Pass     string          `json:"pass"`
	Redirect *ActionRedirect `json:"redirect"`
	Return   *ActionReturn   `json:"return"`
	Proxy    *ActionProxy    `json:"proxy"`
}

// ActionRedirect defines a redirect in an Action.
type ActionRedirect struct {
	URL  string `json:"url"`
	Code int    `json:"code"`
}

// ActionReturn defines a return in an Action.
type ActionReturn struct {
	Code    int      `json:"code"`
	Type    string   `json:"type"`
	Body    string   `json:"body"`
	Headers []Header `json:"headers"`
}

// ActionProxy defines a proxy in an Action.
type ActionProxy struct {
	Upstream        string                `json:"upstream"`
	RewritePath     string                `json:"rewritePath"`
	RequestHeaders  *ProxyRequestHeaders  `json:"requestHeaders"`
	ResponseHeaders *ProxyResponseHeaders `json:"responseHeaders"`
}

// ProxyRequestHeaders defines the request headers manipulation in an ActionProxy.
type ProxyRequestHeaders struct {
	Pass *bool    `json:"pass"`
	Set  []Header `json:"set"`
}

// ProxyResponseHeaders defines the response headers manipulation in an ActionProxy.
type ProxyResponseHeaders struct {
	Hide   []string    `json:"hide"`
	Pass   []string    `json:"pass"`
	Ignore []string    `json:"ignore"`
	Add    []AddHeader `json:"add"`
}

// AddHeader defines an HTTP Header with an optional Always field to use with the add_header NGINX directive.
type AddHeader struct {
	Header `json:",inline"`
	Always bool `json:"always"`
}

// Split defines a split.
type Split struct {
	Weight int     `json:"weight"`
	Action *Action `json:"action"`
}

// Condition defines a condition in a MatchRule.
type Condition struct {
	Header   string `json:"header"`
	Cookie   string `json:"cookie"`
	Argument string `json:"argument"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
}

// Match defines a match.
type Match struct {
	Conditions []Condition `json:"conditions"`
	Action     *Action     `json:"action"`
	Splits     []Split     `json:"splits"`
}

// ErrorPage defines an ErrorPage in a Route.
type ErrorPage struct {
	Codes    []int              `json:"codes"`
	Return   *ErrorPageReturn   `json:"return"`
	Redirect *ErrorPageRedirect `json:"redirect"`
}

// ErrorPageReturn defines a return for an ErrorPage.
type ErrorPageReturn struct {
	ActionReturn `json:",inline"`
}

// ErrorPageRedirect defines a redirect for an ErrorPage.
type ErrorPageRedirect struct {
	ActionRedirect `json:",inline"`
}

// TLS defines TLS configuration for a VirtualServer.
type TLS struct {
	Secret      string       `json:"secret"`
	Redirect    *TLSRedirect `json:"redirect"`
	CertManager *CertManager `json:"cert-manager"`
}

// TLSRedirect defines a redirect for a TLS.
type TLSRedirect struct {
	Enable  bool   `json:"enable"`
	Code    *int   `json:"code"`
	BasedOn string `json:"basedOn"`
}

// CertManager defines a cert manager config for a TLS.
type CertManager struct {
	ClusterIssuer string `json:"cluster-issuer"`
	Issuer        string `json:"issuer"`
	IssuerKind    string `json:"issuer-kind"`
	IssuerGroup   string `json:"issuer-group"`
	CommonName    string `json:"common-name"`
	Duration      string `json:"duration"`
	RenewBefore   string `json:"renew-before"`
	Usages        string `json:"usages"`
	IssueTempCert bool   `json:"issue-temp-cert"`
}

// VirtualServerStatus defines the status for the VirtualServer resource.
type VirtualServerStatus struct {
	State             string             `json:"state"`
	Reason            string             `json:"reason"`
	Message           string             `json:"message"`
	ExternalEndpoints []ExternalEndpoint `json:"externalEndpoints,omitempty"`
}

// ExternalEndpoint defines the IP/ Hostname and ports used to connect to this resource.
type ExternalEndpoint struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Ports    string `json:"ports"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualServerList is a list of the VirtualServer resources.
type VirtualServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VirtualServer `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:resource:shortName=vsr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`,description="Current state of the VirtualServerRoute. If the resource has a valid status, it means it has been validated and accepted by the Ingress Controller."
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.status.externalEndpoints[*].ip`
// +kubebuilder:printcolumn:name="ExternalHostname",type=string,priority=1,JSONPath=`.status.externalEndpoints[*].hostname`
// +kubebuilder:printcolumn:name="Ports",type=string,JSONPath=`.status.externalEndpoints[*].ports`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VirtualServerRoute defines the VirtualServerRoute resource.
type VirtualServerRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualServerRouteSpec   `json:"spec"`
	Status VirtualServerRouteStatus `json:"status"`
}

// VirtualServerRouteSpec is the spec of the VirtualServerRoute resource.
type VirtualServerRouteSpec struct {
	IngressClass string     `json:"ingressClassName"`
	Host         string     `json:"host"`
	Upstreams    []Upstream `json:"upstreams"`
	Subroutes    []Route    `json:"subroutes"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualServerRouteList is a list of VirtualServerRoute
type VirtualServerRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VirtualServerRoute `json:"items"`
}

// UpstreamQueue defines Queue Configuration for an Upstream.
type UpstreamQueue struct {
	Size    int    `json:"size"`
	Timeout string `json:"timeout"`
}

// VirtualServerRouteStatus defines the status for the VirtualServerRoute resource.
type VirtualServerRouteStatus struct {
	State             string             `json:"state"`
	Reason            string             `json:"reason"`
	Message           string             `json:"message"`
	ReferencedBy      string             `json:"referencedBy"`
	ExternalEndpoints []ExternalEndpoint `json:"externalEndpoints,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +kubebuilder:validation:Optional
// +kubebuilder:resource:shortName=gc

// GlobalConfiguration defines the GlobalConfiguration resource.
type GlobalConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GlobalConfigurationSpec `json:"spec"`
}

// GlobalConfigurationSpec is the spec of the GlobalConfiguration resource.
type GlobalConfigurationSpec struct {
	Listeners []Listener `json:"listeners"`
}

// Listener defines a listener.
type Listener struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	Protocol string `json:"protocol"`
	Ssl      bool   `json:"ssl"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalConfigurationList is a list of the GlobalConfiguration resources.
type GlobalConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []GlobalConfiguration `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:resource:shortName=ts
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`,description="Current state of the TransportServer. If the resource has a valid status, it means it has been validated and accepted by the Ingress Controller."
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TransportServer defines the TransportServer resource.
type TransportServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TransportServerSpec   `json:"spec"`
	Status TransportServerStatus `json:"status"`
}

// TransportServerSpec is the spec of the TransportServer resource.
type TransportServerSpec struct {
	IngressClass       string                    `json:"ingressClassName"`
	TLS                *TransportServerTLS       `json:"tls"`
	Listener           TransportServerListener   `json:"listener"`
	ServerSnippets     string                    `json:"serverSnippets"`
	StreamSnippets     string                    `json:"streamSnippets"`
	Host               string                    `json:"host"`
	Upstreams          []TransportServerUpstream `json:"upstreams"`
	UpstreamParameters *UpstreamParameters       `json:"upstreamParameters"`
	SessionParameters  *SessionParameters        `json:"sessionParameters"`
	Action             *TransportServerAction    `json:"action"`
}

// TransportServerTLS defines TransportServerTLS configuration for a TransportServer.
type TransportServerTLS struct {
	Secret string `json:"secret"`
}

// TransportServerListener defines a listener for a TransportServer.
type TransportServerListener struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// TransportServerUpstream defines an upstream.
type TransportServerUpstream struct {
	Name                string                      `json:"name"`
	Service             string                      `json:"service"`
	Port                int                         `json:"port"`
	FailTimeout         string                      `json:"failTimeout"`
	MaxFails            *int                        `json:"maxFails"`
	MaxConns            *int                        `json:"maxConns"`
	HealthCheck         *TransportServerHealthCheck `json:"healthCheck"`
	LoadBalancingMethod string                      `json:"loadBalancingMethod"`
	Backup              string                      `json:"backup"`
	BackupPort          *uint16                     `json:"backupPort"`
}

// TransportServerHealthCheck defines the parameters for active Upstream HealthChecks.
type TransportServerHealthCheck struct {
	Enabled  bool                  `json:"enable"`
	Timeout  string                `json:"timeout"`
	Jitter   string                `json:"jitter"`
	Port     int                   `json:"port"`
	Interval string                `json:"interval"`
	Passes   int                   `json:"passes"`
	Fails    int                   `json:"fails"`
	Match    *TransportServerMatch `json:"match"`
}

// TransportServerMatch defines the parameters of a custom health check.
type TransportServerMatch struct {
	Send   string `json:"send"`
	Expect string `json:"expect"`
}

// UpstreamParameters defines parameters for an upstream.
type UpstreamParameters struct {
	UDPRequests  *int `json:"udpRequests"`
	UDPResponses *int `json:"udpResponses"`

	ConnectTimeout      string `json:"connectTimeout"`
	NextUpstream        bool   `json:"nextUpstream"`
	NextUpstreamTimeout string `json:"nextUpstreamTimeout"`
	NextUpstreamTries   int    `json:"nextUpstreamTries"`
}

// SessionParameters defines session parameters.
type SessionParameters struct {
	Timeout string `json:"timeout"`
}

// TransportServerAction defines an action.
type TransportServerAction struct {
	Pass string `json:"pass"`
}

// TransportServerStatus defines the status for the TransportServer resource.
type TransportServerStatus struct {
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TransportServerList is a list of the TransportServer resources.
type TransportServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []TransportServer `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:resource:shortName=pol
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`,description="Current state of the Policy. If the resource has a valid status, it means it has been validated and accepted by the Ingress Controller."
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Policy defines a Policy for VirtualServer and VirtualServerRoute resources.
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicySpec   `json:"spec"`
	Status PolicyStatus `json:"status"`
}

// PolicyStatus is the status of the policy resource
type PolicyStatus struct {
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// PolicySpec is the spec of the Policy resource.
// The spec includes multiple fields, where each field represents a different policy.
// Only one policy (field) is allowed.
type PolicySpec struct {
	IngressClass  string         `json:"ingressClassName"`
	AccessControl *AccessControl `json:"accessControl"`
	RateLimit     *RateLimit     `json:"rateLimit"`
	JWTAuth       *JWTAuth       `json:"jwt"`
	BasicAuth     *BasicAuth     `json:"basicAuth"`
	IngressMTLS   *IngressMTLS   `json:"ingressMTLS"`
	EgressMTLS    *EgressMTLS    `json:"egressMTLS"`
	OIDC          *OIDC          `json:"oidc"`
	WAF           *WAF           `json:"waf"`
	APIKey        *APIKey        `json:"apiKey"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolicyList is a list of the Policy resources.
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Policy `json:"items"`
}

// AccessControl defines an access policy based on the source IP of a request.
type AccessControl struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// RateLimit defines a rate limit policy.
type RateLimit struct {
	Rate       string `json:"rate"`
	Key        string `json:"key"`
	Delay      *int   `json:"delay"`
	NoDelay    *bool  `json:"noDelay"`
	Burst      *int   `json:"burst"`
	ZoneSize   string `json:"zoneSize"`
	DryRun     *bool  `json:"dryRun"`
	LogLevel   string `json:"logLevel"`
	RejectCode *int   `json:"rejectCode"`
	Scale      bool   `json:"scale"`
	// +kubebuilder:validation:Optional
	Condition *RateLimitCondition `json:"condition"`
}

type RateLimitCondition struct {
	JWT JWTCondition `json:"jwt"`
	// +kubebuilder:validation:Optional
	Default bool `json:"default"`
}

type JWTCondition struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=^([^$\s"'])*$
	Claim string `json:"claim"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=^([^$\s."'])*$
	Match string `json:"match"`
}

// JWTAuth holds JWT authentication configuration.
type JWTAuth struct {
	Realm    string `json:"realm"`
	Secret   string `json:"secret"`
	Token    string `json:"token"`
	JwksURI  string `json:"jwksURI"`
	KeyCache string `json:"keyCache"`
}

// BasicAuth holds HTTP Basic authentication configuration
type BasicAuth struct {
	Realm  string `json:"realm"`
	Secret string `json:"secret"`
}

// IngressMTLS defines an Ingress MTLS policy.
type IngressMTLS struct {
	ClientCertSecret string `json:"clientCertSecret"`
	CrlFileName      string `json:"crlFileName"`
	VerifyClient     string `json:"verifyClient"`
	VerifyDepth      *int   `json:"verifyDepth"`
}

// EgressMTLS defines an Egress MTLS policy.
type EgressMTLS struct {
	TLSSecret         string `json:"tlsSecret"`
	VerifyServer      bool   `json:"verifyServer"`
	VerifyDepth       *int   `json:"verifyDepth"`
	Protocols         string `json:"protocols"`
	SessionReuse      *bool  `json:"sessionReuse"`
	Ciphers           string `json:"ciphers"`
	TrustedCertSecret string `json:"trustedCertSecret"`
	ServerName        bool   `json:"serverName"`
	SSLName           string `json:"sslName"`
}

// OIDC defines an Open ID Connect policy.
type OIDC struct {
	AuthEndpoint          string   `json:"authEndpoint"`
	TokenEndpoint         string   `json:"tokenEndpoint"`
	JWKSURI               string   `json:"jwksURI"`
	ClientID              string   `json:"clientID"`
	ClientSecret          string   `json:"clientSecret"`
	Scope                 string   `json:"scope"`
	RedirectURI           string   `json:"redirectURI"`
	EndSessionEndpoint    string   `json:"endSessionEndpoint"`
	PostLogoutRedirectURI string   `json:"postLogoutRedirectURI"`
	ZoneSyncLeeway        *int     `json:"zoneSyncLeeway"`
	AuthExtraArgs         []string `json:"authExtraArgs"`
	AccessTokenEnable     bool     `json:"accessTokenEnable"`
}

// WAF defines an WAF policy.
type WAF struct {
	Enable       bool           `json:"enable"`
	ApPolicy     string         `json:"apPolicy"`
	ApBundle     string         `json:"apBundle"`
	SecurityLog  *SecurityLog   `json:"securityLog"`
	SecurityLogs []*SecurityLog `json:"securityLogs"`
}

// SecurityLog defines the security log of a WAF policy.
type SecurityLog struct {
	Enable      bool   `json:"enable"`
	ApLogConf   string `json:"apLogConf"`
	ApLogBundle string `json:"apLogBundle"`
	LogDest     string `json:"logDest"`
}

// APIKey defines an API Key policy.
type APIKey struct {
	SuppliedIn   *SuppliedIn `json:"suppliedIn"`
	ClientSecret string      `json:"clientSecret"`
}

// SuppliedIn defines the locations API Key should be supplied in.
type SuppliedIn struct {
	Header []string `json:"header"`
	Query  []string `json:"query"`
}
