package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	Spec              VirtualServerSpec `json:"spec"`
	// Status contains the current status of the VirtualServer.
	Status VirtualServerStatus `json:"status"`
}

// VirtualServerSpec is the spec of the VirtualServer resource.
type VirtualServerSpec struct {
	// Specifies which Ingress Controller must handle the VirtualServerRoute resource. Must be the same as the ingressClassName of the VirtualServer that references this resource.
	IngressClass string `json:"ingressClassName"`
	// The host (domain name) of the server. Must be a valid subdomain as defined in RFC 1123, such as my-app or hello.example.com. When using a wildcard domain like *.example.com the domain must be contained in double quotes. The host value needs to be unique among all Ingress and VirtualServer resources.
	Host string `json:"host"`
	// Sets a custom HTTP and/or HTTPS listener. Valid fields are listener.http and listener.https. Each field must reference the name of a valid listener defined in a GlobalConfiguration resource
	Listener *VirtualServerListener `json:"listener"`
	// The TLS termination configuration.
	TLS *TLS `json:"tls"`
	// Enables or disables decompression of gzipped responses for clients. Allowed values “on”/“off”, “true”/“false” or “yes”/“no”. If the gunzip value is not set, it defaults to off.
	Gunzip bool `json:"gunzip"`
	// A list of policies.
	Policies []PolicyReference `json:"policies"`
	// A list of upstreams.
	Upstreams []Upstream `json:"upstreams"`
	// A list of routes.
	Routes []Route `json:"routes"`
	// Sets a custom snippet in the http context.
	HTTPSnippets string `json:"http-snippets"`
	// Sets a custom snippet in server context. Overrides the server-snippets ConfigMap key.
	ServerSnippets string `json:"server-snippets"`
	// A reference to a DosProtectedResource, setting this enables DOS protection of the VirtualServer route.
	Dos string `json:"dos"`
	// The externalDNS configuration for a VirtualServer.
	ExternalDNS ExternalDNS `json:"externalDNS"`
	// InternalRoute allows for the configuration of internal routing.
	InternalRoute bool `json:"internalRoute"`
}

// VirtualServerListener references a custom http and/or https listener defined in GlobalConfiguration.
type VirtualServerListener struct {
	// The name of an HTTP listener defined in a GlobalConfiguration resource.
	HTTP string `json:"http"`
	// The name of an HTTPS listener defined in a GlobalConfiguration resource.
	HTTPS string `json:"https"`
}

// ExternalDNS defines externaldns sub-resource of a virtual server.
type ExternalDNS struct {
	// Enables ExternalDNS integration for a VirtualServer resource. The default is false.
	Enable bool `json:"enable"`
	// The record Type that should be created, e.g. “A”, “AAAA”, “CNAME”. This is automatically computed based on the external endpoints if not defined.
	RecordType string `json:"recordType,omitempty"`
	// TTL for the DNS record. This defaults to 0 if not defined.
	RecordTTL int64 `json:"recordTTL,omitempty"`
	// Configure labels to be applied to the Endpoint resources that will be consumed by ExternalDNS.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Configure provider specific properties which holds the name and value of a configuration which is specific to individual DNS providers.
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
	// The name of a policy. If the policy doesn’t exist or invalid, NGINX will respond with an error response with the 500 status code.
	Name string `json:"name"`
	// The namespace of a policy. If not specified, the namespace of the VirtualServer resource is used.
	Namespace string `json:"namespace"`
}

// Upstream defines an upstream.
type Upstream struct {
	// The name of the upstream. Must be a valid DNS label as defined in RFC 1035. For example, hello and upstream-123 are valid. The name must be unique among all upstreams of the resource.
	Name string `json:"name"`
	// The name of a service. The service must belong to the same namespace as the resource. If the service doesn’t exist, NGINX will assume the service has zero endpoints and return a 502 response for requests for this upstream. For NGINX Plus only, services of type ExternalName are also supported .
	Service string `json:"service"`
	// Selects the pods within the service using label keys and values. By default, all pods of the service are selected. Note: the specified labels are expected to be present in the pods when they are created. If the pod labels are updated, NGINX Ingress Controller will not see that change until the number of the pods is changed.
	Subselector map[string]string `json:"subselector"`
	// The port of the service. If the service doesn’t define that port, NGINX will assume the service has zero endpoints and return a 502 response for requests for this upstream. The port must fall into the range 1..65535.
	Port uint16 `json:"port"`
	// The load balancing method. To use the round-robin method, specify round_robin. The default is specified in the lb-method ConfigMap key.
	LBMethod string `json:"lb-method"`
	// The time during which the specified number of unsuccessful attempts to communicate with an upstream server should happen to consider the server unavailable. The default is set in the fail-timeout ConfigMap key.
	FailTimeout string `json:"fail-timeout"`
	// The number of unsuccessful attempts to communicate with an upstream server that should happen in the duration set by the fail-timeout to consider the server unavailable. The default is set in the max-fails ConfigMap key.
	MaxFails *int `json:"max-fails"`
	// The maximum number of simultaneous active connections to an upstream server. By default there is no limit. Note: if keepalive connections are enabled, the total number of active and idle keepalive connections to an upstream server may exceed the max_conns value.
	MaxConns *int `json:"max-conns"`
	// Configures the cache for connections to upstream servers. The value 0 disables the cache. The default is set in the keepalive ConfigMap key.
	Keepalive *int `json:"keepalive"`
	// The timeout for establishing a connection with an upstream server. The default is specified in the proxy-connect-timeout ConfigMap key.
	ProxyConnectTimeout string `json:"connect-timeout"`
	// The timeout for reading a response from an upstream server. The default is specified in the proxy-read-timeout ConfigMap key.
	ProxyReadTimeout string `json:"read-timeout"`
	// The timeout for transmitting a request to an upstream server. The default is specified in the proxy-send-timeout ConfigMap key.
	ProxySendTimeout string `json:"send-timeout"`
	// Specifies in which cases a request should be passed to the next upstream server. The default is error timeout.
	ProxyNextUpstream string `json:"next-upstream"`
	// The time during which a request can be passed to the next upstream server. The 0 value turns off the time limit. The default is 0.
	ProxyNextUpstreamTimeout string `json:"next-upstream-timeout"`
	// The number of possible tries for passing a request to the next upstream server. The 0 value turns off this limit. The default is 0.
	ProxyNextUpstreamTries int `json:"next-upstream-tries"`
	// Enables buffering of responses from the upstream server.  The default is set in the proxy-buffering ConfigMap key.
	ProxyBuffering *bool `json:"buffering"`
	// Configures the buffers used for reading a response from the upstream server for a single connection.
	ProxyBuffers *UpstreamBuffers `json:"buffers"`
	// Sets the size of the buffer used for reading the first part of a response received from the upstream server. The default is set in the proxy-buffer-size ConfigMap key.
	ProxyBufferSize string `json:"buffer-size"`
	// Sets the size of the buffers used for reading a response from the upstream server when the proxy_buffering is enabled. The default is set in the proxy-busy-buffers-size ConfigMap key.'
	ProxyBusyBuffersSize string `json:"busy-buffers-size"`
	// Sets the maximum allowed size of the client request body. The default is set in the client-max-body-size ConfigMap key.
	ClientMaxBodySize string `json:"client-max-body-size"`
	// The TLS configuration for the Upstream.
	TLS UpstreamTLS `json:"tls"`
	// The health check configuration for the Upstream. Note: this feature is supported only in NGINX Plus.
	HealthCheck *HealthCheck `json:"healthCheck"`
	// The slow start allows an upstream server to gradually recover its weight from 0 to its nominal value after it has been recovered or became available or when the server becomes available after a period of time it was considered unavailable. By default, the slow start is disabled. Note: The parameter cannot be used along with the random, hash or ip_hash load balancing methods and will be ignored.
	SlowStart string `json:"slow-start"`
	// Configures a queue for an upstream. A client request will be placed into the queue if an upstream server cannot be selected immediately while processing the request. By default, no queue is configured. Note: this feature is supported only in NGINX Plus.
	Queue *UpstreamQueue `json:"queue"`
	// The SessionCookie field configures session persistence which allows requests from the same client to be passed to the same upstream server. The information about the designated upstream server is passed in a session cookie generated by NGINX Plus.
	SessionCookie *SessionCookie `json:"sessionCookie"`
	// Enables using the Cluster IP and port of the service instead of the default behavior of using the IP and port of the pods. When this field is enabled, the fields that configure NGINX behavior related to multiple upstream servers (like lb-method and next-upstream) will have no effect, as NGINX Ingress Controller will configure NGINX with only one upstream server that will match the service Cluster IP.
	UseClusterIP bool `json:"use-cluster-ip"`
	// Allows proxying requests with NTLM Authentication. In order for NTLM authentication to work, it is necessary to enable keepalive connections to upstream servers using the keepalive field. Note: this feature is supported only in NGINX Plus.
	NTLM bool `json:"ntlm"`
	// The type of the upstream. Supported values are http and grpc. The default is http. For gRPC, it is necessary to enable HTTP/2 in the ConfigMap and configure TLS termination in the VirtualServer.
	Type string `json:"type"`
	// The name of the backup service of type ExternalName. This will be used when the primary servers are unavailable. Note: The parameter cannot be used along with the random, hash or ip_hash load balancing methods.
	Backup string `json:"backup"`
	// The port of the backup service. The backup port is required if the backup service name is provided. The port must fall into the range 1..65535.
	BackupPort *uint16 `json:"backupPort"`
}

// UpstreamBuffers defines Buffer Configuration for an Upstream.
type UpstreamBuffers struct {
	// Configures the number of buffers. The default is set in the proxy-buffers ConfigMap key.
	Number int `json:"number"`
	// Configures the size of a buffer. The default is set in the proxy-buffers ConfigMap key.
	Size string `json:"size"`
}

// UpstreamTLS defines a TLS configuration for an Upstream.
type UpstreamTLS struct {
	// Enables HTTPS for requests to upstream servers. The default is False , meaning that HTTP will be used. Note: by default, NGINX will not verify the upstream server certificate. To enable the verification, configure an EgressMTLS Policy.
	Enable bool `json:"enable"`
}

// HealthCheck defines the parameters for active Upstream HealthChecks.
type HealthCheck struct {
	// Enables a health check for an upstream server. The default is false.
	Enable bool `json:"enable"`
	// The path used for health check requests. The default is /. This is not configurable for gRPC type upstreams.
	Path string `json:"path"`
	// The interval between two consecutive health checks. The default is 5s.
	Interval string `json:"interval"`
	// The time within which each health check will be randomly delayed. By default, there is no delay.
	Jitter string `json:"jitter"`
	// The number of consecutive failed health checks of a particular upstream server after which this server will be considered unhealthy. The default is 1.
	Fails int `json:"fails"`
	// The number of consecutive passed health checks of a particular upstream server after which the server will be considered healthy. The default is 1.
	Passes int `json:"passes"`
	// The port used for health check requests. By default, the server port is used. Note: in contrast with the port of the upstream, this port is not a service port, but a port of a pod.
	Port int `json:"port"`
	// The TLS configuration used for health check requests. By default, the tls field of the upstream is used.
	TLS *UpstreamTLS `json:"tls"`
	// The timeout for establishing a connection with an upstream server. By default, the connect-timeout of the upstream is used.
	ConnectTimeout string `json:"connect-timeout"`
	// The timeout for reading a response from an upstream server. By default, the read-timeout of the upstream is used.
	ReadTimeout string `json:"read-timeout"`
	// The timeout for transmitting a request to an upstream server. By default, the send-timeout of the upstream is used.
	SendTimeout string `json:"send-timeout"`
	// The request headers used for health check requests. NGINX Plus always sets the Host, User-Agent and Connection headers for health check requests.
	Headers []Header `json:"headers"`
	// The expected response status codes of a health check. By default, the response should have status code 2xx or 3xx. Examples: "200", "! 500", "301-303 307". This not supported for gRPC type upstreams.
	StatusMatch string `json:"statusMatch"`
	// The expected gRPC status code of the upstream server response to the Check method. Configure this field only if your gRPC services do not implement the gRPC health checking protocol. For example, configure 12 if the upstream server responds with 12 (UNIMPLEMENTED) status code. Only valid on gRPC type upstreams.
	GRPCStatus *int `json:"grpcStatus"`
	// The gRPC service to be monitored on the upstream server. Only valid on gRPC type upstreams.
	GRPCService string `json:"grpcService"`
	// Require every newly added server to pass all configured health checks before NGINX Plus sends traffic to it. If this is not specified, or is set to false, the server will be initially considered healthy. When combined with slow-start, it gives a new server more time to connect to databases and “warm up” before being asked to handle their full share of traffic.
	Mandatory bool `json:"mandatory"`
	// Set the initial “up” state for a server after reload if the server was considered healthy before reload. Enabling persistent requires that the mandatory parameter is also set to true.
	Persistent bool `json:"persistent"`
	// Enables keepalive connections for health checks and specifies the time during which requests can be processed through one keepalive connection. The default is 60s.
	KeepaliveTime string `json:"keepalive-time"`
}

// Header defines an HTTP Header.
type Header struct {
	// The name of the header.
	Name string `json:"name"`
	// The value of the header.
	Value string `json:"value"`
}

// SessionCookie defines the parameters for session persistence.
type SessionCookie struct {
	// Enables session persistence with a session cookie for an upstream server. The default is false.
	Enable bool `json:"enable"`
	// The name of the cookie.
	Name string `json:"name"`
	// The path for which the cookie is set.
	Path string `json:"path"`
	// The time for which a browser should keep the cookie. Can be set to the special value max, which will cause the cookie to expire on 31 Dec 2037 23:55:55 GMT.
	Expires string `json:"expires"`
	// The domain for which the cookie is set.
	Domain string `json:"domain"`
	// Adds the HttpOnly attribute to the cookie.
	HTTPOnly bool `json:"httpOnly"`
	// Adds the Secure attribute to the cookie.
	Secure bool `json:"secure"`
	// Adds the SameSite attribute to the cookie. The allowed values are: strict, lax, none
	SameSite string `json:"samesite"`
}

// Route defines a route.
type Route struct {
	// The path of the route. NGINX will match it against the URI of a request. Possible values are: a prefix ( / , /path ), an exact match ( =/exact/match ), a case insensitive regular expression ( ~*^/Bar.*\.jpg ) or a case sensitive regular expression ( ~^/foo.*\.jpg ). In the case of a prefix (must start with / ) or an exact match (must start with = ), the path must not include any whitespace characters, { , } or ;. In the case of the regex matches, all double quotes " must be escaped and the match can’t end in an unescaped backslash \. The path must be unique among the paths of all routes of the VirtualServer. Check the location directive for more information.
	Path string `json:"path"`
	// A list of policies. The policies override the policies of the same type defined in the spec of the VirtualServer.
	Policies []PolicyReference `json:"policies"`
	// The name of a VirtualServerRoute resource that defines this route. If the VirtualServerRoute belongs to a different namespace than the VirtualServer, you need to include the namespace. For example, tea-namespace/tea.
	Route string `json:"route"`
	// The default action to perform for a request.
	Action *Action `json:"action"`
	// The default splits configuration for traffic splitting. Must include at least 2 splits.
	Splits []Split `json:"splits"`
	// The matching rules for advanced content-based routing. Requires the default Action or Splits. Unmatched requests will be handled by the default Action or Splits.
	Matches []Match `json:"matches"`
	// The custom responses for error codes. NGINX will use those responses instead of returning the error responses from the upstream servers or the default responses generated by NGINX. A custom response can be a redirect or a canned response. For example, a redirect to another URL if an upstream server responded with a 404 status code.
	ErrorPages []ErrorPage `json:"errorPages"`
	// Sets a custom snippet in the location context. Overrides the location-snippets ConfigMap key.
	LocationSnippets string `json:"location-snippets"`
	// A reference to a DosProtectedResource, setting this enables DOS protection of the VirtualServer route.
	Dos string `json:"dos"`
}

// Action defines an action.
type Action struct {
	// Passes requests to an upstream. The upstream with that name must be defined in the resource.
	Pass string `json:"pass"`
	// Redirects requests to a provided URL.
	Redirect *ActionRedirect `json:"redirect"`
	// Returns a preconfigured response.
	Return *ActionReturn `json:"return"`
	// Passes requests to an upstream with the ability to modify the request/response (for example, rewrite the URI or modify the headers).
	Proxy *ActionProxy `json:"proxy"`
}

// ActionRedirect defines a redirect in an Action.
type ActionRedirect struct {
	// The URL to redirect the request to. Supported NGINX variables: $scheme, $http_x_forwarded_proto, $request_uri or $host. Variables must be enclosed in curly braces. For example: ${host}${request_uri}.
	URL string `json:"url"`
	// The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301.
	Code int `json:"code"`
}

// ActionReturn defines a return in an Action.
type ActionReturn struct {
	// The status code of the response. The allowed values are: 2XX, 4XX or 5XX. The default is 200.
	Code int `json:"code"`
	// The MIME type of the response. The default is text/plain.
	Type string `json:"type"`
	// The body of the response. Supports NGINX variables*. Variables must be enclosed in curly brackets. For example: Request is ${request_uri}\n.
	Body string `json:"body"`
	// The custom headers of the response.
	Headers []Header `json:"headers"`
}

// ActionProxy defines a proxy in an Action.
type ActionProxy struct {
	// The name of the upstream which the requests will be proxied to. The upstream with that name must be defined in the resource.
	Upstream string `json:"upstream"`
	// The rewritten URI. If the route path is a regular expression – starts with ~ – the rewritePath can include capture groups with $1-9. For example $1 for the first group, and so on. For more information, check the rewrite example.
	RewritePath string `json:"rewritePath"`
	// The request headers modifications.
	RequestHeaders *ProxyRequestHeaders `json:"requestHeaders"`
	// The response headers modifications.
	ResponseHeaders *ProxyResponseHeaders `json:"responseHeaders"`
}

// ProxyRequestHeaders defines the request headers manipulation in an ActionProxy.
type ProxyRequestHeaders struct {
	// Passes the original request headers to the proxied upstream server.  Default is true.
	Pass *bool `json:"pass"`
	// Allows redefining or appending fields to present request headers passed to the proxied upstream servers.
	Set []Header `json:"set"`
}

// ProxyResponseHeaders defines the response headers manipulation in an ActionProxy.
type ProxyResponseHeaders struct {
	// The headers that will not be passed* in the response to the client from a proxied upstream server.
	Hide []string `json:"hide"`
	// Allows passing the hidden header fields* to the client from a proxied upstream server.
	Pass []string `json:"pass"`
	// Disables processing of certain headers** to the client from a proxied upstream server.
	Ignore []string `json:"ignore"`
	// Adds headers to the response to the client.
	Add []AddHeader `json:"add"`
}

// AddHeader defines an HTTP Header with an optional Always field to use with the add_header NGINX directive.
type AddHeader struct {
	Header `json:",inline"`
	// If set to true, add the header regardless of the response status code**. Default is false.
	Always bool `json:"always"`
}

// Split defines a split.
type Split struct {
	// The weight of an action. Must fall into the range 0..100. The sum of the weights of all splits must be equal to 100.
	Weight int `json:"weight"`
	// The action to perform for a request.
	Action *Action `json:"action"`
}

// Condition defines a condition in a MatchRule.
type Condition struct {
	// The name of a header. Must consist of alphanumeric characters or -.
	Header string `json:"header"`
	// The name of a cookie. Must consist of alphanumeric characters or _.
	Cookie string `json:"cookie"`
	// The name of an argument. Must consist of alphanumeric characters or _.
	Argument string `json:"argument"`
	// The name of an NGINX variable. Must start with $.
	Variable string `json:"variable"`
	// The value to match the condition against.
	Value string `json:"value"`
}

// Match defines a match.
type Match struct {
	// A list of conditions. Must include at least 1 condition.
	Conditions []Condition `json:"conditions"`
	// The action to perform for a request.
	Action *Action `json:"action"`
	// The splits configuration for traffic splitting. Must include at least 2 splits.
	Splits []Split `json:"splits"`
}

// ErrorPage defines an ErrorPage in a Route.
type ErrorPage struct {
	// A list of error status codes.
	Codes []int `json:"codes"`
	// The redirect action for the given status codes.
	Return *ErrorPageReturn `json:"return"`
	// The canned response action for the given status codes.
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
	// The name of a secret with a TLS certificate and key. The secret must belong to the same namespace as the VirtualServer. The secret must be of the type kubernetes.io/tls and contain keys named tls.crt and tls.key that contain the certificate and private key as described here. If the secret doesn’t exist or is invalid, NGINX will break any attempt to establish a TLS connection to the host of the VirtualServer. If the secret is not specified but wildcard TLS secret is configured, NGINX will use the wildcard secret for TLS termination.
	Secret string `json:"secret"`
	// The redirect configuration of the TLS for a VirtualServer.
	Redirect *TLSRedirect `json:"redirect"`
	// The cert-manager configuration of the TLS for a VirtualServer.
	CertManager *CertManager `json:"cert-manager"`
}

// TLSRedirect defines a redirect for a TLS.
type TLSRedirect struct {
	// Enables a TLS redirect for a VirtualServer. The default is False.
	Enable bool `json:"enable"`
	// The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301.
	Code *int `json:"code"`
	// The attribute of a request that NGINX will evaluate to send a redirect. The allowed values are scheme (the scheme of the request) or x-forwarded-proto (the X-Forwarded-Proto header of the request). The default is scheme.
	BasedOn string `json:"basedOn"`
}

// CertManager defines a cert manager config for a TLS.
type CertManager struct {
	// the name of a ClusterIssuer. A ClusterIssuer is a cert-manager resource which describes the certificate authority capable of signing certificates. It does not matter which namespace your VirtualServer resides, as ClusterIssuers are non-namespaced resources. Please note that one of issuer and cluster-issuer are required, but they are mutually exclusive - one and only one must be defined.
	ClusterIssuer string `json:"cluster-issuer"`
	// the name of an Issuer. An Issuer is a cert-manager resource which describes the certificate authority capable of signing certificates. The Issuer must be in the same namespace as the VirtualServer resource. Please note that one of issuer and cluster-issuer are required, but they are mutually exclusive - one and only one must be defined.
	Issuer string `json:"issuer"`
	// The kind of the external issuer resource, for example AWSPCAIssuer. This is only necessary for out-of-tree issuers. This cannot be defined if cluster-issuer is also defined.
	IssuerKind string `json:"issuer-kind"`
	// The API group of the external issuer controller, for example awspca.cert-manager.io. This is only necessary for out-of-tree issuers. This cannot be defined if cluster-issuer is also defined.
	IssuerGroup string `json:"issuer-group"`
	// This field allows you to configure spec.commonName for the Certificate to be generated. This configuration adds a CN to the x509 certificate.
	CommonName string `json:"common-name"`
	// This field allows you to configure spec.duration field for the Certificate to be generated. Must be specified using a Go time.Duration string format, which does not allow the d (days) suffix. You must specify these values using s, m, and h suffixes instead.
	Duration string `json:"duration"`
	// this annotation allows you to configure spec.renewBefore field for the Certificate to be generated. Must be specified using a Go time.Duration string format, which does not allow the d (days) suffix. You must specify these values using s, m, and h suffixes instead.
	RenewBefore string `json:"renew-before"`
	// This field allows you to configure spec.usages field for the Certificate to be generated. Pass a string with comma-separated values i.e. key agreement,digital signature, server auth. An exhaustive list of supported key usages can be found in the the cert-manager api documentation.
	Usages string `json:"usages"`
	// When true, ask cert-manager for a temporary self-signed certificate pending the issuance of the Certificate. This allows HTTPS-only servers to use ACME HTTP01 challenges when the TLS secret does not exist yet.
	IssueTempCert bool `json:"issue-temp-cert"`
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
	// Specifies which Ingress Controller must handle the VirtualServerRoute resource. Must be the same as the ingressClassName of the VirtualServer that references this resource.
	IngressClass string `json:"ingressClassName"`
	// The host (domain name) of the server. Must be a valid subdomain as defined in RFC 1123, such as my-app or hello.example.com. When using a wildcard domain like *.example.com the domain must be contained in double quotes. Must be the same as the host of the VirtualServer that references this resource.
	Host string `json:"host"`
	// A list of upstreams.
	Upstreams []Upstream `json:"upstreams"`
	// A list of subroutes.
	Subroutes []Route `json:"subroutes"`
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
	// The size of the queue.
	Size int `json:"size"`
	// The timeout of the queue. A request cannot be queued for a period longer than the timeout. The default is 60s.
	Timeout string `json:"timeout"`
}

// VirtualServerRouteStatus defines the status for the VirtualServerRoute resource.
type VirtualServerRouteStatus struct {
	// Represents the current state of the resource. There are three possible values: Valid, Invalid and Warning. Valid indicates that the resource has been validated and accepted by the Ingress Controller. Invalid means the resource failed validation or NGINX
	State string `json:"state"`
	// The reason of the current state of the resource.
	Reason string `json:"reason"`
	// The message of the current state of the resource. It can contain more detailed information about the reason.
	Message string `json:"message"`
	// Defines how other resources reference this resource.
	ReferencedBy string `json:"referencedBy"`
	// Defines the IPs, hostnames and ports used to connect to this resource.
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
	Spec              GlobalConfigurationSpec `json:"spec"`
}

// GlobalConfigurationSpec resource defines the global configuration parameters of the Ingress Controller.
type GlobalConfigurationSpec struct {
	// Listeners field of the GlobalConfigurationSpec resource
	Listeners []Listener `json:"listeners"`
}

// Listener defines a listener.
type Listener struct {
	// The name of the listener. The name must be unique across all listeners.
	Name string `json:"name"`
	// The protocol of the listener. For example, HTTP.
	Protocol string `json:"protocol"`
	// The port on which the listener will accept connections.
	Port int `json:"port"`
	// Specifies the IPv4 address to listen on.
	IPv4 string `json:"ipv4"`
	// ipv6 addresse that NGINX will listen on.
	IPv6 string `json:"ipv6"`
	// Whether the listener will be listening for SSL connections
	Ssl bool `json:"ssl"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalConfigurationList is a list of the GlobalConfiguration resources.
type GlobalConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	// Items field of the GlobalConfigurationList resource

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
	Spec              TransportServerSpec `json:"spec"`
	// The status of the TransportServer resource
	Status TransportServerStatus `json:"status"`
}

// TransportServerSpec is the spec of the TransportServer resource.
type TransportServerSpec struct {
	// Specifies which Ingress Controller must handle the VirtualServer resource.
	IngressClass string `json:"ingressClassName"`
	// The TLS termination configuration.
	TLS *TransportServerTLS `json:"tls"`
	// Sets a custom HTTP and/or HTTPS listener. Valid fields are listener.http and listener.https. Each field must reference the name of a valid listener defined in a GlobalConfiguration resource
	Listener TransportServerListener `json:"listener"`
	// Sets a custom snippet in server context. Overrides the server-snippets ConfigMap key.
	ServerSnippets string `json:"serverSnippets"`
	// Sets a custom snippet in the stream context. Overrides the stream-snippets ConfigMap key.
	StreamSnippets string `json:"streamSnippets"`
	// The host (domain name) of the server. Must be a valid subdomain as defined in RFC 1123, such as my-app or hello.example.com. When using a wildcard domain like *.example.com the domain must be contained in double quotes. The host value needs to be unique among all Ingress and VirtualServer resources.
	Host string `json:"host"`
	// A list of upstreams.
	Upstreams []TransportServerUpstream `json:"upstreams"`
	// UpstreamParameters defines parameters for an upstream.
	UpstreamParameters *UpstreamParameters `json:"upstreamParameters"`
	// The parameters of the session to be used for the Server context
	SessionParameters *SessionParameters `json:"sessionParameters"`
	// The action to perform for a request.
	Action *TransportServerAction `json:"action"`
}

// TransportServerTLS defines TransportServerTLS configuration for a TransportServer.
type TransportServerTLS struct {
	Secret string `json:"secret"`
}

// TransportServerListener defines a listener for a TransportServer.
type TransportServerListener struct {
	// The name of a listener defined in a GlobalConfiguration resource.
	Name string `json:"name"`
	// The protocol of the listener.
	Protocol string `json:"protocol"`
}

// TransportServerUpstream defines an upstream.
type TransportServerUpstream struct {
	// The name of the upstream. Must be a valid DNS label as defined in RFC 1035. For example, hello and upstream-123 are valid. The name must be unique among all upstreams of the resource.
	Name string `json:"name"`
	// The name of a service. The service must belong to the same namespace as the resource. If the service doesn’t exist, NGINX will assume the service has zero endpoints and close client connections/ignore datagrams.
	Service string `json:"service"`
	// The port of the service. If the service doesn’t define that port, NGINX will assume the service has zero endpoints and close client connections/ignore datagrams. The port must fall into the range 1..65535.
	Port int `json:"port"`
	// Sets the number of unsuccessful attempts to communicate with the server that should happen in the duration set by the failTimeout parameter to consider the server unavailable. The default is 1.
	FailTimeout string `json:"failTimeout"`
	// Sets the number of maximum connections to the proxied server. Default value is zero, meaning there is no limit. The default is 0.
	MaxFails *int `json:"maxFails"`
	// Sets the time during which the specified number of unsuccessful attempts to communicate with the server should happen to consider the server unavailable and the period of time the server will be considered unavailable. The default is 10s.
	MaxConns *int `json:"maxConns"`
	// The health check configuration for the Upstream. Note: this feature is supported only in NGINX Plus.
	HealthCheck *TransportServerHealthCheck `json:"healthCheck"`
	// The method used to load balance the upstream servers. By default, connections are distributed between the servers using a weighted round-robin balancing method.
	LoadBalancingMethod string `json:"loadBalancingMethod"`
	// The name of the backup service of type ExternalName. This will be used when the primary servers are unavailable. Note: The parameter cannot be used along with the random, hash or ip_hash load balancing methods.
	Backup string `json:"backup"`
	// The port of the backup service. The backup port is required if the backup service name is provided. The port must fall into the range 1..65535.
	BackupPort *uint16 `json:"backupPort"`
}

// TransportServerHealthCheck defines the parameters for active Upstream HealthChecks.
type TransportServerHealthCheck struct {
	// Enables a health check for an upstream server. The default is false.
	Enabled bool `json:"enable"`
	// This overrides the timeout set by proxy_timeout which is set in SessionParameters for health checks. The default value is 5s.
	Timeout string `json:"timeout"`
	// The time within which each health check will be randomly delayed. By default, there is no delay.
	Jitter string `json:"jitter"`
	// The port used for health check requests. By default, the server port is used. Note: in contrast with the port of the upstream, this port is not a service port, but a port of a pod.
	Port int `json:"port"`
	// The interval between two consecutive health checks. The default is 5s.
	Interval string `json:"interval"`
	// The number of consecutive passed health checks of a particular upstream server after which the server will be considered healthy. The default is 1.
	Passes int `json:"passes"`
	// The number of consecutive failed health checks of a particular upstream server after which this server will be considered unhealthy. The default is 1.
	Fails int `json:"fails"`
	// Controls the data to send and the response to expect for the healthcheck.
	Match *TransportServerMatch `json:"match"`
}

// TransportServerMatch defines the parameters of a custom health check.
type TransportServerMatch struct {
	// A string to send to an upstream server.
	Send string `json:"send"`
	// A literal string or a regular expression that the data obtained from the server should match. The regular expression is specified with the preceding ~* modifier (for case-insensitive matching), or the ~ modifier (for case-sensitive matching). NGINX Ingress Controller validates a regular expression using the RE2 syntax.
	Expect string `json:"expect"`
}

// UpstreamParameters defines parameters for an upstream.
type UpstreamParameters struct {
	// The number of datagrams, after receiving which, the next datagram from the same client starts a new session. The default is 0.
	UDPRequests *int `json:"udpRequests"`
	// The number of datagrams expected from the proxied server in response to a client datagram.  By default, the number of datagrams is not limited.
	UDPResponses *int `json:"udpResponses"`
	// The timeout for establishing a connection with a proxied server.  The default is 60s.
	ConnectTimeout string `json:"connectTimeout"`
	// If a connection to the proxied server cannot be established, determines whether a client connection will be passed to the next server. The default is true.
	NextUpstream bool `json:"nextUpstream"`
	// The time allowed to pass a connection to the next server. The default is 0.
	NextUpstreamTimeout string `json:"nextUpstreamTimeout"`
	// The number of tries for passing a connection to the next server. The default is 0.
	NextUpstreamTries int `json:"nextUpstreamTries"`
}

// SessionParameters defines session parameters.
type SessionParameters struct {
	// The timeout between two successive read or write operations on client or proxied server connections. The default is 10m.
	Timeout string `json:"timeout"`
}

// TransportServerAction defines an action.
type TransportServerAction struct {
	// Passes connections/datagrams to an upstream. The upstream with that name must be defined in the resource.
	Pass string `json:"pass"`
}

// TransportServerStatus defines the status for the TransportServer resource.
type TransportServerStatus struct {
	// Represents the current state of the resource. Possible values: Valid (resource validated and accepted), Invalid (validation failed or config reload failed), or Warning (validated but may work in degraded state).
	State string `json:"state"`
	// The reason of the current state of the resource.
	Reason string `json:"reason"`
	// The message of the current state of the resource. It can contain more detailed information about the reason.
	Message string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TransportServerList is a list of the TransportServer resources.
type TransportServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TransportServer `json:"items"`
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
	Spec              PolicySpec `json:"spec"`
	// the status of the Policy resource
	Status PolicyStatus `json:"status"`
}

// PolicyStatus is the status of the policy resource
type PolicyStatus struct {
	// Represents the current state of the resource. There are three possible values: Valid, Invalid and Warning. Valid indicates that the resource has been validated and accepted by the Ingress Controller. Invalid means the resource failed validation or
	State string `json:"state"`
	// The reason of the current state of the resource.
	Reason string `json:"reason"`
	// The message of the current state of the resource. It can contain more detailed information about the reason.
	Message string `json:"message"`
}

// PolicySpec is the spec of the Policy resource.
// The spec includes multiple fields, where each field represents a different policy.
// Only one policy (field) is allowed.
type PolicySpec struct {
	// Specifies which instance of NGINX Ingress Controller must handle the Policy resource.
	IngressClass string `json:"ingressClassName"`
	// The access control policy based on the client IP address.
	AccessControl *AccessControl `json:"accessControl"`
	// The rate limit policy controls the rate of processing requests per a defined key.
	RateLimit *RateLimit `json:"rateLimit"`
	// The JWT policy configures NGINX Plus to authenticate client requests using JSON Web Tokens.
	JWTAuth *JWTAuth `json:"jwt"`
	// The basic auth policy configures NGINX to authenticate client requests using HTTP Basic authentication credentials.
	BasicAuth *BasicAuth `json:"basicAuth"`
	// The IngressMTLS policy configures client certificate verification.
	IngressMTLS *IngressMTLS `json:"ingressMTLS"`
	// The EgressMTLS policy configures upstreams authentication and certificate verification.
	EgressMTLS *EgressMTLS `json:"egressMTLS"`
	// The OpenID Connect policy configures NGINX to authenticate client requests by validating a JWT token against an OAuth2/OIDC token provider, such as Auth0 or Keycloak.
	OIDC *OIDC `json:"oidc"`
	// The WAF policy configures WAF and log configuration policies for NGINX AppProtect
	WAF *WAF `json:"waf"`
	// The API Key policy configures NGINX to authorize requests which provide a valid API Key in a specified header or query param.
	APIKey *APIKey `json:"apiKey"`
	// The Cache Key defines a cache policy for proxy caching
	Cache *Cache `json:"cache"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolicyList is a list of the Policy resources.
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items field of the PolicyList resource
	Items []Policy `json:"items"`
}

// AccessControl defines an access policy based on the source IP of a request.
type AccessControl struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// RateLimit defines a rate limit policy.
type RateLimit struct {
	// The rate of requests permitted. The rate is specified in requests per second (r/s) or requests per minute (r/m).
	Rate string `json:"rate"`
	// The key to which the rate limit is applied. Can contain text, variables, or a combination of them.
	// Variables must be surrounded by ${}. For example: ${binary_remote_addr}. Accepted variables are
	// $binary_remote_addr, $request_uri, $request_method, $url, $http_, $args, $arg_, $cookie_,$jwt_claim_ .
	Key string `json:"key"`
	// The delay parameter specifies a limit at which excessive requests become delayed. If not set all excessive requests are delayed.
	Delay *int `json:"delay"`
	// Disables the delaying of excessive requests while requests are being limited. Overrides delay if both are set.
	NoDelay *bool `json:"noDelay"`
	// Excessive requests are delayed until their number exceeds the burst size, in which case the request is terminated with an error.
	Burst *int `json:"burst"`
	// Size of the shared memory zone. Only positive values are allowed. Allowed suffixes are k or m, if none are present k is assumed.
	ZoneSize string `json:"zoneSize"`
	// Enables the dry run mode. In this mode, the rate limit is not actually applied, but the number of excessive requests is accounted as usual in the shared memory zone.
	DryRun *bool `json:"dryRun"`
	// Sets the desired logging level for cases when the server refuses to process requests due to rate exceeding, or delays request processing. Allowed values are info, notice, warn or error. Default is error.
	LogLevel string `json:"logLevel"`
	// Sets the status code to return in response to rejected requests. Must fall into the range 400..599. Default is 503.
	RejectCode *int `json:"rejectCode"`
	// Enables a constant rate-limit by dividing the configured rate by the number of nginx-ingress pods currently serving traffic. This adjustment ensures that the rate-limit remains consistent, even as the number of nginx-pods fluctuates due to autoscaling. This will not work properly if requests from a client are not evenly distributed across all ingress pods (Such as with sticky sessions, long lived TCP Connections with many requests, and so forth). In such cases using zone-sync instead would give better results. Enabling zone-sync will suppress this setting.
	Scale bool `json:"scale"`
	// Add a condition to a rate-limit policy.
	// +kubebuilder:validation:Optional
	Condition *RateLimitCondition `json:"condition"`
}

// RateLimitCondition defines a condition for a rate limit policy.
type RateLimitCondition struct {
	// defines a JWT condition to rate limit against.
	JWT *JWTCondition `json:"jwt"`
	// defines a Variables condition to rate limit against.
	// +kubebuilder:validation:MaxItems=1
	Variables *[]VariableCondition `json:"variables"`
	// +kubebuilder:validation:Optional
	// sets the rate limit in this policy to be the default if no conditions are met. In a group of policies with the same condition, only one policy can be the default.
	Default bool `json:"default"`
}

// JWTCondition defines a condition for a rate limit by JWT claim.
type JWTCondition struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([^$\s"'])*$`
	// the JWT claim to be rate limit by. Nested claims should be separated by "."
	Claim string `json:"claim"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([^$\s."'])*$`
	// the value of the claim to match against.
	Match string `json:"match"`
}

// VariableCondition defines a condition to rate limit by a variable.
type VariableCondition struct {
	// +kubebuilder:validation:Pattern=`^([^\s"'])*$`
	// +kubebuilder:validation:Required
	// the name of the variable to match against.
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([^\s"'])*$`
	// the value of the variable to match against.
	Match string `json:"match"`
}

// JWTAuth holds JWT authentication configuration.
type JWTAuth struct {
	// The realm of the JWT.
	Realm string `json:"realm"`
	// The name of the Kubernetes secret that stores the Htpasswd configuration. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/htpasswd, and the config must be stored in the secret under the key htpasswd, otherwise the secret will be rejected as invalid.
	Secret string `json:"secret"`
	// The token specifies a variable that contains the JSON Web Token. By default the JWT is passed in the Authorization header as a Bearer Token. JWT may be also passed as a cookie or a part of a query string, for example: $cookie_auth_token. Accepted variables are $http_, $arg_, $cookie_.
	Token string `json:"token"`
	// The remote URI where the request will be sent to retrieve JSON Web Key set
	JwksURI string `json:"jwksURI"`
	// Enables in-memory caching of JWKS (JSON Web Key Sets) that are obtained from the jwksURI and sets a valid time for expiration.
	KeyCache string `json:"keyCache"`
	// Enables SNI (Server Name Indication) for the JWT policy. This is useful when the remote server requires SNI to serve the correct certificate.
	SNIEnabled bool `json:"sniEnabled"`
	// The SNI name to use when connecting to the remote server. If not set, the hostname from the ``jwksURI`` will be used.
	SNIName string `json:"sniName"`
}

// BasicAuth holds HTTP Basic authentication configuration
type BasicAuth struct {
	// The realm for the basic authentication.
	Realm string `json:"realm"`
	// The name of the Kubernetes secret that stores the Htpasswd configuration. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/htpasswd, and the config must be stored in the secret under the key htpasswd, otherwise the secret will be rejected as invalid.
	Secret string `json:"secret"`
}

// The IngressMTLS policy configures client certificate verification.
type IngressMTLS struct {
	// The name of the Kubernetes secret that stores the CA certificate. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/ca, and the certificate must be stored in the secret under the key ca.crt, otherwise the secret will be rejected as invalid.
	ClientCertSecret string `json:"clientCertSecret"`
	// The file name of the Certificate Revocation List. NGINX Ingress Controller will look for this file in /etc/nginx/secrets
	CrlFileName string `json:"crlFileName"`
	// Verification for the client. Possible values are "on", "off", "optional", "optional_no_ca". The default is "on".
	VerifyClient string `json:"verifyClient"`
	// Sets the verification depth in the client certificates chain. The default is 1.
	VerifyDepth *int `json:"verifyDepth"`
}

// The EgressMTLS policy configures upstreams authentication and certificate verification.
type EgressMTLS struct {
	// The name of the Kubernetes secret that stores the TLS certificate and key. It must be in the same namespace as the Policy resource. The secret must be of the type kubernetes.io/tls, the certificate must be stored in the secret under the key tls.crt, and the key must be stored under the key tls.key, otherwise the secret will be rejected as invalid.
	TLSSecret string `json:"tlsSecret"`
	// Enables verification of the upstream HTTPS server certificate.
	VerifyServer bool `json:"verifyServer"`
	// Sets the verification depth in the proxied HTTPS server certificates chain. The default is 1.
	VerifyDepth *int `json:"verifyDepth"`
	// Specifies the protocols for requests to an upstream HTTPS server. The default is TLSv1 TLSv1.1 TLSv1.2.
	Protocols string `json:"protocols"`
	// Enables reuse of SSL sessions to the upstreams. The default is true.
	SessionReuse *bool `json:"sessionReuse"`
	// Specifies the enabled ciphers for requests to an upstream HTTPS server. The default is DEFAULT.
	Ciphers string `json:"ciphers"`
	// The name of the Kubernetes secret that stores the CA certificate. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/ca, and the certificate must be stored in the secret under the key ca.crt, otherwise the secret will be rejected as invalid.
	TrustedCertSecret string `json:"trustedCertSecret"`
	// Enables passing of the server name through Server Name Indication extension.
	ServerName bool `json:"serverName"`
	// Allows overriding the server name used to verify the certificate of the upstream HTTPS server.
	SSLName string `json:"sslName"`
}

// The OIDC policy configures NGINX Plus as a relying party for OpenID Connect authentication.
type OIDC struct {
	// URL for the authorization endpoint provided by your OpenID Connect provider.
	AuthEndpoint string `json:"authEndpoint"`
	// URL for the token endpoint provided by your OpenID Connect provider.
	TokenEndpoint string `json:"tokenEndpoint"`
	// URL for the JSON Web Key Set (JWK) document provided by your OpenID Connect provider.
	JWKSURI string `json:"jwksURI"`
	// The client ID provided by your OpenID Connect provider.
	ClientID string `json:"clientID"`
	// The name of the Kubernetes secret that stores the client secret provided by your OpenID Connect provider. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/oidc, and the secret under the key client-secret, otherwise the secret will be rejected as invalid. If PKCE is enabled, this should be not configured.
	ClientSecret string `json:"clientSecret"`
	// List of OpenID Connect scopes. The scope openid always needs to be present and others can be added concatenating them with a + sign, for example openid+profile+email, openid+email+userDefinedScope. The default is openid.
	Scope string `json:"scope"`
	// Allows overriding the default redirect URI. The default is /_codexch.
	RedirectURI string `json:"redirectURI"`
	// URL provided by your OpenID Connect provider to request the end user be logged out.
	EndSessionEndpoint string `json:"endSessionEndpoint"`
	// URI to redirect to after the logout has been performed. Requires endSessionEndpoint. The default is /_logout.
	PostLogoutRedirectURI string `json:"postLogoutRedirectURI"`
	// Specifies the maximum timeout in milliseconds for synchronizing ID/access tokens and shared values between Ingress Controller pods. The default is 200.
	ZoneSyncLeeway *int `json:"zoneSyncLeeway"`
	// A list of extra URL arguments to pass to the authorization endpoint provided by your OpenID Connect provider. Arguments must be URL encoded, multiple arguments may be included in the list, for example [ arg1=value1, arg2=value2 ]
	AuthExtraArgs []string `json:"authExtraArgs"`
	// Option of whether Bearer token is used to authorize NGINX to access protected backend.
	AccessTokenEnable bool `json:"accessTokenEnable"`
	// Switches Proof Key for Code Exchange on. The OpenID client needs to be in public mode. clientSecret is not used in this mode.
	PKCEEnable bool `json:"pkceEnable"`
}

// The WAF policy configures NGINX Plus to secure client requests using App Protect WAF policies.
type WAF struct {
	// Enables NGINX App Protect WAF.
	Enable bool `json:"enable"`
	// The App Protect WAF policy of the WAF. Accepts an optional namespace. Mutually exclusive with apBundle.
	ApPolicy string `json:"apPolicy"`
	// The App Protect WAF policy bundle. Mutually exclusive with apPolicy.
	ApBundle string `json:"apBundle"`
	//
	SecurityLog *SecurityLog `json:"securityLog"`
	//
	SecurityLogs []*SecurityLog `json:"securityLogs"`
}

// SecurityLog defines the security log of a WAF policy.
type SecurityLog struct {
	// Enables security log.
	Enable bool `json:"enable"`
	// The App Protect WAF log conf resource. Accepts an optional namespace. Only works with apPolicy.
	ApLogConf string `json:"apLogConf"`
	// The App Protect WAF log bundle resource. Only works with apBundle.
	ApLogBundle string `json:"apLogBundle"`
	// The log destination for the security log. Only accepted variables are syslog:server=<ip-address>; localhost; fqdn>:<port>, stderr, <absolute path to file>.
	LogDest string `json:"logDest"`
}

// The APIKey policy configures NGINX to authorize requests which provide a valid API Key in a specified header or query param.
type APIKey struct {
	// The location of the API Key. For example, $http_auth, $arg_apikey, $cookie_auth. Accepted variables are $http_, $arg_, $cookie_.
	SuppliedIn *SuppliedIn `json:"suppliedIn"`
	// The key to which the API key is applied. Can contain text, variables, or a combination of them. Accepted variables are $http_, $arg_, $cookie_.
	ClientSecret string `json:"clientSecret"`
}

// SuppliedIn defines the locations API Key should be supplied in.
type SuppliedIn struct {
	// The location of the API Key as a request header. For example, $http_auth. Accepted variables are $http_.
	Header []string `json:"header"`
	// The location of the API Key as a query param. For example, $arg_apikey. Accepted variables are $arg_.
	Query []string `json:"query"`
}

// Cache defines a cache policy for proxy caching.
// +kubebuilder:validation:XValidation:rule="!has(self.allowedCodes) || (has(self.allowedCodes) && has(self.time))",message="time is required when allowedCodes is specified"
type Cache struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9_]*[a-zA-Z0-9]$|^[a-z]$`
	// CacheZoneName defines the name of the cache zone. Must start with a lowercase letter,
	// followed by alphanumeric characters or underscores, and end with an alphanumeric character.
	// Single lowercase letters are also allowed. Examples: "cache", "my_cache", "cache1".
	CacheZoneName string `json:"cacheZoneName"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[0-9]+[kmg]$`
	// CacheZoneSize defines the size of the cache zone. Must be a number followed by a size unit:
	// 'k' for kilobytes, 'm' for megabytes, or 'g' for gigabytes.
	// Examples: "10m", "1g", "512k".
	CacheZoneSize string `json:"cacheZoneSize"`
	// +kubebuilder:validation:Optional
	// AllowedCodes defines which HTTP response codes should be cached.
	// Accepts either:
	// - The string "any" to cache all response codes (must be the only element)
	// - A list of HTTP status codes as integers (100-599)
	// Examples: ["any"], [200, 301, 404], [200].
	// Invalid: ["any", 200] (cannot mix "any" with specific codes).
	AllowedCodes []intstr.IntOrString `json:"allowedCodes,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:XValidation:rule="self.all(method, method in ['GET', 'HEAD', 'POST'])",message="allowed methods must be one of: GET, HEAD, POST"
	// AllowedMethods defines which HTTP methods should be cached.
	// Only "GET", "HEAD", and "POST" are supported by NGINX proxy_cache_methods directive.
	// GET and HEAD are always cached by default even if not specified.
	// Maximum of 3 items allowed. Examples: ["GET"], ["GET", "HEAD", "POST"].
	// Invalid methods: PUT, DELETE, PATCH, etc.
	AllowedMethods []string `json:"allowedMethods,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^[0-9]+[smhd]$`
	// Time defines the default cache time. Required when allowedCodes is specified.
	// Must be a number followed by a time unit:
	// 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days.
	// Examples: "30s", "5m", "1h", "2d".
	Time string `json:"time,omitempty"`
	// +kubebuilder:validation:Optional
	// CachePurgeAllow defines IP addresses or CIDR blocks allowed to purge cache.
	// This feature is only available in NGINX Plus.
	// Examples: ["192.168.1.100", "10.0.0.0/8", "::1"].
	// Invalid in NGINX OSS (will be ignored).
	CachePurgeAllow []string `json:"cachePurgeAllow,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// OverrideUpstreamCache controls whether to override upstream cache headers
	// (using proxy_ignore_headers directive). When true, NGINX will ignore
	// cache-related headers from upstream servers like Cache-Control, Expires, etc.
	// Default: false.
	OverrideUpstreamCache bool `json:"overrideUpstreamCache,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^[12](?::[12]){0,2}$`
	// Levels defines the cache directory hierarchy levels for storing cached files.
	// Must be in format "X:Y" or "X:Y:Z" where X, Y, Z are either 1 or 2.
	// This controls the number of subdirectory levels and their name lengths.
	// Examples: "1:2", "2:2", "1:2:2".
	// Invalid: "3:1", "1:3", "1:2:3".
	Levels string `json:"levels,omitempty"`
}
