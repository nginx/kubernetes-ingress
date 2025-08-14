# TransportServer

**Group:** `k8s.nginx.org`  
**Version:** `v1`  
**Kind:** `TransportServer`  
**Scope:** `Namespaced`

## Description

The `TransportServer` resource defines a TCP or UDP load balancer. It allows you to expose non-HTTP applications running in your Kubernetes cluster with advanced load balancing and health checking capabilities.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `action` | `object` | The action to perform for a request. |
| `action.pass` | `string` | Passes connections/datagrams to an upstream. The upstream with that name must be defined in the resource. |
| `host` | `string` | The host (domain name) of the server. Must be a valid subdomain as defined in RFC 1123, such as my-app or hello.example.com. When using a wildcard domain like *.example.com the domain must be contained in double quotes. The host value needs to be unique among all Ingress and VirtualServer resources. |
| `ingressClassName` | `string` | Specifies which Ingress Controller must handle the VirtualServer resource. |
| `listener` | `object` | Sets a custom HTTP and/or HTTPS listener. Valid fields are listener.http and listener.https. Each field must reference the name of a valid listener defined in a GlobalConfiguration resource |
| `listener.name` | `string` | The name of a listener defined in a GlobalConfiguration resource. |
| `listener.protocol` | `string` | The protocol of the listener. |
| `serverSnippets` | `string` | Sets a custom snippet in server context. Overrides the server-snippets ConfigMap key. |
| `sessionParameters` | `object` | The parameters of the session to be used for the Server context |
| `sessionParameters.timeout` | `string` | The timeout between two successive read or write operations on client or proxied server connections. The default is 10m. |
| `streamSnippets` | `string` | Sets a custom snippet in the stream context. Overrides the stream-snippets ConfigMap key. |
| `tls` | `object` | The TLS termination configuration. |
| `tls.secret` | `string` | String configuration value. |
| `upstreamParameters` | `object` | UpstreamParameters defines parameters for an upstream. |
| `upstreamParameters.connectTimeout` | `string` | The timeout for establishing a connection with a proxied server. The default is 60s. |
| `upstreamParameters.nextUpstream` | `boolean` | If a connection to the proxied server cannot be established, determines whether a client connection will be passed to the next server. The default is true. |
| `upstreamParameters.nextUpstreamTimeout` | `string` | The time allowed to pass a connection to the next server. The default is 0. |
| `upstreamParameters.nextUpstreamTries` | `integer` | The number of tries for passing a connection to the next server. The default is 0. |
| `upstreamParameters.udpRequests` | `integer` | The number of datagrams, after receiving which, the next datagram from the same client starts a new session. The default is 0. |
| `upstreamParameters.udpResponses` | `integer` | The number of datagrams expected from the proxied server in response to a client datagram. By default, the number of datagrams is not limited. |
| `upstreams` | `array` | A list of upstreams. |
| `upstreams[].backup` | `string` | The name of the backup service of type ExternalName. This will be used when the primary servers are unavailable. Note: The parameter cannot be used along with the random, hash or ip_hash load balancing methods. |
| `upstreams[].backupPort` | `integer` | The port of the backup service. The backup port is required if the backup service name is provided. The port must fall into the range 1..65535. |
| `upstreams[].failTimeout` | `string` | Sets the number of unsuccessful attempts to communicate with the server that should happen in the duration set by the failTimeout parameter to consider the server unavailable. The default is 1. |
| `upstreams[].healthCheck` | `object` | The health check configuration for the Upstream. Note: this feature is supported only in NGINX Plus. |
| `upstreams[].healthCheck.enable` | `boolean` | Enables a health check for an upstream server. The default is false. |
| `upstreams[].healthCheck.fails` | `integer` | The number of consecutive failed health checks of a particular upstream server after which this server will be considered unhealthy. The default is 1. |
| `upstreams[].healthCheck.interval` | `string` | The interval between two consecutive health checks. The default is 5s. |
| `upstreams[].healthCheck.jitter` | `string` | The time within which each health check will be randomly delayed. By default, there is no delay. |
| `upstreams[].healthCheck.match` | `object` | Controls the data to send and the response to expect for the healthcheck. |
| `upstreams[].healthCheck.match.expect` | `string` | A literal string or a regular expression that the data obtained from the server should match. The regular expression is specified with the preceding ~* modifier (for case-insensitive matching), or the ~ modifier (for case-sensitive matching). NGINX Ingress Controller validates a regular expression using the RE2 syntax. |
| `upstreams[].healthCheck.match.send` | `string` | A string to send to an upstream server. |
| `upstreams[].healthCheck.passes` | `integer` | The number of consecutive passed health checks of a particular upstream server after which the server will be considered healthy. The default is 1. |
| `upstreams[].healthCheck.port` | `integer` | The port used for health check requests. By default, the server port is used. Note: in contrast with the port of the upstream, this port is not a service port, but a port of a pod. |
| `upstreams[].healthCheck.timeout` | `string` | This overrides the timeout set by proxy_timeout which is set in SessionParameters for health checks. The default value is 5s. |
| `upstreams[].loadBalancingMethod` | `string` | The method used to load balance the upstream servers. By default, connections are distributed between the servers using a weighted round-robin balancing method. |
| `upstreams[].maxConns` | `integer` | Sets the time during which the specified number of unsuccessful attempts to communicate with the server should happen to consider the server unavailable and the period of time the server will be considered unavailable. The default is 10s. |
| `upstreams[].maxFails` | `integer` | Sets the number of maximum connections to the proxied server. Default value is zero, meaning there is no limit. The default is 0. |
| `upstreams[].name` | `string` | The name of the upstream. Must be a valid DNS label as defined in RFC 1035. For example, hello and upstream-123 are valid. The name must be unique among all upstreams of the resource. |
| `upstreams[].port` | `integer` | The port of the service. If the service doesn’t define that port, NGINX will assume the service has zero endpoints and close client connections/ignore datagrams. The port must fall into the range 1..65535. |
| `upstreams[].service` | `string` | The name of a service. The service must belong to the same namespace as the resource. If the service doesn’t exist, NGINX will assume the service has zero endpoints and close client connections/ignore datagrams. |
