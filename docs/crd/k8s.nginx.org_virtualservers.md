# VirtualServer

**Group:** `k8s.nginx.org`  
**Version:** `v1`  
**Kind:** `VirtualServer`  
**Scope:** `Namespaced`

## Description

The `VirtualServer` resource defines a virtual server for the NGINX Ingress Controller. It provides advanced configuration capabilities beyond standard Kubernetes Ingress resources, including traffic splitting, advanced routing, header manipulation, and integration with NGINX App Protect.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `dos` | `string` | A reference to a DosProtectedResource, setting this enables DOS protection of the VirtualServer route. |
| `externalDNS` | `object` | The externalDNS configuration for a VirtualServer. |
| `externalDNS.enable` | `boolean` | Enables ExternalDNS integration for a VirtualServer resource. The default is false. |
| `externalDNS.labels` | `object` | Configure labels to be applied to the Endpoint resources that will be consumed by ExternalDNS. |
| `externalDNS.providerSpecific` | `array` | Configure provider specific properties which holds the name and value of a configuration which is specific to individual DNS providers. |
| `externalDNS.providerSpecific[].name` | `string` | Name of the property |
| `externalDNS.providerSpecific[].value` | `string` | Value of the property |
| `externalDNS.recordTTL` | `integer` | TTL for the DNS record. This defaults to 0 if not defined. |
| `externalDNS.recordType` | `string` | The record Type that should be created, e.g. “A”, “AAAA”, “CNAME”. This is automatically computed based on the external endpoints if not defined. |
| `gunzip` | `boolean` | Enables or disables decompression of gzipped responses for clients. Allowed values “on”/“off”, “true”/“false” or “yes”/“no”. If the gunzip value is not set, it defaults to off. |
| `host` | `string` | The host (domain name) of the server. Must be a valid subdomain as defined in RFC 1123, such as my-app or hello.example.com. When using a wildcard domain like *.example.com the domain must be contained in double quotes. The host value needs to be unique among all Ingress and VirtualServer resources. |
| `http-snippets` | `string` | Sets a custom snippet in the http context. |
| `ingressClassName` | `string` | Specifies which Ingress Controller must handle the VirtualServerRoute resource. Must be the same as the ingressClassName of the VirtualServer that references this resource. |
| `internalRoute` | `boolean` | InternalRoute allows for the configuration of internal routing. |
| `listener` | `object` | Sets a custom HTTP and/or HTTPS listener. Valid fields are listener.http and listener.https. Each field must reference the name of a valid listener defined in a GlobalConfiguration resource |
| `listener.http` | `string` | The name of an HTTP listener defined in a GlobalConfiguration resource. |
| `listener.https` | `string` | The name of an HTTPS listener defined in a GlobalConfiguration resource. |
| `policies` | `array` | A list of policies. |
| `policies[].name` | `string` | The name of a policy. If the policy doesn’t exist or invalid, NGINX will respond with an error response with the 500 status code. |
| `policies[].namespace` | `string` | The namespace of a policy. If not specified, the namespace of the VirtualServer resource is used. |
| `routes` | `array` | A list of routes. |
| `routes[].action` | `object` | The default action to perform for a request. |
| `routes[].action.pass` | `string` | Passes requests to an upstream. The upstream with that name must be defined in the resource. |
| `routes[].action.proxy` | `object` | Passes requests to an upstream with the ability to modify the request/response (for example, rewrite the URI or modify the headers). |
| `routes[].action.proxy.requestHeaders` | `object` | The request headers modifications. |
| `routes[].action.proxy.requestHeaders.pass` | `boolean` | Passes the original request headers to the proxied upstream server. Default is true. |
| `routes[].action.proxy.requestHeaders.set` | `array` | Allows redefining or appending fields to present request headers passed to the proxied upstream servers. |
| `routes[].action.proxy.requestHeaders.set[].name` | `string` | The name of the header. |
| `routes[].action.proxy.requestHeaders.set[].value` | `string` | The value of the header. |
| `routes[].action.proxy.responseHeaders` | `object` | The response headers modifications. |
| `routes[].action.proxy.responseHeaders.add` | `array` | Adds headers to the response to the client. |
| `routes[].action.proxy.responseHeaders.add[].always` | `boolean` | If set to true, add the header regardless of the response status code**. Default is false. |
| `routes[].action.proxy.responseHeaders.add[].name` | `string` | The name of the header. |
| `routes[].action.proxy.responseHeaders.add[].value` | `string` | The value of the header. |
| `routes[].action.proxy.responseHeaders.hide` | `array[string]` | The headers that will not be passed* in the response to the client from a proxied upstream server. |
| `routes[].action.proxy.responseHeaders.ignore` | `array[string]` | Disables processing of certain headers** to the client from a proxied upstream server. |
| `routes[].action.proxy.responseHeaders.pass` | `array[string]` | Allows passing the hidden header fields* to the client from a proxied upstream server. |
| `routes[].action.proxy.rewritePath` | `string` | The rewritten URI. If the route path is a regular expression – starts with ~ – the rewritePath can include capture groups with $1-9. For example $1 for the first group, and so on. For more information, check the rewrite example. |
| `routes[].action.proxy.upstream` | `string` | The name of the upstream which the requests will be proxied to. The upstream with that name must be defined in the resource. |
| `routes[].action.redirect` | `object` | Redirects requests to a provided URL. |
| `routes[].action.redirect.code` | `integer` | The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301. |
| `routes[].action.redirect.url` | `string` | The URL to redirect the request to. Supported NGINX variables: $scheme, $http_x_forwarded_proto, $request_uri or $host. Variables must be enclosed in curly braces. For example: ${host}${request_uri}. |
| `routes[].action.return` | `object` | Returns a preconfigured response. |
| `routes[].action.return.body` | `string` | The body of the response. Supports NGINX variables*. Variables must be enclosed in curly brackets. For example: Request is ${request_uri}\n. |
| `routes[].action.return.code` | `integer` | The status code of the response. The allowed values are: 2XX, 4XX or 5XX. The default is 200. |
| `routes[].action.return.headers` | `array` | The custom headers of the response. |
| `routes[].action.return.headers[].name` | `string` | The name of the header. |
| `routes[].action.return.headers[].value` | `string` | The value of the header. |
| `routes[].action.return.type` | `string` | The MIME type of the response. The default is text/plain. |
| `routes[].dos` | `string` | A reference to a DosProtectedResource, setting this enables DOS protection of the VirtualServer route. |
| `routes[].errorPages` | `array` | The custom responses for error codes. NGINX will use those responses instead of returning the error responses from the upstream servers or the default responses generated by NGINX. A custom response can be a redirect or a canned response. For example, a redirect to another URL if an upstream server responded with a 404 status code. |
| `routes[].errorPages[].codes` | `array[integer]` | A list of error status codes. |
| `routes[].errorPages[].redirect` | `object` | The canned response action for the given status codes. |
| `routes[].errorPages[].redirect.code` | `integer` | The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301. |
| `routes[].errorPages[].redirect.url` | `string` | The URL to redirect the request to. Supported NGINX variables: $scheme, $http_x_forwarded_proto, $request_uri or $host. Variables must be enclosed in curly braces. For example: ${host}${request_uri}. |
| `routes[].errorPages[].return` | `object` | The redirect action for the given status codes. |
| `routes[].errorPages[].return.body` | `string` | The body of the response. Supports NGINX variables*. Variables must be enclosed in curly brackets. For example: Request is ${request_uri}\n. |
| `routes[].errorPages[].return.code` | `integer` | The status code of the response. The allowed values are: 2XX, 4XX or 5XX. The default is 200. |
| `routes[].errorPages[].return.headers` | `array` | The custom headers of the response. |
| `routes[].errorPages[].return.headers[].name` | `string` | The name of the header. |
| `routes[].errorPages[].return.headers[].value` | `string` | The value of the header. |
| `routes[].errorPages[].return.type` | `string` | The MIME type of the response. The default is text/plain. |
| `routes[].location-snippets` | `string` | Sets a custom snippet in the location context. Overrides the location-snippets ConfigMap key. |
| `routes[].matches` | `array` | The matching rules for advanced content-based routing. Requires the default Action or Splits. Unmatched requests will be handled by the default Action or Splits. |
| `routes[].matches[].action` | `object` | The action to perform for a request. |
| `routes[].matches[].action.pass` | `string` | Passes requests to an upstream. The upstream with that name must be defined in the resource. |
| `routes[].matches[].action.proxy` | `object` | Passes requests to an upstream with the ability to modify the request/response (for example, rewrite the URI or modify the headers). |
| `routes[].matches[].action.proxy.requestHeaders` | `object` | The request headers modifications. |
| `routes[].matches[].action.proxy.requestHeaders.pass` | `boolean` | Passes the original request headers to the proxied upstream server. Default is true. |
| `routes[].matches[].action.proxy.requestHeaders.set` | `array` | Allows redefining or appending fields to present request headers passed to the proxied upstream servers. |
| `routes[].matches[].action.proxy.requestHeaders.set[].name` | `string` | The name of the header. |
| `routes[].matches[].action.proxy.requestHeaders.set[].value` | `string` | The value of the header. |
| `routes[].matches[].action.proxy.responseHeaders` | `object` | The response headers modifications. |
| `routes[].matches[].action.proxy.responseHeaders.add` | `array` | Adds headers to the response to the client. |
| `routes[].matches[].action.proxy.responseHeaders.add[].always` | `boolean` | If set to true, add the header regardless of the response status code**. Default is false. |
| `routes[].matches[].action.proxy.responseHeaders.add[].name` | `string` | The name of the header. |
| `routes[].matches[].action.proxy.responseHeaders.add[].value` | `string` | The value of the header. |
| `routes[].matches[].action.proxy.responseHeaders.hide` | `array[string]` | The headers that will not be passed* in the response to the client from a proxied upstream server. |
| `routes[].matches[].action.proxy.responseHeaders.ignore` | `array[string]` | Disables processing of certain headers** to the client from a proxied upstream server. |
| `routes[].matches[].action.proxy.responseHeaders.pass` | `array[string]` | Allows passing the hidden header fields* to the client from a proxied upstream server. |
| `routes[].matches[].action.proxy.rewritePath` | `string` | The rewritten URI. If the route path is a regular expression – starts with ~ – the rewritePath can include capture groups with $1-9. For example $1 for the first group, and so on. For more information, check the rewrite example. |
| `routes[].matches[].action.proxy.upstream` | `string` | The name of the upstream which the requests will be proxied to. The upstream with that name must be defined in the resource. |
| `routes[].matches[].action.redirect` | `object` | Redirects requests to a provided URL. |
| `routes[].matches[].action.redirect.code` | `integer` | The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301. |
| `routes[].matches[].action.redirect.url` | `string` | The URL to redirect the request to. Supported NGINX variables: $scheme, $http_x_forwarded_proto, $request_uri or $host. Variables must be enclosed in curly braces. For example: ${host}${request_uri}. |
| `routes[].matches[].action.return` | `object` | Returns a preconfigured response. |
| `routes[].matches[].action.return.body` | `string` | The body of the response. Supports NGINX variables*. Variables must be enclosed in curly brackets. For example: Request is ${request_uri}\n. |
| `routes[].matches[].action.return.code` | `integer` | The status code of the response. The allowed values are: 2XX, 4XX or 5XX. The default is 200. |
| `routes[].matches[].action.return.headers` | `array` | The custom headers of the response. |
| `routes[].matches[].action.return.headers[].name` | `string` | The name of the header. |
| `routes[].matches[].action.return.headers[].value` | `string` | The value of the header. |
| `routes[].matches[].action.return.type` | `string` | The MIME type of the response. The default is text/plain. |
| `routes[].matches[].conditions` | `array` | A list of conditions. Must include at least 1 condition. |
| `routes[].matches[].conditions[].argument` | `string` | The name of an argument. Must consist of alphanumeric characters or _. |
| `routes[].matches[].conditions[].cookie` | `string` | The name of a cookie. Must consist of alphanumeric characters or _. |
| `routes[].matches[].conditions[].header` | `string` | The name of a header. Must consist of alphanumeric characters or -. |
| `routes[].matches[].conditions[].value` | `string` | The value to match the condition against. |
| `routes[].matches[].conditions[].variable` | `string` | The name of an NGINX variable. Must start with $. |
| `routes[].matches[].splits` | `array` | The splits configuration for traffic splitting. Must include at least 2 splits. |
| `routes[].matches[].splits[].action` | `object` | The action to perform for a request. |
| `routes[].matches[].splits[].action.pass` | `string` | Passes requests to an upstream. The upstream with that name must be defined in the resource. |
| `routes[].matches[].splits[].action.proxy` | `object` | Passes requests to an upstream with the ability to modify the request/response (for example, rewrite the URI or modify the headers). |
| `routes[].matches[].splits[].action.proxy.requestHeaders` | `object` | The request headers modifications. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.pass` | `boolean` | Passes the original request headers to the proxied upstream server. Default is true. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.set` | `array` | Allows redefining or appending fields to present request headers passed to the proxied upstream servers. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.set[].name` | `string` | The name of the header. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.set[].value` | `string` | The value of the header. |
| `routes[].matches[].splits[].action.proxy.responseHeaders` | `object` | The response headers modifications. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add` | `array` | Adds headers to the response to the client. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add[].always` | `boolean` | If set to true, add the header regardless of the response status code**. Default is false. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add[].name` | `string` | The name of the header. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add[].value` | `string` | The value of the header. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.hide` | `array[string]` | The headers that will not be passed* in the response to the client from a proxied upstream server. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.ignore` | `array[string]` | Disables processing of certain headers** to the client from a proxied upstream server. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.pass` | `array[string]` | Allows passing the hidden header fields* to the client from a proxied upstream server. |
| `routes[].matches[].splits[].action.proxy.rewritePath` | `string` | The rewritten URI. If the route path is a regular expression – starts with ~ – the rewritePath can include capture groups with $1-9. For example $1 for the first group, and so on. For more information, check the rewrite example. |
| `routes[].matches[].splits[].action.proxy.upstream` | `string` | The name of the upstream which the requests will be proxied to. The upstream with that name must be defined in the resource. |
| `routes[].matches[].splits[].action.redirect` | `object` | Redirects requests to a provided URL. |
| `routes[].matches[].splits[].action.redirect.code` | `integer` | The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301. |
| `routes[].matches[].splits[].action.redirect.url` | `string` | The URL to redirect the request to. Supported NGINX variables: $scheme, $http_x_forwarded_proto, $request_uri or $host. Variables must be enclosed in curly braces. For example: ${host}${request_uri}. |
| `routes[].matches[].splits[].action.return` | `object` | Returns a preconfigured response. |
| `routes[].matches[].splits[].action.return.body` | `string` | The body of the response. Supports NGINX variables*. Variables must be enclosed in curly brackets. For example: Request is ${request_uri}\n. |
| `routes[].matches[].splits[].action.return.code` | `integer` | The status code of the response. The allowed values are: 2XX, 4XX or 5XX. The default is 200. |
| `routes[].matches[].splits[].action.return.headers` | `array` | The custom headers of the response. |
| `routes[].matches[].splits[].action.return.headers[].name` | `string` | The name of the header. |
| `routes[].matches[].splits[].action.return.headers[].value` | `string` | The value of the header. |
| `routes[].matches[].splits[].action.return.type` | `string` | The MIME type of the response. The default is text/plain. |
| `routes[].matches[].splits[].weight` | `integer` | The weight of an action. Must fall into the range 0..100. The sum of the weights of all splits must be equal to 100. |
| `routes[].path` | `string` | The path of the route. NGINX will match it against the URI of a request. Possible values are: a prefix ( / , /path ), an exact match ( =/exact/match ), a case insensitive regular expression ( ~*^/Bar.*\.jpg ) or a case sensitive regular expression ( ~^/foo.*\.jpg ). In the case of a prefix (must start with / ) or an exact match (must start with = ), the path must not include any whitespace characters, { , } or ;. In the case of the regex matches, all double quotes " must be escaped and the match can’t end in an unescaped backslash \. The path must be unique among the paths of all routes of the VirtualServer. Check the location directive for more information. |
| `routes[].policies` | `array` | A list of policies. The policies override the policies of the same type defined in the spec of the VirtualServer. |
| `routes[].policies[].name` | `string` | The name of a policy. If the policy doesn’t exist or invalid, NGINX will respond with an error response with the 500 status code. |
| `routes[].policies[].namespace` | `string` | The namespace of a policy. If not specified, the namespace of the VirtualServer resource is used. |
| `routes[].route` | `string` | The name of a VirtualServerRoute resource that defines this route. If the VirtualServerRoute belongs to a different namespace than the VirtualServer, you need to include the namespace. For example, tea-namespace/tea. |
| `routes[].splits` | `array` | The default splits configuration for traffic splitting. Must include at least 2 splits. |
| `routes[].splits[].action` | `object` | The action to perform for a request. |
| `routes[].splits[].action.pass` | `string` | Passes requests to an upstream. The upstream with that name must be defined in the resource. |
| `routes[].splits[].action.proxy` | `object` | Passes requests to an upstream with the ability to modify the request/response (for example, rewrite the URI or modify the headers). |
| `routes[].splits[].action.proxy.requestHeaders` | `object` | The request headers modifications. |
| `routes[].splits[].action.proxy.requestHeaders.pass` | `boolean` | Passes the original request headers to the proxied upstream server. Default is true. |
| `routes[].splits[].action.proxy.requestHeaders.set` | `array` | Allows redefining or appending fields to present request headers passed to the proxied upstream servers. |
| `routes[].splits[].action.proxy.requestHeaders.set[].name` | `string` | The name of the header. |
| `routes[].splits[].action.proxy.requestHeaders.set[].value` | `string` | The value of the header. |
| `routes[].splits[].action.proxy.responseHeaders` | `object` | The response headers modifications. |
| `routes[].splits[].action.proxy.responseHeaders.add` | `array` | Adds headers to the response to the client. |
| `routes[].splits[].action.proxy.responseHeaders.add[].always` | `boolean` | If set to true, add the header regardless of the response status code**. Default is false. |
| `routes[].splits[].action.proxy.responseHeaders.add[].name` | `string` | The name of the header. |
| `routes[].splits[].action.proxy.responseHeaders.add[].value` | `string` | The value of the header. |
| `routes[].splits[].action.proxy.responseHeaders.hide` | `array[string]` | The headers that will not be passed* in the response to the client from a proxied upstream server. |
| `routes[].splits[].action.proxy.responseHeaders.ignore` | `array[string]` | Disables processing of certain headers** to the client from a proxied upstream server. |
| `routes[].splits[].action.proxy.responseHeaders.pass` | `array[string]` | Allows passing the hidden header fields* to the client from a proxied upstream server. |
| `routes[].splits[].action.proxy.rewritePath` | `string` | The rewritten URI. If the route path is a regular expression – starts with ~ – the rewritePath can include capture groups with $1-9. For example $1 for the first group, and so on. For more information, check the rewrite example. |
| `routes[].splits[].action.proxy.upstream` | `string` | The name of the upstream which the requests will be proxied to. The upstream with that name must be defined in the resource. |
| `routes[].splits[].action.redirect` | `object` | Redirects requests to a provided URL. |
| `routes[].splits[].action.redirect.code` | `integer` | The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301. |
| `routes[].splits[].action.redirect.url` | `string` | The URL to redirect the request to. Supported NGINX variables: $scheme, $http_x_forwarded_proto, $request_uri or $host. Variables must be enclosed in curly braces. For example: ${host}${request_uri}. |
| `routes[].splits[].action.return` | `object` | Returns a preconfigured response. |
| `routes[].splits[].action.return.body` | `string` | The body of the response. Supports NGINX variables*. Variables must be enclosed in curly brackets. For example: Request is ${request_uri}\n. |
| `routes[].splits[].action.return.code` | `integer` | The status code of the response. The allowed values are: 2XX, 4XX or 5XX. The default is 200. |
| `routes[].splits[].action.return.headers` | `array` | The custom headers of the response. |
| `routes[].splits[].action.return.headers[].name` | `string` | The name of the header. |
| `routes[].splits[].action.return.headers[].value` | `string` | The value of the header. |
| `routes[].splits[].action.return.type` | `string` | The MIME type of the response. The default is text/plain. |
| `routes[].splits[].weight` | `integer` | The weight of an action. Must fall into the range 0..100. The sum of the weights of all splits must be equal to 100. |
| `server-snippets` | `string` | Sets a custom snippet in server context. Overrides the server-snippets ConfigMap key. |
| `tls` | `object` | The TLS termination configuration. |
| `tls.cert-manager` | `object` | The cert-manager configuration of the TLS for a VirtualServer. |
| `tls.cert-manager.cluster-issuer` | `string` | The name of a ClusterIssuer. A ClusterIssuer is a cert-manager resource which describes the certificate authority capable of signing certificates. It does not matter which namespace your VirtualServer resides, as ClusterIssuers are non-namespaced resources. Please note that one of issuer and cluster-issuer are required, but they are mutually exclusive - one and only one must be defined. |
| `tls.cert-manager.common-name` | `string` | This field allows you to configure spec.commonName for the Certificate to be generated. This configuration adds a CN to the x509 certificate. |
| `tls.cert-manager.duration` | `string` | This field allows you to configure spec.duration field for the Certificate to be generated. Must be specified using a Go time.Duration string format, which does not allow the d (days) suffix. You must specify these values using s, m, and h suffixes instead. |
| `tls.cert-manager.issue-temp-cert` | `boolean` | When true, ask cert-manager for a temporary self-signed certificate pending the issuance of the Certificate. This allows HTTPS-only servers to use ACME HTTP01 challenges when the TLS secret does not exist yet. |
| `tls.cert-manager.issuer` | `string` | The name of an Issuer. An Issuer is a cert-manager resource which describes the certificate authority capable of signing certificates. The Issuer must be in the same namespace as the VirtualServer resource. Please note that one of issuer and cluster-issuer are required, but they are mutually exclusive - one and only one must be defined. |
| `tls.cert-manager.issuer-group` | `string` | The API group of the external issuer controller, for example awspca.cert-manager.io. This is only necessary for out-of-tree issuers. This cannot be defined if cluster-issuer is also defined. |
| `tls.cert-manager.issuer-kind` | `string` | The kind of the external issuer resource, for example AWSPCAIssuer. This is only necessary for out-of-tree issuers. This cannot be defined if cluster-issuer is also defined. |
| `tls.cert-manager.renew-before` | `string` | This annotation allows you to configure spec.renewBefore field for the Certificate to be generated. Must be specified using a Go time.Duration string format, which does not allow the d (days) suffix. You must specify these values using s, m, and h suffixes instead. |
| `tls.cert-manager.usages` | `string` | This field allows you to configure spec.usages field for the Certificate to be generated. Pass a string with comma-separated values i.e. key agreement,digital signature, server auth. An exhaustive list of supported key usages can be found in the the cert-manager api documentation. |
| `tls.redirect` | `object` | The redirect configuration of the TLS for a VirtualServer. |
| `tls.redirect.basedOn` | `string` | The attribute of a request that NGINX will evaluate to send a redirect. The allowed values are scheme (the scheme of the request) or x-forwarded-proto (the X-Forwarded-Proto header of the request). The default is scheme. |
| `tls.redirect.code` | `integer` | The status code of a redirect. The allowed values are: 301, 302, 307 or 308. The default is 301. |
| `tls.redirect.enable` | `boolean` | Enables a TLS redirect for a VirtualServer. The default is False. |
| `tls.secret` | `string` | The name of a secret with a TLS certificate and key. The secret must belong to the same namespace as the VirtualServer. The secret must be of the type kubernetes.io/tls and contain keys named tls.crt and tls.key that contain the certificate and private key as described here. If the secret doesn’t exist or is invalid, NGINX will break any attempt to establish a TLS connection to the host of the VirtualServer. If the secret is not specified but wildcard TLS secret is configured, NGINX will use the wildcard secret for TLS termination. |
| `upstreams` | `array` | A list of upstreams. |
| `upstreams[].backup` | `string` | The name of the backup service of type ExternalName. This will be used when the primary servers are unavailable. Note: The parameter cannot be used along with the random, hash or ip_hash load balancing methods. |
| `upstreams[].backupPort` | `integer` | The port of the backup service. The backup port is required if the backup service name is provided. The port must fall into the range 1..65535. |
| `upstreams[].buffer-size` | `string` | Sets the size of the buffer used for reading the first part of a response received from the upstream server. The default is set in the proxy-buffer-size ConfigMap key. |
| `upstreams[].buffering` | `boolean` | Enables buffering of responses from the upstream server. The default is set in the proxy-buffering ConfigMap key. |
| `upstreams[].buffers` | `object` | Configures the buffers used for reading a response from the upstream server for a single connection. |
| `upstreams[].buffers.number` | `integer` | Configures the number of buffers. The default is set in the proxy-buffers ConfigMap key. |
| `upstreams[].buffers.size` | `string` | Configures the size of a buffer. The default is set in the proxy-buffers ConfigMap key. |
| `upstreams[].busy-buffers-size` | `string` | Sets the size of the buffers used for reading a response from the upstream server when the proxy_buffering is enabled. The default is set in the proxy-busy-buffers-size ConfigMap key.' |
| `upstreams[].client-max-body-size` | `string` | Sets the maximum allowed size of the client request body. The default is set in the client-max-body-size ConfigMap key. |
| `upstreams[].connect-timeout` | `string` | The timeout for establishing a connection with an upstream server. The default is specified in the proxy-connect-timeout ConfigMap key. |
| `upstreams[].fail-timeout` | `string` | The time during which the specified number of unsuccessful attempts to communicate with an upstream server should happen to consider the server unavailable. The default is set in the fail-timeout ConfigMap key. |
| `upstreams[].healthCheck` | `object` | The health check configuration for the Upstream. Note: this feature is supported only in NGINX Plus. |
| `upstreams[].healthCheck.connect-timeout` | `string` | The timeout for establishing a connection with an upstream server. By default, the connect-timeout of the upstream is used. |
| `upstreams[].healthCheck.enable` | `boolean` | Enables a health check for an upstream server. The default is false. |
| `upstreams[].healthCheck.fails` | `integer` | The number of consecutive failed health checks of a particular upstream server after which this server will be considered unhealthy. The default is 1. |
| `upstreams[].healthCheck.grpcService` | `string` | The gRPC service to be monitored on the upstream server. Only valid on gRPC type upstreams. |
| `upstreams[].healthCheck.grpcStatus` | `integer` | The expected gRPC status code of the upstream server response to the Check method. Configure this field only if your gRPC services do not implement the gRPC health checking protocol. For example, configure 12 if the upstream server responds with 12 (UNIMPLEMENTED) status code. Only valid on gRPC type upstreams. |
| `upstreams[].healthCheck.headers` | `array` | The request headers used for health check requests. NGINX Plus always sets the Host, User-Agent and Connection headers for health check requests. |
| `upstreams[].healthCheck.headers[].name` | `string` | The name of the header. |
| `upstreams[].healthCheck.headers[].value` | `string` | The value of the header. |
| `upstreams[].healthCheck.interval` | `string` | The interval between two consecutive health checks. The default is 5s. |
| `upstreams[].healthCheck.jitter` | `string` | The time within which each health check will be randomly delayed. By default, there is no delay. |
| `upstreams[].healthCheck.keepalive-time` | `string` | Enables keepalive connections for health checks and specifies the time during which requests can be processed through one keepalive connection. The default is 60s. |
| `upstreams[].healthCheck.mandatory` | `boolean` | Require every newly added server to pass all configured health checks before NGINX Plus sends traffic to it. If this is not specified, or is set to false, the server will be initially considered healthy. When combined with slow-start, it gives a new server more time to connect to databases and “warm up” before being asked to handle their full share of traffic. |
| `upstreams[].healthCheck.passes` | `integer` | The number of consecutive passed health checks of a particular upstream server after which the server will be considered healthy. The default is 1. |
| `upstreams[].healthCheck.path` | `string` | The path used for health check requests. The default is /. This is not configurable for gRPC type upstreams. |
| `upstreams[].healthCheck.persistent` | `boolean` | Set the initial “up” state for a server after reload if the server was considered healthy before reload. Enabling persistent requires that the mandatory parameter is also set to true. |
| `upstreams[].healthCheck.port` | `integer` | The port used for health check requests. By default, the server port is used. Note: in contrast with the port of the upstream, this port is not a service port, but a port of a pod. |
| `upstreams[].healthCheck.read-timeout` | `string` | The timeout for reading a response from an upstream server. By default, the read-timeout of the upstream is used. |
| `upstreams[].healthCheck.send-timeout` | `string` | The timeout for transmitting a request to an upstream server. By default, the send-timeout of the upstream is used. |
| `upstreams[].healthCheck.statusMatch` | `string` | The expected response status codes of a health check. By default, the response should have status code 2xx or 3xx. Examples: "200", "! 500", "301-303 307". This not supported for gRPC type upstreams. |
| `upstreams[].healthCheck.tls` | `object` | The TLS configuration used for health check requests. By default, the tls field of the upstream is used. |
| `upstreams[].healthCheck.tls.enable` | `boolean` | Enables HTTPS for requests to upstream servers. The default is False , meaning that HTTP will be used. Note: by default, NGINX will not verify the upstream server certificate. To enable the verification, configure an EgressMTLS Policy. |
| `upstreams[].keepalive` | `integer` | Configures the cache for connections to upstream servers. The value 0 disables the cache. The default is set in the keepalive ConfigMap key. |
| `upstreams[].lb-method` | `string` | The load balancing method. To use the round-robin method, specify round_robin. The default is specified in the lb-method ConfigMap key. |
| `upstreams[].max-conns` | `integer` | The maximum number of simultaneous active connections to an upstream server. By default there is no limit. Note: if keepalive connections are enabled, the total number of active and idle keepalive connections to an upstream server may exceed the max_conns value. |
| `upstreams[].max-fails` | `integer` | The number of unsuccessful attempts to communicate with an upstream server that should happen in the duration set by the fail-timeout to consider the server unavailable. The default is set in the max-fails ConfigMap key. |
| `upstreams[].name` | `string` | The name of the upstream. Must be a valid DNS label as defined in RFC 1035. For example, hello and upstream-123 are valid. The name must be unique among all upstreams of the resource. |
| `upstreams[].next-upstream` | `string` | Specifies in which cases a request should be passed to the next upstream server. The default is error timeout. |
| `upstreams[].next-upstream-timeout` | `string` | The time during which a request can be passed to the next upstream server. The 0 value turns off the time limit. The default is 0. |
| `upstreams[].next-upstream-tries` | `integer` | The number of possible tries for passing a request to the next upstream server. The 0 value turns off this limit. The default is 0. |
| `upstreams[].ntlm` | `boolean` | Allows proxying requests with NTLM Authentication. In order for NTLM authentication to work, it is necessary to enable keepalive connections to upstream servers using the keepalive field. Note: this feature is supported only in NGINX Plus. |
| `upstreams[].port` | `integer` | The port of the service. If the service doesn’t define that port, NGINX will assume the service has zero endpoints and return a 502 response for requests for this upstream. The port must fall into the range 1..65535. |
| `upstreams[].queue` | `object` | Configures a queue for an upstream. A client request will be placed into the queue if an upstream server cannot be selected immediately while processing the request. By default, no queue is configured. Note: this feature is supported only in NGINX Plus. |
| `upstreams[].queue.size` | `integer` | The size of the queue. |
| `upstreams[].queue.timeout` | `string` | The timeout of the queue. A request cannot be queued for a period longer than the timeout. The default is 60s. |
| `upstreams[].read-timeout` | `string` | The timeout for reading a response from an upstream server. The default is specified in the proxy-read-timeout ConfigMap key. |
| `upstreams[].send-timeout` | `string` | The timeout for transmitting a request to an upstream server. The default is specified in the proxy-send-timeout ConfigMap key. |
| `upstreams[].service` | `string` | The name of a service. The service must belong to the same namespace as the resource. If the service doesn’t exist, NGINX will assume the service has zero endpoints and return a 502 response for requests for this upstream. For NGINX Plus only, services of type ExternalName are also supported . |
| `upstreams[].sessionCookie` | `object` | The SessionCookie field configures session persistence which allows requests from the same client to be passed to the same upstream server. The information about the designated upstream server is passed in a session cookie generated by NGINX Plus. |
| `upstreams[].sessionCookie.domain` | `string` | The domain for which the cookie is set. |
| `upstreams[].sessionCookie.enable` | `boolean` | Enables session persistence with a session cookie for an upstream server. The default is false. |
| `upstreams[].sessionCookie.expires` | `string` | The time for which a browser should keep the cookie. Can be set to the special value max, which will cause the cookie to expire on 31 Dec 2037 23:55:55 GMT. |
| `upstreams[].sessionCookie.httpOnly` | `boolean` | Adds the HttpOnly attribute to the cookie. |
| `upstreams[].sessionCookie.name` | `string` | The name of the cookie. |
| `upstreams[].sessionCookie.path` | `string` | The path for which the cookie is set. |
| `upstreams[].sessionCookie.samesite` | `string` | Adds the SameSite attribute to the cookie. The allowed values are: strict, lax, none |
| `upstreams[].sessionCookie.secure` | `boolean` | Adds the Secure attribute to the cookie. |
| `upstreams[].slow-start` | `string` | The slow start allows an upstream server to gradually recover its weight from 0 to its nominal value after it has been recovered or became available or when the server becomes available after a period of time it was considered unavailable. By default, the slow start is disabled. Note: The parameter cannot be used along with the random, hash or ip_hash load balancing methods and will be ignored. |
| `upstreams[].subselector` | `object` | Selects the pods within the service using label keys and values. By default, all pods of the service are selected. Note: the specified labels are expected to be present in the pods when they are created. If the pod labels are updated, NGINX Ingress Controller will not see that change until the number of the pods is changed. |
| `upstreams[].tls` | `object` | The TLS configuration for the Upstream. |
| `upstreams[].tls.enable` | `boolean` | Enables HTTPS for requests to upstream servers. The default is False , meaning that HTTP will be used. Note: by default, NGINX will not verify the upstream server certificate. To enable the verification, configure an EgressMTLS Policy. |
| `upstreams[].type` | `string` | The type of the upstream. Supported values are http and grpc. The default is http. For gRPC, it is necessary to enable HTTP/2 in the ConfigMap and configure TLS termination in the VirtualServer. |
| `upstreams[].use-cluster-ip` | `boolean` | Enables using the Cluster IP and port of the service instead of the default behavior of using the IP and port of the pods. When this field is enabled, the fields that configure NGINX behavior related to multiple upstream servers (like lb-method and next-upstream) will have no effect, as NGINX Ingress Controller will configure NGINX with only one upstream server that will match the service Cluster IP. |
