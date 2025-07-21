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
| `dos` | `string` | String configuration value. |
| `externalDNS` | `object` | ExternalDNS defines externaldns sub-resource of a virtual server. |
| `externalDNS.enable` | `boolean` | Enable or disable this feature. |
| `externalDNS.labels` | `object` | Labels stores labels defined for the Endpoint |
| `externalDNS.providerSpecific` | `array` | ProviderSpecific stores provider specific config |
| `externalDNS.providerSpecific[].name` | `string` | Name of the property |
| `externalDNS.providerSpecific[].value` | `string` | Value of the property |
| `externalDNS.recordTTL` | `integer` | TTL for the record |
| `externalDNS.recordType` | `string` | String configuration value. |
| `gunzip` | `boolean` | Enable or disable this feature. |
| `host` | `string` | String configuration value. |
| `http-snippets` | `string` | String configuration value. |
| `ingressClassName` | `string` | String configuration value. |
| `internalRoute` | `boolean` | InternalRoute allows for the configuration of internal routing. |
| `listener` | `object` | VirtualServerListener references a custom http and/or https listener defined in GlobalConfiguration. |
| `listener.http` | `string` | String configuration value. |
| `listener.https` | `string` | String configuration value. |
| `policies` | `array` | List of configuration values. |
| `policies[].name` | `string` | String configuration value. |
| `policies[].namespace` | `string` | String configuration value. |
| `routes` | `array` | List of configuration values. |
| `routes[].action` | `object` | Action defines an action. |
| `routes[].action.pass` | `string` | String configuration value. |
| `routes[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `routes[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `routes[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `routes[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `routes[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `routes[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `routes[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `routes[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `routes[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `routes[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `routes[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `routes[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `routes[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `routes[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `routes[].action.proxy.rewritePath` | `string` | String configuration value. |
| `routes[].action.proxy.upstream` | `string` | String configuration value. |
| `routes[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `routes[].action.redirect.code` | `integer` | Numeric configuration value. |
| `routes[].action.redirect.url` | `string` | String configuration value. |
| `routes[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `routes[].action.return.body` | `string` | String configuration value. |
| `routes[].action.return.code` | `integer` | Numeric configuration value. |
| `routes[].action.return.headers` | `array` | List of configuration values. |
| `routes[].action.return.headers[].name` | `string` | String configuration value. |
| `routes[].action.return.headers[].value` | `string` | String configuration value. |
| `routes[].action.return.type` | `string` | String configuration value. |
| `routes[].dos` | `string` | String configuration value. |
| `routes[].errorPages` | `array` | List of configuration values. |
| `routes[].errorPages[].codes` | `array[integer]` | Configuration field. |
| `routes[].errorPages[].redirect` | `object` | ErrorPageRedirect defines a redirect for an ErrorPage. |
| `routes[].errorPages[].redirect.code` | `integer` | Numeric configuration value. |
| `routes[].errorPages[].redirect.url` | `string` | String configuration value. |
| `routes[].errorPages[].return` | `object` | ErrorPageReturn defines a return for an ErrorPage. |
| `routes[].errorPages[].return.body` | `string` | String configuration value. |
| `routes[].errorPages[].return.code` | `integer` | Numeric configuration value. |
| `routes[].errorPages[].return.headers` | `array` | List of configuration values. |
| `routes[].errorPages[].return.headers[].name` | `string` | String configuration value. |
| `routes[].errorPages[].return.headers[].value` | `string` | String configuration value. |
| `routes[].errorPages[].return.type` | `string` | String configuration value. |
| `routes[].location-snippets` | `string` | String configuration value. |
| `routes[].matches` | `array` | List of configuration values. |
| `routes[].matches[].action` | `object` | Action defines an action. |
| `routes[].matches[].action.pass` | `string` | String configuration value. |
| `routes[].matches[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `routes[].matches[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `routes[].matches[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `routes[].matches[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `routes[].matches[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `routes[].matches[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `routes[].matches[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `routes[].matches[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `routes[].matches[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `routes[].matches[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `routes[].matches[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `routes[].matches[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `routes[].matches[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `routes[].matches[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `routes[].matches[].action.proxy.rewritePath` | `string` | String configuration value. |
| `routes[].matches[].action.proxy.upstream` | `string` | String configuration value. |
| `routes[].matches[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `routes[].matches[].action.redirect.code` | `integer` | Numeric configuration value. |
| `routes[].matches[].action.redirect.url` | `string` | String configuration value. |
| `routes[].matches[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `routes[].matches[].action.return.body` | `string` | String configuration value. |
| `routes[].matches[].action.return.code` | `integer` | Numeric configuration value. |
| `routes[].matches[].action.return.headers` | `array` | List of configuration values. |
| `routes[].matches[].action.return.headers[].name` | `string` | String configuration value. |
| `routes[].matches[].action.return.headers[].value` | `string` | String configuration value. |
| `routes[].matches[].action.return.type` | `string` | String configuration value. |
| `routes[].matches[].conditions` | `array` | List of configuration values. |
| `routes[].matches[].conditions[].argument` | `string` | String configuration value. |
| `routes[].matches[].conditions[].cookie` | `string` | String configuration value. |
| `routes[].matches[].conditions[].header` | `string` | String configuration value. |
| `routes[].matches[].conditions[].value` | `string` | String configuration value. |
| `routes[].matches[].conditions[].variable` | `string` | String configuration value. |
| `routes[].matches[].splits` | `array` | List of configuration values. |
| `routes[].matches[].splits[].action` | `object` | Action defines an action. |
| `routes[].matches[].splits[].action.pass` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `routes[].matches[].splits[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `routes[].matches[].splits[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `routes[].matches[].splits[].action.proxy.rewritePath` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.proxy.upstream` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `routes[].matches[].splits[].action.redirect.code` | `integer` | Numeric configuration value. |
| `routes[].matches[].splits[].action.redirect.url` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `routes[].matches[].splits[].action.return.body` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.return.code` | `integer` | Numeric configuration value. |
| `routes[].matches[].splits[].action.return.headers` | `array` | List of configuration values. |
| `routes[].matches[].splits[].action.return.headers[].name` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.return.headers[].value` | `string` | String configuration value. |
| `routes[].matches[].splits[].action.return.type` | `string` | String configuration value. |
| `routes[].matches[].splits[].weight` | `integer` | Numeric configuration value. |
| `routes[].path` | `string` | String configuration value. |
| `routes[].policies` | `array` | List of configuration values. |
| `routes[].policies[].name` | `string` | String configuration value. |
| `routes[].policies[].namespace` | `string` | String configuration value. |
| `routes[].route` | `string` | String configuration value. |
| `routes[].splits` | `array` | List of configuration values. |
| `routes[].splits[].action` | `object` | Action defines an action. |
| `routes[].splits[].action.pass` | `string` | String configuration value. |
| `routes[].splits[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `routes[].splits[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `routes[].splits[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `routes[].splits[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `routes[].splits[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `routes[].splits[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `routes[].splits[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `routes[].splits[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `routes[].splits[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `routes[].splits[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `routes[].splits[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `routes[].splits[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `routes[].splits[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `routes[].splits[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `routes[].splits[].action.proxy.rewritePath` | `string` | String configuration value. |
| `routes[].splits[].action.proxy.upstream` | `string` | String configuration value. |
| `routes[].splits[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `routes[].splits[].action.redirect.code` | `integer` | Numeric configuration value. |
| `routes[].splits[].action.redirect.url` | `string` | String configuration value. |
| `routes[].splits[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `routes[].splits[].action.return.body` | `string` | String configuration value. |
| `routes[].splits[].action.return.code` | `integer` | Numeric configuration value. |
| `routes[].splits[].action.return.headers` | `array` | List of configuration values. |
| `routes[].splits[].action.return.headers[].name` | `string` | String configuration value. |
| `routes[].splits[].action.return.headers[].value` | `string` | String configuration value. |
| `routes[].splits[].action.return.type` | `string` | String configuration value. |
| `routes[].splits[].weight` | `integer` | Numeric configuration value. |
| `server-snippets` | `string` | String configuration value. |
| `tls` | `object` | TLS defines TLS configuration for a VirtualServer. |
| `tls.cert-manager` | `object` | CertManager defines a cert manager config for a TLS. |
| `tls.cert-manager.cluster-issuer` | `string` | String configuration value. |
| `tls.cert-manager.common-name` | `string` | String configuration value. |
| `tls.cert-manager.duration` | `string` | String configuration value. |
| `tls.cert-manager.issue-temp-cert` | `boolean` | Enable or disable this feature. |
| `tls.cert-manager.issuer` | `string` | String configuration value. |
| `tls.cert-manager.issuer-group` | `string` | String configuration value. |
| `tls.cert-manager.issuer-kind` | `string` | String configuration value. |
| `tls.cert-manager.renew-before` | `string` | String configuration value. |
| `tls.cert-manager.usages` | `string` | String configuration value. |
| `tls.redirect` | `object` | TLSRedirect defines a redirect for a TLS. |
| `tls.redirect.basedOn` | `string` | String configuration value. |
| `tls.redirect.code` | `integer` | Numeric configuration value. |
| `tls.redirect.enable` | `boolean` | Enable or disable this feature. |
| `tls.secret` | `string` | String configuration value. |
| `upstreams` | `array` | List of configuration values. |
| `upstreams[].backup` | `string` | String configuration value. |
| `upstreams[].backupPort` | `integer` | Numeric configuration value. |
| `upstreams[].buffer-size` | `string` | String configuration value. |
| `upstreams[].buffering` | `boolean` | Enable or disable this feature. |
| `upstreams[].buffers` | `object` | UpstreamBuffers defines Buffer Configuration for an Upstream. |
| `upstreams[].buffers.number` | `integer` | Numeric configuration value. |
| `upstreams[].buffers.size` | `string` | String configuration value. |
| `upstreams[].client-max-body-size` | `string` | String configuration value. |
| `upstreams[].connect-timeout` | `string` | String configuration value. |
| `upstreams[].fail-timeout` | `string` | String configuration value. |
| `upstreams[].healthCheck` | `object` | HealthCheck defines the parameters for active Upstream HealthChecks. |
| `upstreams[].healthCheck.connect-timeout` | `string` | String configuration value. |
| `upstreams[].healthCheck.enable` | `boolean` | Enable or disable this feature. |
| `upstreams[].healthCheck.fails` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.grpcService` | `string` | String configuration value. |
| `upstreams[].healthCheck.grpcStatus` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.headers` | `array` | List of configuration values. |
| `upstreams[].healthCheck.headers[].name` | `string` | String configuration value. |
| `upstreams[].healthCheck.headers[].value` | `string` | String configuration value. |
| `upstreams[].healthCheck.interval` | `string` | String configuration value. |
| `upstreams[].healthCheck.jitter` | `string` | String configuration value. |
| `upstreams[].healthCheck.keepalive-time` | `string` | String configuration value. |
| `upstreams[].healthCheck.mandatory` | `boolean` | Enable or disable this feature. |
| `upstreams[].healthCheck.passes` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.path` | `string` | String configuration value. |
| `upstreams[].healthCheck.persistent` | `boolean` | Enable or disable this feature. |
| `upstreams[].healthCheck.port` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.read-timeout` | `string` | String configuration value. |
| `upstreams[].healthCheck.send-timeout` | `string` | String configuration value. |
| `upstreams[].healthCheck.statusMatch` | `string` | String configuration value. |
| `upstreams[].healthCheck.tls` | `object` | UpstreamTLS defines a TLS configuration for an Upstream. |
| `upstreams[].healthCheck.tls.enable` | `boolean` | Enable or disable this feature. |
| `upstreams[].keepalive` | `integer` | Numeric configuration value. |
| `upstreams[].lb-method` | `string` | String configuration value. |
| `upstreams[].max-conns` | `integer` | Numeric configuration value. |
| `upstreams[].max-fails` | `integer` | Numeric configuration value. |
| `upstreams[].name` | `string` | String configuration value. |
| `upstreams[].next-upstream` | `string` | String configuration value. |
| `upstreams[].next-upstream-timeout` | `string` | String configuration value. |
| `upstreams[].next-upstream-tries` | `integer` | Numeric configuration value. |
| `upstreams[].ntlm` | `boolean` | Enable or disable this feature. |
| `upstreams[].port` | `integer` | Numeric configuration value. |
| `upstreams[].queue` | `object` | UpstreamQueue defines Queue Configuration for an Upstream. |
| `upstreams[].queue.size` | `integer` | Numeric configuration value. |
| `upstreams[].queue.timeout` | `string` | String configuration value. |
| `upstreams[].read-timeout` | `string` | String configuration value. |
| `upstreams[].send-timeout` | `string` | String configuration value. |
| `upstreams[].service` | `string` | String configuration value. |
| `upstreams[].sessionCookie` | `object` | SessionCookie defines the parameters for session persistence. |
| `upstreams[].sessionCookie.domain` | `string` | String configuration value. |
| `upstreams[].sessionCookie.enable` | `boolean` | Enable or disable this feature. |
| `upstreams[].sessionCookie.expires` | `string` | String configuration value. |
| `upstreams[].sessionCookie.httpOnly` | `boolean` | Enable or disable this feature. |
| `upstreams[].sessionCookie.name` | `string` | String configuration value. |
| `upstreams[].sessionCookie.path` | `string` | String configuration value. |
| `upstreams[].sessionCookie.samesite` | `string` | String configuration value. |
| `upstreams[].sessionCookie.secure` | `boolean` | Enable or disable this feature. |
| `upstreams[].slow-start` | `string` | String configuration value. |
| `upstreams[].subselector` | `object` | Configuration object. |
| `upstreams[].tls` | `object` | UpstreamTLS defines a TLS configuration for an Upstream. |
| `upstreams[].tls.enable` | `boolean` | Enable or disable this feature. |
| `upstreams[].type` | `string` | String configuration value. |
| `upstreams[].use-cluster-ip` | `boolean` | Enable or disable this feature. |
