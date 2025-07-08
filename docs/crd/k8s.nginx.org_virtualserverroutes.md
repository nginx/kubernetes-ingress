# VirtualServerRoute

**Group:** `k8s.nginx.org`  
**Version:** `v1`  
**Kind:** `VirtualServerRoute`  
**Scope:** `Namespaced`

## Description

The `VirtualServerRoute` resource defines a route that can be referenced by a `VirtualServer`. It enables modular configuration by allowing routes to be defined separately and referenced by multiple VirtualServers.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `host` | `string` | String configuration value. |
| `ingressClassName` | `string` | String configuration value. |
| `subroutes` | `array` | List of configuration values. |
| `subroutes[].action` | `object` | Action defines an action. |
| `subroutes[].action.pass` | `string` | String configuration value. |
| `subroutes[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `subroutes[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `subroutes[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `subroutes[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `subroutes[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `subroutes[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `subroutes[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `subroutes[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `subroutes[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `subroutes[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `subroutes[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `subroutes[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `subroutes[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `subroutes[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `subroutes[].action.proxy.rewritePath` | `string` | String configuration value. |
| `subroutes[].action.proxy.upstream` | `string` | String configuration value. |
| `subroutes[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `subroutes[].action.redirect.code` | `integer` | Numeric configuration value. |
| `subroutes[].action.redirect.url` | `string` | String configuration value. |
| `subroutes[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `subroutes[].action.return.body` | `string` | String configuration value. |
| `subroutes[].action.return.code` | `integer` | Numeric configuration value. |
| `subroutes[].action.return.headers` | `array` | List of configuration values. |
| `subroutes[].action.return.headers[].name` | `string` | String configuration value. |
| `subroutes[].action.return.headers[].value` | `string` | String configuration value. |
| `subroutes[].action.return.type` | `string` | String configuration value. |
| `subroutes[].dos` | `string` | String configuration value. |
| `subroutes[].errorPages` | `array` | List of configuration values. |
| `subroutes[].errorPages[].codes` | `array[integer]` | Configuration field. |
| `subroutes[].errorPages[].redirect` | `object` | ErrorPageRedirect defines a redirect for an ErrorPage. |
| `subroutes[].errorPages[].redirect.code` | `integer` | Numeric configuration value. |
| `subroutes[].errorPages[].redirect.url` | `string` | String configuration value. |
| `subroutes[].errorPages[].return` | `object` | ErrorPageReturn defines a return for an ErrorPage. |
| `subroutes[].errorPages[].return.body` | `string` | String configuration value. |
| `subroutes[].errorPages[].return.code` | `integer` | Numeric configuration value. |
| `subroutes[].errorPages[].return.headers` | `array` | List of configuration values. |
| `subroutes[].errorPages[].return.headers[].name` | `string` | String configuration value. |
| `subroutes[].errorPages[].return.headers[].value` | `string` | String configuration value. |
| `subroutes[].errorPages[].return.type` | `string` | String configuration value. |
| `subroutes[].location-snippets` | `string` | String configuration value. |
| `subroutes[].matches` | `array` | List of configuration values. |
| `subroutes[].matches[].action` | `object` | Action defines an action. |
| `subroutes[].matches[].action.pass` | `string` | String configuration value. |
| `subroutes[].matches[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `subroutes[].matches[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `subroutes[].matches[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `subroutes[].matches[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `subroutes[].matches[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `subroutes[].matches[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `subroutes[].matches[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `subroutes[].matches[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `subroutes[].matches[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `subroutes[].matches[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `subroutes[].matches[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `subroutes[].matches[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `subroutes[].matches[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `subroutes[].matches[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `subroutes[].matches[].action.proxy.rewritePath` | `string` | String configuration value. |
| `subroutes[].matches[].action.proxy.upstream` | `string` | String configuration value. |
| `subroutes[].matches[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `subroutes[].matches[].action.redirect.code` | `integer` | Numeric configuration value. |
| `subroutes[].matches[].action.redirect.url` | `string` | String configuration value. |
| `subroutes[].matches[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `subroutes[].matches[].action.return.body` | `string` | String configuration value. |
| `subroutes[].matches[].action.return.code` | `integer` | Numeric configuration value. |
| `subroutes[].matches[].action.return.headers` | `array` | List of configuration values. |
| `subroutes[].matches[].action.return.headers[].name` | `string` | String configuration value. |
| `subroutes[].matches[].action.return.headers[].value` | `string` | String configuration value. |
| `subroutes[].matches[].action.return.type` | `string` | String configuration value. |
| `subroutes[].matches[].conditions` | `array` | List of configuration values. |
| `subroutes[].matches[].conditions[].argument` | `string` | String configuration value. |
| `subroutes[].matches[].conditions[].cookie` | `string` | String configuration value. |
| `subroutes[].matches[].conditions[].header` | `string` | String configuration value. |
| `subroutes[].matches[].conditions[].value` | `string` | String configuration value. |
| `subroutes[].matches[].conditions[].variable` | `string` | String configuration value. |
| `subroutes[].matches[].splits` | `array` | List of configuration values. |
| `subroutes[].matches[].splits[].action` | `object` | Action defines an action. |
| `subroutes[].matches[].splits[].action.pass` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `subroutes[].matches[].splits[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `subroutes[].matches[].splits[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `subroutes[].matches[].splits[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `subroutes[].matches[].splits[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `subroutes[].matches[].splits[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `subroutes[].matches[].splits[].action.proxy.rewritePath` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.proxy.upstream` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `subroutes[].matches[].splits[].action.redirect.code` | `integer` | Numeric configuration value. |
| `subroutes[].matches[].splits[].action.redirect.url` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `subroutes[].matches[].splits[].action.return.body` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.return.code` | `integer` | Numeric configuration value. |
| `subroutes[].matches[].splits[].action.return.headers` | `array` | List of configuration values. |
| `subroutes[].matches[].splits[].action.return.headers[].name` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.return.headers[].value` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].action.return.type` | `string` | String configuration value. |
| `subroutes[].matches[].splits[].weight` | `integer` | Numeric configuration value. |
| `subroutes[].path` | `string` | String configuration value. |
| `subroutes[].policies` | `array` | List of configuration values. |
| `subroutes[].policies[].name` | `string` | String configuration value. |
| `subroutes[].policies[].namespace` | `string` | String configuration value. |
| `subroutes[].route` | `string` | String configuration value. |
| `subroutes[].splits` | `array` | List of configuration values. |
| `subroutes[].splits[].action` | `object` | Action defines an action. |
| `subroutes[].splits[].action.pass` | `string` | String configuration value. |
| `subroutes[].splits[].action.proxy` | `object` | ActionProxy defines a proxy in an Action. |
| `subroutes[].splits[].action.proxy.requestHeaders` | `object` | ProxyRequestHeaders defines the request headers manipulation in an ActionProxy. |
| `subroutes[].splits[].action.proxy.requestHeaders.pass` | `boolean` | Enable or disable this feature. |
| `subroutes[].splits[].action.proxy.requestHeaders.set` | `array` | List of configuration values. |
| `subroutes[].splits[].action.proxy.requestHeaders.set[].name` | `string` | String configuration value. |
| `subroutes[].splits[].action.proxy.requestHeaders.set[].value` | `string` | String configuration value. |
| `subroutes[].splits[].action.proxy.responseHeaders` | `object` | ProxyResponseHeaders defines the response headers manipulation in an ActionProxy. |
| `subroutes[].splits[].action.proxy.responseHeaders.add` | `array` | List of configuration values. |
| `subroutes[].splits[].action.proxy.responseHeaders.add[].always` | `boolean` | Enable or disable this feature. |
| `subroutes[].splits[].action.proxy.responseHeaders.add[].name` | `string` | String configuration value. |
| `subroutes[].splits[].action.proxy.responseHeaders.add[].value` | `string` | String configuration value. |
| `subroutes[].splits[].action.proxy.responseHeaders.hide` | `array[string]` | Configuration field. |
| `subroutes[].splits[].action.proxy.responseHeaders.ignore` | `array[string]` | Configuration field. |
| `subroutes[].splits[].action.proxy.responseHeaders.pass` | `array[string]` | Configuration field. |
| `subroutes[].splits[].action.proxy.rewritePath` | `string` | String configuration value. |
| `subroutes[].splits[].action.proxy.upstream` | `string` | String configuration value. |
| `subroutes[].splits[].action.redirect` | `object` | ActionRedirect defines a redirect in an Action. |
| `subroutes[].splits[].action.redirect.code` | `integer` | Numeric configuration value. |
| `subroutes[].splits[].action.redirect.url` | `string` | String configuration value. |
| `subroutes[].splits[].action.return` | `object` | ActionReturn defines a return in an Action. |
| `subroutes[].splits[].action.return.body` | `string` | String configuration value. |
| `subroutes[].splits[].action.return.code` | `integer` | Numeric configuration value. |
| `subroutes[].splits[].action.return.headers` | `array` | List of configuration values. |
| `subroutes[].splits[].action.return.headers[].name` | `string` | String configuration value. |
| `subroutes[].splits[].action.return.headers[].value` | `string` | String configuration value. |
| `subroutes[].splits[].action.return.type` | `string` | String configuration value. |
| `subroutes[].splits[].weight` | `integer` | Numeric configuration value. |
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
