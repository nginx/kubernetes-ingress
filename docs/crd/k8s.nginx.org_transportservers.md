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
| `action` | `object` | TransportServerAction defines an action. |
| `action.pass` | `string` | String configuration value. |
| `host` | `string` | String configuration value. |
| `ingressClassName` | `string` | String configuration value. |
| `listener` | `object` | TransportServerListener defines a listener for a TransportServer. |
| `listener.name` | `string` | String configuration value. |
| `listener.protocol` | `string` | String configuration value. |
| `serverSnippets` | `string` | String configuration value. |
| `sessionParameters` | `object` | SessionParameters defines session parameters. |
| `sessionParameters.timeout` | `string` | String configuration value. |
| `streamSnippets` | `string` | String configuration value. |
| `tls` | `object` | TransportServerTLS defines TransportServerTLS configuration for a TransportServer. |
| `tls.secret` | `string` | String configuration value. |
| `upstreamParameters` | `object` | UpstreamParameters defines parameters for an upstream. |
| `upstreamParameters.connectTimeout` | `string` | String configuration value. |
| `upstreamParameters.nextUpstream` | `boolean` | Enable or disable this feature. |
| `upstreamParameters.nextUpstreamTimeout` | `string` | String configuration value. |
| `upstreamParameters.nextUpstreamTries` | `integer` | Numeric configuration value. |
| `upstreamParameters.udpRequests` | `integer` | Numeric configuration value. |
| `upstreamParameters.udpResponses` | `integer` | Numeric configuration value. |
| `upstreams` | `array` | List of configuration values. |
| `upstreams[].backup` | `string` | String configuration value. |
| `upstreams[].backupPort` | `integer` | Numeric configuration value. |
| `upstreams[].failTimeout` | `string` | String configuration value. |
| `upstreams[].healthCheck` | `object` | TransportServerHealthCheck defines the parameters for active Upstream HealthChecks. |
| `upstreams[].healthCheck.enable` | `boolean` | Enable or disable this feature. |
| `upstreams[].healthCheck.fails` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.interval` | `string` | String configuration value. |
| `upstreams[].healthCheck.jitter` | `string` | String configuration value. |
| `upstreams[].healthCheck.match` | `object` | TransportServerMatch defines the parameters of a custom health check. |
| `upstreams[].healthCheck.match.expect` | `string` | String configuration value. |
| `upstreams[].healthCheck.match.send` | `string` | String configuration value. |
| `upstreams[].healthCheck.passes` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.port` | `integer` | Numeric configuration value. |
| `upstreams[].healthCheck.timeout` | `string` | String configuration value. |
| `upstreams[].loadBalancingMethod` | `string` | String configuration value. |
| `upstreams[].maxConns` | `integer` | Numeric configuration value. |
| `upstreams[].maxFails` | `integer` | Numeric configuration value. |
| `upstreams[].name` | `string` | String configuration value. |
| `upstreams[].port` | `integer` | Numeric configuration value. |
| `upstreams[].service` | `string` | String configuration value. |
