# GlobalConfiguration

**Group:** `k8s.nginx.org`  
**Version:** `v1`  
**Kind:** `GlobalConfiguration`  
**Scope:** `Namespaced`

## Description

The `GlobalConfiguration` resource defines global settings for the NGINX Ingress Controller. It allows you to configure listeners for different protocols and ports.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `listeners` | `array` | Listeners field of the GlobalConfigurationSpec resource |
| `listeners[].ipv4` | `string` | Ipv4 and ipv6 addresses that NGINX will listen on. Defaults to listening on all available IPv4 and IPv6 addresses. |
| `listeners[].ipv6` | `string` | Ipv6 addresses that NGINX will listen on. |
| `listeners[].name` | `string` | The name of the listener. The name must be unique across all listeners. |
| `listeners[].passSNI` | `boolean` | Custom SNI processing for listener. Allows listener to be used as a passthrough for SNI processing |
| `listeners[].port` | `integer` | The port on which the listener will accept connections. |
| `listeners[].protocol` | `string` | The protocol of the listener. For example, HTTP. |
| `listeners[].ssl` | `boolean` | Whether the listener will be listening for SSL connections |
