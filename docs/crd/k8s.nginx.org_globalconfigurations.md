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
| `listeners` | `array` | List of configuration values. |
| `listeners[].ipv4` | `string` | String configuration value. |
| `listeners[].ipv6` | `string` | String configuration value. |
| `listeners[].name` | `string` | String configuration value. |
| `listeners[].port` | `integer` | Numeric configuration value. |
| `listeners[].protocol` | `string` | String configuration value. |
| `listeners[].ssl` | `boolean` | Enable or disable this feature. |
