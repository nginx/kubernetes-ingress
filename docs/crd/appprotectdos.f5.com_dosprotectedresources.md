# DosProtectedResource

**Group:** `appprotectdos.f5.com`  
**Version:** `v1beta1`  
**Kind:** `DosProtectedResource`  
**Scope:** `Namespaced`

## Description

The `DosProtectedResource` resource defines a resource that is protected by the NGINX App Protect DoS module. It allows you to enable and configure DoS protection for a specific service or application.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `allowList` | `array` | AllowList is a list of allowed IPs and subnet masks |
| `allowList[].ipWithMask` | `string` | String configuration value. |
| `apDosMonitor` | `object` | ApDosMonitor is how NGINX App Protect DoS monitors the stress level of the protected object. The monitor requests are sent from localhost (127.0.0.1). Default value: URI - None, protocol - http1, timeout - NGINX App Protect DoS default. |
| `apDosMonitor.protocol` | `string` | Protocol determines if the server listens on http1 / http2 / grpc / websocket. The default is http1. Allowed values: `"http1"`, `"http2"`, `"grpc"`, `"websocket"`. |
| `apDosMonitor.timeout` | `integer` | Timeout determines how long (in seconds) should NGINX App Protect DoS wait for a response. Default is 10 seconds for http1/http2 and 5 seconds for grpc. |
| `apDosMonitor.uri` | `string` | URI is the destination to the desired protected object in the nginx.conf: |
| `apDosPolicy` | `string` | ApDosPolicy is the namespace/name of a ApDosPolicy resource |
| `dosAccessLogDest` | `string` | DosAccessLogDest is the network address for the access logs |
| `dosSecurityLog` | `object` | DosSecurityLog defines the security log of the DosProtectedResource. |
| `dosSecurityLog.apDosLogConf` | `string` | ApDosLogConf is the namespace/name of a APDosLogConf resource |
| `dosSecurityLog.dosLogDest` | `string` | DosLogDest is the network address of a logging service, can be either IP or DNS name. |
| `dosSecurityLog.enable` | `boolean` | Enable enables the security logging feature if set to true |
| `enable` | `boolean` | Enable enables the DOS feature if set to true |
| `name` | `string` | Name is the name of protected object, max of 63 characters. |
