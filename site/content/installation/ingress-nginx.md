---
docs: DOCS-1469
doctypes:
- tutorial
tags:
- docs
title: Migrate from Ingress-NGINX Controller to NGINX Ingress Controller
toc: true
weight: 500
---

This document describes how to migrate from the community-maintained Ingress-NGINX Controller to F5 NGINX Ingress Controller.

## Overview

This page explains two different ways to migrate from the community-maintained [Ingress-NGINX Controller](https://github.com/kubernetes/ingress-nginx) project to NGINX Ingress Controller: using NGINX's Ingress Resources or with Kubernetes's built-in Ingress Resources. This is typically because of implementation differences, and to take advantage of features such as [NGINX Plus integration]({{<relref "overview/nginx-plus">}}).

The information in this guide is extracted from a free eBook called "_Kubernetes Ingress Controller Deployment and Security with NGINX_", which can be downloaded from the [NGINX Library](https://www.nginx.com/resources/library/kubernetes-ingress-controller-deployment-security-nginx/).

## Before you begin

To complete the instructions in this guide, you need the following:

- A working knowledge of [Ingress Controllers]({{<relref "glossary.md#ingress-controller-ingress-controller">}}).
- An [NGINX Ingress Controller installation]({{<relref "installation/installing-nic">}}) on the same host as an existing Ingress-NGINX Controller.

There are two primary paths for migrating between the community Ingress-NGINX Controller to NGINX Ingress Controller:

- Using NGINX Ingress Resources
- Using Kubernetes Ingress Resources.

## Migration with NGINX Ingress resources
This path uses Kubernetes Ingress Resources to set root permissions, then NGINX Ingress Resources for configuration using custom resource definitions (CRDs):

* [VirtualServer and VirtualServerRoute]({{<relref "configuration/virtualserver-and-virtualserverroute-resources">}})
* [TransportServer]({{<relref "configuration/transportserver-resource">}})
* [GlobalConfiguration]({{<relref "configuration/global-configuration/globalconfiguration-resource">}})
* [Policy]({{<relref "configuration/policy-resource">}})

### Configuring SSL termination and HTTP path-based routing
The following two code examples correspond to a Kubernetes Ingress Resource and an [NGINX VirtualServer Resource]({{<relref "configuration/virtualserver-and-virtualserverroute-resources">}}). Although the syntax and indentation is different, they accomplish the same basic Ingress functions, used for SSL termination and Layer 7 path-based routing.

**Kubernetes Ingress Resource**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx-test
spec:
  tls:
    - hosts:
      - foo.bar.com
      secretName: tls-secret
  rules:
    - host: foo.bar.com
      http:
        paths:
        - path: /login
          backend:
            serviceName: login-svc
            servicePort: 80
        - path: /billing
            serviceName: billing-svc
            servicePort: 80
```

**NGINX VirtualServer Resource**
```yaml
apiVersion: networking.k8s.io/v1
kind: VirtualServer
metadata:
  name: nginx-test
spec:
  host: foo.bar.com
  tls:
    secret: tls-secret
  upstreams:
    - name: login
      service: login-svc
      port: 80
    - name: billing
      service: billing-svc
      port: 80
  routes:
  - path: /login
    action:
      pass: login
  - path: /billing
    action:
      pass: billing
```

### Configuring TCP/UDP load balancing and TLS passthrough
NGINX Ingress Controller exposes TCP and UDP services using [TransportServer]({{<relref "configuration/transportserver-resource">}}) and [GlobalConfiguration]({{<relref "configuration/global-configuration/globalconfiguration-resource">}}) resources. These resources provide a broad range of options for TCP/UDP and TLS Passthrough load balancing. By contrast, the community Ingress-NGINX Controller exposes TCP/UDP services by using a Kubernetes ConfigMap object.

---

### Convert Ingress-NGINX Controller annotations to NGINX Ingress resources
Kubernetes deployments often need to extend basic Ingress rules for advanced use cases such as canary and blue-green deployments, traffic throttling, and ingress-egress traffic manipulation. The community Ingress-NGINX Controller implements many of these using Kubernetes annotations with custom Lua extensions.

These custom Lua extensions are intended for specific NGINX Ingress resource definitions and may not be as granular as required for advanced use cases. The following examples show how to convert these annotations into NGINX Ingress Controller Resources.

---

#### Canary deployments
Canary and blue-green deployments allow you to push code changes to production environments without disrupting existing users. NGINX Ingress Controller runs them on the data plane: to migrate from the community Ingress-NGINX Controller, you must map the latter's annotations to [VirtualServer and VirtualServerRoute resources]({{<relref "configuration/virtualserver-and-virtualserverroute-resources">}}).

The Ingress-NGINX Controller evaluates canary annotations in the following order:

1. _nginx.ingress.kubernetes.io/canary-by-header_
1. _nginx.ingress.kubernetes.io/canary-by-cookie_
1. _nginx.ingress.kubernetes.io/canary-by-weight_

For NGINX Ingress Controller to evalute them the same way, they must appear in the same order in the VirtualServer or VirtualServerRoute Manifest.

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/canary: "true"
nginx.ingress.kubernetes.io/canary-by-header: "httpHeader"
```

**NGINX Ingress Controller**
```yaml
matches:
- conditions:
  - header: httpHeader
      value: never
  action:
    pass: echo
  - header: httpHeader
      value: always
  action:
    pass: echo-canary
action:
  pass: echo
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/canary: "true"
nginx.ingress.kubernetes.io/canary-by-header: "httpHeader"
nginx.ingress.kubernetes.io/canary-by-header-value: "my-value"
```

**NGINX Ingress Controller**
```yaml
matches:
- conditions:
  - header: httpHeader
      value: my-value
  action:
    pass: echo-canary
action:
  pass: echo
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/canary: "true"
nginx.ingress.kubernetes.io/canary-by-cookie: "cookieName"
```

**NGINX Ingress Controller**
```yaml
matches:
- conditions:
  - cookie: cookieName
      value: never
  action:
    pass: echo
  - cookie: cookieName
      value: always
  action:
    pass: echo-canary
action:
  pass: echo
```

---

#### Traffic control
Environments using microservices tend to use extensive traffic-control policies to manage ephemeral applications using circuit breaking and rate and connection limiting to prevent error conditions due to unhealthy states or abnormal behavior.

The following examples map Ingress-NGINX Controller annotations to NGINX [VirtualServer and VirtualServerRoute resources]({{<relref "configuration/virtualserver-and-virtualserverroute-resources">}}) for rate limiting, custom HTTP errors, custom default backend and URI rewriting.

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/custom-http-errors: "code"

nginx.ingress.kubernetes.io/default-backend: "default-svc"
```

**NGINX Ingress Controller**
```yaml
errorPages:
- codes: [code]
    redirect:
      code: 301
      url: default-svc
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/limit-connections: "number"
```

**NGINX Ingress Controller**
```yaml
http-snippets: |
    limit_conn_zone $binary_remote_addr zone=zone_name:size;
routes:
- path: /path
    location-snippets: |
      limit_conn zone_name number;
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/limit-rate: "number"
nginx.ingress.kubernetes.io/limit-rate-after: "number"
```

**NGINX Ingress Controller**
```yaml
location-snippets: |
    limit_rate number;

    limit_rate_after number;
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/limit-rpm: "number"
nginx.ingress.kubernetes.io/limit-burst-multiplier: "multiplier"
```

**NGINX Ingress Controller**
```yaml
rateLimit:
    rate: numberr/m

    burst: number * multiplier
    key: ${binary_remote_addr}
    zoneSize: size
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/limit-rps: "number"
nginx.ingress.kubernetes.io/limit-burst-multiplier: "multiplier"
```

**NGINX Ingress Controller**
```yaml
rateLimit:
    rate: numberr/s

    burst: number * multiplier
    key: ${binary_remote_addr}
    zoneSize: size
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/limit-whitelist: "CIDR"
```

**NGINX Ingress Controller**
```yaml
http-snippets: |
server-snippets: |
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/rewrite-target: "URI"
```

**NGINX Ingress Controller**
```yaml
rewritePath: "URI"
```

There are four Ingress-NGINX Controller annotations without NGINX Ingress resource fields yet: they must be handled using snippets.

- _nginx.ingress.kubernetes.io/limit-connections_
- _nginx.ingress.kubernetes.io/limit-rate_
- _nginx.ingress.kubernetes.io/limit-rate-after_
- _nginx.ingress.kubernetes.io/limit-whitelist_

---

#### Header manipulation
Manipulating HTTP headers is useful in many cases, as they contain information that is important and relevant to systems involved in HTTP transactions. The community Ingress-NGINX Controller supports enabling and configuring cross-origin resource sharing (CORS) headings used by AJAX applications, where front-end Javascript code interacts with backend applications or web servers.

These code blocks show how the Ingress-NGINX annotations correspond to NGINX Ingress Controller [VirtualServer and VirtualServerRoute resources]({{<relref "configuration/virtualserver-and-virtualserverroute-resources">}}).

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/enable-cors: "true"
nginx.ingress.kubernetes.io/cors-allow-credentials: "true"

nginx.ingress.kubernetes.io/cors-allow-headers: "X-Forwarded-For"

nginx.ingress.kubernetes.io/cors-allow-methods: "PUT, GET, POST, OPTIONS"

nginx.ingress.kubernetes.io/cors-allow-origin: "*"

nginx.ingress.kubernetes.io/cors-max-age: "seconds"
```

**NGINX Ingress Controller**
```yaml
responseHeaders:
  add:
    - name: Access-Control-Allow-Credentials
      value: "true"
    - name: Access-Control-Allow-Headers
      value: "X-Forwarded-For"
    - name: Access-Control-Allow-Methods
      value: "PUT, GET, POST, OPTIONS"
    - name: Access-Control-Allow-Origin
      value: "*"
    - name: Access-Control-Max-Age
      value: "seconds"
```

---

#### Proxying and load balancing
NGINX Ingress Controller has multiple proxy and load balancing functionalities you may want to configure based on the use case, such as configuring the load balancing algorithm and the timeout and buffering settings for proxied connections.

This table shows how Ingress-NGINX Controller annotations map to statements in the upstream field for [VirtualServer and VirtualServerRoute resources]({{<relref "configuration/virtualserver-and-virtualserverroute-resources">}}), covering load balancing, proxy timeout, proxy buffering and connection routing for a services' ClusterIP address and port.

{{< bootstrap-table "table table-bordered table-striped table-responsive" >}}
| Ingress-NGINX Controller | NGINX Ingress Controller |
| ------------------------ | ------------------------ |
| _nginx.ingress.kubernetes.io/load-balance_ | _lb-method_ |
| _nginx.ingress.kubernetes.io/proxy-buffering_ | _buffering_ |
| _nginx.ingress.kubernetes.io/proxy-buffers-number_ | _buffers_ |
| _nginx.ingress.kubernetes.io/proxy-buffer-size_ | _buffers_ |
| _nginx.ingress.kubernetes.io/proxy-connect-timeout_ | _connect-timeout_ |
| _nginx.ingress.kubernetes.io/proxy-next-upstream_ | _next-upstream_ |
| _nginx.ingress.kubernetes.io/proxy-next-upstream-timeout_ | _next-upstream-timeout_ |
| _nginx.ingress.kubernetes.io/proxy-read-timeout_ | _read-timeout_ |
| _nginx.ingress.kubernetes.io/proxy-send-timeout_ | _send-timeout_ |
| _nginx.ingress.kubernetes.io/service-upstream_ | _use-cluster-ip_ |
{{% /bootstrap-table %}}

#### mTLS authentication

mTLS authentication is a way of enforcing mutual authentication on traffic entering and exiting a cluster (north-sourth traffic). This secure form of communication is common within a service mesh, commonly used in strict zero-trust environments.

NGINX Ingress Controller layer can handle mTLS authentication for end systems through the presentation of valid certificates for external connections. It accomplishes this through [Policy]({{<relref "configuration/policy-resource">}}) resources, which correspond to Ingress-NGINX Controller annotations for [client certificate authentication](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#client-certificate-authentication) and [backend certificate authentication](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#backend-certificate-authentication).

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/auth-tls-secret: secretName
nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
nginx.ingress.kubernetes.io/auth-tls-verify-depth: "1"
```

**NGINX Ingress Controller**
```yaml
ingressMTLS:
   clientCertSecret: secretName
   verifyClient: "on"

   verifyDepth: 1
```

---

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/proxy-ssl-secret: "secretName"
nginx.ingress.kubernetes.io/proxy-ssl-verify: "on|off"
nginx.ingress.kubernetes.io/proxy-ssl-verify-depth: "1"
nginx.ingress.kubernetes.io/proxy-ssl-protocols: "TLSv1.2"
nginx.ingress.kubernetes.io/proxy-ssl-ciphers: "DEFAULT"
nginx.ingress.kubernetes.io/proxy-ssl-name: "server-name"
nginx.ingress.kubernetes.io/proxy-ssl-server-name: "on|off"
```

**NGINX Ingress Controller**
```yaml
egressMTLS:
   tlsSecret: secretName

   verifyServer: true|false

   verifyDepth: 1

   protocols: TLSv1.2

   ciphers: DEFAULT

   sslName: server-name

   serverName: true|false
```

---

#### Session persistence with NGINX Plus
With [NGINX Plus]({{<relref "overview/nginx-plus">}}), you can use [Policy]({{<relref "configuration/policy-resource">}}) resources for session persistence, which have corresponding annotations for the community Ingress-NGINX Controller.

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/affinity: "cookie"
nginx.ingress.kubernetes.io/session-cookie-name: "cookieName"
nginx.ingress.kubernetes.io/session-cookie-expires: "x"
nginx.ingress.kubernetes.io/session-cookie-path: "/route"
nginx.ingress.kubernetes.io/session-cookie-secure: "true"
```

**NGINX Ingress Controller**
```yaml
sessionCookie:
  enable: true

  name: cookieName

  expires: xh

  path: /route

  secure: true
```

## Migration with Kubernetes Ingress resources
The other option for migrating from the community Ingress-NGINX Controller to NGINX Ingress Controller is using only [annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) and [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) from standard Kubernetes resources, potentially relying on [mergeable Ingress types](https://github.com/nginx/kubernetes-ingress/tree/main/examples/ingress-resources/mergeable-ingress-types).

This ensures that all configuration is kept in the Ingress object.

{{< warning >}}
You should avoid altering the `spec` field of the Ingress resource when taking this option. Ingress-NGINX Controller and NGINX Ingress Controller differ slightly in their implementations: changing the Kubernetes Ingress can create incompatibility issues.
{{< /warning >}}

### Advanced configuration with annotations
This table maps the Ingress-NGINX Controller annotations to NGINX Ingress Controller's equivalent annotations, and the respective NGINX Directive.

{{< bootstrap-table "table table-bordered table-striped table-responsive" >}}
| Ingress-NGINX Controller | NGINX Ingress Controller | NGINX Directive |
| ------------------------ | ------------------------ | --------------- |
| [_nginx.ingress.kubernetes.io/configuration-snippet_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#configuration-snippet) | [_nginx.org/location-snippets_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#snippets-and-custom-templates) | N/A |
| [_nginx.ingress.kubernetes.io/load-balance_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#custom-nginx-load-balancing) (1) |  [_nginx.org/lb-method_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#backend-services-upstreams) | [_random two least_conn_](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#random) |
| [_nginx.ingress.kubernetes.io/proxy-buffering_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#proxy-buffering) | [_nginx.org/proxy-buffering_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#general-customization) | [_proxy_buffering_](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering) |
| [_nginx.ingress.kubernetes.io/proxy-buffers-number_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#proxy-buffers-number) | [_nginx.org/proxy-buffers_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#general-customization) | [_proxy_buffers_](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffers) |
| [_nginx.ingress.kubernetes.io/proxy-buffer-size_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#proxy-buffer-size) | [_nginx.org/proxy-buffer-size_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#general-customization) | [_proxy_buffer_size_](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size) |
| [_nginx.ingress.kubernetes.io/proxy-connect-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#custom-timeouts) | [_nginx.org/proxy-connect-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#general-customization) | [_proxy_connect_timeout_](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_connect_timeout) |
| [_nginx.ingress.kubernetes.io/proxy-read-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#custom-timeouts) | [_nginx.org/proxy-read-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#general-customization) | [_proxy_read_timeout_](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout) |
| [_nginx.ingress.kubernetes.io/proxy-send-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#custom-timeouts) | [_nginx.org/proxy-send-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#general-customization) | [_proxy_send_timeout_](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_send_timeout) |
| [_nginx.ingress.kubernetes.io/rewrite-target_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rewrite) | [_nginx.org/rewrites_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#request-uriheader-manipulation) | [_rewrite_](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite) |
| [_nginx.ingress.kubernetes.io/server-snippet_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#server-snippet)| [_nginx.org/server-snippets_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#snippets-and-custom-templates) | N/A |
| [_nginx.ingress.kubernetes.io/ssl-redirect_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#server-side-https-enforcement-through-redirect) | [_ingress.kubernetes.io/ssl-redirect_](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#auth-and-ssltls) | N/A (2) |
{{% /bootstrap-table %}}

1. Ingress-NGINX Controller implements some of its load balancing algorithms with Lua, which may not have an equivalent in NGINX Ingress Controller.
1. To redirect HTTP (80) traffic to HTTPS (443), NGINX Ingress Controller uses built-in NGINX `if` conditions while Ingress-NGINX Controller uses Lua.

The following two snippets outline Ingress-NGINX Controller annotations that correspond to annotations for NGINX Ingress Controller with NGINX Plus.

**Ingress-NGINX Controller**
```yaml
nginx.ingress.kubernetes.io/affinity: "cookie"
nginx.ingress.kubernetes.io/session-cookie-name: "cookie_name"
nginx.ingress.kubernetes.io/session-cookie-expires: "seconds"
nginx.ingress.kubernetes.io/session-cookie-path: "/route"
```

**NGINX Ingress Controller (with NGINX Plus)**
```yaml
nginx.com/sticky-cookie-services: "serviceName=example-svc cookie_name expires=time path=/route"
```

{{< note >}}
NGINX Ingress Controller has additional annotations for features using NGINX Plus that have no Ingress-NGINX Controller equivalent, such as active health checks and authentication using JSON Web Tokens (JWTs).
{{< /note >}}

### Global configuration with ConfigMaps

This table maps the Ingress-NGINX Controller ConfigMap keys to NGINX Ingress Controller's equivalent ConfigMap keys.

<!-- {{< note >}}
Some of the key names are identical, and each Ingress Controller has ConfigMap keys that the other does not (Which are indicated).
{{< /note >}} -->

{{< bootstrap-table "table table-bordered table-striped table-responsive" >}}
| Ingress-NGINX Controller | NGINX Ingress Controller |
| ------------------------ | ------------------------ |
| [_disable-access-log_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#disable-access-log) | [_access-log-off_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#logging) |
| [_error-log-level_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#error-log-level) | [_error-log-level_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#logging) |
| [_hsts_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#hsts) | [_hsts_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls) |
| [_hsts-include-subdomains_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#hsts-include-subdomains) | [_hsts-include-subdomains_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls)       |
| [_hsts-max-age_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#hsts-max-age) | [_hsts-max-age_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls) |
| [_http-snippet_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#http-snippet) | [_http-snippets_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#snippets-and-custom-templates) |
| [_keep-alive_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#keep-alive) | [_keepalive-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_keep-alive-requests_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#keep-alive-requests) | [_keepalive-requests_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_load-balance_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#load-balance) | [_lb-method_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#backend-services-upstreams) |
| [_location-snippet_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#location-snippet) | [_location-snippets_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#snippets-and-custom-templates) |
| [_log-format-escape-json_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#log-format-escape-json) | [_log-format-escaping: "json"_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#logging) |
| [_log-format-stream_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#log-format-stream) | [_stream-log-format_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#logging) |
| [_log-format-upstream_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#log-format-upstream) | [_log-format_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#logging) |
| [_main-snippet_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#main-snippet) | [_main-snippets_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#snippets-and-custom-templates) |
| [_max-worker-connections_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#max-worker-connections) | [_worker-connections_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_max-worker-open-files_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#max-worker-open-files) | [_worker-rlimit-nofile_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-body-size_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-body-size) | [_client-max-body-size_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-buffering_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-buffering) | [_proxy-buffering_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-buffers-number_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-buffers-number) | [_proxy-buffers: number size_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-buffer-size_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-buffer-size) | [_proxy-buffers: number size_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-connect-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-connect-timeout) | [_proxy-connect-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-read-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-read-timeout) | [_proxy-read-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-send-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-send-timeout) | [_proxy-send-timeout_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_server-name-hash-bucket-size_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#server-name-hash-bucket-size) | [_server-names-hash-bucket-size_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_proxy-headers-hash-max-size_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#proxy-headers-hash-max-size) | [_server-names-hash-max-size_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_server-snippet_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#server-snippet) | [_server-snippets_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#snippets-and-custom-templates) |
| [_server-tokens _](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#server-tokens) | [_server-tokens_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_ssl-ciphers_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#ssl-ciphers) | [_ssl-ciphers_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls) |
| [_ssl-dh-param_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#ssl-dh-param) | [_ssl-dhparam-file_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls) |
| [_ssl-protocols_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#ssl-protocols) | [_ssl-protocols_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls) |
| [_ssl-redirect_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#ssl-redirect) | [_ssl-redirect_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#auth-and-ssltls) |
| [_upstream-keepalive-connections_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#upstream-keepalive-connections) | [_keepalive_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#backend-services-upstreams) |
| [_use-http2_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-http2) | [_http2_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#listeners) |
| [_use-proxy-protocol_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-proxy-protocol) | [_proxy-protocol_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#listeners) |
| [_variables-hash-bucket-size_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#variables-hash-bucket-size)     | [_variables-hash-bucket-size_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_worker-cpu-affinity_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#worker-cpu-affinity) | [_worker-cpu-affinity_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_worker-processes_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#worker-processes) | [_worker-processes_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
| [_worker-shutdown-timeout_](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#worker-shutdown-timeout) | [_worker-shutdown-timeole_](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#general-customization) |
{{% /bootstrap-table %}}
