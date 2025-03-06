---
docs: DOCS-591
doctypes:
- ''
title: Advanced configuration with Annotations
toc: true
weight: 200
---

This topic explains how to enable advanced features in F5 NGINX Ingress Controller with Annotations.

The Ingress resource can use basic NGINX features such as host or path-based routing and TLS termination. Advanced features like rewriting the request URI or inserting additional response headers can be enabled with Annotations.

Outside of advanced features, Annotations are necessary for customizing NGINX behavior such as setting the value of connection timeouts.

Customization is also available through the [ConfigMap]({{< relref "/configuration/global-configuration/configmap-resource.md" >}}) resources: Annotations take priority.

## Using Annotations

This example uses Annotations to customize the configuration for an Ingress resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-with-annotations
  annotations:
    nginx.org/proxy-connect-timeout: "30s"
    nginx.org/proxy-read-timeout: "20s"
    nginx.org/client-max-body-size: "4m"
    nginx.org/server-snippets: |
      location / {
        return 302 /coffee;
      }
spec:
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /tea
        pathType: Prefix
        backend:
          service:
            name: tea-svc
            port:
              number: 80
      - path: /coffee
        pathType: Prefix
        backend:
          service:
            name: coffee-svc
            port:
              number: 80
```

## Validation

NGINX Ingress Controller validates the annotations of Ingress resources. If an Ingress is invalid, NGINX Ingress Controller will reject it: the Ingress will continue to exist in the cluster, but NGINX Ingress Controller will ignore it.

You can check if NGINX Ingress Controller successfully applied the configuration for an Ingress resource. For the example `cafe-ingress-with-annotations` Ingress, you can run:

```shell
kubectl describe ing cafe-ingress-with-annotations
```
```text
...
Events:
  Type     Reason          Age   From                      Message
  ----     ------          ----  ----                      -------
  Normal   AddedOrUpdated  3s    nginx-ingress-controller  Configuration for default/cafe-ingress-with-annotations was added or updated
```

The events section includes a Normal event with the AddedOrUpdated reason that informs us that the configuration was successfully applied.

If you create an invalid Ingress, NGINX Ingress Controller will reject it and emit a Rejected event. For example, if you create an Ingress `cafe-ingress-with-annotations`, with an annotation `nginx.org/redirect-to-https` set to `yes please` instead of `true`, you will get:

```shell
kubectl describe ing cafe-ingress-with-annotations
```
```text
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  13s   nginx-ingress-controller  annotations.nginx.org/redirect-to-https: Invalid value: "yes please": must be a boolean
```

Note how the events section includes a Warning event with the Rejected reason.

{{< note >}} If you make an existing Ingress invalid, NGINX Ingress Controller will reject it and remove the corresponding configuration from NGINX. {{< /note >}}

The `nginx.com/jwt-token` Ingress annotation has limited validation.

## Summary of Annotations

The table below summarizes the available annotations.

{{< note >}} Annotations that start with `nginx.com` are only supported with NGINX Plus. {{< /note >}}

### General customization

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/proxy-connect-timeout* | *proxy-connect-timeout* | Sets the value of the [proxy_connect_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_connect_timeout) and [grpc_connect_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_connect_timeout) directive. | *60s* |  |
| *nginx.org/proxy-read-timeout* | *proxy-read-timeout* | Sets the value of the [proxy_read_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout) and [grpc_read_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_read_timeout) directive. | *60s* |  |
| *nginx.org/proxy-send-timeout* | *proxy-send-timeout* | Sets the value of the [proxy_send_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_send_timeout) and [grpc_send_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_send_timeout) directive. | *60s* |  |
| *nginx.org/client-max-body-size* | *client-max-body-size* | Sets the value of the [client_max_body_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size) directive. | *1m* |  |
| *nginx.org/proxy-buffering* | *proxy-buffering* | Enables or disables [buffering of responses](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering) from the proxied server. | *True* |  |
| *nginx.org/proxy-buffers* | *proxy-buffers* | Sets the value of the [proxy_buffers](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffers) directive. | Depends on the platform. |  |
| *nginx.org/proxy-buffer-size* | *proxy-buffer-size* | Sets the value of the [proxy_buffer_size](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size) and [grpc_buffer_size](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_buffer_size) directives. | Depends on the platform. |  |
| *nginx.org/proxy-max-temp-file-size* | *proxy-max-temp-file-size* | Sets the value of the  [proxy_max_temp_file_size](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_max_temp_file_size) directive. | *1024m* |  |
| *nginx.org/server-tokens* | *server-tokens* | Enables or disables the [server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens) directive. Additionally, with the NGINX Plus, you can specify a custom string value, including the empty string value, which disables the emission of the “Server” field. | *True* |  |
| *nginx.org/path-regex* | N/A | Enables regular expression modifiers for Ingress path parameter. This translates to the NGINX [location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location) directive. You can specify one of these values: "case_sensitive", "case_insensitive", or "exact". The annotation is applied to the entire Ingress resource and its paths. While using Master and Minion Ingresses i.e. Mergeable Ingresses, this annotation can be specified on Minion types. The `path-regex` annotation specified on Master is ignored, and has no effect on paths defined on Minions.   | N/A |  [path-regex](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/path-regex) |
{{</bootstrap-table>}}

### Request URI/Header Manipulation

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/proxy-hide-headers* | *proxy-hide-headers* | Sets the value of one or more  [proxy_hide_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header) directives. Example: ``"nginx.org/proxy-hide-headers": "header-a,header-b"* | N/A |  |
| *nginx.org/proxy-pass-headers* | *proxy-pass-headers* | Sets the value of one or more   [proxy_pass_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass_header) directives. Example: ``"nginx.org/proxy-pass-headers": "header-a,header-b"* | N/A |  |
| *nginx.org/rewrites* | N/A | Configures URI rewriting using [proxy_pass](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass) directive. | N/A | [rewrites](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/rewrites) |
|*nginx.org/proxy-set-headers* | N/A | Enables customization of proxy headers and values using the [proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header) directive. Example: ``"nginx.org/proxy-set-headers": "header-a: valueA,header-b: valueB,header-c: valueC"`` | N/A | [Proxy Set Headers](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/proxy-set-headers). |
{{</bootstrap-table>}}

### Auth and SSL/TLS

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/redirect-to-https* | *redirect-to-https* | Sets the 301 redirect rule based on the value of the ``http_x_forwarded_proto* header on the server block to force incoming traffic to be over HTTPS. Useful when terminating SSL in a load balancer in front of NGINX Ingress Controller — see [115](https://github.com/nginx/kubernetes-ingress/issues/115) | *False* |  |
| *ingress.kubernetes.io/ssl-redirect* | *ssl-redirect* | Sets an unconditional 301 redirect rule for all incoming HTTP traffic to force incoming traffic over HTTPS. | *True* |  |
| *nginx.org/hsts* | *hsts* | Enables [HTTP Strict Transport Security (HSTS)](https://www.nginx.com/blog/http-strict-transport-security-hsts-and-nginx/)\ : the HSTS header is added to the responses from backends. The ``preload* directive is included in the header. | *False* |  |
| *nginx.org/hsts-max-age* | *hsts-max-age* | Sets the value of the ``max-age* directive of the HSTS header. | *2592000* (1 month) |  |
| *nginx.org/hsts-include-subdomains* | *hsts-include-subdomains* | Adds the ``includeSubDomains* directive to the HSTS header. | *False* |  |
| *nginx.org/hsts-behind-proxy* | *hsts-behind-proxy* | Enables HSTS based on the value of the ``http_x_forwarded_proto* request header. Should only be used when TLS termination is configured in a load balancer (proxy) in front of NGINX Ingress Controller. Note: to control redirection from HTTP to HTTPS configure the ``nginx.org/redirect-to-https* annotation. | *False* |  |
| *nginx.org/basic-auth-secret* | N/A | Specifies a Secret resource with a user list for HTTP Basic authentication. | N/A | |
| *nginx.org/basic-auth-realm* | N/A | Specifies a realm. | N/A | |
| *nginx.com/jwt-key* | N/A | Specifies a Secret resource with keys for validating JSON Web Tokens (JWTs). | N/A | [Support for JSON Web Tokens (JWTs)](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/jwt). |
| *nginx.com/jwt-realm* | N/A | Specifies a realm. | N/A | [Support for JSON Web Tokens (JWTs)](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/jwt). |
| *nginx.com/jwt-token* | N/A | Specifies a variable that contains a JSON Web Token. | By default, a JWT is expected in the ``Authorization* header as a Bearer Token. | [Support for JSON Web Tokens (JWTs)](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/jwt). |
| *nginx.com/jwt-login-url* | N/A | Specifies a URL to which a client is redirected in case of an invalid or missing JWT. | N/A | [Support for JSON Web Tokens (JWTs)](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/jwt). |
{{</bootstrap-table>}}

### Listeners

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/listen-ports* | N/A | Configures HTTP ports that NGINX will listen on. | *[80]* |  |
| *nginx.org/listen-ports-ssl* | N/A | Configures HTTPS ports that NGINX will listen on. | *[443]* |  |
{{</bootstrap-table>}}

### Backend services (Upstreams)

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/lb-method* | *lb-method* | Sets the [load balancing method](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-load-balancer/#choosing-a-load-balancing-method). To use the round-robin method, specify ``"round_robin"``. | *"random two least_conn"* |  |
| *nginx.org/ssl-services* | N/A | Enables HTTPS or gRPC over SSL when connecting to the endpoints of services. | N/A | [ssl-services](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/ssl-services) |
| *nginx.org/grpc-services* | N/A | Enables gRPC for services. Note: requires HTTP/2 (see ``http2* ConfigMap key); only works for Ingresses with TLS termination enabled. | N/A | [grpc-services](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/grpc-services) |
| *nginx.org/websocket-services* | N/A | Enables WebSocket for services. | N/A | [websocket](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/websocket) |
| *nginx.org/max-fails* | *max-fails* | Sets the value of the [max_fails](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#max_fails) parameter of the ``server* directive. | *1* |  |
| *nginx.org/max-conns* | N\A | Sets the value of the [max_conns](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#max_conns) parameter of the ``server* directive. | *0* |  |
| *nginx.org/upstream-zone-size* | *upstream-zone-size* | Sets the size of the shared memory [zone](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#zone) for upstreams. For NGINX, the special value 0 disables the shared memory zones. For NGINX Plus, shared memory zones are required and cannot be disabled. The special value 0 will be ignored. | *256K* |  |
| *nginx.org/fail-timeout* | *fail-timeout* | Sets the value of the [fail_timeout](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#fail_timeout) parameter of the ``server* directive. | *10s* |  |
| *nginx.com/sticky-cookie-services* | N/A | Configures session persistence. | N/A | [session-persistence](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/session-persistence) |
| *nginx.org/keepalive* | *keepalive* | Sets the value of the [keepalive](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive) directive. Note that ``proxy_set_header Connection "";* is added to the generated configuration when the value > 0. | *0* |  |
| *nginx.com/health-checks* | N/A | Enables active health checks. | *False* | [health-checks](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/health-checks) |
| *nginx.com/health-checks-mandatory* | N/A | Configures active health checks as mandatory. | *False* | [health-checks](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/health-checks) |
| *nginx.com/health-checks-mandatory-queue* | N/A | When active health checks are mandatory, creates a queue where incoming requests are temporarily stored while NGINX Plus is checking the health of the endpoints after a configuration reload. | *0* | [health-checks](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/health-checks) |
| *nginx.com/slow-start* | N/A | Sets the upstream server [slow-start period](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-load-balancer/#server-slow-start). By default, slow-start is activated after a server becomes [available](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/#passive-health-checks) or [healthy](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/#active-health-checks). To enable slow-start for newly-added servers, configure [mandatory active health checks](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/health-checks). | *"0s"* |  |
| *nginx.org/use-cluster-ip* | N/A | Enables using the Cluster IP and port of the service instead of the default behavior of using the IP and port of the pods. When this field is enabled, the fields that configure NGINX behavior related to multiple upstream servers (like ``lb-method* and ``next-upstream``) will have no effect, as NGINX Ingress Controller will configure NGINX with only one upstream server that will match the service Cluster IP.   | *False* |  |
{{</bootstrap-table>}}

### Rate limiting

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/limit-req-rate* | N/A | Enables request-rate-limiting for this ingress by creating a [limit_req_zone](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone) and matching [limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req) for each location. All servers/locations of one ingress share the same zone. Must have unit r/s or r/m. | N/A | 200r/s |
| *nginx.org/limit-req-key* | N/A | The key to which the rate limit is applied. Can contain text, variables, or a combination of them. Variables must be surrounded by ${}. | ${binary_remote_addr} | ${binary_remote_addr} |
| *nginx.org/limit-req-zone-size* | N/A | Configures the size of the created [limit_req_zone](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone). | 10m | 20m |
| *nginx.org/limit-req-delay* | N/A | Configures the delay-parameter of the [limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req) directive. | 0 | 100 |
| *nginx.org/limit-req-no-delay* | N/A | Configures the nodelay-parameter of the [limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req) directive. | false | true |
| *nginx.org/limit-req-burst* | N/A | Configures the burst-parameter of the [limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req) directive. | N/A | 100 |
| *nginx.org/limit-req-dry-run* | N/A | Enables the dry run mode. In this mode, the rate limit is not actually applied, but the number of excessive requests is accounted as usual in the shared memory zone. | false | true |
| *nginx.org/limit-req-log-level* | N/A | Sets the desired logging level for cases when the server refuses to process requests due to rate exceeding, or delays request processing. Allowed values are info, notice, warn or error. | error | info |
| *nginx.org/limit-req-reject-code* | N/A | Sets the status code to return in response to rejected requests. Must fall into the range 400..599. | 429 | 503 |
| *nginx.org/limit-req-scale* | N/A | Enables a constant rate-limit by dividing the configured rate by the number of nginx-ingress pods currently serving traffic. This adjustment ensures that the rate-limit remains consistent, even as the number of nginx-pods fluctuates due to autoscaling. Note: This will not work properly if requests from a client are not evenly distributed accross all ingress pods (sticky sessions, long lived TCP-Connections with many requests etc.). In such cases using NGINX+'s zone-sync feature instead would give better results. | false | true |
{{</bootstrap-table>}}

### Snippets and custom templates

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *nginx.org/location-snippets* | *location-snippets* | Sets a custom snippet in location context. | N/A |  |
| *nginx.org/server-snippets* | *server-snippets* | Sets a custom snippet in server context. | N/A |  |
{{</bootstrap-table>}}

### App Protect WAF {#app-protect}

{{< note >}} The App Protect annotations only work if the App Protect WAF module is [installed]({{< relref "installation/integrations/app-protect-waf/installation.md" >}}). {{< /note >}}

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *appprotect.f5.com/app-protect-policy* | N/A | The name of the App Protect Policy for the Ingress Resource. Format is ``namespace/name``. If no namespace is specified, the same namespace of the Ingress Resource is used. If not specified but ``appprotect.f5.com/app-protect-enable* is true, a default policy id applied. If the referenced policy resource does not exist, or policy is invalid, this annotation will be ignored, and the default policy will be applied. | N/A | [app-protect-waf](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-waf) |
| *appprotect.f5.com/app-protect-enable* | N/A | Enable App Protect for the Ingress Resource. | *False* | [app-protect-waf](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-waf) |
| *appprotect.f5.com/app-protect-security-log-enable* | N/A | Enable the [security log](/nginx-app-protect/troubleshooting/#app-protect-logging-overview) for App Protect. | *False* | [app-protect-waf](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-waf) |
| *appprotect.f5.com/app-protect-security-log* | N/A | The App Protect log configuration for the Ingress Resource. Format is ``namespace/name``. If no namespace is specified, the same namespace as the Ingress Resource is used. If not specified the  default is used which is:  filter: ``illegal``, format: ``default``. Multiple configurations can be specified in a comma separated list. Both log configurations and destinations list (see below) must be of equal length. Configs and destinations are paired by the list indices. | N/A | [app-protect-waf](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-waf) |
| *appprotect.f5.com/app-protect-security-log-destination* | N/A | The destination of the security log. For more information check the [DESTINATION argument](/nginx-app-protect/troubleshooting/#app-protect-logging-overview). Multiple destinations can be specified in a comma-separated list.  Both log configurations and destinations list (see above) must be of equal length. Configs and destinations are paired by the list indices. | *syslog:server=localhost:514* | [app-protect-waf](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-waf) |
{{</bootstrap-table>}}

### App Protect DoS

{{< note >}} The App Protect DoS annotations only work if the App Protect DoS module is [installed]({{< relref "installation/integrations/app-protect-dos/installation.md" >}}). {{< /note >}}

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Annotation | ConfigMap Key | Description | Default | Example |
| ---| ---| ---| ---| --- |
| *appprotectdos.f5.com/app-protect-dos-resource* | N/A | Enable App Protect DoS for the Ingress Resource by specifying a [DosProtectedResource]({{< relref "installation/integrations/app-protect-dos/dos-protected.md" >}}). | N/A | [app-protect-dos](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-dos) |
{{</bootstrap-table>}}
