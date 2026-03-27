---
title: TransportServer Resource
description: "The TransportServer resource allows you to configure TCP, UDP, and TLS Passthrough load balancing."
weight: 1900
doctypes: [""]
toc: true
docs: "DOCS-598"
---


The TransportServer resource allows you to configure TCP, UDP, and TLS Passthrough load balancing. The resource is implemented as a [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

This document is the reference documentation for the TransportServer resource. To see additional examples of using the resource for specific use cases, go to the [examples/custom-resources](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/custom-resources) folder in our GitHub repo.

## Prerequisites

- For TCP and UDP, the TransportServer resource must be used in conjunction with the [GlobalConfiguration resource](/nginx-ingress-controller/configuration/global-configuration/globalconfiguration-resource), which must be created separately.
- For TLS Passthrough, make sure to enable the [`-enable-tls-passthrough`](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments#cmdoption-enable-tls-passthrough) command-line argument of the Ingress Controller.

## TransportServer Specification

The TransportServer resource defines load balancing configuration for TCP, UDP, or TLS Passthrough traffic. Below are a few examples:

- TCP load balancing:

  ```yaml
  apiVersion: k8s.nginx.org/v1
  kind: TransportServer
  metadata:
    name: dns-tcp
  spec:
    listener:
      name: dns-tcp
      protocol: TCP
    tls:
      secret: cafe-secret
    upstreams:
    - name: dns-app
      service: dns-service
      port: 5353
    action:
      pass: dns-app
  ```

- UDP load balancing:

  ```yaml
  apiVersion: k8s.nginx.org/v1
  kind: TransportServer
  metadata:
    name: dns-udp
  spec:
    listener:
      name: dns-udp
      protocol: UDP
    upstreams:
    - name: dns-app
      service: dns-service
      port: 5353
    upstreamParameters:
      udpRequests: 1
      udpResponses: 1
    action:
      pass: dns-app
  ```

- TLS passthrough load balancing:

  ```yaml
  apiVersion: k8s.nginx.org/v1
  kind: TransportServer
  metadata:
    name: secure-app
  spec:
    listener:
      name: tls-passthrough
      protocol: TLS_PASSTHROUGH
    host: app.example.com
    upstreams:
    - name: secure-app
      service: secure-app
      port: 8443
    action:
      pass: secure-app
  ```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``listener`` | The listener on NGINX that will accept incoming connections/datagrams. | [listener](#listener) | Yes |
|``host`` | The host (domain name) of the server. Must be a valid subdomain as defined in RFC 1123, such as ``my-app`` or ``hello.example.com``. Wildcard domains like ``*.example.com`` are not allowed. Required for TLS Passthrough load balancing. | ``string`` | No |
|``tls`` | The TLS termination configuration. Not supported for TLS Passthrough load balancing. | [tls](#tls) | No |
|``upstreams`` | A list of upstreams. | [[]upstream](#upstream) | Yes |
|``upstreamParameters`` | The upstream parameters. | [upstreamParameters](#upstreamparameters) | No |
|``action`` | The action to perform for a client connection/datagram. | [action](#action) | Yes |
|``ingressClassName`` | Specifies which Ingress Controller must handle the TransportServer resource. | ``string`` | No |
|``streamSnippets`` | Sets a custom snippet in the ``stream`` context. | ``string`` | No |
|``serverSnippets`` | Sets a custom snippet in the ``server`` context. | ``string`` | No |
{{% /table %}}

\* -- Required for TLS Passthrough load balancing.

### Listener

The listener field references a listener that NGINX will use to accept incoming traffic for the TransportServer. For TCP and UDP, the listener must be defined in the [GlobalConfiguration resource](/nginx-ingress-controller/configuration/global-configuration/globalconfiguration-resource). When referencing a listener, both the name and the protocol must match. For TLS Passthrough, use the built-in listener with the name `tls-passthrough` and the protocol `TLS_PASSTHROUGH`.

An example:

```yaml
listener:
  name: dns-udp
  protocol: UDP
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``name`` | The name of the listener. | ``string`` | Yes |
|``protocol`` | The protocol of the listener. | ``string`` | Yes |
{{% /table %}}

### TLS

The tls field defines TLS configuration for a TransportServer. Please note the current implementation supports TLS termination on multiple ports, where each application owns a dedicated port - the Ingress Controller terminates TLS connections on each port, where each application uses its own cert/key, and routes connections to appropriate application (service) based on that incoming port (any TLS connection regardless of the SNI on a port will be routed to the application that corresponds to that port). An example configuration is shown below:

```yaml
secret: cafe-secret
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``secret`` | The name of a secret with a TLS certificate and key. The secret must belong to the same namespace as the TransportServer. The secret must be of the type ``kubernetes.io/tls`` and contain keys named ``tls.crt`` and ``tls.key`` that contain the certificate and private key as described [here](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls). | ``string`` | No |
{{% /table %}}

### Upstream

The upstream defines a destination for the TransportServer. For example:

```yaml
name: secure-app
service: secure-app
port: 8443
maxFails: 3
maxConns: 100
failTimeout: 30s
loadBalancingMethod: least_conn
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``name`` | The name of the upstream. Must be a valid DNS label as defined in RFC 1035. For example, ``hello`` and ``upstream-123`` are valid. The name must be unique among all upstreams of the resource. | ``string`` | Yes |
|``service`` | The name of a [service](https://kubernetes.io/docs/concepts/services-networking/service/). The service must belong to the same namespace as the resource. If the service doesn't exist, NGINX will assume the service has zero endpoints and close client connections/ignore datagrams. | ``string`` | Yes |
|``port`` | The port of the service. If the service doesn't define that port, NGINX will assume the service has zero endpoints and close client connections/ignore datagrams. The port must fall into the range ``1..65535``. | ``int`` | Yes |
|``maxFails`` | Sets the [number](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#max_fails) of unsuccessful attempts to communicate with the server that should happen in the duration set by the failTimeout parameter to consider the server unavailable. The default ``1``. | ``int`` | No |
|``maxConns`` | Sets the [number](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#max_conns) of maximum connections to the proxied server. Default value is zero, meaning there is no limit. The default is ``0``. | ``int`` | No |
|``failTimeout`` | Sets the [time](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#fail_timeout) during which the specified number of unsuccessful attempts to communicate with the server should happen to consider the server unavailable and the period of time the server will be considered unavailable. The default is ``10s``. | ``string`` | No |
|``healthCheck`` | The health check configuration for the Upstream. See the [health_check](https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html#health_check) directive. Note: this feature is supported only in NGINX Plus. | [healthcheck](#upstreamhealthcheck) | No |
|``loadBalancingMethod`` | The method used to load balance the upstream servers. By default, connections are distributed between the servers using a weighted round-robin balancing method. See the [upstream](http://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#upstream) section for available methods and their details. | ``string`` | No |
|``backup`` | The name of the backup service of type [ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname). This will be used when the primary servers are unavailable. Note: The parameter cannot be used along with the ``random`` , ``hash`` or ``ip_hash`` load balancing methods. | ``string`` | No |
|``backupPort`` | The port of the backup service. The backup port is required if the backup service name is provided. The port must fall into the range ``1..65535``. | ``uint16`` | No |
{{% /table %}}

### Upstream.Healthcheck

The Healthcheck defines an [active health check](https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html?#health_check). In the example below we enable a health check for an upstream and configure all the available parameters:

```yaml
name: secure-app
service: secure-app
port: 8443
healthCheck:
  enable: true
  interval: 20s
  timeout: 30s
  jitter: 3s
  fails: 5
  passes: 5
  port: 8080
```

Note: This feature is supported only in NGINX Plus.

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``enable`` | Enables a health check for an upstream server. The default is ``false``. | ``boolean`` | No |
|``interval`` | The interval between two consecutive health checks. The default is ``5s``. | ``string`` | No |
|``timeout`` | This overrides the timeout set by [proxy_timeout](http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_timeout) which is set in `SessionParameters` for health checks. The default value is ``5s``. | ``string`` | No |
|``jitter`` | The time within which each health check will be randomly delayed. By default, there is no delay. | ``string`` | No |
|``fails`` | The number of consecutive failed health checks of a particular upstream server after which this server will be considered unhealthy. The default is ``1``. | ``integer`` | No |
|``passes`` | The number of consecutive passed health checks of a particular upstream server after which the server will be considered healthy. The default is ``1``. | ``integer`` | No |
|``port`` | The port used for health check requests. By default, the [server port is used](https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html#health_check_port). Note: in contrast with the port of the upstream, this port is not a service port, but a port of a pod. | ``integer`` | No |
|``match`` | Controls the data to send and the response to expect for the healthcheck. | [match](#upstreamhealthcheckmatch) | No |
{{% /table %}}

### Upstream.Healthcheck.Match

The match controls the data to send and the response to expect for the healthcheck:

```yaml
match:
  send: 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'
  expect: "~200 OK"
```

Both `send` and `expect` fields can contain hexadecimal literals with the prefix `\x` followed by two hex digits, for example, `\x80`.

See the [match](https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html#match) directive for details.

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``send`` | A string to send to an upstream server. | ``string`` | No |
|``expect`` | A literal string or a regular expression that the data obtained from the server should match. The regular expression is specified with the preceding ``~*`` modifier (for case-insensitive matching), or the ``~`` modifier (for case-sensitive matching). The Ingress Controller validates a regular expression using the RE2 syntax. | ``string`` | No |
{{% /table %}}

### UpstreamParameters

The upstream parameters define various parameters for the upstreams:

```yaml
upstreamParameters:
  udpRequests: 1
  udpResponses: 1
  connectTimeout: 60s
  nextUpstream: true
  nextUpstreamTimeout: 50s
  nextUpstreamTries: 1
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``udpRequests`` | The number of datagrams, after receiving which, the next datagram from the same client starts a new session. See the [proxy_requests](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_requests) directive. The default is ``0``. | ``int`` | No |
|``udpResponses`` | The number of datagrams expected from the proxied server in response to a client datagram. See the [proxy_responses](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_responses) directive. By default, the number of datagrams is not limited. | ``int`` | No |
|``connectTimeout`` | The timeout for establishing a connection with a proxied server. See the [proxy_connect_timeout](http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_connect_timeout) directive. The default is ``60s``. | ``string`` | No |
|``nextUpstream`` | If a connection to the proxied server cannot be established, determines whether a client connection will be passed to the next server. See the [proxy_next_upstream](http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream) directive. The default is ``true``. | bool | No |
|``nextUpstreamTries`` | The number of tries for passing a connection to the next server. See the [proxy_next_upstream_tries](http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream_tries) directive. The default is ``0``. | ``int`` | No |
|``nextUpstreamTimeout`` | The time allowed to pass a connection to the next server. See the [proxy_next_upstream_timeout](http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream_timeout) directive. The default us ``0``. | ``string`` | No |
{{% /table %}}

### SessionParameters

The session parameters define various parameters for TCP connections and UDP sessions.

```yaml
sessionParameters:
  timeout: 50s
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``timeout`` | The timeout between two successive read or write operations on client or proxied server connections. See [proxy_timeout](http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_timeout) directive. The default is ``10m``. | ``string`` | No |
{{% /table %}}

### Action

The action defines an action to perform for a client connection/datagram.

In the example below, client connections/datagrams are passed to an upstream `dns-app`:

```yaml
action:
  pass: dns-app
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``pass`` | Passes connections/datagrams to an upstream. The upstream with that name must be defined in the resource. | ``string`` | Yes |
{{% /table %}}

## Using TransportServer

You can use the usual `kubectl` commands to work with TransportServer resources, similar to Ingress resources.

For example, the following command creates a TransportServer resource defined in `transport-server-passthrough.yaml` with the name `secure-app`:

```console
kubectl apply -f transport-server-passthrough.yaml

transportserver.k8s.nginx.org/secure-app created
```

You can get the resource by running:

```console
kubectl get transportserver secure-app

NAME         AGE
secure-app   46sm
```

In the kubectl get and similar commands, you can also use the short name `ts` instead of `transportserver`.

### Using Snippets

Snippets allow you to insert raw NGINX config into different contexts of NGINX configuration. In the example below, we use snippets to configure [access control](http://nginx.org/en/docs/stream/ngx_stream_access_module.html) in a TransportServer:

```yaml
apiVersion: k8s.nginx.org/v1
kind: TransportServer
metadata:
  name: cafe
spec:
  host: cafe.example.com
  serverSnippets: |
    deny  192.168.1.1;
    allow 192.168.1.0/24;
  upstreams:
  - name: tea
    service: tea-svc
    port: 80
```

Snippets can also be specified for a stream. In the example below, we use snippets to [limit the number of connections](https://nginx.org/en/docs/stream/ngx_stream_limit_conn_module.html):

```yaml
apiVersion: k8s.nginx.org/v1
kind: TransportServer
metadata:
  name: cafe
spec:
  host: cafe.example.com
  streamSnippets: limit_conn_zone $binary_remote_addr zone=addr:10m;
  serverSnippets: limit_conn addr 1;
  upstreams:
  - name: tea
    service: tea-svc
    port: 80
```

Snippets are intended to be used by advanced NGINX users who need more control over the generated NGINX configuration.

However, because of the disadvantages described below, snippets are disabled by default. To use snippets, set the [`enable-snippets`](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments#cmdoption-enable-snippets) command-line argument.

Disadvantages of using snippets:

- *Complexity*. To use snippets, you will need to:
  - Understand NGINX configuration primitives and implement a correct NGINX configuration.
  - Understand how the IC generates NGINX configuration so that a snippet doesn't interfere with the other features in the configuration.
- *Decreased robustness*. An incorrect snippet makes the NGINX config invalid which will lead to a failed reload. This will prevent any new configuration updates, including updates for the other TransportServer resource until the snippet is fixed.
- *Security implications*. Snippets give access to NGINX configuration primitives and those primitives are not validated by the Ingress Controller.

> Note: during a period when the NGINX config includes an invalid snippet, NGINX will continue to operate with the latest valid configuration.

> Note: to configure snippets in the `stream` context, use `stream-snippets` ConfigMap key.

### Validation

Two types of validation are available for the TransportServer resource:

- *Structural validation* by the `kubectl` and Kubernetes API server.
- *Comprehensive validation* by the Ingress Controller.

#### Structural Validation

The custom resource definition for the TransportServer includes structural OpenAPI schema which describes the type of every field of the resource.

If you try to create (or update) a resource that violates the structural schema (for example, you use a string value for the port field of an upstream), `kubectl` and Kubernetes API server will reject such a resource:

- Example of `kubectl` validation:

    ```console
    kubectl apply -f transport-server-passthrough.yaml

      error: error validating "transport-server-passthrough.yaml": error validating data: ValidationError(TransportServer.spec.upstreams[0].port): invalid type for org.nginx.k8s.v1.TransportServer.spec.upstreams.port: got "string", expected "integer"; if you choose to ignore these errors, turn validation off with --validate=false
    ```

- Example of Kubernetes API server validation:

    ```console
    kubectl apply -f transport-server-passthrough.yaml --validate=false

      The TransportServer "secure-app" is invalid: []: Invalid value: map[string]interface {}{ ... }: validation failure list:
      spec.upstreams.port in body must be of type integer: "string"
    ```

If a resource is not rejected (it doesn't violate the structural schema), the Ingress Controller will validate it further.

#### Comprehensive Validation

The Ingress Controller validates the fields of a TransportServer resource. If a resource is invalid, the Ingress Controller will reject it: the resource will continue to exist in the cluster, but the Ingress Controller will ignore it.

You can check if the Ingress Controller successfully applied the configuration for a TransportServer. For our example `secure-app` TransportServer, we can run:

```console
kubectl describe ts secure-app

. . .
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  3s    nginx-ingress-controller  Configuration for default/secure-app was added or updated
```

Note how the events section includes a Normal event with the AddedOrUpdated reason that informs us that the configuration was successfully applied.

If you create an invalid resource, the Ingress Controller will reject it and emit a Rejected event. For example, if you create a TransportServer `secure-app` with a pass action that references a non-existing upstream, you will get  :

```console
kubectl describe ts secure-app

. . .
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  2s    nginx-ingress-controller  TransportServer default/secure-app is invalid and was rejected: spec.action.pass: Not found: "some-app"
```

Note how the events section includes a Warning event with the Rejected reason.

**Note**: If you make an existing resource invalid, the Ingress Controller will reject it and remove the corresponding configuration from NGINX.

## Customization via ConfigMap

The [ConfigMap](/nginx-ingress-controller/configuration/global-configuration/configmap-resource) keys (except for `stream-snippets`, `stream-log-format`, `resolver-addresses`, `resolver-ipv6`, `resolver-valid` and `resolver-timeout`) do not affect TransportServer resources.
