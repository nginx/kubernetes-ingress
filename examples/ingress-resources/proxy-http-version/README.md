# Proxy HTTP Version

In this example we configure the HTTP version that NGINX uses for connections to upstream
servers, using the `nginx.org/proxy-http-version` Ingress annotation and the standard
Kubernetes Service `appProtocol` field.

The annotation maps to NGINX's
[`proxy_http_version`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version)
directive.

## Configuration reference

| Surface | Accepted values | Notes |
| --- | --- | --- |
| `nginx.org/proxy-http-version` annotation | `"1.0"`, `"1.1"`, `"2"` | Applies to every location of the Ingress. Inherited by minions. |
| Service `spec.ports[].appProtocol` | `kubernetes.io/h2c` | Infers `"2"` for the upstreams backed by that Service port. Any other value is ignored. |

Precedence, highest first:

1. The `nginx.org/proxy-http-version` annotation
2. The `appProtocol` of the backing Service port (`kubernetes.io/h2c` implies `"2"`)
3. Unset: the directive is not rendered and NGINX uses HTTP/1.1

## Requirements and limitations

- HTTP/2 forbids the hop-by-hop `Connection` and `Upgrade` headers
  ([RFC 9113 8.2.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2)), so NGINX Ingress
  Controller omits them for locations that proxy over HTTP/2. As a consequence, WebSocket
  (`nginx.org/websocket-services`) cannot be used together with HTTP/2 upstreams. A warning
  event is emitted if you configure both.
- HTTP/1.0 has no persistent connections or `Upgrade` mechanism, so locations that proxy over
  HTTP/1.0 send `Connection: close` to the upstream, as
  [recommended by NGINX](https://blog.nginx.org/blog/keep-alive-to-upstreams-is-now-default-in-nginx-1-29-7).
  WebSocket cannot be used together with HTTP/1.0 upstreams either, and a warning event is
  emitted if you configure both.
- Services listed in `nginx.org/grpc-services` are proxied with `grpc_pass`, which always
  uses HTTP/2. The annotation is ignored for them and a warning event is emitted.

## Running the Example

## 1. Deploy the Ingress Controller

Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installing-nic/installation-with-manifests/)
instructions to deploy the Ingress Controller.

Save the public IP address of the Ingress Controller into a shell variable:

```console
IC_IP=XXX.YYY.ZZZ.III
```

Save the HTTP port of the Ingress Controller into a shell variable:

```console
IC_HTTP_PORT=<port number>
```

## 2. Deploy the Cafe Application

Create the coffee and tea deployments and services:

```console
kubectl apply -f cafe.yaml
```

Both applications run `nginx:alpine` with HTTP/2 enabled on a cleartext listener, so they
accept HTTP/1.0, HTTP/1.1 and cleartext HTTP/2 (h2c) connections on the same port. Every
response reports the protocol and the `Connection` header of the request received from the
Ingress Controller. `tea-svc` declares `appProtocol: kubernetes.io/h2c`; `coffee-svc`
declares no `appProtocol`.

## 3. Configure the upstream HTTP version with the annotation

```console
kubectl apply -f cafe-ingress-annotation.yaml
```

The annotation sets HTTP/1.0 for every location and takes precedence over the `appProtocol`
of `tea-svc`. Send a request to each location:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
```

```text
Server name: coffee-7586895968-r26zn
URI: /coffee
Upstream protocol: HTTP/1.0
Connection header: close
```

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

```text
Server name: tea-5c457db9-4dzrk
URI: /tea
Upstream protocol: HTTP/1.0
Connection header: close
```

Both backends received an HTTP/1.0 request with `Connection: close`.

## 4. Configure the upstream HTTP version with appProtocol

Replace the Ingress with one that has no annotation:

```console
kubectl delete -f cafe-ingress-annotation.yaml
kubectl apply -f cafe-ingress-app-protocol.yaml
```

Each location is now resolved from its own backing Service:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
```

```text
Server name: coffee-7586895968-r26zn
URI: /coffee
Upstream protocol: HTTP/1.1
Connection header:
```

`coffee-svc` has no `appProtocol`, so no `proxy_http_version` directive is rendered and NGINX
uses HTTP/1.1.

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

```text
Server name: tea-5c457db9-4dzrk
URI: /tea
Upstream protocol: HTTP/2.0
Connection header:
```

`tea-svc` declares `appProtocol: kubernetes.io/h2c`, so `proxy_http_version 2;` is inferred
and the request reaches the backend over cleartext HTTP/2, without a `Connection` header.
