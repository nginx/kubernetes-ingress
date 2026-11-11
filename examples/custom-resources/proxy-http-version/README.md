# Proxy HTTP Version

In this example we configure the HTTP version that NGINX uses for connections to upstream
servers, using the `proxy-http-version` field of a VirtualServer upstream and the standard
Kubernetes Service `appProtocol` field.

The field maps to NGINX's
[`proxy_http_version`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version)
directive. The same field is available on VirtualServerRoute upstreams.

## Configuration reference

| Surface | Accepted values | Notes |
| --- | --- | --- |
| `spec.upstreams[].proxy-http-version` | `"1.0"`, `"1.1"`, `"2"` | Applies to every location that passes to this upstream. |
| Service `spec.ports[].appProtocol` | `kubernetes.io/h2c` | Infers `"2"` for the upstreams backed by that Service port. Any other value is ignored. |

Precedence, highest first:

1. The upstream `proxy-http-version` field
2. The `appProtocol` of the backing Service port (`kubernetes.io/h2c` implies `"2"`)
3. Unset: the directive is not rendered and NGINX uses HTTP/1.1

## Requirements and limitations

- HTTP/2 forbids the hop-by-hop `Connection` and `Upgrade` headers
  ([RFC 9113 8.2.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2)), so NGINX Ingress
  Controller omits them for locations that proxy over HTTP/2. WebSocket connections
  therefore cannot be served through an HTTP/2 upstream.
- HTTP/1.0 has no persistent connections or `Upgrade` mechanism, so locations that proxy over
  HTTP/1.0 send `Connection: close` to the upstream (and no `Upgrade` header), as
  [recommended by NGINX](https://blog.nginx.org/blog/keep-alive-to-upstreams-is-now-default-in-nginx-1-29-7).
  WebSocket connections therefore cannot be served through an HTTP/1.0 upstream either.
- Upstreams with `type: grpc` are proxied with `grpc_pass`, which always uses HTTP/2. The
  field is ignored for them and a warning is reported in the VirtualServer status.

## Running the Example

## 1. Deploy the Ingress Controller

Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installing-nic/installation-with-manifests/)
instructions to deploy the Ingress Controller, with custom resources enabled.

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

## 3. Configure Load Balancing

```console
kubectl apply -f cafe-virtual-server.yaml
```

The `coffee` upstream sets `proxy-http-version: "1.0"`. The `tea` upstream sets no field, so
its HTTP version is inferred from the `appProtocol` of `tea-svc`.

## 4. Test the Application

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
```

```text
Server name: coffee-7586895968-r26zn
URI: /coffee
Upstream protocol: HTTP/1.0
Connection header: close
```

The `coffee` backend received an HTTP/1.0 request with `Connection: close`, from the explicit
`proxy-http-version` field.

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

```text
Server name: tea-5c457db9-4dzrk
URI: /tea
Upstream protocol: HTTP/2.0
Connection header:
```

The `tea` backend received the request over cleartext HTTP/2, without a `Connection` header,
because `proxy_http_version 2;` is inferred from `appProtocol: kubernetes.io/h2c`.
