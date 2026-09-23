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
3. Unset: the directive is not rendered and NGINX applies its own default, which is
   HTTP/1.1 as of NGINX 1.29.7

## Requirements and limitations

- The value `"2"` requires NGINX 1.29.4 or later, which every supported NGINX Ingress
  Controller image satisfies.
- HTTP/2 forbids the hop-by-hop `Connection` and `Upgrade` headers
  ([RFC 9113 8.2.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2)), so NGINX Ingress
  Controller omits them for locations that proxy over HTTP/2. WebSocket connections
  therefore cannot be served through an HTTP/2 upstream.
- HTTP/1.0 has no persistent connections or `Upgrade` mechanism, so locations that proxy over
  HTTP/1.0 send `Connection: close` to the upstream (and no `Upgrade` header), as recommended in
  [Keep-alive to upstreams is now default in NGINX 1.29.7](https://blog.nginx.org/blog/keep-alive-to-upstreams-is-now-default-in-nginx-1-29-7).
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

Create the coffee and tea deployments and services. `tea-svc` declares
`appProtocol: kubernetes.io/h2c`, `coffee-svc` declares no `appProtocol`:

```console
kubectl apply -f cafe.yaml
```

## 3. Configure Load Balancing

```console
kubectl apply -f cafe-virtual-server.yaml
```

The generated configuration renders:

- `proxy_http_version 1.0;` and `proxy_set_header Connection close;` for the `coffee` upstream,
  from the explicit field
- `proxy_http_version 2;` for the `tea` upstream, inferred from its Service `appProtocol`

```console
kubectl exec -it <nginx-ingress-pod> -- grep proxy_http_version /etc/nginx/conf.d/vs_default_cafe.conf
```

## 4. Test the Application

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

> [!NOTE]
> `nginxdemos/nginx-hello` does not serve cleartext HTTP/2. The `/tea` request is expected to
> fail against it; replace `tea` with an h2c-capable backend to exercise the HTTP/2 upstream
> path end to end.
