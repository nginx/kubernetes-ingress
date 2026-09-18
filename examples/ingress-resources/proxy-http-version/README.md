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
3. Unset: the directive is not rendered and NGINX applies its own default, which is
   HTTP/1.1 as of NGINX 1.29.7

## Requirements and limitations

- The value `"2"` requires NGINX 1.29.4 or later, which every supported NGINX Ingress
  Controller image satisfies.
- HTTP/2 forbids the hop-by-hop `Connection` and `Upgrade` headers
  ([RFC 9113 8.2.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2)), so NGINX Ingress
  Controller omits them for locations that proxy over HTTP/2. As a consequence, WebSocket
  (`nginx.org/websocket-services`) cannot be used together with HTTP/2 upstreams. A warning
  event is emitted if you configure both.
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

Create the coffee and tea deployments and services. `tea-svc` declares
`appProtocol: kubernetes.io/h2c`, `coffee-svc` declares no `appProtocol`:

```console
kubectl apply -f cafe.yaml
```

## 3. Configure the upstream HTTP version with the annotation

```console
kubectl apply -f cafe-ingress-annotation.yaml
```

Both locations now render `proxy_http_version 1.0;`, because the annotation takes precedence
over the `appProtocol` of `tea-svc`:

```console
kubectl exec -it <nginx-ingress-pod> -- grep -A1 'location /' /etc/nginx/conf.d/default-cafe-ingress.conf
```

## 4. Configure the upstream HTTP version with appProtocol

```console
kubectl delete -f cafe-ingress-annotation.yaml
kubectl apply -f cafe-ingress-app-protocol.yaml
```

With no annotation, each location is resolved from its own backing Service:

- `/coffee` renders no `proxy_http_version` directive, so NGINX uses its default (HTTP/1.1)
- `/tea` renders `proxy_http_version 2;`, inferred from `appProtocol: kubernetes.io/h2c`

## 5. Test the Application

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

> [!NOTE]
> `nginxdemos/nginx-hello` does not serve cleartext HTTP/2. The `/tea` request in step 4 is
> expected to fail against it; replace `tea` with an h2c-capable backend to exercise the
> HTTP/2 upstream path end to end.
