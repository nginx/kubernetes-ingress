# Custom HTTP Errors

In this example we demonstrate the `nginx.org/custom-http-errors` annotation:
NGINX intercepts backend responses with matching status codes and routes the
intercepted request to the Ingress's `spec.defaultBackend` so a user-provided
Service can render a custom error body, while preserving the original
upstream status code.

The annotation maps to NGINX's
[`proxy_intercept_errors`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_intercept_errors)
and [`error_page`](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
directives.

The annotation is only meaningful when the Ingress has a `spec.defaultBackend`.
If the annotation is set without a `spec.defaultBackend`, a `Warning` event
is emitted on the Ingress in that case.

The default-backend Service must live in the **same namespace** as the
Ingress.

## Running the Example

### 1. Deploy the Ingress Controller

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

### 2. Deploy the cafe application and the error-pages backend

```console
kubectl apply -f cafe.yaml
kubectl apply -f error-pages.yaml
```

### 3. Apply the Ingress

```console
kubectl apply -f cafe-ingress.yaml
```

### 4. Trigger an upstream error

The `coffee` and `tea` demo apps return `200 OK` for any path, so requesting
them will never trigger interception. To demonstrate the annotation, the
example ships a dedicated `fail-backend` Service (deployed by `error-pages.yaml`)
that always returns `502 Bad Gateway`, and the Ingress routes `/fail` to it:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP \
    http://cafe.example.com:$IC_HTTP_PORT/fail
```

Expected response:

```text
Something went wrong and the application is temporarily unavailable. Please try again later.
```

### 5. Confirm successful responses are not intercepted

Requests that hit the coffee / tea backends and return `200 OK` are passed
through unchanged, the annotation only intervenes on matching error codes:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP \
    http://cafe.example.com:$IC_HTTP_PORT/coffee
```

```text
Server address: 10.92.0.16:8080
Server name: coffee-7b9578cff9-m8v5h
Date: 14/Jul/2026:16:01:47 +0000
URI: /coffee
Request ID: d2521141a10854fa0225ab64602a8b9a
```
