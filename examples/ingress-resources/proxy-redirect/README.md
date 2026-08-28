# Proxy Redirect

In this example we deploy a custom redirect backend and demonstrate the supported
uses of the `nginx.org/proxy-redirect-from` and `nginx.org/proxy-redirect-to` Ingress
annotations.

These annotations map to NGINX's
[`proxy_redirect`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_redirect) directive,
which rewrites the `Location` and `Refresh` response headers that a backend sends before
they reach the client.

## Annotation reference

| Annotation | Description |
| --- | --- |
| `nginx.org/proxy-redirect-from` | The `redirect` parameter. Accepts `off`, `default`, a URL string, or a regex prefixed with `~` (case-sensitive) or `~*` (case-insensitive). |
| `nginx.org/proxy-redirect-to` | The `replacement` parameter. Required when `proxy-redirect-from` is a URL or regex; must not be set without `proxy-redirect-from`. |

The primary use cases are:

- Explicit pair: (`from` + `to`): rewrite a known URL prefix to the public hostname
- Regex pair: (`~pattern` + `replacement`): rewrite using a PCRE regex with capture groups

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

## 2. Deploy the backend

The `redirect-backend` simulates a backend that returns `301` redirects pointing to its
own internal service hostname (`http://redirect-backend-svc/v1/...`). This is the
canonical case where `proxy_redirect` is needed to rewrite the `Location` header to
the public ingress hostname before the client receives it.

```console
kubectl apply -f redirect-backend.yaml
```

## 3. Choose an example and apply it

### Case 1: Explicit URL pair (`from` → `to`)

Rewrites a fixed URL prefix in `Location` responses to the public hostname.

1. First, observe the `Location` header set to internal URL without the annotation.

    ```console
    kubectl apply -f ingress-no-redirect.yaml
    ```

    ```console
    curl -D - --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP \
        http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    ```text
    HTTP/1.1 301 Moved Permanently
    Server: nginx/1.29.8
    Date: Thu, 14 May 2026 18:19:19 GMT
    Content-Type: text/html
    Content-Length: 169
    Connection: keep-alive
    Location: http://redirect-backend-svc/v1/coffee
    ```

2. Now apply the ingress with annotation and observe the `Location` header rewritten to the public URL.

    ```console
    kubectl apply -f ingress-redirect-from-to.yaml
    ```

    ```console
    curl -D - --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP \
        http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    ```text
    HTTP/1.1 301 Moved Permanently
    Server: nginx/1.29.8
    Date: Thu, 14 May 2026 18:19:33 GMT
    Content-Type: text/html
    Content-Length: 169
    Connection: keep-alive
    Location: http://cafe.example.com/coffee/coffee
    ```

  The prefix `http://redirect-backend-svc/v1/` was replaced by
  `http://cafe.example.com/coffee/`.

### Case 2: Regex pair

Same as Case 1, but the `from` value is a regular expression. NGINX tests the
full `Location` header value against the pattern and substitutes capture groups into
`to` using `$1`, `$2`, etc.

1. Apply the ingress with annotation and observe the `Location` header rewritten to the public URL.

    ```console
    kubectl apply -f ingress-redirect-regex.yaml
    ```

2. The `redirect-backend` returns `301 Location: http://redirect-backend-svc/v1/coffee`
    (`$1=1`, `$2=coffee`). NGINX applies the regex and builds the replacement:

    ```console
    curl -D - --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP \
        http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    ```text
    HTTP/1.1 301 Moved Permanently
    Server: nginx/1.29.8
    Date: Thu, 14 May 2026 18:27:01 GMT
    Content-Type: text/html
    Content-Length: 169
    Connection: keep-alive
    Location: http://cafe.example.com/coffee/coffee
    ```

  The `Location` was rewritten from `http://redirect-backend-svc/v1/coffee` to
  `http://cafe.example.com/coffee/coffee` using capture group `$2`.
