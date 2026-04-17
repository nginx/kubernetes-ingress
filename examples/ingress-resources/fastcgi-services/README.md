# FastCGI support

To route traffic to a FastCGI backend (such as PHP-FPM) with NGINX Ingress Controller, add the
**nginx.org/fastcgi-services** annotation to your Ingress resource definition. This eliminates the need for a sidecar
NGINX container in your application pods.

## Syntax

The `nginx.org/fastcgi-services` specifies which services are FastCGI services. The annotation syntax is as follows:

```yaml
nginx.org/fastcgi-services: "service1[,service2,...]"
```

## Example 1: PHP-FPM application

In the following example we route traffic to a PHP-FPM backend that speaks FastCGI on port 9000:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: php-ingress
  annotations:
    nginx.org/fastcgi-services: "php-svc"
    nginx.org/server-snippets: |
      root /var/www/html;
    nginx.org/location-snippets: |
      fastcgi_index index.php;
spec:
  ingressClassName: nginx
  rules:
  - host: php.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: php-svc
            port:
              number: 9000
```

*php-svc* is a Kubernetes Service pointing to PHP-FPM pods. NGINX will use `fastcgi_pass` instead of `proxy_pass` for
this service.

The `server-snippets` annotation sets `root` to the directory containing your PHP files inside the PHP-FPM container.
This is required so that `SCRIPT_FILENAME` (which defaults to `$document_root$fastcgi_script_name`) resolves to the
correct file path. The `location-snippets` annotation sets `fastcgi_index` for directory requests.

> **Note**: The snippet annotations require `-enable-snippets` on the Ingress Controller.

## Example 2: Symfony application with custom SCRIPT_FILENAME

Symfony routes all requests through `public/index.php`. Use `nginx.org/server-snippets` to set the document root and
`nginx.org/location-snippets` to override the default `SCRIPT_FILENAME` and set `fastcgi_index`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: symfony-ingress
  annotations:
    nginx.org/fastcgi-services: "symfony-svc"
    nginx.org/server-snippets: |
      root /app/public;
    nginx.org/location-snippets: |
      fastcgi_index index.php;
      fastcgi_param SCRIPT_FILENAME /app/public/index.php;
spec:
  ingressClassName: nginx
  rules:
  - host: symfony.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: symfony-svc
            port:
              number: 9000
```

> **Note**: The `location-snippets` annotation requires `-enable-snippets` on the Ingress Controller.

## Example 3: Mixed FastCGI and HTTP backends

You can mix FastCGI and HTTP backends on the same Ingress. Only the services listed in `nginx.org/fastcgi-services` use
`fastcgi_pass`; all others continue to use `proxy_pass`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mixed-ingress
  annotations:
    nginx.org/fastcgi-services: "php-svc"
spec:
  ingressClassName: nginx
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: php-svc
            port:
              number: 9000
      - path: /static
        pathType: Prefix
        backend:
          service:
            name: static-svc
            port:
              number: 80
```

## Migration from community ingress-nginx

Users migrating from the community `kubernetes/ingress-nginx` controller should note the following annotation mapping:

| Community (kubernetes/ingress-nginx) | NginxInc (nginx/kubernetes-ingress) |
|--------------------------------------|-------------------------------------|
| `nginx.ingress.kubernetes.io/backend-protocol: "FCGI"` | `nginx.org/fastcgi-services: "svc-name"` |
| `nginx.ingress.kubernetes.io/fastcgi-index` | Use `nginx.org/location-snippets` with `fastcgi_index` directive |
| `nginx.ingress.kubernetes.io/fastcgi-params-configmap` | Use `nginx.org/location-snippets` with `fastcgi_param` directives |

The key difference is that the NginxInc annotation uses per-service granularity (matching `nginx.org/grpc-services`),
while the community annotation applies to all paths in the Ingress.
