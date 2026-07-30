# Support for a custom upstream Host header

You can customize the `Host` header that NGINX and NGINX Plus send to the upstream servers using an Ingress annotation.

NGINX Ingress Controller provides the following annotation for configuring the upstream `Host` header:

- ```nginx.org/upstream-vhost: "hostname"``` - specifies the value of the `Host` header sent to the upstream

The annotation applies to every path of the Ingress resource, and it applies to both HTTP and gRPC backends. For gRPC
backends, the `grpc_set_header` directive is generated instead of `proxy_set_header`.

The value of the annotation must be a valid DNS subdomain name, so NGINX variables such as `$host` are rejected. If the
value is empty or invalid, NGINX Ingress Controller rejects the annotation and reports the error as an event on the
Ingress resource.

Before using the examples, run `make secrets` command to generate the necessary secrets.

## Upstream-Vhost Annotation In Standard Ingress Type

### Example 1: Setting the Upstream Host Header

In the following example, the ``nginx.org/upstream-vhost`` annotation is used to send `example.internal` as the `Host`
header to the upstream servers:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress
  annotations:
    nginx.org/upstream-vhost: "example.internal"
spec:
  ingressClassName: nginx
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /coffee
        pathType: Prefix
        backend:
          service:
            name: coffee-svc
            port:
              number: 80
```

Corresponding NGINX config file snippet:

```shell
...

location /coffee {
  ...

  proxy_set_header Host example.internal;

  ...

...
```

### Example 2: gRPC Backend

When the path is a gRPC backend, configured with the ``nginx.org/grpc-services`` annotation, the annotation sets the
`Host` header using the `grpc_set_header` directive:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-ingress
  annotations:
    nginx.org/grpc-services: "grpc-svc"
    nginx.org/upstream-vhost: "example.internal"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - grpc.example.com
    secretName: tls-secret
  rules:
  - host: grpc.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: grpc-svc
            port:
              number: 50051
```

Corresponding NGINX config file snippet:

```shell
...

location / {
  ...

  grpc_set_header Host example.internal;

  ...

...
```

## Upstream-Vhost Annotation In Mergeable Ingress Type

The `nginx.org/upstream-vhost` annotation behaves the same way in mergeable Ingresses as the
[`nginx.org/proxy-set-headers`](../proxy-set-headers/README.md) annotation does: if a minion does not set the
annotation itself, it inherits the value configured on the master. If a minion sets its own value, that value
overrides the master's, and only applies to that minion's paths.

### Example: Minion Override and Minion Inheritance

In this example, the master sets the upstream `Host` header for all minions. The coffee minion overrides it with its
own value, while the tea minion has no annotation and therefore inherits the master's value:

Content of `cafe-master.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-master
  annotations:
    nginx.org/mergeable-ingress-type: "master"
    nginx.org/upstream-vhost: "example.internal"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - cafe.example.com
    secretName: tls-secret
  rules:
  - host: cafe.example.com
```

Content of `coffee-minion.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-coffee-minion
  annotations:
    nginx.org/mergeable-ingress-type: "minion"
    nginx.org/upstream-vhost: "coffee.example.com"
spec:
  ingressClassName: nginx
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /coffee
        pathType: Prefix
        backend:
          service:
            name: coffee-svc
            port:
              number: 80
```

Content of `tea-minion.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-tea-minion
  annotations:
    nginx.org/mergeable-ingress-type: "minion"
spec:
  ingressClassName: nginx
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
```

Corresponding NGINX config file snippet:

```shell
...

location /coffee {
  ...

  proxy_set_header Host coffee.example.com;

  ...

...
location /tea {
  ...

  proxy_set_header Host example.internal;

  ...

...
```
