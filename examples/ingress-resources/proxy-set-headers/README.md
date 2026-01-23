# Support for custom proxy headers

You can customize proxy headers for NGINX and NGINX Plus using Ingress annotations.

NGINX Ingress Controller provides the following annotation for configuring custom proxy headers:

- Optional: ```nginx.org/proxy-set-headers: "Header-Name"``` - specifies a custom header to be set

The `nginx.org/proxy-set-headers` annotation allows for the following configurations:

- **Single Header**: Set a single custom header by specifying its name.
- **Multiple Headers**: Set multiple custom headers by separating their names with commas.
- **Custom Header Values**: Set custom values for headers by using the format `"Header-Name: Value"`.

When using the ``proxy-set-headers`` annotation, the specified headers will be added to the outgoing requests proxied by NGINX.

Before using the examples, run `make secrets` command to generate the necessary secrets.

## Proxy-Set-Headers Annotation In Standard Ingress Type

### Example 1: Setting a Single Custom Header With Default Value

In the following example, the ``nginx.org/proxy-set-headers`` annotation is used to set a single custom header named `X-Forwarded-ABC`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    nginx.org/proxy-set-headers: "X-Forwarded-ABC"
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        backend:
          serviceName: example-service
          servicePort: 80
```

Corresponding NGINX config file snippet:

```shell
...

  proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;

...
```

### Example 2: Setting Multiple Custom Headers With Default Values

In this example, the ``nginx.org/proxy-set-headers`` annotation is used to set multiple custom headers, `X-Forwarded-ABC` and `ABC2`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    nginx.org/proxy-set-headers: "X-Forwarded-ABC, ABC2"
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        backend:
          serviceName: example-service
          servicePort: 80
```

Corresponding NGINX config file snippet:

```shell
...

  proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;
  proxy_set_header ABC2 $http_abc2;

...
```

### Example 3: Setting Custom Header Values

In this example, the ``nginx.org/proxy-set-headers annotation`` is used to set a custom value for the ``X-Forwarded-ABC`` header.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    nginx.org/proxy-set-headers: "X-Forwarded-ABC: test"
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        backend:
          serviceName: example-service
          servicePort: 80
```

Corresponding NGINX config file snippet:

```shell
...

  proxy_set_header X-Forwarded-ABC "test";

...
```

## Proxy-Set-Headers Annotation In Mergeable Ingress Type

When using the proxy-set-headers annotation in minions, if there are conflicting headers with different values between master and minion, the minion's value will override the master's.

If different headers are specified in both master and minions, both sets of annotations will be applied.

### Example 1: Headers in both Master and Minions

In this example, we add a custom header and value to each minion with defaults for master:

Content of `cafe-master.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-master
  annotations:
    nginx.org/mergeable-ingress-type: "master"
    nginx.org/proxy-set-headers: "X-Forwarded-Master"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
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
    nginx.org/proxy-set-headers: "X-Forwarded-Coffee cappuccino"
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
    nginx.org/proxy-set-headers: "X-Forwarded-Tea greenTea"
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

  proxy_set_header X-Forwarded-Master $http_x_forwarded_master;
  proxy_set_header X-Forwarded-Coffee "cappuccino";

  ...

...
location /tea {
  ...
  
  proxy_set_header X-Forwarded-Master $http_x_forwarded_master;
  proxy_set_header X-Forwarded-Tea "greenTea";
  
  ...
...

```

### Example 2: Minion Override Master Header

In this example, a header is in both a master and a minion; in the minion it has a different value and therefore overrides master.

Content of `cafe-master.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-master
  annotations:
    nginx.org/mergeable-ingress-type: "master"
    nginx.org/proxy-set-headers: "X-Forwarded-ABC: master"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
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
    nginx.org/proxy-set-headers: "X-Forwarded-Coffee: cappuccino,X-Forwarded-ABC: coffee"
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
    nginx.org/proxy-set-headers: "X-Forwarded-Tea: greenTea,X-Forwarded-Minion: tea"
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
  proxy_set_header X-Forwarded-Coffee "cappuccino";
  proxy_set_header X-Forwarded-ABC "coffee";
  ...

...
location /tea {
  ...
  proxy_set_header X-Forwarded-ABC "master";
  proxy_set_header X-Forwarded-Tea "greenTea";
  proxy_set_header X-Forwarded-Minion "tea";
  ...

...

```

### Example 3: No Annotation in Minion

In this example, we use the annotation in master to add a custom header and value to a minion without an annotation:

Content of `cafe-master.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-master
  annotations:
    nginx.org/mergeable-ingress-type: "master"
    nginx.org/proxy-set-headers: "X-Forwarded-Master"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
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
    nginx.org/proxy-set-headers: "X-Forwarded-Coffee: cappuccino"
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
  proxy_set_header X-Forwarded-Master $http_x_forwarded_master;
  proxy_set_header X-Forwarded-Coffee "cappuccino";
  ...

...
location /tea {
  ...
  proxy_set_header X-Forwarded-Master $http_x_forwarded_master;
  ...

...

```
