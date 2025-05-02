---
docs: DOCS-1451
doctypes:
- concept
title: Ingresses Path Matching Using Path-Regex Annotation
toc: true
weight: 1800
---

This document describes how to customize Ingress and Mergeable Ingress types with path-regex annotations.

## Customizing NGINX Ingress Controller with Path-Regex Annotations

We suggest reading the NGINX [documentation on resolve location priority](https://docs.nginx.com/nginx/admin-guide/web-server/web-server/#nginx-location-priority)
to gain additional context about NGINX and NGINX Plus before using the ``path-regex`` annotation.

## Ingress Type

In this example, you will use the `nginx.org/path-regex` annotations to add regex modifiers to the location paths.

Start by modifying `cafe-ingress.yaml` metadata to add the annotation section and configure
the ``nginx.org/path-regex`` annotation.

`cafe-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress
  annotations:
    nginx.org/path-regex: "case_sensitive"
spec:
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /tea/[A-Z0-9]
        backend:
          serviceName: tea-svc
          servicePort: 80
      - path: /coffee/[A-Z0-9]
        backend:
          serviceName: coffee-svc
          servicePort: 80
```

After creating the Ingress (`kubectl create -f cafe-ingres.yaml`), all defined paths will be updated. In the generated
NGINX config file the ``tea`` and ``coffee`` paths will look like in the snippets below:

tea path:

```nginx
location ~ "^/tea/[A-Z0-9]"
```

coffee path:

```nginx
location ~ "^/coffee/[A-Z0-9]"
```

Note that the regex modifier `case_sensitive` is applied to all paths.

To change regex modifier value from `case_sensitive` to `case_insensitive` update the `nginx.org/path-regex` annotation.

The config `cafe-ingress.yaml` file below shows the change.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress
  annotations:
    nginx.org/path-regex: "case_insensitive"
spec:
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /tea/[A-Z0-9]
        backend:
          serviceName: tea-svc
          servicePort: 80
      - path: /coffee/[A-Z0-9]
        backend:
          serviceName: coffee-svc
          servicePort: 80
```

In the NGINX config file, the ``/tea/[A-Z0-9]`` and ``/coffee/[A-Z0-9]`` paths should look like in the snippets below.

tea path

```nginx
location ~* "^/tea/[A-Z0-9]"
```

coffee path

```nginx
location ~* "^/coffee/[A-Z0-9]"
```

## Mergeable Ingress Type

This document section explains how to deploy and configure Mergeable Ingress Type.

First, you will deploy a Master Ingress and two Minion Ingresses. Then, you will configure them with `path-regex` annotations.

Create a Master Ingress.

`cafe-master.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-master
  annotations:
    nginx.org/mergeable-ingress-type: "master"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
  rules:
  - host: cafe.example.com
```

Create the Ingress

```shell
kubectl create -f cafe-master.yaml
```

Verify the Master Ingress was created

```shell
kubectl get ingress cafe-ingress-master

NAME                  CLASS   HOSTS              ADDRESS   PORTS     AGE
cafe-ingress-master   nginx   cafe.example.com             80, 443   29s
```

```shell
kubectl describe ingress cafe-ingress-master

Name:             cafe-ingress-master
Labels:           <none>
Namespace:        default
Address:
Ingress Class:    nginx
Default backend:  <default>
TLS:
  cafe-secret terminates cafe.example.com
Rules:
  Host        Path  Backends
  ----        ----  --------
  *           *     <default>
Annotations:  nginx.org/mergeable-ingress-type: master
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  62s   nginx-ingress-controller  Configuration for default/cafe-ingress-master was added or updated
```

Create the first Ingress Minion.

`tea-minion.yaml`

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

```shell
kubectl create -f tea-minion.yaml

ingress.networking.k8s.io/cafe-ingress-tea-minion created
```

Verify the Minion was created:

```shell
kubectl get ingress cafe-ingress-tea-minion

NAME                      CLASS   HOSTS              ADDRESS   PORTS   AGE
cafe-ingress-tea-minion   nginx   cafe.example.com             80      23m
```

```shell
kubectl describe ingress cafe-ingress-tea-minion

Name:             cafe-ingress-tea-minion
Labels:           <none>
Namespace:        default
Address:
Ingress Class:    nginx
Default backend:  <default>
Rules:
  Host              Path  Backends
  ----              ----  --------
  cafe.example.com
                    /tea   tea-svc:80 (10.244.0.6:8080,10.244.0.7:8080,10.244.0.8:8080)
Annotations:        nginx.org/mergeable-ingress-type: minion
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  24m   nginx-ingress-controller  Configuration for default/cafe-ingress-tea-minion was added or updated
```

Create the second Ingress Minion.

`tea-minion.yaml`

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

```shell
kubectl create -f tea-minion.yaml

ingress.networking.k8s.io/cafe-ingress-tea-minion created
```

Verify the Minion Ingress was created:

```shell
kubectl get ingress cafe-ingress-tea-minion

NAME                      CLASS   HOSTS              ADDRESS   PORTS   AGE
cafe-ingress-tea-minion   nginx   cafe.example.com             80      5m21s
```

```shell
kubectl describe ingress cafe-ingress-tea-minion

Name:             cafe-ingress-tea-minion
Labels:           <none>
Namespace:        default
Address:
Ingress Class:    nginx
Default backend:  <default>
Rules:
  Host              Path  Backends
  ----              ----  --------
  cafe.example.com
                    /tea   tea-svc:80 (10.244.0.6:8080,10.244.0.7:8080,10.244.0.8:8080)
Annotations:        nginx.org/mergeable-ingress-type: minion
Events:
  Type    Reason          Age    From                      Message
  ----    ------          ----   ----                      -------
  Normal  AddedOrUpdated  5m52s  nginx-ingress-controller  Configuration for default/cafe-ingress-tea-minion was added or updated
```

You created a Master Ingress and two Minion Ingresses. Minion Ingresses are defined with two paths: `/tea` and `/coffee`.

In the following steps, you will modify the paths by applying regex modifiers.

Update the Minion Ingress `Tea`:

- add `path-regex` annotation with value `case_insensitive`
- modify path with regex you want to use (in the example below: `/tea/[A-Z0-9]`)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-tea-minion
  annotations:
    nginx.org/mergeable-ingress-type: "minion"
    nginx.org/path-regex: "case_insensitive"
spec:
  ingressClassName: nginx
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /tea/[A-Z0-9]
        pathType: Prefix
        backend:
          service:
            name: tea-svc
            port:
              number: 80
```

Apply the changes:

```shell
kubectl apply -f tea-minion.yaml
```

Verify the change:

```shell
kubectl describe ingress cafe-ingress-tea-minion

Name:             cafe-ingress-tea-minion
Labels:           <none>
Namespace:        default
Address:
Ingress Class:    nginx
Default backend:  <default>
Rules:
  Host              Path  Backends
  ----              ----  --------
  cafe.example.com
                    /tea/[A-Z0-9]   tea-svc:80 (10.244.0.6:8080,10.244.0.7:8080,10.244.0.8:8080)
Annotations:        nginx.org/mergeable-ingress-type: minion
                    nginx.org/path-regex: case_insensitive
Events:
  Type    Reason          Age                From                      Message
  ----    ------          ----               ----                      -------
  Normal  AddedOrUpdated  47s (x2 over 34m)  nginx-ingress-controller  Configuration for default/cafe-ingress-tea-minion was added or updated
```

Looking at the updated list of annotations, we can see the new `path-regex` annotation was added.

It updates the path `/tea/[A-Z0-9]` using the `case_insensitive` regex modifier.
Updated path (location) in the NGINX config file: `location ~* "^/tea/[A-Z0-9]"`.

Note that the `path-regex` annotation applies only to paths defined on the corresponding Minion Ingress.
The paths defined in the second Minion (`coffee`) are not modified.

Follow the steps below to configure the type `case_sensitive` regex modifier on the Second Minion Ingress.

Modify deployed `coffee-minion.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-coffee-minion
  annotations:
    nginx.org/mergeable-ingress-type: "minion"
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

Add `path-regex` annotation and modify the path `/coffee`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-coffee-minion
  annotations:
    nginx.org/mergeable-ingress-type: "minion"
    nginx.org/path-regex: "case_sensitive"
spec:
  ingressClassName: nginx
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /coffee/[A-Za-z0-9]
        pathType: Prefix
        backend:
          service:
            name: coffee-svc
            port:
              number: 80
```

Apply changes to the Minion Ingress:

```shell
kubectl apply -f coffee-minion.yaml

ingress.networking.k8s.io/cafe-ingress-coffee-minion created
```

Verify the applied changes:

```shell
kubectl describe ingress cafe-ingress-coffee-minion

Name:             cafe-ingress-coffee-minion
Labels:           <none>
Namespace:        default
Address:
Ingress Class:    nginx
Default backend:  <default>
Rules:
  Host              Path  Backends
  ----              ----  --------
  cafe.example.com
                    /coffee/[A-Za-z0-9]   coffee-svc:80 (10.244.0.10:8080,10.244.0.9:8080)
Annotations:        nginx.org/mergeable-ingress-type: minion
                    nginx.org/path-regex: case_sensitive
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  11m   nginx-ingress-controller  Configuration for default/cafe-ingress-coffee-minion was added or updated
```

The new annotation `nginx.org/path-regex` was added.
It updates the path `/coffee/[A-Za-z0-9]` using the `case_sensitive` regex modifier.
Updated path (location) in the NGINX config file: `location ~ "^/coffee/[A-Za-z0-9]"`.
