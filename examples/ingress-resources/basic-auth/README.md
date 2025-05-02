# Support for HTTP Basic Authentication

NGINX supports authenticating requests with
[ngx_http_auth_basic_module](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html).

The Ingress controller provides the following 2 annotations for configuring Basic Auth validation:

- Required: ```nginx.org/basic-auth-secret: "secret"``` -- specifies a Secret resource with a htpasswd user list. The
  htpasswd must be stored in the `htpasswd` data field. The type of the secret must be `nginx.org/htpasswd`.
- Optional: ```nginx.org/basic-auth-realm: "realm"``` -- specifies a realm.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Deploy the Basic Auth Secret

Create a secret of type `nginx.org/htpasswd` with the name `cafe-passwd` that will be used for Basic Auth validation. It
contains a list of user and base64 encoded password pairs:

```console
kubectl apply -f cafe-passwd.yaml
```

## Step 3 - Configure Load Balancing

Create an Ingress resource for the web application:

```console
kubectl apply -f cafe-ingress.yaml
```

Note that the Ingress resource references the `cafe-passwd` secret created in Step 2 via the
`nginx.org/basic-auth-secret` annotation.

## Step 4 - Test the Configuration

If you attempt to access the application without providing a valid user and password, NGINX will reject your requests
for that Ingress:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/
```

```text
<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>
```

If you provide a valid user and password, your request will succeed:

```console
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure -u foo:bar
```

```text
Server address: 10.244.0.6:8080
Server name: coffee-7b9b4bbd99-bdbxm
Date: 20/Jun/2022:11:43:34 +0000
URI: /coffee
Request ID: f91f15d1af17556e552557df2f5a0dd2
```

## Example 2: a Separate Htpasswd Per Path

In the following example we enable Basic Auth validation for the [mergeable Ingresses](../mergeable-ingress-types) with
a separate Basic Auth user:password list per path:

- Master:

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

- Tea minion:

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: cafe-ingress-tea-minion
    annotations:
      nginx.org/mergeable-ingress-type: "minion"
      nginx.org/basic-auth-secret: "tea-passwd"
      nginx.org/basic-auth-realm: "Tea"
  spec:
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

- Coffee minion:

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: cafe-ingress-coffee-minion
    annotations:
      nginx.org/mergeable-ingress-type: "minion"
      nginx.org/basic-auth-secret: "coffee-passwd"
      nginx.org/basic-auth-realm: "Coffee"
  spec:
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
