# Basic Authentication

NGINX supports authenticating requests with
[ngx_http_auth_basic_module](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html). In this example, we deploy
a web application, configure load balancing for it via a VirtualServer, and apply a Basic Auth policy.

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

## Step 3 - Deploy the Basic Auth Policy

Create a policy with the name `basic-auth-policy` that references the secret from the previous step and only permits
requests to our web application that contain a valid user:password auth:

```console
kubectl apply -f basic-auth-policy.yaml
```

## Step 4 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer references the policy `basic-auth-policy` created in Step 3.

## Step 5 - Test the Configuration

If you attempt to access the application without providing a valid user and password, NGINX will reject your requests
for that VirtualServer:

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
