# API Key Authentication

NGINX supports authenticating requests with
[ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html). In this example, we deploy
a web application, configure load balancing for it via a VirtualServer, and apply an API Key Auth policy.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/) instructions to deploy the Ingress Controller.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f cafe.yaml -f cafe-secret.yaml
```

## Step 2 - Deploy the API Key Auth Secret

Create a secret of type `nginx.org/apikey` with the name `api-key-client-secret` that will be used for authorization on the server level.

This secret will contain a mapping of client IDs to base64 encoded API Keys.

```console
kubectl apply -f api-key-secret.yaml
```

## Step 3 - Deploy the API Key Auth Policy

Create a policy with the name `api-key-policy` that references the secret from the previous step in the clientSecret field.
Provide an array of headers and queries in the header and query fields of the suppliedIn field, indicating where the API key can be sent

```console
kubectl apply -f api-key-policy.yaml
```

## Step 4 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer references the policy `api-key-policy` created in Step 3.

## Step 5 - Test the Configuration

If you attempt to access the application without providing a valid API Key in a expected header or query param for that VirtualServer:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/
```

```text
<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>
```

If you attempt to access the application providing an incorrect API Key in an expected header or query param for that VirtualServer:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -H "X-header-name: wrongpassword" https://cafe.example.com:$IC_HTTPS_PORT/coffee
```

```text
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
</body>
</html>
```

If you provide a valid API Key in an a header or query defined in the policy, your request will succeed:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -H "X-header-name: password" https://cafe.example.com:$IC_HTTPS_PORT/coffee 
```

```text
Server address: 10.244.0.6:8080
Server name: coffee-56b44d4c55-vjwxd
Date: 13/Jun/2024:13:12:17 +0000
URI: /coffee
Request ID: 4feedb3265a0430a1f58831d016e846d
```

Additionally you can set [error pages](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#errorpage) to handle the 401 and 403 responses.
