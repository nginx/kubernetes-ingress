# VirtualServerRoute Selector With Policies Configuration

In this example we use the [VirtualServer and
VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resources attached using `routeSelector` to configure load balancing for the cafe application with additional api-key and rate-limit policies on different routes.

The example demonstrates:

- How policies defined on a VirtualServer are inherited by all routes
- How VirtualServerRoute resources can have their own additional policies
- Policy layering where a route can have both inherited and route-specific policies

The example is similar to the [basic route selector example](../vsr-route-selector-basic/README.md).
However, instead of just routing configuration, we add policy configuration using [`Policy`](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/) resources to demonstrate inheritance and layering.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller with custom resources enabled.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Create Cafe Namespace

Create the required cafe namespace for the api-key policy:

```console
kubectl create -f cafe-namespace.yaml
```

## Step 2 - Deploy the API Key Auth Secret in the Cafe Namespace

Create a secret of type `nginx.org/apikey` with the name `api-key-client-secret` that will be used for authorization on the server level.

This secret will contain a mapping of client IDs to base64 encoded API Keys.

```console
kubectl apply -f api-key-secret.yaml
```

## Step 3 - Deploy the API Key Auth Policy in the Cafe Namespace

Create a policy with the name `api-key-policy` that references the secret from the previous step in the clientSecret field.
Provide an array of headers and queries in the header and query fields of the suppliedIn field, indicating where the API key can be sent

```console
kubectl apply -f api-key-policy.yaml
```

## Step 4 - Deploy the Cafe Application

1. Create the tea deployment and service:

    ```console
    kubectl create -f tea.yaml
    ```

1. Create the coffee deployment and service:

    ```console
    kubectl create -f coffee.yaml
    ```

## Step 5 - Deploy the Rate Limit Policy

In this step, we create a policy with the name `rate-limit-policy` that allows only 1 request per second coming from a
single IP address.

Create the policy:

```console
kubectl apply -f rate-limit.yaml
```

## Step 6 - Configure Load Balancing and TLS Termination

1. Create the secret with the TLS certificate and key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

1. Create the VirtualServerRoute resource for tea:

    ```console
    kubectl create -f tea-virtual-server-route.yaml
    ```

1. Create the VirtualServerRoute resource for coffee with the rate-limit policy:

    ```console
    kubectl create -f coffee-virtual-server-route.yaml
    ```

    Note that the coffee VirtualServerRoute references the policy `rate-limit-policy` created in Step 5.

1. Create the VirtualServer resource for the cafe app with the api-key policy:

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

    Note that the VirtualServer references the policy `api-key-policy` created in Step 3.

## Step 7 - Test the API Key Configuration

Let's test the API key authentication that applies to all routes. The policy is defined on the VirtualServer and inherited by both tea and coffee routes.

### Test without API Key (401 Unauthorized)

If you attempt to access any route without providing a valid API Key:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea
```

```text
<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>
```

### Test with Invalid API Key (403 Forbidden)

If you attempt to access any route with an incorrect API Key:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -H "X-header-name: wrongpassword" https://cafe.example.com:$IC_HTTPS_PORT/tea
```

```text
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
</body>
</html>
```

Additionally you can set [error pages](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#errorpage) to handle the 401 and 403 responses.

### Test with Valid API Key - Tea Route (Inheritance)

With a valid API key, you can access the tea route:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -H "X-header-name: password" https://cafe.example.com:$IC_HTTPS_PORT/tea
```

```text
Server address: 10.244.0.7:8080
Server name: tea-56b44d4c55-abcde
Date: 13/Jun/2024:13:12:17 +0000
URI: /tea
Request ID: 4feedb3265a0430a1f58831d016e846f
```

### Test without an API Key - Coffee Route (Inheritance)

The coffee route applies the `rate-limit-policy` policy on the VirtualServerRoute, this means it does not inherit the API Key policy from the VirtualServer resource.  A request can be made without needing the `X-header-name` header:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee
```

```text
Server address: 10.244.0.6:8080
Server name: coffee-56b44d4c55-vjwxd
Date: 13/Jun/2024:13:12:17 +0000
URI: /coffee
Request ID: 4feedb3265a0430a1f58831d016e846d
```

## Step 8 - Test the Rate Limit Configuration on Coffee Route

The coffee route has both API key authentication (inherited from VirtualServer) AND rate limiting. Let's test the rate limiting by making rapid requests to the coffee endpoint.

First, wait at least 1 second from your last request, then make a successful request with valid API key:

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

Now make another request immediately (within 1 second). The rate limit policy will reject it:

```console
curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -H "X-header-name: password" https://cafe.example.com:$IC_HTTPS_PORT/coffee
```

```text
<html>
<head><title>503 Service Temporarily Unavailable</title></head>
<body>
<center><h1>503 Service Temporarily Unavailable</h1></center>
</body>
</html>
```

Note that the tea route does NOT have rate limiting, so you can make multiple requests to it without being rate limited (as long as you have a valid API key).
