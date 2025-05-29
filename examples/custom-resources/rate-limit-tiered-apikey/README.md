# Tiered Rate Limits with API Keys

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply two rate
limit Policies, grouped in a tier, using the API Key Client ID as the key to the rate limit and using a regex of the Client ID to determine which rate limit Policy is applied.  One rate limit policy will be the default ratelimit for the group.

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

Create the application deployments and services:

```console
kubectl apply -f coffee.yaml
```

## Step 2 - Deploy the Rate Limit Policies

In this step, we create three Policies:

- one with the name `api-key-policy` which defines the API Key Policy
- one with the name `rate-limit-apikey-premium`, that allows 100 requests per second coming from a request containing an API Key with a client id that ends with `premium`
- one with the name `rate-limit-apikey-basic` that allows 10 request per second coming from a request containing an API Key with a client id that ends with `basic`

The `rate-limit-apikey-basic` Policy is also the default policy if the API Key Client ID does not match a tier.

Create the policies:

```console
kubectl apply -f api-key-policy.yaml
kubectl apply -f rate-limit.yaml
```

## Step 3 - Deploy the API Key Auth Secret

Create a secret of type `nginx.org/apikey` with the name `api-key-client-secret` that will be used for authorization on the server level.

This secret will contain a mapping of client IDs to base64 encoded API Keys.

```console
kubectl apply -f api-key-secret.yaml
```

## Step 4 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policies `api-key-policy`, `rate-limit-apikey-premium` & `rate-limit-apikey-basic` created in Step 2.

## Step 5 - Test the Premium Configuration

In this test we are relying on the NGINX Plus `ngx_http_auth_jwt_module` to extract the `sub` claim from the JWT payload into the `$jwt_claim_sub` variable and use this as the rate limiting `key`.  The NGINX Plus `ngx_http_auth_jwt_module` will also extract the `user_details.level` to select the correct rate limit policy to be applied.

Let's test the configuration.  If you access the application at a rate that exceeds 10 requests per second, NGINX will
start rejecting your requests:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee -H "Authorization: Bearer: `cat premium-token.jwt`"
```

```text
Server address: 10.8.1.19:8080
Server name: coffee-dc88fc766-zr7f8
. . .
```

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee -H "Authorization: Bearer: `cat premium-token.jwt`"
```

```text
<html>
<head><title>503 Service Temporarily Unavailable</title></head>
<body>
<center><h1>503 Service Temporarily Unavailable</h1></center>
</body>
</html>
```

> Note: The command result is truncated for the clarity of the example.

## Step 6 - Test the Basic Configuration

The Basic JWT payload used in this testing looks like:

```json
{
  "user_details": {
    "level": "Basic"
  },
  "sub": "client2",
  "name": "Jane Doe"
}
```

This test is similar to Step 4, however, this time we will be setting the `user_details.level` JWT claim to `Basic`.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee -H "Authorization: Bearer: `cat basic-token.jwt`"
```

```text
Server address: 10.8.1.19:8080
Server name: coffee-dc88fc766-zr7f8
. . .
```

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee -H "Authorization: Bearer: `cat basic-token.jwt`"
```

```text
<html>
<head><title>503 Service Temporarily Unavailable</title></head>
<body>
<center><h1>503 Service Temporarily Unavailable</h1></center>
</body>
</html>
```

> Note: The command result is truncated for the clarity of the example.

## Step 7 - Test the default Configuration

The default JWT payload used in this testing looks like:

```json
{
  "sub": "client3",
  "name": "Billy Bloggs"
}
```

This test is similar to Step 4 & 5, however, this time we will not be setting the `user_details.level` JWT claim but
will still be seeing the default `rate-limit-jwt-basic` Policy applied.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee -H "Authorization: Bearer: `cat default-token.jwt`"
```

```text
Server address: 10.8.1.19:8080
Server name: coffee-dc88fc766-zr7f8
. . .
```

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee -H "Authorization: Bearer: `cat default-token.jwt`"
```

```text
<html>
<head><title>503 Service Temporarily Unavailable</title></head>
<body>
<center><h1>503 Service Temporarily Unavailable</h1></center>
</body>
</html>
```

> Note: The command result is truncated for the clarity of the example.
---
> Note: This example does not validate the JWT token sent in the request, you should use either of the [`JWT Using Local Kubernetes Secret`](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#jwt-using-local-kubernetes-secret) or [`JWT Using JWKS From Remote Location`](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#jwt-using-jwks-from-remote-location) for that purpose.
