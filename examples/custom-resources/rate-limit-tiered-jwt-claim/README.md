# Rate Limit JWT claim

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply two rate
limit Policies, grouped in a tier, using a JWT claim `sub` as the key to the rate limit and using another JWT claim
`user_details.level` to determine which rate limit Policy is applied.  One rate limit policy will be the default rate
limit for the group.

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

In this step, we create two Policies:

- one with the name `rate-limit-jwt-premium`, that allows 10 requests per second coming from a request containing a JWT claim `user_details.level` with a value of `Premium`,
- one with the name `rate-limit-jwt-basic` that allows 1 request per second coming from a request containing a JWT claim `user_details.level` with a value of `Basic`.

The `rate-limit-jwt-basic` Policy is also the default policy if there is not a `user_details.level` JWT claim present.

Create the policies:

```console
kubectl apply -f rate-limit.yaml
```

## Step 3 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policies `rate-limit-jwt-premium` & `rate-limit-jwt-basic` created in Step 2.

## Step 4 - Test the Premium Configuration

The Premium JWT payload used in this testing looks like:

```json
{
  "user_details": {
    "level": "Premium"
  },
  "sub": "client1",
  "name": "John Doe"
}
```

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

## Step 5 - Test the Basic Configuration

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

## Step 6 - Test the default Configuration

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
