# Rate Limit JWT claim

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply a rate
limit policy using a JWT claim as the key to the rate limit.

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
kubectl apply -f webapp.yaml
```

## Step 2 - Deploy the Rate Limit Policy

In this step, we create a policy with the name `rate-limit-jwt` that allows only 1 request per second coming from a
request containing a JWT claim `sub`.

Create the policy:

```console
kubectl apply -f rate-limit.yaml
```

## Step 3 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `rate-limit-jwt` created in Step 2.

## Step 4 - Test the Configuration

The JWT payload used in this testing looks like:

```json
{
  "name": "Quotation System",
  "sub": "quotes",
  "iss": "My API Gateway"
}
```

In this test we are relying on the NGINX Plus `ngx_http_auth_jwt_module` to extract the `sub` claim from the JWT payload into the `$jwt_claim_sub` variable and use this as the rate limiting `key`.

Let's test the configuration.  If you access the application at a rate that exceeds one request per second, NGINX will
start rejecting your requests:

```console
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/ -H "Authorization: Bearer: `cat token.jwt`"
```

```text
Server address: 10.8.1.19:8080
Server name: webapp-dc88fc766-zr7f8
. . .
```

```console
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/ -H "Authorization: Bearer: `cat token.jwt`"
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
