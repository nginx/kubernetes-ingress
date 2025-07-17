# Tiered Rate Limits with API Keys

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply two rate
limit Policies, grouped in a tier, using the API Key client name as the key to the rate limit and using a regex of the client name to determine which rate limit Policy is applied.  One rate limit policy will be the default ratelimit for the group.

> Note: This example makes use of the NGINX variables `$apikey_auth_token` & `apikey_client_name` which are made available by applying an API Key authentication Policy to your VirtualServer resource.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy NGINX Ingress Controller.
2. Save the public IP address of NGINX Ingress Controller into a shell variable:

```shell
IC_IP=XXX.YYY.ZZZ.III
```
<!-- markdownlint-disable MD029 -->
3. Save the HTTP port of NGINX Ingress Controller into a shell variable:
<!-- markdownlint-enable MD029 -->
```shell
IC_HTTP_PORT=<port number>
```

## Deploy a web application

Create the application deployments and services:

```shell
kubectl apply -f coffee.yaml
```

## Deploy the rate limit Policies

In this step, we create three Policies:

- `api-key-policy` which defines the API Key Policy
- `rate-limit-apikey-premium`, that allows 5 requests per second coming from a request containing an API Key with a client name that ends with `premium`
- `rate-limit-apikey-basic` that allows 1 request per second coming from a request containing an API Key with a client name that ends with `basic`

The `rate-limit-apikey-basic` Policy is also the default policy if the API Key client name does not match a tier.

Create the Policies:

```shell
kubectl apply -f api-key-policy.yaml
kubectl apply -f rate-limits.yaml
```

## Deploy the API key authentication Secret

Create a Secret of type `nginx.org/apikey` with the name `api-key-client-secret` that will be used for authorization on the server level.

This Secret will contain a mapping of client names to base64 encoded API Keys.

```shell
kubectl apply -f api-key-secret.yaml
```

## Configure load balancing

Create a VirtualServer resource for the web application:

```shell
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer references the policies `api-key-policy`, `rate-limit-apikey-premium` & `rate-limit-apikey-basic` created in Step 2.

## Test the premium configuration

Let's test the configuration.  If you access the application with an API Key in an expected header at a rate that exceeds 5 requests per second, NGINX will
start rejecting your requests:

```shell
while true; do
  curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP -H "X-header-name: client1premium" http://cafe.example.com:$IC_HTTP_PORT/coffee;
  sleep 0.1;
done
```

```text
Server address: 10.8.1.19:8080
Server name: coffee-dc88fc766-zr7f8

. . .

<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
<hr><center>nginx/1.27.5</center>
</body>
</html>
```

> Note: The command result is truncated for the clarity of the example.

## Test the basic configuration

This test is similar to the previous step, however, this time we will be setting the API Key in the header to a value that maps to the `client1-basic` client name.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```shell
while true; do
  curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP -H "X-header-name: client1basic" http://cafe.example.com:$IC_HTTP_PORT/coffee;
  sleep 0.5;
done
```

```text
Server address: 10.8.1.19:8080
Server name: coffee-dc88fc766-zr7f8

. . .

<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
<hr><center>nginx/1.27.5</center>
</body>
</html>
```

> Note: The command result is truncated for the clarity of the example.

## Test the default configuration

This test is similar to the previous two steps, however, this time we will setting the API Key in the header to a value that maps to the `random` client name, which matches neither of the regex patterns configured in the Policies.  However, we will still be seeing the default `rate-limit-apikey-basic` Policy applied.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```shell
while true; do
  curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP -H "X-header-name: random" http://cafe.example.com:$IC_HTTP_PORT/coffee;
  sleep 0.5;
done
```

```text
Server address: 10.8.1.19:8080
Server name: coffee-dc88fc766-zr7f8

. . .

<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
<hr><center>nginx/1.27.5</center>
</body>
</html>
```

> Note: The command result is truncated for the clarity of the example.
