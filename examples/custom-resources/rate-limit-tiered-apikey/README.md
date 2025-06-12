# Tiered Rate Limits with API Keys

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply two rate
limit Policies, grouped in a tier, using the API Key client name as the key to the rate limit and using a regex of the client name to determine which rate limit Policy is applied.  One rate limit policy will be the default ratelimit for the group.

> Note: This example makes use of the NGINX variables `$apikey_auth_token` & `apikey_client_name` which are made available by applying an API Key authentication Policy to your VirtualServer resource.

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
- one with the name `rate-limit-apikey-premium`, that allows 5 requests per second coming from a request containing an API Key with a client name that ends with `premium`
- one with the name `rate-limit-apikey-basic` that allows 1 request per second coming from a request containing an API Key with a client name that ends with `basic`

The `rate-limit-apikey-basic` Policy is also the default policy if the API Key client name does not match a tier.

Create the policies:

```console
kubectl apply -f api-key-policy.yaml
kubectl apply -f rate-limits.yaml
```

## Step 3 - Deploy the API Key Auth Secret

Create a secret of type `nginx.org/apikey` with the name `api-key-client-secret` that will be used for authorization on the server level.

This secret will contain a mapping of client names to base64 encoded API Keys.

```console
kubectl apply -f api-key-secret.yaml
```

## Step 4 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer references the policies `api-key-policy`, `rate-limit-apikey-premium` & `rate-limit-apikey-basic` created in Step 2.

## Step 5 - Test the Premium Configuration

Let's test the configuration.  If you access the application with an API Key in an expected header at a rate that exceeds 5 requests per second, NGINX will
start rejecting your requests:

```console
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

## Step 6 - Test the Basic Configuration

This test is similar to Step 5, however, this time we will be setting the API Key in the header to a value that maps to the `client1-basic` client name.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```console
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

## Step 7 - Test the default Configuration

This test is similar to Step 5 & 6, however, this time we will setting the API Key in the header to a value that maps to the `random` client name, which matches neither of the regex patterns configured in the Policies.  However, we will still be seeing the default `rate-limit-apikey-basic` Policy applied.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```console
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
