# Tiered Rate Limits with Request Methods

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply two rate
limit Policies, grouped in a tier, using the client IP address as the key to the rate limit and using a regex of HTTP Request Methods to determine which rate limit Policy is applied.  One rate limit policy will be the default ratelimit for the group.

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

- one with the name `rate-limit-request-method-get-head`, that allows 5 requests per second coming from a request containing the `GET` or `HEAD` request methods.
- one with the name `rate-limit-request-method-put-post-patch-delete` that allows 1 request per second coming from a request containing the `POST`, `PUT`, `PATCH` or `DELETE` request methods.

The `rate-limit-request-method-put-post-patch-delete` Policy is also the default policy if the request method does not match a tier.

Create the policies:

```console
kubectl apply -f rate-limits.yaml
```

## Step 3 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer references the policies `rate-limit-request-method-get-head` & `rate-limit-request-method-put-post-patch-delete` created in Step 2.

## Step 4 - Test the Configuration

Let's test the configuration.  If you access the application at a rate that exceeds 5 requests per second with a `GET` request method, NGINX will
start rejecting your requests:

```console
while true; do
  curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee";
  sleep 0.1
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

## Step 5 - Test the Request types that update a resource

This test is similar to Step 4, however, this time we will be using the `POST` request method.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```console
while true; do 
  curl -XPOST --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee; 
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

## Step 6 - Test the default Configuration

This test is similar to Step 4 & 5, however, this time we will not be using a configured request method, however we
will still be seeing the default `rate-limit-request-method-put-post-patch-delete` Policy applied.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```console
while true; do 
  curl -XOPTIONS --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee; 
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
