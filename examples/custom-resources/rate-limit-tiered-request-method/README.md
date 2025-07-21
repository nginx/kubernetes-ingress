# Tiered Rate Limits with Request Methods

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply two rate
limit Policies, grouped in a tier, using the client IP address as the key to the rate limit and using a regex of HTTP Request Methods to determine which rate limit Policy is applied.  One rate limit policy will be the default ratelimit for the group.

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

In this step, we create two Policies:

- `rate-limit-request-method-get-head`, that allows 5 requests per second coming from a request containing the `GET` or `HEAD` request methods.
- `rate-limit-request-method-put-post-patch-delete` that allows 1 request per second coming from a request containing the `POST`, `PUT`, `PATCH` or `DELETE` request methods.

The `rate-limit-request-method-put-post-patch-delete` Policy is also the default Policy if the request method does not match a tier.

Create the Policies:

```shell
kubectl apply -f rate-limits.yaml
```

## Configure load balancing

Create a VirtualServer resource for the web application:

```shell
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer references the policies `rate-limit-request-method-get-head` & `rate-limit-request-method-put-post-patch-delete` created in Step 2.

## Test the configuration

Let's test the configuration.  If you access the application at a rate that exceeds 5 requests per second with a `GET` request method, NGINX will
start rejecting your requests:

```shell
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

## Test the request types that update a resource

This test is similar to previous step, however, this time we will be using the `POST` request method.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```shell
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

## Test the default configuration

This test is similar to the previous two steps, however, this time we will not be using a configured request method, however we
will still be seeing the default `rate-limit-request-method-put-post-patch-delete` Policy applied.

Let's test the configuration.  If you access the application at a rate that exceeds 1 request per second, NGINX will
start rejecting your requests:

```shell
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
