# Connection Limit

In this example, we deploy the cafe application, configure load balancing for it via an Ingress resource, and apply a
connection limit policy with the `nginx.org/policies` annotation.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1 - Deploy the Cafe Application

Create the coffee and tea deployments and services:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Deploy the Connection Limit Policy

In this step, we create a policy with the name `connection-limit-policy` that allows only 1 request in progress at a
time from a single IP address. The policy sets every field:

- `connections`: the maximum number of requests in progress at the same time for each value of the key.
- `key`: `${binary_remote_addr}` gives each client IP address its own counter.
- `zoneSize`: the size of the shared memory zone that stores the counters.
- `rejectCode`: the status code returned for rejected requests, 429 instead of the default 503.
- `logLevel`: the level at which rejected requests are logged.
- `dryRun`: when `true`, requests over the limit are logged but not rejected.
- `scale`: when `true`, `connections` is divided by the number of NGINX Ingress Controller replicas.

Create the policy:

```console
kubectl apply -f connection-limit-policy.yaml
```

## Step 3 - Configure Load Balancing

Create an Ingress resource for the cafe application:

```console
kubectl apply -f cafe-ingress.yaml
```

Note that the Ingress references the policy `connection-limit-policy` created in Step 2 with the `nginx.org/policies`
annotation. The policy applies to every path of the Ingress, and the paths share the limit.

## Step 4 - Test the Configuration

Let's test the configuration. Keep one request to `/coffee` in progress by uploading a body slowly. This command runs
for about 100 seconds:

```console
head -c 100000 /dev/zero | curl --limit-rate 1k --data-binary @- --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
```

While it runs, send a request to `/tea` from another terminal. NGINX rejects it, because the paths share the limit:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

```text
<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
</body>
</html>
```

When the upload finishes, the request succeeds:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
```

```text
Server address: 10.8.1.19:8080
Server name: tea-7cd44fcb4d-xfw2x
. . .
```

> Note: The command result is truncated for the clarity of the example.
