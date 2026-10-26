# Connection Limit

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply a
connection limit policy.

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

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
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
kubectl apply -f connection-limit.yaml
```

## Step 3 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `connection-limit-policy` created in Step 2.

## Step 4 - Test the Configuration

Let's test the configuration. Keep one request in progress by uploading a body slowly. This command runs for about
10 seconds:

```console
head -c 100000 /dev/zero | curl --limit-rate 10k --data-binary @- --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
```

While it runs, send a second request from another terminal. NGINX rejects it:

```console
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
```

```text
<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
</body>
</html>
```

When the upload finishes, the second request succeeds:

```console
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
```

```text
Server address: 10.8.1.19:8080
Server name: webapp-dc88fc766-zr7f8
. . .
```

> Note: The command result is truncated for the clarity of the example.
