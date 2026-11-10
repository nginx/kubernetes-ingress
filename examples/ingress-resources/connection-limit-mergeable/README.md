# Connection Limit with Mergeable Ingresses

In this example, we deploy the cafe application, configure load balancing for it with
[Mergeable Ingress](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/cross-namespace-configuration/)
resources, and apply connection limit policies with the `nginx.org/policies` annotation:

- The master Ingress references `connection-limit-policy`, which applies to every path of the host.
- The coffee minion references its own policy, `coffee-connection-limit-policy`, which replaces the master policy for
  `/coffee`.
- The tea minion references no policy, so `/tea` uses the master policy.

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

## Step 2 - Deploy the Connection Limit Policies

Create the policies:

```console
kubectl apply -f connection-limit-policy.yaml
kubectl apply -f coffee-connection-limit-policy.yaml
```

- `connection-limit-policy` allows 1 request in progress at a time from a single IP address, and rejects requests over
  the limit with 429.
- `coffee-connection-limit-policy` sets only `connections: 1`. The other fields use their defaults, so it also counts
  requests per client IP address, but rejects requests over the limit with 503.

## Step 3 - Configure Load Balancing

Create the master Ingress and the minion Ingress resources:

```console
kubectl apply -f cafe-ingress-master.yaml
kubectl apply -f tea-minion.yaml
kubectl apply -f coffee-minion.yaml
```

## Step 4 - Test the Configuration

1. Keep one request to `/tea` in progress by uploading a body slowly. This command runs for about 10 seconds:

    ```console
    head -c 100000 /dev/zero | curl --limit-rate 10k --data-binary @- --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
    ```

1. While it runs, send a second request to `/tea` from another terminal. The master policy rejects it with 429:

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

1. While the upload still runs, send a request to `/coffee`. It succeeds, because the coffee policy counts requests to
   `/coffee` separately:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    ```text
    Server address: 10.8.1.20:8080
    Server name: coffee-7586895968-r26zn
    . . .
    ```

1. To see the coffee policy reject a request, repeat steps 1 and 2 with `/coffee` in place of `/tea`. The second
   request gets 503.

> Note: The command results are truncated for the clarity of the example.
