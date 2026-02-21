# External Authentication with Advanced Routing

In this example we deploy a web application with advanced routing rules and protect all routes using an ExternalAuth
policy backed by HTTP Basic Authentication. This combines the concepts from the
[external-auth](../external-auth/) and [advanced-routing](../advanced-routing/) examples — without the OAuth2 Proxy
component.

The routing configuration is:

- **`/tea`** — POST requests are routed to `tea-post-svc`; all other requests (e.g. GET) go to `tea-svc`.
- **`/coffee`** — Requests with the cookie `version=v2` are routed to `coffee-v2-svc`; all other requests go to
  `coffee-v1-svc`.

Both routes are protected by an ExternalAuth policy that delegates authentication to an NGINX basic-auth backend.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy NGINX Ingress Controller with custom resources enabled.
2. Generate the required secrets by running from the root of the repository:

    ```shell
    make secrets
    ```

3. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

4. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy TLS Secret

Apply the TLS secret for the cafe application:

```shell
kubectl apply -f tls-secret.yaml
```

## Step 2 - Deploy the Cafe Application

Deploy the four backend services (tea, tea-post, coffee-v1, coffee-v2):

```shell
kubectl apply -f cafe.yaml
```

## Step 3 - Deploy the Basic Auth Backend

Deploy the htpasswd secret and the NGINX basic-auth service:

```shell
kubectl apply -f htpasswd-secret.yaml
kubectl apply -f basic-auth.yaml
```

## Step 4 - Deploy the ExternalAuth Policy

Create the ExternalAuth policy that points to the basic-auth service:

```shell
kubectl apply -f external-auth-basic.yaml
```

## Step 5 - Deploy the VirtualServer

Deploy the VirtualServer that combines external authentication with advanced routing:

```shell
kubectl apply -f cafe-virtual-server.yaml
```

## Step 6 - Test the Configuration

1. Check that the configuration has been applied:

    ```shell
    kubectl describe virtualserver cafe
    ```

    ```text
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  2s    nginx-ingress-controller  Configuration for default/cafe was added or updated
    ```

2. Test the `/tea` route with basic-auth credentials (`foo` / `bar`):

    Send a POST request and confirm the response comes from `tea-post-svc`:

    ```shell
    curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -u foo:bar https://cafe.example.com:$IC_HTTPS_PORT/tea -X POST
    ```

    ```text
    Server address: 10.16.1.188:80
    Server name: tea-post-b5dd479b4-6ssmh
    . . .
    ```

    Send a GET request and confirm the response comes from `tea-svc`:

    ```shell
    curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -u foo:bar https://cafe.example.com:$IC_HTTPS_PORT/tea
    ```

    ```text
    Server address: 10.16.1.189:80
    Server name: tea-7d57856c44-2hsvr
    . . .
    ```

    Verify that requests without credentials are rejected:

    ```shell
    curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea
    ```

    ```text
    <html>
    <head><title>401 Authorization Required</title></head>
    . . .
    ```

3. Test the `/coffee` route:

    Send a request with the cookie `version=v2` and confirm the response comes from `coffee-v2-svc`:

    ```shell
    curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -u foo:bar https://cafe.example.com:$IC_HTTPS_PORT/coffee --cookie "version=v2"
    ```

    ```text
    Server address: 10.16.1.187:80
    Server name: coffee-v2-7fd446968b-vkthp
    . . .
    ```

    Send a request without the cookie and confirm the response comes from `coffee-v1-svc`:

    ```shell
    curl -k --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -u foo:bar https://cafe.example.com:$IC_HTTPS_PORT/coffee
    ```

    ```text
    Server address: 10.16.0.153:80
    Server name: coffee-v1-78754bdcfb-bs9nh
    . . .
    ```
