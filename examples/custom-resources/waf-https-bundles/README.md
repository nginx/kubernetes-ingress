# WAF with HTTPS Bundle Source

In this example we deploy the NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and configure WAF protection using pre-compiled policy bundles fetched from an HTTPS endpoint.

The HTTPS source type works with any server that can serve a compiled `.tgz` bundle over HTTPS — for example, an artifact repository, a CI/CD pipeline output, or any static file server. In this example, we use a self-contained [bundle server](../../shared-examples/waf-bundle-server/) that compiles and serves bundles using the `waf-compiler` image from the F5 private registry.

For sourcing bundles from NGINX Instance Manager or NGINX One Console instead, see [waf-management-plane](../waf-management-plane/).

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with F5 WAF for NGINX v5.

1. An `imagePullSecret` named `regcred` in the `default` namespace with access to
   `private-registry.nginx.com` (required by the bundle server's `waf-compiler` init containers). This is the same secret used
   for NIC. See [Download NGINX Ingress Controller from the F5 Registry](https://docs.nginx.com/nginx-ingress-controller/install/images/registry-download/).

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1. Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 2 - Generate the TLS Secrets

Run `make secrets` from the repository root to generate the TLS certificates used by the bundle server and NIC:

```console
make secrets
```

This creates:

- `bundle-server-tls` — server certificate for the bundle server HTTPS endpoint
- `bundle-server-ca` — CA certificate for server verification
- `bundle-client-tls` — client certificate for mTLS authentication

Apply the generated secrets:

```console
kubectl apply -f ../../shared-examples/waf-bundle-server/bundle-server-tls-secret.yaml
kubectl apply -f ../../shared-examples/waf-bundle-server/bundle-server-ca-secret.yaml
kubectl apply -f ../../shared-examples/waf-bundle-server/bundle-client-tls-secret.yaml
```

## Step 3 - Deploy the Bundle Server

The bundle server compiles WAF policy and log profile JSON definitions into `.tgz` bundles at startup using `waf-compiler` init containers, then serves them over HTTPS with mTLS:

```console
kubectl apply -f ../../shared-examples/waf-bundle-server/deployment.yaml
```

Wait for the bundle server pod to be ready (init containers compile the bundles first):

```console
kubectl wait --for=condition=ready pod -l app=bundle-server --timeout=120s
```

The compiled bundles are available at:

- `https://bundle-server.default.svc.cluster.local/bundles/attack-signatures-blocking.tgz`
- `https://bundle-server.default.svc.cluster.local/bundles/log-default.tgz`

See the [bundle server README](../../shared-examples/waf-bundle-server/) for details on customizing policies.

## Step 4 - Deploy the WAF Policy

Create the WAF policy that fetches bundles from the HTTPS bundle server:

```console
kubectl apply -f waf-https.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

The policy should show `State: Valid` once the bundle has been fetched and applied. If the bundle server is unreachable, the status will be `Warning` with reason `BundleFetchFailed`. NIC retries on the next poll interval.

## Step 5 - Configure Load Balancing

Create the VirtualServer resource:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `waf-policy` created in Step 4.

## Step 6 - Test the Application

1. Send a valid request to the application:

    ```console
    curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: webapp-7586895968-r26zn
    ...
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP "http://webapp.example.com:$IC_HTTP_PORT/<script>"
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    The suspicious request is blocked by F5 WAF for NGINX.

## Automatic Policy Updates (Polling)

This example has `enablePolling: true` with `pollInterval: "5m"`. NIC uses HTTP conditional requests (`ETag` / `If-Modified-Since`) to efficiently detect changes — if the bundle has not changed on the server, a `304 Not Modified` response is returned and no data is transferred.

To disable automatic updates, set `enablePolling: false`. The bundle is fetched once when the Policy is created; subsequent updates require editing the Policy resource to trigger a new fetch.

## Using Your Own HTTPS Endpoint

The bundle server in this example is provided for testing and development. In production, you would typically host compiled bundles on your own HTTPS infrastructure — for example:

- An artifact repository (Artifactory, Nexus)
- An S3-compatible object store (AWS S3, GCS, MinIO)
- A CI/CD pipeline that publishes compiled bundles to a static file server
- Any HTTPS server that serves `.tgz` files

To use your own endpoint, edit `waf-https.yaml` and replace the `url` with your bundle URL. Adjust the `secret` reference for your authentication method (client mTLS, bearer token, or basic auth).
