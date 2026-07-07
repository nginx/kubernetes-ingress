# WAF with Management Plane Bundle Sources

In this example we deploy the NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and configure WAF protection using pre-compiled policy bundles sourced from a management plane API — either [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager/) (NIM) or [NGINX One Console](https://docs.nginx.com/nginx-one-console/) (N1C).

This decouples policy authoring (SecOps) from policy application (platform teams). SecOps authors and compiles policies in the management plane; platform teams reference the API endpoint in a Kubernetes Policy resource. NIC automatically fetches the compiled bundles — no manual compilation or file copying is required.

For sourcing bundles from an HTTPS endpoint instead, see [waf-https-bundles](../waf-https-bundles/).

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with F5 WAF for NGINX v5.

1. A compiled WAF policy available on your management plane:
   - **NIM**: see [Create a security policy bundle](https://docs.nginx.com/nginx-instance-manager/waf-integration/policies-and-logs/bundles/create-bundle/)
   - **N1C**: see [Manage policies](https://docs.nginx.com/nginx-one-console/waf-integration/policy/)

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

## Step 2 - Create the Credentials Secret

NIC authenticates with the management plane using a Kubernetes Secret of type `nginx.com/waf-bundle`.

For NIM, create a secret with a bearer token:

```console
kubectl create secret generic nim-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=token=<YOUR_NIM_TOKEN>
```

NIM also supports basic auth. To use username and password instead:

```console
kubectl create secret generic nim-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=username=<YOUR_USERNAME> \
  --from-literal=password=<YOUR_PASSWORD>
```

For N1C, create a secret with an API token.

Generate an API token from the [F5 Distributed Cloud Console](https://console.ves.volterra.io) under **Account Settings > Credentials > Add Credentials > API Token**. See [Managing User Credentials](https://docs.cloud.f5.com/docs/how-to/user-mgmt/credentials) for details.

```console
kubectl create secret generic n1c-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=token=<YOUR_N1C_API_TOKEN>
```

## Step 3 - Deploy the WAF Policy

Choose the WAF policy that matches your management plane.

### Option A: NGINX Instance Manager (NIM)

Edit `waf-nim.yaml` and replace the placeholder values:

- `<nim_host>` — your NIM server hostname or IP
- `<policy_name>` — the name of the compiled policy in NIM
- `<log_profile_name>` — the name of the log profile in NIM

```console
kubectl apply -f waf-nim.yaml
```

### Option B: NGINX One Console (N1C)

Edit `waf-n1c.yaml` and replace the placeholder values:

- `<tenant>` — your N1C tenant hostname (e.g., `my-tenant.console.ves.volterra.io`)
- `<policy_name>` — the name of the policy in your N1C namespace

```console
kubectl apply -f waf-n1c.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

The policy should show `State: Valid` once the bundle has been fetched and applied. If the management plane is unreachable, the status will be `Warning` with reason `BundleFetchFailed`. NIC retries on the next poll interval.

## Step 4 - Configure Load Balancing

Create the VirtualServer resource:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `waf-policy` created in Step 3.

## Step 5 - Test the Application

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

Both examples have `enablePolling: true` with `pollInterval: "5m"`. NIC periodically checks the management plane for updated policy bundles and applies them automatically — no changes to the Kubernetes Policy resource are needed.

- **NIM**: NIC fetches only metadata on each poll cycle. The full bundle is downloaded only when the metadata hash changes, avoiding unnecessary data transfer.
- **N1C**: NIC checks the compile status hash before downloading. If the bundle has not changed, no download occurs.

To disable automatic updates, set `enablePolling: false`. The bundle is fetched once when the Policy is created; subsequent updates require editing the Policy resource to trigger a new fetch.
