# WAF with Remote Bundle Sources

In this example we deploy the NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/),
a simple web application, and then configure WAF protection using pre-compiled policy bundles
fetched from a remote source via `apBundleSource`.

For the VirtualServer equivalent, see [custom-resources/app-protect-waf-v5-bundle-source](../../custom-resources/app-protect-waf-v5-bundle-source/).

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with F5 WAF for NGINX v5.

1. Run `make secrets` command to generate the necessary secrets for the example.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1. Deploy a Web Application

Create the application deployments and services:

```console
kubectl apply -f cafe.yaml
```

## Step 2. Create the Credentials Secret and WAF Policy

Choose one of the following options based on your bundle source.

### Option A - NGINX One Console (N1C)

Generate an API token from the [F5 Distributed Cloud Console](https://console.ves.volterra.io)
under **Account Settings > Credentials > Add Credentials > API Token**.
See [NGINX One Console API Authentication](https://docs.nginx.com/nginx-one-console/api/authentication/) for details.

Create the credentials secret:

```console
kubectl create secret generic n1c-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=token=<Your API Token>
```

> This is separate from the `dataplane-key` secret used by the NGINX Agent for Console visibility.

Edit `waf-n1c.yaml` and replace `<tenant>` and `<policy_name>` with your values, then apply:

```console
kubectl apply -f waf-n1c.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

The policy should show `State: Valid`. If the bundle is still being fetched or the source is
unreachable, the status will be `Warning` with reason `BundleFetchFailed`.

### Option B - HTTPS Bundle Server

Follow the [WAF Bundle Server](../../shared-examples/waf-bundle-server/) README to deploy
a bundle server that compiles and serves WAF policy bundles over HTTPS.

Then apply the WAF policy:

```console
kubectl apply -f waf-https.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

The policy should show `State: Valid`.

### Option C - NGINX Instance Manager (NIM)

> **Note**: The NIM policy and log profile referenced by `policyName` must be compiled before applying `waf-nim.yaml`. If no compiled bundle exists, the Policy status will show `BundleFetchFailed`.

Create the credentials secret with a bearer token:

```console
kubectl create secret generic nim-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=token=<Your NIM Token>
```

Or with username and password:

```console
kubectl create secret generic nim-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=username=<NIM Username> \
  --from-literal=password=<NIM Password>
```

If your NIM instance uses a self-signed or private CA certificate, configure TLS trust in
`waf-nim.yaml` using one of the following options:

- **Recommended** — provide a CA secret of type `nginx.org/ca` containing `ca.crt`:

  ```yaml
  apBundleSource:
    trustedCertSecret: nim-ca
  ```

- **Lab/testing only** — skip certificate verification (not for production):

  ```yaml
  apBundleSource:
    insecureSkipVerify: true
  ```

Edit `waf-nim.yaml` and replace `<nim_host>`, `<policy_name>`, and `<log_profile_name>` with
your values, then apply:

```console
kubectl apply -f waf-nim.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

The policy should show `State: Valid`.

## Step 3. Configure Load Balancing

Create the Ingress resource:

```console
kubectl apply -f cafe-ingress.yaml
```

Note that the Ingress references the policy `waf-policy` created in Step 2 via the
`nginx.com/policies` annotation.

## Step 4. Test the Application

1. Send a request to the application:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: tea-7586895968-r26zn
    ...
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP "http://cafe.example.com:$IC_HTTP_PORT/tea?x=<script>"
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    The suspicious request is blocked by F5 WAF for NGINX.
