# WAF with Remote Bundle Sources

In this example we deploy the NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/),
a simple web application, and then configure WAF protection using pre-compiled policy bundles
fetched from a remote source via `apBundleSource`.

For the Ingress equivalent, see [ingress-resources/app-protect-waf-v5-bundle-source](../../ingress-resources/app-protect-waf-v5-bundle-source/).

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

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
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

NIM support is not yet implemented. See `waf-n1c.yaml` for a reference of the expected format.

## Step 3. Configure Load Balancing

Create the VirtualServer resource:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `waf-policy` created in Step 2.

Verify the VirtualServer status:

```console
kubectl describe vs webapp
```

The VirtualServer should show `State: Valid`.

## Step 4. Test the Application

1. Send a request to the application:

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
