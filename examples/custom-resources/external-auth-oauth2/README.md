# External Authentication with OAuth2

In this example we deploy the cafe application, configure load balancing with a VirtualServer, and apply different
external authentication methods per route:

- `/tea` is protected by **HTTP Basic Auth** using an NGINX service that validates credentials from an htpasswd file.
- `/coffee` is protected by **OAuth2 Proxy** using [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)
  configured with [GitHub OAuth](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).

Each route references its own ExternalAuth Policy in the VirtualServer route configuration. The OAuth2 Policy also
passes the user name and email that oauth2-proxy returns to the coffee backend.

For a simpler example that uses only basic-auth with a spec-level policy, see [external-auth](../external-auth/).

## Prerequisites

1. Run `make secrets` command to generate the necessary secrets for the example.
1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy the Cafe Application

Create the coffee and tea deployments and services:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Deploy Secrets

Create the TLS secrets:

```console
kubectl apply -f tls-secret.yaml
kubectl apply -f external-auth-server-tls-secret.yaml
kubectl apply -f external-auth-ca-secret.yaml
```

## Step 3 - Deploy the Basic Auth Backend

Create the htpasswd secret and deploy the basic-auth service:

```console
kubectl apply -f htpasswd-secret.yaml
kubectl apply -f basic-auth.yaml
```

## Step 4 - Create a GitHub OAuth App

1. Go to **GitHub -> Settings -> Developer settings ->
   [OAuth Apps](https://github.com/settings/developers)** and click **New OAuth App**.
1. Fill in the form:

   | Field | Value |
   | ----- | ----- |
   | **Application name** | `nginx-ingress-demo` (or any name) |
   | **Homepage URL** | `https://cafe.example.com` |
   | **Redirect URI** | `https://cafe.example.com/oauth2/callback` |

1. Click **Register application**.
1. Note the **Client ID** and generate a **client secret**.

## Step 5 - Deploy OAuth2 Proxy

1. Base64-encode your GitHub client secret and update `oauth2-proxy-client-secret.yaml` with the value, then update the
   `OAUTH2_PROXY_CLIENT_ID` environment variable in `oauth2-proxy.yaml` with your client ID:

    ```console
    echo -n '<your-github-client-secret>' | base64
    ```

1. Apply the secret and deploy oauth2-proxy:

    ```console
    kubectl apply -f oauth2-proxy-client-secret.yaml
    kubectl apply -f oauth2-proxy.yaml
    ```

The oauth2-proxy configuration sets `set_xauthrequest = true`, so oauth2-proxy returns the user's details in
`X-Auth-Request-*` headers when it allows a request.

## Step 6 - Deploy the ExternalAuth Policies

Create the ExternalAuth policies that the VirtualServer routes will reference:

```console
kubectl apply -f basic-auth-policy.yaml
kubectl apply -f oauth2-policy.yaml
```

The OAuth2 policy lists `X-Auth-Request-User` and `X-Auth-Request-Email` in `authResponseHeaders`. After oauth2-proxy
allows a request, NGINX passes these headers from its response to the coffee backend. Their values replace any headers
of the same name that the client sends, and a listed header that oauth2-proxy does not return is removed.

## Step 7 - Configure Load Balancing

Create the VirtualServer resource. Each route references its own ExternalAuth policy -- `/tea` is protected by
basic-auth and `/coffee` is protected by OAuth2 Proxy:

```console
kubectl apply -f cafe-virtual-server.yaml
```

## Step 8 - Test the Configuration

### Basic Auth (`/tea`)

1. Send a request without credentials. NGINX will reject it with a `401`:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

1. Send a request with valid credentials (default: `foo` / `bar`):

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure -u foo:bar
    ```

    ```text
    Server address: 10.244.0.6:8080
    Server name: tea-7b9b4bbd99-bdbxm
    ...
    ```

### OAuth2 (`/coffee`)

Open `https://cafe.example.com/coffee` in a browser. You will be redirected to GitHub to authorize the OAuth App. After
granting access, GitHub redirects you back and the page loads normally.

> **Note:** The OAuth2 flow requires browser interaction. Use a browser for the initial login. Once authenticated, the
> `_oauth2_proxy` cookie allows subsequent requests, including `curl`, to pass through.

The coffee backend does not print request headers. To check that NGINX passes the user and email to it, look for the
directives that the OAuth2 policy adds to the configuration:

```console
kubectl exec <nginx-ingress-pod> -n nginx-ingress -- grep auth_resp_ /etc/nginx/conf.d/vs_default_cafe.conf
```

```text
auth_request_set $auth_resp_x_auth_request_user $upstream_http_x_auth_request_user;
proxy_set_header X-Auth-Request-User $auth_resp_x_auth_request_user;
auth_request_set $auth_resp_x_auth_request_email $upstream_http_x_auth_request_email;
proxy_set_header X-Auth-Request-Email $auth_resp_x_auth_request_email;
```
