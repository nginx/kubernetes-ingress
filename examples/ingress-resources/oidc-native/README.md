# OIDC Native

In this example, we deploy a web application, load-balance it via an Ingress resource, and protect it using the NGINX Plus native `ngx_http_oidc_module` (`oidcNative` policy) and [Keycloak](https://www.keycloak.org/).

**Note**: The Keycloak container does not support IPv6 environments.

## Prerequisites

1. Run `make secrets` to generate the TLS secrets for the example.
2. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests) instructions to deploy NGINX Ingress Controller with `-enable-oidc`. The HTTPS port of the Ingress Controller must be `443`.
3. Save the public IP address of the Ingress Controller into `/etc/hosts` of your machine:

    ```text
    ...

    XXX.YYY.ZZZ.III webapp.example.com
    XXX.YYY.ZZZ.III keycloak.example.com
    ```

## Step 1 - Deploy TLS Secrets

Create the TLS secrets used for TLS termination of the web application and Keycloak, as well as the trusted CA secret used for verifying Keycloak's TLS certificate:

```shell
kubectl apply -f tls-secret.yaml
kubectl apply -f keycloak-tls-secret.yaml
kubectl apply -f keycloak-ca-secret.yaml
```

## Step 2 - Deploy Resolver ConfigMap

Apply the ConfigMap `nginx-config.yaml` to configure the NGINX DNS resolver so the native OIDC module can resolve the IdP issuer hostname:

```shell
kubectl apply -f nginx-config.yaml
```

## Step 3 - Deploy Keycloak and the Web Application

Create Keycloak, its Ingress, and the web application deployment:

```shell
kubectl apply -f keycloak.yaml
kubectl apply -f keycloak-ingress.yaml
kubectl apply -f webapp.yaml
```

The shipped TLS secrets are self-signed, so your browser will show a certificate warning when visiting either page - accept it once per hostname. Backchannel communication (NGINX ↔ Keycloak) is verified via the trusted CA certificate in `keycloak-ca-secret.yaml` (`sslVerify: true` in the policy).

## Step 4 - Configure Keycloak

Configure the Keycloak realm, client, and test user. You can complete this step automatically via the Keycloak API or manually using the Web Admin Console:

### Option A: Automated API Setup (Recommended)

Follow [`keycloak_setup.md`](./keycloak_setup.md) to create the `nginx-plus` client and `nginx-user` account via `curl` commands.

### Option B: Manual Web Admin Console Setup

1. Navigate to the Keycloak Admin Console at `https://keycloak.example.com`, accept the self-signed TLS certificate warning, and sign in with **`admin` / `admin`**.
2. Create an OIDC client named `nginx-plus` with the following configuration:
   - **Client authentication**: On
   - **Valid redirect URIs**: `https://webapp.example.com/*`
   - **Valid post logout redirect URIs**: `https://webapp.example.com/_logout`
3. Create a test user named `nginx-user` with password `test`.
4. Copy the client secret from the **Credentials** tab for use in Step 5.

## Step 5 - Deploy the Client Secret

**Note**: If you're using PKCE, skip this step and remove `clientSecret: oidcnative-secret` from `oidc-native-policy.yaml`. PKCE clients do not have client secrets. Applying the secret or leaving `clientSecret` configured without a secret will result in missing secret errors.

1. Encode the secret obtained in Step 5:

    ```shell
    echo -n $SECRET | base64
    ```

2. Edit `client-secret.yaml`, replacing `<insert-secret-here>` with the base64-encoded secret.

3. Deploy the secret:

    ```shell
    kubectl apply -f client-secret.yaml
    ```

## Step 6 - Deploy the OIDC Native Policy and Ingress Resource

Deploy the policy and the `webapp-ingress` resource (which references the policy via the `nginx.com/policies: "oidcnative-policy"` annotation):

```shell
kubectl apply -f oidc-native-policy.yaml
kubectl apply -f webapp-ingress.yaml
```

## Step 7 - Test the Authentication Flow

1. Open `https://webapp.example.com` in your browser. You are redirected to Keycloak.
2. Log in as `nginx-user` / `test`. ![keycloak](./keycloak.png)
3. You are redirected back to the web application.

## Step 8 - Log Out

1. Navigate to `https://webapp.example.com/logout`. Your session is terminated and you land on `/_logout`. ![logout](./logout.png)
2. Visit `https://webapp.example.com` again — you are prompted to log in.

## How it Differs from the NJS OIDC Example

| Feature | NJS OIDC (`spec.oidc`) | Native OIDC (`spec.oidcNative`) |
| --- | --- | --- |
| Implementation | JavaScript (njs) | Native C module |
| Endpoints | Explicit (auth, token, jwks) | Auto-discovered from issuer metadata |
| Session storage | Explicit keyval zones | Managed by the module |
| Multiple providers per Ingress | No | Yes (per location) |
| PKCE | Manual toggle | Configurable per policy |
| Callback URI | `/_codexch` | `/oidc_callback_<provider-name>` (default) |
