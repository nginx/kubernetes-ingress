# OIDC Native Authentication with Ingress Resources

This example demonstrates how to configure OpenID Connect (OIDC) authentication for a web application using standard Kubernetes `Ingress` resources and an `oidcNative` Policy.

Native OIDC leverages NGINX Plus native OIDC functionality introduced in NGINX Plus R32+.

> **Note**: Native OIDC requires NGINX Plus R32+ and NGINX Ingress Controller 5.6.0+.

## Prerequisites

1. An NGINX Ingress Controller instance running NGINX Plus with `-enable-oidc=true` enabled.
2. `make secrets` run to generate required TLS secrets.

## Step 1 - Deploy Core ConfigMap

Deploy the `ConfigMap` resource containing DNS resolver configuration required for OIDC:

```shell
kubectl apply -f nginx-config.yaml
```

## Step 2 - Deploy Keycloak IdP

Deploy Keycloak and its Ingress resource:

```shell
kubectl apply -f keycloak.yaml
kubectl apply -f keycloak-ingress.yaml
```

Wait until Keycloak is ready:

```shell
kubectl rollout status deployment/keycloak
```

## Step 3 - Configure Keycloak

Follow the instructions in [keycloak_setup.md](keycloak_setup.md) to create the `nginx-user` user and `nginx-plus` client registration.

## Step 4 - Deploy the Web Application

Deploy the sample web application:

```shell
kubectl apply -f webapp.yaml
```

## Step 5 - Deploy TLS Secrets

Generate and apply TLS secrets:

```shell
make secrets
kubectl apply -f tls-secret.yaml
kubectl apply -f keycloak-tls-secret.yaml
```

## Step 6 - Deploy Client Secret

Deploy the secret containing the Keycloak client secret:

```shell
kubectl apply -f client-secret.yaml
```

## Step 7 - Deploy the OIDC Native Policy and Ingress Resource

Deploy the policy and the `webapp-ingress` resource (which references the policy via the `nginx.com/policies: "oidcnative-policy"` annotation):

```shell
kubectl apply -f oidc-native-policy.yaml
kubectl apply -f webapp-ingress.yaml
```

## Step 8 - Test the Authentication Flow

1. Open `https://webapp.<EXTERNAL-IP>.nip.io` (or `https://${WEBAPP_HOST}`) in your browser. You are redirected to Keycloak.
2. Log in as `nginx-user` / `test`. ![keycloak](./keycloak.png)
3. You are redirected back to the web application.

## Step 9 - Log Out

1. Navigate to `https://webapp.<EXTERNAL-IP>.nip.io/logout` (or `https://${WEBAPP_HOST}/logout`). Your session is terminated and you land on `/_logout`. ![logout](./logout.png)
2. Visit `https://webapp.<EXTERNAL-IP>.nip.io` again — you are prompted to log in.
