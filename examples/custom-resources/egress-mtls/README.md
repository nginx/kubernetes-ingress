# Egress MTLS

In this example, we deploy a secure web application, configure load balancing for it via a VirtualServer, and apply an
Egress MTLS policy.

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

## Step 1 - Deploy a Secure Web Application

The application requires clients to use TLS and present a client TLS certificate which it will verify.

Create the application deployment, service and secret:

```console
kubectl apply -f secure-app.yaml
```

## Step 2 - Deploy the Egress MTLS Secret

Create a secret with the name `egress-mtls-secret` that will be used for authentication to application:

```console
kubectl apply -f egress-mtls-secret.yaml
```

## Step 3 - Deploy the Trusted CA Secret

Create a secret with the name `egress-trusted-ca-secret` that will be used to verify the certificate of the application:

```console
kubectl apply -f egress-trusted-ca-secret.yaml
```

## Step 4 - Deploy the Egress MTLS Policy

Create a policy with the name `egress-mtls-policy` that references the secrets from the previous steps:

```console
kubectl apply -f egress-mtls.yaml
```

## Step 5 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `egress-mtls-policy` created in Step 4.

## Step 6 - Test the Configuration

Access the secure backend with the following command:

```console
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
```

```text
hello from pod secure-app-8cb576989-7hdhp
```
