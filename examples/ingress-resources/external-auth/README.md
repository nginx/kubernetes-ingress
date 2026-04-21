# External Authentication

In this example we deploy the cafe application, configure load balancing with an Ingress resource, and protect routes
with external authentication using HTTP Basic Auth via the ExternalAuth Policy.

The basic-auth backend is an NGINX service that validates credentials from an htpasswd file. The Ingress resource
references the ExternalAuth Policy via the `nginx.org/policies` annotation.

## Prerequisites

1. Run `make secrets` command to generate the necessary secrets for the example.
1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller.
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

Create the TLS secret for the Ingress and the TLS secret used by the basic-auth backend:

```console
kubectl apply -f tls-secret.yaml
kubectl apply -f external-auth-server-tls-secret.yaml
```

## Step 3 - Deploy the Basic Auth Backend

Create the htpasswd secret and deploy the basic-auth service:

```console
kubectl apply -f htpasswd-secret.yaml
kubectl apply -f basic-auth.yaml
```

## Step 4 - Deploy the ExternalAuth Policy

Create the ExternalAuth policy that the Ingress resource will reference:

```console
kubectl apply -f basic-auth-policy.yaml
```

## Step 5 - Configure Load Balancing

Create an Ingress resource that references the basic-auth policy via the `nginx.org/policies` annotation:

```console
kubectl apply -f cafe-ingress.yaml
```

## Step 6 - Test the Configuration

1. Send a request without credentials. NGINX will reject it with a `401`:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    <html>
    <head><title>401 Authorization Required</title></head>
    <body>
    <center><h1>401 Authorization Required</h1></center>
    </body>
    </html>
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

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure -u foo:bar
    ```

    ```text
    Server address: 10.244.0.7:8080
    Server name: coffee-7b9b4bbd99-xn7wp
    ...
    ```
