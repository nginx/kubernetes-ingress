# HSTS Policy

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply a HSTS policy to enable HTTP Strict Transport Security for the application host.

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

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 2 - Deploy the HSTS Policy

Create a HSTS policy:

```console
kubectl apply -f hsts-policy.yaml
```

## Step 3 - Configure Load Balancing and TLS Termination

1. Create the secret with the TLS certificate and key:

    ```console
    kubectl apply -f tls-secret.yaml
    ```

1. Create a VirtualServer resource for the web application:

    ```console
    kubectl apply -f virtual-server.yaml
    ```

Note that the VirtualServer references the policy `hsts-policy` created in Step 2.

## Step 4 - Test the Configuration

Send an HTTPS request to the application:

```console
curl --insecure --resolve webapp.example.com:$IC_HTTPS_PORT:$IC_IP \
   https://webapp.example.com:$IC_HTTPS_PORT/ -v
```

You should see the `Strict-Transport-Security` header in the response:

```text
< Strict-Transport-Security: max-age=2592000; includeSubDomains
```

Send a plain HTTP request to confirm the header is not sent over unencrypted connections:

```console
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
   http://webapp.example.com:$IC_HTTP_PORT/ -v
```

The `Strict-Transport-Security` header should be absent from the response.

## Step 5 - Removing the HSTS Policy

HSTS instructs browsers to enforce HTTPS for the duration of `maxAge`. Follow this sequence to safely remove the policy.

1. Update the policy and set `maxAge` to 0 to instruct browsers to immediately expire the HSTS policy:

   ```console
      kubectl apply -f hsts-policy.yaml
   ```

   Send a request to confirm:

   ```console
   curl --insecure --resolve webapp.example.com:$IC_HTTPS_PORT:$IC_IP \
   https://webapp.example.com:$IC_HTTPS_PORT/ -v
   ```

   You should see:

   ```text
   < Strict-Transport-Security: max-age=0; includeSubDomains
   ```

1. Edit virtual-server.yaml to remove the policies entry, then apply:

   ```console
   kubectl apply -f virtual-server.yaml
   ```

1. Delete the HSTS policy:

   ```console
   kubectl delete -f hsts-policy.yaml
   ```
