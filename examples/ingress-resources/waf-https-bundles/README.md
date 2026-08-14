# WAF with HTTPS Bundle Source (Ingress)

In this example we deploy the NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and configure WAF protection for an Ingress resource using pre-compiled policy bundles fetched from an HTTPS endpoint.

The HTTPS source type works with any server that can serve a compiled `.tgz` bundle over HTTPS. In this example, we use a self-contained [bundle server](../../shared-examples/waf-bundle-server/) that compiles and serves bundles using the `waf-compiler` image from the F5 private registry.

For VirtualServer equivalents, see [custom-resources/waf-https-bundles](../../custom-resources/waf-https-bundles/).
For sourcing bundles from NGINX Instance Manager or NGINX One Console instead, see [waf-management-plane](../waf-management-plane/).

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with F5 WAF for NGINX v5.

1. An `imagePullSecret` named `regcred` in the `default` namespace with access to
   `private-registry.nginx.com` (required by the bundle server's `waf-compiler` init containers). See [Download NGINX Ingress Controller from the F5 Registry](https://docs.nginx.com/nginx-ingress-controller/install/images/registry-download/).

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

## Step 2 - Generate the TLS Secrets

Run `make secrets` from the repository root to generate the TLS certificates:

```console
make secrets
```

Apply the generated secrets:

```console
kubectl apply -f ../../shared-examples/waf-bundle-server/bundle-server-tls-secret.yaml
kubectl apply -f ../../shared-examples/waf-bundle-server/bundle-server-ca-secret.yaml
kubectl apply -f ../../shared-examples/waf-bundle-server/bundle-client-tls-secret.yaml
```

## Step 3 - Deploy the Bundle Server

```console
kubectl apply -f ../../shared-examples/waf-bundle-server/deployment.yaml
kubectl wait --for=condition=ready pod -l app=bundle-server --timeout=120s
```

See the [bundle server README](../../shared-examples/waf-bundle-server/) for details.

## Step 4 - Deploy the WAF Policy

```console
kubectl apply -f waf-https.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

## Step 5 - Configure Load Balancing

Create the Ingress resource:

```console
kubectl apply -f cafe-ingress.yaml
```

## Step 6 - Test the Application

1. Send a valid request:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP "http://cafe.example.com:$IC_HTTP_PORT/<script>"
    ```

    The suspicious request is blocked by F5 WAF for NGINX.
