# WAF with Management Plane Bundle Sources (Ingress)

In this example we deploy the NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and configure WAF protection for an Ingress resource using pre-compiled policy bundles sourced from a management plane API — either [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager/) (NIM) or [NGINX One Console](https://docs.nginx.com/nginx-one-console/) (N1C).

For VirtualServer equivalents, see [custom-resources/waf-management-plane](../../custom-resources/waf-management-plane/).
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

Create the application deployments and services:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Create the Credentials Secret

For NIM, create a secret with a bearer token:

```console
kubectl create secret generic nim-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=token=<YOUR_NIM_TOKEN>
```

For N1C, create a secret with an API token:

```console
kubectl create secret generic n1c-credentials \
  --type=nginx.com/waf-bundle \
  --from-literal=token=<YOUR_N1C_API_TOKEN>
```

## Step 3 - Deploy the WAF Policy

To use NIM, edit `waf-nim.yaml` with your NIM details, then:

```console
kubectl apply -f waf-nim.yaml
```

To use N1C instead, edit `waf-n1c.yaml` with your N1C details, then:

```console
kubectl apply -f waf-n1c.yaml
```

Verify the policy status:

```console
kubectl describe policy waf-policy
```

## Step 4 - Configure Load Balancing

Create the Ingress resource:

```console
kubectl apply -f cafe-ingress.yaml
```

## Step 5 - Test the Application

1. Send a valid request:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP "http://cafe.example.com:$IC_HTTP_PORT/<script>"
    ```

    The suspicious request is blocked by F5 WAF for NGINX.
