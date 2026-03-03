# Access Control Policy

In this example we deploy the NGINX Ingress Controller, a simple web application and then configure load balancing with
an Access Control policy that restricts access based on client IP address. We first apply an **allow** policy, then
update it to a **deny** policy.

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

Create the coffee and the tea deployments and services:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Configure NGINX to use the X-Real-IP header

Apply the ConfigMap to configure NGINX to trust the `X-Real-IP` header, so the access control policy is enforced
based on the client IP provided in that header:

```console
kubectl apply -f nginx-config.yaml
```

## Step 3 - Deploy the Allow Policy and Ingress

1. Create the Access Control policy that **allows** traffic from the `10.0.0.0/8` CIDR range:

    ```console
    kubectl apply -f access-control-policy-allow.yaml
    ```

2. Create the Ingress resource that references the policy:

    ```console
    kubectl apply -f cafe-ingress.yaml
    ```

    The Ingress resource references the `webapp-policy` via the `nginx.org/policies` annotation.

## Step 4 - Test the Allow Policy

1. Send a request with an IP in the allowed `10.0.0.0/8` range using the `X-Real-IP` header:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure -H "X-Real-IP: 10.0.0.1"
    ```

    The request succeeds because `10.0.0.1` is in the allowed range:

    ```text
    Server address: 10.244.0.6:8080
    Server name: coffee-7586895968-r26zn
    ...
    ```

2. Now send a request with an IP **outside** the allowed range:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure -H "X-Real-IP: 192.168.1.1"
    ```

    NGINX rejects the request with a `403 Forbidden`:

    ```text
    <html>
    <head><title>403 Forbidden</title></head>
    <body>
    <center><h1>403 Forbidden</h1></center>
    </body>
    </html>
    ```

## Step 5 - Update to the Deny Policy

1. Update the policy to **deny** traffic from the `10.0.0.0/8` CIDR range instead:

    ```console
    kubectl apply -f access-control-policy-deny.yaml
    ```

    This replaces the allow list with a deny list using the same policy name (`webapp-policy`), so the Ingress resource
    picks up the change automatically.

2. Send a request with an IP in the now-denied `10.0.0.0/8` range:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure -H "X-Real-IP: 10.0.0.1"
    ```

    The same IP that was previously allowed is now rejected:

    ```text
    <html>
    <head><title>403 Forbidden</title></head>
    <body>
    <center><h1>403 Forbidden</h1></center>
    </body>
    </html>
    ```

3. Send a request with an IP **outside** the denied range:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure -H "X-Real-IP: 192.168.1.1"
    ```

    Clients outside the denied range are now allowed through:

    ```text
    Server address: 10.244.0.6:8080
    Server name: coffee-7586895968-r26zn
    ...
    ```
