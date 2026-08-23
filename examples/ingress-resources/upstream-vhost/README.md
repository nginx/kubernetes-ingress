# Upstream Vhost

In this example we deploy a custom backend that returns the `Host` header it
receives and demonstrate the `nginx.org/upstream-vhost` Ingress annotation.

This annotation maps to NGINX's `proxy_set_header` directive, which sets the
`Host` header sent to an upstream application.

## Running the Example

### 1. Deploy the Ingress Controller

1. Run `make secrets` command to generate the necessary secrets for the example.

2. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy NGINX Ingress Controller.

3. Save its public IP address and HTTPS port in shell variables:

```console
IC_IP=XXX.YYY.ZZZ.III
IC_HTTPS_PORT=<port number>
```

### 2. Deploy the Backend

The backend returns the `Host` header it receives, making the annotation's
effect visible in the response.

1. Create the backend deployment and Service:

    ```console
    kubectl create -f cafe.yaml
    ```

### 3. Configure the Upstream Host Header

1. Create a secret with an SSL certificate and a key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

2. Create an Ingress resource:

    ```console
    kubectl create -f cafe-ingress.yaml
    ```

### 4. Test the Application

1. To access the coffee Service:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Host: example.internal
    ```

    The client sends a request to `cafe.example.com`, while the upstream receives `example.internal`.

The client uses `cafe.example.com`, while the upstream application receives
`example.internal`.
