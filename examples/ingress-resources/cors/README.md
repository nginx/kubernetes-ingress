# CORS Policy

In this example, we deploy the cafe application, attach CORS policies to Ingress resources using the `nginx.org/policies` annotation, and verify preflight and actual cross-origin requests.

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

## Step 2 - Deploy the CORS Policies

Create a CORS policy that allows specific origins and methods:

```console
kubectl apply -f cors-policy.yaml
```

## Step 3 - Deploy Ingress Resources

Create an Ingress that references `cors-policy` via annotation `nginx.org/policies`:

```console
kubectl apply -f cafe-ingress.yaml
```

## Step 4 - Test the Configuration

1. Send a preflight CORS request to `/tea`:

    ```console
    curl -X OPTIONS \
         -H "Origin: https://app.example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
            --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP \
            https://cafe.example.com:$IC_HTTPS_PORT/tea/ --insecure -v
    ```

    You should see CORS headers in the response and a `204` response from NGINX.

1. Send an actual cross-origin request to `/tea`:

    ```console
    curl -X POST \
         -H "Origin: https://app.example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
            --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP \
            https://cafe.example.com:$IC_HTTPS_PORT/tea/ --insecure -v
    ```

    The response should include CORS headers and a response from the backend.

1. Send a preflight request to `/coffee` with a non-matching origin:

    ```console
    curl -X OPTIONS \
         -H "Origin: https://example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
            --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP \
            https://cafe.example.com:$IC_HTTPS_PORT/coffee/ --insecure -v
    ```

    You should see `204` response from NGINX, but `Access-Control-Allow-Origin` should be missing because the origin does not match any allowed ones.
