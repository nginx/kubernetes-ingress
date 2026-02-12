# CORS Policy

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply a CORS policy to enable Cross-Origin Resource Sharing following MDN guidelines.

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

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 2 - Deploy the CORS Policy

Create a CORS policy that allows requests from specific origins with common HTTP methods:

```console
kubectl apply -f cors-policy.yaml
```

## Step 3 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `cors-policy` created in Step 2.

## Step 4 - Test the Configuration

1. Send a preflight CORS request:

    ```console
    curl -X OPTIONS \
         -H "Origin: https://example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
         --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
         http://webapp.example.com:$IC_HTTP_PORT/api/data -v
    ```

    You should see CORS headers in the response:

    ```console
    Access-Control-Allow-Origin: https://example.com
    Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
    Access-Control-Allow-Headers: Content-Type, Authorization
    Access-Control-Max-Age: 3600
    ```

2. Send an actual cross-origin request:

    ```console
    curl -X POST \
         -H "Origin: https://example.com" \
         -H "Content-Type: application/json" \
         -d '{"message": "Hello World"}' \
         --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
         http://webapp.example.com:$IC_HTTP_PORT/api/data -v
    ```

    The response should include CORS headers allowing the cross-origin request.

3. Test with an unauthorized origin:

    ```console
    curl -X POST \
         -H "Origin: https://unauthorized.com" \
         -H "Content-Type: application/json" \
         --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
         http://webapp.example.com:$IC_HTTP_PORT/api/data -v
    ```

    The response should not include the `Access-Control-Allow-Origin` header, effectively blocking the cross-origin request from the browser's perspective.
