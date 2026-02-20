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

## Step 2 - Deploy the CORS wildcard Policy

Create a CORS policy that does origin matching base on wildcard:

```console
kubectl apply -f wildcard-cors-policy.yaml
```

## Step 4 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `cors-policy` created in Step 2.

## Step 5 - Test the Configuration

1. Send a preflight CORS request to `/test`:

    ```console
    curl -X OPTIONS \
         -H "Origin: https://app.example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
         --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
         http://webapp.example.com:$IC_HTTP_PORT/test/ -v
    ```

    You should see CORS headers in the response and 204 response from nginx

    ```console
        < Access-Control-Allow-Origin: https://app.example.com
        < Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
        < Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With
        < Access-Control-Allow-Credentials: true
        < Access-Control-Expose-Headers: X-Total-Count, X-Page-Size
        < Access-Control-Max-Age: 86400
    ```

2. Send an actual cross-origin request:

    ```console
    curl -X POST \
         -H "Origin: https://app.example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
         --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
         http://webapp.example.com:$IC_HTTP_PORT/test/ -v
    ```

    The response should include CORS headers allowing the cross-origin request and response from backend.

    ```console
    < Access-Control-Allow-Origin: https://app.example.com
    < Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
    < Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-API-Key
    < Access-Control-Allow-Credentials: true
    < Access-Control-Expose-Headers: X-Total-Count, X-Page-Size, X-RateLimit-Remaining, X-RateLimit-Reset
    < Access-Control-Max-Age: 3600
    < 
    Server address: 10.0.0.25:8080
    Server name: webapp-558ff5c8f6-mtnlc
    Date: 17/Feb/2026:16:24:44 +0000
    URI: /test/
    Request ID: 8d1317dacf9243ea42c75e5d3fd9f382
    * Connection #0 to host webapp.example.com left intact
    ```

3. Send a pre-flight request to `/prod` with `https://example.com`:

    ```console
    curl -X OPTIONS \
         -H "Origin: https://example.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: Content-Type" \
         --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
         http://webapp.example.com:$IC_HTTP_PORT/prod/ -v
    ```

    ```console
    < HTTP/1.1 204 No Content
    < Server: nginx/1.29.5
    < Date: Fri, 20 Feb 2026 11:35:14 GMT
    < Connection: keep-alive
    < Vary: Origin
    < Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
    < Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With
    < Access-Control-Allow-Credentials: true
    < Access-Control-Expose-Headers: X-Total-Count, X-Page-Size
    < Access-Control-Max-Age: 86400
    < Content-Type: text/plain
    < Content-Length: 0
    ```

    You should see 204 response from nginx and `Access-Control-Allow-Origin` missing from returned
    headers, as the origin sent did not match the one specified by wildcard policy.
