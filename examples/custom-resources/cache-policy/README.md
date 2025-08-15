# Cache Policy

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply a cache
policy to improve performance by caching responses.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/) instructions to deploy the Ingress Controller.
1. Make sure the snippets are enabled (this is only required for this example as we can see the `X-Cache-Status` header in the response, not required for functionality).
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```shell
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```shell
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```shell
kubectl apply -f cafe.yaml
```

## Step 2 - Create the TLS Secret

Create a secret with the TLS certificate and key:

```shell
kubectl apply -f cafe-secret.yaml
```

## Step 3 - Deploy the Cache Policy

In this step, we create a policy with the name `cache-policy` that configures NGINX to cache responses for 30 minutes.

Create the cache policy:

```shell
kubectl apply -f cache.yaml
```

This policy configures:

- A cache zone named `testcache` with a size of 15MB
- Caching for any response codes using `allowedCodes: ["any"]`
- Caching for GET, HEAD, and POST methods
- Cache duration of 30 minutes
- Override upstream cache headers with `overrideUpstreamCache: true`, to ignore upstream cache headers

## Step 4 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```shell
kubectl apply -f cafe-virtual-server.yaml
```

Note that the VirtualServer:

- References the policy `cache-policy` created in Step 3
- Includes a server snippet to add the `X-Cache-Status` header to responses
- This header shows whether responses are served from cache (HIT) or fetched from upstream (MISS)

## Step 5 - Test the Configuration

Let's test the caching behavior by making multiple requests to the same endpoint.

### Test Cache MISS (First Request)

Make the first request to the `/coffee` endpoint:

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee -I --insecure

HTTP/1.1 200 OK
Server: nginx/1.27.4
Date: Wed, 13 Aug 2025 12:11:34 GMT
Content-Type: text/plain
Content-Length: 160
Connection: keep-alive
Expires: Wed, 13 Aug 2025 12:11:33 GMT
Cache-Control: no-cache
X-Cache-Status: MISS
```

The `X-Cache-Status: MISS` header indicates this response was fetched from the upstream server.  The response is now cached.

### Test Cache HIT (Subsequent Requests)

Make the same request again within the cache duration:

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee -I --insecure

HTTP/1.1 200 OK
Server: nginx/1.27.4
Date: Wed, 13 Aug 2025 12:13:00 GMT
Content-Type: text/plain
Content-Length: 160
Connection: keep-alive
Expires: Wed, 13 Aug 2025 12:11:33 GMT
Cache-Control: no-cache
X-Cache-Status: HIT
```

The `X-Cache-Status: HIT` header indicates this response was served from the cache, providing faster response times.

### Test with Request ID for Full Response

You can also view the full response to see the Request ID:

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure

Server address: 10.0.0.215:8080
Server name: coffee-676c9f8944-bhvxw
Date: 13/Aug/2025:12:11:34 +0000
URI: /coffee
Request ID: c0ca10182c70590112c622835dd060f2
```

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure

Server address: 10.0.0.215:8080
Server name: coffee-676c9f8944-bhvxw
Date: 13/Aug/2025:12:11:34 +0000
URI: /coffee
Request ID: c0ca10182c70590112c622835dd060f2
```

When you make the same request again (while it's still cached), you'll get the same cached response with the same Request ID.

### Test Different Endpoints

Test the `/tea` endpoint to see cache behavior for different URLs:

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea -I --insecure

HTTP/1.1 200 OK
Server: nginx/1.27.4
Date: Wed, 13 Aug 2025 12:16:16 GMT
Content-Type: text/plain
Content-Length: 154
Connection: keep-alive
Expires: Wed, 13 Aug 2025 12:16:15 GMT
Cache-Control: no-cache
X-Cache-Status: MISS

```

Each unique URL has its own cache entry, so the first request to `/tea` will show `MISS` even if `/coffee` is already cached.

## Cache Configuration

The cache policy supports additional configuration options:

### Cache Purging (NGINX Plus Only)

For NGINX Plus deployments, you can enable cache purging by adding IP addresses or CIDR ranges to the `cachePurgeAllow` field:

```yaml
spec:
  cache:
    cacheZoneName: "testcache"
    cacheZoneSize: "15m"
    cachePurgeAllow: ["192.168.1.0/24", "10.0.0.1"]
    # ... other configuration
```

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee -I --insecure

HTTP/1.1 200 OK
Server: nginx/1.27.4
Date: Wed, 13 Aug 2025 12:22:07 GMT
Content-Type: text/plain
Content-Length: 160
Connection: keep-alive
Expires: Wed, 13 Aug 2025 12:19:29 GMT
Cache-Control: no-cache
X-Cache-Status: HIT
```

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee -I -X PURGE --insecure

HTTP/1.1 204 No Content
Server: nginx/1.27.4
Date: Wed, 13 Aug 2025 12:22:39 GMT
Connection: keep-alive
```

```shell
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee -I --insecure

HTTP/1.1 200 OK
Server: nginx/1.27.4
Date: Wed, 13 Aug 2025 12:22:51 GMT
Content-Type: text/plain
Content-Length: 160
Connection: keep-alive
Expires: Wed, 13 Aug 2025 12:22:50 GMT
Cache-Control: no-cache
X-Cache-Status: MISS
```

This allows authorized clients to purge cached content using the PURGE HTTP method.

### Specific Response Codes

Instead of caching all response codes with `["any"]`, you can specify particular codes:

```yaml
spec:
  cache:
    cacheZoneName: "testcache"
    cacheZoneSize: "15m"
    allowedCodes: [200, 301, 404]
    # ... other configuration
```

This configuration only caches responses with 200, 301, or 404 status codes.
