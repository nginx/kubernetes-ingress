# CORS Policy

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply a CORS policy to enable Cross-Origin Resource Sharing following MDN guidelines.

## MDN CORS Compliance

This implementation follows the [Mozilla Developer Network (MDN) CORS guidelines](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) ensuring:

### ✅ Security Features

- **Wildcard + Credentials Restriction**: Prevents using `allowOrigin: ["*"]` with `allowCredentials: true`
- **Injection Prevention**: Validates against dangerous characters (`;{}\\n\\r$\``)
- **RFC Compliance**: Header names must follow RFC 7230 token rules

### ✅ CORS Request Types Support

- **Simple Requests**: GET, HEAD, POST with basic headers (no preflight required)
- **Preflighted Requests**: Complex methods/headers requiring OPTIONS preflight
- **Credentialed Requests**: Requests with cookies/authorization headers

## Examples Provided

1. **cors-policy.yaml** - Advanced credentialed CORS configuration
2. **cors-simple-policy.yaml** - Basic public API CORS configuration  
3. **cors-preflight-policy.yaml** - Complex preflight CORS configuration

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

## MDN-Specific Testing Scenarios

### 1. Simple Request Test (No Preflight)

Test a simple GET request that doesn't require preflight:

```console
curl -X GET \
     -H "Origin: https://example.com" \
     -H "Accept: application/json" \
     --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
     http://webapp.example.com:$IC_HTTP_PORT/api/simple -v
```

**Expected**: Response should include CORS headers immediately, no preflight required.

### 2. Preflight Request Test (Complex Request)

Test a complex request that triggers preflight:

```console
# First, the browser sends a preflight request
curl -X OPTIONS \
     -H "Origin: https://app.example.com" \
     -H "Access-Control-Request-Method: PUT" \
     -H "Access-Control-Request-Headers: Authorization,X-Custom-Header" \
     --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
     http://webapp.example.com:$IC_HTTP_PORT/api/data -v
```

**Expected**: Should return preflight approval headers.

```console
# Then, the actual request
curl -X PUT \
     -H "Origin: https://app.example.com" \
     -H "Authorization: Bearer token123" \
     -H "X-Custom-Header: value" \
     -H "Content-Type: application/json" \
     -d '{"data": "test"}' \
     --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
     http://webapp.example.com:$IC_HTTP_PORT/api/data -v
```

### 3. Credentialed Request Test

Test requests with credentials (using cors-policy.yaml with allowCredentials: true):

```console
curl -X POST \
     -H "Origin: https://example.com" \
     -H "Content-Type: application/json" \
     -H "Cookie: sessionid=abc123" \
     -d '{"message": "authenticated"}' \
     --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP \
     http://webapp.example.com:$IC_HTTP_PORT/api/auth -v
```

**Expected**: Should include `Access-Control-Allow-Credentials: true` header.

### 4. Security Validation Tests

Test security restrictions:

```console
# This should be rejected at CRD level (dangerous characters)
kubectl apply -f - <<EOF
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: invalid-cors-policy
spec:
  cors:
    allowOrigin: ["https://example.com; evil_command;"]
EOF
```

**Expected**: CRD validation error about dangerous characters.

```console
# This should be rejected at CRD level (wildcard + credentials)
kubectl apply -f - <<EOF
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: invalid-wildcard-policy
spec:
  cors:
    allowOrigin: ["*"]
    allowCredentials: true
EOF
```

**Expected**: CRD validation error about wildcard with credentials.

## Browser Testing

For comprehensive testing, use a browser with developer tools:

1. **Open Browser Console** on `https://example.com`
2. **Run JavaScript** to test CORS scenarios:

```javascript
// Simple request test
fetch(`http://webapp.example.com:${IC_HTTP_PORT}/api/simple`, {
  method: 'GET',
  headers: {
    'Accept': 'application/json'
  }
}).then(response => console.log('Simple request:', response.status));

// Preflight request test
fetch(`http://webapp.example.com:${IC_HTTP_PORT}/api/data`, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token123'
  },
  body: JSON.stringify({data: 'test'})
}).then(response => console.log('Preflight request:', response.status));

// Credentialed request test
fetch(`http://webapp.example.com:${IC_HTTP_PORT}/api/auth`, {
  method: 'POST',
  credentials: 'include', // Include cookies
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({message: 'authenticated'})
}).then(response => console.log('Credentialed request:', response.status));
```

**Monitor Network Tab** to see:

- Preflight OPTIONS requests
- CORS headers in responses  
- Browser CORS error messages

## Troubleshooting

### Common Issues

1. **CORS error in browser but curl works**
   - Browser enforces CORS, curl doesn't
   - Check browser developer console for specific errors

2. **Preflight request not getting correct headers**
   - Ensure OPTIONS method is in allowMethods
   - Check Access-Control-Allow-Headers matches request headers

3. **Credentials not working**
   - Verify allowCredentials is true
   - Ensure allowOrigin is explicit domain, not wildcard

4. **Custom headers not accessible in JavaScript**
   - Add custom headers to exposeHeaders array

### Debug Commands

```console
# Check if policy is applied
kubectl get policy cors-policy -o yaml

# Check VirtualServer configuration
kubectl get virtualserver webapp -o yaml

# Check nginx configuration (if access to pods)
kubectl exec -n nginx-ingress <nginx-pod> -- nginx -T | grep -A 20 cors
```
