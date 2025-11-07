# Support for Rewrite Target

The `nginx.org/rewrite-target` annotation enables URL path rewriting by specifying a target path that requests should be rewritten to. This annotation works with regular expression capture groups from the Ingress path to create dynamic rewrites.

The annotation is mutually exclusive with `nginx.org/rewrites`. If both are present, `nginx.org/rewrites` takes precedence.

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/) instructions to deploy the Ingress Controller.

2. Save the public IP address of the Ingress Controller into a shell variable:
   ```console
   IC_IP=XXX.YYY.ZZZ.III
   ```

3. Save the HTTP port of the Ingress Controller into a shell variable:
   ```console
   IC_HTTP_PORT=<port number>
   ```

## 2. Deploy the Cafe Application

Create the coffee and tea deployments and services:

```console
kubectl create -f cafe.yaml
```

## 3. Configure Rewrite Examples

### Example 1: Simple Static Rewrite

Create an Ingress resource with basic rewrite functionality:

```console
kubectl create -f simple-rewrite.yaml
```

This configures rewriting from `/coffee` to `/beverages/coffee`.

### Example 2: Dynamic Rewrite with Regex

Create an Ingress resource with regular expression-based rewriting:

```console
kubectl create -f regex-rewrite.yaml
```

This configures dynamic rewriting using capture groups from `/menu/([^/]+)/([^/]+)` to `/beverages/$1/$2`.

## 4. Test the Application

### Test Simple Rewrite

Access the coffee service through the rewritten path:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee --insecure
```

```text
Server address: 10.16.0.16:8080
Server name: coffee-676c9f8944-n2bmb
Date: 07/Nov/2025:11:23:09 +0000
URI: /beverages/coffee
Request ID: c224b3e06d79b66f8f33e86cef046c32
```

The request to `/coffee` is rewritten to `/beverages/coffee`.

### Test Regex Rewrite

Access the service using the menu path with dynamic rewriting:

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/menu/coffee/espresso --insecure
```

```text
Server address: 10.16.1.29:8080
Server name: coffee-676c9f8944-vj45p
Date: 07/Nov/2025:11:26:05 +0000
URI: /beverages/coffee/espresso
Request ID: 88334a8b0eeaee2ffe4fdb4c7768641b
```

```console
curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/menu/tea/green --insecure
```

```text
Server address: 10.16.0.16:8080
Server name: coffee-676c9f8944-n2bmb
Date: 07/Nov/2025:11:26:33 +0000
URI: /beverages/tea/green
Request ID: 2ba8f9055aecc059b32f797f1ce2aca5
```

The requests to `/menu/coffee/espresso` and `/menu/tea/green` are rewritten to `/beverages/coffee/espresso` and `/beverages/tea/green` using the captured groups.

## Validations

1. Mutual Exclusivity: The `nginx.org/rewrite-target` annotation is mutually exclusive with `nginx.org/rewrites`. If both annotations are present, `nginx.org/rewrites` takes precedence and a warning will be generated.

2. Security Validation: The annotation includes built-in security validation to prevent:
   - Absolute URLs (`http://` or `https://`)
   - Protocol-relative URLs (`//`)
   - Path traversal patterns (`../` or `..\\`)
   - Paths not starting with `/`
