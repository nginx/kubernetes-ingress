# Startup Probe Configuration for NGINX Ingress Controller

This example demonstrates how to configure Kubernetes startup probes for the NGINX Ingress Controller using a dedicated endpoint that always returns HTTP 200.

## Configuration

### 1. Deploy the Always-200 Ingress

Apply the startup probe Ingress resource that creates a dedicated endpoint:

```shell
kubectl apply -f startup-probe-ingress.yaml
```

This Ingress uses `nginx.org/server-snippets` to:

- Listen on port 9999 (dedicated startup probe port)
- Always return HTTP 200 with "ok" response

### 2. Helm Chart Configuration

Configure the startup probe in your Helm values:

```yaml
controller:
  enableSnippets: true  # Enable custom NGINX configuration snippets
  startupStatus:
    enable: true
    port: 9999
    path: /
    initialDelaySeconds: 5
    periodSeconds: 1
    timeoutSeconds: 1
    successThreshold: 1
    failureThreshold: 30
```

If enable is set to true then port and path are required.

### 3. Install/Upgrade the Helm Chart

Deploy or upgrade your NGINX Ingress Controller with startup probe enabled:

```shell
helm upgrade --install nginx-ingress nginx-stable/nginx-ingress \
  --set controller.enableSnippets=true \
  --set controller.startupStatus.enable=true \
  --set controller.startupStatus.port=9999 \
  --set controller.startupStatus.path=/ 
```

## Verification

Check that the startup probe is working:

```shell
# Check pod status
kubectl logs -n <namespace> <pod-name>
>> "GET / HTTP/1.1" 200 2 "-" "kube-probe/1.33" "-"
```

```shell
# Check startup probe endpoint (from within the pod)
kubectl exec -it <pod-name> -n <namespace> -- curl http://localhost:9999/
>>ok%
```
