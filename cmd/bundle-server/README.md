# Using the Bundle Server with NGINX Ingress Controller on GKE

This guide walks through deploying and using the local bundle test server alongside the NGINX Ingress Controller on a GKE cluster, for testing the remote WAF bundle fetching feature.

> **Proof of Concept** -- This implementation uses HTTP polling with ETag-based conditional GETs. See [Design Considerations: Why Polling Is Not Ideal for Kubernetes](#design-considerations-why-polling-is-not-ideal-for-kubernetes) at the end of this document for why this approach is a pragmatic starting point but not a production-grade pattern for Kubernetes workloads.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│ GKE Cluster                                             │
│                                                         │
│  ┌──────────────────┐       ┌────────────────────────┐  │
│  │ NGINX Ingress    │──────>│ bundle-server (Pod)     │  │
│  │ Controller       │ HTTPS │ Serves .tgz bundles     │  │
│  │                  │ mTLS  │ with ETag support       │  │
│  │ Polls every 1m   │       │                         │  │
│  │ If-None-Match    │       │ GET /bundles/{name}     │  │
│  └──────────────────┘       │ POST /bundles/{name}    │  │
│                             └────────────────────────┘  │
│                                                         │
│  ┌──────────────────┐                                   │
│  │ WAF Policy CR    │                                   │
│  │ apBundleSource:  │                                   │
│  │   url: https://..│                                   │
│  │   tlsSecret: ... │                                   │
│  └──────────────────┘                                   │
└─────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- A running GKE cluster with `kubectl` configured
- `gcloud` CLI authenticated
- Go 1.22+ installed locally (to build the server image)
- Docker or a container build tool
- A container registry accessible from GKE (e.g., `gcr.io/<PROJECT_ID>` or Artifact Registry)

---

## Step 1: Generate TLS Certificates for mTLS

Generate a self-signed CA plus server and client certificates. The server cert is for the bundle-server; the client cert is used by the Ingress Controller to authenticate.

```bash
# Create a working directory
mkdir -p certs && cd certs

# 1. Generate the CA key and certificate
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=Bundle Server CA"

# 2. Generate the server key and CSR
openssl req -newkey rsa:4096 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=bundle-server.bundle-server.svc.cluster.local"

# 3. Create a SAN config for the server cert
cat > server-ext.cnf <<EOF
subjectAltName = DNS:bundle-server.bundle-server.svc.cluster.local,DNS:bundle-server,DNS:localhost
EOF

# 4. Sign the server certificate with the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 \
  -extfile server-ext.cnf

# 5. Generate the client key and CSR (for NIC mTLS authentication)
openssl req -newkey rsa:4096 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=nginx-ingress-controller"

# 6. Sign the client certificate with the CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365 -sha256

cd ..
```

---

## Step 2: Build and Push the Bundle Server Image

```bash
# Set your GCP project and registry
export PROJECT_ID=$(gcloud config get-value project)
export REGISTRY=gcr.io/${PROJECT_ID}

# Build the bundle-server binary
cd /path/to/kubernetes-ingress
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/bundle-server ./cmd/bundle-server/

# Create a minimal Dockerfile
cat > cmd/bundle-server/Dockerfile <<'EOF'
FROM gcr.io/distroless/static:nonroot
COPY bin/bundle-server /bundle-server
USER nonroot:nonroot
ENTRYPOINT ["/bundle-server"]
EOF

# Build and push the image
docker buildx build \
  --platform linux/amd64 \
  --push \
  -t gcr.io/f5-gcs-7899-ptg-ingrss-ctlr/dev/vepatel/bundle-server:latest \
  -f cmd/bundle-server/Dockerfile \
  .
```

---

## Step 3: Deploy the Bundle Server to GKE

### 3a. Create the namespace and TLS secrets

```bash
kubectl create namespace bundle-server

# Server TLS cert (used by the bundle-server pod)
kubectl create secret tls bundle-server-tls \
  --cert=certs/server.crt \
  --key=certs/server.key \
  -n bundle-server

# Client CA (used by the bundle-server to verify the NIC client cert)
kubectl create secret generic bundle-server-client-ca \
  --from-file=ca.crt=certs/ca.crt \
  -n bundle-server
```

### 3b. Create the client TLS secret in the NIC namespace

This secret is referenced by the WAF Policy's `tlsSecret` field. It must contain the client certificate, key, and optionally the CA cert (to verify the server).

```bash
# Create in the namespace where your WAF Policy will be applied (e.g., default)
kubectl create secret tls bundle-client-tls \
  --cert=certs/client.crt \
  --key=certs/client.key \
  -n default

# Patch the secret to also include the CA cert (so NIC can verify the server)
kubectl patch secret bundle-client-tls -n default \
  --type merge -p "{\"data\":{\"ca.crt\":\"$(base64 < certs/ca.crt)\"}}"
```

### 3c. Deploy the bundle-server

```yaml
# Save as bundle-server-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bundle-server
  namespace: bundle-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bundle-server
  template:
    metadata:
      labels:
        app: bundle-server
    spec:
      containers:
      - name: bundle-server
        image: gcr.io/<PROJECT_ID>/bundle-server:latest  # Replace <PROJECT_ID>
        args:
        - "--port=8443"
        - "--bundle-dir=/data/bundles"
        - "--tls-cert=/tls/tls.crt"
        - "--tls-key=/tls/tls.key"
        - "--client-ca=/client-ca/ca.crt"
        ports:
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: tls
          mountPath: /tls
          readOnly: true
        - name: client-ca
          mountPath: /client-ca
          readOnly: true
        - name: bundles
          mountPath: /data/bundles
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: tls
        secret:
          secretName: bundle-server-tls
      - name: client-ca
        secret:
          secretName: bundle-server-client-ca
      - name: bundles
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: bundle-server
  namespace: bundle-server
spec:
  selector:
    app: bundle-server
  ports:
  - port: 443
    targetPort: 8443
    protocol: TCP
    name: https
  type: ClusterIP
```

```bash
kubectl apply -f bundle-server-deployment.yaml
```

### 3d. Verify the bundle-server is running

```bash
kubectl get pods -n bundle-server
kubectl logs -n bundle-server deployment/bundle-server
```

---

## Step 4: Upload a Test Bundle

You can upload a bundle file from your local machine via port-forward, or from within the cluster.

### Option A: Via port-forward (from your laptop)

```bash
# Port-forward to the bundle-server
kubectl port-forward -n bundle-server svc/bundle-server 8443:443 &

# Upload the actual file contents (note the @ prefix)
curl -k --cert certs/client.crt --key certs/client.key \
  -X POST --data-binary @compiled_policy.tgz \
  https://localhost:8443/bundles/compiled_policy.tgz

# Verify the ETag header is present (HEAD request - no body returned)
curl -k --cert certs/client.crt --key certs/client.key \
  -I https://localhost:8443/bundles/compiled_policy.tgz

# Fetch using the same name you uploaded
curl -k --cert certs/client.crt --key certs/client.key \
  -o compiled_policy.tgz \
  https://localhost:8443/bundles/compiled_policy.tgz


# Stop port-forward
kill %1
```

### Option B: Via a temporary pod inside the cluster

```bash
kubectl run -n bundle-server curl-test --rm -it --image=curlimages/curl -- \
  curl -k -I https://bundle-server.bundle-server.svc.cluster.local/bundles/test-policy.tgz
```

---

## Step 5: Create the WAF Policy CR with `apBundleSource`

The in-cluster URL for the bundle-server is:

```
https://bundle-server.bundle-server.svc.cluster.local/bundles/<filename>
```

```yaml
# Save as waf-remote-bundle-policy.yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: waf-remote-bundle
  namespace: default
spec:
  waf:
    enable: true
    apBundleSource:
      url: "https://bundle-server.bundle-server.svc.cluster.local/bundles/test-policy.tgz"
      tlsSecret: "bundle-client-tls"
      pollInterval: "1m"
```

```bash
kubectl apply -f waf-remote-bundle-policy.yaml

# Verify the policy status
kubectl get pol waf-remote-bundle -o yaml
```

---

## Step 6: Reference the Policy from a VirtualServer

```yaml
# Save as cafe-virtualserver.yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: cafe
  namespace: default
spec:
  host: cafe.example.com
  policies:
  - name: waf-remote-bundle
  upstreams:
  - name: tea
    service: tea-svc
    port: 80
  routes:
  - path: /tea
    action:
      pass: tea
```

```bash
kubectl apply -f cafe-virtualserver.yaml
```

---

## Step 7: Verify End-to-End Flow

### Check NIC logs for bundle fetch activity

```bash
# Get NIC pod name
NIC_POD=$(kubectl get pods -n nginx-ingress -l app.kubernetes.io/name=nginx-ingress -o jsonpath='{.items[0].metadata.name}')

# Check logs for bundle fetching activity
kubectl logs -n nginx-ingress $NIC_POD | grep -i "bundle"
```

You should see log lines like:

```
Remote bundle updated for default/waf-remote-bundle/policy, re-syncing policies
```

### Check the bundle-server logs

```bash
kubectl logs -n bundle-server deployment/bundle-server
```

You should see request logs with ETag values and 304 Not Modified responses on subsequent polls.

### Verify ETag-based caching

After the initial fetch, subsequent polls return `304 Not Modified` (no re-download):

```bash
# Watch the bundle-server logs live
kubectl logs -f -n bundle-server deployment/bundle-server
```

In NIC logs, a 304 appears as a `DEBUG`-level line:

```
Remote bundle unchanged for default/waf-remote-bundle/policy (304 Not Modified)
```

### Reading poll and fetch logs in NIC

NIC emits structured logs at different levels as it polls:

| Log line | Level | Meaning |
|----------|-------|---------|
| `Starting bundle poll loop for ... (interval=1m0s, url=...)` | INFO | Poll goroutine started for this bundle key |
| `Fetching remote bundle for ... from ...` | INFO | Initial synchronous fetch (on policy apply) |
| `Remote bundle fetched successfully for ... -> /etc/app_protect/bundles/...` | INFO | Bundle downloaded and written to disk |
| `Remote bundle unchanged for ... (304 Not Modified)` | INFO | Initial fetch — server already had same content |
| `Polling remote bundle for ... from ...` | DEBUG | Each periodic poll tick (not visible at default INFO level) |
| `Remote bundle unchanged for ... (304 Not Modified)` | INFO | Poll result: bundle has not changed |
| `Remote bundle updated for ... -> ... (new ETag detected)` | INFO | Poll found a new bundle version; NGINX will reload |
| `Bundle fetch failed for ... from ...: ...` | WARN | Transient error; stale bundle preserved |
| `Bundle poll loop stopped for ...` | DEBUG | Goroutine stopped (policy deleted or controller shutdown) |

To see DEBUG-level lines, the NIC log level must be set to `debug`. With the default `info` level you will see the INFO lines only (initial fetch and bundle updates).

```bash
# Stream all bundle-related log lines from NIC
NIC_POD=$(kubectl get pods -n nginx-ingress -l app.kubernetes.io/name=nginx-ingress \
  -o jsonpath='{.items[0].metadata.name}')
kubectl logs -f -n nginx-ingress "$NIC_POD" | grep -i bundle
```

### Force an ETag change to observe a new bundle fetch

The bundle-server computes the ETag as the first 8 bytes of the SHA-256 hash of the file contents. Uploading any file with **different content** produces a different ETag, which NIC detects on the next poll and triggers a re-download.

#### Option A: Re-upload the real compiled policy

If you have an updated `compiled_policy.tgz` from NGINX App Protect:

```bash
kubectl port-forward -n bundle-server svc/bundle-server 8443:443 &

curl -k --cert certs/client.crt --key certs/client.key \
  -X POST --data-binary @compiled_policy.tgz \
  https://localhost:8443/bundles/compiled_policy.tgz

kill %1
```

The response includes the new ETag:

```
Bundle uploaded successfully (ETag: "a3f1b2c4d5e6f7a8")
```

#### Option B: Re-upload the same file with a dummy change to force a new ETag

This is useful in testing when you don't have a new bundle but want to observe the poll/re-download flow without waiting for real content to change.

```bash
# Unpack the existing bundle and add a dummy file to change its SHA-256
mkdir -p /tmp/bundle-repack
cp compiled_policy.tgz /tmp/bundle-repack/
cd /tmp/bundle-repack
tar xzf compiled_policy.tgz

# Add a timestamp file to guarantee different content
echo "forced-update-$(date +%s)" > .force_etag_change
tar czf compiled_policy_v2.tgz .

cd -

kubectl port-forward -n bundle-server svc/bundle-server 8443:443 &

# Upload using the original filename — the URL path determines the bundle name on disk
curl -k --cert certs/client.crt --key certs/client.key \
  -X POST --data-binary @/tmp/bundle-repack/compiled_policy_v2.tgz \
  https://localhost:8443/bundles/compiled_policy.tgz

kill %1
```

#### Verify the new ETag is active on the server

```bash
kubectl port-forward -n bundle-server svc/bundle-server 8443:443 &

# Check the current ETag without downloading the file body
curl -sk --cert certs/client.crt --key certs/client.key \
  -I https://localhost:8443/bundles/compiled_policy.tgz | grep -i etag

kill %1
```

#### Watch NIC detect the change on the next poll

Within one `pollInterval` (default 1 minute), NIC will fetch the new bundle:

```bash
kubectl logs -f -n nginx-ingress "$NIC_POD" | grep -i bundle
```

You should see:

```
Polling remote bundle for default/waf-remote-bundle/policy from https://...
Remote bundle updated for default/waf-remote-bundle/policy -> /etc/app_protect/bundles/compiled_policy.tgz (new ETag detected)
```

To trigger the check **immediately** without waiting for the poll interval, force a policy re-sync by touching the Policy resource:

```bash
kubectl annotate policy waf-remote-bundle -n default \
  force-sync="$(date +%s)" --overwrite
```

This causes NIC to re-validate the policy and call `FetchNow`, bypassing the poll timer.

---

## Step 8: Cleanup

```bash
# Remove the WAF policy and VirtualServer
kubectl delete -f waf-remote-bundle-policy.yaml
kubectl delete -f cafe-virtualserver.yaml

# Remove the bundle-server deployment
kubectl delete -f bundle-server-deployment.yaml
kubectl delete namespace bundle-server

# Remove the client TLS secret
kubectl delete secret bundle-client-tls -n default

# Remove local certs
rm -rf certs/
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Policy stays `Invalid` | URL must start with `https://` | Check `apBundleSource.url` prefix |
| NIC log: "Failed to resolve TLS secret" | Secret not found or wrong namespace | Ensure `bundle-client-tls` is in the same namespace as the Policy |
| NIC log: "Initial fetch failed" | Bundle-server unreachable or cert mismatch | Verify DNS `bundle-server.bundle-server.svc.cluster.local` resolves; check cert SANs |
| 304 responses but no re-download | Working correctly | ETag matches; upload a new bundle to trigger update |
| NIC log: "x509: certificate signed by unknown authority" | Missing `ca.crt` in client secret | Patch the `bundle-client-tls` secret to include `ca.crt` (Step 3b) |
| Bundle-server log: "tls: bad certificate" | mTLS failure; NIC client cert not presented or not signed by expected CA | Verify `--client-ca` points to the CA that signed the client cert |
| VS event: `AddedOrUpdatedWithError: Error extracting .tgz: File Not Found` | Race between the atomic bundle file replacement and APP_PROTECT v5's `waf-config-mgr` detecting the new inode. `waf-config-mgr` briefly marks the path as unavailable while reconciling its internal state for the new file. | NIC now inserts a 2-second stabilisation delay (`bundleReloadDelay`) between the download completing and the NGINX reload being triggered. If you hit this on an older NIC build, run `kubectl annotate policy waf-remote-bundle -n default force-sync="$(date +%s)" --overwrite` to trigger a fresh re-sync after the file is stable. |

---

## Configuration Reference

### BundleSource Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `url` | string | Yes | - | HTTPS URL to fetch the bundle. Must start with `https://`. |
| `tlsSecret` | string | No | - | Name of a `kubernetes.io/tls` Secret for mTLS. Must be in the same namespace as the Policy. May optionally include a `ca.crt` data key for server certificate verification. |
| `pollInterval` | string | No | `1m` | How often to check for updates via ETag. Go duration format (e.g., `30s`, `2m`, `1h`). Minimum: `10s`. |

### Bundle Server CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8443` | Port to listen on |
| `--bundle-dir` | `./bundles` | Directory to store/serve bundle files |
| `--tls-cert` | (none) | Path to server TLS certificate (enables HTTPS) |
| `--tls-key` | (none) | Path to server TLS private key |
| `--client-ca` | (none) | Path to client CA cert (enables mTLS verification) |

---

## Design Considerations: Why Polling Is Not Ideal for Kubernetes

This implementation uses timer-based HTTP polling (every `pollInterval`, default 1 minute) to check for bundle updates. While functional, polling is fundamentally at odds with how Kubernetes controllers are designed to work:

### 1. Kubernetes is event-driven, not poll-driven

The Kubernetes controller pattern (informers, watches, reconciliation loops) is built around reacting to change notifications via the API server's watch mechanism. Polling an external HTTP endpoint from inside a controller introduces a second, independent control loop that operates outside the K8s event model. This creates:

- **Inconsistent reconciliation triggers** -- The controller reconciles resources when K8s events arrive (create, update, delete). Bundle updates arrive on a completely separate timer cadence, so there's a "two-clock" problem where the controller's view of the world can be stale for up to `pollInterval`.
- **No backpressure** -- K8s informers have built-in backpressure (rate limiting, requeueing, exponential backoff). A raw poll loop doesn't participate in the controller's work queue priorities or rate limiting.
- **Leader election blind spots** -- In HA deployments, only the leader should be fetching bundles. This poll loop runs on every replica, wasting resources on non-leaders and risking conflicting writes to the shared bundle directory.

### 2. Resource overhead scales poorly

Each registered bundle source spawns its own goroutine with a `time.Ticker`. In a cluster with many WAF policies referencing remote bundles, this becomes N concurrent polling loops making HTTP requests, each holding a `sync.Mutex` lock during fetch operations. Kubernetes controllers are designed to batch work through a single work queue -- not fan out into unbounded parallel HTTP callers.

### 3. ETag-based caching is fragile

The implementation assumes the remote server supports ETags correctly. If the server doesn't return an ETag, every poll results in a full download. If the server returns weak ETags or changes ETag semantics across deployments, the cache invalidation logic breaks silently. There's no way for the controller to signal "I need a new bundle" -- it can only wait for the next poll cycle.

### 4. Better alternatives for production

| Approach | Description | Why it's better |
|----------|-------------|-----------------|
| **Webhook / Push model** | External system pushes updated bundles into a K8s ConfigMap or OCI artifact, triggering a standard K8s watch event | Fits the K8s event model natively; no polling |
| **OCI registry + init container** | Store bundles as OCI artifacts; use an init container or sidecar to pull on pod start | Leverages existing image pull infrastructure and caching |
| **Custom Resource + operator** | Define a `BundleSync` CR that an operator watches; operator fetches bundles and writes to a PVC or emptyDir | Standard operator pattern; supports RBAC, status, events |
| **Flux/Argo CD artifact sync** | Use GitOps tooling to sync bundle files from a Git repo or Helm chart into the cluster | Auditable, declarative, integrates with existing CD pipelines |
| **K8s informer on a ConfigMap/Secret** | Store the bundle content (or a reference) in a ConfigMap; the controller already watches these | Zero new infrastructure; works with existing secret management |

### 5. When polling makes sense

Polling is acceptable as a **proof-of-concept** or when:

- The external API cannot push notifications (legacy systems, air-gapped environments)
- The bundle update frequency is very low (hours, not minutes)
- A single controller replica is responsible for fetching (no HA concerns)
- You need a quick integration path while designing a proper event-driven solution

### Summary

This polling-based approach demonstrates the data flow -- `Policy CR -> BundleFetcher -> local file -> NGINX config -> reload` -- but should not be considered the production architecture. A production implementation should replace the poll loop with an event-driven mechanism that participates in the Kubernetes controller's reconciliation model.

---

## Internal Implementation Details

For developers working on this feature, here are key implementation details:

### Bundle Key Format

Bundle entries are keyed as `{namespace}/{policyName}/{type}` where type is:

- `policy` -- for `apBundleSource` (the WAF policy bundle)
- `log-0`, `log-1`, ... -- for `apLogBundleSource` entries in `securityLogs[]`

### Data Flow

```
Policy CR applied
  -> syncPolicy() validates + registers with BundleFetcher
  -> BundleFetcher.FetchNow() does initial HTTP GET (with mTLS if tlsSecret is set)
  -> File written atomically to {bundlePath}/{ns}-{name}-{type}.tgz
  -> Background ticker polls every pollInterval with If-None-Match: {etag}
  -> On 200 (new content): atomic re-download, onChange callback enqueues policy re-sync
  -> On 304 (unchanged): no-op
  -> generatePolicies() reads BundleFetcher.GetLocalPath() to get the on-disk path
  -> Path is validated via BundleValidator, then set as WAF.ApBundle in NGINX config
  -> NGINX reloads with the new bundle reference
```

### Graceful Degradation

- If the initial fetch fails, the policy is still valid but the generated NGINX config will warn and return a 500.
- If a subsequent poll fails (server down, network error), the stale bundle file is preserved and continues to be used.
- If the BundleFetcher is nil (AppProtect not enabled or no bundle path configured), `apBundleSource` policies produce a warning and error status.
