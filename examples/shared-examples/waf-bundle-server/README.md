# WAF Bundle Server

HTTPS server that compiles and serves WAF policy and log profile bundles for use with `apBundleSource`.

WAF policy and log profile definitions are stored as JSON in a ConfigMap. At pod startup,
[waf-compiler](https://docs.nginx.com/waf/configure/compiler/) init containers compile
them into `.tgz` bundles, which are then served by NGINX over HTTPS.

## Prerequisites

1. An `imagePullSecret` named `regcred` in the `default` namespace with access to
   `private-registry.nginx.com` (for the `waf-compiler` image). This is the same secret used
   for NIC (`controller.serviceAccount.imagePullSecretName=regcred`). See
   [Download NGINX Ingress Controller from the F5 Registry](https://docs.nginx.com/nginx-ingress-controller/install/images/registry-download/).

1. Run `make secrets` command to generate the necessary secrets for the example.

## Step 1 - Create the TLS Secrets

Create the TLS secrets used by the bundle server for HTTPS and by NIC for server certificate verification:

```console
kubectl apply -f bundle-server-tls-secret.yaml
kubectl apply -f bundle-client-tls-secret.yaml
```

## Step 2 - Deploy the Bundle Server

Deploy the bundle server. The init containers will compile the WAF policy and log profile JSON
into `.tgz` bundles before the NGINX server starts:

```console
kubectl apply -f deployment.yaml
```

## Step 3 - Verify the Bundle Server is Running

Wait for the init containers to finish compiling and the server to become available:

```console
kubectl wait --for=condition=Available deployment/bundle-server --timeout=120s
```

Verify the pod is running:

```console
kubectl get pods -l app=bundle-server
```

The compiled bundles are available at:

```console
https://bundle-server.default.svc.cluster.local/bundles/attack-signatures-blocking.tgz
https://bundle-server.default.svc.cluster.local/bundles/log-default.tgz
```

## Customizing Policies

To add or change WAF policies or log profiles, edit the `waf-policy-definitions` ConfigMap in
`deployment.yaml` and add corresponding init containers. Use the `-p` flag for policies and
`-l` for log profiles. See [Build and use the compiler tool](https://docs.nginx.com/waf/configure/compiler/)
for JSON format and compiler usage.

## See Also

- [WAF with Remote Bundle Sources (VirtualServer)](../../custom-resources/app-protect-waf-v5-bundle-source/) — complete example using this bundle server
- [WAF with Remote Bundle Sources (Ingress)](../../ingress-resources/app-protect-waf-v5-bundle-source/) — Ingress equivalent
- [Configure F5 WAF for NGINX with NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/integrations/app-protect-waf-v5/configuration/)
