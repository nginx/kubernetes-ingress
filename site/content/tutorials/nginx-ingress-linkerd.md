---
docs: DOCS-1450
doctypes:
- concept
title: NGINX Ingress Controller and Linkerd
toc: true
weight: 1800
---

This document explains how to integrate NGINX Ingress Controller with Linkerd using Linkerd's sidecar proxy. Linkerd works with both NGINX Ingress Controller open source and NGINX Ingress Controller using NGINX Plus.

---

## Before you Begin

There are two methods provided in this tutorial:

- Adding Linkerd to a new NGINX Ingress Controller Installation
- Adding Linkerd to an Existing NGINX Ingress Controller Installation

If you are adding Linkerd to an existing installation, these are the requirements:

- A working NGINX Ingress Controller instance.
- A working [Linkerd installation](https://linkerd.io/2.13/getting-started/).

---

## Integrating Linkerd

Linkerd integrates with NGINX Ingress Controller using its control plane utility through injection.

You can do this through the use of NGINX Ingress Controller's custom resource definitions (CRDs) in a Kubernetes Manifest, or Helm.

---

### During Installation

**Using Manifests**

When installing NGINX Ingress Controller, you can [create a custom resource](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/#3-create-custom-resources) for Linkerd.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-ingress
  namespace: nginx-ingress
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-ingress
  template:
    metadata:
      annotations:
        linkerd.io/inject: enabled
      labels:
        app: nginx-ingress
        app.kubernetes.io/name: nginx-ingress
```

**Using Helm**

Add the following annotation to your Helm deployment:

```yaml
controller:
  pod:
    ## The annotations of the Ingress Controller pod.
    annotations: { linkerd.io/inject: enabled }
```

This annotation will instruct `helm` to tell `Linkerd` to automatically inject its sidecar during the installation of NGINX Ingress Controller.

---

### With an Existing Installation

To integrate Linkerd with an existing NGINX Ingress Controller installation, you will need to inject the `Linkerd` sidecar, using its `linkerd` control plane utility.

**Using Manifests**

If you want to inject into an existing Manifest-based installation, you can run the following:

```bash
kubectl get deployment -n nginx-ingress nginx-ingress -o yaml | linkerd inject - | kubectl apply -f -
```

**Using Helm**
If you want to inject into an existing `Helm` installation, you can run the following:

```bash
kubectl get deployment -n <name_of_namespace> <name_of_helm_release> -o yaml | linkerd inject - | kubectl apply -f -
```

In this example, the `helm` release named `kic01-nginx-ingress-controller` is injected into the `nginx-ingress` namespace:

```bash
kubectl get deploy -n nginx-ingress kic01-nginx-ingress-controller -o yaml | linkerd inject - | kubectl apply -f -
```

## Testing the Integration

Once NGINX Ingress Controller has been integrated with Linkerd, we can check the number of pods to confirm that the sidecar has successfully injected.

```bash
kubectl get pods -n nginx-ingress

NAME                                              READY   STATUS    RESTARTS   AGE
kic01-nginx-ingress-controller-5f8c9b586d-ng4r8   2/2     Running   0          30m
```

In the above example, `2/2` displays the number of pods, and confirms the `Linkerd` sidecar has successfully injected into NGINX Ingress Controller.

For additional testing, we can install an example application. In this case, we'll use the `httpbin` image.

```bash
kubectl create ns httpbin
curl -sL https://raw.githubusercontent.com/openservicemesh/osm-docs/release-v1.2/manifests/samples/httpbin/httpbin.yaml
kubectl apply -f httpbin.yaml
```

Once `httpbin` has been created and applied, we can inject it into an existing deployment with the following command:

```bash
kubectl get deployment -n httpbin httpbin -o yaml | linkerd inject - | kubectl apply -f -
```

Like the main installation, you can check the number of pods to confirm that the application has been successfully injected using the `linkerd` sidecar:

```bash
kubectl get pods -n httpbin
NAME                       READY   STATUS    RESTARTS   AGE
httpbin-66df5bfbc9-ffhdp   2/2     Running   0          67s
```

Next, we are going to create `virtualserver` resource for NGINX Ingress controller.

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: httpbin
  namespace: httpbin
spec:
  host: httpbin.example.com
  tls:
    secret: httpbin-secret
  upstreams:
  - name: httpbin
    service: httpbin
    port: 14001
    use-cluster-ip: true
  routes:
  - path: /
    action:
      pass: httpbin
```

The `use-cluster-ip` is required when using the Linkerd sidecar proxy.

We can now start sending traffic to NGINX Ingress Controller, to verify that `Linkerd` is handling the sidecar traffic connections.

```bash
curl -k https://httpbin.example.com -I

HTTP/1.1 200 OK
Server: nginx/1.23.4
Date: Sat, 20 May 2023 00:08:31 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 9593
Connection: keep-alive
access-control-allow-credentials: true
access-control-allow-origin: *
```

You can additionally view the status of NGINX Ingress Controller and Linkerd by using the Viz dashboard provided by Linkerd.

```bash
linkerd viz dashboard
```
