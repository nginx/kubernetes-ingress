---
docs: DOCS-1181
doctypes:
- concept
title: NGINX Ingress Controller and Open Service Mesh
toc: true
weight: 1800
---


This document outlines how to integrate F5 NGINX Ingress Controller with Open Service Mesh (OSM)

Open Service Mesh will work with both versions of [F5 NGINX Ingress controller](https://github.com/nginx/kubernetes-ingress): the free as well as the NGINX Plus versions.

Below is a link to the official F5 NGINX Ingress Controller documentation.
[F5 NGINX Ingress controller](https://docs.nginx.com/nginx-ingress-controller/)

# Integrating NGINX Ingress Controller with Open Service Mesh

There are two ways to integrate NGINX Ingress Controller with Open Service Mesh (OSM):

1. Injecting an envoy sidecar directly with NGINX Ingress Controller.
2. Using the Open Service Mesh `ingressBackend` "proxy" feature.

# NGINX Ingress controller and OSM with sidecar proxy injected

Install OSM in the cluster

```shell
osm install --mesh-name osm-nginx --osm-namespace osm-system
```

### Mark the F5 NGINX Ingress controller namespace for sidecar injection

*NOTE:* Depending on how you install NGINX Ingress controller, you might need to create the `namespace`. For example, if you are using manifests to install NGINX Ingress controller, you can complete all of the steps on our documentation page, *EXCEPT*, actually deploying NGINX Ingress controller. This is because, when using the sidecar approach, OSM needs to "manage" the namespace so it knows what `namespaces` it needs to inject sidecars into.

Next thing we need to do is install OSM into the `NGINX Ingress controller` namespace so that the `envoy` sidecar will be injected into NGINX Ingress controller.
First, create the `nginx-ingress` namespace:

```shell
kubectl create ns nginx-ingress
```

Then "mark" the `nginx-ingress` namespace for OSM to deploy a sidecar.

```shell
osm namespace add nginx-ingress --mesh-name osm-nginx
```

The above command will use the mark the `nginx-ingress` namespace, where OSM will be installed (sidecar)

# Install F5 NGINX Ingress controller

Links to the complete install guides:

[Using Helm to install NGINX Ingress](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/)
[Using Manifests to install NGINX Ingress](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)

When using the sidecar method, ensure that you add the correct annotations listed below. This ensures proper integration of NGINX Ingress Controller with the envoy sidecar proxy.

## Helm installs

If using `helm`, add the following `annotation` to your `values.yaml` file:

Under `controller.pod.annotations`:

```yaml
pod:
  annotations: {
    openservicemesh.io/inbound-port-exclusion-list: "80, 443"
    }
```

You can also use the `set` command available with `helm` to set these at install time.

```shell
helm install nic01 nginx-stable/nginx-ingress -n nginx-ingress --create-namespace --set controller.pod.annotations.'openservicemesh\.io/inbound\-port\-exclusion\-list=\{ "80"\, "443"\ }'
```

Change your `release` accordingly to match your environment.

## Manifest installs

For your `manifest` deployments, add the following `annotation`.

```yaml
annotations:
  openservicemesh.io/inbound-port-exclusion-list: "80,443"
```

### Sample deployment file with required annotation

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
      labels:
        app: nginx-ingress
      annotations:
        openservicemesh.io/inbound-port-exclusion-list: "80,443"
```

This annotation is *required* when injecting envoy sidecar into NGINX Ingress controller.
`InboundPortExclusionList` defines a global list of ports to exclude from inbound traffic interception by the sidecar proxy.

### Install a Test Application

To test the integration, we will use the `httpbin` sample application from the [Ingress With Kubernetes NGINX Ingress Controller](https://release-v1-2.docs.openservicemesh.io/docs/demos/ingress_k8s_nginx/) guide.

The following three commands will create the namespace for the application, add the namespace to OSM for monitoring, then install the application.

```shell
kubectl create ns httpbin
osm namespace add httpbin --mesh-name osm-nginx
kubectl apply -f https://raw.githubusercontent.com/openservicemesh/osm-docs/release-v1.2/manifests/samples/httpbin/httpbin.yaml -n httpbin
```

### Verify that the envoy sidecar has been *injected* into NGINX Ingress Controller

```shell
kubectl get pods -n nginx-ingress
NAME                             READY   STATUS    RESTARTS       AGE
nginx-ingress-7b9557ddc6-zw7l5   2/2     Running   1 (5m8s ago)   5m19s
```

2/2 shows we have two containers in the NGINX Ingress controller pod: NGINX Ingress and Envoy

Configure your NGINX VirtualServer yaml to similar below

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: httpbin
  namespace: httpbin
spec:
  host: httpbin.example.com
  tls:
    secret: secret01
  upstreams:
  - name: httpbin
    service: httpbin
    port: 14001
    use-cluster-ip: true
  routes:
  - path: /
    action:
      proxy:
        upstream: httpbin
        requestHeaders:
          set:
          - name: Host
            value: httpbin.httpbin.svc.cluster.local
```

Test your configuration:

```shell
 curl  http://httpbin.example.com/get -v
*   Trying 172.19.0.2:80...
* TCP_NODELAY set
* Connected to httpbin.example.com (172.19.0.2) port 80 (#0)
> GET /get HTTP/1.1
> Host: httpbin.example.com
> User-Agent: curl/7.68.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.23.3
< Date: Sun, 19 Feb 2023 19:06:47 GMT
< Content-Type: application/json
< Content-Length: 454
< Connection: keep-alive
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 2
<
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.httpbin.svc.cluster.local",
    "Osm-Stats-Kind": "Deployment",
    "Osm-Stats-Name": "httpbin",
    "Osm-Stats-Namespace": "httpbin",
    "Osm-Stats-Pod": "httpbin-78555f5c4b-t6qln",
    "User-Agent": "curl/7.68.0",
    "X-Envoy-Internal": "true",
    "X-Forwarded-Host": "httpbin.example.com"
  },
  "origin": "172.19.0.1",
  "url": "http://httpbin.example.com/get"
}
* Connection #0 to host httpbin.example.com left intact
```

## Using The Open Service Mesh `ingressBackend` "proxy" Feature

Install OSM into the cluster.
By running the following command, you will install OSM into the cluster with the mesh name `osm-nginx` using the `osm-system` namespace.

```shell
osm install --mesh-name osm-nginx --osm-namespace osm-system
```

Once OSM has been installed, this next command will mark NGINX Ingress Controller as part of the OSM mesh, while also disabling sidecar injection.
*NOTE*: The nginx-ingress name can be created as part of the NGINX Ingress install process, or manually. If you are creating it manually, the namespace must created before you "add" the namespace to Open Service Mesh.

```shell
osm namespace add nginx-ingress --mesh-name osm-nginx --disable-sidecar-injection
```

# Install F5 NGINX Ingress controller

Links to the complete install guides:

[Using Helm to install NGINX Ingress](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/)
[Using Manifests to install NGINX Ingress](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)

*NOTE*: This method does NOT require annotations added to the deployment, compared to the sidecar install method.

### Install a Test Application

To test the integration, we will use the `httpbin` sample application from the [Ingress With Kubernetes NGINX Ingress Controller](https://release-v1-2.docs.openservicemesh.io/docs/demos/ingress_k8s_nginx/) guide.

The following three commands will create the namespace for the application, add the namespace to OSM for monitoring, then install the application.

```shell
kubectl create ns httpbin
osm namespace add httpbin --mesh-name osm-nginx
kubectl apply -f https://raw.githubusercontent.com/openservicemesh/osm-docs/release-v1.2/manifests/samples/httpbin/httpbin.yaml -n httpbin
```

### mTLS Setup

To enable mTLS for NGINX Ingress Controller and OSM, you need to configure the `IngressBackend` API to use `https` as the backend protocol as and trigger OSM to issue a certificate. NGINX will use this certificate to proxy HTTPS connections to the TLS backends. The client certificate and certificate authority (CA) certificate will be stored in a Kubernetes secret that NGINX will use for authentication."

To begin, edit the `osm-mesh-config` resource:

```shell
kubectl edit meshconfig osm-mesh-config -n osm-system
```

You will need to update under `certificate` to look like this:

```yaml
spec:
  certificate:
    ingressGateway:
      secret:
        name: osm-nginx-client-cert
        namespace: osm-system
      subjectAltNames:
      - nginx-ingress.nginx-ingress.cluster.local
      validityDuration: 24h
```

This will generate a new client certificate (osm-nginx-client-cert) that NGINX Ingress controller will use for mTLS.
The *SAN*, `subjectAltNames`, is the following form:

```shell
<service_account>.<namespace>.cluster.local
```

With the above OSM mesh config changed, that secret will be created in the `osm-system` namespace.
There will also be the `osm-ca-bundle` secret as well, which is autogenerated by OSM.

```shell
kubectl get secrets -n osm-system
NAME                              TYPE                 DATA   AGE
osm-ca-bundle                     Opaque               2      37m
osm-nginx-client-cert             kubernetes.io/tls    3      17m
```

Now, we need to "export" out these certificates in order to use them with NGINX Ingress Controller.

```shell
kubectl get secret osm-ca-bundle -n osm-system -o yaml > osm-ca-bundle-secret.yaml
kubectl get secret osm-nginx-client-cert -n osm-system -o yaml > osm-nginx-client-cert.yaml
```

We need to edit the two exported out .yaml files and change a few parts.

Edit `osm-ca-bundle-secret.yaml`
Remove the `private.key` section under `data.`
Change the `namespace` field to your nginx-ingress location
Change the `type` to `type: nginx.org/ca`

Updated file should look like the following.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: osm-ca-bundle
  namespace: nginx-ingress
type: nginx.org/ca
data:
  ca.crt: <ca_cert_data>
```

Edit `osm-nginx-client-cert.yaml`
Remove the `ca.crt` in the `data` section
Change the namespace to the nginx-ingress namespace.

Updated file should look like the following.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: osm-nginx-client-cert
  namespace: nginx-ingress
type: kubernetes.io/tls
data:
  tls.crt: <tls_crt_data>
  tls.key: <tls_key_data>
```

Then apply these two secrets to the cluster.

```shell
kubectl apply -f osm-ca-bundle-secret.yaml
kubectl apply -f osm-nginx-client-cert.yaml
```

Ensure the secrets exist in the `nginx-ingress` namespace:

```shell
kubectl get secrets -n nginx-ingress
NAME                    TYPE                DATA   AGE
osm-nginx-client-cert   kubernetes.io/tls   2      23m
osm-ca-bundle           nginx.org/ca        1      23m
```

We now need to create our CRDs (virtualServer and policy).
Here is the `policy` resource that holds the mTLS information.
Make sure you apply the `policy` or the  mTLS connection will not work. (required for virtualServer)

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: osm-mtls
  namespace: nginx-ingress
spec:
  egressMTLS:
    tlsSecret: osm-nginx-client-cert
    trustedCertSecret: osm-ca-bundle
    verifyDepth: 2
    verifyServer: on
    sslName: httpbin.httpbin.cluster.local
```

Here is an example `virtualServer` resource as well as the `ingressBackend`.

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: httpbin
  namespace: httpbin
spec:
  policies:
    - name: osm-mtls
      namespace: nginx-ingress
  host: httpbin.example.com
  tls:
    secret: secret01
  upstreams:
  - name: httpbin
    service: httpbin
    port: 14001
    tls:
      enable: true
  routes:
  - path: /
    action:
      pass: httpbin
---
kind: IngressBackend
apiVersion: policy.openservicemesh.io/v1alpha1
metadata:
  name: httpbin
  namespace: httpbin
spec:
  backends:
  - name: httpbin
    port:
      number: 14001 # targetPort of httpbin service
      protocol: https
    tls:
      skipClientCertValidation: false
  sources:
  - kind: Service
    namespace: nginx-ingress
    name: nginx-ingress
  - kind: AuthenticatedPrincipal
    name: nginx-ingress.nginx-ingress.cluster.local
```

Once these are applied, verify they are valid (virtualServer) and committed (ingressBackend):

```shell
kubectl get vs,ingressbackend -A
NAMESPACE   NAME                                  STATE   HOST                  IP    PORTS   AGE
httpbin     virtualserver.k8s.nginx.org/httpbin   Valid   httpbin.example.com                 26m

NAMESPACE   NAME                                               STATUS
httpbin     ingressbackend.policy.openservicemesh.io/httpbin   committed
```

You can now send traffic through NGINX Ingress Controller with open service mesh.

```shell
curl http://httpbin.example.com/get -v
*   Trying 172.18.0.2:80...
* TCP_NODELAY set
* Connected to httpbin.example.com (172.18.0.2) port 80 (#0)
> GET /get HTTP/1.1
> Host: httpbin.example.com
> User-Agent: curl/7.68.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.23.3
< Date: Sat, 18 Feb 2023 22:41:27 GMT
< Content-Type: application/json
< Content-Length: 280
< Connection: keep-alive
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 1
<
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.example.com",
    "User-Agent": "curl/7.68.0",
    "X-Envoy-Internal": "true",
    "X-Forwarded-Host": "httpbin.example.com"
  },
  "origin": "172.18.0.1",
  "url": "http://httpbin.example.com/get"
}
* Connection #0 to host httpbin.example.com left intact
```
