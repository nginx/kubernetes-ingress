---
docs: DOCS-600
doctypes:
- concept
title: F5 BIG-IP
toc: true
weight: 400
---

Learn how to use F5 IngressLink with NGINX Ingress Controller to configure your F5 BIG-IP device.

F5 IngressLink is an integration between NGINX Ingress Controller and [F5 BIG-IP Container Ingress Services](https://clouddocs.f5.com/containers/latest/) (CIS) that configures an F5 BIG-IP device as a load balancer for NGINX Ingress Controller pods.

## Install NGINX Ingress Controller with the integration enabled

The steps to enable the integration depend on the option chosen to install NGINX Ingress Controller: Using [Manifests]({{< relref "installation/installing-nic/installation-with-manifests" >}}) or using the [Helm chart]({{< relref "installation/installing-nic/installation-with-helm" >}}).

### Installation using manifests

1. Create a service for the Ingress Controller pods for ports 80 and 443. For example:

    ```yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: nginx-ingress-ingresslink
      namespace: nginx-ingress
      labels:
        app: ingresslink
    spec:
      ports:
      - port: 80
        targetPort: 80
        protocol: TCP
        name: http
      - port: 443
        targetPort: 443
        protocol: TCP
        name: https
      selector:
        app: nginx-ingress
    ```

    Note the label `app: ingresslink`. We will use it in the [Configure CIS](#configure-cis) step.

1. In the [ConfigMap resource]({{< relref "configuration/global-configuration/configmap-resource" >}}) enable the proxy protocol, which the BIG-IP system will use to pass the client IP and port information to NGINX. For the  `set-real-ip-from` key, use the subnet of the IP which the BIG-IP system uses to send traffic to NGINX:

    ```yaml
    proxy-protocol: "True"
    real-ip-header: "proxy_protocol"
    set-real-ip-from: "0.0.0.0/0"
    ```

1. Deploy NGINX Ingress Controller with additional [command-line arguments]({{< relref "configuration/global-configuration/command-line-arguments" >}}):

    ```yaml
    args:
    - -ingresslink=nginx-ingress
    - -report-ingress-status
    . . .
    ```

    where `ingresslink` references the name of the IngressLink resource from step 1, and `report-ingress-status` enables [reporting ingress statuses]({{< relref "configuration/global-configuration/reporting-resources-status#ingress-resources" >}}).

### Installation using Helm

Install a Helm release with the following values:

```yaml
controller:
  config:
    entries:
      proxy-protocol: "True"
      real-ip-header: "proxy_protocol"
      set-real-ip-from: "0.0.0.0/0"
  reportIngressStatus:
    ingressLink: nginx-ingress
  service:
    type: ClusterIP
    externalTrafficPolicy: Cluster
    extraLabels:
      app: ingresslink
```

We will use the `ingressLink` and `extraLabels` parameter values to configure CIS in the next section. For the  `set-real-ip-from` key, use the subnet of the IP which the BIG-IP system uses to send traffic to NGINX.

## Configure CIS

To enable the integration, F5 BIG-IP Container Ingress Services must be deployed in the cluster and configured to support the integration. Follow the instructions on the [CIS documentation portal](https://clouddocs.f5.com/containers/latest/userguide/ingresslink/#configuring-ingresslink).

Make sure that:

- The name of the IngressLink resource is the same as the one used during the installation of NGINX Ingress Controller (`nginx-ingress` in the previous example).
- The selector in the IngressLink resource is the same as the Service labels configured during Ingress Controller installation (`app: ingresslink` in the previous example).
- The IngressLink must belong to the same namespace as the Ingress Controller pod (`nginx-ingress` or the namespace used for installing the Helm chart).
