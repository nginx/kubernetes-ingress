---
docs: DOCS-1455
doctypes:
- ''
title: Use the GCP Marketplace NGINX Ingress Controller image
toc: true
weight: 300
draft: true
---

Follow these steps to deploy F5 NGINX Ingress Controller through the GCP Marketplace.

## Overview

NGINX Ingress Controller acts as a Kubernetes Ingress Controller for both NGINX and NGINX Plus. It offers:

- Routing based on host headers: For example, _foo.example.com_ routes to one set of services, while _bar.example.com_ routes to another.
- Path-based routing: Requests beginning with `/serviceA` go to service A; those starting with `/serviceB` go to service B.
- SSL/TLS termination for individual hostnames, like _foo.example.com_.

## Before you begin

Before installing NGINX Ingress Controller, review our [Installation with Manifests]({{< relref "installation/installing-nic/installation-with-manifests.md" >}}) guide. This guide shows you how to build a local NGINX Ingress Controller image and set up the required CustomResourceDefinitions (CRDs).

## Installation

Choose one of the following methods to install NGINX Ingress Controller.

### Install NGINX Ingress Controller to an existing GKE cluster

1. Open [Google Cloud Console](https://console.cloud.google.com/) and go to **Kubernetes Engine > Applications**.

2. Select **DEPLOY FROM MARKETPLACE** and search for *NGINX Ingress Controller*.

   {{<note>}}Make sure to choose a _Premium Edition_ image from _NGINX, Inc._, not a third-party one.{{</note>}}

3. Choose the appropriate *NGINX Ingress Controller* image, then select **CONFIGURE**.

4. Choose your cluster:

   Select an existing Kubernetes Cluster from the list. The _default_ namespace is automatically chosen, but you can create a new one if you prefer. The **App instance name** will be a prefix for all resources created by the deployment and needs to be unique within the selected namespace.

   Recommended settings are pre-selected but feel free to adjust them.

   {{< note >}}If you see the **CREATE NEW CLUSTER** button, select **OR SELECT AN EXISTING CLUSTER** . {{</note>}}

5. Select **DEPLOY** to start NGINX Ingress Controller installation process.

   You can find NGINX Ingress Controller application by going back to **Kubernetes Engine > Applications**.

### Install to a new GKE cluster

If you prefer to use a new GKE cluster, follow these steps. Ensure you have enough vCPU for both NGINX Ingress Controller and any other applications you'll deploy.

1. Open [Google Cloud Console](https://console.cloud.google.com/) and go to **Marketplace*.
2. Search for *NGINX Ingress Controller*.

   {{<note>}}Make sure to choose a _Premium Edition_ image from _NGINX, Inc._, not a third-party one.{{</note>}}

3. Choose the appropriate *NGINX Ingress Controller* image, then select **CONFIGURE**.

4. Configure the new GKE cluster:

   Choose the appropriate zone, network, and subnetwork.

5. Select **CREATE NEW CLUSTER**.

   After a short delay, the cluster will be ready.

6. Finish the installation:

   The _default_ namespace is automatically selected, but you can create a new one if you wish. The **App instance name** will be a prefix for all resources created by the deployment and needs to be unique within the selected namespace. Confirm or adjust the settings and then select **DEPLOY**.

   You can find your NGINX Ingress Controller application by going back to **Kubernetes Engine > Applications**.

## Configuration

When you install NGINX Ingress Controller from the GCP Marketplace, it comes with default settings and an empty *ConfigMap*. The resources have names ending in a suffix that reflects the app instance name you chose during installation. This suffix has the format <app-instance-name>-nginx-ingress.

For example, if you've installed NGINX Ingress Controller in the `nginx-ingress` namespace and used the app instance name `nginx-ingress-plus`, you can check its _ConfigMap_ by running this `kubectl` command:

```bash
kubectl get configmap -n nginx-ingress nginx-ingress-plus-nginx-ingress -o yaml
```

``` yaml
$ kubectl get configmap -n nginx-ingress nginx-ingress-plus-nginx-ingress -o yaml
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":null,"kind":"ConfigMap","metadata":{"annotations":{},"labels":{"app.kubernetes.io/instance":"nginx-ingress-plus","app.kubernetes.io/managed-by":"Helm","app.kubernetes.io/name":"nginx-ingress-plus-nginx-ingress","helm.sh/chart":"nginx-ingress-0.16.2"},"name":"nginx-ingress-plus-nginx-ingress","namespace":"nginx-ingress","ownerReferences":[{"apiVersion":"app.k8s.io/v1beta1","blockOwnerDeletion":true,"kind":"Application","name":"nginx-ingress-plus","uid":"5cbbebd8-df13-4001-bd65-9467405d9a9d"}]}}
  creationTimestamp: "2022-08-25T01:03:10Z"
  labels:
    app.kubernetes.io/instance: nginx-ingress-plus
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: nginx-ingress-plus-nginx-ingress
    helm.sh/chart: nginx-ingress-0.16.2
  name: nginx-ingress-plus-nginx-ingress
  namespace: nginx-ingress
  ownerReferences:
  - apiVersion: app.k8s.io/v1beta1
    blockOwnerDeletion: true
    kind: Application
    name: nginx-ingress-plus
    uid: 5cbbebd8-df13-4001-bd65-9467405d9a9d
  resourceVersion: "147519"
  uid: 3fa33891-7a30-4004-91bd-bd5d652e34a9
```

<br>

For options to customize your resources, see our [Configuration documentation]({{< relref "configuration/" >}}).

## Basic Usage

To learn how to set up a basic application with NGINX Ingress Controller, refer to our [Basic Configuration Example](https://github.com/nginx/kubernetes-ingress/tree/main/examples/custom-resources/basic-configuration).
