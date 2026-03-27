---
title: Installation with the NGINX Ingress Operator
description: "This document explains how to install NGINX Ingress Controller in your Kubernetes cluster using NGINX Ingress Operator."
weight: 300
doctypes: [""]
toc: true
docs: "DOCS-604"
---

{{<custom-styles>}}

<style>
h2 {
  border-top: 1px solid #ccc;
  padding-top:20px;
}
</style>

## Before you start

{{<note>}} We recommend the most recent stable version of NGINX Ingress Controller, available on the GitHub repository's [releases page]({{< relref "releases.md" >}}). {{</note>}}

1. Make sure you have access to the NGINX Ingress Controller image:

    - For NGINX Ingress Controller, use the image `nginx/nginx-ingress` from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress).
    - For NGINX Plus Ingress Controller, see [here]({{< relref "installation/nic-images/pulling-ingress-controller-image" >}}) for details on how to pull the image from the F5 Docker registry.
    - To pull from the F5 Container registry, configure a docker registry secret using your JWT token from the MyF5 portal by following the instructions from [here]({{< relref "installation/nic-images/using-the-jwt-token-docker-secret" >}}).
    - It is also possible to build your own image and push it to your private Docker registry by following the instructions from [here]({{< relref "installation/building-nginx-ingress-controller.md" >}})).

2. Install the NGINX Ingress Operator following the [instructions](https://github.com/nginxinc/nginx-ingress-helm-operator/blob/main/docs/installation.md).
3. Create the SecurityContextConstraint as outlined in the ["Getting Started" instructions](https://github.com/nginxinc/nginx-ingress-helm-operator/blob/main/README.md#getting-started).

{{<note>}} If you're upgrading your operator installation to a later release, navigate [here](https://github.com/nginxinc/nginx-ingress-helm-operator/blob/main/helm-charts/nginx-ingress) and run `kubectl apply -f crds/` or `oc apply -f crds/` as a prerequisite{{</note>}}

## Create the NGINX Ingress Controller manifest

Create a manifest `nginx-ingress-controller.yaml` with the following content:

```yaml
apiVersion: charts.nginx.org/v1alpha1
kind: NginxIngress
metadata:
  name: nginxingress-sample
  namespace: nginx-ingress
spec:
  controller:
    image:
      pullPolicy: IfNotPresent
      repository: nginx/nginx-ingress
      tag: 3.3.2-ubi
    ingressClass: nginx
    kind: deployment
    nginxplus: false
    replicaCount: 1
    serviceAccount:
      imagePullSecretName: ""
```

{{<note>}}For NGINX Plus, change the `image.repository` and `image.tag` values and change `nginxPlus` to `True`. If required, set the `serviceAccount.imagePullSecretName` or `serviceAccount.imagePullSecretsNames` to the name of the pre-created docker config secret that should be associated with the ServiceAccount.{{</note>}}

## Deploy NGINX Ingress Controller

```shell
kubectl apply -f nginx-ingress-controller.yaml
```

A new instance of NGINX Ingress Controller will be deployed by the NGINX Ingress Operator in the `default` namespace with default parameters.

To configure other parameters of the NginxIngressController resource, check the [documentation](https://github.com/nginxinc/nginx-ingress-helm-operator/blob/main/docs/nginx-ingress-controller.md).

## Troubleshooting

If you experience an `OOMkilled` error when deploying the NGINX Ingress Operator in a large cluster, it's likely because the Helm operator is caching all Kubernetes objects and using up too much memory. If you encounter this issue, try the following solutions:

- Set the operator to only watch one namespace.
- If monitoring multiple namespaces is required, consider manually increasing the memory limit for the operator. Keep in mind that this value might be overwritten after a release update.

We are working with the OpenShift team to resolve this issue.
