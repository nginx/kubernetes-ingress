# Installation

We currently support 2 methods of installation:

1. [Installation in an OpenShift cluster](./openshift-installation.md) using the [OLM](https://github.com/operator-framework/operator-lifecycle-manager).
1. [Manual installation](./manual-installation.md) in a Kubernetes or OpenShift cluster by manually deploying the operator manifests.

After installation, use the [sample CR definition](../config/samples/charts_v1alpha1_nginxingress.yaml) to deploy the NGINX Ingress Controller using the operator.

**Note:** Some users reported an `OOMkilled` error when they deployed the NGINX Ingress Operator in a large cluster with multiple namespaces and Kubernetes objects. This is due to the helm operator caching every Kubernetes object in the cluster, and thus consuming too much system memory. If you encounter this issue, consider setting the operator to only watch one namespace. If watching multiple namespaces is required in your use case, try manually increasing the memory limit for the operator. Note that the value might be overwritten after a release update. We are working with the OpenShift team to resolve this issue.
