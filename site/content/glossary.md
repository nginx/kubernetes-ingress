---
description: null
docs: DOCS-1446
title: Glossary
weight: 10000
---

This is a glossary of terms related to F5 NGINX Ingress Controller and Kubernetes as a whole.

---

## Ingress {#ingress}

_Ingress_ refers to an _Ingress Resource_, a Kubernetes API object which allows access to [Services](https://kubernetes.io/docs/concepts/services-networking/service/) within a cluster. They are managed by an [Ingress Controller]({{< relref "glossary.md#ingress-controller">}}).

_Ingress_ resources enable the following functionality:

- **Load balancing**, extended through the use of Services
- **Content-based routing**, using hosts and paths
- **TLS/SSL termination**, based on hostnames

For additional information, please read the official [Kubernetes Ingress Documentation](https://kubernetes.io/docs/concepts/services-networking/ingress/).

---

## Ingress Controller {#ingress-controller}

*Ingress Controllers* are applications within a Kubernetes cluster that enable [Ingress]({{< relref "glossary.md#ingress">}}) resources to function. They are not automatically deployed with a Kubernetes cluster, and can vary in implementation based on intended use, such as load balancing algorithms for Ingress resources.

[The design of NGINX Ingress Controller]({{< relref "overview/design.md">}}) explains the technical details of NGINX Ingress Controller.
