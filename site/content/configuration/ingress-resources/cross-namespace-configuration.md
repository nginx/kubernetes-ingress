---
docs: DOCS-594
doctypes:
- ''
title: Cross-namespace configuration
toc: true
weight: 500
---

This topic explains how to spread Ingress configuration across different namespaces in F5 NGINX Ingress Controller.

You can spread the Ingress configuration for a common host across multiple Ingress resources using Mergeable Ingress resources. Such resources can belong to the *same* or *different* namespaces. This enables easier management when using a large number of paths. See the [Mergeable Ingress Resources](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/mergeable-ingress-types) example in our GitHub repo.

As an alternative to Mergeable Ingress resources, you can use [VirtualServer and VirtualServerRoute resources](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/) for cross-namespace configuration. See the [Cross-Namespace Configuration](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/cross-namespace-configuration) example in our GitHub repo.
