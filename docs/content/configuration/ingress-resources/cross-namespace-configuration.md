---
title: Cross-namespace Configuration

description: "This document explains how to spread Ingress configuration across different namespaces."
weight: 2000
doctypes: [""]
toc: true
docs: "DOCS-594"
---


You can spread the Ingress configuration for a common host across multiple Ingress resources using Mergeable Ingress resources. Such resources can belong to the *same* or *different* namespaces. This enables easier management when using a large number of paths. See the [Mergeable Ingress Resources](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/mergeable-ingress-types) example in our GitHub repo.

As an alternative to Mergeable Ingress resources, you can use [VirtualServer and VirtualServerRoute resources](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/) for cross-namespace configuration. See the [Cross-Namespace Configuration](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/custom-resources/cross-namespace-configuration) example in our GitHub repo.
