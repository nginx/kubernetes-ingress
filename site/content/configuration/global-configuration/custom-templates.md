---
docs: DOCS-587
doctypes:
- ''
title: Custom templates
toc: true
weight: 500
---


F5 NGINX Ingress Controller uses templates to generate NGINX configuration for Ingress resources, VirtualServer resources and the main NGINX configuration file. You can customize the templates and apply them via the ConfigMap. See the [corresponding example](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/shared-examples/custom-templates).
