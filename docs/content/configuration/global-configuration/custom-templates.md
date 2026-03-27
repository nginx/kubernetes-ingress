---
title: Custom Templates

description:
weight: 1800
doctypes: [""]
toc: true
docs: "DOCS-587"
---


The Ingress Controller uses templates to generate NGINX configuration for Ingress resources, VirtualServer resources and the main NGINX configuration file. You can customize the templates and apply them via the ConfigMap. See the [corresponding example](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/shared-examples/custom-templates).
