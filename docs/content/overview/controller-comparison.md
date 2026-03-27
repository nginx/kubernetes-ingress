---
title: Which Ingress Controller Do I Need?
description: This document describes the key differences between the community Ingress-NGINX Controller and F5 NGINX Ingress Controller.
weight: 400
doctypes: ["concept"]
toc: true
docs: "DOCS-610"
draft: true
---

There are two NGINX-based Ingress Controller implementations out there: the one made by NGINX ([nginxinc/kubernetes-ingress](https://github.com/nginxinc/kubernetes-ingress)) and the one made by Kubernetes ([kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx)). In this document, we explain the key differences between those implementations. This information should help you to choose an appropriate implementation for your requirements or move from one implementation to the other.

## Which One Am I Using?

If you are unsure about which implementation you are using, check the container image of the Ingress Controller that is running. For the nginxinc/kubernetes-ingress Ingress Controller its Docker image is published on [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/) and available as *nginx/nginx-ingress*.

## The Key Differences

The table below summarizes the key difference between nginxinc/kubernetes-ingress and kubernetes/ingress-nginx Ingress Controllers. Note that the table has two columns for the nginxinc/kubernetes-ingress Ingress Controller, as it can be used both with NGINX and NGINX Plus. For more information about nginxinc/kubernetes-ingress with NGINX Plus, read the [NGINX Ingress Controller with NGINX Plus](/nginx-ingress-controller/intro/nginx-plus) documentation.

{{% table %}}
| Aspect or Feature | kubernetes/ingress-nginx | nginxinc/kubernetes-ingress with NGINX | nginxinc/kubernetes-ingress with NGINX Plus |
| --- | --- | --- | --- |
| **Fundamental** |
| Authors | Kubernetes community | NGINX Inc and community |  NGINX Inc and community |
| NGINX version | [Custom](https://github.com/kubernetes/ingress-nginx/tree/main/images/nginx) NGINX build that includes several third-party modules | NGINX official mainline [build](https://github.com/nginxinc/docker-nginx) | NGINX Plus |
| Commercial support | N/A | N/A | Included |
| **Load balancing configuration via the Ingress resource** |
| Merging Ingress rules with the same host | Supported | Supported via [Mergeable Ingresses](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/mergeable-ingress-types) | Supported via [Mergeable Ingresses](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/mergeable-ingress-types) |
| HTTP load balancing extensions - Annotations | See the [supported annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/) | See the [supported annotations](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/) | See the [supported annotations](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/)|
| HTTP load balancing extensions -- ConfigMap | See the [supported ConfigMap keys](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/) | See the [supported ConfigMap keys](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/) | See the [supported ConfigMap keys](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/) |
| TCP/UDP | Supported via a ConfigMap | Supported via custom resources | Supported via custom resources |
| Websocket  | Supported | Supported via an [annotation](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/websocket) | Supported via an [annotation](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/websocket) |
| TCP SSL Passthrough | Supported via a ConfigMap | Supported via custom resources | Supported via custom resources |
| JWT validation | Not supported | Not supported | Supported |
| Session persistence | Supported via a third-party module | Not supported | Supported |
| Canary testing (by header, cookie, weight) | Supported via annotations | Supported via custom resources | Supported via custom resources |
| Configuration templates *1 | See the [template](https://github.com/kubernetes/ingress-nginx/blob/main/rootfs/etc/nginx/template/nginx.tmpl) | See the [templates](../internal/configs/version1) | See the [templates](../internal/configs/version1) |
| **Load balancing configuration via Custom Resources** |
| HTTP load balancing | Not supported | See [VirtualServer and VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/) resources | See [VirtualServer and VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/) resources |
| TCP/UDP load balancing | Not supported | See [TransportServer](https://docs.nginx.com/nginx-ingress-controller/configuration/transportserver-resource/) resource | See [TransportServer](https://docs.nginx.com/nginx-ingress-controller/configuration/transportserver-resource/) resource |
| TCP SSL Passthrough load balancing | Not supported | See [TransportServer](https://docs.nginx.com/nginx-ingress-controller/configuration/transportserver-resource/) resource | See [TransportServer](https://docs.nginx.com/nginx-ingress-controller/configuration/transportserver-resource/) resource |
| **Deployment** |
| Command-line arguments *2 | See the [arguments](https://kubernetes.github.io/ingress-nginx/user-guide/cli-arguments/) | See the [arguments](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/) | See the [arguments](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/) |
| TLS certificate and key for the default server | Required as a command-line argument/ auto-generated | Required as a command-line argument | Required as a command-line argument |
| Helm chart | Supported | Supported | Supported |
| Operator | Not supported | Supported | Supported |
| **Operational** |
| Reporting the IP address(es) of the Ingress Controller into Ingress resources | Supported | Supported | Supported |
| Extended Status | Supported via a third-party module | Not supported | Supported |
| Prometheus Integration | Supported | Supported | Supported |
| Dynamic reconfiguration of endpoints (no configuration reloading) | Supported with a third-party Lua module | Not supported | Supported |
{{% /table %}}

Notes:

*1 -- The configuration templates that are used by the Ingress Controllers to generate NGINX configuration are different. As a result, for the same Ingress resource the generated NGINX configuration files are different from one Ingress Controller to the other, which in turn means that in some cases the behavior of NGINX can be different as well.

*2 -- Because the command-line arguments are different, it is not possible to use the same deployment manifest for deploying the Ingress Controllers.

## How to Swap an Ingress Controller

If you decide to swap an Ingress Controller implementation, be prepared to deal with the differences that were mentioned in the previous section. At minimum, you need to start using a different deployment manifest.
