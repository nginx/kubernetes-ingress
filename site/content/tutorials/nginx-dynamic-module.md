---
docs: DOCS-1231
doctypes:
- concept
title: Using NGINX Ingress Controller with NGINX Dynamic Modules
toc: true
weight: 1800
---

This document describes how to use NGINX Ingress Controller with NGINX dynamic modules.

## Overview

NGINX Plus has several Dynamic Modules that can add additional features and capabilities to NGINX, which NGINX Ingress Controller can also use. To do this, you must modify your NGINX Ingress Controller image to add a module, then load the updated image.

For more information about Dynamic Modules, you can read [the documentation for NGINX Plus](https://docs.nginx.com/nginx/admin-guide/dynamic-modules/dynamic-modules/).

There are two steps involved:

1. Updating the Dockerfile and building the image with the dynamic module.
1. Loading the module in NGINX Ingress Controler using a `configmap`

## Updating the Image

To build a custom NGINX Ingress Controller image with specific modules, you must modify the `Dockerfile` located in the `build` directory of the code repository.

First, clone the NGINX Ingress Controller repository:

```shell
git clone git@github.com:nginx/kubernetes-ingress.git
```

Once you have cloned the repository, edit the `Dockerfile` located in the `build` directory.

In this example, we add the `Headers-more` dynamic module to the NGINX Ingress Controller image. We choose the `debian-plus` operating system: modify the entry for the system you are using.

```docker
FROM debian:12-slim AS debian-plus
ARG IC_VERSION
ARG NGINX_PLUS_VERSION
ARG BUILD_OS

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y ca-certificates gnupg curl apt-transport-https libcap2-bin \
	&& curl -fsSL https://cs.nginx.com/static/keys/nginx_signing.key | gpg --dearmor > /etc/apt/trusted.gpg.d/nginx_signing.gpg \
	&& curl -fsSL -o /etc/apt/apt.conf.d/90pkgs-nginx https://cs.nginx.com/static/files/90pkgs-nginx \
	&& DEBIAN_VERSION=$(awk -F '=' '/^VERSION_CODENAME=/ {print $2}' /etc/os-release) \
	&& printf "%s\n" "Acquire::https::pkgs.nginx.com::User-Agent \"k8s-ic-$IC_VERSION${BUILD_OS##debian-plus}-apt\";" >> /etc/apt/apt.conf.d/90pkgs-nginx \
	&& printf "%s\n" "deb https://pkgs.nginx.com/plus/${NGINX_PLUS_VERSION^^}/debian ${DEBIAN_VERSION} nginx-plus" > /etc/apt/sources.list.d/nginx-plus.list \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-plus nginx-plus-module-njs \
	&& apt-get purge --auto-remove -y apt-transport-https gnupg curl \
	&& rm -rf /var/lib/apt/lists/*
```

In the snippet above there is a line similar to the following, which you must modify to add a dynamic module to NGINX Ingress Controller.

```shell
apt-get install --no-install-recommends --no-install-suggests -y nginx-plus nginx-plus-module-njs
```

For this example, we add the `headers-more` module with the argument `nginx-plus-module-headers-more`. The updated line then looks like this:

```shell
apt-get install --no-install-recommends --no-install-suggests -y nginx-plus nginx-plus-module-njs nginx-plus-module-headers-more
```

## Loading Modules

Once the new NGINX Ingress module image has built successfully, the next step is to load the module into NGINX Ingress Controller when it is deployed into your Kubernetes cluster.

To do this, modify your NGINX Ingress Controller configuration to add the module into the `main` context, which can be done through both Manifest and Helm deployments.

{{<tabs name="install-methods">}}

{{%tab name="Helm"%}}

```yaml
config:
  name: nginx-ingress
  entries:
    main-snippets: load_module modules/ngx_http_headers_more_filder_module.so;
    http-snippets: underscores_in_headers on;
    lb-method: "least_time last_byte"
```

{{%/tab%}}

{{%tab name="Manifest"%}}

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-config
  namespace: nginx-ingress
data:
  main-snippets: |
    load_module modules/ngx_http_headers_more_filter_module.so;
```

{{%/tab%}}



{{</tabs>}}

NGINX Ingress Controller will load the `ngx_http_headers_more` module, which can then be verified by running `nginx -T` in the NGINX Ingress Controller pod:

```shell
kubectl exec -it -n nginx-ingress <nginx_ingress_pod> -- nginx -T
```

You should see the module in the `nginx -T` output, indicating it is now loaded in NGINX Ingress Controller.
