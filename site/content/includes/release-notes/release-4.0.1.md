---
docs: DOCS-616
---

07 Feb 2025

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [7295](https://github.com/nginx/kubernetes-ingress/pull/7295) Clean up and fix for NIC Pod failing to bind when NGINX exits unexpectedly

### <i class="fa-solid fa-box"></i> Helm Chart
{{< warning >}} From this release onwards, the Helm chart location has changed from `oci://ghcr.io/nginxinc/charts/nginx-ingress` to `oci://ghcr.io/nginx/charts/nginx-ingress`. {{< /warning >}}
- [7188](https://github.com/nginx/kubernetes-ingress/pull/7188) Correct typo in helm lease annotations template

### <i class="fa-solid fa-upload"></i> Dependencies
- [7301](https://github.com/nginx/kubernetes-ingress/pull/7301), [7307](https://github.com/nginx/kubernetes-ingress/pull/7307) & [7310](https://github.com/nginx/kubernetes-ingress/pull/7310) Update to nginx 1.27.4
- [7163](https://github.com/nginx/kubernetes-ingress/pull/7163) Bump Go version to 1.23.5
- [7024](https://github.com/nginx/kubernetes-ingress/pull/7024), [7061](https://github.com/nginx/kubernetes-ingress/pull/7061), [7113](https://github.com/nginx/kubernetes-ingress/pull/7113), [7145](https://github.com/nginx/kubernetes-ingress/pull/7145), [7148](https://github.com/nginx/kubernetes-ingress/pull/7148), [7154](https://github.com/nginx/kubernetes-ingress/pull/7154), [7164](https://github.com/nginx/kubernetes-ingress/pull/7164), [7229](https://github.com/nginx/kubernetes-ingress/pull/7229), [7265](https://github.com/nginx/kubernetes-ingress/pull/7265), [7250](https://github.com/nginx/kubernetes-ingress/pull/7250), [7296](https://github.com/nginx/kubernetes-ingress/pull/7296) & [7321](https://github.com/nginx/kubernetes-ingress/pull/7321) Bump Go dependencies
- [7012](https://github.com/nginx/kubernetes-ingress/pull/7012), [7022](https://github.com/nginx/kubernetes-ingress/pull/7022), [7028](https://github.com/nginx/kubernetes-ingress/pull/7028), [7144](https://github.com/nginx/kubernetes-ingress/pull/7144), [7152](https://github.com/nginx/kubernetes-ingress/pull/7152), [7155](https://github.com/nginx/kubernetes-ingress/pull/7155), [7181](https://github.com/nginx/kubernetes-ingress/pull/7181), [7267](https://github.com/nginx/kubernetes-ingress/pull/7267), [7302](https://github.com/nginx/kubernetes-ingress/pull/7302), [7304](https://github.com/nginx/kubernetes-ingress/pull/7304) & [7320](https://github.com/nginx/kubernetes-ingress/pull/7320) Bump Docker dependencies

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 4.0.1 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=4.0.1),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 4.0.1 images from the F5 Container registry or build your own image using the 4.0.1 source code
- For Helm, use version 2.0.1 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.32.
