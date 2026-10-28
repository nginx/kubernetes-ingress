# NGINX Ingress Controller

![logo](docs/img/logo.png)

[![Go Version](https://img.shields.io/github/go-mod/go-version/nginx/kubernetes-ingress?logo=go&logoColor=white)](https://github.com/nginx/kubernetes-ingress/blob/main/go.mod)
[![Stars](https://img.shields.io/github/stars/nginx/kubernetes-ingress?style=flat&logo=github)](https://github.com/nginx/kubernetes-ingress/stargazers)
[![Forks](https://img.shields.io/github/forks/nginx/kubernetes-ingress?style=flat&logo=github)](https://github.com/nginx/kubernetes-ingress/forks)
[![Latest Release](https://img.shields.io/github/v/release/nginx/kubernetes-ingress?logo=github&sort=semver)](https://github.com/nginx/kubernetes-ingress/releases/latest)
[![Contributors](https://img.shields.io/github/contributors/nginx/kubernetes-ingress?logo=github)](https://github.com/nginx/kubernetes-ingress/graphs/contributors)
[![Docker Pulls](https://img.shields.io/docker/pulls/nginx/nginx-ingress?logo=docker&logoColor=white)](https://hub.docker.com/r/nginx/nginx-ingress)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nginx-ingress)](https://artifacthub.io/packages/container/nginx-ingress/kubernetes-ingress)
[![Go Reference](https://pkg.go.dev/badge/github.com/nginx/kubernetes-ingress.svg)](https://pkg.go.dev/github.com/nginx/kubernetes-ingress)
[![codecov](https://codecov.io/gh/nginx/kubernetes-ingress/branch/main/graph/badge.svg?token=snCn7Y0zC7)](https://codecov.io/gh/nginx/kubernetes-ingress)
[![OpenSSFScorecard](https://api.securityscorecards.dev/projects/github.com/nginx/kubernetes-ingress/badge)](https://scorecard.dev/viewer/?uri=github.com/nginx/kubernetes-ingress)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Commercial Support](https://badgen.net/badge/support/commercial/green?icon=awesome)

[![Open Issues](https://img.shields.io/github/issues/nginx/kubernetes-ingress?logo=github)](https://github.com/nginx/kubernetes-ingress/issues)
[![Closed Issues](https://img.shields.io/github/issues-closed/nginx/kubernetes-ingress?logo=github)](https://github.com/nginx/kubernetes-ingress/issues?q=is%3Aissue+is%3Aclosed)
[![Open PRs](https://img.shields.io/github/issues-pr/nginx/kubernetes-ingress?logo=github)](https://github.com/nginx/kubernetes-ingress/pulls)

[![K8s](https://img.shields.io/badge/Website-kubernetes.nginx.org-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.nginx.org/)
[![Community Forum](https://img.shields.io/badge/Community_Forum-Join_us!-009639?logo=nginx&logoColor=white)](https://community.nginx.org)
[![Forum Topics](https://img.shields.io/discourse/topics?server=https%3A%2F%2Fcommunity.nginx.org&logo=nginx&label=forum)](https://community.nginx.org)
[![Forum Users](https://img.shields.io/discourse/users?server=https%3A%2F%2Fcommunity.nginx.org&logo=nginx&label=forum)](https://community.nginx.org)

**A production-grade Ingress Controller for Kubernetes, powered by NGINX or NGINX Plus.**

This repo provides an implementation of an Ingress Controller for NGINX and NGINX Plus from the people behind NGINX.

---

- [Why NGINX Ingress Controller?](#why-nginx-ingress-controller)
- [Features](#features)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Docker Images](#docker-images)
- [Releases](#releases)
- [Community](#community)
- [License](#license)
- [Support](#support)

---

## Why NGINX Ingress Controller?

NGINX Ingress Controller manages traffic into your Kubernetes cluster — routing HTTP, HTTPS, TCP, UDP, and gRPC to your
services based on rules you define. Built by the team behind NGINX, it gives you the reliability and performance of
NGINX with native Kubernetes integration.

> **Note**: Coming from the community-supported [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx) controller? Check out the [NGINX Kubernetes Hub](https://kubernetes.nginx.org) for details on how to migrate to the NGINX Ingress Controller.

## Features

- **Content-based routing** — Host and path-based routing via standard Ingress resources
- **TLS/SSL termination** — Automatic certificate handling per hostname
- **Advanced traffic management** — Traffic splitting, A/B testing, and canary deployments via [VirtualServer/VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/) CRDs
- **TCP/UDP/gRPC load balancing** — Via [TransportServer](https://docs.nginx.com/nginx-ingress-controller/configuration/transportserver-resource/) CRD
- **Security policies** — Rate limiting, JWT auth, WAF (via F5 WAF for NGINX), mTLS, OIDC, and more
- **Prometheus metrics** — Built-in monitoring and observability
- **Highly configurable** — [Annotations](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/), [ConfigMap](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/), and CRDs for fine-grained control
- **Commercial support** — Available for NGINX Plus users

## Quick Start

### Install with Helm (recommended)

```bash
helm repo add nginx-ingress https://helm.nginx.com/stable
helm repo update
helm install nginx-ingress nginx-ingress/nginx-ingress --namespace nginx-ingress --create-namespace
```

### Install with Manifests

> **Note**: Replace `v5.7.0` in the commands below with the [latest release tag](https://github.com/nginx/kubernetes-ingress/releases/latest).

```shell
# Install the Custom Resource Definitions (required for the default configuration)
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deploy/crds.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deployments/common/ns-and-sa.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deployments/rbac/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deployments/common/nginx-config.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deployments/deployment/nginx-ingress.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deployments/service/loadbalancer.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/deployments/common/ingress-class.yaml
```

**[Full Installation Guide →](https://docs.nginx.com/nginx-ingress-controller/install/)**

### Try It Out

Once installed, deploy a sample application:

```bash
# Deploy the Cafe example app
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/examples/ingress-resources/complete-example/cafe.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/examples/ingress-resources/complete-example/cafe-secret.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.7.0/examples/ingress-resources/complete-example/cafe-ingress.yaml
```

See more [examples](https://github.com/nginx/kubernetes-ingress/tree/main/examples) to explore all capabilities.

## Documentation

| Resource | Link |
| --- | --- |
| Full documentation | [docs.nginx.com/nginx-ingress-controller](https://docs.nginx.com/nginx-ingress-controller/) |
| Configuration examples | [Examples](https://docs.nginx.com/nginx-ingress-controller/configuration/configuration-examples/) |
| NGINX Plus features | [NGINX Plus overview](https://docs.nginx.com/nginx-ingress-controller/overview/nginx-plus/) |
| Helm chart | [charts/nginx-ingress](https://github.com/nginx/kubernetes-ingress/tree/main/charts/nginx-ingress) |

## Docker Images

The latest stable release is [5.7.0](https://github.com/nginx/kubernetes-ingress/releases/tag/v5.7.0). For production
use, we recommend that you choose the latest stable release.

| Registry | Link |
| --- | --- |
| Docker Hub | [nginx/nginx-ingress](https://hub.docker.com/r/nginx/nginx-ingress/) |
| GitHub Container Registry | [ghcr.io/nginx/kubernetes-ingress](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) |
| Amazon ECR Public Gallery | [public.ecr.aws/nginx/nginx-ingress](https://gallery.ecr.aws/nginx/nginx-ingress) |
| Quay.io | [quay.io/nginx/nginx-ingress](https://quay.io/repository/nginx/nginx-ingress) |
| F5 Container Registry (NGINX Plus) | [See registry docs](https://docs.nginx.com/nginx-ingress-controller/install/images/registry-download/) |

You can also [build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/).

### Container images & installation resources

| Version | Description | Image for NGINX | Image for NGINX Plus | Installation Manifests and Helm Chart | Documentation and Examples |
| ------- | ----------- | --------------- | -------------------- | --------------------------------------- | -------------------------- |
| Latest stable release | For production use | Use the 5.7.0 images from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress) or [build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/). | Use the 5.7.0 images from the [F5 Container Registry](https://docs.nginx.com/nginx-ingress-controller/install/images/registry-download/) or [Build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build). | [Manifests](https://github.com/nginx/kubernetes-ingress/tree/v5.7.0/deployments). [Helm chart](https://github.com/nginx/kubernetes-ingress/tree/v5.7.0/charts/nginx-ingress). | [Documentation](https://docs.nginx.com/nginx-ingress-controller/). [Examples](https://docs.nginx.com/nginx-ingress-controller/configuration/configuration-examples/). |
| Edge/Nightly | For testing and experimenting | Use the edge or nightly images from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress) or [build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/). | [Build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/). | [Manifests](https://github.com/nginx/kubernetes-ingress/tree/main/deployments). [Helm chart](https://github.com/nginx/kubernetes-ingress/tree/main/charts/nginx-ingress). | [Documentation](https://docs.nginx.com/nginx-ingress-controller). [Examples](https://github.com/nginx/kubernetes-ingress/tree/main/examples). |

## Releases

The latest stable release is **[5.7.0](https://github.com/nginx/kubernetes-ingress/releases/tag/v5.7.0)**. For
production use, we recommend the latest stable release.

The **edge** version is built from the [latest commit](https://github.com/nginx/kubernetes-ingress/commits/main) on
`main` and is useful for testing new features.

### LTS Releases

LTS (Long Term Support) releases receive extended maintenance, including critical bug fixes and security patches, for customers who need stability over an extended period. LTS images are NGINX Plus only.

| LTS Release | Base Version | Release Date | Tag |
| --- | --- | ------------- | --- |
| 2026 LTS r9 | 5.4.3 | 14 Oct 2026 | `2026-lts-r9` |

LTS images are available from the following registries:

| Registry | Link |
| --- | --- |
| F5 Container Registry | [See registry docs](https://docs.nginx.com/nginx-ingress-controller/lts/install/images/registry-download/) |

### SBOM (Software Bill of Materials)

We generate SBOMs for the binaries and the Docker images.

**Binaries**: Available on the [releases page](https://github.com/nginx/kubernetes-ingress/releases) in SPDX format, generated using [syft](https://github.com/anchore/syft).

**Docker Images**: Available in [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress) as attestations in the image manifest.

Example — retrieve and analyze the SBOM for `linux/amd64`:

```console
docker buildx imagetools inspect nginx/nginx-ingress:edge --format '{{ json (index .SBOM "linux/amd64").SPDX }}' | grype
```

## Community

We'd love to hear from you! Here's how to get involved:

- **[Upcoming Events](https://community.nginx.org/upcoming-events/month)**
- **[Community Forum](https://community.nginx.org)** — Questions and discussion about NGINX Ingress Controller
- **[Issues](https://github.com/nginx/kubernetes-ingress/issues)** — Report bugs or request features
- **[Discussions](https://github.com/nginx/kubernetes-ingress/discussions)** — Talk about NGINX Ingress Controller, share ideas, and connect with other users
- **[Contributing Guide](CONTRIBUTING.md)** — Learn how to contribute
- **[Code of Conduct](CODE_OF_CONDUCT.md)** — Our commitment to a welcoming community **PLEASE READ BEFORE SUBMITTING**
- **[Security Policy](SECURITY.md)** — How to report security issues
- **Community Calls** — Every other Monday at 16:00 GMT ([convert to your timezone](https://dateful.com/convert/gmt?t=16))

### Join The Next Community Call

We value community input so please join our community call on the first Tuesday of each month. At these calls, we discuss submissions made by community members, answer your questions and hear your feedback. We would love to see you there!

See all of our scheduled calls along with other events [on our calendar](https://community.nginx.org/upcoming-events).

#### Meeting Details

**Zoom**: [NGINX Ingress Controller - Community Call](https://f5.zoom.us/j/98544055687?pwd=q4sGaaeWM0DawJTePBGbCngtfLJxgq.1&from=addon)

**Meeting ID:** `985 4405 5687`

**Passcode:** `982193`

**When**: 16:00 Irish Time / [Convert to your timezone](https://dateful.com/convert/ireland?t=16), first Tuesday of every month.

| **Community Call Dates** |
| ------------------------ |
| **2026-11-03**           |
| **2026-12-01**           |
| **2027-01-05**           |
| **2027-02-02**           |
| **2027-03-02**           |
| **2027-04-06**           |

You can also join the [NGINX Community Forum](https://community.nginx.org) to chat about the NGINX Ingress Controller.

## License

[Apache License 2.0](LICENSE)

## Support

For NGINX Plus customers, NGINX Ingress Controller (when used with NGINX Plus) is covered by the support contract.
