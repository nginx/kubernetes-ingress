<!-- markdownlint-disable-next-line first-line-h1 -->

# NGINX Ingress Controller

![logo](docs/img/logo.png)

**A production-grade Ingress Controller for Kubernetes, powered by NGINX or NGINX Plus.**

[![Latest Release](https://img.shields.io/github/v/release/nginx/kubernetes-ingress?logo=github&sort=semver)](https://github.com/nginx/kubernetes-ingress/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/nginx/nginx-ingress?logo=docker&logoColor=white)](https://hub.docker.com/r/nginx/nginx-ingress)
[![Go Report Card](https://goreportcard.com/badge/github.com/nginx/kubernetes-ingress)](https://goreportcard.com/report/github.com/nginx/kubernetes-ingress)
[![Regression](https://github.com/nginx/kubernetes-ingress/actions/workflows/regression.yml/badge.svg?event=schedule)](https://github.com/nginx/kubernetes-ingress/actions/workflows/regression.yml?query=event%3Aschedule)
[![codecov](https://codecov.io/gh/nginx/kubernetes-ingress/branch/main/graph/badge.svg?token=snCn7Y0zC7)](https://codecov.io/gh/nginx/kubernetes-ingress)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSFScorecard](https://api.securityscorecards.dev/projects/github.com/nginx/kubernetes-ingress/badge)](https://scorecard.dev/viewer/?uri=github.com/nginx/kubernetes-ingress)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nginx-ingress)](https://artifacthub.io/packages/container/nginx-ingress/kubernetes-ingress)

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

> **Note**: Replace `v5.5.0` in the commands below with the [latest release tag](https://github.com/nginx/kubernetes-ingress/releases/latest).

```shell
    # Install the Custom Resource Definitions (required for the default configuration)
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deploy/crds.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deployments/common/ns-and-sa.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deployments/rbac/rbac.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deployments/common/nginx-config.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deployments/deployment/nginx-ingress.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deployments/service/loadbalancer.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/deployments/common/ingress-class.yaml
```

**[Full Installation Guide →](https://docs.nginx.com/nginx-ingress-controller/install/)**

### Try It Out

Once installed, deploy a sample application:

```bash
# Deploy the Cafe example app
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/examples/ingress-resources/complete-example/cafe.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/examples/ingress-resources/complete-example/cafe-secret.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.5.0/examples/ingress-resources/complete-example/cafe-ingress.yaml
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

Official NGINX Ingress Controller images are available from multiple registries:

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
| --- | --- | --- | --- | --- | --- |
| Latest stable release | For production use | Use the 5.5.0 images from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress) or [build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/). | Use the 5.5.0 images from the [F5 Container Registry](https://docs.nginx.com/nginx-ingress-controller/install/images/registry-download/) or [Build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build). | [Manifests](https://github.com/nginx/kubernetes-ingress/tree/v5.5.0/deployments). [Helm chart](https://github.com/nginx/kubernetes-ingress/tree/v5.5.0/charts/nginx-ingress). | [Documentation](https://docs.nginx.com/nginx-ingress-controller/). [Examples](https://docs.nginx.com/nginx-ingress-controller/configuration/configuration-examples/). |
| Edge/Nightly | For testing and experimenting | Use the edge or nightly images from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress) or [build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/). | [Build your own image](https://docs.nginx.com/nginx-ingress-controller/install/build/). | [Manifests](https://github.com/nginx/kubernetes-ingress/tree/main/deployments). [Helm chart](https://github.com/nginx/kubernetes-ingress/tree/main/charts/nginx-ingress). | [Documentation](https://docs.nginx.com/nginx-ingress-controller). [Examples](https://github.com/nginx/kubernetes-ingress/tree/main/examples). |

## Releases

The latest stable release is **[5.5.0](https://github.com/nginx/kubernetes-ingress/releases/tag/v5.5.0)**. For
production use, we recommend the latest stable release.

The **edge** version is built from the [latest commit](https://github.com/nginx/kubernetes-ingress/commits/main) on
`main` and is useful for testing new features.

### LTS Releases

LTS (Long Term Support) releases receive extended maintenance, including critical bug fixes and security patches, for customers who need stability over an extended period. LTS images are NGINX Plus only.

| LTS Release | Base Version | Release Date | Tag |
| --- | --- | ------------- | --- |
| 2026 LTS R1 | 5.4.3 | 4 June 2026 | `2026-lts-r1` |

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

- **[Community Forum](https://community.nginx.org)** — Ask questions and share knowledge
- **[Issues](https://github.com/nginx/kubernetes-ingress/issues)** — Report bugs or request features
- **[Discussions](https://github.com/nginx/kubernetes-ingress/discussions)** — Talk about NGINX Ingress Controller, share ideas, and connect with other users
- **[Contributing Guide](CONTRIBUTING.md)** — Learn how to contribute
- **[Code of Conduct](CODE_OF_CONDUCT.md)** — Our commitment to a welcoming community
- **[Security Policy](SECURITY.md)** — How to report security issues
- **Community Calls** — Every other Monday at 16:00 GMT ([convert to your timezone](https://dateful.com/convert/gmt?t=16))

### Upcoming community call dates

| **Community Call Dates** |
| --- |
| **2026-07-13** |
| **2026-07-27** |
| **2026-08-10** |
| **2026-08-24** |
| **2026-09-07** |
| **2026-09-21** |
| **2026-10-05** |
| **2026-10-19** |

Join via **[Zoom](https://f5.zoom.us/j/98544055687?pwd=q4sGaaeWM0DawJTePBGbCngtfLJxgq.1&from=addon)** — Meeting ID: `985 4405 5687`, Passcode: `982193`

## License

[Apache License 2.0](LICENSE)

## Support

For NGINX Plus customers, NGINX Ingress Controller (when used with NGINX Plus) is covered by the support contract.
