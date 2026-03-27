---
title: Technical Specifications
description: "NGINX Ingress Controller Technical Specifications."
weight: 200
doctypes: ["concept"]
toc: true
docs: "DOCS-617"
---


## Supported NGINX Ingress Controller Versions

We recommend upgrading to the latest release of the NGINX Ingress Controller. We provide software updates for the most recent release. We provide technical support for F5 customers who are using the most recent version of NGINX Ingress Controller, and any version released within two years of the current release.

Release 3.0.0 provides support for the `discovery.k8s.io/v1` API version of EndpointSlice, available from Kubernetes 1.21 onwards.
Release 2.4.2 is compatible with the Kubernetes Ingress v1 API, available in Kubernetes 1.19 and later.
Release 1.12 supports the Ingress v1beta1 API and continues to receive security fixes to support environments running Kubernetes versions older than 1.19. The v1beta1 Ingress API was deprecated in Kubernetes release 1.19, and removed in the Kubernetes 1.22.

## Supported Kubernetes Versions

We explicitly test NGINX Ingress Controller on a range of Kubernetes platforms for each release, and we list them in the [release notes]({{< relref "/releases.md" >}}). We provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider, and which passes the [Kubernetes conformance tests](https://www.cncf.io/certification/software-conformance/).

{{< bootstrap-table "table table-bordered table-striped table-responsive" >}}
| NIC Version | Supported Kubernetes Version | NIC Helm Chart Version | NIC Operator Version | NGINX / NGINX Plus version |
| --- | --- | --- | --- | --- |
| 3.3.2 | 1.29 - 1.23 | 1.0.2 | 2.1.0 | 1.25.4 / R31 P1 |
| 3.3.2 | 1.28 - 1.22 | 1.0.2 | 2.0.2 | 1.25.3 / R30 |
| 3.2.1 | 1.27 - 1.22 | 0.18.1 | 1.5.1 | 1.25.2 / R30 |
| 3.1.1 | 1.26 - 1.22 | 0.17.1 | 1.4.2 | 1.23.4 / R29 |
| 3.0.2 | 1.26 - 1.21 | 0.16.2 | 1.3.1 | 1.23.3 / R28 |
| 2.4.2 | 1.25 - 1.19 | 0.15.2 | 1.2.1 | 1.23.2 / R28 |
| 2.3.1 | 1.24 - 1.19 | 0.14.1 | 1.1.0 | 1.23.1 / R27 |
| 2.2.2 | 1.23 - 1.19 | 0.13.2 | 1.0.0 | 1.21.6 / R26 |
| 2.1.2 | 1.23 - 1.19 | 0.12.1 | 0.5.1 | 1.21.6 / R26 |
| 2.0.3 | 1.22 - 1.19 | 0.11.3 | 0.4.0 | 1.21.3 / R25 |
| 1.12.4 | 1.21 - 1.16 | 0.10.4 | 0.3.0 | 1.21.6 / R26 |
| 1.11.3 | 1.20 - 1.16 | 0.9.0 | 0.2.0 | 1.21.0 / R23 P1 |
| 1.10.1 | 1.19 - 1.16 | 0.8.0 | 0.1.0 | 1.19.8 / R23 |
| 1.9.1 | 1.18 - 1.16 | 0.7.1 | 0.0.7 | 1.19.3 / R22 |
| 1.8.1 |  | 0.6.0 | 0.0.6 | 1.19.2 / R22 |
| 1.7.2 |  | 0.5.1 | 0.0.4 | 1.19.0 / R22 |
| 1.6.3 |  | 0.4.3 | -- | 1.17.9 / R21 |
{{% /bootstrap-table %}}

## Supported Docker Images

We provide the following Docker images, which include NGINX or NGINX Plus bundled with the Ingress Controller binary.

### Images with NGINX

_All images include NGINX 1.25.4._

{{< bootstrap-table "table table-bordered table-responsive" >}}
|<div style="width:200px">Name</div> | <div style="width:100px">Base image</div> | <div style="width:200px">Third-party modules</div> | DockerHub image | Architectures |
| ---| --- | --- | --- | --- |
|Alpine-based image | ``nginx:1.25.4-alpine``,<br>based on on ``alpine:3.18`` | NGINX OpenTracing module<br><br>OpenTracing library<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | ``nginx/nginx-ingress:3.3.2-alpine`` | arm/v7<br>arm64<br>amd64<br>ppc64le<br>s390x |
|Debian-based image | ``nginx:1.25.4``,<br>based on on ``debian:12-slim`` | NGINX OpenTracing module<br><br>OpenTracing library<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | ``nginx/nginx-ingress:3.3.2`` | arm/v7<br>arm64<br>amd64<br>ppc64le<br>s390x |
|Ubi-based image | ``nginxcontrib/nginx:1.25.4-ubi``,<br>based on on ``redhat/ubi9-minimal`` |  | ``nginx/nginx-ingress:3.3.2-ubi`` | arm64<br>amd64<br>ppc64le<br>s390x |
{{% /bootstrap-table %}}

### Images with NGINX Plus

_NGINX Plus images include NGINX Plus R31._

#### **F5 Container registry**

NGINX Plus images are available through the F5 Container registry `private-registry.nginx.com` - see [Getting the NGINX Ingress Controller Image with JWT]({{<relref "/installation/nic-images/using-the-jwt-token-docker-secret.md">}}) and [Getting the F5 Registry NGINX Ingress Controller Image]({{<relref "/installation/nic-images/pulling-ingress-controller-image.md">}}).

{{< bootstrap-table "table table-striped table-bordered table-responsive" >}}
|<div style="width:200px">Name</div> | <div style="width:100px">Base image</div> | <div style="width:200px">Third-party modules</div> | F5 Container Registry Image | Architectures |
| ---| ---| --- | --- | --- |
|Alpine-based image | ``alpine:3.18`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic/nginx-plus-ingress:3.3.2-alpine` | arm64<br>amd64 |
|Alpine-based image with FIPS inside | ``alpine:3.18`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog<br><br>FIPS module and OpenSSL configuration | `nginx-ic/nginx-plus-ingress:3.3.2-alpine-fips` | arm64<br>amd64 |
|Debian-based image | ``debian:12-slim`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic/nginx-plus-ingress:3.3.2` | arm64<br>amd64 |
|Debian-based image with NGINX App Protect WAF | ``debian:11-slim`` | NGINX App Protect WAF<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-nap/nginx-plus-ingress:3.3.2` | amd64 |
|Debian-based image with NGINX App Protect DoS | ``debian:11-slim`` | NGINX App Protect DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-dos/nginx-plus-ingress:3.3.2` | amd64 |
|Debian-based image with NGINX App Protect WAF and DoS | ``debian:11-slim`` | NGINX App Protect WAF and DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-nap-dos/nginx-plus-ingress:3.3.2` | amd64 |
|Ubi-based image | ``redhat/ubi9-minimal`` | NGINX Plus JavaScript module | `nginx-ic/nginx-plus-ingress:3.3.2-ubi` | arm64<br>amd64<br>s390x |
|Ubi-based image with NGINX App Protect WAF | ``redhat/ubi8`` | NGINX App Protect WAF and NGINX Plus JavaScript module | `nginx-ic-nap/nginx-plus-ingress:3.3.2-ubi` | amd64 |
|Ubi-based image with NGINX App Protect DoS | ``redhat/ubi8`` | NGINX App Protect DoS and NGINX Plus JavaScript module | `nginx-ic-dos/nginx-plus-ingress:3.3.2-ubi` | amd64 |
|Ubi-based image with NGINX App Protect WAF and DoS | ``redhat/ubi8`` | NGINX App Protect WAF and DoS<br><br>NGINX Plus JavaScript module | `nginx-ic-nap-dos/nginx-plus-ingress:3.3.2-ubi` | amd64 |
{{% /bootstrap-table %}}

#### **AWS Marketplace**

We also provide NGINX Plus images through the AWS Marketplace. Please see [Using the AWS Marketplace Ingress Controller Image]({{< relref "/installation/nic-images/using-aws-marketplace-image.md" >}}) for details on how to set up the required IAM resources in your EKS cluster.

{{< bootstrap-table "table table-striped table-bordered table-responsive" >}}
|<div style="width:200px">Name</div> | <div style="width:100px">Base image</div> | <div style="width:200px">Third-party modules</div> | AWS Marketplace Link | Architectures |
| ---| ---| --- | --- | --- |
|Debian-based image | ``debian:12-slim`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | [F5 NGINX Ingress Controller](https://aws.amazon.com/marketplace/pp/prodview-fx3faxl7zqeau) | amd64 |
|Debian-based image with NGINX App Protect WAF | ``debian:11-slim`` | NGINX App Protect WAF<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | [F5 NGINX Ingress Controller with F5 NGINX App Protect WAF](https://aws.amazon.com/marketplace/pp/prodview-vnrnxbf6u3nra) | amd64 |
|Debian-based image with NGINX App Protect DoS | ``debian:11-slim`` | NGINX App Protect DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | [F5 NGINX Ingress Controller with F5 NGINX App Protect WAF and DoS](https://aws.amazon.com/marketplace/pp/prodview-yltaqwzwrnhco) | amd64 |
|Debian-based image with NGINX App Protect WAF and DoS | ``debian:11-slim`` | NGINX App Protect WAF and DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | [F5 NGINX Ingress Controller with F5 NGINX App Protect DoS](https://aws.amazon.com/marketplace/pp/prodview-sghjw2csktega) | amd64 |
{{% /bootstrap-table %}}

#### **Google Cloud Marketplace**
We also provide NGINX Plus images through the Google Cloud Marketplace. Please see [Using the GCP Marketplace NGINX Ingress Controller Image]({{< relref "/installation/nic-images/using-gcp-marketplace-package.md" >}}) for details on how to use them.

{{< bootstrap-table "table table-striped table-bordered table-responsive" >}}
|<div style="width:200px">Name</div> | <div style="width:100px">Base image</div> | <div style="width:200px">Third-party modules</div> | GCP Marketplace Link | Architectures |
| ---| ---| --- | --- | --- |
|Debian-based image | ``debian:11-slim`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | [F5 NGINX Ingress Controller](https://console.cloud.google.com/marketplace/product/f5-7626-networks-public/nginx-ingress-plus) | amd64 |
|Debian-based image with NGINX App Protect DoS | ``debian:11-slim`` | NGINX App Protect DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | [F5 NGINX Ingress Controller w/ F5 NGINX App Protect DoS](https://console.cloud.google.com/marketplace/product/f5-7626-networks-public/nginx-ingress-plus-dos) | amd64 |
{{% /bootstrap-table %}}

### Custom Images

You can customize an existing Dockerfile or use it as a reference to create a new one, which is necessary for the following cases:

- Choosing a different base image.
- Installing additional NGINX modules.

## Supported Helm Versions

NGINX Ingress Controller can be [installed]({{< relref "/installation/installing-nic/installation-with-helm.md" >}}) using Helm 3.0 or later.
