---
title: Technical specifications
toc: true
weight: 200
doctype: reference
product: NIC
docs: DOCS-617
---

This page describes technical specifications for F5 NGINX Ingress Controller, such as its version compatibility with Kubernetes and other NGINX software.

---

## Supported NGINX Ingress Controller versions

We recommend using the latest release of NGINX Ingress Controller. We provide software updates for the most recent release. We provide technical support for F5 customers who are using the most recent version of NGINX Ingress Controller, and any version released within two years of the current release.

- Release 3.0.0 provides support for the `discovery.k8s.io/v1` API version of EndpointSlice, available from Kubernetes 1.21 onwards.
- Release 2.4.2 is compatible with the Kubernetes Ingress v1 API, available in Kubernetes 1.19 and later.
- Release 1.12 supports the Ingress v1beta1 API and continues to receive security fixes to support environments running Kubernetes versions older than 1.19. The v1beta1 Ingress API was deprecated in Kubernetes release 1.19, and removed in the Kubernetes 1.22.

---

## Supported Kubernetes versions

We test NGINX Ingress Controller on a range of Kubernetes platforms for each release, and list them in the [release notes]({{< relref "/releases.md" >}}). We provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider, and that passes the [Kubernetes conformance tests](https://www.cncf.io/certification/software-conformance/).

{{< bootstrap-table "table table-bordered table-striped table-responsive" >}}
| NIC Version | Supported Kubernetes Version | NIC Helm Chart Version | NIC Operator Version | NGINX / NGINX Plus version |
| --- | --- | --- | --- | --- |
| {{< nic-version >}} | 1.25 - 1.32 | {{< nic-helm-version >}} | {{< nic-operator-version >}} | 1.27.4 / R33 P2 |
| 3.7.2 | 1.25 - 1.31 | 1.4.2 | 2.4.2 | 1.27.2 / R32 P1 |
| 3.6.2 | 1.25 - 1.31 | 1.3.2 | 2.3.2 | 1.27.1 / R32 P1 |
| 3.5.2 | 1.23 - 1.30 | 1.2.2 | 2.2.2 | 1.27.0 / R32 |
| 3.4.3 | 1.23 - 1.29 | 1.1.3 | 2.1.2 | 1.25.4 / R31 P1 |
| 3.3.2 | 1.22 - 1.28 | 1.0.2 | 2.0.2 | 1.25.3 / R30 |
| 3.2.1 | 1.22 - 1.27 | 0.18.1 | 1.5.1 | 1.25.2 / R30 |
| 3.1.1 | 1.22 - 1.26 | 0.17.1 | 1.4.2 | 1.23.4 / R29 |
| 3.0.2 | 1.21 - 1.26 | 0.16.2 | 1.3.1 | 1.23.3 / R28 |
{{% /bootstrap-table %}}

---

## Supported Docker images

We provide the following Docker images, which include NGINX or NGINX Plus bundled with the Ingress Controller binary.

### Images with NGINX

_All images include NGINX 1.27.4._

{{< bootstrap-table "table table-bordered table-responsive" >}}
|<div style="width:200px">Name</div> | <div style="width:100px">Base image</div> | <div style="width:200px">Third-party modules</div> | DockerHub image | Architectures |
| ---| --- | --- | --- | --- |
|Alpine-based image | ``nginx:1.27.4-alpine``,<br>based on on ``alpine:3.20`` | NGINX OpenTracing module<br><br>OpenTracing library<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | ``nginx/nginx-ingress:{{< nic-version >}}-alpine`` | arm/v7<br>arm64<br>amd64<br>ppc64le<br>s390x |
|Debian-based image | ``nginx:1.27.4``,<br>based on on ``debian:12-slim`` | NGINX OpenTracing module<br><br>OpenTracing library<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | ``nginx/nginx-ingress:{{< nic-version >}}`` | arm/v7<br>arm64<br>amd64<br>ppc64le<br>s390x |
|Ubi-based image | ``redhat/ubi9-minimal`` | | ``nginx/nginx-ingress:{{< nic-version >}}-ubi`` | arm64<br>amd64<br>ppc64le<br>s390x |
{{% /bootstrap-table %}}

---

### Images with NGINX Plus

_NGINX Plus images include NGINX Plus R33._

---

#### **F5 Container registry**

NGINX Plus images are available through the F5 Container registry `private-registry.nginx.com`, explained in the [Get the NGINX Ingress Controller image with JWT]({{<relref "/installation/nic-images/get-image-using-jwt.md">}}) and [Get the F5 Registry NGINX Ingress Controller image]({{<relref "/installation/nic-images/get-registry-image.md">}}) topics.

{{< bootstrap-table "table table-striped table-bordered table-responsive" >}}
|<div style="width:200px">Name</div> | <div style="width:100px">Base image</div> | <div style="width:200px">Third-party modules</div> | F5 Container Registry Image | Architectures |
| ---| ---| --- | --- | --- |
|Alpine-based image | ``alpine:3.20`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic/nginx-plus-ingress:{{< nic-version >}}-alpine` | arm64<br>amd64 |
|Alpine-based image with FIPS inside | ``alpine:3.20`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog<br><br>FIPS module and OpenSSL configuration | `nginx-ic/nginx-plus-ingress:{{< nic-version >}}-alpine-fips` | arm64<br>amd64 |
|Alpine-based image with NGINX App Protect WAF & FIPS inside | ``alpine:3.17`` | NGINX App Protect WAF<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog<br><br>FIPS module and OpenSSL configuration | `nginx-ic-nap/nginx-plus-ingress:{{< nic-version >}}-alpine-fips` | amd64 |
|Alpine-based image with NGINX App Protect WAF v5 & FIPS inside | ``alpine:3.17`` | NGINX App Protect WAF v5<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog<br><br>FIPS module and OpenSSL configuration | `nginx-ic-nap-v5/nginx-plus-ingress:{{< nic-version >}}-alpine-fips` | amd64 |
|Debian-based image | ``debian:12-slim`` | NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic/nginx-plus-ingress:{{< nic-version >}}` | arm64<br>amd64 |
|Debian-based image with NGINX App Protect WAF | ``debian:12-slim`` | NGINX App Protect WAF<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-nap/nginx-plus-ingress:{{< nic-version >}}` | amd64 |
|Debian-based image with NGINX App Protect WAF v5 | ``debian:12-slim`` | NGINX App Protect WAF v5<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-nap-v5/nginx-plus-ingress:{{< nic-version >}}` | amd64 |
|Debian-based image with NGINX App Protect DoS | ``debian:12-slim`` | NGINX App Protect DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-dos/nginx-plus-ingress:{{< nic-version >}}` | amd64 |
|Debian-based image with NGINX App Protect WAF and DoS | ``debian:12-slim`` | NGINX App Protect WAF and DoS<br><br>NGINX Plus JavaScript and OpenTracing modules<br><br>OpenTracing tracers for Jaeger<br><br>Zipkin and Datadog | `nginx-ic-nap-dos/nginx-plus-ingress:{{< nic-version >}}` | amd64 |
|Ubi-based image | ``redhat/ubi9-minimal`` | NGINX Plus JavaScript module | `nginx-ic/nginx-plus-ingress:{{< nic-version >}}-ubi` | arm64<br>amd64 |
|Ubi-based image with NGINX App Protect WAF | ``redhat/ubi9`` | NGINX App Protect WAF and NGINX Plus JavaScript module | `nginx-ic-nap/nginx-plus-ingress:{{< nic-version >}}-ubi` | amd64 |
|Ubi-based image with NGINX App Protect WAF v5 | ``redhat/ubi9`` | NGINX App Protect WAF v5 and NGINX Plus JavaScript module | `nginx-ic-nap-v5/nginx-plus-ingress:{{< nic-version >}}-ubi` | amd64 |
|Ubi-based image with NGINX App Protect DoS | ``redhat/ubi8`` | NGINX App Protect DoS and NGINX Plus JavaScript module | `nginx-ic-dos/nginx-plus-ingress:{{< nic-version >}}-ubi` | amd64 |
|Ubi-based image with NGINX App Protect WAF and DoS | ``redhat/ubi8`` | NGINX App Protect WAF and DoS<br><br>NGINX Plus JavaScript module | `nginx-ic-nap-dos/nginx-plus-ingress:{{< nic-version >}}-ubi` | amd64 |
{{% /bootstrap-table %}}

---

### Custom images

You can customize an existing Dockerfile or use it as a reference to create a new one, which is necessary when:

- Choosing a different base image.
- Installing additional NGINX modules.

---

## Supported Helm versions

NGINX Ingress Controller can be [installed]({{< relref "/installation/installing-nic/installation-with-helm.md" >}}) using Helm 3.0 or later.
