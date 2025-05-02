---
title: Create a license Secret 
toc: true
weight: 300
type: how-to
product: NIC
docs: DOCS-000
---

This document explains how to create and use a license secret for F5 NGINX Ingress Controller. 

# Overview

NGINX Plus Ingress Controller requires a valid JSON Web Token (JWT) to download the container image from the F5 registry. From version 4.0.0, this JWT token is also required to run NGINX Plus.

This requirement is part of F5’s broader licensing program and aligns with industry best practices. The JWT will streamline subscription renewals and usage reporting, helping you manage your NGINX Plus subscription more efficiently. The [telemetry](#telemetry) data we collect helps us improve our products and services to better meet your needs.

The JWT is required for validating your subscription and reporting telemetry data. For environments connected to the internet, telemetry is automatically sent to F5’s licensing endpoint.  In offline environments, telemetry is routed through [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager/). By default usage is reported every hour and also whenever NGINX is reloaded.

{{< note >}} Read the [subscription licenses topic](https://docs.nginx.com/solutions/about-subscription-licenses/#for-internet-connected-environments) for a list of IPs associated with F5's licensing endpoint (`product.connect.nginx.com`). {{</ note >}}

---

## Set up your NGINX Plus license 

### Download the JWT

{{< include "/installation/download-jwt.md" >}}

---

### Create the Secret 

The JWT needs to be configured before deploying NGINX Ingress Controller. The JWT will be stored in a Kubernetes Secret of type `nginx.com/license`, and can be created with the following command.

```shell
kubectl create secret generic license-token --from-file=license.jwt=<path-to-your-jwt> --type=nginx.com/license -n <Your Namespace> 
```
You can now delete the downloaded `.jwt` file.

{{< note >}}
The Secret needs to be in the same Namespace as the NGINX Ingress Controller Pod(s).
{{</ note >}}

{{< include "installation/jwt-password-note.md" >}}

---

### Use the NGINX Plus license Secret

If using a name other than the default `license-token`, provide the name of this Secret when installing NGINX Ingress Controller:

{{<tabs name="plus-secret-install">}}

{{%tab name="Helm"%}}

Specify the Secret name using the `controller.mgmt.licenseTokenSecretName` Helm value.

For detailed guidance on creating the Management block via Helm, refer to the [Helm configuration documentation]({{< relref "installation/installing-nic/installation-with-helm/#configuration" >}}).

{{% /tab %}}

{{%tab name="Manifests"%}}

Specify the Secret name in the `license-token-secret-name` Management ConfigMap key.

For detailed guidance on creating the Management ConfigMap, refer to the [Management ConfigMap Resource Documentation]({{< relref "configuration/global-configuration/mgmt-configmap-resource/" >}}).

{{% /tab %}}

{{</tabs>}}

**If you are reporting to the default licensing endpoint, then you can now proceed with [installing NGINX Ingress Controller]({{< relref "installation/installing-nic/" >}}). Otherwise, follow the steps below to configure reporting to NGINX Instance Manager.**

---

### Create report for NGINX Instance Manager {#nim}

If you are deploying NGINX Ingress Controller in an "air-gapped" environment you will need to report to [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager/) instead of the default licensing endpoint.

First, you must specify the endpoint of your NGINX Instance Manager.

{{<tabs name="nim-endpoint">}}

{{%tab name="Helm"%}}

Specify the endpoint using the `controller.mgmt.usageReport.endpoint` helm value.

{{% /tab %}}

{{%tab name="Manifests"%}}

Specify the endpoint in the `usage-report-endpoint` Management ConfigMap key.

{{% /tab %}}

{{</tabs>}}

---

#### Configure SSL certificates and SSL trusted certificates {#nim-cert}

To configure SSL certificates or SSL trusted certificates, extra steps are necessary.

To use Client Auth with NGINX Instance Manager, first create a Secret of type `kubernetes.io/tls` in the same namespace as the NGINX Ingress Controller pods. 

```shell
kubectl create secret tls ssl-certificate --cert=<path-to-your-client.pem> --key=<path-to-your-client.key> -n <Your Namespace>
```

To provide a SSL trusted certificate, and an optional Certificate Revocation List, create a Secret of type `nginx.org/ca` in the Namespace that the NIC Pod(s) are in.

```shell
kubectl create secret generic ssl-trusted-certificate \
   --from-file=ca.crt=<path-to-your-ca.crt> \
   --from-file=ca.crl=<path-to-your-ca.crl> \ # optional
   --type=nginx.org/ca
```

Providing an optional CRL (certificate revocation list) will configure the [`ssl_crl`](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_crl) directive.

{{<tabs name="nim-secret-install">}}

{{%tab name="Helm"%}}

Specify the SSL certificate Secret name using the `controller.mgmt.sslCertificateSecretName` Helm value. 

Specify the SSL trusted certificate Secret name using the `controller.mgmt.sslTrustedCertificateSecretName` Helm value.

{{% /tab %}}

{{%tab name="Manifests"%}}

Specify the SSL certificate Secret name in the `ssl-certificate-secret-name` management ConfigMap key.

Specify the SSL trusted certificate Secret name in the `ssl-trusted-certificate-secret-name` management ConfigMap key.

{{% /tab %}}

{{</tabs>}}

<br>

**Once these Secrets are created and configured, you can now [install NGINX Ingress Controller ]({{< relref "installation/installing-nic" >}}).**

---

## What’s reported and how it’s protected {#telemetry}

NGINX Plus reports the following data every hour by default:

- **NGINX version and status**: The version of NGINX Plus running on the instance.
- **Instance UUID**: A unique identifier for each NGINX Plus instance.
- **Traffic data**:
  - **Bytes received from and sent to clients**: HTTP and stream traffic volume between clients and NGINX Plus.
  - **Bytes received from and sent to upstreams**: HTTP and stream traffic volume between NGINX Plus and upstream servers.
  - **Client connections**: The number of accepted client connections (HTTP and stream traffic).
  - **Requests handled**: The total number of HTTP requests processed.
- **NGINX uptime**: The number of reloads and worker connections during uptime.
- **Usage report timestamps**: Start and end times for each usage report.
- **Kubernetes node details**: Information about Kubernetes nodes.

### Security and privacy of reported data

All communication between your NGINX Plus instances, NGINX Instance Manager, and F5’s licensing endpoint (`product.connect.nginx.com`) is protected using **SSL/TLS** encryption.

Only **operational metrics** are reported — no **personally identifiable information (PII)** or **sensitive customer data** is transmitted.
