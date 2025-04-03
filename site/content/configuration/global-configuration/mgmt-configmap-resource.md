---
docs: DOCS-586
doctypes:
- ''
title: Management ConfigMap resource
toc: true
weight: 300
---

When using F5 NGINX Ingress Controller with NGINX Plus, it is required to pass a [command line argument]({{< relref "configuration/global-configuration/command-line-arguments" >}}) to NGINX Ingress Controller, `--mgmt-configmap=<namespace/name>` which specifies the ConfigMap to use. The minimal required ConfigMap must have a `license-token-secret-name` key. Helm users will not need to create this map or pass the argument, it will be created with a Helm install. 

---

1. Create a ConfigMap file with the name *nginx-config-mgmt.yaml* and set the values
that make sense for your setup:

    ```yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: nginx-config-mgmt
      namespace: nginx-ingress
    data:
      license-token-secret-name: "license-token"
    ```
1. Create a new (or update the existing) ConfigMap resource:

    ```shell
    kubectl apply -f nginx-config-mgmt.yaml
    ```

    The [NGINX Management](https://nginx.org/en/docs/ngx_mgmt_module.html) block configuration will be updated.
---
## Management ConfigMap keys

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|ConfigMap Key | Description | Default |
| ---| ---| ---|
|*license-token-secret-name* | Configures the secret used in the [license_token](https://nginx.org/en/docs/ngx_mgmt_module.html#license_token) directive. This key assumes the secret is in the Namespace that NGINX Ingress Controller is deployed in. The secret must be of type `nginx.com/license` with the base64 encoded JWT in the `license.jwt` key.  | N/A |
|*ssl-verify* | Configures the [ssl_verify](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_verify) directive, which enables or disables verification of the usage reporting endpoint certificate. | `true` |
|*enforce-initial-report* | Configures the [enforce_initial_report](https://nginx.org/en/docs/ngx_mgmt_module.html#enforce_initial_report) directive, which enables or disables the 180-day grace period for sending the initial usage report. | `false` |
|*usage-report-endpoint* | Configures the endpoint of the [usage_report](https://nginx.org/en/docs/ngx_mgmt_module.html#usage_report) directive. This is used to configure the endpoint NGINX uses to send usage reports to NIM. | `product.connect.nginx.com` |
|*usage-report-interval* | Configures the interval of the [usage_report](https://nginx.org/en/docs/ngx_mgmt_module.html#usage_report) directive. This specifies the frequency that usage reports are sent. This field takes an [NGINX time](https://nginx.org/en/docs/syntax.html). | `1h` |
|*usage-report-proxy-host* | Configures the host name of the [proxy](https://nginx.org/en/docs/ngx_mgmt_module.html#proxy) directive with optional port. | N/A |
|*ssl-trusted-certificate-secret-name* | Configures the secret used to create the file(s) referenced the in [ssl_trusted_certifcate](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_trusted_certificate), and [ssl_crl](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_crl) directives. This key assumes the secret is in the Namespace that NGINX Ingress Controller is deployed in. The secret must be of type `nginx.org/ca`, where the `ca.crt` key contains a base64 encoded trusted cert, and the optional `ca.crl` key can contain a base64 encoded CRL. If the optional `ca.crl` key is supplied, it will configure the NGINX `ssl_crl` directive. | N/A |
|*ssl-certificate-secret-name* | Configures the secret used to create the `ssl_certificate` and `ssl_certificate_key` directives. This key assumes the secret is in the Namespace that NGINX Ingress Controller is deployed in. The secret must be of type `kubernetes.io/tls`| N/A |
|*resolver-addresses* | Configures addresses used in the mgmt block [resolver](https://nginx.org/en/docs/ngx_mgmt_module.html#resolver) directive. This field takes a comma separated list of addresses. | N/A |
|*resolver-ipv6* | Configures whether the mgmt block [resolver](https://nginx.org/en/docs/ngx_mgmt_module.html#resolver) directive will look up IPv6 addresses. | `true` |
|*resolver-valid* | Configures an [NGINX time](https://nginx.org/en/docs/syntax.html) that the mgmt block [resolver](https://nginx.org/en/docs/ngx_mgmt_module.html#resolver) directive will override the TTL value of responses from nameservers with. | N/A |
{{</bootstrap-table>}}
