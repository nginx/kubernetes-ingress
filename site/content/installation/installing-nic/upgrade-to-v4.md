---
title: Upgrade to NGINX Ingress Controller 4.0.0
toc: true
weight: 400
type: how-to
product: NIC
docs: DOCS-000
---

This document explains how to upgrade F5 NGINX Ingress Controller to 4.0.0.

There are two necessary steps required: updating the `apiVersion` value of custom resources and configuring structured logging.

For NGINX Plus users, there is a third step to create a Secret for your license.

---

## Update custom resource apiVersion

If the Helm chart you have been using is `v2.x`, before upgrading to NGINX Ingress Controller 4.0.0 you must update your GlobalConfiguration, Policy and TransportServer resources from `apiVersion: k8s.nginx.org/v1alpha1` to `apiVersion: k8s.nginx.org/v1`.

If the Helm chart you have been using is `v1.0.2` or earlier (NGINX Ingress Controller `v3.3.2`), upgrade to Helm chart `v1.4.2` (NGINX Ingress Controller `v3.7.2`) before updating your GlobalConfiguration, Policy and TransportServer resources.

The example below shows the change for a Policy resource: you must do the same for all GlobalConfiguration and TransportServer resources.

{{<tabs name="resource-version-update">}}

{{% comment %}} Keep this left aligned. {{% /comment %}}
{{%tab name="Before"%}}

```yaml
apiVersion: k8s.nginx.org/v1alpha1
kind: Policy
metadata:
  name: rate-limit-policy
spec:
  rateLimit:
    rate: 1r/s
    key: ${binary_remote_addr}
    zoneSize: 10M
```
{{% /tab %}}

{{%tab name="After"%}}
```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: rate-limit-policy
spec:
  rateLimit:
    rate: 1r/s
    key: ${binary_remote_addr}
    zoneSize: 10M
```
{{% /tab %}}

{{</tabs>}}

{{< warning >}}
If a *GlobalConfiguration*, *Policy* or *TransportServer* resource is deployed with `apiVersion: k8s.nginx.org/v1alpha1`, it will be **deleted** during the upgrade process.
{{</ warning >}}

Once above specified custom resources are moved to `v1` ,please run below `kubectl` commands before upgrading to v4.0.0 Custom Resource Definitions (CRDs) to avoid [this issue](https://github.com/nginx/kubernetes-ingress/issues/7010).

```shell
kubectl patch customresourcedefinitions transportservers.k8s.nginx.org --subresource='status' --type='merge' -p '{"status":{"storedVersions": ["v1"]}}'
```

```shell
kubectl patch customresourcedefinitions globalconfigurations.k8s.nginx.org --subresource='status' --type='merge' -p '{"status":{"storedVersions": ["v1"]}}'
```

---

## Configure structured logging

To configure structured logging, you must update your log deployment arguments from an integer to a string. The logs themselves can also be rendered in different formats.

{{< note >}} These options apply to NGINX Ingress Controller logs, and do not affect NGINX logs. {{< /note >}}

| **Level arguments** | **Format arguments** |
|---------------------|----------------------|
| `trace`             | `json`               |
| `debug`             | `text`               |
| `info`              | `glog`               |
| `warning`           |                      |
| `error`             |                      |
| `fatal`             |                      |

{{<tabs name="structured logging">}}

{{%tab name="Helm"%}}

The Helm value of `controller.logLevel` has been changed from an integer to a string.

To change the rendering of the log format, use the `controller.logFormat` key.

```yaml
controller:
    logLevel: info
    logFormat: json
```
{{% /tab %}}

{{%tab name="Manifests"%}}

The command line argument `-v` has been replaced with `-log-level`, and takes a string instead of an integer. The argument `-logtostderr` has also been deprecated.

To change the rendering of the log format, use the `-log-format` argument.

```yaml
args:
    - -log-level=info
    - -log-format=json
```
{{% /tab %}}

{{</tabs>}}

---

## Create License secret

If you're using [NGINX Plus]({{< ref "/overview/nginx-plus.md" >}}) with NGINX Ingress Controller, you should read the [Create License Secret]({{< ref "/installation/create-license-secret.md" >}}) topic to set up your NGINX Plus license.

The topic also contains guidance for [sending reports to NGINX Instance Manager]({{< ref "/installation/create-license-secret.md#nim">}}), which is necessary for air-gapped environments.

In prior versions, usage reporting with the cluster connector was required: it is no longer necessary, as it is built into NGINX Plus.
