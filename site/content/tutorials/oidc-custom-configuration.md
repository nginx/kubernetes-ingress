---
title: Customize OIDC Configuration with NGINX Ingress Controller
weight: 1800
toc: true
type: how-to
product: NIC
docs: DOCS-000
---

The F5 NGINX Ingress Controller implements OpenID Connect (OIDC) using the NGINX OpenID Connect Reference implementation: [nginx-openid-connect](https://github.com/nginxinc/nginx-openid-connect).

This guide will walk through how to customize and configure this default implementation.

## Prerequisites

This guide assumes that you have an F5 NGINX Ingress Controller deployed. If not, please follow the installation steps using either the [Manifest]({{< ref "/installation/installing-nic/installation-with-manifests.md" >}}) or [Helm]({{< ref "/installation/installing-nic/installation-with-helm.md" >}}) approach.

To customize the NGINX OpenID Connect Reference implementation, you will need to:

1. Create a ConfigMap containing the contents of the default `oidc.conf` file
2. Attach a `Volume` and `VolumeMount` to your deployment of the F5 NGINX Ingress Controller

This setup will allow the custom configuration in your ConfigMap to override the contents of the default `oidc.conf` file.

## Step 1 - Creating the ConfigMap

Run the below command to generate a ConfigMap with the contents of the `oidc.conf` file.
**NOTE** The ConfigMap must be deployed in the same `namespace` as the F5 NGINX Ingress Controller.

```console
kubectl create configmap oidc-config-map --from-literal=oidc.conf="$(curl -k https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/internal/configs/oidc/oidc.conf)"
```

Use the `kubectl describe` command to confirm the contents of the ConfigMap are correct.

```shell
kubectl describe configmap oidc-config-map
```

```yaml
Name:         oidc-config-map
Namespace:    default
Labels:       <none>
Annotations:  <none>

Data
====
oidc.conf:
docs: "DOCS-1448"
----
    # Advanced configuration START
    set $internal_error_message "NGINX / OpenID Connect login failure\n";
    set $pkce_id "";
    # resolver 8.8.8.8; # For DNS lookup of IdP endpoints;
    subrequest_output_buffer_size 32k; # To fit a complete tokenset response
    gunzip on; # Decompress IdP responses if necessary
    # Advanced configuration END

    ...
    # Rest of configuration file truncated
```

## Step 2 - Customizing the default configuration

Once the contents of the `oidc.conf` file has been added to the ConfigMap, you are free to customize the contents of this ConfigMap.
This example demonstrates adding a comment to the top of the file. The comment will be shown at the top of the `oidc.conf` file.
This comment will be `# >> Custom Comment for my OIDC file <<`

```shell
kubectl edit configmap oidc-config-map
```

Add the custom content:

```yaml
# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
  oidc.conf: |2-
        # >> Custom Comment for my OIDC file <<
        # Advanced configuration START
        set $internal_error_message "NGINX / OpenID Connect login failure\n";
        set $pkce_id "";
        # resolver 8.8.8.8; # For DNS lookup of IdP endpoints;
        subrequest_output_buffer_size 32k; # To fit a complete tokenset response
        gunzip on; # Decompress IdP responses if necessary
        # Advanced configuration END

        ...
        # Rest of configuration file truncated
```

{{< important >}}

In the next step, NGINX Ingress Controller will be deployed using this ConfigMap.

Any changes made to this ConfigMap must be made **before** deploying or updating NGINX Ingress Controller. If an update is applied to the ConfigMap after NGINX Ingress Controller is deployed, it will not be applied.

Applying any updates to the data in this ConfigMap will require NGINX Ingress Controller to be re-deployed.

{{< /important >}}

## Step 3 - Add Volume and VolumeMount to the Ingress Controller deployment

In this step we will add a `Volume` and `VolumeMount` to the NGINX Ingress Controller deployment.
This will allow you to mount the ConfigMap created in Step 1 and overwrite the contents of the `oidc.conf` file.

This document will demonstrate how to add the `Volume` and `VolumeMount` using both Manifest and HELM

### Manifest

The below configuration shows where the `Volume` and `VolumeMount` can be added to your Deployment/Daemonset file.

The `VolumeMount` must be added the `spec.template.spec.containers` section.

The `Volume` must be added the `spec.template.spec` section:

```yaml
apiVersion: apps/v1
kind: <Deployment/Daemonset>
metadata:
  name: <name>
  namespace: <ic-namespace>
spec:
  ...
  ...
  template:
    ...
    ...
    spec:
      ...
      ...
      volumes:
      - name: oidc-volume
        configMap:
          name: <config-map-name> # Must match the name of the ConfigMap
      containers:
        ...
        ...
        volumeMounts:
        - name: oidc-volume
          mountPath: /etc/nginx/oidc/oidc.conf
          subPath: oidc.conf # Must match the name in the data filed
          readOnly: true
```

Once the `Volume` and `VolumeMount` has been added the manifest file, apply the changes to the Ingress Controller deployment.

Confirm the `oidc.conf` file has been updated:

```shell
kubectl exec -it -n <ic-namespace> <ingess-controller-pod> -- cat /etc/nginx/oidc/oidc.conf
```

### Helm

Deployments using helm will need to edit their existing
Edit the NGINX Ingress Controller Deployment/Daemonset yaml to include a `Volume` and `VolumeMount`.

The `Volume` should be within the `spec.template.spec` section.

The `VolumeMount`must be added the `spec.template.spec.containers` section.

For Deployments:

```shell
kubectl edit deployments <name-of-deployment> -n <ic-namespace>
```

For Daemonsets:

```shell
kubectl edit daemonset <name-of-daemonset> -n <ic-namespace>
```

```yaml
apiVersion: apps/v1
kind: <Deployment/Daemonset>
metadata:
  name: <name>
  namespace: <ic-namespace>
spec:
  ...
  ...
  template:
    ...
    ...
    spec:
      ...
      ...
      volumes:
      - name: oidc-volume
        configMap:
          name: <config-map-name> # Must match the name of the ConfigMap
      containers:
        ...
        ...
        volumeMounts:
        - name: oidc-volume
          mountPath: /etc/nginx/oidc/oidc.conf
          subPath: oidc.conf # Must match the name in the data filed
          readOnly: true
```

Once the Deployment/Daemonset has been edited, save the file and exit.

Confirm the `oidc.conf` file has been updated:

```shell
kubectl exec -it -n <ic-namespace> <ingess-controller-pod> -- cat /etc/nginx/oidc/oidc.conf
```
