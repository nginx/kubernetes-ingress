---
title: Enable Usage Reporting
toc: true
weight: 1800
noindex: true
headless: true
type: how-to
product: NIC
docs: DOCS-1445
---

{{< important >}}
This page is only applicable to NGINX Ingress Controller versions 3.2.0 - 3.7.2.

For more recent versions of NGINX Ingress Controller, view the [Upgrade to NGINX Ingress Controller 4.0.0]({{< ref "/installation/install-nic/upgrade-to-v4.md" >}}) topic.

{{< /important >}}

This page describes how to enable Usage Reporting for F5 NGINX Ingress Controller and how to view usage data through the API.

---

## Overview

Usage Reporting is a Kubernetes controller that connects to the NGINX Instance Manager and reports the number of NGINX Ingress Controller nodes in the cluster. It is installed as a Kubernetes Deployment in the same cluster as NGINX Ingress Controller whose nodes you would like reported.

To use Usage Reporting, you must have access to NGINX Instance Manager. For more information, see [NGINX Instance Manager](https://www.f5.com/products/nginx/instance-manager/). Usage Reporting is a requirement of the new Flexible Consumption Program for NGINX Ingress Controller.

---

## Requirements

To deploy Usage Reporting, you must have the following:

- [NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller) 3.2.0 - 3.7.2
- [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager) 2.11.0 or later

In addition to the software requirements, you will need:

- Access to an NGINX Instance Manager username and password for basic authentication. You will need the URL of your NGINX Instance Manager system, and a username and password for Usage Reporting. The Usage Reporting user account must have access to the `/api/platform/v1/k8s-usage` endpoint.
- Access to the Kubernetes cluster where NGINX Ingress Controller is deployed, with the ability to deploy a Kubernetes Deployment and a Kubernetes Secret.
- Access to public internet to pull the Usage Reporting image. This image is hosted in the NGINX container registry at `docker-registry.nginx.com/cluster-connector`. You can pull the image and push it to a private container registry for deployment.

[//]: # ( TODO: Update the image and tag after publish)

---

## Add a user account to NGINX Instance Manager

Usage Reporting needs a user account to send usage data to NGINX Instance Manager: these are the steps involved.

1. Create a role following the steps in [Create a Role](https://docs.nginx.com/nginx-instance-manager/admin-guide/rbac/create-roles/#create-roles) section of the NGINX Instance Manager documentation. Select these permissions in step 6 for the role:
   - Module: Instance Manager
   - Feature: NGINX Plus Usage
   - Access: CRUD

1. Create a user account following the steps in [Add Users](https://docs.nginx.com/nginx-instance-manager/admin-guide/rbac/assign-roles/#assign-roles-to-users-basic-authentication) section of the NGINX Instance Manager documentation. In step 5, assign the user to the role created above. Note that currently only "basic auth" authentication is supported for usage reporting purposes.

---

## Deploy Usage Reporting

### Create a namespace

Create the Kubernetes namespace `nginx-cluster-connector` for Usage Reporting:

  ```shell
  kubectl create namespace nginx-cluster-connector
  ```

---

### Pass the credential to the NGINX Instance Manager API

To make the credential available to Usage Reporting, create a Kubernetes secret. The username and password created in the previous section are required to connect the NGINX Instance Manager API.

Both the username and password are stored in the Kubernetes Secret and need to be converted to base64. In this example the username will be `foo` and the password will be `bar`.

To obtain the base64 representation of a string, use the following command:

```shell
echo -n 'foo' | base64
# Zm9v
echo -n 'bar' | base64
# YmFy
```

Add the following content to a text editor, and insert the base64 representations of the username and password (Obtained in the previous step) to the `data` parameter:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: nms-basic-auth
  namespace: nginx-cluster-connector
type: kubernetes.io/basic-auth
data:
  username: Zm9v # base64 representation of 'foo'
  password: YmFy # base64 representation of 'bar'
```

Save this in a file named `nms-basic-auth.yaml`. In the example, the namespace is `nginx-cluster-connector` (The default namespace) and the secret name is `nms-basic-auth`.

If you are using a different namespace, change the namespace in the `metadata` section of the file above.

{{< note >}} Usage Reporting only supports basic-auth secret type in `data` format, not `stringData`, with the username and password encoded in base64. {{< /note >}}

---

### Deploy the Kubernetes secret to the Kubernetes cluster

```shell
kubectl apply -f nms-basic-auth.yaml
```

If you need to update the basic-auth credentials for NGINX Instance Manager in the future, update the `username` and `password` fields, and apply the changes by running the command again. Usage Reporting will automatically detect the changes, using the new username and password without redeployment.

Download and save the deployment file [cluster-connector.yaml](https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/examples/shared-examples/usage-reporting/cluster-connector.yaml). Edit the following under the `args` section and then save the file:

```yaml
    args:
    - -nms-server-address=https://nms.example.com/api/platform/v1
    - -nms-basic-auth-secret=nginx-cluster-connector/nms-basic-auth
```

- `-nms-server-address` should be the address of the Usage Reporting API, which will be the combination of NGINX Instance Manager server hostname and the URI `api/platform/v1`
- `nms-basic-auth-secret` should be the namespace/name of the secret created in step 3: `nginx-cluster-connector/nms-basic-auth`.

{{< note >}}  OpenShift requires a SecurityContextConstraints object for NGINX Cluster Connector.

It can be created with the command `oc create -f scc.yaml`, using the file found in `shared-examples/` {{< /note >}}

For more information, read the [Command-line arguments](#command-line-arguments) section of this page.

---

### Finish deployment

To deploy Usage Reporting, run the following command to deploy it to your Kubernetes cluster:

```shell
kubectl apply -f cluster-connector.yaml
```

---

## Viewing usage data from the NGINX Instance Manager API

Usage Reporting sends the number of NGINX Ingress Controller instances and nodes in the cluster to NGINX Instance Manager. To view the usage data, query the NGINX Instance Manager API. The usage data is available at the following endpoint:


```shell
curl --user "foo:bar" https://nms.example.com/api/platform/v1/k8s-usage
```
```json
{
  "items": [
    {
      "metadata": {
        "displayName": "my-cluster",
        "uid": "d290f1ee-6c54-4b01-90e6-d701748f0851",
        "createTime": "2023-01-27T09:12:33.001Z",
        "updateTime": "2023-01-29T10:12:33.001Z",
        "monthReturned": "May"
      },
      "node_count": 4,
      "max_node_count": 5,
      "pod_details": {
        "current_pod_counts": {
          "pod_count": 15,
          "waf_count": 5,
          "dos_count": 0
        },
        "max_pod_counts": {
          "max_pod_count": 25,
          "max_waf_count": 7,
          "max_dos_count": 1
        }
      }
    },
    {
      "metadata": {
        "displayName": "my-cluster2",
        "uid": "12tgb8ug-g8ik-bs7h-gj3j-hjitk672946hb",
        "createTime": "2023-01-25T09:12:33.001Z",
        "updateTime": "2023-01-26T10:12:33.001Z",
        "monthReturned": "May"
      },
      "node_count": 3,
      "max_node_count": 3,
      "pod_details": {
        "current_pod_counts": {
          "pod_count": 5,
          "waf_count": 5,
          "dos_count": 0
        },
        "max_pod_counts": {
          "max_pod_count": 15,
          "max_waf_count": 5,
          "max_dos_count": 0
        }
      }
    }
  ]
}
```

If you want a friendly name for each cluster in the response, You can specify the `displayName` for the cluster with the `-cluster-display-name` command-line argument when you deploy Usage Reporting. In the response, you can see the cluster `uid` corresponding to the cluster name. For more information, read the [Command-line Arguments](#command-line-arguments) section.

You can query the usage data for a specific cluster by specifying the cluster uid in the endpoint, for example:

```shell
curl --user "foo:bar" https://nms.example.com/api/platform/v1/k8s-usage/d290f1ee-6c54-4b01-90e6-d701748f0851
```
```json
{
  "metadata": {
    "displayName": "my-cluster",
    "uid": "d290f1ee-6c54-4b01-90e6-d701748f0851",
    "createTime": "2023-01-27T09:12:33.001Z",
    "updateTime": "2023-01-29T10:12:33.001Z",
    "monthReturned": "May"
  },
  "node_count": 4,
  "max_node_count": 5,
  "pod_details": {
    "current_pod_counts": {
      "pod_count": 15,
      "waf_count": 5,
      "dos_count": 0
    },
    "max_pod_counts": {
      "max_pod_count": 25,
      "max_waf_count": 7,
      "max_dos_count": 1
    }
  }
}
```

---

## Uninstall Usage Reporting

To remove Usage Reporting from your Kubernetes cluster, run the following command:

```shell
kubectl delete -f cluster-connector.yaml
```

---

## Command-line arguments

Usage Reporting supports several command-line arguments, which can be specified in the `args` section of the Kubernetes deployment file.

The following is a list of the supported command-line arguments and their usage:

---

### -nms-server-address `<string>`

The address of the NGINX Instance Manager host. IPv4 addresses and hostnames are supported.
Default: `http://apigw.nms.svc.cluster.local/api/platform/v1/k8s-usage`.

---

### -nms-basic-auth-secret `<string>`

Secret for basic authentication to the NGINX Instance Manager API. The secret must be in `kubernetes.io/basic-auth` format using base64 encoding.
Format: `<namespace>/<name>`.

---

### -cluster-display-name `<string>`

The display name of the Kubernetes cluster.

---

### -skip-tls-verify

Skip TLS verification for the NGINX Instance Manager server.

{{< warning >}} This argument is intended for using a self-assigned certificate for testing purposes only. {{< /warning >}}

---

### -min-update-interval `<string>`

The minimum interval between updates to the NGINX Instance Manager.
Default: `24h`.

{{< warning >}} This argument is intended for testing purposes only. {{< /warning >}}
