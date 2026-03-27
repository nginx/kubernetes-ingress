---
title: Enabling Usage Reporting
description: "This page outlines how to enable Usage Reporting for the NGINX Ingress Controller and how to view the usage data through the API."
weight: 1800
doctypes: ["concept"]
toc: true
---

## Overview

Usage Reporting is a Kubernetes controller that connects to the NGINX Management Suite and reports the number of NGINX Ingress Controller nodes in the cluster. It is installed as a Kubernetes Deployment in the same cluster as the NGINX Ingress Controller whose nodes you would like reported.

To use Usage Reporting, you must have access to NGINX Management Suite. For more information, see [NGINX Management Suite](https://www.nginx.com/products/nginx-management-suite/). Usage Reporting is a requirement of the new Flexible Consumption Program for NGINX Ingress Controller, used to calculate costs.

## Requirements

To deploy Usage Reporting, you must have the following:

- [NGINX Ingress Controller 3.2.0](https://docs.nginx.com/nginx-ingress-controller) or later
- [NGINX Management Suite 2.11](https://docs.nginx.com/nginx-management-suite) or later

In addition to the software requirements, you will need:

- Access to an NGINX Management Suite username and password for basic authentication. You will need the URL of your NGINX Management Suite system, and a username and password for Usage Reporting. The Usage Reporting user account must have access to the `/api/platform/v1/k8s-usage` endpoint.
- Access to the Kubernetes cluster where the NGINX Ingress Controller is deployed, with the ability to deploy a Kubernetes Deployment and a Kubernetes Secret.
- Access to public internet to pull the Usage Reporting image. This image is hosted in the NGINX container registry at `docker-registry.nginx.com/cluster-connector`. You can pull the image and push it to a private container registry for deployment.

[//]: # ( TODO: Update the image and tag after publish)

## Adding a User Account to NGINX Management Suite

Usage Reporting needs a user account to send usage data to NGINX Instance Manager: these are the steps involved.

1. Create a role following the steps in [Create a Role](https://docs.nginx.com/nginx-management-suite/admin-guides/access-control/set-up-rbac/#create-role) section of the NGINX Management Suite documentation. Select these permissions in step 6 for the role:
   - Module: Instance Manager
   - Feature: NGINX Plus Usage
   - Access: CRUD

2. Create a user account following the steps in [Add Users](https://docs.nginx.com/nginx-management-suite/admin-guides/access-control/set-up-rbac/#add-users) section of the NGINX Management Suite documentation. In step 6, assign the user to the role created above. Note that currently only "basic auth" authentication is supported for usage reporting purposes.

## Deploying Usage Reporting

### Creating a Namespace

1. Create the Kubernetes namespace `nginx-cluster-connector` for Usage Reporting:

    ```console
    kubectl create namespace nginx-cluster-connector
    ```

### Passing the Credential to the NGINX Management Suite API

To make the credential available to Usage Reporting, we need to create a Kubernetes secret.

2. The username and password created in the previous section are required to connect the NGINX Management Suite API. Both the username and password are stored in the Kubernetes Secret and need to be converted to base64. In this example the username will be `foo` and the password will be `bar`. To obtain the base64 representation of a string, use the following command:

    ```console
    echo -n 'foo' | base64
    # Zm9v
    echo -n 'bar' | base64
    # YmFy
    ```

3. Add the following content to a text editor, and insert the base64 representations of the username and password (Obtained in the previous step) to the `data` parameter:

    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: nms-basic-auth
      namespace: nginx-cluster-connector
    type: kubernetes.io/basic-auth
    data:
      username: Zm9v # base64 representation of 'foo' obtained in step 1
      password: YmFy # base64 representation of 'bar' obtained in step 1
    ```

   Save this in a file named `nms-basic-auth.yaml`. In the example, the namespace is `nginx-cluster-connector` and the secret name is `nms-basic-auth`. The namespace is the default namespace for Usage Reporting.

   If you are using a different namespace, please change the namespace in the `metadata` section of the file above. Note that Usage Reporting only supports basic-auth secret type in `data` format, not `stringData`, with the username and password encoded in base64.

4. Deploy the Kubernetes secret created in step 5 to the Kubernetes cluster:

    ```console
    kubectl apply -f nms-basic-auth.yaml
    ```

If you need to update the basic-auth credentials for NGINX Management Suite in the future, update the `username` and `password` fields, and apply the changes by running the command again. Usage Reporting will automatically detect the changes, using the new username and password without redeployment.

5. Download and save the deployment file [cluster-connector.yaml](https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/shared-examples/usage-reporting/cluster-connector.yaml). Edit the following under the `args` section and then save the file:

   ```yaml
        args:
        - -nms-server-address=https://nms.example.com/api/platform/v1
        - -nms-basic-auth-secret=nginx-cluster-connector/nms-basic-auth
   ```

The `-nms-server-address` should be the address of the Usage Reporting API, which will be the combination of NGINX Management Suite server hostname and the URI `api/platform/v1`. The `nms-basic-auth-secret` should be the namespace/name of the secret created in step 3: `nginx-cluster-connector/nms-basic-auth`.

For more information, read the [Command-line Arguments](#command-line-arguments) section.

6. To deploy Usage Reporting, run the following command to deploy it to your Kubernetes cluster:

   ```console
   kubectl apply -f cluster-connector.yaml
   ```

## Viewing Usage Data from the NGINX Management Suite API

Usage Reporting sends the number of NGINX Ingress Controller instances and nodes in the cluster to NGINX Management Suite. To view the usage data, query the NGINX Management Suite API. The usage data is available at the following endpoint:

```json
curl --user "foo:bar" https://nms.example.com/api/platform/v1/k8s-usage
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

You can also query the usage data for a specific cluster by specifying the cluster uid in the endpoint, for example:

```json
curl --user "foo:bar" https://nms.example.com/api/platform/v1/k8s-usage/d290f1ee-6c54-4b01-90e6-d701748f0851
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

## Uninstalling Usage Reporting

To remove Usage Reporting from your Kubernetes cluster, run the following command:

```console
kubectl delete -f cluster-connector.yaml
```

## Command-line Arguments

Usage Reporting supports several command-line arguments. The command-line arguments can be specified in the `args` section of the Kubernetes deployment file. The following is a list of the supported command-line arguments and their usage:

### -nms-server-address `<string>`

The address of the NGINX Management Suite host. IPv4 addresses and hostnames are supported.
Default `http://apigw.nms.svc.cluster.local/api/platform/v1/k8s-usage`.

### -nms-basic-auth-secret `<string>`

Secret for basic authentication to the NGINX Management Suite API. The secret must be in `kubernetes.io/basic-auth` format using base64 encoding.
Format `<namespace>/<name>`.

### -cluster-display-name `<string>`

The display name of the Kubernetes cluster.

### -skip-tls-verify

Skip TLS verification for the NGINX Management Suite server. **For testing purposes with NGINX Management Suite server using self-assigned certificate.**

### -min-update-interval `<string>`

The minimum interval between updates to the NGINX Management Suite. **For testing purposes only.**
Default `24h`.
