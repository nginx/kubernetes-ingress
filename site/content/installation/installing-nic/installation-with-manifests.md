---
title: Installation with Manifests
toc: true
weight: 200
type: how-to
product: NIC
docs: DOCS-603
---

This guide explains how to use Manifests to install F5 NGINX Ingress Controller, then create both common and custom resources and set up role-based access control.

## Before you start

If you are using NGINX Plus, get the NGINX Ingress Controller JWT and [create a license secret]({{< relref "/installation/create-license-secret.md" >}}).

### Get the NGINX Controller Image

{{< note >}} Always use the latest stable release listed on the [releases page]({{< relref "releases.md" >}}). {{< /note >}}

Choose one of the following methods to get the NGINX Ingress Controller image:

- **NGINX Ingress Controller**: Download the image `nginx/nginx-ingress` from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress).
- **NGINX Plus Ingress Controller**: You have two options for this, both requiring an NGINX Ingress Controller subscription.
  - Download the image using your NGINX Ingress Controller subscription certificate and key. View the [Get NGINX Ingress Controller from the F5 Registry]({{< relref "installation/nic-images/get-registry-image.md" >}}) topic.
  - The [Get the NGINX Ingress Controller image with JWT]({{< relref "installation/nic-images/get-image-using-jwt.md" >}}) topic describes how to use your subscription JWT token to get the image.
- **Build your own image**: To build your own image, follow the [Build NGINX Ingress Controller]({{< relref "installation/build-nginx-ingress-controller.md" >}}) topic.

### Clone the repository

Clone the NGINX Ingress Controller repository using the command shown below, and replace `<version_number>` with the specific release you want to use.

```shell
git clone https://github.com/nginx/kubernetes-ingress.git --branch <version_number>
```

For example, if you want to use version {{< nic-version >}}, the command would be `git clone https://github.com/nginx/kubernetes-ingress.git --branch v{{< nic-version >}}`.

This guide assumes you are using the latest release.

Change the active directory.

```shell
cd kubernetes-ingress
```

### App Protect DoS

To use App Protect DoS, install the App Protect DoS Arbitrator using the provided manifests in the same namespace as the NGINX Ingress Controller. If you install multiple NGINX Ingress Controllers in the same namespace, they will need to share the same Arbitrator because there can only be one Arbitrator in a single namespace.

---

## Set up role-based access control (RBAC) {#configure-rbac}

{{< include "rbac/set-up-rbac.md" >}}

---

## Create common resources {#create-common-resources}

{{< include "installation/create-common-resources.md" >}}

---

## Create core custom resources {#create-custom-resources}

{{< include "installation/create-custom-resources.md" >}}

### Create optional custom resources

There are optional CRDs that are necessary if you want to use NGINX App Protect WAF or NGINX App Protect DoS.

**NGINX App Protect WAF**:
- `APPolicy`
- `APLogConf`
- `APUserSig`

**NGINX App Protect DoS**:
- `APDosPolicy`
- `APDosLogConf`
- `DosProtectedResource`

{{<tabs name="install-nap-crds">}}

{{%tab name="Install CRDs from single YAML"%}}


**NGINX App Protect WAF**

{{<  note >}} This step can be skipped if you are using App Protect WAF module with policy bundles. {{<  /note >}}

```shell
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds-nap-waf.yaml
```

**NGINX App Protect DoS**:

```shell
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds-nap-dos.yaml
```

{{%/tab%}}

{{%tab name="Install CRDs after cloning the repo"%}}

**NGINX App Protect WAF**

{{<  note >}} This step can be skipped if you are using App Protect WAF module with policy bundles. {{<  /note >}}

```shell
kubectl apply -f config/crd/bases/appprotect.f5.com_aplogconfs.yaml
kubectl apply -f config/crd/bases/appprotect.f5.com_appolicies.yaml
kubectl apply -f config/crd/bases/appprotect.f5.com_apusersigs.yaml
```

**NGINX App Protect DoS**:

```shell
kubectl apply -f config/crd/bases/appprotectdos.f5.com_apdoslogconfs.yaml
kubectl apply -f config/crd/bases/appprotectdos.f5.com_apdospolicy.yaml
kubectl apply -f config/crd/bases/appprotectdos.f5.com_dosprotectedresources.yaml
```

{{%/tab%}}

{{</tabs>}}

---

## Deploy NGINX Ingress Controller {#deploy-ingress-controller}

You have two options for deploying NGINX Ingress Controller:

- **Deployment**. Choose this method for the flexibility to dynamically change the number of NGINX Ingress Controller replicas.
- **DaemonSet**. Choose this method if you want NGINX Ingress Controller to run on all nodes or a subset of nodes.

Before you start, update the [command-line arguments]({{< relref "configuration/global-configuration/command-line-arguments.md" >}}) for the NGINX Ingress Controller container in the relevant manifest file to meet your specific requirements.

### Using a Deployment

{{< include "installation/manifests/deployment.md" >}}

### Using a DaemonSet

{{< include "installation/manifests/daemonset.md" >}}

---

## Confirm NGINX Ingress Controller is running

{{< include "installation/manifests/verify-pods-are-running.md" >}}

---

## How to access NGINX Ingress Controller

### Using a Deployment

For Deployments, you have two options for accessing NGINX Ingress Controller pods.

#### Option 1: Create a NodePort service

For more information about the  _NodePort_ service, refer to the [Kubernetes documentation](https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport).

1. To create a service of type *NodePort*, run:

    ```shell
    kubectl create -f deployments/service/nodeport.yaml
    ```

    Kubernetes automatically allocates two ports on every node in the cluster. You can access NGINX Ingress Controller by combining any node's IP address with these ports.

#### Option 2: Create a LoadBalancer service

For more information about the _LoadBalancer_ service, refer to the [Kubernetes documentation](https://kubernetes.io/docs/concepts/services-networking/service/#type-loadbalancer).

1. To set up a _LoadBalancer_ service, run one of the following commands based on your cloud provider:

    - GCP or Azure:

        ```shell
        kubectl apply -f deployments/service/loadbalancer.yaml
        ```

    - AWS:

        ```shell
        kubectl apply -f deployments/service/loadbalancer-aws-elb.yaml
        ```

        For more details see service guide [here](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/service/annotations/#annotations)

2. AWS users: Follow these additional steps to work with ELB in TCP mode.

     - Add the following keys to the `nginx-config.yaml` ConfigMap file, which you created in the [Create common resources](#create-common-resources) section.

         ```yaml
         proxy-protocol: "True"
         real-ip-header: "proxy_protocol"
         set-real-ip-from: "0.0.0.0/0"
         ```

     - Update the ConfigMap:

         ```shell
         kubectl apply -f deployments/common/nginx-config.yaml
         ```

    {{<note>}}AWS users have more customization options for their load balancers. These include choosing the load balancer type and configuring SSL termination. Refer to the [Kubernetes documentation](https://kubernetes.io/docs/concepts/services-networking/service/#type-loadbalancer) to learn more. {{</note>}}

3. To access NGINX Ingress Controller, get the public IP of your load balancer.

    - For GCP or Azure, run:

        ```shell
        kubectl get svc nginx-ingress --namespace=nginx-ingress
        ```

    - For AWS find the DNS name:

        ```shell
        kubectl describe svc nginx-ingress --namespace=nginx-ingress
        ```

        Resolve the DNS name into an IP address using `nslookup`:

        ```shell
        nslookup <dns-name>
        ```

    You can also find more details about the public IP in the status section of an ingress resource. For more details, refer to the [Reporting Resources Status doc]({{< relref "configuration/global-configuration/reporting-resources-status.md" >}}).

### Using a DaemonSet

Connect to ports 80 and 443 using the IP address of any node in the cluster where NGINX Ingress Controller is running.

---

## Uninstall NGINX Ingress Controller

{{<warning>}}Proceed with caution when performing these steps, as they will remove NGINX Ingress Controller and all related resources, potentially affecting your running services.{{</warning>}}

1. **Delete the nginx-ingress namespace**: To remove NGINX Ingress Controller and all auxiliary resources, run:

    ```shell
    kubectl delete namespace nginx-ingress
    ```

1. **Remove the cluster role and cluster role binding**:

    ```shell
    kubectl delete clusterrole nginx-ingress
    kubectl delete clusterrolebinding nginx-ingress
    ```

1. **Delete the Custom Resource Definitions**:

{{<tabs name="delete-crds">}}

{{%tab name="Deleting CRDs from single YAML"%}}

   1. Delete core custom resource definitions:
    ```shell
    kubectl delete -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds.yaml
    ```
   2. Delete custom resource definitions for the NGINX App Protect WAF module:

   ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds-nap-waf.yaml
    ```

   3. Delete custom resource definitions for the NGINX App Protect DoS module:
   ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds-nap-dos.yaml
    ```
   {{%/tab%}}

{{%tab name="Deleting CRDs after cloning the repo"%}}

1. Delete core custom resource definitions:
```shell
kubectl delete -f config/crd/bases/crds.yaml
```
2. Delete custom resource definitions for the NGINX App Protect WAF module:

```shell
kubectl apply -f config/crd/bases/crds-nap-waf.yaml
```

3. Delete custom resource definitions for the NGINX App Protect DoS module:
```shell
kubectl apply -f config/crd/bases/crds-nap-dos.yaml
```

{{%/tab%}}

{{</tabs>}}
