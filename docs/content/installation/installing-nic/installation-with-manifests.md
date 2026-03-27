---
title: Installation with Manifests
description: "This guide explains how to install NGINX Ingress Controller in a Kubernetes cluster using manifests. In addition, it provides instructions on how to set up role-based access control, create both common and custom resources, and uninstall NGINX Ingress Controller."
weight: 200
doctypes: [""]
aliases:
    - /installation/
toc: true
docs: "DOCS-603"
---

{{<custom-styles>}}

## Before you start

### Get the NGINX Controller Image

{{<note>}}Always use the most up-to-date stable release listed on the [releases page]({{< relref "releases.md" >}}).{{</note>}}

Choose one of the following methods to get the NGINX Ingress Controller image:

- **NGINX Ingress Controller**: Download the image `nginx/nginx-ingress` from [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress).
- **NGINX Plus Ingress Controller**: You have two options for this, both requiring an NGINX Ingress Controller subscription.

  - Download the image using your NGINX Ingress Controller subscription certificate and key. See the [Getting the F5 Registry NGINX Ingress Controller Image]({{< relref "installation/nic-images/pulling-ingress-controller-image.md" >}}) guide.
  - Use your NGINX Ingress Controller subscription JWT token to get the image: Instructions are in [Getting the NGINX Ingress Controller Image with JWT]({{< relref "installation/nic-images/using-the-jwt-token-docker-secret.md" >}}).

- **Build your own image**: To build your own image, follow the [Building NGINX Ingress Controller]({{< relref "installation/building-nginx-ingress-controller.md" >}}) guide.

### Clone the repository

Clone the NGINX Ingress Controller repository using the command shown below, and replace `<version_number>` with the specific release you want to use.

```shell
git clone https://github.com/nginxinc/kubernetes-ingress.git --branch <version_number>
```

For example, if you want to use version 3.3.2, the command would be `git clone https://github.com/nginxinc/kubernetes-ingress.git --branch v3.3.2`.

This guide assumes you are using the latest release.

---

## Set up role-based access control (RBAC) {#configure-rbac}

{{< include "rbac/set-up-rbac.md" >}}

---

## Create common resources {#create-common-resources}

{{< include "installation/create-common-resources.md" >}}

---

## Create custom resources {#create-custom-resources}

To make sure your NGINX Ingress Controller pods reach the `Ready` state, you'll need to create custom resource definitions (CRDs) for various components. Alternatively, you can disable this requirement by setting the `-enable-custom-resources` command-line argument to `false`.
There are two ways you can install the custom resource definitions:
   1. Using a URL to apply a single CRD yaml file. We recommend this approach.
   2. Applying your local copy of the CRD yaml files. This requires that you [clone the repository](#lone-the-repository).

{{<tabs name="install-crds">}}

{{%tab name="Install CRDs from single YAML"%}}

### Core custom resource definitions

1. Create CRDs for [VirtualServer and VirtualServerRoute]({{< relref "configuration/virtualserver-and-virtualserverroute-resources.md" >}}), [TransportServer]({{< relref "configuration/transportserver-resource.md" >}}), [Policy]({{< relref "configuration/policy-resource.md" >}}) and [GlobalConfiguration]({{< relref "configuration/global-configuration/globalconfiguration-resource.md" >}}):

    ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds.yaml
    ```

### Optional custom resource definitions

1. For the NGINX App Protect WAF module, create CRDs for `APPolicy`, `APLogConf` and `APUserSig`:

    ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds-nap-waf.yaml
    ```

2. For the NGINX App Protect DoS module, create CRDs for `APDosPolicy`, `APDosLogConf` and `DosProtectedResource`:

    ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds-nap-dos.yaml
    ```

{{%/tab%}}

{{%tab name="Install CRDs after cloning the repo"%}}

If you are installing the CRDs this way, ensure that you have first [cloned the repository](#clone-the-repository)

### Core custom resource definitions

1. Create CRDs for [VirtualServer and VirtualServerRoute]({{< relref "configuration/virtualserver-and-virtualserverroute-resources.md" >}}), [TransportServer]({{< relref "configuration/transportserver-resource.md" >}}), [Policy]({{< relref "configuration/policy-resource.md" >}}) and [GlobalConfiguration]({{< relref "configuration/global-configuration/globalconfiguration-resource.md" >}}):

    ```shell
    kubectl apply -f config/crd/bases/k8s.nginx.org_virtualservers.yaml
    kubectl apply -f config/crd/bases/k8s.nginx.org_virtualserverroutes.yaml
    kubectl apply -f config/crd/bases/k8s.nginx.org_transportservers.yaml
    kubectl apply -f config/crd/bases/k8s.nginx.org_policies.yaml
    kubectl apply -f config/crd/bases/k8s.nginx.org_globalconfigurations.yaml
    ```
### Optional custom resource definitions

{{<  note >}} This step can be skipped if you are using App Protect WAF module with policy bundles. {{<  /note >}}

1. For the NGINX App Protect WAF module, create CRDs for `APPolicy`, `APLogConf` and `APUserSig`:

    ```shell
    kubectl apply -f config/crd/bases/appprotect.f5.com_aplogconfs.yaml
    kubectl apply -f config/crd/bases/appprotect.f5.com_appolicies.yaml
    kubectl apply -f config/crd/bases/appprotect.f5.com_apusersigs.yaml
    ```

2. For the NGINX App Protect DoS module, create CRDs for `APDosPolicy`, `APDosLogConf` and `DosProtectedResource`:

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

        If you're using AWS, Kubernetes will set up a Classic Load Balancer (ELB) in TCP mode. This load balancer will have the PROXY protocol enabled to pass along the client's IP address and port.

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

2. **Remove the cluster role and cluster role binding**:

    ```shell
    kubectl delete clusterrole nginx-ingress
    kubectl delete clusterrolebinding nginx-ingress
    ```

3. **Delete the Custom Resource Definitions**:

   {{<tabs name="delete-crds">}}

   {{%tab name="Deleting CRDs from single YAML"%}}

   1. Delete core custom resource definitions:
    ```shell
    kubectl delete -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds.yaml
    ```
   2. Delete custom resource definitions for the NGINX App Protect WAF module:

   ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds-nap-waf.yaml
    ```

   3. Delete custom resource definitions for the NGINX App Protect DoS module:
   ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds-nap-dos.yaml
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
