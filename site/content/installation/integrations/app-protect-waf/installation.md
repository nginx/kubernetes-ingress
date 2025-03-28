---
title: Build NGINX Ingress Controller with NGINX App Protect WAF
weight: 100
toc: true
type: how-to
product: NIC
docs: DOCS-579
---

This document explains how to build a F5 NGINX Ingress Controller image with F5 NGINX App Protect WAF from source code.

{{<call-out "tip" "Pre-built image alternatives" >}} If you'd rather not build your own NGINX Ingress Controller image, see the [pre-built image options](#pre-built-images) at the end of this guide.{{</call-out>}}

## Before you start

- To use NGINX App Protect WAF with NGINX Ingress Controller, you must have NGINX Plus.

## Prepare the environment

Get your system ready for building and pushing the NGINX Ingress Controller image with NGINX App Protect WAF.

1. Sign in to your private registry. Replace `<my-docker-registry>` with the path to your own private registry.

    ```shell
    docker login <my-docker-registry>
    ```

1. Clone the NGINX Ingress Controller repository:

    ```console
    git clone https://github.com/nginx/kubernetes-ingress.git --branch v{{< nic-version >}}
    cd kubernetes-ingress
    ```

---

## Build the image

Follow these steps to build the NGINX Controller Image with NGINX App Protect WAF.

1. Place your NGINX Plus license files (_nginx-repo.crt_ and _nginx-repo.key_) in the project's root folder. To verify they're in place, run:

    ```shell
    ls nginx-repo.*
    ```

    You should see:

    ```shell
    nginx-repo.crt  nginx-repo.key
    ```

2. Build the image. Replace `<makefile target>` with your chosen build option and `<my-docker-registry>` with your private registry's path. Refer to the [Makefile targets](#makefile-targets) table below for the list of build options.

    ```shell
    make <makefile target> PREFIX=<my-docker-registry>/nginx-plus-ingress TARGET=download
    ```

    For example, to build a Debian-based image with NGINX Plus and NGINX App Protect DoS, run:

    ```shell
    make debian-image-dos-plus PREFIX=<my-docker-registry>/nginx-plus-ingress TARGET=download
    ```

     **What to expect**: The image is built and tagged with a version number, which is derived from the `VERSION` variable in the [_Makefile_]({{< relref "installation/build-nginx-ingress-controller.md#makefile-details" >}}). This version number is used for tracking and deployment purposes.

{{<note>}} In the event a patch of NGINX Plus is released, make sure to rebuild your image to get the latest version. If your system is caching the Docker layers and not updating the packages, add `DOCKER_BUILD_OPTIONS="--pull --no-cache"` to the make command. {{</note>}}

### Makefile targets {#makefile-targets}

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
| Makefile Target           | Description                                                       | Compatible Systems  |
|---------------------------|-------------------------------------------------------------------|---------------------|
| **debian-image-nap-plus** | Builds a Debian-based image with NGINX Plus and the [NGINX App Protect WAF](/nginx-app-protect-waf/) module. | Debian  |
| **debian-image-nap-dos-plus** | Builds a Debian-based image with NGINX Plus, [NGINX App Protect WAF](/nginx-app-protect-waf/), and [NGINX App Protect DoS](/nginx-app-protect-dos/) | Debian  |
| **ubi-image-nap-plus**    | Builds a UBI-based image with NGINX Plus and the [NGINX App Protect WAF](/nginx-app-protect-waf/) module. | OpenShift |
| **ubi-image-nap-dos-plus** | Builds a UBNI-based image with NGINX Plus, [NGINX App Protect WAF](/nginx-app-protect-waf/), and [NGINX App Protect DoS](/nginx-app-protect-dos/). | OpenShift |
{{</bootstrap-table>}}

<br>

{{< see-also >}} For the complete list of _Makefile_ targets and customizable variables, see the [Build NGINX Ingress Controller]({{< relref "installation/build-nginx-ingress-controller.md#makefile-details" >}}) topic. {{</ see-also >}}

---

## Push the image to your private registry

Once you've successfully built the NGINX Ingress Controller image with NGINX App Protect WAF, the next step is to upload it to your private Docker registry. This makes the image available for deployment to your Kubernetes cluster.

To upload the image, run the following command. If you're using a custom tag, add `TAG=your-tag` to the end of the command. Replace `<my-docker-registry>` with your private registry's path.

```shell
make push PREFIX=<my-docker-registry>/nginx-plus-ingress
```

---

## Set up role-based access control (RBAC) {#set-up-rbac}

{{< include "rbac/set-up-rbac.md" >}}

---

## Create common resources {#create-common-resources}

{{< include "installation/create-common-resources.md" >}}

---

## Create core custom resources {#create-custom-resources}


{{< include "installation/create-custom-resources.md" >}}

---

## Create App Protect WAF custom resources

{{< note >}} If you're using NGINX Ingress Controller with the App Protect WAF module and policy bundles, you can skip this section. You will need to create and configure [Persistent Volume and Persistent Volume Claim](https://kubernetes.io/docs/concepts/storage/persistent-volumes/) in your Kubernetes cluster. {{< /note >}}

<br>

{{<tabs name="install-waf-crds">}}

{{%tab name="Install CRDs from single YAML"%}}

This single YAML file creates CRDs for the following resources:

- `APPolicy`
- `APLogConf`
- `APUserSig`

```shell
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds-nap-waf.yaml
```

{{%/tab%}}

{{%tab name="Install CRDs after cloning the repo"%}}

{{< note >}} If you are installing the CRDs this way, ensure you have first cloned the repository. {{< /note >}}

These YAML files create CRDs for the following resources:

- `APPolicy`
- `APLogConf`
- `APUserSig`

```shell
kubectl apply -f config/crd/bases/appprotect.f5.com_appolicies.yaml
kubectl apply -f config/crd/bases/appprotect.f5.com_aplogconfs.yaml
kubectl apply -f config/crd/bases/appprotect.f5.com_apusersigs.yaml
```

{{%/tab%}}

{{</tabs>}}

---

## Deploy NGINX Ingress Controller {#deploy-ingress-controller}

{{< include "installation/deploy-controller.md" >}}

{{< note >}} If you're using NGINX Ingress Controller with the AppProtect WAF module and policy bundles, you will need to modify the Deployment or DaemonSet file to include volumes and volume mounts.

NGINX Ingress Controller **requires** the volume mount path to be `/etc/nginx/waf/bundles`. {{< /note >}}

Add a `volumes` section to deployment template spec:

```yaml
...
volumes:
- name: <volume_name>
persistentVolumeClaim:
    claimName: <claim_name>
...
```

Add volume mounts to the `containers` section:

```yaml
...
volumeMounts:
- name: <volume_mount_name>
    mountPath: /etc/nginx/waf/bundles
...
```

### Using a Deployment

{{< include "installation/manifests/deployment.md" >}}

### Using a DaemonSet

{{< include "installation/manifests/daemonset.md" >}}

---

## Enable NGINX App Protect WAF module

To enable the NGINX App Protect DoS Module:

- Add the `enable-app-protect` [command-line argument]({{< relref "configuration/global-configuration/command-line-arguments.md#cmdoption-enable-app-protect" >}}) to your Deployment or DaemonSet file.

---

## Confirm NGINX Ingress Controller is running

{{< include "installation/manifests/verify-pods-are-running.md" >}}

For more information, see the [Configuration guide]({{< relref "installation/integrations/app-protect-waf/configuration.md" >}}) and the NGINX Ingress Controller with App Protect example resources on GitHub [for VirtualServer resources](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/app-protect-waf) and [for Ingress resources](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/app-protect-waf).

---

## Alternatives to building your own image {#pre-built-images}

If you prefer not to build your own NGINX Ingress Controller image, you can use pre-built images. Here are your options:

- Download the image using your NGINX Ingress Controller subscription certificate and key. View the [Get NGINX Ingress Controller from the F5 Registry]({{< relref "installation/nic-images/get-registry-image.md" >}}) topic.
- The [Get the NGINX Ingress Controller image with JWT]({{< relref "installation/nic-images/get-image-using-jwt.md" >}}) topic describes how to use your subscription JWT token to get the image.
