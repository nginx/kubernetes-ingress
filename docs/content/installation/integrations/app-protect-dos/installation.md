---
title: Building NGINX Ingress Controller with NGINX App Protect DoS
description: "This document explains how to build an image for NGINX Ingress Controller with the NGINX App Protect DoS from source code."
weight: 100
doctypes: [""]
toc: true
docs: "DOCS-583"
---

{{< custom-styles >}}

{{<call-out "tip" "Pre-built image alternatives" >}}If you'd rather not build your own NGINX Ingress Controller image, see the [pre-built image options](#pre-built-images) at the end of this guide.{{</call-out>}}

## Before you start

- To use NGINX App Protect DoS with NGINX Ingress Controller, you must have NGINX Plus.

---

## Prepare the environment {#prepare-environment}

Get your system ready for building and pushing the NGINX Ingress Controller image with NGINX App Protect DoS.

1. Sign in to your private registry. Replace `<my-docker-registry>` with the path to your own private registry.

    ```shell
    docker login <my-docker-registry>
    ```

2. Clone the NGINX Ingress Controller GitHub repository. Replace `<version_number>` with the version of NGINX Ingress Controller you want.

    ```shell
    git clone https://github.com/nginxinc/kubernetes-ingress.git --branch <version_number>
    cd kubernetes-ingress
    ```

    For instance if you want to clone version v3.3.2, the commands to run would be:

    ```shell
    git clone https://github.com/nginxinc/kubernetes-ingress.git --branch v3.3.2
    cd kubernetes-ingress/deployments
    ```

---

## Build the image {#build-docker-image}

Follow these steps to build the NGINX Controller Image with NGINX App Protect DoS.

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

     **What to expect**: The image is built and tagged with a version number, which is derived from the `VERSION` variable in the [_Makefile_]({{< relref "installation/building-nginx-ingress-controller.md#makefile-details" >}}). This version number is used for tracking and deployment purposes.

{{<note>}}In the event a patch version of NGINX Plus is released, make sure to rebuild your image to get the latest version. If your system is caching the Docker layers and not updating the packages, add `DOCKER_BUILD_OPTIONS="--pull --no-cache"` to the make command.{{</note>}}

### Makefile targets {#makefile-targets}

{{<bootstrap-table "table table-striped table-bordered">}}
| Makefile Target           | Description                                                       | Compatible Systems  |
|---------------------------|-------------------------------------------------------------------|---------------------|
| **debian-image-dos-plus** | Builds a Debian-based image with NGINX Plus and the [NGINX App Protect DoS](/nginx-app-protect-dos/) module. | Debian  |
| **debian-image-nap-dos-plus** | Builds a Debian-based image with NGINX Plus, [NGINX App Protect DoS](/nginx-app-protect-dos/), and [NGINX App Protect WAF](/nginx-app-protect/). | Debian  |
| **ubi-image-dos-plus**    | Builds a UBI-based image with NGINX Plus and the [NGINX App Protect DoS](/nginx-app-protect-dos/) module. | OpenShift |
| **ubi-image-nap-dos-plus** | Builds a UBI-based image with NGINX Plus, [NGINX App Protect DoS](/nginx-app-protect-dos/), and [NGINX App Protect WAF](/nginx-app-protect/). | OpenShift |
{{</bootstrap-table>}}

<br>

{{<see-also>}}For the complete list of _Makefile_ targets and customizable variables, see the [Building NGINX Ingress Controller]({{< relref "installation/building-nginx-ingress-controller.md#makefile-details" >}}) guide{{</see-also>}}

---

## Push the image to your private registry

Once you've successfully built the NGINX Ingress Controller image with NGINX App Protect DoS, the next step is to upload it to your private Docker registry. This makes the image available for deployment to your Kubernetes cluster.

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

## Create custom resources {#create-custom-resources}

{{< include "installation/create-custom-resources.md" >}}

---

## Create App Protect DoS custom resources

{{<tabs name="install-dos-crds">}}

{{%tab name="Install CRDs from single YAML"%}}

This single YAML file creates CRDs for the following resources:

- `APDosPolicy`
- `APDosLogConf`
- `DosProtectedResource`

```shell
kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/deploy/crds-nap-dos.yaml
```

{{%/tab%}}

{{%tab name="Install CRDs after cloning the repo"%}}

These YAML files create CRDs for the following resources:

- `APDosPolicy`
- `APDosLogConf`
- `DosProtectedResource`

```shell
kubectl apply -f config/crd/bases/appprotectdos.f5.com_apdoslogconfs.yaml
kubectl apply -f config/crd/bases/appprotectdos.f5.com_apdospolicy.yaml
kubectl apply -f config/crd/bases/appprotectdos.f5.com_dosprotectedresources.yaml
```

{{%/tab%}}

{{</tabs>}}

---

## Deploy NGINX Ingress Controller {#deploy-ingress-controller}

{{< include "installation/deploy-controller.md" >}}

### Using a Deployment

{{< include "installation/manifests/deployment.md" >}}

### Using a DaemonSet

{{< include "installation/manifests/daemonset.md" >}}

---

## Install the App Protect DoS Arbitrator

### Helm Chart

The App Protect DoS Arbitrator can be installed using the [NGINX App Protect DoS Helm Chart](https://github.com/nginxinc/nap-dos-arbitrator-helm-chart).
If you have the NGINX Helm Repository already added, you can install the App Protect DoS Arbitrator by running the following command:

```shell
helm install my-release-dos nginx-stable/nginx-appprotect-dos-arbitrator
```

### YAML Manifests

Alternatively, you can install the App Protect DoS Arbitrator using the YAML manifests provided in the NGINX Ingress Controller repo.

1. Create the namespace and service account:

    ```shell
      kubectl apply -f common/ns-and-sa.yaml
    ```

2. Deploy the NGINX App Protect Arbitrator as a Deployment and service:

    ```shell
    kubectl apply -f deployment/appprotect-dos-arb.yaml
    kubectl apply -f service/appprotect-dos-arb-svc.yaml
    ```

---

## Enable NGINX App Protect DoS module

To enable the NGINX App Protect DoS Module:

- Add the `enable-app-protect-dos` [command-line argument]({{< relref "configuration/global-configuration/command-line-arguments.md#cmdoption-enable-app-protect-dos" >}}) to your Deployment or DaemonSet file.

---

## Confirm NGINX Ingress Controller is running

{{< include "installation/manifests/verify-pods-are-running.md" >}}

For more information, see the [Configuration guide]({{< relref "installation/integrations/app-protect-dos/configuration.md" >}}),the [NGINX Ingress Controller with App Protect DoS example for VirtualServer](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/custom-resources/app-protect-dos) and the [NGINX Ingress Controller with App Protect DoS example for Ingress](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/app-protect-dos).

---

## Alternatives to building your own image {#pre-built-images}

If you prefer not to build your own NGINX Ingress Controller image, you can use pre-built images. Here are your options:

- Download the image using your NGINX Ingress Controller subscription certificate and key. See the [Getting the F5 Registry NGINX Ingress Controller Image]({{< relref "installation/nic-images/pulling-ingress-controller-image.md" >}}) guide.
- Use your NGINX Ingress Controller subscription JWT token to get the image: Instructions are in [Getting the NGINX Ingress Controller Image with JWT]({{< relref "installation/nic-images/using-the-jwt-token-docker-secret.md" >}}).
