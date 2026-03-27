---
title: Getting the NGINX Ingress Controller Image with JWT
description: "Use your NGINX Ingress Controller subscription JWT token to get the NGINX Plus Ingress Controller image from the F5 Docker registry."
weight: 150
doctypes: [""]
toc: true
---

{{<custom-styles>}}

## Overview

Follow the steps in this document to pull the NGINX Plus Ingress Controller image from the F5 Docker registry into your Kubernetes cluster using your JWT token.

{{<important>}}
An NGINX Plus subscription certificate and key will not work with the F5 Docker registry.

For NGINX Ingress Controller, you must have an NGINX Ingress Controller subscription -- download the NGINX Plus Ingress Controller (per instance) JWT access token from [MyF5](https://my.f5.com).

To list the available image tags using the Docker registry API, you will also need to download the NGINX Plus Ingress Controller (per instance) certificate (`nginx-repo.crt`) and the key (`nginx-repo.key`) from [MyF5](https://my.f5.com).{{</important>}}

{{< note >}}
You can also get the image using alternative methods:

* You can use Docker to pull an NGINX Ingress Controller image with NGINX Plus and push it to your private registry by following the ["Pulling the Ingress Controller Image"]({{< relref "installation/nic-images/pulling-ingress-controller-image" >}}) documentation.
* You can build an NGINX Ingress Controller image by following the ["Information on how to build an Ingress Controller image"]({{< relref "installation/building-nginx-ingress-controller" >}}) documentation.

If you would like to use an NGINX Ingress Controller image using NGINX open source, we provide the image through [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/).
{{< /note >}}

## Before You Begin

You will need the following information from [MyF5](https://my.f5.com) for these steps:

- A JWT Access Token (per instance) for NGINX Ingress Controller from an active NGINX Ingress Controller subscription.
- The certificate (`nginx-repo.crt`) and key (`nginx-repo.key`) for each NGINX Ingress Controller instance, used to list the available image tags from the Docker registry API.

## Prepare NGINX Ingress Controller

1. Choose your desired [NGINX Ingress Controller Image](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/#images-with-nginx-plus).
1. Log into the [MyF5 Portal](https://my.f5.com/), navigate to your subscription details, and download the relevant .cert, .key and .JWT files.
1. Create a Kubernetes secret using the JWT token. You should use `cat` to view the contents of the JWT token and store the output for use in later steps.
1. Ensure there are no additional characters or extra whitespace that might have been accidentally added. This will break authorization and prevent the NGINX Ingress Controller image from being downloaded.
1. Modify your deployment (manifest or Helm) to use the Kubernetes secret created in step 3.
1. Deploy NGINX Ingress Controller into your Kubernetes cluster and verify that the installation has been successful.

## Using the JWT token in a Docker Config Secret

1. Create a Kubernetes `docker-registry` secret type on the cluster, using the JWT token as the username and `none` for password (as the password is not used).  The name of the docker server is `private-registry.nginx.com`.

    ```shell
    kubectl create secret docker-registry regcred --docker-server=private-registry.nginx.com --docker-username=<JWT Token> --docker-password=none [-n nginx-ingress]
    ```

    It is important that the `--docker-username=<JWT Token>` contains the contents of the token and is not pointing to the token itself. Ensure that when you copy the contents of the JWT token, there are no additional characters or extra whitespaces. This can invalidate the token and cause 401 errors when trying to authenticate to the registry.

1. Confirm the details of the created secret by running:

    ```shell
    kubectl get secret regcred --output=yaml
    ```

1. You can now use the newly created Kubernetes secret in Helm and manifest deployments.

---

## Manifest Deployment

The page ["Installation with Manifests"](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/) explains how to install NGINX Ingress Controller using manifests. The following snippet is an example of a deployment:

```yaml
spec:
  serviceAccountName: nginx-ingress
  imagePullSecrets:
  - name: regcred
  automountServiceAccountToken: true
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - image: private-registry.nginx.com/nginx-ic/nginx-plus-ingress:3.3.2
    imagePullPolicy: IfNotPresent
    name: nginx-plus-ingress
```

The `imagePullSecrets` and `containers.image` lines represent the Kubernetes secret, as well as the registry and version of the NGINX Ingress Controller we are going to deploy.

---

## Helm Deployment

If you are using Helm for deployment, there are two main methods: using *sources* or *charts*.

### Helm Source

The [Installation with Helm ]({{< relref "installation/installing-nic/installation-with-helm.md#managing-the-chart-via-sources" >}}) documentation has a section describing how to use sources: these are the unique steps for Docker secrets using JWT tokens.

1. Clone the NGINX [`kubernetes-ingress` repository](https://github.com/nginxinc/kubernetes-ingress).
1. Navigate to the `charts/nginx-ingress` folder of your local clone.
1. Open the `values.yaml` file in an editor.

    You must change a few lines NGINX Ingress Controller with NGINX Plus to be deployed.

    1. Change the `nginxplus` argument to `true`.
    1. Change the `repository` argument to the NGINX Ingress Controller image you intend to use.
    2. Add an argument to `imagePullSecretName` or `imagePullSecretsNames` to allow Docker to pull the image from the private registry.

    The following code block shows snippets of the parameters you will need to change, and an example of their contents:

    ```yaml
    ## Deploys the Ingress Controller for NGINX Plus
    nginxplus: true
    ## Truncated fields
    ## ...
    ## ...
    image:
    ## The image repository for the desired NGINX Ingress Controller image
    repository: private-registry.nginx.com/nginx-ic/nginx-plus-ingress

    ## The version tag
    tag: 3.3.2

    serviceAccount:
        ## The annotations of the service account of the Ingress Controller pods.
        annotations: {}

    ## Truncated fields
    ## ...
    ## ...

        ## The name of the secret containing docker registry credentials.
        ## Secret must exist in the same namespace as the helm release.
        ## Note that also imagePullSecretsNames can be used here if multiple secrets need to be set.
        imagePullSecretName: regcred
    ```

With the modified `values.yaml` file, you can now use Helm to install NGINX Ingress Controller, for example:

```shell
helm install nicdev01 -n nginx-ingress --create-namespace -f values.yaml .
```

The above command will install NGINX Ingress Controller in the `nginx-ingress` namespace.

If the namespace does not exist, `--create-namespace` will create it. Using `-f values.yaml` tells Helm to use the `values.yaml` file that you modified earlier with the settings you want to apply for your NGINX Ingress Controller deployment.


### Helm Chart

If you want to install NGINX Ingress Controller using the charts method, the following is an example of using the command line to pass the required arguments using the `set` parameter.

```shell
helm install my-release -n nginx-ingress oci://ghcr.io/nginxinc/charts/nginx-ingress --version 1.0.2 --set controller.image.repository=private-registry.nginx.com/nginx-ic/nginx-plus-ingress --set controller.image.tag=3.3.2 --set controller.nginxplus=true --set controller.serviceAccount.imagePullSecretName=regcred
```
You can also use the certificate and key from the MyF5 portal and the Docker registry API to list the available image tags for the repositories, for example:

```shell
   $ curl https://private-registry.nginx.com/v2/nginx-ic/nginx-plus-ingress/tags/list --key <path-to-client.key> --cert <path-to-client.cert> | jq

   {
    "name": "nginx-ic/nginx-plus-ingress",
    "tags": [
        "3.3.2-alpine",
        "3.3.2-ubi",
        "3.3.2"
    ]
    }

   $ curl <https://private-registry.nginx.com/v2/nginx-ic-nap/nginx-plus-ingress/tags/list> --key <path-to-client.key> --cert <path-to-client.cert> | jq
   {
    "name": "nginx-ic-nap/nginx-plus-ingress",
    "tags": [
        "3.3.2-ubi",
        "3.3.2"
    ]
    }

   $ curl <https://private-registry.nginx.com/v2/nginx-ic-dos/nginx-plus-ingress/tags/list> --key <path-to-client.key> --cert <path-to-client.cert> | jq
   {
    "name": "nginx-ic-dos/nginx-plus-ingress",
    "tags": [
        "3.3.2-ubi",
        "3.3.2"
    ]
    }
```

---

## Pulling an Image for Local Use

If you need to pull the image for local use to then push to a different container registry, use this command:

```shell
docker login private-registry.nginx.com --username=<output_of_jwt_token> --password=none
```

Replace the contents of `<output_of_jwt_token>` with the contents of the JWT token itself.
Once you have successfully pulled the image, you can then tag it as needed.
