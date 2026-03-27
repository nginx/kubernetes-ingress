---
title: Getting the F5 Registry NGINX Ingress Controller Image
description: "Learn how to pull an F5 NGINX Plus Ingress Controller image—including those with NGINX App Protect WAF and NGINX App Protect DoS—from the official F5 Docker registry and upload it to your private registry. This guide covers the prerequisites, image tagging, and troubleshooting steps."
weight: 100
doctypes: ["install"]
toc: true
docs: "DOCS-605"
---

{{<custom-styles>}}

---

## Before you begin

Before you start, you'll need these installed on your machine:

- [Docker v18.09 or higher](https://docs.docker.com/engine/release-notes/18.09/).
- An NGINX Ingress Controller subscription. Download both the certificate (*nginx-repo.crt*) and key (*nginx-repo.key*) from the [MyF5 Customer Portal](https://my.f5.com). Keep in mind that an NGINX Plus certificate and key won't work for for the steps in this guide.

---

## Set up Docker for F5 Container Registry

Start by setting up Docker to communicate with the F5 Container Registry located at `private-registry.nginx.com`. If you're using Linux, follow these steps to create a directory and add your certificate and key:

```shell
mkdir -p /etc/docker/certs.d/private-registry.nginx.com
cp <path-to-your-nginx-repo.crt> /etc/docker/certs.d/private-registry.nginx.com/client.cert
cp <path-to-your-nginx-repo.key> /etc/docker/certs.d/private-registry.nginx.com/client.key
```

The steps provided are for Linux. For Mac or Windows, consult the [Docker for Mac](https://docs.docker.com/docker-for-mac/#add-client-certificates) or [Docker for Windows](https://docs.docker.com/docker-for-windows/#how-do-i-add-client-certificates) documentation. For more details on Docker Engine security, you can refer to the [Docker Engine Security documentation](https://docs.docker.com/engine/security/).

---

## Pull the image

Next, pull the image you need from `private-registry.nginx.com`. To find the correct image, consult the [Tech Specs guide]({{< relref "technical-specifications#images-with-nginx-plus" >}}).

To pull an image, follow these steps. Replace `<version-tag>` with the specific version you need, for example, `3.3.2`.

- For NGINX Plus Ingress Controller, run:

  ```shell
  docker pull private-registry.nginx.com/nginx-ic/nginx-plus-ingress:<version-tag>
  ```

- For NGINX Plus Ingress Controller with NGINX App Protect WAF, run:

   ```shell
   docker pull private-registry.nginx.com/nginx-ic-nap/nginx-plus-ingress:<version-tag>
   ```

- For NGINX Plus Ingress Controller with NGINX App Protect DoS, run:

   ```shell
   docker pull private-registry.nginx.com/nginx-ic-dos/nginx-plus-ingress:<version-tag>
   ```

You can use the Docker registry API to list the available image tags by running the following commands. Replace `<path-to-client.key>` with the location of your client key and `<path-to-client.cert>` with the location of your client certificate. The `jq` command is used to format the JSON output for easier reading.

```json
$ curl https://private-registry.nginx.com/v2/nginx-ic/nginx-plus-ingress/tags/list --key <path-to-client.key> --cert <path-to-client.cert> | jq
{
  "name": "nginx-ic/nginx-plus-ingress",
  "tags": [
    "3.3.2-alpine",
    "3.3.2-ubi",
    "3.3.2"
  ]
}

$ curl https://private-registry.nginx.com/v2/nginx-ic-nap/nginx-plus-ingress/tags/list --key <path-to-client.key> --cert <path-to-client.cert> | jq
{
  "name": "nginx-ic-nap/nginx-plus-ingress",
  "tags": [
    "3.3.2-ubi",
    "3.3.2"
  ]
}

$ curl https://private-registry.nginx.com/v2/nginx-ic-dos/nginx-plus-ingress/tags/list --key <path-to-client.key> --cert <path-to-client.cert> | jq
{
  "name": "nginx-ic-dos/nginx-plus-ingress",
  "tags": [
    "3.3.2-ubi",
    "3.3.2"
  ]
}
```

---

## Push to your private registry

After pulling the image, tag it and upload it to your private registry.

1. Log in to your private registry:

   ```shell
   docker login <my-docker-registry>
   ```

1. Tag and push the image. Replace `<my-docker-registry>` with your registry's path and `<version-tag>` with the version you're using, for example `3.3.2`:

   - For NGINX Plus Ingress Controller, run:

      ```shell
      docker tag private-registry.nginx.com/nginx-ic/nginx-plus-ingress:<version-tag> <my-docker-registry>/nginx-ic/nginx-plus-ingress:<version-tag>
      docker push <my-docker-registry>/nginx-ic/nginx-plus-ingress:<version-tag>
      ```

   - For NGINX Controller with NGINX App Protect WAF, run:

      ```shell
      docker tag private-registry.nginx.com/nginx-ic-nap/nginx-plus-ingress:<version-tag> <my-docker-registry>/nginx-ic-nap/nginx-plus-ingress:<version-tag>
      docker push <my-docker-registry>/nginx-ic-nap/nginx-plus-ingress:<version-tag>
      ```

   - For NGINX Controller with NGINX App Protect DoS, run:

      ```shell
      docker tag private-registry.nginx.com/nginx-ic-dos/nginx-plus-ingress:<version-tag> <my-docker-registry>/nginx-ic-dos/nginx-plus-ingress:<version-tag>
      docker push <my-docker-registry>/nginx-ic-dos/nginx-plus-ingress:<version-tag>
      ```

---

## Troubleshooting

If you encounter issues while following this guide, here are solutions to common problems:

- **Certificate errors**
  - **Likely Cause**: Incorrect certificate or key location, or using an NGINX Plus certificate.
  - **Solution**: Verify you have the correct NGINX Ingress Controller certificate and key. Place them in the correct directory and ensure the certificate has a *.cert* extension.

- **Docker version compatibility**
  - **Likely Cause**: Outdated Docker version.
  - **Solution**: Make sure you're running [Docker v18.09 or higher](https://docs.docker.com/engine/release-notes/18.09/). Upgrade if necessary.

- **Can't pull the image**
  - **Likely Cause**: Mismatched image name or tag.
  - **Solution**: Double-check the image name and tag against the [Tech Specs guide]({{< relref "technical-specifications.md#images-with-nginx-plus" >}}).

- **Failed to push to private registry**
  - **Likely Cause**: Not logged into your private registry or incorrect image tagging.
  - **Solution**: Verify login status and correct image tagging before pushing. Consult the [Docker documentation](https://docs.docker.com/docker-hub/repos/) for more details.

---

## Alternative installation options

You can also get the NGINX Ingress Controller image using the following alternate methods:

- [Install using a JWT token in a Docker Config Secret]({{< relref "using-the-jwt-token-docker-secret" >}}).
- [Build the Ingress Controller image]({{< relref "building-nginx-ingress-controller" >}}) using the source code from the GitHub repository and your NGINX Plus subscription certificate and key.
- For NGINX Ingress Controller based on NGINX OSS, you can pull the [nginx/nginx-ingress image](https://hub.docker.com/r/nginx/nginx-ingress/) from DockerHub.
