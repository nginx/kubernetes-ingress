---
title: Installation with Helm
toc: true
weight: 100
type: how-to
product: NIC
docs: DOCS-602
---

This document explains how to install F5 NGINX Ingress Controller using [Helm](https://helm.sh/).

## Before you begin

{{< note >}} All documentation should only be used with the latest stable release, indicated on [the releases page]({{< relref "releases.md" >}}) of the GitHub repository. {{< /note >}}

- A [Kubernetes Version Supported by NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/#supported-kubernetes-versions)
- Helm 3.0+.
- If you’d like to use NGINX Plus:
  - Get the NGINX Ingress Controller JWT and [create a license secret]({{< relref "/installation/create-license-secret.md" >}}).
  - Download the image using your NGINX Ingress Controller subscription certificate and key. View the [Get NGINX Ingress Controller from the F5 Registry]({{< relref "installation/nic-images/get-registry-image.md" >}}) topic.
  - The [Get the NGINX Ingress Controller image with JWT]({{< relref "installation/nic-images/get-image-using-jwt.md" >}}) topic describes how to use your subscription JWT token to get the image.
  - The [Build NGINX Ingress Controller]({{< relref "installation/build-nginx-ingress-controller.md" >}}) topic explains how to push an image to a private Docker registry.
  - Update the `controller.image.repository` field of the `values-plus.yaml` accordingly.

---

## Custom Resource Definitions

NGINX Ingress Controller requires custom resource definitions (CRDs) installed in the cluster, which Helm will install. If the CRDs are not installed, NGINX Ingress Controller pods will not become `Ready`.

If you do not use the custom resources that require those CRDs (which corresponds to `controller.enableCustomResources` set to `false` and `controller.appprotect.enable` set to `false` and `controller.appprotectdos.enable` set to `false`), the installation of the CRDs can be skipped by specifying `--skip-crds` for the helm install command.

---

### Upgrade the CRDs

{{< note >}} Please make sure to read the steps outlined in [Upgrade to V4](https://docs.nginx.com/nginx-ingress-controller/installation/installing-nic/upgrade-to-v4/#update-custom-resource-apiversion) before running the CRD upgrade and perform the steps if applicable.
{{< /note >}}

To upgrade the CRDs, pull the chart sources as described in [Pull the Chart](#pull-the-chart) and then run:

```shell
kubectl apply -f crds/
```

Alternatively, CRDs can be upgraded without pulling the chart by running:

```shell
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/deploy/crds.yaml
```

In the above command, `v{{< nic-version >}}` represents the version of NGINX Ingress Controller release rather than the Helm chart version.

{{< note >}} The following warning is expected and can be ignored: `Warning: kubectl apply should be used on resource created by either kubectl create --save-config or kubectl apply`.

Check the [release notes](https://www.github.com/nginx/kubernetes-ingress/releases) for a new release for any special upgrade procedures.
{{< /note >}}

### Uninstall the CRDs

To remove the CRDs, pull the chart sources as described in [Pull the Chart](#pull-the-chart) and then run:

```shell
kubectl delete -f crds/
```

{{< warning >}} This command will delete all the corresponding custom resources in your cluster across all namespaces. Please ensure there are no custom resources that you want to keep and there are no other NGINX Ingress Controller instances running in the cluster. {{< /warning >}}

## Manage the chart with OCI Registry

### Install the chart

Run the following commands to install the chart with the release name my-release (my-release is the name that you choose):

- For NGINX:

    ```shell
    helm install my-release oci://ghcr.io/nginx/charts/nginx-ingress --version {{< nic-helm-version >}}
    ```

- For NGINX Plus: (This assumes you have pushed NGINX Ingress Controller image `nginx-plus-ingress` to your private registry `myregistry.example.com`)

    ```shell
    helm install my-release oci://ghcr.io/nginx/charts/nginx-ingress --version {{< nic-helm-version >}} --set controller.image.repository=myregistry.example.com/nginx-plus-ingress --set controller.nginxplus=true
    ```

These commands install the latest `edge` version of NGINX Ingress Controller from GitHub Container Registry. If you prefer using Docker Hub, you can replace `ghcr.io/nginx/charts/nginx-ingress` with `registry-1.docker.io/nginxcharts/nginx-ingress`.

### Upgrade the chart

Helm does not upgrade the CRDs during a release upgrade. Before you upgrade a release, see [Upgrade the CRDs](#upgrade-the-crds).

To upgrade the release `my-release`:

```shell
helm upgrade my-release oci://ghcr.io/nginx/charts/nginx-ingress --version {{< nic-helm-version >}}
```

### Uninstall the chart

To uninstall/delete the release `my-release`:

```shell
helm uninstall my-release
```

The command removes all the Kubernetes components associated with the release and deletes the release.

Uninstalling the release does not remove the CRDs. To remove the CRDs, see [Uninstall the CRDs](#uninstall-the-crds).

### Edge version

To test the latest changes in NGINX Ingress Controller before a new release, you can install the `edge` version. This version is built from the `main` branch of the NGINX Ingress Controller repository.
You can install the `edge` version by specifying the `--version` flag with the value `0.0.0-edge`:

```shell
helm install my-release oci://ghcr.io/nginx/charts/nginx-ingress --version 0.0.0-edge
```

{{< warning >}} The `edge` version is not intended for production use. It is intended for testing and development purposes only. {{< /warning >}}

## Manage the chart with Sources

### Pull the chart

This step is required if you're installing the chart using its sources. It also manages the custom resource definitions (CRDs) which NGINX Ingress Controller requires, and for upgrading or deleting the CRDs.

1. Pull the chart sources:

    ```shell
    helm pull oci://ghcr.io/nginx/charts/nginx-ingress --untar --version {{< nic-helm-version >}}
    ```

2. Change your working directory to nginx-ingress:

    ```shell
    cd nginx-ingress
    ```

### Install the chart

To install the chart with the release name my-release (my-release is the name that you choose):

- For NGINX:

    ```shell
    helm install my-release .
    ```

- For NGINX Plus:

    ```shell
    helm install my-release -f values-plus.yaml .
    ```

The command deploys the Ingress Controller in your Kubernetes cluster in the default configuration. The configuration section lists the parameters that can be configured during installation.

### Upgrade the chart

Helm does not upgrade the CRDs during a release upgrade. Before you upgrade a release, see [Upgrade the CRDs](#upgrade-the-crds).

To upgrade the release `my-release`:

```shell
helm upgrade my-release .
```

### Uninstall the chart

To uninstall/delete the release `my-release`:

```shell
helm uninstall my-release
```

The command removes all the Kubernetes components associated with the release and deletes the release.

Uninstalling the release does not remove the CRDs. To remove the CRDs, see [Uninstall the CRDs](#uninstall-the-crds).

## Upgrade without downtime

### Background

In NGINX Ingress Controller version 3.1.0, [changes were introduced](https://github.com/nginx/kubernetes-ingress/pull/3606) to Helm resource names, labels and annotations to fit with Helm best practices.
When using Helm to upgrade from a version prior to 3.1.0, certain resources like Deployment, DaemonSet and Service will be recreated due to the aforementioned changes, which will result in downtime.

Although the advisory is to update all resources in accordance with new naming convention, to avoid downtime follow the steps listed below.

### Upgrade steps

{{< note >}} The following steps apply to both 2.x and 3.0.x releases.  {{</ note >}}

The steps you should follow depend on the Helm release name:

{{<tabs name="upgrade-helm">}}

{{%tab name="Helm release name is `nginx-ingress`"%}}

1. Use `kubectl describe` on deployment/daemonset to get the `Selector` value:

    ```shell
    kubectl describe deployments -n <namespace>
    ```

   Copy the key=value under `Selector`, such as:

    ```shell
    Selector: app=nginx-ingress-nginx-ingress
    ```

2. Checkout the latest available tag using `git checkout v{{< nic-version >}}`

3. Navigate to `/kubernates-ingress/charts/nginx-ingress`

4. Update the `selectorLabels: {}` field in the `values.yaml` file located at `/kubernates-ingress/charts/nginx-ingress` with the copied `Selector` value.
    ```shell
    selectorLabels: {app: nginx-ingress-nginx-ingress}
    ```

5. Run `helm upgrade` with following arguments set:
    ```shell
    --set serviceNameOverride="nginx-ingress-nginx-ingress"
    --set controller.name=""
    --set fullnameOverride="nginx-ingress-nginx-ingress"
    ```
   It could look as follows:

    ```shell
    helm upgrade nginx-ingress oci://ghcr.io/nginx/charts/nginx-ingress --version 0.19.0 --set controller.kind=deployment/daemonset --set controller.nginxplus=false/true --set controller.image.pullPolicy=Always --set serviceNameOverride="nginx-ingress-nginx-ingress" --set controller.name="" --set fullnameOverride="nginx-ingress-nginx-ingress" -f values.yaml
    ```

6. Once the upgrade process has finished, use `kubectl describe` on the deployment to verify the change by reviewing its events:
    ```shell
        Type    Reason             Age    From                   Message
    ----    ------             ----   ----                   -------
    Normal  ScalingReplicaSet  9m11s  deployment-controller  Scaled up replica set nginx-ingress-nginx-ingress-<old_version> to 1
    Normal  ScalingReplicaSet  101s   deployment-controller  Scaled up replica set nginx-ingress-nginx-ingress-<new_version> to 1
    Normal  ScalingReplicaSet  98s    deployment-controller  Scaled down replica set nginx-ingress-nginx-ingress-<old_version> to 0 from 1
    ```
{{%/tab%}}

{{%tab name="Helm release name is not `nginx-ingress`"%}}

1. Use `kubectl describe` on deployment/daemonset to get the `Selector` value:

    ```shell
    kubectl describe deployment/daemonset -n <namespace>
    ```

   Copy the key=value under ```Selector```, such as:

    ```shell
    Selector: app=<helm_release_name>-nginx-ingress
    ```

2. Checkout the latest available tag using `git checkout v{{< nic-version >}}`

3. Navigate to `/kubernates-ingress/charts/nginx-ingress`

4. Update the `selectorLabels: {}` field in the `values.yaml` file located at `/kubernates-ingress/charts/nginx-ingress` with the copied `Selector` value.

    ```shell
    selectorLabels: {app: <helm_release_name>-nginx-ingress}
    ```

5. Run `helm upgrade` with following arguments set:

    ```shell
    --set serviceNameOverride="<helm_release_name>-nginx-ingress"
    --set controller.name=""
    ```

   It could look as follows:

    ```shell
    helm upgrade test-release oci://ghcr.io/nginx/charts/nginx-ingress --version 0.19.0 --set controller.kind=deployment/daemonset --set controller.nginxplus=false/true --set controller.image.pullPolicy=Always --set serviceNameOverride="test-release-nginx-ingress" --set controller.name="" -f values.yaml
    ```

6. Once the upgrade process has finished, use `kubectl describe` on the deployment to verify the change by reviewing its events:

    ```shell
        Type    Reason             Age    From                   Message
    ----    ------             ----   ----                   -------
    Normal  ScalingReplicaSet  9m11s  deployment-controller  Scaled up replica set test-release-nginx-ingress-<old_version> to 1
    Normal  ScalingReplicaSet  101s   deployment-controller  Scaled up replica set test-release-nginx-ingress-<new_version> to 1
    Normal  ScalingReplicaSet  98s    deployment-controller  Scaled down replica set test-release-nginx-ingress-<old_version> to 0 from 1
    ```

{{%/tab%}}

{{</tabs>}}


## Run multiple NGINX Ingress Controllers

If you are running NGINX Ingress Controller releases in your cluster with custom resources enabled, the releases will share a single version of the CRDs.

Ensure the NGINX Ingress Controller versions match the version of the CRDs. When uninstalling a release, ensure that you don’t remove the CRDs until there are no other NGINX Ingress Controller releases running in the cluster.

The [Run multiple NGINX Ingress Controllers]({{< relref "installation/run-multiple-ingress-controllers.md" >}}) topic has more details.

## Configuration

The following tables lists the configurable parameters of the NGINX Ingress Controller chart and their default values.

{{< table >}}
{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Parameter | Description | Default |
| --- | --- | --- |
| **controller.name** | The name of the Ingress Controller daemonset or deployment. | Autogenerated |
| **controller.kind** | The kind of the Ingress Controller installation - deployment or daemonset. | deployment |
| **controller.annotations** | Allows for setting of `annotations` for deployment or daemonset. | {} |
| **controller.nginxplus** | Deploys the Ingress Controller for NGINX Plus. | false |
| **controller.mgmt.licenseTokenSecretName** | Configures the secret used in the [license_token](https://nginx.org/en/docs/ngx_mgmt_module.html#license_token) directive. This key assumes the secret is in the Namespace that NGINX Ingress Controller is deployed in. The secret must be of type `nginx.com/license` with the base64 encoded JWT in the `license.jwt` key. | license-token |
| **controller.mgmt.enforceInitialReport** | Configures the [enforce_initial_report](https://nginx.org/en/docs/ngx_mgmt_module.html#enforce_initial_report) directive, which enables or disables the 180-day grace period for sending the initial usage report. | false |
| **controller.mgmt.usageReport.endpoint** | Configures the endpoint of the [usage_report](https://nginx.org/en/docs/ngx_mgmt_module.html#usage_report) directive. This is used to configure the endpoint NGINX uses to send usage reports to NIM. | product.connect.nginx.com |
| **controller.mgmt.usageReport.interval** | Configures the interval of the [usage_report](https://nginx.org/en/docs/ngx_mgmt_module.html#usage_report) directive. This specifies the frequency that usage reports are sent. This field takes an [NGINX time](https://nginx.org/en/docs/syntax.html). | 1h |
| **controller.mgmt.sslVerify** | Configures the [ssl_verify](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_verify) directive, which enables or disables verification of the usage reporting endpoint certificate.  | true |
| **controller.mgmt.resolver.ipv6** | Configures whether the mgmt block [resolver](https://nginx.org/en/docs/ngx_mgmt_module.html#resolver) directive will look up IPv6 addresses.  | true |
| **controller.mgmt.resolver.valid** | Configures an [NGINX time](https://nginx.org/en/docs/syntax.html) that the mgmt block [resolver](https://nginx.org/en/docs/ngx_mgmt_module.html#resolver) directive will override the TTL value of responses from nameservers with.  | N/A |
| **controller.mgmt.resolver.addresses** | Configures addresses used in the mgmt block [resolver](https://nginx.org/en/docs/ngx_mgmt_module.html#resolver) directive. This field takes a list of addresses. | N/A |
| **controller.mgmt.sslCertificateSecretName** | Configures the secret used to create the `ssl_certificate` and `ssl_certificate_key` directives. This key assumes the secret is in the Namespace that NGINX Ingress Controller is deployed in. The secret must be of type `kubernetes.io/tls` | N/A |
| **controller.mgmt.sslTrustedCertificateSecretName** | Configures the secret used to create the file(s) referenced the in [ssl_trusted_certifcate](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_trusted_certificate), and [ssl_crl](https://nginx.org/en/docs/ngx_mgmt_module.html#ssl_crl) directives. This key assumes the secret is in the Namespace that NGINX Ingress Controller is deployed in. The secret must be of type `nginx.org/ca`, where the `ca.crt` key contains a base64 encoded trusted cert, and the optional `ca.crl` key can contain a base64 encoded CRL. If the optional `ca.crl` key is supplied, it will configure the NGINX `ssl_crl` directive. | N/A |
| **controller.mgmt.configMapName** | Allows changing the name of the MGMT config map. The name should not include a namespace| Autogenerated |
| **controller.nginxReloadTimeout** | The timeout in milliseconds which the Ingress Controller will wait for a successful NGINX reload after a change or at the initial start. | 60000 |
| **controller.hostNetwork** | Enables the Ingress Controller pods to use the host's network namespace. | false |
| **controller.dnsPolicy** | DNS policy for the Ingress Controller pods. | ClusterFirst |
| **controller.nginxDebug** | Enables debugging for NGINX. Uses the `nginx-debug` binary. Requires `error-log-level: debug` in the ConfigMap via `controller.config.entries`. | false |
| **controller.logLevel** | The log level of the Ingress Controller. | info |
| **controller.logFormat** | The log format of the Ingress Controller. | glog |
| **controller.image.digest** | The image digest of the Ingress Controller. | None |
| **controller.image.repository** | The image repository of the Ingress Controller. | nginx/nginx-ingress |
| **controller.image.tag** | The tag of the Ingress Controller image. | {{< nic-version >}} |
| **controller.image.pullPolicy** | The pull policy for the Ingress Controller image. | IfNotPresent |
| **controller.lifecycle** | The lifecycle of the Ingress Controller pods. | {} |
| **controller.customConfigMap** | The name of the custom ConfigMap used by the Ingress Controller. If set, then the default config is ignored. | "" |
| **controller.config.name** | The name of the ConfigMap used by the Ingress Controller. | Autogenerated |
| **controller.config.annotations** | The annotations of the Ingress Controller configmap. | {} |
| **controller.config.entries** | The entries of the ConfigMap for customizing NGINX configuration. See [ConfigMap resource docs](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/) for the list of supported ConfigMap keys. | {} |
| **controller.customPorts** | A list of custom ports to expose on the NGINX Ingress Controller pod. Follows the conventional Kubernetes yaml syntax for container ports. | [] |
| **controller.defaultTLS.cert** | The base64-encoded TLS certificate for the default HTTPS server. **Note:** It is recommended that you specify your own certificate. Alternatively, omitting the default server secret completely will configure NGINX to reject TLS connections to the default server. |
| **controller.defaultTLS.key** | The base64-encoded TLS key for the default HTTPS server. **Note:** It is recommended that you specify your own key. Alternatively, omitting the default server secret completely will configure NGINX to reject TLS connections to the default server. |
| **controller.defaultTLS.secret** | The secret with a TLS certificate and key for the default HTTPS server. The value must follow the following format: `<namespace>/<name>`. Used as an alternative to specifying a certificate and key using `controller.defaultTLS.cert` and `controller.defaultTLS.key` parameters. **Note:** Alternatively, omitting the default server secret completely will configure NGINX to reject TLS connections to the default server. | None |
| **controller.wildcardTLS.cert** | The base64-encoded TLS certificate for every Ingress/VirtualServer host that has TLS enabled but no secret specified. If the parameter is not set, for such Ingress/VirtualServer hosts NGINX will break any attempt to establish a TLS connection. | None |
| **controller.wildcardTLS.key** | The base64-encoded TLS key for every Ingress/VirtualServer host that has TLS enabled but no secret specified. If the parameter is not set, for such Ingress/VirtualServer hosts NGINX will break any attempt to establish a TLS connection. | None |
| **controller.wildcardTLS.secret** | The secret with a TLS certificate and key for every Ingress/VirtualServer host that has TLS enabled but no secret specified. The value must follow the following format: `<namespace>/<name>`. Used as an alternative to specifying a certificate and key using `controller.wildcardTLS.cert` and `controller.wildcardTLS.key` parameters. | None |
| **controller.nodeSelector** | The node selector for pod assignment for the Ingress Controller pods. | {} |
| **controller.terminationGracePeriodSeconds** | The termination grace period of the Ingress Controller pod. | 30 |
| **controller.tolerations** | The tolerations of the Ingress Controller pods. | [] |
| **controller.affinity** | The affinity of the Ingress Controller pods. | {} |
| **controller.topologySpreadConstraints** | The topology spread constraints of the Ingress controller pods. | {} |
| **controller.env** | The additional environment variables to be set on the Ingress Controller pods. | [] |
| **controller.volumes** | The volumes of the Ingress Controller pods. | [] |
| **controller.volumeMounts** | The volumeMounts of the Ingress Controller pods. | [] |
| **controller.initContainers** | InitContainers for the Ingress Controller pods. | [] |
| **controller.extraContainers** | Extra (eg. sidecar) containers for the Ingress Controller pods. | [] |
| **controller.podSecurityContext**| The SecurityContext for Ingress Controller pods. | "seccompProfile": {"type": "RuntimeDefault"} |
| **controller.securityContext** | The SecurityContext for Ingress Controller container. | {} |
| **controller.initContainerSecurityContext** | The SecurityContext for Ingress Controller init container when `readOnlyRootFilesystem` is enabled by either setting `controller.securityContext.readOnlyRootFilesystem` or `controller.readOnlyRootFilesystem`to `true`. | {} |
| **controller.resources** | The resources of the Ingress Controller pods. | requests: cpu=100m,memory=128Mi |
| **controller.initContainerResources** | The resources of the init container which is used when `readOnlyRootFilesystem` is enabled by either setting `controller.securityContext.readOnlyRootFilesystem` or `controller.readOnlyRootFilesystem`to `true`. | requests: cpu=100m,memory=128Mi |
| **controller.replicaCount** | The number of replicas of the Ingress Controller deployment. | 1 |
| **controller.ingressClass.name** | A class of the Ingress Controller. An IngressClass resource with the name equal to the class must be deployed. Otherwise, the Ingress Controller will fail to start. The Ingress Controller only processes resources that belong to its class - i.e. have the "ingressClassName" field resource equal to the class. The Ingress Controller processes all the VirtualServer/VirtualServerRoute/TransportServer resources that do not have the "ingressClassName" field for all versions of Kubernetes. | nginx |
| **controller.ingressClass.create** | Creates a new IngressClass object with the name `controller.ingressClass.name`. Set to `false` to use an existing ingressClass created using `kubectl` with the same name. If you use `helm upgrade`, do not change the values from the previous release as helm will delete IngressClass objects managed by helm. If you are upgrading from a release earlier than {{< nic-version >}}, do not set the value to false. | true |
| **controller.ingressClass.setAsDefaultIngress** | New Ingresses without an `"ingressClassName"` field specified will be assigned the class specified in `controller.ingressClass.name`. Requires `controller.ingressClass.create`.  | false |
| **controller.watchNamespace** | Comma separated list of namespaces the Ingress Controller should watch for resources. By default the Ingress Controller watches all namespaces. Mutually exclusive with `controller.watchNamespaceLabel`. Please note that if configuring multiple namespaces using the Helm cli `--set` option, the string needs to wrapped in double quotes and the commas escaped using a backslash - e.g. `--set controller.watchNamespace="default\,nginx-ingress"`. | "" |
| **controller.watchNamespaceLabel** | Configures the Ingress Controller to watch only those namespaces with label foo=bar. By default the Ingress Controller watches all namespaces. Mutually exclusive with `controller.watchNamespace`. | "" |
| **controller.watchSecretNamespace** | Comma separated list of namespaces the Ingress Controller should watch for resources of type Secret. If this arg is not configured, the Ingress Controller watches the same namespaces for all resources. See `controller.watchNamespace` and `controller.watchNamespaceLabel`. Please note that if configuring multiple namespaces using the Helm cli `--set` option, the string needs to wrapped in double quotes and the commas escaped using a backslash - e.g. `--set controller.watchSecretNamespace="default\,nginx-ingress"`. | "" |
| **controller.enableCustomResources** | Enable the custom resources. | true |
| **controller.enableOIDC** | Enable OIDC policies. | false |
| **controller.enableTLSPassthrough** | Enable TLS Passthrough on default port 443. Requires `controller.enableCustomResources`. | false |
| **controller.tlsPassThroughPort** | Set the port for the TLS Passthrough. Requires `controller.enableCustomResources` and `controller.enableTLSPassthrough`.  | 443 |
| **controller.enableCertManager** | Enable x509 automated certificate management for VirtualServer resources using cert-manager (cert-manager.io). Requires `controller.enableCustomResources`. | false |
| **controller.enableExternalDNS** | Enable integration with ExternalDNS for configuring public DNS entries for VirtualServer resources using [ExternalDNS](https://github.com/kubernetes-sigs/external-dns). Requires `controller.enableCustomResources`. | false |
| **controller.globalConfiguration.create** | Creates the GlobalConfiguration custom resource. Requires `controller.enableCustomResources`. | false |
| **controller.globalConfiguration.spec** | The spec of the GlobalConfiguration for defining the global configuration parameters of the Ingress Controller. | {} |
| **controller.enableSnippets** | Enable custom NGINX configuration snippets in Ingress, VirtualServer, VirtualServerRoute and TransportServer resources. | false |
| **controller.healthStatus** | Add a location "/nginx-health" to the default server. The location responds with the 200 status code for any request. Useful for external health-checking of the Ingress Controller. | false |
| **controller.healthStatusURI** | Sets the URI of health status location in the default server. Requires `controller.healthStatus`. | "/nginx-health" |
| **controller.nginxStatus.enable** | Enable the NGINX stub_status, or the NGINX Plus API. | true |
| **controller.nginxStatus.port** | Set the port where the NGINX stub_status or the NGINX Plus API is exposed. | 8080 |
| **controller.nginxStatus.allowCidrs** | Add IP/CIDR blocks to the allow list for NGINX stub_status or the NGINX Plus API. Separate multiple IP/CIDR by commas. | 127.0.0.1,::1 |
| **controller.priorityClassName** | The PriorityClass of the Ingress Controller pods. | None |
| **controller.service.create** | Creates a service to expose the Ingress Controller pods. | true |
| **controller.service.type** | The type of service to create for the Ingress Controller. | LoadBalancer |
| **controller.service.externalTrafficPolicy** | The externalTrafficPolicy of the service. The value Local preserves the client source IP. | Local |
| **controller.service.annotations** | The annotations of the Ingress Controller service. | {} |
| **controller.service.extraLabels** | The extra labels of the service. | {} |
| **controller.service.loadBalancerIP** | The static IP address for the load balancer. Requires `controller.service.type` set to `LoadBalancer`. The cloud provider must support this feature. | "" |
| **controller.service.externalIPs** | The list of external IPs for the Ingress Controller service. | [] |
| **controller.service.clusterIP** | The clusterIP for the Ingress Controller service, autoassigned if not specified. | "" |
| **controller.service.loadBalancerSourceRanges** | The IP ranges (CIDR) that are allowed to access the load balancer. Requires `controller.service.type` set to `LoadBalancer`. The cloud provider must support this feature. | [] |
| **controller.service.name** | The name of the service. | Autogenerated |
| **controller.service.customPorts** | A list of custom ports to expose through the Ingress Controller service. Follows the conventional Kubernetes yaml syntax for service ports. | [] |
| **controller.service.httpPort.enable** | Enables the HTTP port for the Ingress Controller service. | true |
| **controller.service.httpPort.port** | The HTTP port of the Ingress Controller service. | 80 |
| **controller.service.httpPort.nodePort** | The custom NodePort for the HTTP port. Requires `controller.service.type` set to `NodePort`. | "" |
| **controller.service.httpPort.targetPort** | The target port of the HTTP port of the Ingress Controller service. | 80 |
| **controller.service.httpsPort.enable** | Enables the HTTPS port for the Ingress Controller service. | true |
| **controller.service.httpsPort.port** | The HTTPS port of the Ingress Controller service. | 443 |
| **controller.service.httpsPort.nodePort** | The custom NodePort for the HTTPS port. Requires `controller.service.type` set to `NodePort`. | "" |
| **controller.service.httpsPort.targetPort** | The target port of the HTTPS port of the Ingress Controller service. | 443 |
| **controller.serviceAccount.annotations** | The annotations of the Ingress Controller service account. | {} |
| **controller.serviceAccount.name** | The name of the service account of the Ingress Controller pods. Used for RBAC. | Autogenerated |
| **controller.serviceAccount.imagePullSecretName** | The name of the secret containing docker registry credentials. Secret must exist in the same namespace as the helm release. | "" |
| **controller.serviceAccount.imagePullSecretsNames** | The list of secret names containing docker registry credentials. Secret must exist in the same namespace as the helm release. | [] |
| **controller.serviceMonitor.name** | The name of the serviceMonitor. | Autogenerated |
| **controller.serviceMonitor.create** | Create a ServiceMonitor custom resource. | false |
| **controller.serviceMonitor.labels** | Kubernetes object labels to attach to the serviceMonitor object. | "" |
| **controller.serviceMonitor.selectorMatchLabels** | A set of labels to allow the selection of endpoints for the ServiceMonitor. | "" |
| **controller.serviceMonitor.endpoints** | A list of endpoints allowed as part of this ServiceMonitor. | "" |
| **controller.reportIngressStatus.enable** | Updates the address field in the status of Ingress resources with an external address of the Ingress Controller. You must also specify the source of the external address either through an external service via `controller.reportIngressStatus.externalService`, `controller.reportIngressStatus.ingressLink` or the `external-status-address` entry in the ConfigMap via `controller.config.entries`. **Note:** `controller.config.entries.external-status-address` takes precedence over the others. | true |
| **controller.reportIngressStatus.externalService** | Specifies the name of the service with the type LoadBalancer through which the Ingress Controller is exposed externally. The external address of the service is used when reporting the status of Ingress, VirtualServer and VirtualServerRoute resources. `controller.reportIngressStatus.enable` must be set to `true`. The default is autogenerated and enabled when `controller.service.create` is set to `true` and `controller.service.type` is set to `LoadBalancer`. | Autogenerated |
| **controller.reportIngressStatus.ingressLink** | Specifies the name of the IngressLink resource, which exposes the Ingress Controller pods via a BIG-IP system. The IP of the BIG-IP system is used when reporting the status of Ingress, VirtualServer and VirtualServerRoute resources. `controller.reportIngressStatus.enable` must be set to `true`. | "" |
| **controller.reportIngressStatus.enableLeaderElection** | Enable Leader election to avoid multiple replicas of the controller reporting the status of Ingress resources. `controller.reportIngressStatus.enable` must be set to `true`. | true |
| **controller.reportIngressStatus.leaderElectionLockName** | Specifies the name of the ConfigMap, within the same namespace as the controller, used as the lock for leader election. controller.reportIngressStatus.enableLeaderElection must be set to true. | Autogenerated |
| **controller.reportIngressStatus.annotations** | The annotations of the leader election configmap. | {} |
| **controller.pod.annotations** | The annotations of the Ingress Controller pod. | {} |
| **controller.pod.extraLabels** | The additional extra labels of the Ingress Controller pod. | {} |
| **controller.appprotect.enable** | Enables the App Protect WAF module in the Ingress Controller. | false |
| **controller.appprotect.v5** | Enables App Protect WAF v5. | false |
| **controller.appprotect.volumes** | Volumes for App Protect WAF v5. | [{"name": "app-protect-bd-config", "emptyDir": {}},{"name": "app-protect-config", "emptyDir": {}},{"name": "app-protect-bundles", "emptyDir": {}}] |
| **controller.appprotect.enforcer.host** | Host that the App Protect WAF v5 Enforcer runs on. | "127.0.0.1" |
| **controller.appprotect.enforcer.port** | Port that the App Protect WAF v5 Enforcer runs on. | 50000 |
| **controller.appprotect.enforcer.image.repository** | The image repository of the App Protect WAF v5 Enforcer. | private-registry.nginx.com/nap/waf-enforcer |
| **controller.appprotect.enforcer.image.tag** | The tag of the App Protect WAF v5 Enforcer. | "5.5.0" |
| **controller.appprotect.enforcer.image.digest** | The digest of the App Protect WAF v5 Enforcer. Takes precedence over tag if set. | "" |
| **controller.appprotect.enforcer.image.pullPolicy** | The pull policy for the App Protect WAF v5 Enforcer image. | IfNotPresent |
| **controller.appprotect.enforcer.securityContext** | The security context for App Protect WAF v5 Enforcer container. | {} |
| **controller.appprotect.configManager.image.repository** | The image repository of the App Protect WAF v5 Configuration Manager. | private-registry.nginx.com/nap/waf-config-mgr |
| **controller.appprotect.configManager.image.tag** | The tag of the App Protect WAF v5 Configuration Manager. | "5.5.0" |
| **controller.appprotect.configManager.image.digest** | The digest of the App Protect WAF v5 Configuration Manager. Takes precedence over tag if set. | "" |
| **controller.appprotect.configManager.image.pullPolicy** | The pull policy for the App Protect WAF v5 Configuration Manager image. | IfNotPresent |
| **controller.appprotect.configManager.securityContext** | The security context for App Protect WAF v5 Configuration Manager container. | {"allowPrivilegeEscalation":false,"runAsUser":101,"runAsNonRoot":true,"capabilities":{"drop":["all"]}} |
| **controller.appprotectdos.enable** | Enables the App Protect DoS module in the Ingress Controller. | false |
| **controller.appprotectdos.enable** | Enables the App Protect DoS module in the Ingress Controller. | false |
| **controller.appprotectdos.debug** | Enable debugging for App Protect DoS. | false |
| **controller.appprotectdos.maxDaemons** | Max number of ADMD instances. | 1 |
| **controller.appprotectdos.maxWorkers** | Max number of nginx processes to support. | Number of CPU cores in the machine |
| **controller.appprotectdos.memory** | RAM memory size to consume in MB. | 50% of free RAM in the container or 80MB, the smaller |
| **controller.readyStatus.enable** | Enables the readiness endpoint `"/nginx-ready"`. The endpoint returns a success code when NGINX has loaded all the config after the startup. This also configures a readiness probe for the Ingress Controller pods that uses the readiness endpoint. | true |
| **controller.readyStatus.port** | The HTTP port for the readiness endpoint. | 8081 |
| **controller.readyStatus.initialDelaySeconds** | The number of seconds after the Ingress Controller pod has started before readiness probes are initiated. | 0 |
| **controller.enableLatencyMetrics** | Enable collection of latency metrics for upstreams. Requires `prometheus.create`. | false |
| **controller.minReadySeconds** | Specifies the minimum number of seconds for which a newly created Pod should be ready without any of its containers crashing, for it to be considered available. [docs](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#min-ready-seconds) | 0 |
| **controller.autoscaling.enabled** | Enables HorizontalPodAutoscaling. | false |
| **controller.autoscaling.annotations** | The annotations of the Ingress Controller HorizontalPodAutoscaler. | {} |
| **controller.autoscaling.behavior** | Behavior configuration for the HPA. | {} |
| **controller.autoscaling.minReplicas** | Minimum number of replicas for the HPA. | 1 |
| **controller.autoscaling.maxReplicas** | Maximum number of replicas for the HPA. | 3 |
| **controller.autoscaling.targetCPUUtilizationPercentage** | The target CPU utilization percentage. | 50 |
| **controller.autoscaling.targetMemoryUtilizationPercentage** | The target memory utilization percentage. | 50 |
| **controller.podDisruptionBudget.enabled** | Enables PodDisruptionBudget. | false |
| **controller.podDisruptionBudget.annotations** | The annotations of the Ingress Controller pod disruption budget | {} |
| **controller.podDisruptionBudget.minAvailable** | The number of Ingress Controller pods that should be available. This is a mutually exclusive setting with "maxUnavailable". | 0 |
| **controller.podDisruptionBudget.maxUnavailable** | The number of Ingress Controller pods that can be unavailable. This is a mutually exclusive setting with "minAvailable". | 0 |
| **controller.strategy** | Specifies the strategy used to replace old Pods with new ones. Docs for [Deployment update strategy](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy) and [Daemonset update strategy](https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/#daemonset-update-strategy) | {} |
| **controller.disableIPV6** | Disable IPV6 listeners explicitly for nodes that do not support the IPV6 stack. | false |
| **controller.defaultHTTPListenerPort**  | Sets the port for the HTTP `default_server` listener. | 80 |
| **controller.defaultHTTPSListenerPort**  | Sets the port for the HTTPS `default_server` listener. | 443 |
| **controller.readOnlyRootFilesystem** | Configure root filesystem as read-only and add volumes for temporary data. Three major releases after 3.5.x this argument will be moved permanently to the `controller.securityContext` section.  | false |
| **controller.enableSSLDynamicReload** | Enable lazy loading for SSL Certificates. | true |
| **controller.telemetryReporting.enable** | Enable telemetry reporting. | true |
| **controller.enableWeightChangesDynamicReload** | Enable weight changes without reloading the NGINX configuration. May require increasing `map_hash_bucket_size`, `map_hash_max_size`, `variable_hash_bucket_size`, and `variable_hash_max_size` in the [ConfigMap](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/) if there are many two-way splits. Requires `controller.nginxplus` | false |
| **rbac.create** | Configures RBAC. | true |
| **rbac.clusterrole.create** | Configures creation of ClusterRole. Creation can be disabled when more fine-grained control over RBAC is required. For example when controller.watchNamespace is used. | true |
| **prometheus.create** | Expose NGINX or NGINX Plus metrics in the Prometheus format. | true |
| **prometheus.port** | Configures the port to scrape the metrics. | 9113 |
| **prometheus.scheme** | Configures the HTTP scheme to use for connections to the Prometheus endpoint. | http |
| **prometheus.secret** | The namespace / name of a Kubernetes TLS Secret. If specified, this secret is used to secure the Prometheus endpoint with TLS connections. | "" |
| **prometheus.service.create** | Create a Headless service to expose prometheus metrics. Requires `prometheus.create`. | false |
| **prometheus.service.labels** | Kubernetes object labels to attach to the service object. | {service: "nginx-ingress-prometheus-service"} |
| **prometheus.serviceMonitor.create** | Create a ServiceMonitor custom resource. Requires ServiceMonitor CRD to be installed. For the latest CRD, check the latest release on the [prometheus-operator](https://github.com/prometheus-operator/prometheus-operator) GitHub repo under `example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml` | false |
| **prometheus.serviceMonitor.labels** | Kubernetes object labels to attach to the serviceMonitor object. | {} |
| **prometheus.serviceMonitor.selectorMatchLabels** | A set of labels to allow the selection of endpoints for the ServiceMonitor. | {service: "nginx-ingress-prometheus-service"} |
| **prometheus.serviceMonitor.endpoints** | A list of endpoints allowed as part of this ServiceMonitor. | [port: prometheus] |
| **serviceInsight.create** | Expose NGINX Plus Service Insight endpoint. | false |
| **serviceInsight.port** | Configures the port to expose endpoints. | 9114 |
| **serviceInsight.scheme** | Configures the HTTP scheme to use for connections to the Service Insight endpoint. | http |
| **serviceInsight.secret** | The namespace / name of a Kubernetes TLS Secret. If specified, this secret is used to secure the Service Insight endpoint with TLS connections. | "" |
| **serviceNameOverride** | Used to prevent cloud load balancers from being replaced due to service name change during helm upgrades. | "" |
| **nginxServiceMesh.enable** | Enable integration with NGINX Service Mesh. See the NGINX Service Mesh [docs](https://docs.nginx.com/nginx-service-mesh/tutorials/kic/deploy-with-kic/) for more details. Requires `controller.nginxplus`. | false |
| **nginxServiceMesh.enableEgress** | Enable NGINX Service Mesh workloads to route egress traffic through the Ingress Controller. See the NGINX Service Mesh [docs](https://docs.nginx.com/nginx-service-mesh/tutorials/kic/deploy-with-kic/#enabling-egress) for more details. Requires `nginxServiceMesh.enable`. | false |
|**nginxAgent.enable** | Enable NGINX Agent to integrate the Security Monitoring and App Protect WAF modules. Requires `controller.appprotect.enable`. | false |
|**nginxAgent.instanceGroup** | Set a custom Instance Group name for the deployment, shown when connected to NGINX Instance Manager. `nginx-ingress.controller.fullname` will be used if not set. | "" |
|**nginxAgent.logLevel** | Log level for NGINX Agent. | "error |
|**nginxAgent.instanceManager.host** | FQDN or IP for connecting to NGINX Ingress Controller. Required when `nginxAgent.enable` is set to `true` | "" |
|**nginxAgent.instanceManager.grpcPort** | Port for connecting to NGINX Ingress Controller. | 443 |
|**nginxAgent.instanceManager.sni** | Server Name Indication for Instance Manager. See the NGINX Agent [docs](https://docs.nginx.com/nginx-agent/configuration/encrypt-communication/) for more details. | "" |
|**nginxAgent.instanceManager.tls.enable** | Enable TLS for Instance Manager connection. | true |
|**nginxAgent.instanceManager.tls.skipVerify** | Skip certification verification for Instance Manager connection. | false |
|**nginxAgent.instanceManager.tls.caSecret** | Name of `nginx.org/ca` secret used for verification of Instance Manager TLS. | "" |
|**nginxAgent.instanceManager.tls.secret** | Name of `kubernetes.io/tls` secret with a TLS certificate and key for using mTLS between NGINX Agent and Instance Manager. See the NGINX Instance Manager [docs](https://docs.nginx.com/nginx-instance-manager/system-configuration/secure-traffic/#mutual-client-certificate-authentication-setup-mtls) and the NGINX Agent [docs](https://docs.nginx.com/nginx-agent/configuration/encrypt-communication/) for more details. | "" |
|**nginxAgent.syslog.host** | Address for NGINX Agent to run syslog listener. | 127.0.0.1 |
|**nginxAgent.syslog.port** | Port for NGINX Agent to run syslog listener. | 1514 |
|**nginxAgent.napMonitoring.collectorBufferSize** | Buffer size for collector. Will contain log lines and parsed log lines. | 50000 |
|**nginxAgent.napMonitoring.processorBufferSize** | Buffer size for processor. Will contain log lines and parsed log lines. | 50000 |
|**nginxAgent.customConfigMap** | The name of a custom ConfigMap to use instead of the one provided by default. | "" |
{{</bootstrap-table>}}
{{< /table >}}
