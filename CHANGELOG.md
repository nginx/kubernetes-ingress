# Changelog

Starting with version 1.11.0, an automatically generated list of changes can be found on the [GitHub Releases page](https://github.com/nginx/kubernetes-ingress/releases).

A curated list of changes can be found in the [Releases](http://docs.nginx.com/nginx-ingress-controller/releases/) page
on NGINX Documentation website.

## 1.10.1

CHANGES:

- Update NGINX version to 1.19.8.
- Add Kubernetes 1.20 support.
- [1373](https://github.com/nginx/kubernetes-ingress/pull/1373),
  [1439](https://github.com/nginx/kubernetes-ingress/pull/1439),
  [1440](https://github.com/nginx/kubernetes-ingress/pull/1440): Fix various issues in the Makefile. In 1.10.0, a bug
  was introduced that prevented building Ingress Controller images on versions of make < 4.1.

HELM CHART:

- The version of the Helm chart is now 0.8.1.

UPGRADE:

- For NGINX, use the 1.10.1 image from our DockerHub: `nginx/nginx-ingress:1.10.1`, `nginx/nginx-ingress:1.10.1-alpine`
  or `nginx/nginx-ingress:1.10.1-ubi`
- For NGINX Plus, please build your own image using the 1.10.1 source code.
- For Helm, use version 0.8.1 of the chart.

## 1.10.0

OVERVIEW:

Release 1.10.0 includes:

- Open ID Connect authentication policy.
- Improved handling of Secret resources with extended validation and error reporting.
- Improved visibility with Prometheus metrics for the configuration workqueue and the ability to annotate NGINX logs
  with the metadata of Kubernetes resources.
- NGINX App Protect User-Defined signatures support.
- Improved validation of Ingress annotations.

You will find the complete changelog for release 1.10.0, including bug fixes, improvements, and changes below.

FEATURES FOR POLICY RESOURCE:

- [1304](https://github.com/nginx/kubernetes-ingress/pull/1304) Add Open ID Connect policy.

FEATURES FOR NGINX APP PROTECT:

- [1281](https://github.com/nginx/kubernetes-ingress/pull/1281) Add support for App Protect User Defined Signatures.

FEATURES:

- [1266](https://github.com/nginx/kubernetes-ingress/pull/1266) Add workqueue metrics to Prometheus metrics.
- [1233](https://github.com/nginx/kubernetes-ingress/pull/1233) Annotate tcp metrics with k8s object labels.
- [1231](https://github.com/nginx/kubernetes-ingress/pull/1231) Support k8s objects variables in log format.

IMPROVEMENTS:

- [1270](https://github.com/nginx/kubernetes-ingress/pull/1270) and
  [1277](https://github.com/nginx/kubernetes-ingress/pull/1277) Improve validation of Ingress annotations.
- [1265](https://github.com/nginx/kubernetes-ingress/pull/1265) Report warnings for misconfigured TLS and JWK
  secrets.
- [1262](https://github.com/nginx/kubernetes-ingress/pull/1262) Use setcap(8) only once.
  [1263](https://github.com/nginx/kubernetes-ingress/pull/1263) Use chown(8) only once.
  [1264](https://github.com/nginx/kubernetes-ingress/pull/1264) Use mkdir(1) only once. Thanks to [Sergey A.
  Osokin](https://github.com/osokin).
- [1256](https://github.com/nginx/kubernetes-ingress/pull/1256) and
  [1260](https://github.com/nginx/kubernetes-ingress/pull/1260) Improve handling of secret resources.
- [1240](https://github.com/nginx/kubernetes-ingress/pull/1240) Validate TLS and CA secrets.
- [1235](https://github.com/nginx/kubernetes-ingress/pull/1235) Use buildkit secret flag for NGINX plus images.
- Documentation improvements: [1282](https://github.com/nginx/kubernetes-ingress/pull/1282),
  [1293](https://github.com/nginx/kubernetes-ingress/pull/1293),
  [1303](https://github.com/nginx/kubernetes-ingress/pull/1303),
  [1315](https://github.com/nginx/kubernetes-ingress/pull/1315).

HELM CHART:

- The version of the helm chart is now 0.8.0.
- [1290](https://github.com/nginx/kubernetes-ingress/pull/1290) Add new preview policies parameter to chart.
  `controller.enablePreviewPolicies` was added.
- [1232](https://github.com/nginx/kubernetes-ingress/pull/1232) Replace deprecated imagePullSecrets helm setting.
  `controller.serviceAccount.imagePullSecrets` was removed. `controller.serviceAccount.imagePullSecretName` was added.
- [1228](https://github.com/nginx/kubernetes-ingress/pull/1228) Fix installation of ingressclass on Kubernetes
  versions `v1.18.x-*`

CHANGES:

- [1299](https://github.com/nginx/kubernetes-ingress/pull/1299) Update NGINX App Protect version to 2.3 and debian
  distribution to `debian:buster-slim`.
- [1291](https://github.com/nginx/kubernetes-ingress/pull/1291) Update NGINX OSS to `1.19.6`. Update NGINX Plus to
  `R23`.
- [1290](https://github.com/nginx/kubernetes-ingress/pull/1290) Graduate policy resource and accessControl policy to
  generally available.
- [1225](https://github.com/nginx/kubernetes-ingress/pull/1225) Require secrets to have types.
- [1237](https://github.com/nginx/kubernetes-ingress/pull/1237) Deprecate support for helm2 clients.

UPGRADE:

- For NGINX, use the 1.10.0 image from our DockerHub: `nginx/nginx-ingress:1.10.0`, `nginx/nginx-ingress:1.10.0-alpine`
  or `nginx-ingress:1.10.0-ubi`
- For NGINX Plus, please build your own image using the 1.10.0 source code.
- For Helm, use version 0.8.0 of the chart.
- As a result of [1270](https://github.com/nginx/kubernetes-ingress/pull/1270) and
  [1277](https://github.com/nginx/kubernetes-ingress/pull/1277), the Ingress Controller improved validation of
  Ingress annotations: more annotations are validated and validation errors are reported via events for Ingress
  resources. Additionally, the default behavior for invalid annotation values was changed: instead of using the default
  values, the Ingress Controller will reject a resource with an invalid annotation value, which will make clients see
  `404` responses from NGINX. See this
  [document](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#validation)
  to learn more. Before upgrading, ensure the Ingress resources don't have annotations with invalid values. Otherwise,
  after the upgrade, the Ingress Controller will reject such resources.
- In [1232](https://github.com/nginx/kubernetes-ingress/pull/1232) `controller.serviceAccount.imagePullSecrets` was
  removed. Use the new `controller.serviceAccount.imagePullSecretName` instead.
- The Policy resource was promoted to `v1`. If you used the `alpha1` version, the policies are needed to be recreated
  with the `v1` version. Before upgrading the Ingress Controller, run the following command to remove the `alpha1`
  policies CRD (that will also remove all existing `alpha1` policies):

    ```console
     kubectl delete crd policies.k8s.nginx.org
    ```

  As part of the upgrade, make sure to create the `v1` policies CRD. See the corresponding instructions for the
  [manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/#create-custom-resources)
  and [Helm](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/#upgrading-the-crds)
  installations.

  Also note that all policies except for `accessControl` are still in preview. To enable them, run the Ingress
  Controller with `- -enable-preview-policies` command-line argument (`controller.enablePreviewPolicies` Helm
  parameter).
- It is necessary to update secret resources. See the section UPDATING SECRETS below.

UPDATING SECRETS:

In [1225](https://github.com/nginx/kubernetes-ingress/pull/1225), as part of improving how the Ingress Controller
handles secret resources, we added a requirement for secrets to be of one of the following types:

- `kubernetes.io/tls` for TLS secrets.
- `nginx.org/jwk` for JWK secrets.
- `nginx.org/ca` for CA secrets.

The Ingress Controller now ignores secrets that are not of a supported type. As a consequence, special upgrade steps are
required.

Before upgrading, ensure that the secrets referenced in Ingress, VirtualServer or Policies resources are of a supported
type, which is configured via the `type` field. Because that field is immutable, it is necessary to either:

- Recreate the secrets. Note that in this case, the client traffic for the affected resources will be rejected for the
  period during which a secret doesn't exist in the cluster.
- Create copies of the secrets and update the affected resources to reference the copies. The copies need to be of a
  supported type. In contrast with the previous options, this will not make NGINX reject the client traffic.

It is also necessary to update the default server secret and the wildcard secret (if it was configured) in case their
type is not `kubernetes.io/tls`. The steps depend on how you installed the Ingress Controller: via manifests or Helm.
Performing the steps will not lead to a disruption of the client traffic, as the Ingress Controller retains the default
and wildcard secrets if they are removed.

For *manifests installation*:

1. Recreate the default server secret and the wildcard secret with the type `kubernetes.io/tls`.
1. Upgrade the Ingress Controller.

For *Helm installation*, there two cases:

1. If Helm created the secrets (you configured `controller.defaultTLS.cert` and `controller.defaultTLS.key` for the
   default secret and `controller.wildcardTLS.cert` and `controller.wildcardTLS.key` for the wildcard secret), then no
   special upgrade steps are required: during the upgrade, the Helm will remove the existing default and wildcard
   secrets and create new ones with different names with the type `kubernetes.io/tls`.
1. If you created the secrets separately from Helm (you configured `controller.defaultTLS.secret` for the default secret
   and `controller.wildcardTLS.secret` for the wildcard secret):
    1. Recreate the secrets with the type `kubernetes.io/tls`.
    1. Upgrade to the new Helm release.

NOTES:

- Helm 2 clients are no longer supported due to reaching End of Life: <https://helm.sh/blog/helm-2-becomes-unsupported/>

## 1.9.1

CHANGES:

- Fix deployment of ingressclass resource via helm on some versions of Kubernetes.
- Update the base ubi images to 8.3.
- Renew CA cert for egress-mtls example.
- Add imagePullSecretName support to helm chart.

HELM CHART:

- The version of the Helm chart is now 0.7.1.

UPGRADE:

- For NGINX, use the 1.9.1 image from our DockerHub: `nginx/nginx-ingress:1.9.1`, `nginx/nginx-ingress:1.9.1-alpine` or
  `nginx/nginx-ingress:1.9.1-ubi`
- For NGINX Plus, please build your own image using the 1.9.1 source code.
- For Helm, use version 0.7.1 of the chart.

## 1.9.0

OVERVIEW:

Release 1.9.0 includes:

- Support for new Prometheus metrics and enhancements of the existing ones, including configuration reload reason, NGINX
  worker processes count, upstream latency, and more.
- Support for rate limiting, JWT authentication, ingress(client) and egress(upstream) mutual TLS via the Policy
  resource.
- Support for the latest Ingress resource features and the IngressClass resource.
- Support for NGINX Service Mesh.

You will find the complete changelog for release 1.9.0, including bug fixes, improvements, and changes below.

FEATURES FOR POLICY RESOURCE:

- [1180](https://github.com/nginx/kubernetes-ingress/pull/1180) Add support for EgressMTLS.
- [1166](https://github.com/nginx/kubernetes-ingress/pull/1166) Add IngressMTLS policy support.
- [1154](https://github.com/nginx/kubernetes-ingress/pull/1154) Add JWT policy support.
- [1120](https://github.com/nginx/kubernetes-ingress/pull/1120) Add RateLimit policy support.
- [1058](https://github.com/nginx/kubernetes-ingress/pull/1058) Support policies in VS routes and VSR subroutes.

FEATURES FOR NGINX APP PROTECT:

- [1147](https://github.com/nginx/kubernetes-ingress/pull/1147) Add option to specify other log destinations in
  AppProtect.
- [1131](https://github.com/nginx/kubernetes-ingress/pull/1131) Update packages and CRDs to AppProtect 2.0. This
  update includes features such as: [JSON Schema
  Validation](https://docs.nginx.com/nginx-app-protect/configuration#applying-a-json-schema), [User-Defined
  URLs](https://docs.nginx.com/nginx-app-protect/configuration/#user-defined-urls) and [User-Defined
  Parameters](https://docs.nginx.com/nginx-app-protect/configuration/#user-defined-parameters). See the [release
  notes](https://docs.nginx.com/nginx-app-protect/releases/#release-2-0) for a complete feature list.
- [1100](https://github.com/nginx/kubernetes-ingress/pull/1100) Add external references to AppProtect.
- [1085](https://github.com/nginx/kubernetes-ingress/pull/1085) Add installation of threat campaigns package.

FEATURES:

- [1133](https://github.com/nginx/kubernetes-ingress/pull/1133) Add support for IngressClass resources.
- [1130](https://github.com/nginx/kubernetes-ingress/pull/1130) Add prometheus latency collector.
- [1076](https://github.com/nginx/kubernetes-ingress/pull/1076) Add prometheus worker process metrics.
- [1075](https://github.com/nginx/kubernetes-ingress/pull/1075) Add support for NGINX Service Mesh internal routes.

IMPROVEMENTS:

- [1178](https://github.com/nginx/kubernetes-ingress/pull/1178) Resolve host collisions in VirtualServer and
  Ingresses.
- [1158](https://github.com/nginx/kubernetes-ingress/pull/1158) Support variables in action proxy headers.
- [1137](https://github.com/nginx/kubernetes-ingress/pull/1137) Add pod_owner label to metrics when
  -spire-agent-address is set.
- [1107](https://github.com/nginx/kubernetes-ingress/pull/1107) Extend Upstream Servers with pod_name label.
- [1099](https://github.com/nginx/kubernetes-ingress/pull/1099) Add reason label to total_reload metrics.
- [1088](https://github.com/nginx/kubernetes-ingress/pull/1088) Extend Upstream Servers and Server Zones metrics,
  thanks to [Raúl](https://github.com/Rulox).
- [1080](https://github.com/nginx/kubernetes-ingress/pull/1080) Support pathType field in the Ingress resource.
- [1078](https://github.com/nginx/kubernetes-ingress/pull/1078) Remove trailing blank lines in vs/vsr snippets.
- Documentation improvements: [1083](https://github.com/nginx/kubernetes-ingress/pull/1083),
  [1092](https://github.com/nginx/kubernetes-ingress/pull/1092),
  [1089](https://github.com/nginx/kubernetes-ingress/pull/1089),
  [1174](https://github.com/nginx/kubernetes-ingress/pull/1174),
  [1175](https://github.com/nginx/kubernetes-ingress/pull/1175),
  [1171](https://github.com/nginx/kubernetes-ingress/pull/1171).

BUGFIXES:

- [1179](https://github.com/nginx/kubernetes-ingress/pull/1179) Fix TransportServers in debian AppProtect image.
- [1129](https://github.com/nginx/kubernetes-ingress/pull/1129) Support real-ip in default server.
- [1110](https://github.com/nginx/kubernetes-ingress/pull/1110) Add missing threat campaigns key to AppProtect CRD.

HELM CHART:

- The version of the helm chart is now 0.7.0
- [1105](https://github.com/nginx/kubernetes-ingress/pull/1105) Fix GlobalConfiguration support in helm chart.
- Add new parameters to the Chart: `controller.setAsDefaultIngress`, `controller.enableLatencyMetrics`. Added in
  [1133](https://github.com/nginx/kubernetes-ingress/pull/1133) and
  [1148](https://github.com/nginx/kubernetes-ingress/pull/1148).

CHANGES:

- [1182](https://github.com/nginx/kubernetes-ingress/pull/1182) Update NGINX version to 1.19.3.

UPGRADE:

- For NGINX, use the 1.9.0 image from our DockerHub: `nginx/nginx-ingress:1.9.0`, `nginx/nginx-ingress:1.9.0-alpine` or
  `nginx-ingress:1.9.0-ubi`
- For NGINX Plus, please build your own image using the 1.9.0 source code.
- For Helm, use version 0.7.0 of the chart.

For Kubernetes >= 1.18, when upgrading using the
[manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), make sure to
update the [ClusterRole](deployments/rbac/rbac.yaml) and create the [IngressClass
resource](deployments/common/ingress-class.yaml), which is required for Kubernetes >= 1.18. Otherwise, the Ingress
Controller will fail to start. If you run multiple NGINX Ingress Controllers in the cluster, each Ingress Controller has
to have its own IngressClass resource. Make sure your Ingress resources have the `ingressClassName` field or the
`kubernetes.io/ingress.class` annotation set to the name of the IngressClass resource. Otherwise, the Ingress Controller
will ignore them.

HELM UPGRADE:

- If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to
  `true`), after you run the `helm upgrade` command, the CRDs will not be upgraded. After running the `helm upgrade`
  command, run `kubectl apply -f deployments/helm-chart/crds` to upgrade the CRDs.
- For Kubernetes >= 1.18, a dedicated IngressClass resource, which is configured by `controller.ingressClass`, is
  required per helm release. Ensure `controller.ingressClass` is not set to the name of the IngressClass of other
  releases or Ingress Controllers. Make sure your Ingress resources have the `ingressClassName` field or the
  `kubernetes.io/ingress.class` annotation set to the value of `controller.ingressClass`. Otherwise, the Ingress
  Controller will ignore them.

NOTES:

- When using Kubernetes >= 1.18 the Ingress Controller will only process resources that belong to its class. See
  [IngressClass
  doc](https://docs.nginx.com/nginx-ingress-controller/installation/running-multiple-ingress-controllers/#ingress-class)
  to learn more.
- For Kubernetes >= 1.18, a dedicated IngressClass resource, which is configured by `controller.ingressClass`, is
  required per helm release. When upgrading or installing releases, ensure `controller.ingressClass` is not set to the
  name of the IngressClass of other releases or Ingress Controllers.

## 1.8.1

CHANGES:

- Update NGINX version to 1.19.2.

HELM CHART:

- The version of the Helm chart is now 0.6.1.

UPGRADE:

- For NGINX, use the 1.8.1 image from our DockerHub: `nginx/nginx-ingress:1.8.1`, `nginx/nginx-ingress:1.8.1-alpine` or
  `nginx/nginx-ingress:1.8.1-ubi`
- For NGINX Plus, please build your own image using the 1.8.1 source code.
- For Helm, use version 0.6.1 of the chart.

## 1.8.0

OVERVIEW:

Release 1.8.0 includes:

- Support for NGINX App Protect Web Application Firewall.
- Support for configuration snippets and custom template for VirtualServer and VirtualServerRoute resources.
- Support for request/response header manipulation and request URI rewriting for VirtualServer/VirtualServerRoute.
- Introducing a new configuration resource - Policy - with the first policy for IP-based access control.

You will find the complete changelog for release 1.8.0, including bug fixes, improvements, and changes below.

FEATURES FOR VIRTUALSERVER AND VIRTUALSERVERROUTE RESOURCES:

- [1036](https://github.com/nginx/kubernetes-ingress/pull/1036): Add VirtualServer custom template support.
- [1028](https://github.com/nginx/kubernetes-ingress/pull/1028): Add access control policy.
- [1019](https://github.com/nginx/kubernetes-ingress/pull/1019): Add VirtualServer/VirtualServerRoute snippets
  support.
- [1006](https://github.com/nginx/kubernetes-ingress/pull/1006): Add request/response modifiers to VS and VSR.
- [994](https://github.com/nginx/kubernetes-ingress/pull/994): Support Class Field in VS/VSR.
- [973](https://github.com/nginx/kubernetes-ingress/pull/973): Add status to VirtualServer and VirtualServerRoute.

FEATURES:

- [1035](https://github.com/nginx/kubernetes-ingress/pull/1035): Support for App Protect module.
- [1029](https://github.com/nginx/kubernetes-ingress/pull/1029): Add readiness endpoint.

IMPROVEMENTS:

- [995](https://github.com/nginx/kubernetes-ingress/pull/995): Emit event for orphaned VirtualServerRoutes.
- Documentation improvements: [946](https://github.com/nginx/kubernetes-ingress/pull/946) thanks to [谭九
  鼎](https://github.com/imba-tjd), [948](https://github.com/nginx/kubernetes-ingress/pull/948),
  [972](https://github.com/nginx/kubernetes-ingress/pull/972),
  [965](https://github.com/nginx/kubernetes-ingress/pull/965).

BUGFIXES:

- [1030](https://github.com/nginx/kubernetes-ingress/pull/1030): Fix port range validation in cli arguments.
- [953](https://github.com/nginx/kubernetes-ingress/pull/953): Fix error logging of master/minion ingresses.

HELM CHART:

- The version of the helm chart is now 0.6.0.
- Add new parameters to the Chart: `controller.appprotect.enable`, `controller.globalConfiguration.create`,
  `controller.globalConfiguration.spec`, `controller.readyStatus.enable`, `controller.readyStatus.port`,
  `controller.config.annotations`, `controller.reportIngressStatus.annotations`. Added in
  [1035](https://github.com/nginx/kubernetes-ingress/pull/1035),
  [1034](https://github.com/nginx/kubernetes-ingress/pull/1034),
  [1029](https://github.com/nginx/kubernetes-ingress/pull/1029),
  [1003](https://github.com/nginx/kubernetes-ingress/pull/1003) thanks to
  [RubyLangdon](https://github.com/RubyLangdon).
- [1047](https://github.com/nginx/kubernetes-ingress/pull/1047) and
  [1009](https://github.com/nginx/kubernetes-ingress/pull/1009): Change how Helm manages the custom resource
  definitions (CRDs) to support installing multiple Ingress Controller releases. **Note**: If you're using the custom
  resources (`controller.enableCustomResources` is set to `true`), this is a breaking change. See the HELM UPGRADE
  section below for the upgrade instructions.

CHANGES:

- Update NGINX version to 1.19.1.
- Update NGINX Plus to R22.
- [1029](https://github.com/nginx/kubernetes-ingress/pull/1029): Add readiness endpoint. The Ingress Controller now
  exposes a readiness endpoint on port `8081` and the path `/nginx-ready`. The endpoint returns a `200` response after
  the Ingress Controller finishes the initial configuration of NGINX at the start. The pod template was updated to use
  that endpoint in a readiness probe.
- [980](https://github.com/nginx/kubernetes-ingress/pull/980): Enable leader election by default.

UPGRADE:

- For NGINX, use the 1.8.0 image from our DockerHub: `nginx/nginx-ingress:1.8.0`, `nginx/nginx-ingress:1.8.0-alpine` or
  `nginx-ingress:1.8.0-ubi`
- For NGINX Plus, please build your own image using the 1.8.0 source code.
- For Helm, use version 0.6.0 of the chart.

HELM UPGRADE:

If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to
`true`), after you run the `helm upgrade` command, the CRDs and the corresponding custom resources will be removed from
the cluster. Before upgrading, make sure to back up the custom resources. After running the `helm upgrade` command, run
`kubectl apply -f deployments/helm-chart/crds` to re-install the CRDs and then restore the custom resources.

NOTES:

- As part of installing a release, Helm will install the CRDs unless that step is disabled (see the [corresponding
  doc](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/)). The installed CRDs
  include the CRDs for all Ingress Controller features, including the ones disabled by default (like App Protect with
  `aplogconfs.appprotect.f5.com` and `appolicies.appprotect.f5.com` CRDs).

## 1.7.2

CHANGES:

- Update NGINX Plus version to R22.

HELM CHART:

- The version of the Helm chart is now 0.5.2.

UPGRADE:

- For NGINX, use the 1.7.2 image from our DockerHub: `nginx/nginx-ingress:1.7.2`, `nginx/nginx-ingress:1.7.2-alpine` or
  `nginx/nginx-ingress:1.7.2-ubi`
- For NGINX Plus, please build your own image using the 1.7.2 source code.
- For Helm, use version 0.5.2 of the chart.

## 1.7.1

CHANGES:

- Update NGINX version to 1.19.0.

HELM CHART:

- The version of the Helm chart is now 0.5.1.

UPGRADE:

- For NGINX, use the 1.7.1 image from our DockerHub: `nginx/nginx-ingress:1.7.1`, `nginx/nginx-ingress:1.7.1-alpine` or
  `nginx/nginx-ingress:1.7.1-ubi`
- For NGINX Plus, please build your own image using the 1.7.1 source code.
- For Helm, use version 0.5.1 of the chart.

## 1.7.0

OVERVIEW:

Release 1.7.0 includes:

- Support for TCP, UDP, and TLS Passthrough load balancing with the new configuration resources: TransportServer and
  GlobalConfiguration. The resources allow users to deliver complex, non-HTTP-based applications from Kubernetes using
  NGINX Ingress Controller.
- Support for error pages in VirtualServer and VirtualServerRoute resources. A user can now specify custom error
  responses for errors returned by backend applications or generated by NGINX, such as a 502 response.
- Improved validation of VirtualServer and VirtualServerRoute resources. kubectl and the Kubernetes API server can now
  detect violations of the structure of VirtualServer/VirtualServerRoute resources and return an error.
- Support for an operator which manages the lifecycle of the Ingress Controller on Kubernetes or OpenShift. See the
  [NGINX Ingress Operator GitHub repo](https://github.com/nginx/nginx-ingress-operator).

See the [1.7.0 release announcement blog
post](https://www.nginx.com/blog/announcing-nginx-ingress-controller-for-kubernetes-release-1-7-0/), which includes an
overview of each feature.

You will find the complete changelog for release 1.7.0, including bug fixes, improvements, and changes below.

FEATURES FOR VIRTUALSERVER AND VIRTUALSERVERROUTE RESOURCES:

- [868](https://github.com/nginx/kubernetes-ingress/pull/868): Add OpenAPI CRD schema validation.
- [847](https://github.com/nginx/kubernetes-ingress/pull/847): Add support for error pages for VS/VSR.

FEATURES:

- [902](https://github.com/nginx/kubernetes-ingress/pull/902): Add TransportServer and GlobalConfiguration Resources.
- [894](https://github.com/nginx/kubernetes-ingress/pull/894): Add Dockerfile for NGINX Open Source for Openshift.
- [857](https://github.com/nginx/kubernetes-ingress/pull/857): Add Openshift Dockerfile for NGINX Plus.
- [852](https://github.com/nginx/kubernetes-ingress/pull/852): Add default-server-access-log-off to configmap.
- [845](https://github.com/nginx/kubernetes-ingress/pull/845): Add log-format-escaping and stream-log-format-escaping
  configmap keys. Thanks to [Alexey Maslov](https://github.com/alxmsl).
- [827](https://github.com/nginx/kubernetes-ingress/pull/827): Add ingress class label to all Prometheus metrics.

IMPROVEMENTS:

- [850](https://github.com/nginx/kubernetes-ingress/pull/850): Extend redirect URI validation with protocol check in
  VS/VSR.
- [832](https://github.com/nginx/kubernetes-ingress/pull/832): Update the examples to run the
  `nginxdemos/nginx-hello:plain-text` image, that doesn't require root user.
- [825](https://github.com/nginx/kubernetes-ingress/pull/825): Add multi-stage docker builds.

BUGFIXES:

- [828](https://github.com/nginx/kubernetes-ingress/pull/828): Fix error messages for actions of the type return.

HELM CHART:

- The version of the helm chart is now 0.5.0.
- Add new parameters to the Chart: `controller.enableTLSPassthrough`, `controller.volumes`, `controller.volumeMounts`,
  `controller.priorityClassName`. Added in [921](https://github.com/nginx/kubernetes-ingress/pull/921),
  [878](https://github.com/nginx/kubernetes-ingress/pull/878),
  [807](https://github.com/nginx/kubernetes-ingress/pull/807) thanks to [Greg Snow](https://github.com/gsnegovskiy).

CHANGES:

- Update NGINX version to 1.17.10.
- Update NGINX Plus to R21.
- [854](https://github.com/nginx/kubernetes-ingress/pull/854): Update the Debian base images for NGINX Plus to
  `debian:buster-slim`.
- [852](https://github.com/nginx/kubernetes-ingress/pull/852): Add default-server-access-log-off to configmap. The
  access logs for the default server are now enabled by default.
- [847](https://github.com/nginx/kubernetes-ingress/pull/847): Add support for error pages for VS/VSR. The PR affects
  how the Ingress Controller generates configuration for VirtualServer and VirtualServerRoutes. See [this
  comment](https://github.com/nginx/kubernetes-ingress/pull/847) for more details.
- [827](https://github.com/nginx/kubernetes-ingress/pull/827): Add ingress class label to all Prometheus metrics.
  Every Prometheus metric exposed by the Ingress Controller now includes the label `class` with the value of the Ingress
  Controller class (by default `nginx`),
- [825](https://github.com/nginx/kubernetes-ingress/pull/825): Add multi-stage docker builds. When building the
  Ingress Controller image in Docker, we now use a multi-stage docker build.

UPGRADE:

- For NGINX, use the 1.7.0 image from our DockerHub: `nginx/nginx-ingress:1.7.0`, `nginx/nginx-ingress:1.7.0-alpine` or
  `nginx-ingress:1.7.0-ubi`
- For NGINX Plus, please build your own image using the 1.7.0 source code.
- For Helm, use version 0.5.0 of the chart.

When upgrading using the
[manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), make sure to
deploy the new TransportServer CRD (`common/ts-definition.yaml`), as it is required by the Ingress Controller.
Otherwise, you will get error messages in the Ingress Controller logs.

## 1.6.3

CHANGES:

- Update NGINX version to 1.17.9.

HELM CHART:

- The version of the Helm chart is now 0.4.3.

UPGRADE:

- For NGINX, use the 1.6.3 image from our DockerHub: `nginx/nginx-ingress:1.6.3` or `nginx/nginx-ingress:1.6.3-alpine`
- For NGINX Plus, please build your own image using the 1.6.3 source code.
- For Helm, use version 0.4.3 of the chart.

## 1.6.2

CHANGES:

- Update NGINX version to 1.17.8.

HELM CHART:

- The version of the Helm chart is now 0.4.2.

UPGRADE:

- For NGINX, use the 1.6.2 image from our DockerHub: `nginx/nginx-ingress:1.6.2` or `nginx/nginx-ingress:1.6.2-alpine`
- For NGINX Plus, please build your own image using the 1.6.2 source code.
- For Helm, use version 0.4.2 of the chart.

## 1.6.1

CHANGES:

- Update NGINX version to 1.17.7.

HELM CHART:

- The version of the Helm chart is now 0.4.1.

UPGRADE:

- For NGINX, use the 1.6.1 image from our DockerHub: `nginx/nginx-ingress:1.6.1` or `nginx/nginx-ingress:1.6.1-alpine`
- For NGINX Plus, please build your own image using the 1.6.1 source code.
- For Helm, use version 0.4.1 of the chart.

## 1.6.0

OVERVIEW:

Release 1.6.0 includes:

- Improvements to VirtualServer and VirtualServerRoute resources, adding support for richer load balancing behavior,
  more sophisticated request routing, redirects, direct responses, and blue-green and circuit breaker patterns. The
  VirtualServer and VirtualServerRoute resources are enabled by default and are ready for production use.
- Support for OpenTracing, helping you to monitor and debug complex transactions.
- An improved security posture, with support to run the Ingress Controller as a non-root user.

The release announcement blog post includes the overview for each feature. See
<https://www.nginx.com/blog/announcing-nginx-ingress-controller-for-kubernetes-release-1-6-0/>

You will find the complete changelog for release 1.6.0, including bug fixes, improvements, and changes below.

FEATURES FOR VIRTUALSERVER AND VIRTUALSERVERROUTE RESOURCES:

- [780](https://github.com/nginx/kubernetes-ingress/pull/780): Add support for canned responses to VS/VSR.
- [778](https://github.com/nginx/kubernetes-ingress/pull/778): Add redirect support in VS/VSR.
- [766](https://github.com/nginx/kubernetes-ingress/pull/766): Add exact matches and regex support to location paths
  in VS/VSR.
- [748](https://github.com/nginx/kubernetes-ingress/pull/748): Add TLS redirect support in Virtualserver.
- [745](https://github.com/nginx/kubernetes-ingress/pull/745): Improve routing rules in VS/VSR
- [728](https://github.com/nginx/kubernetes-ingress/pull/728): Add session persistence in VS/VSR.
- [724](https://github.com/nginx/kubernetes-ingress/pull/724): Add VS/VSR Prometheus metrics.
- [712](https://github.com/nginx/kubernetes-ingress/pull/712): Add service subselector support in vs/vsr.
- [707](https://github.com/nginx/kubernetes-ingress/pull/707): Emit warning events in VS/VSR.
- [701](https://github.com/nginx/kubernetes-ingress/pull/701): Add support queue in upstreams for plus in VS/VSR.
- [693](https://github.com/nginx/kubernetes-ingress/pull/693): Add ServerStatusZones support in vs/vsr.
- [670](https://github.com/nginx/kubernetes-ingress/pull/670): Add buffering support for vs/vsr.
- [660](https://github.com/nginx/kubernetes-ingress/pull/660): Add ClientBodyMaxSize support in vs/vsr.
- [659](https://github.com/nginx/kubernetes-ingress/pull/659): Support configuring upstream zone sizes in VS/VSR.
- [655](https://github.com/nginx/kubernetes-ingress/pull/655): Add slow-start support in vs/vsr.
- [653](https://github.com/nginx/kubernetes-ingress/pull/653): Add websockets support for vs/vsr upstreams.
- [641](https://github.com/nginx/kubernetes-ingress/pull/641): Add support for ExternalName Services for vs/vsr.
- [635](https://github.com/nginx/kubernetes-ingress/pull/635): Add HealthChecks support for vs/vsr.
- [634](https://github.com/nginx/kubernetes-ingress/pull/634): Add Active Connections support to vs/vsr.
- [628](https://github.com/nginx/kubernetes-ingress/pull/628): Add retries support for vs/vsr.
- [621](https://github.com/nginx/kubernetes-ingress/pull/621): Add TLS support for vs/vsr upstreams.
- [617](https://github.com/nginx/kubernetes-ingress/pull/617): Add keepalive support to vs/vsr.
- [612](https://github.com/nginx/kubernetes-ingress/pull/612): Add timeouts support to vs/vsr.
- [607](https://github.com/nginx/kubernetes-ingress/pull/607): Add fail-timeout and max-fails support to vs/vsr.
- [596](https://github.com/nginx/kubernetes-ingress/pull/596): Add lb-method support in vs and vsr.

FEATURES:

- [750](https://github.com/nginx/kubernetes-ingress/pull/750): Add support for health status uri customisation.
- [691](https://github.com/nginx/kubernetes-ingress/pull/691): Helper Functions for custom annotations.
- [631](https://github.com/nginx/kubernetes-ingress/pull/631): Add max_conns support for NGINX plus.
- [629](https://github.com/nginx/kubernetes-ingress/pull/629): Added upstream zone directive annotation. Thanks to
  [Victor Regalado](https://github.com/vrrs).
- [616](https://github.com/nginx/kubernetes-ingress/pull/616): Add proxy-send-timeout to configmap key and
  annotation.
- [615](https://github.com/nginx/kubernetes-ingress/pull/615): Add support for Opentracing.
- [614](https://github.com/nginx/kubernetes-ingress/pull/614): Add max-conns annotation. Thanks to [Victor
  Regalado](https://github.com/vrrs).

IMPROVEMENTS:

- [678](https://github.com/nginx/kubernetes-ingress/pull/678): Increase defaults for server-names-hash-max-size and
  servers-names-hash-bucket-size ConfigMap keys.
- [694](https://github.com/nginx/kubernetes-ingress/pull/694): Reject VS/VSR resources with enabled plus features for
  OSS.
- Documentation improvements: [713](https://github.com/nginx/kubernetes-ingress/pull/713) thanks to [Matthew
  Wahner](https://github.com/mattwahner).

BUGFIXES:

- [788](https://github.com/nginx/kubernetes-ingress/pull/788): Fix VSR updates when namespace is set implicitly.
- [736](https://github.com/nginx/kubernetes-ingress/pull/736): Init Ingress labeled metrics on start.
- [686](https://github.com/nginx/kubernetes-ingress/pull/686): Check if config map created for leader-election.
- [664](https://github.com/nginx/kubernetes-ingress/pull/664): Fix reporting events for Ingress minions.
- [632](https://github.com/nginx/kubernetes-ingress/pull/632): Fix hsts support when not using SSL. Thanks to [Martín
  Fernández](https://github.com/bilby91).

HELM CHART:

- The version of the helm chart is now 0.4.0.
- Add new parameters to the Chart: `controller.healthCheckURI`, `controller.resources`, `controller.logLevel`,
  `controller.customPorts`, `controller.service.customPorts`. Added in
  [750](https://github.com/nginx/kubernetes-ingress/pull/750),
  [636](https://github.com/nginx/kubernetes-ingress/pull/636) thanks to [Guilherme
  Oki](https://github.com/guilhermeoki), [600](https://github.com/nginx/kubernetes-ingress/pull/600),
  [581](https://github.com/nginx/kubernetes-ingress/pull/581) thanks to [Alex
  Meijer](https://github.com/ameijer-corsha).
- [722](https://github.com/nginx/kubernetes-ingress/pull/722): Fix trailing leader election cm when using helm. This
  change might lead to a failed upgrade. See the helm upgrade instruction below.
- [573](https://github.com/nginx/kubernetes-ingress/pull/573): Use Controller name value for app selectors.

CHANGES:

- Update NGINX versions to 1.17.6.
- Update NGINX Plus version to R20.
- [799](https://github.com/nginx/kubernetes-ingress/pull/779): Enable CRDs by default. VirtualServer and
  VirtualServerRoute resources are now enabled by default.
- [772](https://github.com/nginx/kubernetes-ingress/pull/772): Update VS/VSR version from v1alpha1 to v1. Make sure
  to update the `apiVersion` of your VirtualServer and VirtualServerRoute resources.
- [748](https://github.com/nginx/kubernetes-ingress/pull/748): Add TLS redirect support in VirtualServer. The
  `redirect-to-https` and `ssl-redirect` ConfigMap keys no longer have any effect on generated configs for VirtualServer
  resources.
- [745](https://github.com/nginx/kubernetes-ingress/pull/745): Improve routing rules. Update the spec of
  VirtualServer and VirtualServerRoute accordingly. See YAML examples of the changes
  [here](https://github.com/nginx/kubernetes-ingress/pull/745).
- [710](https://github.com/nginx/kubernetes-ingress/pull/710): Run IC as non-root. Make sure to use the updated
  manifests to install/upgrade the Ingress Controller.
- [603](https://github.com/nginx/kubernetes-ingress/pull/603): Update apiVersion in Deployments and DaemonSets to
  apps/v1.

UPGRADE:

- For NGINX, use the 1.6.0 image from our DockerHub: `nginx/nginx-ingress:1.6.0` or `nginx/nginx-ingress:1.6.0-alpine`
- For NGINX Plus, please build your own image using the 1.6.0 source code.
- For Helm, use version 0.4.0 of the chart.

HELM UPGRADE:

If leader election (the `controller.reportIngressStatus.enableLeaderElection` parameter) is enabled, when upgrading to
the new version of the Helm chart:

1. Make sure to specify a new ConfigMap lock name (`controller.reportIngressStatus.leaderElectionLockName`) different
   from the one that was created by the current version. To find out the current name, check ConfigMap resources in the
   namespace where the Ingress Controller is running.
1. After the upgrade, delete the old ConfigMap.

Otherwise, the helm upgrade will not succeed.

## 1.5.8

CHANGES:

- Update NGINX version to 1.17.6.
- Update deployment and daemonset manifests to apps/v1.

HELM CHART:

- The version of the Helm chart is now 0.3.8.

UPGRADE:

- For NGINX, use the 1.5.8 image from our DockerHub: `nginx/nginx-ingress:1.5.8` or `nginx/nginx-ingress:1.5.8-alpine`
- For NGINX Plus, please build your own image using the 1.5.8 source code.
- For Helm, use version 0.3.8 of the chart.

## 1.5.7

CHANGES:

- Update NGINX version to 1.17.5.

HELM CHART:

- The version of the Helm chart is now 0.3.7.

UPGRADE:

- For NGINX, use the 1.5.7 image from our DockerHub: `nginx/nginx-ingress:1.5.7` or `nginx/nginx-ingress:1.5.7-alpine`
- For NGINX Plus, please build your own image using the 1.5.7 source code.
- For Helm, use version 0.3.7 of the chart.

## 1.5.6

CHANGES:

- Update NGINX version to 1.17.4.

HELM CHART:

- The version of the Helm chart is now 0.3.6.

UPGRADE:

- For NGINX, use the 1.5.6 image from our DockerHub: `nginx/nginx-ingress:1.5.6` or `nginx/nginx-ingress:1.5.6-alpine`
- For NGINX Plus, please build your own image using the 1.5.6 source code.
- For Helm, use version 0.3.6 of the chart.

## 1.5.5

CHANGES:

- Update NGINX Plus version to R19.

HELM CHART:

- The version of the Helm chart is now 0.3.5.

UPGRADE:

- For NGINX, use the 1.5.5 image from our DockerHub: `nginx/nginx-ingress:1.5.5` or `nginx/nginx-ingress:1.5.5-alpine`
- For NGINX Plus, please build your own image using the 1.5.5 source code.
- For Helm, use version 0.3.5 of the chart.

## 1.5.4

CHANGES:

- Update NGINX version to 1.17.3.

HELM CHART:

- The version of the Helm chart is now 0.3.4.

UPGRADE:

- For NGINX, use the 1.5.4 image from our DockerHub: `nginx/nginx-ingress:1.5.4` or `nginx/nginx-ingress:1.5.4-alpine`
- For NGINX Plus, please build your own image using the 1.5.4 source code.
- For Helm, use version 0.3.4 of the chart.

## 1.5.3

CHANGES:

- Update NGINX Plus version to R18p1.

HELM CHART:

- The version of the Helm chart is now 0.3.3.

UPGRADE:

- For NGINX, use the 1.5.3 image from our DockerHub: `nginx/nginx-ingress:1.5.3` or `nginx/nginx-ingress:1.5.3-alpine`
- For NGINX Plus, please build your own image using the 1.5.3 source code.
- For Helm, use version 0.3.3 of the chart.

## 1.5.2

CHANGES:

- Update NGINX version to 1.17.2.

HELM CHART:

- The version of the Helm chart is now 0.3.2.

UPGRADE:

- For NGINX, use the 1.5.2 image from our DockerHub: `nginx/nginx-ingress:1.5.2` or `nginx/nginx-ingress:1.5.2-alpine`
- For NGINX Plus, please build your own image using the 1.5.2 source code.
- For Helm, use version 0.3.2 of the chart.

## 1.5.1

CHANGES:

- Update NGINX version to 1.17.1.

HELM CHART:

- The version of the Helm chart is now 0.3.1.
- [593](https://github.com/nginx/kubernetes-ingress/pull/593): Fix the selector in the Ingress Controller service
  when the `controller.name` parameter is set. This introduces a change, see the HELM UPGRADE section.

UPGRADE:

- For NGINX, use the 1.5.1 image from our DockerHub: `nginx/nginx-ingress:1.5.1` or `nginx/nginx-ingress:1.5.1-alpine`
- For NGINX Plus, please build your own image using the 1.5.1 source code.
- For Helm, use version 0.3.1 of the chart.

HELM UPGRADE:

In the changelog of Release 1.5.0, we advised not to upgrade the helm chart from `0.2.1` to `0.3.0` unless the mentioned
in the changelog problems were acceptable. This release we provide mitigation instructions on how to upgrade from
`0.2.1` to `0.3.1` without disruptions.

When you upgrade from `0.2.1` to `0.3.1`, make sure to configure the following parameters:

- `controller.name` is set to `nginx-ingress` or the previously used value in case you customized it. This ensures the
  Deployment/Daemonset will not be recreated.
- `controller.service.name` is set to `nginx-ingress`. This ensures the service will not be recreated.
- `controller.config.name` is set to `nginx-config`. This ensures the ConfigMap will not be recreated.

Upgrading from `0.3.0` to `0.3.1`: Upgrading is not affected unless you customized `controller.name`. In that case,
because of the fix [593](https://github.com/nginx/kubernetes-ingress/pull/593), the upgraded service will have a new
selector, and the upgraded pod spec will have a new label. As a result, during an upgrade, the old pods will be
immediately excluded from the service. Also, for the Deployment, the old pods will not terminate but continue to run. To
terminate the old pods, manually remove the corresponding ReplicaSet.

## 1.5.0

FEATURES:

- [560](https://github.com/nginx/kubernetes-ingress/pull/560): Add new configuration resources -- VirtualServer and
  VirtualServerRoute.
- [554](https://github.com/nginx/kubernetes-ingress/pull/554): Add new Prometheus metrics related to the Ingress
  Controller's operation (as opposed to NGINX/NGINX Plus metrics).
- [496](https://github.com/nginx/kubernetes-ingress/pull/496): Support a wildcard TLS certificate for TLS-enabled
  Ingress resources.
- [485](https://github.com/nginx/kubernetes-ingress/pull/485): Support ExternalName services in Ingress backends.

IMPROVEMENTS:

- Add new ConfigMap keys: `keepalive-timeout`, `keepalive-requests`, `access-log-off`, `variables-hash-bucket-size`,
  `variables-hash-max-size`. Added in [565](https://github.com/nginx/kubernetes-ingress/pull/565),
  [511](https://github.com/nginx/kubernetes-ingress/pull/511).
- [504](https://github.com/nginx/kubernetes-ingress/pull/504): Run the Prometheus exporter inside the Ingress
  Controller process instead of a sidecar container.

BUGFIXES:

- [520](https://github.com/nginx/kubernetes-ingress/pull/520): Fix the type of the Prometheus port annotation in
  manifests.
- [481](https://github.com/nginx/kubernetes-ingress/pull/481): Fix the HSTS support.
- [439](https://github.com/nginx/kubernetes-ingress/pull/439): Fix the validation of the `lb-method` ConfigMap key
  and `nginx.org/lb-method` annotation.

HELM CHART:

- The version of the helm chart is now 0.3.0.
- The helm chart is now available in our helm chart repo `helm.nginx.com/stable`.
- Add new parameters to the Chart: `controller.service.httpPort.targetPort`, `controller.service.httpsPort.targetPort`,
  `controller.service.name`, `controller.pod.annotations`, `controller.config.name`,
  `controller.reportIngressStatus.leaderElectionLockName`, `controller.service.httpPort`,
  `controller.service.httpsPort`, `controller.service.loadBalancerIP`, `controller.service.loadBalancerSourceRanges`,
  `controller.tolerations`, `controller.affinity`. Added in
  [562](https://github.com/nginx/kubernetes-ingress/pull/562),
  [561](https://github.com/nginx/kubernetes-ingress/pull/561),
  [553](https://github.com/nginx/kubernetes-ingress/pull/553),
  [534](https://github.com/nginx/kubernetes-ingress/pull/534) thanks to [Paulo Ribeiro](https://github.com/paigr),
  [479](https://github.com/nginx/kubernetes-ingress/pull/479) thanks to [Alejandro
  Llanes](https://github.com/sombralibre),  [468](https://github.com/nginx/kubernetes-ingress/pull/468),
  [456](https://github.com/nginx/kubernetes-ingress/pull/456).
- [546](https://github.com/nginx/kubernetes-ingress/pull/546): Support deploying multiple Ingress Controllers in a
  cluster. **Note**: The generated resources have new names that are unique for each Ingress Controller. As a
  consequence, the name change affects the upgrade. See the HELM UPGRADE section for more information.
- [542](https://github.com/nginx/kubernetes-ingress/pull/542): Reduce the required privileges in the RBAC manifests.

CHANGES:

- Update NGINX version to 1.15.12.
- Prometheus metrics for NGINX/NGINX Plus have new namespace `nginx_ingress`. Examples: `nginx_http_requests_total` ->
  `nginx_ingress_http_requests_total`, `nginxplus_http_requests_total` -> `nginx_ingress_nginxplus_http_requests_total`.

UPGRADE:

- For NGINX, use the 1.5.0 image from our DockerHub: `nginx/nginx-ingress:1.5.0` or `nginx/nginx-ingress:1.5.0-alpine`
- For NGINX Plus, please build your own image using the 1.5.0 source code.
- For Helm, use version 0.3.0 of the chart.

HELM UPGRADE:

The new version of the helm chart uses different names for the generated resources. This makes it possible to deploy
multiple Ingress Controllers in a cluster. However, as a side effect, during the upgrade from the previous version, helm
will recreate the resources, instead of updating the existing ones. This, in turn, might cause problems for the
following resources:

- Service: If the service was created with the type LoadBalancer, the public IP of the new service might change.
  Additionally, helm updates the selector of the service, so that the old pods will be immediately excluded from the
  service.
- Deployment/DaemonSet: Because the resource is recreated, the old pods will be removed and the new ones will be
  launched, instead of the default Deployment/Daemonset upgrade strategy.
- ConfigMap: After the helm removes the resource, the old Ingress Controller pods will be immediately reconfigured to
  use the default values of the ConfigMap keys. During a small window between the reconfiguration and the shutdown of
  the old pods, NGINX will use the configuration with the default values.

We advise not to upgrade to the new version of the helm chart unless the mentioned problems are acceptable for your
case. We will provide special upgrade instructions for helm that mitigate the problems for the next minor release of the
Ingress Controller (1.5.1).

## 1.4.6

CHANGES:

- Update NGINX version to 1.15.11.
- Update NGINX Plus version to R18.

HELM CHART:

- The version of the Helm chart is now 0.2.1.

UPGRADE:

- For NGINX, use the 1.4.6 image from our DockerHub: `nginx/nginx-ingress:1.4.6` or `nginx/nginx-ingress:1.4.6-alpine`
- For NGINX Plus, please build your own image using the 1.4.6 source code.
- For Helm, use version 0.2.1 of the chart.

## 1.4.5

CHANGES:

- Update NGINX version to 1.15.10.

UPGRADE:

- For NGINX, use the 1.4.5 image from our DockerHub: `nginx/nginx-ingress:1.4.5` or `nginx/nginx-ingress:1.4.5-alpine`
- For NGINX Plus, please build your own image using the 1.4.5 source code.

## 1.4.4

CHANGES:

- Update NGINX version to 1.15.9.

UPGRADE:

- For NGINX, use the 1.4.4 image from our DockerHub: `nginx/nginx-ingress:1.4.4` or `nginx/nginx-ingress:1.4.4-alpine`
- For NGINX Plus, please build your own image using the 1.4.4 source code.

## 1.4.3

CHANGES:

- Update NGINX version to 1.15.8.

UPGRADE:

- For NGINX, use the 1.4.3 image from our DockerHub: `nginx/nginx-ingress:1.4.3` or `nginx/nginx-ingress:1.4.3-alpine`
- For NGINX Plus, please build your own image using the 1.4.3 source code.

## 1.4.2

CHANGES:

- Update NGINX Plus version to R17.

 UPGRADE:

- For NGINX, use the 1.4.2 image from our DockerHub: `nginx/nginx-ingress:1.4.2` or `nginx/nginx-ingress:1.4.2-alpine`
- For NGINX Plus, please build your own image using the 1.4.2 source code.

## 1.4.1

CHANGES:

- Update NGINX version to 1.15.7.

UPGRADE:

- For NGINX, use the 1.4.1 image from our DockerHub: `nginx/nginx-ingress:1.4.1` or `nginx/nginx-ingress:1.4.1-alpine`
- For NGINX Plus, please build your own image using the 1.4.1 source code.

## 1.4.0

FEATURES:

- [401](https://github.com/nginx/kubernetes-ingress/pull/401): Add the `-nginx-debug` flag for enabling debugging of
  NGINX using the `nginx-debug` binary.
- [387](https://github.com/nginx/kubernetes-ingress/pull/387): Add the `-nginx-status-allow-cidrs` command-line
  argument for white listing IPv4 IP/CIDR blocks to allow access to NGINX stub_status or the NGINX Plus API. Thanks to
  [Jasmine Hegman](https://github.com/r4j4h).
- [376](https://github.com/nginx/kubernetes-ingress/pull/376): Support the
  [random](http://nginx.org/en/docs/http/ngx_http_upstream_module.html#random) load balancing method.
- [375](https://github.com/nginx/kubernetes-ingress/pull/375): Support custom annotations.
- [346](https://github.com/nginx/kubernetes-ingress/pull/346): Support the Prometheus exporter for NGINX (the
  stub_status metrics).
- [344](https://github.com/nginx/kubernetes-ingress/pull/344): Expose NGINX Plus API/NGINX stub_status on a custom
  port via the `-nginx-status-port` command-line argument. See also the CHANGES section.
- [342](https://github.com/nginx/kubernetes-ingress/pull/342): Add the `error-log-level` configmap key. Thanks to
  [boran seref](https://github.com/boranx).
- [320](https://github.com/nginx/kubernetes-ingress/pull/340): Support TCP/UDP load balancing via the
  `stream-snippets` configmap key.

IMPROVEMENTS:

- [434](https://github.com/nginx/kubernetes-ingress/pull/434): Improve consistency of templates.
- [432](https://github.com/nginx/kubernetes-ingress/pull/432): Fix cli-docs and Improve main test.
- [419](https://github.com/nginx/kubernetes-ingress/pull/419): Refactor config writing. Thanks to
  [feifeiiiiiiiiii](https://github.com/feifeiiiiiiiiiii).
- [403](https://github.com/nginx/kubernetes-ingress/pull/403): Improve NGINX start.
- [400](https://github.com/nginx/kubernetes-ingress/pull/400): Fix error message in
  internal/controller/controller.go. Thanks to [Alex O Regan](https://github.com/aaaaaaaalex).
- [399](https://github.com/nginx/kubernetes-ingress/pull/399): Improve secret handling. See also the CHANGES section.
- [391](https://github.com/nginx/kubernetes-ingress/pull/391): Update default lb-method to be random two least_conn.
  See also the CHANGES section.
- [389](https://github.com/nginx/kubernetes-ingress/pull/389): Improve parsing nginx.org/rewrites annotation.
- [380](https://github.com/nginx/kubernetes-ingress/pull/380): Verify reloads & cache secrets.
- [362](https://github.com/nginx/kubernetes-ingress/pull/362): Reduce reloads.
- [357](https://github.com/nginx/kubernetes-ingress/pull/357): Improve Project Layout and Refactor Controller
  Package. See also the CHANGES section.
- [351](https://github.com/nginx/kubernetes-ingress/pull/351): Make socket address obvious.

BUGFIXES:

- [429](https://github.com/nginx/kubernetes-ingress/pull/429): Fix panic with health checks.
- [386](https://github.com/nginx/kubernetes-ingress/pull/386): Fix Configmap/Mergeable Ingress Add/Update event
  logging.
- [379](https://github.com/nginx/kubernetes-ingress/pull/379): Fix configmap update.
- [365](https://github.com/nginx/kubernetes-ingress/pull/365): Don't enqueue ingress for some service changes.
- [348](https://github.com/nginx/kubernetes-ingress/pull/348): Fix Configurator error check.

HELM CHART:

- [430](https://github.com/nginx/kubernetes-ingress/pull/430): Add the `controller.serviceAccount.imagePullSecrets`
  parameter to the helm chart. See also the CHANGES section.
- [420](https://github.com/nginx/kubernetes-ingress/pull/420): Simplify values files for Helm Chart.
- [398](https://github.com/nginx/kubernetes-ingress/pull/398): Add the `controller.nginxStatus.allowCidrs` and
  `controller.service.externalIPs` parameters to helm chart.
- [393](https://github.com/nginx/kubernetes-ingress/pull/393): Refactor Helm Chart templates.
- [390](https://github.com/nginx/kubernetes-ingress/pull/390): Add the `controller.service.loadBalancerIP` parameter
  to the helm chat.
- [377](https://github.com/nginx/kubernetes-ingress/pull/377): Add the `controller.nginxStatus` parameters to the
  helm chart.
- [335](https://github.com/nginx/kubernetes-ingress/pull/335): Add the `controller.reportIngressStatus` parameters to
  the helm chart.
- The version of the Helm chart is now 0.2.0.

CHANGES:

- Update NGINX version to 1.15.6.
- Update NGINX Plus version to R16p1.
- Update NGINX Prometheus Exporter to 0.2.0.
- [430](https://github.com/nginx/kubernetes-ingress/pull/430): Add the `controller.serviceAccount.imagePullSecrets`
  parameter to the helm chart. **Note**: the `controller.serviceAccountName` parameter has been changed to
  `controller.serviceAccount.name`.
- [399](https://github.com/nginx/kubernetes-ingress/pull/399): Improve secret handling. **Note**: the PR changed how
  the Ingress Controller processes Ingress resources with TLS termination enabled but without any referenced (or with
  invalid) secrets and Ingress resources with JWT validation enabled but without any referenced (or with invalid) JWK.
  Please read [here](https://github.com/nginx/kubernetes-ingress/pull/399) for more details.
- [357](https://github.com/nginx/kubernetes-ingress/pull/357): Improve Project Layout and Refactor Controller
  Package. **Note**: the PR significantly changed the layout of the project to follow best practices.
- [347](https://github.com/nginx/kubernetes-ingress/pull/347): Use edge version in manifests and Helm chart.
  **Note**: the manifests and the helm chart in the master branch now reference the edge version of the Ingress
  Controller instead of the latest stable version used previously.
- [391](https://github.com/nginx/kubernetes-ingress/pull/391): Update default lb-method to be random two least_conn.
  **Note**: the default load balancing method is now the power of two choices as it better suits the Ingress Controller
  use case. Please read the [blog post](https://www.nginx.com/blog/nginx-power-of-two-choices-load-balancing-algorithm/)
  about the method for more details.
- [344](https://github.com/nginx/kubernetes-ingress/pull/344): Expose NGINX Plus API/NGINX stub_status on a custom
  port via the `-nginx-status-port` command-line argument. **Note**: For NGINX the stub_status is now exposed on port
  8080 at the /stub_status URL by default. Previously, the stub_status was not exposed on any port. The stub_status can
  be disabled via the `-nginx-status` flag.

DOC AND EXAMPLES FIXES/IMPROVEMENTS: [435](https://github.com/nginx/kubernetes-ingress/pull/435),
[433](https://github.com/nginx/kubernetes-ingress/pull/433),
[432](https://github.com/nginx/kubernetes-ingress/pull/432),
[418](https://github.com/nginx/kubernetes-ingress/pull/418) (Thanks to [Hal Deadman](https://github.com/hdeadman)),
[406](https://github.com/nginx/kubernetes-ingress/pull/406),
[381](https://github.com/nginx/kubernetes-ingress/pull/381),
[349](https://github.com/nginx/kubernetes-ingress/pull/349) (Thanks to [Artur
Geraschenko](https://github.com/arturgspb)), [343](https://github.com/nginx/kubernetes-ingress/pull/343)

UPGRADE:

- For NGINX, use the 1.4.0 image from our DockerHub: `nginx/nginx-ingress:1.4.0` or `nginx/nginx-ingress:1.4.0-alpine`
- For NGINX Plus, please build your own image using the 1.4.0 source code.

## 1.3.2

CHANGES:

- Update NGINX version to 1.15.6.

UPGRADE:

- For NGINX, use the 1.3.2 image from our DockerHub: `nginx/nginx-ingress:1.3.2` or `nginx/nginx-ingress:1.3.2-alpine`
- For NGINX Plus, please build your own image using the 1.3.2 source code.

## 1.3.1

CHANGES:

- Update NGINX Plus version to R15p2.

UPGRADE:

- For NGINX, use the 1.3.1 image from our DockerHub: `nginx/nginx-ingress:1.3.1` or `nginx/nginx-ingress:1.3.1-alpine`
- For NGINX Plus, please build your own image using the 1.3.1 source code.

## 1.3.0

IMPROVEMENTS:

- [325](https://github.com/nginx/kubernetes-ingress/pull/325): Report ingress status.
- [311](https://github.com/nginx/kubernetes-ingress/pull/311): Support JWT auth in mergeable minions.
- [310](https://github.com/nginx/kubernetes-ingress/pull/310): NGINX configuration template custom path support.
- [308](https://github.com/nginx/kubernetes-ingress/pull/308): Add prometheus exporter support to helm chart.
- [303](https://github.com/nginx/kubernetes-ingress/pull/303): Add fetch custom NGINX template from ConfigMap.
- [301](https://github.com/nginx/kubernetes-ingress/pull/301): Update prometheus exporter image for Plus.
- [298](https://github.com/nginx/kubernetes-ingress/pull/298): Prefetch ConfigMap before initial NGINX Config
  generation.
- [296](https://github.com/nginx/kubernetes-ingress/pull/296): Improve Helm Chart.
- [295](https://github.com/nginx/kubernetes-ingress/pull/295): Report version information.
- [294](https://github.com/nginx/kubernetes-ingress/pull/294): Support dynamic reconfiguration in mergeable ingresses
  for Plus.
- [287](https://github.com/nginx/kubernetes-ingress/pull/287): Support slow-start for Plus.
- [286](https://github.com/nginx/kubernetes-ingress/pull/286): Add support for active health checks for Plus.

CHANGES:

- [330](https://github.com/nginx/kubernetes-ingress/pull/330): Update NGINX version to 1.15.2.
- [329](https://github.com/nginx/kubernetes-ingress/pull/329): Enforce annotations inheritance in minions.

BUGFIXES:

- [326](https://github.com/nginx/kubernetes-ingress/pull/326): Fix find ingress for secret ns bug.
- [284](https://github.com/nginx/kubernetes-ingress/pull/284): Correct Logs for Mergeable Types with Duplicate
  Location. Thanks to [Fernando Diaz](https://github.com/diazjf).

UPGRADE:

- For NGINX, use the 1.3.0 image from our DockerHub: `nginx/nginx-ingress:1.3.0`
- For NGINX Plus, please build your own image using the 1.3.0 source code.

## 1.2.0

- [279](https://github.com/nginx/kubernetes-ingress/pull/279): Update dependencies.
- [278](https://github.com/nginx/kubernetes-ingress/pull/278): Fix mergeable Ingress types.
- [277](https://github.com/nginx/kubernetes-ingress/pull/277): Support grpc error responses.
- [276](https://github.com/nginx/kubernetes-ingress/pull/276): Add gRPC support.
- [274](https://github.com/nginx/kubernetes-ingress/pull/274): Change the default load balancing method to
  least_conn.
- [272](https://github.com/nginx/kubernetes-ingress/pull/272): Move nginx-ingress image to the official nginx
  DockerHub.
- [268](https://github.com/nginx/kubernetes-ingress/pull/268): Correct Mergeable Types misspelling and optimize
  blacklists. Thanks to [Fernando Diaz](https://github.com/diazjf).
- [266](https://github.com/nginx/kubernetes-ingress/pull/266): Add support for passive health checks.
- [261](https://github.com/nginx/kubernetes-ingress/pull/261): Update Customization Example.
- [258](https://github.com/nginx/kubernetes-ingress/pull/258): Handle annotations and conflicting paths for
  MergeableTypes. Thanks to [Fernando Diaz](https://github.com/diazjf).
- [256](https://github.com/nginx/kubernetes-ingress/pull/256): Add helm chart support.
- [249](https://github.com/nginx/kubernetes-ingress/pull/249): Add support for prometheus for Plus.
- [241](https://github.com/nginx/kubernetes-ingress/pull/241): Update the doc about building the Docker image.
- [240](https://github.com/nginx/kubernetes-ingress/pull/240): Use new NGINX Plus API.
- [239](https://github.com/nginx/kubernetes-ingress/pull/239): Fix a typo in a variable name. Thanks to [Tony
  Li](https://github.com/mysterytony).
- [238](https://github.com/nginx/kubernetes-ingress/pull/238): Remove apt-get upgrade from Plus Dockerfile.
- [237](https://github.com/nginx/kubernetes-ingress/pull/237): Add unit test for ingress-class handling.
- [236](https://github.com/nginx/kubernetes-ingress/pull/236): Always respect `-ingress-class` option. Thanks to
  [Nick Novitski](https://github.com/nicknovitski).
- [235](https://github.com/nginx/kubernetes-ingress/pull/235): Change the base image to Debian Stretch for Plus
  controller.
- [234](https://github.com/nginx/kubernetes-ingress/pull/234): Update installation manifests and instructions.
- [233](https://github.com/nginx/kubernetes-ingress/pull/233): Add docker build options to Makefile.
- [231](https://github.com/nginx/kubernetes-ingress/pull/231): Prevent a possible failure of building Plus image.
- Documentation Fixes: [248](https://github.com/nginx/kubernetes-ingress/pull/248), thanks to
  [zariye](https://github.com/zariye). [252](https://github.com/nginx/kubernetes-ingress/pull/252).
  [270](https://github.com/nginx/kubernetes-ingress/pull/270).
- Update NGINX version to 1.13.12.
- Update NGINX Plus version to R15 P1.

## 1.1.1

- [228](https://github.com/nginx/kubernetes-ingress/pull/228): Add worker-rlimit-nofile configmap key. Thanks to
  [Aleksandr Lysenko](https://github.com/Sarga).
- [223](https://github.com/nginx/kubernetes-ingress/pull/223): Add worker-connections configmap key. Thanks to
  [Aleksandr Lysenko](https://github.com/Sarga).
- Update NGINX version to 1.13.8.

## 1.1.0

- [221](https://github.com/nginx/kubernetes-ingress/pull/221): Add git commit info to the IC log.
- [220](https://github.com/nginx/kubernetes-ingress/pull/220): Update dependencies.
- [213](https://github.com/nginx/kubernetes-ingress/pull/213): Add main snippets to allow Main context customization.
  Thanks to [Dewen Kong](https://github.com/kongdewen).
- [211](https://github.com/nginx/kubernetes-ingress/pull/211): Minimize the number of configuration reloads when the
  Ingress Controller starts; fix a problem with endpoints updates for Plus.
- [208](https://github.com/nginx/kubernetes-ingress/pull/208): Add worker-shutdown-timeout configmap key. Thanks to
  [Aleksandr Lysenko](https://github.com/Sarga).
- [199](https://github.com/nginx/kubernetes-ingress/pull/199): Add support for Kubernetes ssl-redirect annotation.
  Thanks to [Luke Seelenbinder](https://github.com/lseelenbinder).
- [194](https://github.com/nginx/kubernetes-ingress/pull/194) Add keepalive configmap key and annotation.
- [193](https://github.com/nginx/kubernetes-ingress/pull/193): Add worker-cpu-affinity configmap key.
- [192](https://github.com/nginx/kubernetes-ingress/pull/192): Add worker-processes configmap key.
- [186](https://github.com/nginx/kubernetes-ingress/pull/186): Fix hardcoded controller class. Thanks to [Serhii
  M](https://github.com/SiriusRed).
- [184](https://github.com/nginx/kubernetes-ingress/pull/184): Return a meaningful error when there is no cert and
  key for the default server.
- Update NGINX version to 1.13.7.
- Makefile updates: golang container was updated to 1.9.

## 1.0.0

- [175](https://github.com/nginx/kubernetes-ingress/pull/175): Add support for JWT for NGINX Plus.
- [171](https://github.com/nginx/kubernetes-ingress/pull/171): Allow NGINX to listen on non-standard ports. Thanks to
  [Stanislav Seletskiy](https://github.com/seletskiy).
- [170](https://github.com/nginx/kubernetes-ingress/pull/170): Add the default server. **Note**: The Ingress
  Controller will fail to start if there are no cert and key for the default server. You can pass a TLS Secret for the
  default server as an argument to the Ingress Controller or add a cert and a key to the Docker image.
- [169](https://github.com/nginx/kubernetes-ingress/pull/169): Ignore Ingress resources with empty hostnames.
- [168](https://github.com/nginx/kubernetes-ingress/pull/168): Add the `nginx.org/lb-method` annotation. Thanks to
  [Sajal Kayan](https://github.com/sajal).
- [166](https://github.com/nginx/kubernetes-ingress/pull/166): Watch Secret resources for updates. **Note**: If a
  Secret referenced by one or more Ingress resources becomes invalid or gets removed, the configuration for those
  Ingress resources will be disabled until there is a valid Secret.
- [160](https://github.com/nginx/kubernetes-ingress/pull/160): Add support for events. See the details
  [here](https://github.com/nginx/kubernetes-ingress/pull/160).
- [157](https://github.com/nginx/kubernetes-ingress/pull/157): Add graceful termination - when the Ingress Controller
  receives `SIGTERM`, it shutdowns itself as well as NGINX, using `nginx -s quit`.

## 0.9.0

- [156](https://github.com/nginx/kubernetes-ingress/pull/156): Write a pem file with an SSL certificate and key
  atomically.
- [155](https://github.com/nginx/kubernetes-ingress/pull/155): Remove http2 annotation (http/2 can be enabled
  globally in the ConfigMap).
- [154](https://github.com/nginx/kubernetes-ingress/pull/154): Merge NGINX and NGINX Plus Ingress Controller
  implementations.
- [151](https://github.com/nginx/kubernetes-ingress/pull/151): Use k8s.io/client-go.
- [146](https://github.com/nginx/kubernetes-ingress/pull/146): Fix health status.
- [141](https://github.com/nginx/kubernetes-ingress/pull/141): Set `worker_processes` to `auto` in NGINX
  configuration. Thanks to [Andreas Krüger](https://github.com/woopstar).
- [140](https://github.com/nginx/kubernetes-ingress/pull/140): Fix an error message. Thanks to [Andreas
  Krüger](https://github.com/woopstar).
- Update NGINX to version 1.13.3.

## 0.8.1

- Update NGINX version to 1.13.0.

## 0.8.0

- [117](https://github.com/nginx/kubernetes-ingress/pull/117): Add a customization option: location-snippets,
  server-snippets and http-snippets. Thanks to [rchicoli](https://github.com/rchicoli).
- [116](https://github.com/nginx/kubernetes-ingress/pull/116): Add support for the 301 redirect to https based on the
  `http_x_forwarded_proto` header. Thanks to [Chris](https://github.com/cwhenderson20).
- Update NGINX version to 1.11.13.
- Makefile updates: gcloud docker push command; golang container was updated to 1.8.
- Documentation fixes: [113](https://github.com/nginx/kubernetes-ingress/pull/113). Thanks to [Linus
  Lewandowski](https://github.com/LEW21).

## 0.7.0

- [108](https://github.com/nginx/kubernetes-ingress/pull/108): Support for the `server_tokens` directive via the
  annotation and in the configmap. Thanks to [David Radcliffe](https://github.com/dwradcliffe).
- [103](https://github.com/nginx/kubernetes-ingress/pull/103): Improve error reporting when NGINX fails to start.
- [100](https://github.com/nginx/kubernetes-ingress/pull/100): Add the health check location. Thanks to
  [Julian](https://github.com/jmastr).
- [95](https://github.com/nginx/kubernetes-ingress/pull/95): Fix the runtime.TypeAssertionError issue, which
  sometimes occurred when deleting resources. Thanks to [Tang Le](https://github.com/tangle329).
- [93](https://github.com/nginx/kubernetes-ingress/pull/93): Fix overwriting of Secrets with the same name from
  different namespaces.
- [92](https://github.com/nginx/kubernetes-ingress/pull/92/files): Add overwriting of the HSTS header. Previously,
  when HSTS was enabled, if a backend issued the HSTS header, the controller would add the second HSTS header. Now the
  controller overwrites the HSTS header, if a backend also issues it.
- [91](https://github.com/nginx/kubernetes-ingress/pull/91): Fix the issue with single service Ingress resources
without any Ingress rules: the controller didn't pick up any updates of the endpoints of the service of such an Ingress
resource. Thanks to [Tang Le](https://github.com/tangle329).
- [88](https://github.com/nginx/kubernetes-ingress/pull/88): Support for the `proxy_hide_header` and the
  `proxy_pass_header` directives via annotations and in the configmap. Thanks to [Nico
  Schieder](https://github.com/thetechnick).
- [85](https://github.com/nginx/kubernetes-ingress/pull/85): Add the configmap settings to support perfect forward
  secrecy. Thanks to [Nico Schieder](https://github.com/thetechnick).
- [84](https://github.com/nginx/kubernetes-ingress/pull/84): Secret retry: If a certificate Secret referenced in an
Ingress object is not found, the Ingress Controller will reject the Ingress object. but retries every 5s. Thanks to
[Nico Schieder](https://github.com/thetechnick).
- [81](https://github.com/nginx/kubernetes-ingress/pull/81): Add configmap options to turn on the PROXY protocol.
  Thanks to [Nico Schieder](https://github.com/thetechnick).
- Update NGINX version to 1.11.8.
- Documentation fixes: [104](https://github.com/nginx/kubernetes-ingress/pull/104/files) and
  [97](https://github.com/nginx/kubernetes-ingress/pull/97/files). Thanks to [Ruilin Huang](https://github.com/hrl)
  and [Justin Garrison](https://github.com/rothgar).

## 0.6.0

- [75](https://github.com/nginx/kubernetes-ingress/pull/75): Add the HSTS settings in the configmap and annotations.
  Thanks to [Nico Schieder](https://github.com/thetechnick).
- [74](https://github.com/nginx/kubernetes-ingress/pull/74): Fix the issue of the `kubernetes.io/ingress.class`
  annotation handling. Thanks to [Tang Le](https://github.com/tangle329).
- [70](https://github.com/nginx/kubernetes-ingress/pull/70): Add support for the alpine-based image for the NGINX
  controller.
- [68](https://github.com/nginx/kubernetes-ingress/pull/68): Support for proxy-buffering settings in the configmap
  and annotations. Thanks to [Mark Daniel Reidel](https://github.com/df-mreidel).
- [66](https://github.com/nginx/kubernetes-ingress/pull/66): Support for custom log-format in the configmap. Thanks
  to [Mark Daniel Reidel](https://github.com/df-mreidel).
- [65](https://github.com/nginx/kubernetes-ingress/pull/65): Add HTTP/2 as an option in the configmap and
  annotations. Thanks to [Nico Schieder](https://github.com/thetechnick).
- The NGINX Plus controller image is now based on Ubuntu Xenial.

## 0.5.0

- Update NGINX version to 1.11.5.
- [64](https://github.com/nginx/kubernetes-ingress/pull/64): Add the `nginx.org/rewrites` annotation, which allows to
  rewrite the URI of a request before sending it to the application. Thanks to [Julian](https://github.com/jmastr).
- [62](https://github.com/nginx/kubernetes-ingress/pull/62): Add the `nginx.org/ssl-services` annotation, which
  allows load balancing of HTTPS applications. Thanks to [Julian](https://github.com/jmastr).

## 0.4.0

- [54](https://github.com/nginx/kubernetes-ingress/pull/54): Previously, when specifying the port of a service in an
  Ingress rule, you had to use the value of the target port of that port of the service, which was incorrect. Now you
  must use the port value or the name of the port of the service instead of the target port value. **Note**: Please make
  necessary changes to your Ingress resources, if ports of your services have different values of the port and the
  target port fields.
- [55](https://github.com/nginx/kubernetes-ingress/pull/55): Add support for the `kubernetes.io/ingress.class`
  annotation in Ingress resources.
- [58](https://github.com/nginx/kubernetes-ingress/pull/58): Add the version information to the controller. For each
  version of the NGINX controller, you can find a corresponding image on
  [DockerHub](https://hub.docker.com/r/nginxdemos/nginx-ingress/tags/) with a tag equal to the version. The latest
  version is available through the `latest` tag.

The previous version was 0.3

## Notes

- Except when mentioned otherwise, the controller refers both to the NGINX and the NGINX Plus Ingress Controllers.
