---
title: Product telemetry
toc: true
weight: 500
---

Learn why, what and how F5 NGINX Ingress Controller collects telemetry.

---

## Overview

NGINX Ingress Controller collects product telemetry data to allow its developers to understand how it's deployed and configured by users. This data is used to triage development work, prioritizing features and functionality that will benefit the most people.

Product telemetry is enabled by default, collected once every 24 hours. It's then sent over HTTPS to a service managed by F5 at `oss.edge.df.f5.com`.

{{< note >}} If you would prefer not to send any telemetry data, you can [opt-out](#opt-out) when installing NGINX Ingress Controller. {{< /note >}}

---

## Data collected

These are the data points collected and reported by NGINX Ingress Controller:

- **Project Name** The name of the software, which will be labelled `NIC`.
- **Project Version** NGINX Ingress Controller version.
- **Project Architecture** The architecture of the kubernetes environment. (e.g. amd64, arm64, etc...)
- **Cluster ID** A unique identifier of the kubernetes cluster that NGINX Ingress Controller is deployed to.
- **Cluster Version** The version of the Kubernetes cluster.
- **Cluster Platform** The platform that the kubernetes cluster is operating on. (e.g. eks, aks,  etc...)
- **Cluster Node Count** The number of nodes in the cluster that NGINX Ingress Controller is deployed to.
- **Installation ID** Used to identify a unique installation of NGINX Ingress Controller.
- **VirtualServers** The number of VirtualServer resources managed by NGINX Ingress Controller.
- **VirtualServerRoutes** The number of VirtualServerRoute resources managed by NGINX Ingress Controller.
- **TransportServers** The number of TransportServer resources managed by NGINX Ingress Controller.
- **Replicas** Number of Deployment replicas, or Daemonset instances.
- **Secrets** Number of Secret resources managed by NGINX Ingress Controller.
- **ClusterIPServices** Number of ClusterIP Services managed by NGINX Ingress Controller.
- **NodePortServices** Number of NodePort Services managed by NGINX Ingress Controller.
- **LoadBalancerServices** Number of LoadBalancer Services managed by NGINX Ingress Controller.
- **ExternalNameServices** Number of ExternalName Services managed by NGINX Ingress Controller.
- **RegularIngressCount** The number of Regular Ingress resources managed by NGINX Ingress Controller.
- **MasterIngressCount** The number of Master Ingress resources managed by NGINX Ingress Controller.
- **MinionIngressCount** The number of Minion Ingress resources managed by NGINX Ingress Controller.
- **IngressClasses** Number of Ingress Classes in the cluster.
- **IngressAnnotations** List of Ingress annotations managed by NGINX Ingress Controller
- **AccessControlPolicies** Number of AccessControl policies.
- **RateLimitPolicies** Number of RateLimit policies.
- **APIKeyPolicies** Number of API Key Auth policies.
- **JWTAuthPolicies** Number of JWTAuth policies.
- **BasicAuthPolicies** Number of BasicAuth policies.
- **IngressMTLSPolicies** Number of IngressMTLS policies.
- **EgressMTLSPolicies** Number of EgressMTLS policies.
- **OIDCPolicies** Number of OIDC policies.
- **WAFPolicies** Number of WAF policies.
- **GlobalConfiguration** Represents the use of a GlobalConfiguration resource.
- **AppProtectVersion** The AppProtect version
- **IsPlus** Represents whether NGINX is Plus or OSS
- **InstallationFlags** List of command line arguments configured for NGINX Ingress Controller
- **BuildOS** The base operating system image in which NGINX Ingress Controller is running on.
- **ConfigMapKeys** List of ConfigMap keys from the main ConfigMap configured for NGINX Ingress Controller.
- **MGMTConfigMapKeys** List of MGMTConfigMap keys from the mgmt ConfigMap configured for NGINX Ingress Controller.



---

## Opt out

Product telemetry can be disabled when installing NGINX Ingress Controller.

### Helm

When installing or upgrading NGINX Ingress Controller with Helm, set the `controller.telemetryReporting.enable` option to `false`.

This can be set directly in the `values.yaml` file, or using the `--set` option

```shell
helm upgrade --install ... --set controller.telemetryReporting.enable=false
```

---

### Manifests

When installing NGINX Ingress Controller with Manifests, set the `-enable-telemetry-reporting` flag to `false`
