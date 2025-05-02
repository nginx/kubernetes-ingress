---
docs: DOCS-597
doctypes:
- ''
title: Security recommendations
toc: true
weight: 300
---

F5 NGINX Ingress Controller follows Kubernetes best practices: this page outlines configuration specific to NGINX Ingress Controller you may require, including links to examples in the [GitHub repository](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples).

For general guidance, we recommend the official Kubernetes documentation for [Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/).

## Kubernetes recommendations

### RBAC and Service Accounts

Kubernetes uses [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) to control the resources and operations available to different types of users.

NGINX Ingress Controller requires RBAC to configure a [ServiceUser](https://kubernetes.io/docs/concepts/security/service-accounts/#default-service-accounts), and provides least privilege access in its standard deployment configurations:

- [Helm](https://github.com/nginx/kubernetes-ingress/blob/v{{< nic-version >}}/deployments/rbac/rbac.yaml)
- [Manifests](https://github.com/nginx/kubernetes-ingress/blob/v{{< nic-version >}}/deployments/rbac/rbac.yaml)

By default, the ServiceAccount has access to all Secret resources in the cluster.

### Secrets

[Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) are required by NGINX Ingress Controller for certificates and privacy keys, which Kubernetes stores unencrypted by default. We recommend following the [Kubernetes documentation](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) to store these Secrets using at-rest encryption.


## NGINX Ingress Controller recommendations

### Configure root filesystem as read-only

{{< caution >}}
 This feature is compatible with [NGINX App Protect WAFv5](https://docs.nginx.com/nginx-app-protect-waf/v5/). It is not compatible with [NGINX App Protect WAFv4](https://docs.nginx.com/nginx-app-protect-waf/v4/) or [NGINX App Protect DoS](https://docs.nginx.com/nginx-app-protect-dos/).
{{< /caution >}}

NGINX Ingress Controller is designed to be resilient against attacks in various ways, such as running the service as non-root to avoid changes to files. We recommend setting filesystems on all containers to read-only, this includes `nginx-ingress-controller`, though also includes `waf-enforcer` and `waf-config-mgr` when NGINX App Protect WAFv5 is in use.  This is so that the attack surface is further reduced by limiting changes to binaries and libraries.

This is not enabled by default, but can be enabled with **Helm** using the [**readOnlyRootFilesystem**]({{< relref "installation/installing-nic/installation-with-helm.md#configuration" >}}) argument in security contexts on all containers: `nginx-ingress-controller`, `waf_enforcer` and `waf_config_mgr`.

For **Manifests**, uncomment the following sections of the deployment and add sections for `waf-enforcer` and `waf-config-mgr` containers:

- `readOnlyRootFilesystem: true`
- The entire **volumeMounts** section
- The entire **initContainers** section

The block below shows the code you will look for:

```yaml
#      volumes:
#      - name: nginx-etc
#        emptyDir: {}
#      - name: nginx-cache
#        emptyDir: {}
#      - name: nginx-lib
#        emptyDir: {}
#      - name: nginx-log
#        emptyDir: {}
.
.
.
#          readOnlyRootFilesystem: true
.
.
.
#        volumeMounts:
#        - mountPath: /etc/nginx
#          name: nginx-etc
#        - mountPath: /var/cache/nginx
#          name: nginx-cache
#        - mountPath: /var/lib/nginx
#          name: nginx-lib
#        - mountPath: /var/log/nginx
#          name: nginx-log
```

- Add **waf-enforcer** and **waf-config-mgr** container sections
- Add `readOnlyFilesystem: true` in both containers security context sections

### Prometheus

If Prometheus metrics are [enabled]({{< relref "/logging-and-monitoring/prometheus.md" >}}), we recommend [using HTTPS]({{< relref "configuration/global-configuration/command-line-arguments.md#cmdoption-prometheus-tls-secret" >}}).

### Snippets

Snippets allow raw NGINX configuration to be inserted into resources. They are intended for advanced NGINX users and could create vulnerabilities in a cluster if misused.

Snippets are disabled by default. To use snippets, set the [**enable-snippets**]({{< relref"configuration/global-configuration/command-line-arguments.md#cmdoption-enable-snippets" >}}) command-line argument.

{{< caution >}}
 Snippets are **always** enabled for ConfigMap.
{{< /caution >}}

For more information, read the following:

- [Advanced configuration using Snippets]({{< relref "/configuration/ingress-resources/advanced-configuration-with-snippets.md" >}})
- [Using Snippets with VirtualServer/VirtualServerRoute]({{< relref "configuration/virtualserver-and-virtualserverroute-resources.md#using-snippets" >}})
- [Using Snippets with TransportServer]({{< relref "/configuration/transportserver-resource.md#using-snippets" >}})
- [ConfigMap snippets and custom templates]({{< relref "configuration/global-configuration/configmap-resource.md#snippets-and-custom-templates" >}})
