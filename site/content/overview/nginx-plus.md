---
docs: DOCS-611
doctypes:
- concept
title: Extensibility with NGINX Plus
weight: 300
---

This document explains how F5 NGINX Plus can extend the functionality of F5 NGINX Ingress Controller.

NGINX Ingress Controller works with [NGINX](https://nginx.org/) as well as [NGINX Plus](https://www.nginx.com/products/nginx/), a commercial closed source version of NGINX which has additional features and support from NGINX Inc. NGINX Ingress Controller can leverage functionality from NGINX Plus to extend its base capabilities.

---

## Additional features

- _Real-time metrics_: Metrics for NGINX Plus and application performance are available through the API or the [NGINX Status Page]({{< relref "logging-and-monitoring/status-page">}}). These metrics can also be exported to [Prometheus]({{< relref "logging-and-monitoring/prometheus">}}).
- _Additional load balancing methods_: The `least_time` and `random two least_time` methods and their derivatives become available. The NGINX [`ngx_http_upstream_module` documentation](https://nginx.org/en/docs/http/ngx_http_upstream_module.html) has the complete list of load balancing methods.
- _Session persistence_: The *sticky cookie* method becomes available. See the [Ingress Resource](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/session-persistence) and [Custom Resource](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/session-persistence) examples.
- _Active health checks_:  See the [Ingress Resource](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/health-checks) and [Custom Resource](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/health-checks) examples.
- _JWT validation_: See the [Ingress Resource](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/jwt) and [Custom Resource](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/jwt) examples.

For a comprehensive guide of NGINX Plus features available with Ingress resources, see the [ConfigMap]({{< relref "configuration/global-configuration/configmap-resource">}}) and [Annotations]({{< relref "configuration/ingress-resources/advanced-configuration-with-annotations">}}) documentation.

{{< note >}} NGINX Plus features are configured for Ingress resources using Annotations that start with `nginx.com`. {{< /note >}}

For a comprehensive guide of NGINX Plus features available with custom resources, see the [Policy]({{< relref "configuration/policy-resource" >}}), [VirtualServer]({{< relref "configuration/virtualserver-and-virtualserverroute-resources" >}}) and [TransportServer]({{< relref "configuration/transportserver-resource" >}}) documentation.

---

## Dynamic reconfiguration

NGINX Ingress Controller updates the configuration of the load balancer to reflect changes every time the number of pods exposed through an Ingress resource changes. When using NGINX, the configuration file must be changed then reloaded.

For NGINX Plus, its dynamic reconfiguration is utilized, updating NGINX Plus without reloading. This avoids the increase of memory usage caused by reloads (Particularly with large volumes of client requests) and when load balancing applications with long-lived connections (Such as those using WebSockets or handling file uploads, downloads or streaming).
