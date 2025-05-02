---
docs: DOCS-614
doctypes:
- concept
title: Prometheus
toc: true
weight: 2000
---

NGINX Ingress Controller exposes metrics in the [Prometheus](https://prometheus.io/) format. Those include NGINX/NGINX Plus and the Ingress Controller metrics.

## Enabling Metrics

### Using Manifests
If you're using *Kubernetes manifests* (Deployment or DaemonSet) to install the Ingress Controller, to enable Prometheus metrics:

1. Run the Ingress Controller with the `-enable-prometheus-metrics` [command-line argument](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments). As a result, the Ingress Controller will expose NGINX or NGINX Plus metrics in the Prometheus format via the path `/metrics` on port `9113` (customizable via the `-prometheus-metrics-listen-port` command-line argument).
1. To enable TLS for the Prometheus endpoint, configure the `-prometheus-tls-secret` cli argument with the namespace and name of a TLS Secret.
1. Add the Prometheus port to the list of the ports of the Ingress Controller container in the template of the Ingress Controller pod:

    ```yaml
    - name: prometheus
      containerPort: 9113
    ```

1. Make Prometheus aware of the Ingress Controller targets by adding the following annotations to the template of the Ingress Controller pod (note: this assumes your Prometheus is configured to discover targets by analyzing the annotations of pods):

    ```yaml
    annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9113"
        prometheus.io/scheme: http
    ```

### Using Helm

If you're using *Helm* to install the Ingress Controller, to enable Prometheus metrics, configure the `prometheus.*` parameters of the Helm chart. See the [Installation with Helm]({{< relref "/installation/installing-nic/installation-with-helm.md" >}}) doc.

### Using ServiceMonitor

When deploying with *Helm*, you can deploy a `Service` and `ServiceMonitor` resource using the `prometheus.service.*` and `prometheus.serviceMonitor.*` parameters.
When these resources are deployed, Prometheus metrics exposed by NGINX Ingress Controller can be captured and enumerated using a `Prometheus` resource alongside a Prometheus Operator deployment.

To view metrics captured this way, the following is required:
* The latest ServiceMonitor CRD from the [prometheus-operator](https://github.com/prometheus-operator/prometheus-operator) repository:
```shell
LATEST=$(curl -s https://api.github.com/repos/prometheus-operator/prometheus-operator/releases/latest | jq -cr .tag_name)
curl https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/$LATEST/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml | kubectl create -f -
```
* A working [Prometheus resource and Prometheus Operator](https://prometheus-operator.dev/docs/getting-started/introduction/)

## Available Metrics

The Ingress Controller exports the following metrics:

- NGINX/NGINX Plus metrics:
  - Exported by NGINX/NGINX Plus. Refer to the [NGINX Prometheus Exporter developer docs](https://github.com/nginx/nginx-prometheus-exporter#exported-metrics) to find more information about the exported metrics.
  - There is a Grafana dashboard for NGINX Plus metrics located in the root repo folder.
  - Calculated by the Ingress Controller:
    - `controller_upstream_server_response_latency_ms_count`. Bucketed response times from when NGINX establishes a connection to an upstream server to when the last byte of the response body is received by NGINX. **Note**: The metric for the upstream isn't available until traffic is sent to the upstream. The metric isn't enabled by default. To enable the metric, set the `-enable-latency-metrics` command-line argument.
- Ingress Controller metrics
  - `controller_nginx_reloads_total`. Number of successful NGINX reloads. This includes the label `reason` with 2 possible values `endpoints` (the reason for the reload was an endpoints update) and `other` (the reload was caused by something other than an endpoint update like an ingress update).
  - `controller_nginx_reload_errors_total`. Number of unsuccessful NGINX reloads.
  - `controller_nginx_last_reload_status`. Status of the last NGINX reload, 0 meaning down and 1 up.
  - `controller_nginx_last_reload_milliseconds`. Duration in milliseconds of the last NGINX reload.
  - `controller_nginx_worker_processes_total`. Number of NGINX worker processes. This metric includes the constant label `generation` with two possible values `old` (the shutting down processes of the old generations) or `current` (the processes of the current generation).
  - `controller_ingress_resources_total`. Number of handled Ingress resources. This metric includes the label type, that groups the Ingress resources by their type (regular, [minion or master](/nginx-ingress-controller/configuration/ingress-resources/cross-namespace-configuration)). **Note**: The metric doesn't count minions without a master.
  - `controller_virtualserver_resources_total`. Number of handled VirtualServer resources.
  - `controller_virtualserverroute_resources_total`. Number of handled VirtualServerRoute resources. **Note**: The metric counts only VirtualServerRoutes that have a reference from a VirtualServer.
  - `location_zone` (upstream services) metrics:
    - `location_zone_sent`. Number of bytes sent to clients.
    - `location_zone_received`. Number of bytes received from clients.
    - `location_zone_requests`. Total number of client requests.
    - `location_zone_responses`. Total number of responses sent to clients.
    - `location_zone_responses_codes`. Total number of responses sent to clients.
    - `location_zone_sent`. Number of bytes sent to clients.
  - `controller_transportserver_resources_total`. Number of handled TransportServer resources. This metric includes the label type, that groups the TransportServer resources by their type (passthrough, tcp or udp).
  - Workqueue metrics. **Note**: the workqueue is a queue used by the Ingress Controller to process changes to the relevant resources in the cluster like Ingress resources. The Ingress Controller uses only one queue. The metrics for that queue will have the label `name="taskQueue"`
    - `workqueue_depth`. Current depth of the workqueue.
    - `workqueue_queue_duration_second`. How long in seconds an item stays in the workqueue before being requested.
    - `workqueue_work_duration_seconds`. How long in seconds processing an item from the workqueue takes.

**Note**: all metrics have the namespace `nginx_ingress`. For example, `nginx_ingress_controller_nginx_reloads_total`.

**Note**: all metrics include the label `class`, which is set to the class of the Ingress Controller. The class is configured via the `-ingress-class` command-line argument.
