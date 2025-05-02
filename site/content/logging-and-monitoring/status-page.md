---
docs: DOCS-615
doctypes:
- ''
title: Status Page
toc: true
weight: 1900
---

This document explains how to get access to the stub status in NGINX and the dashboard in NGINX Plus.

NGINX comes with a status page that reports basic metrics about NGINX called the [stub status](https://nginx.org/en/docs/http/ngx_http_stub_status_module.html).

NGINX Plus comes with a [dashboard](https://docs.nginx.com/nginx/admin-guide/monitoring/live-activity-monitoring/) that reports key load-balancing and performance metrics.

NGINX App Protect DoS comes with a [dashboard](https://docs.nginx.com/nginx-app-protect-dos/monitoring/live-activity-monitoring/) that shows the status and information of the protected objects.
This doc shows how to get access to the stub status/dashboard.

## Accessing Stub Status

Prerequisites:

1. The stub status is enabled by default. Ensure that the `nginx-status` [command-line argument](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments) is not set to false.
1. The stub status is available on port 8080 by default. It is customizable by the `nginx-status-port` command-line argument. If yours is not on 8080, modify the kubectl proxy command below.

To access the status:

1. Use the `kubectl port-forward` command to forward connections to port 8080 on your local machine to port 8080 of an NGINX Ingress Controller pod (replace `<nginx-ingress-pod>` with the actual name of a pod):.

    ```
    kubectl port-forward <nginx-ingress-pod> 8080:8080 --namespace=nginx-ingress
    ```

1. Open your browser at [http://127.0.0.1:8080/stub_status](http://127.0.0.1:8080/stub_status) to access the status.

If you want to access the stub status externally (without `kubectl port-forward`):

1. Configure `-nginx-status-allow-cidrs` command-line argument with IP/CIDR blocks for which you want to allow access to the status. By default, the access is allowed for `127.0.0.1,::1`.
1. Use the IP/port through which the Ingress Controller pod/pods are available to connect the stub status at the `/stub_status` path.

## Accessing Live Activity Monitoring Dashboard

Prerequisites:

1. The dashboard is enabled by default. Ensure that the `nginx-status` [command-line argument](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments)is not set to false.
1. The dashboard is available on port 8080 by default. It is customizable by the `nginx-status-port` command-line argument. If yours is not on 8080, modify the kubectl proxy command below.

To access the dashboard:

1. Use the `kubectl port-forward` command to forward connections to port 8080 on your local machine to port 8080 of an NGINX Plus Ingress Controller pod (replace `<nginx-plus-ingress-pod>` with the actual name of a pod):

    ```
    kubectl port-forward <nginx-plus-ingress-pod> 8080:8080 --namespace=nginx-ingress
    ```

1. Open your browser at <http://127.0.0.1:8080/dashboard.html> to access the dashboard.
1. App Protect DoS: Open your browser at <http://127.0.0.1:8080/dashboard-dos.html> to access the dashboard.

If you want to access the dashboard externally (without `kubectl port-forward`):

1. Configure `-nginx-status-allow-cidrs` command-line argument with IP/CIDR blocks for which you want to allow access to the dashboard. By default, the access is allowed for `127.0.0.1,::1`.
1. Use the IP/port through which the Ingress Controller pod/pods are available to connect the dashboard at the `/dashboard.html` path.

**Note**: The [API](https://nginx.org/en/docs/http/ngx_http_api_module.html), which the dashboard uses to get the metrics, is also accessible: use the `/api` path. For App Protect DoS use the `/api/dos` path. Note that the API is configured in the read-only mode.
