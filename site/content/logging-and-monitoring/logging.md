---
docs: DOCS-613
doctypes:
- ''
title: Logging
toc: true
weight: 1800
---

This document gives an overview of logging provided by NGINX Ingress Controller.

NGINX Ingress Controller exposes the logs of the Ingress Controller process (the process that generates NGINX configuration and reloads NGINX to apply it) and NGINX access and error logs. All logs are sent to the standard output and error of the NGINX Ingress Controller process. To view the logs, you can execute the `kubectl logs` command for an Ingress Controller pod. For example:

```shell
kubectl logs <nginx-ingress-pod> -n nginx-ingress
```

## NGINX Ingress Controller Process Logs

The NGINX Ingress Controller process logs are configured through the `-log-level` command-line argument of the NGINX Ingress Controller, which sets the log level. The default value is `info`. Other options include: `trace`, `debug`, `info`, `warning`, `error` and `fatal`. The value `debug` is useful for troubleshooting: you will be able to see how NGINX Ingress Controller gets updates from the Kubernetes API, generates NGINX configuration and reloads NGINX.

See also the doc about NGINX Ingress Controller [command-line arguments](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments).

## NGINX Logs

The NGINX includes two logs:

- *Access log*, where NGINX writes information about client requests in the access log right after the request is processed. The access log is configured via the [logging-related](/nginx-ingress-controller/configuration/global-configuration/configmap-resource#logging) ConfigMap keys:
  - `log-format` for HTTP and HTTPS traffic.
  - `stream-log-format` for TCP, UDP, and TLS Passthrough traffic.

    Additionally, you can disable access logging with the `access-log-off` ConfigMap key.
- *Error log*, where NGINX writes information about encountered issues of different severity levels. It is configured via the `error-log-level` [ConfigMap key](/nginx-ingress-controller/configuration/global-configuration/configmap-resource#logging). To enable debug logging, set the level to `debug` and also set the `-nginx-debug` [command-line argument](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments), so that NGINX is started with the debug binary `nginx-debug`.

See also the doc about [NGINX logs](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/) from NGINX Admin guide.
