---
docs: DOCS-1459
doctypes:
- troubleshooting
draft: false
tags:
- docs
title: Troubleshooting common issues
toc: true
weight: 200
---

This page describes how to troubleshoot common issues with NGINX Ingress Controller. Instruction for specific resources is available in the [Troubleshooting]({{< relref "troubleshooting/" >}}) section.

## Common issues

{{% table %}}
| Problem Area | Symptom | Troubleshooting Method | Common Cause |
|-----|-----|-----|-----|
| Startup | NGINX Ingress Controller fails to start. | Check the logs. | Misconfigured RBAC, a missing default server TLS Secret.|
| Ingress resource and annotations | The configuration is not applied | Check the events of the Ingress resource, check the logs, check the generated config. | Invalid values of annotations. |
| VirtualServer and VirtualServerRoute resources | The configuration is not applied. | Check the events of the VirtualServer and VirtualServerRoutes, check the logs, check the generated config. | VirtualServer or VirtualServerRoute is invalid. |
| Policy resource | The configuration is not applied. | Check the events of the Policy resource as well as the events of the VirtualServers that reference that policy, check the logs, check the generated config. | Policy is invalid. |
| ConfigMap keys | The configuration is not applied. | Check the events of the ConfigMap, check the logs, check the generated config.  | Invalid values of ConfigMap keys. |
| NGINX | NGINX responds with unexpected responses. | Check the logs, check the generated config, check the live activity dashboard (NGINX Plus only), run NGINX in the debug mode. | Unhealthy backend pods, a misconfigured backend service. |
{{% /table %}}

---

## Troubleshooting Methods

This section explains how to gather additional information for troubleshooting.

The commands examples make the following assumptions:

- That NGINX Ingress Controller is deployed in the namespace `nginx-ingress`.
- `<nginx-ingress-pod>` is the name of one of the NGINX Ingress Controller pods.

### Check NGINX Ingress Controller logs

To check NGINX Ingress Controller logs, which include both information from NGINX Ingress Controller and NGINX's access and error logs, run the following command:

```shell
kubectl logs <nginx-ingress-pod> -n nginx-ingress
```

### Check the generated configuration files

For each Ingress/VirtualServer resource, NGINX Ingress Controller generates a corresponding NGINX configuration file in the `/etc/nginx/conf.d folder`.

 Additionally, NGINX Ingress Controller generates the main configuration file `/etc/nginx/nginx.conf`, which includes all the configurations files from `/etc/nginx/conf.d`. The configuration for a VirtualServerRoute resource is located in the configuration file of the VirtualServer that references the resource.

You can view the content of the main configuration file by running:

```shell
kubectl exec <nginx-ingress-pod> -n nginx-ingress -- cat /etc/nginx/nginx.conf
```

Similarly, you can view the content of any generated configuration file in the `/etc/nginx/conf.d` folder.

You can also print all NGINX configuration files together:

```shell
kubectl exec <nginx-ingress-pod> -n nginx-ingress -- nginx -T
```

However, this command will fail if any of the configuration files is not valid.

### Check the Live Activity Monitoring Dashboard

The live activity monitoring dashboard shows the real-time information about NGINX Plus and the applications it is load balancing, which is helpful for troubleshooting. To access the dashboard, read the [Status Page]({{< relref "logging-and-monitoring/status-page.md" >}}) topic.

### Enable debugging for NGINX Ingress Controller

For additional NGINX Ingress Controller debugging, you can enable debug settings to get more verbose logging.

Increasing the debug log levels for NGINX Ingress Controller will also apply to NGINX itself.

There are two places to configure more verbose logging for NGINX Ingress Controller:

1. Command line arguments
2. Configmap settings

**Command line arguments**

When using `manifest` for deployment, use the command line argument `-nginx-debug` in your deployment or daemonset.

You can add the `-log-level` parameter to increase the verbosity of the NGINX Ingress Controller process.

Here is a small snippet of setting these command line arguments in the `args` section of a deployment:

```yaml
args:
  - -nginx-configmaps=$(POD_NAMESPACE)/nginx-config
  - -enable-cert-manager
  - -nginx-debug
  - -log-level=debug
```

**ConfigMap settings**  
You can configure `error-log-level` in NGINX Ingress Controller `configMap`:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-config
  namespace: nginx-ingress
data:
  error-log-level: "debug"
 ```

**Using Helm**

If you are using `helm`, you can adjust these two settings:

```none
controller.nginxDebug = true or false
controller.loglevel = fatal, error, warn, info, debug or trace
```

For example, if using a `values.yaml` file:

```yaml
  ## Enables debugging for NGINX. Uses the nginx-debug binary. Requires error-log-level: debug in ConfigMap via `controller.config.entries`.
  nginxDebug: true

  ## The log level of the Ingress Controller.
  logLevel: debug
```

This is a more complete example `values.yaml` file:

```yaml
controller:
  kind: Deployment
  nginxDebug: true
  logLevel: debug
  annotations:
    nginx: ingress-prod
  pod:
    annotations:
      prometheus.io/scrape: "true"
      prometheus.io/port: "9113"
      prometheus.io/scheme: http
    extraLabels:
      env: prod-weset
  nginxplus: plus
  image:
    repository: nginx/nginx-ingress
    tag: {{< nic-version >}}
  # NGINX Configmap
  config:
    entries:
      error-log-level: "debug"
      proxy_connet_timeout: "5s"
      http-snippets: |
        underscores_in_headers on;
  ingressClass: nginx
```

Enable the `nginx-debug` CLI argument and change the `error-log-level` to `debug` to capture more output for debugging.

{{< note >}} It is recommended to only enable `nginx-debug` CLI and the `error-log-level` when debugging. {{< /note >}}

#### Example debug NGINX Ingress Controller Output

These logs show some of the additional entries when debugging is enabled for NGINX Ingress Controller.

```shell
I1026 15:39:03.269092       1 manager.go:301] Reloading nginx with configVersion: 1
I1026 15:39:03.269115       1 utils.go:17] executing /usr/sbin/nginx-debug -s reload -e stderr
2022/10/26 15:39:03 [notice] 19#19: signal 1 (SIGHUP) received from 42, reconfiguring
2022/10/26 15:39:03 [debug] 19#19: wake up, sigio 0
2022/10/26 15:39:03 [notice] 19#19: reconfiguring
2022/10/26 15:39:03 [debug] 19#19: posix_memalign: 000056362AF0A420:16384 @16
2022/10/26 15:39:03 [debug] 19#19: add cleanup: 000056362AF0C318
2022/10/26 15:39:03 [debug] 19#19: posix_memalign: 000056362AF48230:16384 @16
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF00DE0:4096
2022/10/26 15:39:03 [debug] 19#19: read: 46, 000056362AF00DE0, 3090, 0
2022/10/26 15:39:03 [debug] 19#19: posix_memalign: 000056362AF58670:16384 @16
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF12440:4280
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF13500:4280
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF145C0:4280
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF5C680:4280
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF5D740:4280
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF5E800:4280
2022/10/26 15:39:03 [debug] 19#19: posix_memalign: 000056362AF5F8C0:16384 @16
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF41500:4096
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF638D0:8192
2022/10/26 15:39:03 [debug] 19#19: include /etc/nginx/mime.types
2022/10/26 15:39:03 [debug] 19#19: include /etc/nginx/mime.types
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF658E0:4096
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF668F0:5349
2022/10/26 15:39:03 [debug] 19#19: read: 47, 000056362AF658E0, 4096, 0
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF67DE0:4096
2022/10/26 15:39:03 [debug] 19#19: read: 47, 000056362AF658E1, 1253, 4096
2022/10/26 15:39:03 [debug] 19#19: posix_memalign: 000056362AF68DF0:16384 @16
2022/10/26 15:39:03 [debug] 19#19: posix_memalign: 000056362AF6CE00:16384 @16
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AF70E10:524288
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362AFF0E20:524288
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362B070E30:524288
2022/10/26 15:39:03 [debug] 19#19: malloc: 000056362B0F0E40:400280
```

Once you have completed your debugging process, you can change the values back to the original values.
