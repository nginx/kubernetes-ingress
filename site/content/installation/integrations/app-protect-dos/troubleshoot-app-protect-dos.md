---
docs: DOCS-1456
doctypes:
- ''
title: Troubleshoot NGINX App Protect DoS
toc: true
weight: 400
---

This document describes how to troubleshoot problems when using NGINX Ingress Controller and the App Protect DoS module.

To troubleshoot other parts of NGINX Ingress Controller, check the [troubleshooting]({{< relref "troubleshooting/troubleshoot-common.md" >}}) section of the documentation.

## Potential problems

The table below outlines potential problems with NGINX Ingress Controller when the App Protect DoS module is enabled. It suggests how to troubleshoot those problems with methods explained in the next section.

{{% table %}}
|Problem area | Symptom | Troubleshooting method | Common cause |
| ---| ---| ---| --- |
|Start | NGINX Ingress Controller fails to start. | Check the NGINX Ingress Controller logs. | Misconfigured DosProtectedResource, APDosLogConf or APDosPolicy. |
|DosProtectedResource, APDosLogConf, APDosPolicy or Ingress Resource. | The configuration is not applied. | Check the events of the DosProtectedResource, APDosLogConf, APDosPolicy and Ingress Resource, check the Ingress Controller logs. | DosProtectedResource, APDosLogConf or APDosPolicy is invalid. |
{{% /table %}}

## Troubleshooting ethods

### Checking NGINX Ingress Controller and App Protect DoS logs

App Protect DoS logs are part of the NGINX Ingress Controller logs when the module is enabled. To check the Ingress Controller logs, follow the steps of [Checking the Ingress Controller Logs]({{< relref "troubleshooting/troubleshoot-common#checking-nginx-ingress-controller-logs" >}}s) of the Troubleshooting guide.

For App Protect DoS specific logs, look for messages starting with `APP_PROTECT_DOS`, such as:

```shell
2021/06/14 08:17:50 [notice] 242#242: APP_PROTECT_DOS { "event": "shared_memory_connected", "worker_pid": 242, "mode": "operational", "mode_changed": true }
```

### Checking Ingress Resource Events

Follow the steps of [Troubleshooting Ingress Resources]({{< relref "troubleshooting/troubleshoot-ingress" >}}).

### Checking VirtualServer Resource Events

Follow the steps of [Troubleshooting VirtualServer Resources]({{< relref "troubleshooting/troubleshoot-virtualserver" >}}).

### Checking for DoSProtectedResource Events

After you create or update an DosProtectedResource, you can immediately check if the NGINX configuration was successfully applied by NGINX:

```shell
kubectl describe dosprotectedresource dos-protected
Name:         dos-protected
Namespace:    default

Events:
  Type     Reason          Age   From                      Message
  ----     ------          ----  ----                      -------
  Normal   AddedOrUpdated  2s    nginx-ingress-controller  Configuration for default/dos-protected was added or updated
```

Note that in the events section, we have a `Normal` event with the `AddedOrUpdated` reason, which informs us that the configuration was successfully applied.

If the DosProtectedResource refers to a missing resource, you should see a message like the following:

```shell
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  8s    nginx-ingress-controller  dos protected refers (default/dospolicy) to an invalid DosPolicy: DosPolicy default/dospolicy not found
```

This can be fixed by adding the missing resource.

### Checking for APDosLogConf Events

After you create or update an APDosLogConf, you can immediately check if the NGINX configuration was successfully applied by NGINX:

```shell
kubectl describe apdoslogconf logconf
Name:         logconf
Namespace:    default

Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  11s   nginx-ingress-controller  AppProtectDosLogConfig  default/logconf was added or updated
```

Note that in the events section, we have a `Normal` event with the `AddedOrUpdated` reason, which informs us that the configuration was successfully applied.

### Check events of APDosPolicy

After you create or update an APDosPolicy, you can immediately check if the NGINX configuration was successfully applied by NGINX:

```shell
kubectl describe apdospolicy dospolicy
Name:         dospolicy
Namespace:    default
. . .
Events:
  Type    Reason          Age    From                      Message
  ----    ------          ----   ----                      -------
  Normal  AddedOrUpdated  2m25s  nginx-ingress-controller  AppProtectDosPolicy default/dospolicy was added or updated
```

The events section has a *Normal* event with the *AddedOrUpdated reason*, indicating the policy was successfully accepted.

## Run App Protect DoS in Debug log Mode

When you set the Ingress Controller to use debug log mode, the setting also applies to the App Protect DoS module.  See  [Running NGINX in the Debug Mode](/nginx-ingress-controller/troubleshooting/#running-nginx-in-the-debug-mode) for instructions.

You can enable debug log mode to App Protect DoS module only by setting the `app-protect-dos-debug` [configmap](/nginx-ingress-controller/configuration/global-configuration/configmap-resource#modules).
