---
docs: DOCS-1457
doctypes:
- ''
title: Troubleshooting Policy resources
toc: true
weight: 300
---

This page describes how to troubleshoot NGINX Ingress Controller Policy Resources.

## Policy Resources

After you create or update a Policy resource, you can use `kubectl describe` to check whether or not NGINX Ingress Controller accepted the policy:

```shell
kubectl describe pol webapp-policy
```
```shell
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  11s   nginx-ingress-controller  Policy default/webapp-policy was added or updated
```

The events section has a *Normal* event with the *AddedOrUpdated reason*, indicating the policy was successfully accepted.

However, the fact that a policy was accepted doesn’t guarantee that the NGINX configuration was successfully applied.

To verify the configuration applied, check the events of the [VirtualServer and VirtualServerRoute resources]({{< relref "troubleshooting/troubleshoot-virtualserver.md" >}}) that reference the policy.

## ConfigMap Resources

After you update the ConfigMap resource, you can immediately check if the configuration was successfully applied by NGINX:

```shell
kubectl describe configmap nginx-config -n nginx-ingress
Name:         nginx-config
Namespace:    nginx-ingress
Labels:       <none>

Events:
  Type    Reason   Age                From                      Message
  ----    ------   ----               ----                      -------
  Normal  Updated  11s (x2 over 26m)  nginx-ingress-controller  Configuration from nginx-ingress/nginx-config was updated
```

Similar to *Policies*, the events section has a *Normal* event with the *AddedOrUpdated reason*, indicating the policy was successfully accepted.
