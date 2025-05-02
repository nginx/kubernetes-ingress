---
docs: DOCS-1458
doctypes:
- ''
title: Troubleshooting Ingress resources
toc: true
weight: 300
---

This page describes how to troubleshoot NGINX Ingress Controller Policy Resources.

## Ingress resources

After you create or update an Ingress resource, you can immediately check if the NGINX configuration for that Ingress resource was successfully applied by NGINX:

```shell
kubectl describe ing cafe-ingress
```
```shell
Name:             cafe-ingress
Namespace:        default

Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  12s   nginx-ingress-controller  Configuration for default/cafe-ingress was added or updated
```

The events section has a *Normal* event with the *AddedOrUpdated reason*, indicating the policy was successfully accepted.
