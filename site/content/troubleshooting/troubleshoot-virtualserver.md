---
docs: DOCS-1461
doctypes:
- ''
title: Troubleshooting VirtualServer resources
toc: true
weight: 600
---

This page describes how to troubleshoot VirtualServer and VirtualServer resource events.

## Inspecting VirtualServer and VirtualServerRoute resource events

After creating or updating a VirtualServer resource, you can immediately check if the NGINX configuration for that resource was successfully by using `kubectl describe vs <resource-name>`:

```shell
kubectl describe vs cafe
```
```shell
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  16s   nginx-ingress-controller  Configuration for default/cafe was added or updated
```

In the above example, we have a `Normal` event with the `AddedOrUpdate` reason, which informs us that the configuration was successfully applied.

Checking the events of a VirtualServerRoute is similar:

```shell
kubectl describe vsr coffee
```
```shell
Events:
  Type     Reason                 Age   From                      Message
  ----     ------                 ----  ----                      -------
  Normal   AddedOrUpdated         1m    nginx-ingress-controller  Configuration for default/coffee was added or updated
```
