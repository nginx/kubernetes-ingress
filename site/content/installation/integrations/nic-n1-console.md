---
title: Connect NGINX Ingress Controller to NGINX One Console
toc: true
draft: true
weight: 1800
nd-type: how-to
nd-product: NIC
---

This document explains how to connect F5 NGINX Ingress Controller to NGINX One Console using NGINX Agent.

Connecting NGINX Ingress Controller to NGINX One Console enables centralized monitoring of all controller instances.

## Deploy NGINX Ingress Controller with NGINX Agent

{{<tabs name="deploy-config-resource">}}

{{%tab name="Helm"%}}

Edit your `values.yaml` file to enable NGINX Agent and configure it to connect to NGINX One Console:
```yaml
nginxAgent:
  enable: true
  dataplaneKey: "<Your Dataplane Key>"
```

 The `dataplaneKey` is used to authenticate the agent with NGINX One Console. See the NGINX One Console Docs [here](https://docs.nginx.com/nginx-one/getting-started/#generate-data-plane-key) to generate your dataplane key from the NGINX One Console.


Follow the [Installation with Helm]({{< ref "/installation/installing-nic/installation-with-helm.md" >}}) instructions to deploy NGINX Ingress Controller.

{{%/tab%}}

{{%tab name="Manifests"%}}

Add the following flag to the deployment/daemonset file of NGINX Ingress Controller:

```yaml
args:
- -agent=true
```

Create a ConfigMap with an `nginx-agent.conf` file:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-agent-config
  namespace: <namespace>
data:
  nginx-agent.conf: |-
  log:
    # set log level (error, info, debug; default "info")
    level: info
    # set log path. if empty, don't log to file.
    path: ""

  allowed_directories:
    - /etc/nginx
    - /usr/lib/nginx/modules

  features:
    - certificates
    - connection
    - metrics
    - file-watcher

  ## command server settings
  command:
    server:
      host: product.connect.nginx.com
      port: 443
    auth:
      token: "<Your Dataplane Key>"
    tls:
      skip_verify: false
```      
  
Make sure you set the namespace in the nginx-agent-config to the same namespace as NGINX Ingress Controller.

Mount the ConfigMap to the deployment/daemonset file of NGINX Ingress Controller:

```yaml
volumeMounts:
- name: nginx-agent-config
  mountPath: /etc/nginx-agent/nginx-agent.conf
  subPath: nginx-agent.conf
volumes:
- name: nginx-agent-config
  configMap:
    name: nginx-agent-config
```

Follow the [Installation with Manifests]({{< ref "/installation/installing-nic/installation-with-manifests.md" >}}) instructions to deploy NGINX Ingress Controller.

{{%/tab%}}

{{</tabs>}}

## Verify that NGINX Ingress Controller is connected to NGINX One

After deploying NGINX Ingress Controller with NGINX Agent, you can verify the connection to NGINX One Console.

Log in to your NGINX One Console account and navigate to the Instances dashboard. Your NGINX Ingress Controller instances should appear in the list, where the instance name will be the pod name.

## Troubleshooting

If you encounter issues connecting NGINX Ingress Controller to NGINX One Console, try the following steps based on your image type:

Check the NGINX Agent version:

```shell
kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- nginx-agent -v
```
  
If nginx-agent version is v3, continue with the following steps.
Otherwise, make sure you are using an image that does not include App Protect. 

Check the NGINX Agent configuration:

```shell
kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- cat /etc/nginx-agent/nginx-agent.conf
```

Check NGINX Agent logs:

```shell
kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- nginx-agent
```
