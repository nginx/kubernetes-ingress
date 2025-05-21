---
doctypes:
   - concept
title: Connect NGINX Ingress Controller to NGINX One Console
toc: true
weight: 1800
---

This document explains how to connect F5 NGINX Ingress Controller to NGINX One Console using NGINX Agent.

## Overview of NGINX One Console and Agent

NGINX One Console is a cloud-based management platform that provides visibility and control over your NGINX deployments. NGINX Agent enables communication between NGINX Ingress Controller and the NGINX One Console.

Key benefits of connecting NGINX Ingress Controller to NGINX One Console include:

- Centralized monitoring of NGINX Ingress Controller instances

## Deploying NGINX Ingress Controller with NGINX Agent configuration

{{<tabs name="deploy-config-resource">}}

{{%tab name="Using Helm"%}}

1. Edit your `values.yaml` file to enable NGINX Agent and configure it to connect to NGINX One Console:
   ```yaml
   nginxAgent:
      enable: true
      dataplaneKey: "<Your Dataplane Key>"
   ```

   The `dataplaneKey` is used to authenticate the agent with NGINX One Console. See the NGINX One Console Docs [here](https://docs.nginx.com/nginx-one/getting-started/#generate-data-plane-key) to generate your dataplane key from the NGINX One Console.


1. Follow the [Installation with Helm]({{< relref "/installation/installing-nic/installation-with-helm.md" >}}) instructions to deploy NGINX Ingress Controller.

{{%/tab%}}

{{%tab name="Using Manifests"%}}

1. Add the following arguments to the deployment/daemonset file of NGINX Ingress Controller:

   ```yaml
   args:
     - -agent=true
   ```

2. Create a ConfigMap with an `nginx-agent.conf` file:
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
   Make sure you set the namespace in the nginx-agent-config to the same namespace as the Ingress Controller.

3. Mount the ConfigMap to the deployment/daemonset file of NGINX Ingress Controller:
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

4. Follow the [Installation with Manifests]({{< relref "/installation/installing-nic/installation-with-manifests.md" >}}) instructions to deploy NGINX Ingress Controller.

{{%/tab%}}

{{</tabs>}}

## Verifying the Connection

After deploying NGINX Ingress Controller with NGINX Agent configuration, you can verify the connection to NGINX One Console.

Log in to your NGINX One Console account and navigate to the Instances dashboard. Your NGINX Ingress Controller instances should appear in the list, where the instance name will be the pod name.

## Troubleshooting

If you encounter issues connecting NGINX Ingress Controller to NGINX One Console, try the following steps based on your image type:

1. Check the NGINX Agent version:
   ```bash
   kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- nginx-agent -v
   ```
   
   if nginx-agent version is v3, continue with the following steps.
   Otherwise, make sure you are using an image that does not include App Protect. 

2. Check the NGINX Agent configuration:
   ```bash
   kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- cat /etc/nginx-agent/nginx-agent.conf
   ```

3. Check NGINX Agent logs:
   ```bash
   kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- nginx-agent
   ```


## Additional Resources

- [NGINX Agent Documentation](https://docs.nginx.com/nginx-agent/)
- [NGINX One Console Documentation](https://docs.nginx.com/nginx-one/)
