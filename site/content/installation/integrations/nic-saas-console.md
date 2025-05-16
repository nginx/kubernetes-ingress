---
doctypes:
- concept
title: Connect NGINX Ingress Controller to NGINX One Console
toc: true
weight: 1800
---

This document explains how to connect F5 NGINX Ingress Controller to NGINX One Console using Agent.

## Prerequisites

- NGINX Ingress Controller with NGINX Plus
- Access to NGINX One SaaS Console

## Overview of NGINX One SaaS Console and Agent V3

NGINX One SaaS Console is a cloud-based management platform that provides visibility and control over your NGINX deployments. Agent V3 is the latest version of the NGINX Agent that enables communication between NGINX Ingress Controller and the NGINX One SaaS Console.

Key benefits of connecting NGINX Ingress Controller to NGINX One SaaS Console include:

- Centralized monitoring of NGINX Ingress Controller instances
- Enhanced security monitoring and analytics
- Real-time metrics and alerts

## Deploying NGINX Ingress Controller with NGINX Agent configuration

{{< important >}}
The NGINX Agent configuration must be done before deploying NGINX Ingress Controller. If you attempt to add the Agent configuration to an already deployed NGINX Ingress Controller, it may not work correctly.
{{< /important >}}

{{<tabs name="deploy-config-resource">}}

{{%tab name="Using Helm"%}}

1. Edit your `values.yaml` file to enable NGINX Agent V3 and configure it to connect to NGINX One SaaS Console:
   ```yaml
   nginxAgent:
   enable: true
   logLevel: "error"

   dataplaneKey: "<Your Dataplane Key>"
   endpointHost: "product.connect.nginx.com"
   ```

   Make sure you get your dataplane key from the NGINX One SaaS Console. The `dataplaneKey` is used to authenticate the agent with NGINX One SaaS Console. [See here](https://docs.nginx.com/nginx-one/getting-started/#generate-data-plane-key) to get your dataplane key from the NGINX One SaaS Console.

   Change the endpointHost value to the NGINX One SaaS Console hostname or leave it default to `product.connect.nginx.com`.


1. Follow the [Installation with Helm]({{< relref "/installation/installing-nic/installation-with-helm.md" >}}) instructions to deploy NGINX Ingress Controller.

{{%/tab%}}

{{%tab name="Using Manifests"%}}

1. Add the following arguments to the deployment file of NGINX Ingress Controller:

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
        level: debug
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

3. Mount the ConfigMap to the NGINX Ingress Controller deployment `nginx-plus-ingress.yaml` file:
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

After deploying NGINX Ingress Controller with NGINX Agent V3 configuration, you can verify the connection to NGINX One SaaS Console:

1. Check if the NGINX Agent is running:
   ```bash
   kubectl logs -n <namespace> <nginx-ingress-pod-name>
   ```

2. Log in to your NGINX One SaaS Console account and navigate to the Instances dashboard. Your NGINX Ingress Controller instances should appear in the list.

3. If your instances don't appear, check the NGINX Agent logs for any errors:
   ```bash
   kubectl logs -n <namespace> <nginx-ingress-pod-name> | grep "error"
   ```

## Troubleshooting

If you encounter issues connecting NGINX Ingress Controller to NGINX One SaaS Console, try the following:

1. Verify that the NGINX Agent is running:
   ```bash
   kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- ps aux | grep nginx-agent
   ```

2. Check the NGINX Agent configuration:
   ```bash
   kubectl exec -it -n <namespace> <nginx-ingress-pod-name> -- cat /etc/nginx-agent/nginx-agent.conf
   ```

3. Ensure that the dataplane key is correctly configured and has the appropriate permissions.


## Additional Resources

- [NGINX Agent Documentation](https://docs.nginx.com/nginx-agent/)
- [NGINX One SaaS Console Documentation](https://docs.nginx.com/nginx-one/)
