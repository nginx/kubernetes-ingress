---
title: Configure NGINX App Protect with NGINX Ingress Controller
weight: 200
toc: true
type: how-to
product: NIC
docs: DOCS-000
---

## Overview

This document explains how to use F5 NGINX Ingress Controller to configure [NGINX App Protect WAF v5](https://docs.nginx.com/nginx-app-protect-waf/v5/).

{{< note >}} There are complete NGINX Ingress Controller with NGINX App Protect WAF [example resources on GitHub](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5). {{< /note >}}

## Global configuration

NGINX Ingress Controller has global configuration parameters that match those in NGINX App Protect WAF. They are found in the [ConfigMap resource]({{< relref "configuration/global-configuration/configmap-resource.md#modules" >}}): the NGINX App Protect WAF parameters are prefixed with `app-protect*`.

## Enable NGINX App Protect WAF v5

NGINX App Protect WAF v5 can be enabled and configured for custom resources only(VirtualServer, VirtualServerRoute). You need to create a Policy Custom Resource referencing a policy bundle, then add it to the VirtualServer/VirtualServerRoute definition. Additional detail can be found in the [Policy Resource documentation]({{< relref "configuration/policy-resource.md#waf" >}}).

---

## NGINX App Protect WAF Bundles

App Protect WAF bundles for VirtualServer custom resources are defined by creating policy bundles and putting them on a mounted volume accessible from NGINX Ingress Controller.

Before applying a policy, a WAF policy bundle must be created, then copied to a volume mounted to `/etc/app_protect/bundles`.

{{< note >}} NGINX Ingress Controller supports `securityLogs` for policy bundles. Log bundles must also be copied to a volume mounted to `/etc/app_protect/bundles`. {{< /note >}}

This example shows how a policy is configured by referencing a generated WAF Policy Bundle:

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: <policy_name>
spec:
  waf:
    enable: true
    apBundle: "<policy_bundle_name>.tgz"
```

This example shows the same policy as above but with a log bundle used for security log configuration:

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: <policy_name>
spec:
  waf:
    enable: true
    apBundle: "<policy_bundle_name>.tgz"
    securityLogs:
    - enable: true
      apLogBundle: "<log_bundle_name>.tgz"
      logDest: "syslog:server=syslog-svc.default:514"
```

{{< note >}}
We recommend compiling your NGINX App Protect WAF Policy Bundles using the [NGINX App Protect Compiler](https://docs.nginx.com/nginx-app-protect-waf/v5/admin-guide/compiler/) with each release of NGINX Ingress Controller. 

This ensures Policies remain compatible and are compiled with the latest attack signatures, bot signatures, and Threat campaigns.
{{< /note >}}

---

## Configure NGINX Plus Ingress Controller using Virtual Server resources

This example shows how to deploy NGINX Ingress Controller with NGINX Plus and NGINX App Protect WAF v5, deploy a simple web application, and then configure load balancing and WAF protection for that application using the VirtualServer resource.

{{< note >}} You can find the files for this example on [GitHub](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5).{{< /note >}}

### Prerequisites

1. Follow the installation [instructions]({{< relref "installation/integrations/app-protect-waf-v5/installation.md" >}}) to deploy NGINX Ingress Controller with NGINX Plus and NGINX App Protect WAF version 5.

2. Save the public IP address of NGINX Ingress Controller into a shell variable:

   ```shell
    IC_IP=XXX.YYY.ZZZ.III
   ```

3. Save the HTTP port of NGINX Ingress Controller into a shell variable:

   ```shell
    IC_HTTP_PORT=<port number>
   ```

### Deploy a web application

Create the application deployment and service:

  ```shell
  kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5/webapp.yaml
  ```

### Create the Syslog service

Create the syslog service and pod for the NGINX App Protect WAF security logs:


   ```shell
   kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5/syslog.yaml
   ```

### Deploy the WAF Policy


{{< note >}} Configuration settings in the Policy resource enable WAF protection by configuring NGINX App Protect WAF with the log configuration created in the previous step. The policy bundle referenced as `your_policy_bundle_name.tgz` need to be created and placed in the `/etc/app_protect/bundles` volume first.{{</ note >}}

Create and deploy the WAF policy.

 ```shell
  kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5/waf.yaml
 ```


### Configure load balancing

{{< note >}} VirtualServer references the `waf-policy` created in Step 3.{{</ note >}}

1. Create the VirtualServer Resource:

    ```shell
    kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5/virtual-server.yaml
    ```


### Test the application

To access the application, curl the coffee and the tea services. Use the `--resolve` option to set the Host header of a request with `webapp.example.com`

1. Send a request to the application:

  ```shell
  curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
  ```

  ```shell
  Server address: 10.12.0.18:80
  Server name: webapp-7586895968-r26zn
  ```

1. Try to send a request with a suspicious URL:

  ```shell
  curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP "http://webapp.example.com:$IC_HTTP_PORT/<script>"
  ```

  ```shell
  <html><head><title>Request Rejected</title></head><body>
  ```

1.  Check the security logs in the syslog pod:

  ```shell
  kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
  ```

## Example VirtualServer configuration

The GitHub repository has a full [VirtualServer example](https://raw.githubusercontent.com/nginx/kubernetes-ingress/v{{< nic-version >}}/examples/custom-resources/app-protect-waf-v5/webapp.yaml).

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: webapp
spec:
  host: webapp.example.com
  policies:
  - name: waf-policy
  upstreams:
  - name: webapp
    service: webapp-svc
    port: 80
  routes:
  - path: /
    action:
      pass: webapp
```
