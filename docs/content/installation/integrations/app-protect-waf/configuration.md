---
title: Configuration
description: "This document explains how to use F5 NGINX Ingress Controller to configure NGINX App Protect WAF."
weight: 1900
doctypes: [""]
toc: true
docs: "DOCS-578"
aliases: ["/app-protect/configuration/"]
---

{{< note >}} The NGINX Ingress Controller repository has complete NGINX App Protect WAF examples with [VirtualServer resources](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/custom-resources/app-protect-waf) and [Ingress resources](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/app-protect-waf). {{< /note >}}

## Global Configuration

NGINX Ingress Controller has global configuration parameters that match those in NGINX App Protect WAF. They are found in the [ConfigMap resource]({{< relref "configuration/global-configuration/configmap-resource.md#modules" >}}): the NGINX App Protect WAF parameters are prefixed with `app-protect*`.

## Enable NGINX App Protect WAF

NGINX App Protect WAF can be enabled and configured for custom resources (VirtualServer, VirtualServerRoute) or Ingress resources.

- For custom resources, you need to create a Policy Custom Resource referencing the `APPolicy` custom resource or bundle, then add it to the VirtualServer definition. Additional detail can be found in the [Policy Resource documentation]({{< relref "configuration/policy-resource.md#waf" >}}).
- For Ingress resources, apply the [`app-protect` annotations]({{< relref "configuration/ingress-resources/advanced-configuration-with-annotations.md#app-protect" >}}) to each desired resource.


## NGINX App Protect WAF Policies

NGINX App Protect WAF Policies can be created for VirtualServer, VirtualServerRoute, or Ingress resources by creating an `APPolicy` [custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/). There are some caveats:

- The fields `policy.signature-requirements[].minRevisionDatetime` and `policy.signature-requirements[].maxRevisionDatetime` are not supported.
- [The Advanced gRPC Protection for Unary Traffic](/nginx-app-protect-waf/configuration-guide/configuration/#grpc-protection-for-unary-traffic) only supports providing an `idl-file` inline. The fields `policy.idl-files[].link`, `policy.idl-files[].$ref`, and
 `policy.idl-files[].file` are not supported. The IDL file should be provided in field `policy.idl-files[].contents`. The value of this field can be base64 encoded. In this case the field `policy.idl-files[].isBase64` should be set to `true`.

{{<warning>}} External references are deprecated in NGINX Ingress Controller and will not be supported in future releases. {{</warning>}}

To add an [NGINX App Protect WAF policy](/nginx-app-protect-waf/declarative-policy/policy/) to an Ingress resource:

1. Create an `APPolicy` custom resource manifest.
1. Add the policy to the `spec` field in the `APPolicy` resource.

A resource specification and its Policy JSON **must** match. The fields must be identical in name and nesting level. If the resources are defined with YAML, the policy must also be represented in YAML.

As an example, this is a [DataGuard policy](/nginx-app-protect-waf/declarative-policy/policy/#policy/data-guard):

```json
{
    "policy": {
        "name": "dataguard_blocking",
        "template": { "name": "POLICY_TEMPLATE_NGINX_BASE" },
        "applicationLanguage": "utf-8",
        "enforcementMode": "blocking",
        "blocking-settings": {
            "violations": [
                {
                    "name": "VIOL_DATA_GUARD",
                    "alarm": true,
                    "block": true
                }
            ]
        },
        "data-guard": {
            "enabled": true,
            "maskData": true,
            "creditCardNumbers": true,
            "usSocialSecurityNumbers": true,
            "enforcementMode": "ignore-urls-in-list",
            "enforcementUrls": []
        }
    }
}
  ```

This is what its corresponding `APPolicy` resource defined in the `spec` would look like:

```yaml
apiVersion: appprotect.f5.com/v1beta1
kind: APPolicy
metadata:
  name: dataguard-blocking
spec:
  policy:
    name: dataguard_blocking
    template:
      name: POLICY_TEMPLATE_NGINX_BASE
    applicationLanguage: utf-8
    enforcementMode: blocking
    blocking-settings:
      violations:
      - name: VIOL_DATA_GUARD
        alarm: true
        block: true
    data-guard:
      enabled: true
      maskData: true
      creditCardNumbers: true
      usSocialSecurityNumbers: true
      enforcementMode: ignore-urls-in-list
      enforcementUrls: []
```

Notice that the fields match in name and nesting: NGINX Ingress Controller will transform the YAML into a valid JSON WAF policy config.

## NGINX App Protect WAF Logs

Configuring

You can set the [NGINX App Protect WAF log configurations](/nginx-app-protect-waf/logging-overview/logs-overview/) by creating an `APLogConf` [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

To add the [log configurations](/nginx-app-protect-waf/logging-overview/security-log/) to a VirtualServer or an Ingress resource:

1. Create an `APLogConf` Custom Resource manifest.
1. Add the log configuration to the `spec` field in the `APLogConf` resource.
1. Add a reference to `APLogConf` in the [VirtualServer Policy resource]({{< relref "configuration/policy-resource.md#waf" >}}) or the [Ingress resource]({{< relref "configuration/ingress-resources/advanced-configuration-with-annotations.md#app-protect" >}}) as per the documentation.

   > **Note**: The fields from the JSON must be presented in the YAML *exactly* the same, in name and level. NGINX Ingress Controller will transform the YAML into a valid JSON WAF log config.

For example, say you want to [log state changing requests](/nginx-app-protect-waf/logging-overview/security-log/#security-log-configuration-file) for your VirtualServer or Ingress resources using NGINX App Protect WAF. The  log configuration looks like this:

```json
{
    "filter": {
        "request_type": "all"
    },
    "content": {
        "format": "default",
        "max_request_size": "any",
        "max_message_size": "5k"
    }
}
```

You would define that config in the `spec` of your `APLogConf` resource as follows:

```yaml
apiVersion: appprotect.f5.com/v1beta1
kind: APLogConf
metadata:
  name: logconf
spec:
  filter:
    request_type: all
  content:
    format: default
    max_request_size: any
    max_message_size: 5k
```

## NGINX App Protect WAF User Defined Signatures

You can define NGINX App Protect WAF [User-Defined Signatures](/nginx-app-protect-waf/configuration-guide/configuration/#user-defined-signatures) for your VirtualServer or Ingress resources by creating an `APUserSig` [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

 > **Note**: The field `revisionDatetime` is not currently supported.

> **Note**: `APUserSig` resources increase the reload time of NGINX Plus compared with `APPolicy` and `APLogConf` resources. Refer to [NGINX Fails to Start or Reload]({{< relref "troubleshooting/troubleshooting-app-protect-waf.md#nginx-fails-to-start-or-reload" >}}) for more information.

To add the [User Defined Signatures](https://docs.nginx.com/nginx-app-protect-waf/configuration-guide/configuration/#user-defined-signatures) to a VirtualServer or Ingress resource:

1. Create an `APUserSig` Custom resource manifest.
2. Add the desired User defined signature to the `spec` field in the `APUserSig` resource.

   > **Note**: The fields from the JSON must be presented in the YAML *exactly* the same, in name and level. The Ingress Controller will transform the YAML into a valid JSON User-Defined signature. There is no need to reference the user defined signature resource in the Policy or Ingress resources.

For example, say you want to create the following user defined signature:

```json
{  "softwareVersion": "15.1.0",
    "tag": "Fruits",
    "signatures": [
      {
      "name": "Apple_medium_acc",
      "rule": "content:\"apple\"; nocase;",
      "signatureType": "request",
      "attackType": {
         "name": "Brute Force Attack"
      },
      "systems": [
         {"name": "Microsoft Windows"},
         {"name": "Unix/Linux"}
                     ],
      "risk": "medium",
      "accuracy": "medium",
      "description": "Medium accuracy user defined signature with tag (Fruits)"
      }
   ]
}
```

You would add that config in the `spec` of your `APUserSig` resource as follows:

```yaml
apiVersion: appprotect.f5.com/v1beta1
kind: APUserSig
metadata:
  name: apple
spec:
  signatures:
  - accuracy: medium
    attackType:
      name: Brute Force Attack
    description: Medium accuracy user defined signature with tag (Fruits)
    name: Apple_medium_acc
    risk: medium
    rule: content:"apple"; nocase;
    signatureType: request
    systems:
    - name: Microsoft Windows
    - name: Unix/Linux
  softwareVersion: 15.1.0
  tag: Fruits
```

## App Protect WAF Bundles

You can define App Protect WAF bundles for VirtualServer custom resources by creating policy bundles and putting them on a mounted volume accessible from NGINX Ingress Controller.

Before applying a policy, a WAF policy bundle must be created, then copied to a volume mounted to `/etc/nginx/waf/bundles`.

{{< note >}} NGINX Ingress Controller does not currently support `securityLogs` for policy bundles. {{< /note >}}

This example show how a policy is configured by referencing a generated WAF Policy Bundle:


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

## OpenAPI Specification in NGINX Ingress Controller

The OpenAPI Specification defines the spec file format needed to describe RESTful APIs. The spec file can be written either in JSON or YAML. Using a spec file simplifies the work of implementing API protection. Refer to the [OpenAPI Specification](https://github.com/OAI/OpenAPI-Specification) (formerly called Swagger) for details.

NGINX Ingress Controller supports OpenAPI Specification versions 2.0 and 3.0.

The simplest way to create an API protection policy is using an OpenAPI Specification file to import the details of the APIs. If you use an OpenAPI Specification file, NGINX App Protect WAF will automatically create a policy for the following properties (depending on what's included in the spec file):

- Methods
- URLs
- Parameters
- JSON profiles

An OpenAPI-ready policy template is provided with the NGINX App Protect WAF packages and is located in: `/etc/app_protect/conf/NginxApiSecurityPolicy.json`

It contains violations related to OpenAPI set to blocking (enforced).

### Types of OpenAPI References

There are different ways of referencing OpenAPI Specification files. The configuration is similar to [External References](/nginx-app-protect-waf/configuration-guide/configuration/#external-references).

**Note**: Any update of an OpenAPI Specification file referenced in the policy will not trigger a policy compilation. This action needs to be done actively by reloading the NGINX configuration.

#### URL Reference

URL reference is the method of referencing an external source by providing its full URL.

Make sure to configure certificates prior to using the HTTPS protocol - see the [External References](/nginx-app-protect-waf/configuration-guide/configuration/#types-of-references) for details.

## Configuration in NGINX Ingress Controller

These are the typical steps to deploy an OpenAPI protection Policy in NGINX Ingress Controller:

1. Copy the API security policy `/etc/app_protect/conf/NginxApiSecurityPolicy.json` to a different file so that it can be edited.
2. Add the reference to the desired OpenAPI file.
3. Make other custom changes if needed (e.g. enable Data Guard protection).
4. Use a tool to convert the result to YAML. There are many, for example: [`yq` utility](https://github.com/mikefarah/yq).
5. Add the YAML properties to create an `APPolicy` Custom Resource putting the policy itself (as in step 4) within the `spec` property of the Custom Resource. Refer to the [NGINX App Protect Policies](#nginx-app-protect-waf-policies) section above.
6. Create a `Policy` object which references the `APPolicy` Custom Resource as in [this example](https://github.com/nginxinc/kubernetes-ingress/blob/v3.3.2/examples/custom-resources/app-protect-waf/waf.yaml).
7. Finally, attach the `Policy` object to a `VirtualServer` resource as in [this example](https://github.com/nginxinc/kubernetes-ingress/blob/v3.3.2/examples/custom-resources/app-protect-waf/virtual-server.yaml).

**Note**:  You need to make sure that the server where the resource files are located is always available when you are compiling your policy.

### Example Configuration

In this example, we are adding an OpenAPI Specification file reference to `/etc/app_protect/conf/NginxApiSecurityPolicy.yaml` using the [link](https://raw.githubusercontent.com/aws-samples/api-gateway-secure-pet-store/master/src/main/resources/swagger.yaml). This will configure allowed data types for `query_int` and `query_str` parameters values.

**Policy configuration:**

```yaml
---
apiVersion: appprotect.f5.com/v1beta1
  kind: APPolicy
  metadata:
    name: petstore_api_security_policy
  spec:
    policy:
      name: petstore_api_security_policy
      description: NGINX App Protect WAF API Security Policy for the Petstore API
      template:
        name: POLICY_TEMPLATE_NGINX_BASE
      open-api-files:
      - link: https://raw.githubusercontent.com/aws-samples/api-gateway-secure-pet-store/master/src/main/resources/swagger.yaml
      blocking-settings:
        violations:
        - block: true
          description: Disallowed file upload content detected in body
          name: VIOL_FILE_UPLOAD_IN_BODY
        - block: true
          description: Mandatory request body is missing
          name: VIOL_MANDATORY_REQUEST_BODY
        - block: true
          description: Illegal parameter location
          name: VIOL_PARAMETER_LOCATION
        - block: true
          description: Mandatory parameter is missing
          name: VIOL_MANDATORY_PARAMETER
        - block: true
          description: JSON data does not comply with JSON schema
          name: VIOL_JSON_SCHEMA
        - block: true
          description: Illegal parameter array value
          name: VIOL_PARAMETER_ARRAY_VALUE
        - block: true
          description: Illegal Base64 value
          name: VIOL_PARAMETER_VALUE_BASE64
        - block: true
          description: Disallowed file upload content detected
          name: VIOL_FILE_UPLOAD
        - block: true
          description: Illegal request content type
          name: VIOL_URL_CONTENT_TYPE
        - block: true
          description: Illegal static parameter value
          name: VIOL_PARAMETER_STATIC_VALUE
        - block: true
          description: Illegal parameter value length
          name: VIOL_PARAMETER_VALUE_LENGTH
        - block: true
          description: Illegal parameter data type
          name: VIOL_PARAMETER_DATA_TYPE
        - block: true
          description: Illegal parameter numeric value
          name: VIOL_PARAMETER_NUMERIC_VALUE
        - block: true
          description: Parameter value does not comply with regular expression
          name: VIOL_PARAMETER_VALUE_REGEXP
        - block: true
          description: Illegal URL
          name: VIOL_URL
        - block: true
          description: Illegal parameter
          name: VIOL_PARAMETER
        - block: true
          description: Illegal empty parameter value
          name: VIOL_PARAMETER_EMPTY_VALUE
        - block: true
          description: Illegal repeated parameter name
          name: VIOL_PARAMETER_REPEATED
```

Content of the referenced file `myapi.yaml`:

```yaml
openapi: 3.0.1
info:
  title: 'Primitive data types'
  description: 'Primitive data types.'
  version: '2.5.0'
servers:
  - url: http://localhost
paths:
  /query:
    get:
      tags:
        - query_int_str
      description: query_int_str
      operationId: query_int_str
      parameters:
        - name: query_int
          in: query
          required: false
          allowEmptyValue: false
          schema:
            type: integer
        - name: query_str
          in: query
          required: false
          allowEmptyValue: true
          schema:
            type: string
      responses:
        200:
          description: OK
        404:
          description: NotFound
```

In this case, the following request will trigger an `Illegal parameter data type` violation, as we expect to have an integer value in the `query_int` parameter:

```
http://localhost/query?query_int=abc
```

The request will be blocked.

The `link` option is also available in the `openApiFileReference` property and is synonymous with the `open-api-files` property as seen in the policy example above.

**Note**: `openApiFileReference` is not an array.

## Configuration in NGINX Plus Ingress Controller using Virtual Server Resource

In this example we deploy NGINX Ingress Controller with NGINX Plus and NGINX App Protect WAF, deploy a simple web application, and then configure load balancing and WAF protection for that application using the VirtualServer resource.

**Note:** You can find the example, and the files referenced, on [GitHub](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/custom-resources/app-protect-waf).

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX Ingress Controller with NGINX Plus and NGINX App Protect WAF.
2. Save the public IP address of NGINX Ingress Controller into a shell variable:

   ```console
    IC_IP=XXX.YYY.ZZZ.III
   ```

3. Save the HTTP port of NGINX Ingress Controller into a shell variable:

   ```console
    IC_HTTP_PORT=<port number>
   ```

### Step 1. Deploy a Web Application

Create the application deployment and service:

  ```console
  kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/webapp.yaml
  ```

### Step 2. Deploy the AP Policy

1. Create the syslog service and pod for the NGINX App Protect WAF security logs:

   ```console
   kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/syslog.yaml
   ```

2. Create the User-Defined Signature, WAF policy, and log configuration:

    ```console
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/ap-apple-uds.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/ap-dataguard-alarm-policy.yaml
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/ap-logconf.yaml
    ```

### Step 3 - Deploy the WAF Policy

Create the WAF policy

 ```console
  kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/waf.yaml
 ```

  Note the NGINX App Protect WAF configuration settings in the Policy resource. They enable WAF protection by configuring NGINX App Protect WAF with the policy and log configuration created in the previous step.

### Step 4 - Configure Load Balancing

1. Create the VirtualServer Resource:

    ```console
    kubectl apply -f https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/virtual-server.yaml
    ```

Note that the VirtualServer references the policy waf-policy created in Step 3.

### Step 5 - Test the Application

To access the application, curl the coffee and the tea services. We'll use the --resolve option to set the Host header of a request with `webapp.example.com`

1. Send a request to the application:

   ```console
    $ curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
    Server address: 10.12.0.18:80
    Server name: webapp-7586895968-r26zn
   ```

2. Now, let's try to send a request with a suspicious URL:

   ```console
    $ curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP "http://webapp.example.com:$IC_HTTP_PORT/<script>"
    <html><head><title>Request Rejected</title></head><body>
   ```

3. Lastly, let's try to send some suspicious data that matches the user defined signature.

    ```console
    $ curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP -X POST -d "apple" http://webapp.example.com:$IC_HTTP_PORT/
    <html><head><title>Request Rejected</title></head><body>
    ```

    As you can see, the suspicious requests were blocked by NGINX App Protect WAF.

4. To check the security logs in the syslog pod:

    ```console
    kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
    ```

### Configuration Example of Virtual Server

Refer to GitHub repo for [Virtual Server example](https://raw.githubusercontent.com/nginxinc/kubernetes-ingress/v3.3.2/examples/custom-resources/app-protect-waf/webapp.yaml).

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
