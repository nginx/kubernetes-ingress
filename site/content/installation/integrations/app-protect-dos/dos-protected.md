---
docs: DOCS-581
doctypes:
- ''
title: DoS protected resource specification
toc: true
weight: 300
---

NGINX App Protect DoS protected resource specification

{{< note >}} This feature is only available using the NGINX Plus [NGINX App Protect DoS Module](/nginx-app-protect-dos/deployment-guide/learn-about-deployment/). {{< /note >}}

## DoS Protected resource specification

Below is an example of a DoS protected resource.

```yaml
apiVersion: appprotectdos.f5.com/v1beta1
kind: DosProtectedResource
metadata:
  name: dos-protected
spec:
  enable: true
  name: "my-dos"
  apDosMonitor:
    uri: "webapp.example.com"
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``enable`` | Enables NGINX App Protect DoS, Default value: false. | ``bool`` | No |
|``name`` | Name of the protected object, max of 63 characters. | ``string`` | Yes |
|``dosAccessLogDest`` | The log destination for the access log with dos log format. Accepted variables are ``<ip-address \| localhost \| fqdn>:<port>`` or ``stderr``. | ``string`` | No |
|``apDosMonitor.uri`` | The destination to the desired protected object. [App Protect DoS monitor](#dosprotectedresourceapdosmonitor) Default value: None, URL will be extracted from the first request which arrives and taken from "Host" header or from destination ip+port. | ``string`` | No |
|``apDosMonitor.protocol`` | Determines if the server listens on http1 / http2 / grpc / websocket. [App Protect DoS monitor](#dosprotectedresourceapdosmonitor) Default value: http1. | ``enum`` | No |
|``apDosMonitor.timeout`` | Determines how long (in seconds) should NGINX App Protect DoS wait for a response. [App Protect DoS monitor](#dosprotectedresourceapdosmonitor) Default value: 10 seconds for http1/http2 and 5 seconds for grpc. | ``int64`` | No |
|``apDosPolicy`` | The [App Protect DoS policy](#dosprotectedresourceapdospolicy) of the dos. Accepts an optional namespace. | ``string`` | No |
|``dosSecurityLog.enable`` | Enables security log. | ``bool`` | No |
|``dosSecurityLog.apDosLogConf`` | The [App Protect DoS log conf]({{< relref "installation/integrations/app-protect-dos/configuration.md#app-protect-dos-logs" >}}) resource. Accepts an optional namespace. | ``string`` | No |
|``dosSecurityLog.dosLogDest`` | The log destination for the security log. Accepted variables are ``<ip-address \| localhost \| fqdn>:<port>`` or ``stderr``. Default is ``127.0.0.1:514``. | ``string`` | No |
|``allowList`` | List of allowed IP addresses and subnet masks. Each entry is represented by an `IPWithMask` string. | ``[]AllowListEntry`` | No |
{{% /table %}}

### DosProtectedResource.apDosPolicy

The `apDosPolicy` is a reference (qualified identifier in the format `namespace/name`) to the policy configuration defined as an `ApDosPolicy`.

### DosProtectedResource.apDosMonitor

This is how NGINX App Protect DoS monitors the stress level of the protected object. The monitor requests are sent from localhost (127.0.0.1).

### Invalid DoS Protected resources

NGINX will treat a DoS protected resource as invalid if one of the following conditions is met:

- The DoS protected resource doesn't pass the [comprehensive validation](#comprehensive-validation).
- The DoS protected resource isn't present in the cluster.

### Validation

Two types of validation are available for the DoS protected resource:

- *Structural validation*, done by `kubectl` and the Kubernetes API server.
- *Comprehensive validation*, done by NGINX Ingress Controller.

#### Structural validation

The custom resource definition for the DoS protected resource includes a structural OpenAPI schema, which describes the type of every field of the resource.

If you try to create (or update) a resource that violates the structural schema -- for example, the resource uses a string value instead of a bool in the `enable` field -- `kubectl` and the Kubernetes API server will reject the resource.

- Example of `kubectl` validation:

    ```shell
    kubectl apply -f apdos-protected.yaml
    ```
    ```shell
    error: error validating "examples/app-protect-dos/apdos-protected.yaml": error validating data: ValidationError(DosProtectedResource.spec.enable): invalid type for com.f5.appprotectdos.v1beta1.DosProtectedResource.spec.enable: got "string", expected "boolean"; if you choose to ignore these errors, turn validation off with --validate=false
    ```

- Example of Kubernetes API server validation:

    ```shell
    kubectl apply -f access-control-policy-allow.yaml --validate=false
    ```
    ```shell
    The DosProtectedResource "dos-protected" is invalid: spec.enable: Invalid value: "string": spec.enable in body must be of type boolean: "string"
    ```

If a resource passes structural validation, then NGINX Ingress Controller will start comprehensive validation.

#### Comprehensive validation

NGINX Ingress Controller validates the fields of a DoS protected resource. If a resource is invalid, NGINX Ingress Controller will reject it. The resource will continue to exist in the cluster, but NGINX Ingress Controller will ignore it.

You can use `kubectl` to check if NGINX Ingress Controller successfully applied a DoS protected resource configuration. For our example `dos-protected` DoS protected resource, we can run:

```shell
kubectl describe dosprotectedresource dos-protected
```
```shell
Events:
  Type    Reason          Age                From                      Message
  ----    ------          ----               ----                      -------
  Normal  AddedOrUpdated  12s (x2 over 18h)  nginx-ingress-controller  Configuration for default/dos-protected was added or updated
```

Note how the events section includes a Normal event with the AddedOrUpdated reason that informs us that the configuration was successfully applied.

If you create an invalid resource, NGINX Ingress Controller will reject it and emit a Rejected event. For example, if you create a dos protected resource `dos-protected` with an invalid URI `bad` in the `dosSecurityLog/dosLogDest` field, you will get:

```shell
kubectl describe policy webapp-policy
```
```shell
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  2s    nginx-ingress-controller  error validating DosProtectedResource: dos-protected invalid field: dosSecurityLog/dosLogDest err: invalid log destination: bad, must follow format: <ip-address | localhost | dns name>:<port> or stderr
```

The events section has Warning event with the rejection error in the message.

{{< warning >}} If you invalidate an existing resource, NGINX Ingress Controller will reject it. {{< /warning >}}
