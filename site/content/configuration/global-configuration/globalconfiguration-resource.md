---
docs: DOCS-588
doctypes:
- ''
title: GlobalConfiguration resource
toc: true
weight: 200
---

This page explains how to use the GlobalConfiguration resource to define the global configuration parameters of F5 NGINX Ingress Controller.

The resource supports configuring listeners for TCP and UDP load balancing, and is implemented as a [Custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

Listeners are required by [TransportServer resources]({{< relref "/configuration/transportserver-resource.md" >}}) and can be used to [configure custom listeners for VirtualServers]({{< relref "tutorials/virtual-server-with-custom-listener-ports.md" >}}).

---

## Prerequisites

When [installing NGINX Ingress Controller using Manifests]({{< relref "/installation/installing-nic/installation-with-manifests.md" >}}), you need to reference a GlobalConfiguration resource in the [`-global-configuration`](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments#cmdoption-global-configuration) command-line argument. NGINX Ingress Controller only needs one GlobalConfiguration resource.

---

## GlobalConfiguration specification

The GlobalConfiguration resource defines the global configuration parameters of the Ingress Controller. Below is an example:

```yaml
apiVersion: k8s.nginx.org/v1
kind: GlobalConfiguration
metadata:
  name: nginx-configuration
  namespace: nginx-ingress
spec:
  listeners:
  - name: dns-udp
    port: 5353
    protocol: UDP
  - name: dns-tcp
    port: 5353
    protocol: TCP
  - name: http-8083
    port: 8083
    protocol: HTTP
  - name: https-8443
    port: 8443
    protocol: HTTP
    ssl: true
```

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
| *listeners* | A list of listeners. | [listener](#listener) | No |
{{</bootstrap-table>}}

### Listener

The `listeners:` key defines a listener (a combination of a protocol and a port) that NGINX will use to accept traffic for a [TransportServer]({{< relref "/configuration/transportserver-resource.md" >}})  and a [VirtualServer]({{< relref "/configuration/virtualserver-and-virtualserverroute-resources.md" >}}):

```yaml
- name: dns-tcp
  port: 5353
  protocol: TCP
- name: http-8083
  port: 8083
  protocol: HTTP
```

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
| *name* | The name of the listener. Must be a valid DNS label as defined in RFC 1035. For example, ``hello`` and ``listener-123`` are valid. The name must be unique among all listeners. The name ``tls-passthrough`` is reserved for the built-in TLS Passthrough listener and cannot be used. | *string* | Yes |
| *port* | The port of the listener. The port must fall into the range ``1..65535`` with the following exceptions: ``80``, ``443``, the [status port](/nginx-ingress-controller/logging-and-monitoring/status-page), the [Prometheus metrics port](/nginx-ingress-controller/logging-and-monitoring/prometheus). Among all listeners, only a single combination of a port-protocol is allowed. | *int* | Yes |
| *protocol* | The protocol of the listener. Supported values: ``TCP``, ``UDP`` and ``HTTP``. | *string* | Yes |
| *ssl* | Configures the listener with SSL. This is currently only supported for ``HTTP`` listeners. Default value is ``false`` | *bool* | No |
| *ipv4* | Specifies the IPv4 address to listen on. | *string* | No |
| *ipv6* | Specifies the IPv6 address to listen on. | *string* | No |

{{</bootstrap-table>}}

---

## Using GlobalConfiguration

You can use the usual `kubectl` commands to work with a GlobalConfiguration resource.

For example, the following command creates a GlobalConfiguration resource defined in `global-configuration.yaml` with the name `nginx-configuration`:

```shell
kubectl apply -f global-configuration.yaml
```
```shell
globalconfiguration.k8s.nginx.org/nginx-configuration created
```

Assuming the namespace of the resource is `nginx-ingress`, you can get the resource by running:

```shell
kubectl get globalconfiguration nginx-configuration -n nginx-ingress
```
```shell
NAME                  AGE
nginx-configuration   13s
```

With `kubectl get` and similar commands, you can use the short name `gc` instead of `globalconfiguration`.

---

### Validation

Two types of validation are available for the GlobalConfiguration resource:

- *Structural validation* by `kubectl` and Kubernetes API server.
- *Comprehensive validation* by NGINX Ingress Controller.


#### Structural validation

The custom resource definition for the GlobalConfiguration includes structural OpenAPI schema which describes the type of every field of the resource.

If you try to create (or update) a resource that violates the structural schema (for example, you use a string value for the port field of a listener), `kubectl` and Kubernetes API server will reject such a resource:

- Example of `kubectl` validation:

    ```shell
    kubectl apply -f global-configuration.yaml
    ```
    ```text
    error: error validating "global-configuration.yaml": error validating data: ValidationError(GlobalConfiguration.spec.listeners[0].port): invalid type for org.nginx.k8s.v1.GlobalConfiguration.spec.listeners.port: got "string", expected "integer"; if you choose to ignore these errors, turn validation off with --validate=false
    ```

- Example of Kubernetes API server validation:

    ```shell
    kubectl apply -f global-configuration.yaml --validate=false
    ```
    ```text
    The GlobalConfiguration "nginx-configuration" is invalid: []: Invalid value: map[string]interface {}{ ... }: validation failure list:
    spec.listeners.port in body must be of type integer: "string"
    ```

If a resource is not rejected (it doesn't violate the structural schema), NGINX Ingress Controller will validate it further.

#### Comprehensive validation

NGINX Ingress Controller validates the fields of a GlobalConfiguration resource. If a GlobalConfiguration resource is partially invalid, NGINX Ingress Controller use the valid listeners and emit events about invalid listeners.

You can check if the Ingress Controller successfully applied the configuration for a GlobalConfiguration. For our  `nginx-configuration` GlobalConfiguration, we can run:

```shell
kubectl describe gc nginx-configuration -n nginx-ingress
```
```text
...
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Normal   Updated   11s   nginx-ingress-controller  GlobalConfiguration nginx-ingress/nginx-configuration was updated
```

The events section includes a Normal event with the Updated reason that informs us that the configuration was successfully applied.

If you create a GlobalConfiguration `nginx-configuration` with two or more listeners that have the same protocol UDP and port 53, you will get:

```shell
kubectl describe gc nginx-configuration -n nginx-ingress
```
```text
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Normal   Updated   55s   nginx-ingress-controller  GlobalConfiguration nginx-ingress/nginx-configuration was updated
  Warning  AddedOrUpdatedWithError  6s    nginx-ingress-controller  GlobalConfiguration nginx-ingress/nginx-configuration is invalid and was rejected: spec.listeners: Duplicate value: "Duplicated port/protocol combination 53/UDP"
```

The events section includes a Warning event with the AddedOrUpdatedWithError reason.


## Using IPV4 and IPV6 Addresses with GlobalConfiguration

You can customize the IPv4 and IPv6 Address listeners in the global configuration and apply them to your VirtualServer resources. See the corresponding example [here](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/custom-ip-listeners/virtualserver/)
