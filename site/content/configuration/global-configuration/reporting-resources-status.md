---
docs: DOCS-589
doctypes:
- ''
title: Reporting resource status
toc: true
weight: 600
---

This page describes how to view the status of resources managed by F5 NGINX Ingress Controller.

## Ingress resources

An Ingress resource status includes the address (an IP address or a DNS name), through which the hosts of that Ingress resource are publicly accessible.

You can see the address in the output of the `kubectl get ingress` command, in the ADDRESS column, as shown below:

```shell
kubectl get ingresses
```
```text
NAME           HOSTS              ADDRESS           PORTS     AGE
cafe-ingress   cafe.example.com   12.13.23.123      80, 443   2m
```

NGINX Ingress Controller must be configured to report an Ingress status:

1. Use the command-line flag `-report-ingress-status`.
1. Define a source for an external address. This can be either of:
    1. A user defined address, specified in the `external-status-address` ConfigMap key.
    1. A Service of the type LoadBalancer configured with an external IP or address and specified by the `-external-service` command-line flag.

View the [ConfigMap keys](/nginx-ingress-controller/configuration/global-configuration/configmap-resource) and [Command-line arguments](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments) topics for more information.

{{< note >}} NGINX Ingress Controller does not clear the status of Ingress resources when it is being shut down. {{< /note >}}

## VirtualServer and VirtualServerRoute resources

A VirtualServer or VirtualServerRoute resource includes the status field with information about the state of the resource and the IP address, through which the hosts of that resource are publicly accessible.

You can see the status in the output of the `kubectl get virtualservers` or `kubectl get virtualserverroutes` commands as shown below:

```shell
kubectl get virtualservers
```
```text
  NAME   STATE   HOST                   IP            PORTS      AGE
  cafe   Valid   cafe.example.com       12.13.23.123  [80,443]   34s
```

To see an external hostname address associated with a VirtualServer resource, use the `-o wide` option:

```shell
kubectl get virtualservers -o wide
```
```text
  NAME   STATE   HOST               IP    EXTERNALHOSTNAME                                                         PORTS      AGE
  cafe   Valid   cafe.example.com         ae430f41a1a0042908655abcdefghijkl-12345678.eu-west-2.elb.amazonaws.com   [80,443]   106s
```

{{< note >}} If there are multiple addresses, only the first one is shown. {{< /note >}}

In order to see additional addresses or extra information about the `Status` of the resource, use the following command:

```shell
kubectl describe virtualserver <NAME>
```
```text
...
Status:
  External Endpoints:
    Ip:        12.13.23.123
    Ports:     [80,443]
  Message:  Configuration for cafe/cafe was added or updated
  Reason:   AddedOrUpdated
  State:    Valid
```

### Status specification

The following fields are reported in both VirtualServer and VirtualServerRoute status:

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type |
| ---| ---| --- |
|*State* | Current state of the resource. Can be ``Valid``, ``Warning`` an ``Invalid``. For more information, refer to the ``message`` field. | *string* |
|*Reason* | The reason of the last update. | *string* |
|*Message* | Additional information about the state. | *string* |
|*ExternalEndpoints* | A list of external endpoints for which the hosts of the resource are publicly accessible. | *[externalEndpoint](#externalendpoint)* |
{{</bootstrap-table>}}

The *ReferencedBy* field is reported for the VirtualServerRoute status only:

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type |
| ---| ---| --- |
| *ReferencedBy* | The VirtualServer that references this VirtualServerRoute. Format as ``namespace/name`` | *string* |
{{</bootstrap-table>}}

### externalEndpoint

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type |
| ---| ---| --- |
|``IP`` | The external IP address. | ``string`` |
|``Hostname`` | The external LoadBalancer Hostname address. | ``string`` |
|``Ports`` | A list of external ports. | ``string`` |
{{</bootstrap-table>}}

NGINX Ingress Controller must be configured to report a VirtualServer or VirtualServerRoute status:

1. If you want NGINX Ingress Controller to report the `externalEndpoints`, define a source for an external address (The rest of the fields will be reported without the external address configured). This can be:
    1. A user defined address, specified in the `external-status-address` ConfigMap key.
    1. A Service of the type LoadBalancer configured with an external IP or address and specified by the `-external-service` command-line flag.

View the [ConfigMap keys](/nginx-ingress-controller/configuration/global-configuration/configmap-resource) and [Command-line arguments](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments) topics for more information.

{{< note >}} NGINX Ingress Controller does not clear the status of VirtualServer and VirtualServerRoute resources when it is being shut down. {{< /note >}}

## Policy resources

A Policy resource includes the status field with information about the state of the resource.

You can see the status in the output of the `kubectl get policy` command as shown below:

```shell
kubectl get policy
```
```text
  NAME              STATE   AGE
  webapp-policy     Valid   30s
```

In order to see additional addresses or extra information about the `Status` of the resource, use the following command:

```shell
kubectl describe policy <NAME>
```
```text
...
Status:
  Message:  Configuration for default/webapp-policy was added or updated
  Reason:   AddedOrUpdated
  State:    Valid
```

### Status specification

The following fields are reported in Policy status:

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type |
| ---| ---| --- |
|``State`` | Current state of the resource. Can be ``Valid`` or ``Invalid``. For more information, refer to the ``message`` field. | ``string`` |
|``Reason`` | The reason of the last update. | ``string`` |
|``Message`` | Additional information about the state. | ``string`` |
{{</bootstrap-table>}}

## TransportServer resources

A TransportServer resource includes the status field with information about the state of the resource.

You can see the status in the output of the `kubectl get transportserver` command as shown below:

```shell
kubectl get transportserver
```
```text
  NAME      STATE   REASON           AGE
  dns-tcp   Valid   AddedOrUpdated   47m
```

To see additional addresses or extra information about the `Status` of the resource, use the following command:

```shell
kubectl describe transportserver <NAME>
```
```text
Status:
  Message:  Configuration for default/dns-tcp was added or updated
  Reason:   AddedOrUpdated
  State:    Valid
```

### Status specification

The following fields are reported in TransportServer status:

{{<bootstrap-table "table table-striped table-bordered table-responsive">}}
|Field | Description | Type |
| ---| ---| --- |
| *State* | Current state of the resource. Can be ``Valid``, ``Warning`` or ``Invalid``. For more information, refer to the ``message`` field. | *string* |
| *Reason* | The reason of the last update. | *string* |
| *Message* | Additional information about the state. | *string* |
{{</bootstrap-table>}}
