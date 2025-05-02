---
docs: DOCS-609
doctypes:
- reference
title: The design of NGINX Ingress Controller
toc: true
weight: 200
---

This document explains how the F5 NGINX Ingress Controller is designed, and how it differs when using NGINX or NGINX Plus.

The intended audience for this information is primarily the two following groups:

- _Operators_ who want to know how the software works and understand how it can fail.
- _Developers_ who want to [contribute](https://github.com/nginx/kubernetes-ingress/blob/main/CONTRIBUTING.md) to the project.

We assume that the reader is familiar with core Kubernetes concepts, such as Pods, Deployments, Services, and Endpoints. For an understanding of how NGINX itself works, you can read the ["Inside NGINX: How We Designed for Performance & Scale"](https://www.nginx.com/blog/inside-nginx-how-we-designed-for-performance-scale/) blog post.

For conciseness in diagrams, NGINX Ingress Controller is often labelled "IC" on this page.

---

## NGINX Ingress Controller at a high level

This figure depicts an example of NGINX Ingress Controller exposing two web applications within a Kubernetes cluster to clients on the internet:

{{<img src="img/ic-high-level.png" alt="">}}

{{<note>}} For simplicity, necessary Kubernetes resources like Deployments and Services aren't shown, which Admin and the users also need to create.{{</note>}}

The figure shows:

- A _Kubernetes cluster_.
- Cluster users _Admin_, _User A_ and _User B_, which use the cluster via the _Kubernetes API_.
- _Clients A_ and _Clients B_, which connect to the _Applications A_ and _B_ deployed by the corresponding users.
- _NGINX Ingress Controller_, deployed in a pod with the namespace _nginx-ingress_ and configured using the _ConfigMap resource_ _nginx-ingress_. A single pod is depicted; at least two pods are typically deployed for redundancy. _NGINX Ingress Controller_ uses the _Kubernetes API_ to get the latest Ingress resources created in the cluster and then configures _NGINX_ according to those resources.
- _Application A_ with two pods deployed in the _namespace A_ by _User A_. To expose the application to its clients (_Clients A_) via the host `a.example.com`, _User A_ creates _Ingress A_.
- _Application B_ with one pod deployed in the _namespace B_ by _User B_. To expose the application to its clients (_Clients B_) via the host `b.example.com`, _User B_ creates _VirtualServer B_.
- _Public Endpoint_, which fronts the _NGINX Ingress Controller_ pod(s). This is typically a standalone TCP load balancer (Cloud, software, or hardware) or a combination of a load balancer with a NodePort service. _Clients A_ and _B_ connect to their applications via the _Public Endpoint_.

The yellow and purple arrows represent connections related to the client traffic, and the black arrows represent access to the Kubernetes API.

---

## The NGINX Ingress Controller pod

The NGINX Ingress Controller pod consists of a single container, which includes the following:

- The _NGINX Ingress Controller process_, which configures NGINX according to Ingress and other resources created in the cluster.
- The _NGINX master process_, which controls NGINX worker processes.
- _NGINX worker processes_, which handle the client traffic and load balance the traffic to the backend applications.

The following is an architectural diagram depicting how those processes interact together and with some external entities:

{{<img src="img/ic-pod.png" alt="">}}

This table describes each connection, starting with its type:

{{< bootstrap-table "table table-bordered table-striped table-responsive" >}}
| # | Protocols | Description |
| --- | --- | --- |
|1|HTTP| _Prometheus_ fetches NGINX Ingress Controller and NGINX metrics with an NGINX Ingress Controller HTTP endpoint (Default `:9113/metrics`). **Note**: *Prometheus* is not required and the endpoint can be turned off. |
|2|HTTPS| _NGINX Ingress Controller_ reads the _Kubernetes API_ for the latest versions of the resources in the cluster and writes to the API to update the handled resources' statuses and emit events.
|3|HTTP| _Kubelet_ checks the _NGINX Ingress Controller_ readiness probe (Default `:8081/nginx-ready`) to consider the _NGINX Ingress Controller_ pod [ready](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-conditions).
|4|File I/O| When _NGINX Ingress Controller_ starts, it reads the _configuration templates_ from the filesystem necessary for configuration generation. The templates are located in the `/` directory of the container and have the `.tmpl` extension
|5|File I/O| _NGINX Ingress Controller_ writes logs to *stdout* and *stderr*, which are collected by the container runtime.
|6|File I/O| _NGINX Ingress Controller_ generates NGINX *configuration* based on the resources created in the cluster (See [NGINX Ingress Controller is a Kubernetes Controller](#nginx-ingress-controller-is-a-kubernetes-controller)) and writes it on the filesystem in the `/etc/nginx` folder. The configuration files have a `.conf` extension.
|7|File I/O| _NGINX Ingress Controller_ writes _TLS certificates_ and _keys_ from any [TLS Secrets](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets) referenced in the Ingress and other resources to the filesystem.
|8|HTTP| _NGINX Ingress Controller_ fetches the [NGINX metrics](https://nginx.org/en/docs/http/ngx_http_stub_status_module.html#stub_status) via the `unix:/var/lib/nginx/nginx-status.sock` UNIX socket and converts it to Prometheus format used in #1.
|9|HTTP| To verify a successful configuration reload, _NGINX Ingress Controller_ ensures at least one _NGINX worker_ has the new configuration. To do that, the *IC* checks a particular endpoint via the `unix:/var/lib/nginx/nginx-config-version.sock` UNIX socket.
|10|N/A|  To start NGINX, NGINX Ingress Controller runs the `nginx` command, which launches the _NGINX master_.
|11|Signal| To reload NGINX, the _NGINX Ingress Controller_ runs the `nginx -s reload` command, which validates the configuration and sends the [reload signal](https://nginx.org/en/docs/control.html) to the *NGINX master*.
|12|Signal| To shutdown NGINX, the _NGINX Ingress Controller_ executes `nginx -s quit` command, which sends the graceful shutdown signal to the *NGINX master*.
|13|File I/O| The _NGINX master_ sends logs to its _stdout_ and _stderr_, which are collected by the container runtime.
|14|File I/O| The _NGINX master_ reads the _TLS cert and keys_ referenced in the configuration when it starts or reloads.
|15|File I/O| The _NGINX master_ reads _configuration files_ when it starts or during a reload.
|16|Signal| The _NGINX master_ controls the [lifecycle of _NGINX workers_](https://nginx.org/en/docs/control.html#reconfiguration) it creates workers with the new configuration and shutdowns workers with the old configuration.
|17|File I/O| An _NGINX worker_ writes logs to its _stdout_ and _stderr_, which are collected by the container runtime.
|18|UDP| An _NGINX worker_ sends the HTTP upstream server response latency logs via the Syslog protocol over the UNIX socket `/var/lib/nginx/nginx-syslog.sock` to _NGINX Ingress Controller_. In turn, _NGINX Ingress Controller_ analyzes and transforms the logs into Prometheus metrics.
|19|HTTP,HTTPS,TCP,UDP| A _client_ sends traffic to and receives traffic from any of the _NGINX workers_ on ports 80 and 443 and any additional ports exposed by the [GlobalConfiguration resource](/nginx-ingress-controller/configuration/global-configuration/globalconfiguration-resource).
|20|HTTP,HTTPS,TCP,UDP| An _NGINX worker_ sends traffic to and receives traffic from the _backends_.
|21|HTTP| _Admin_ can connect to the [NGINX stub_status](http://nginx.org/en/docs/http/ngx_http_stub_status_module.html#stub_status) using port 8080 via an _NGINX worker_. By default, NGINX only allows connections from `localhost`.
{{% /bootstrap-table %}}

---

### Differences with NGINX Plus

The previous diagram depicts NGINX Ingress Controller using NGINX. NGINX Ingress Controller with NGINX Plus has the following differences:

- To configure NGINX Plus, NGINX Ingress Controller uses [configuration reloads](#reloading-nginx) and the [NGINX Plus API](http://nginx.org/en/docs/http/ngx_http_api_module.html#api). This allows NGINX Ingress Controller to dynamically change the upstream servers.
- Instead of the stub status metrics, the extended metrics available from the NGINX Plus API are used.
- In addition to TLS certs and keys, NGINX Ingress Controller writes JWKs from the secrets of the type `nginx.org/jwk`, and NGINX workers read them.

---

## The NGINX Ingress Controller process

This section covers the architecture of the NGINX Ingress Controller process, including:

- How NGINX Ingress Controller processes a new Ingress resource created by a user.
- A summary of how NGINX Ingress Controller works in relation to others Kubernetes Controllers.
- The different components of the IC process.

---

### Processing a new Ingress resource

The following diagram depicts how NGINX Ingress Controller processes a new Ingress resource. The the NGINX master and worker processes are represented as a single rectangle, _NGINX_ for simplicity. VirtualServer and VirtualServerRoute resources are indicated similarly.

{{<img src="img/ic-process.png" alt="">}}

Processing a new Ingress resource involves the following steps: each step corresponds to the arrow on the diagram with the same number:

1. _User_ creates a new Ingress resource.
1. The NGINX Ingress Controller process has a _Cache_ of the resources in the cluster. The _Cache_ includes only the resources NGINX Ingress Controller is concerned with such as Ingresses. The _Cache_ stays in sync with the Kubernetes API by [watching for changes to the resources](https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes).
1. Once the _Cache_ has the new Ingress resource, it notifies the _Control Loop_ about the changed resource.
1. The _Control Loop_ gets the latest version of the Ingress resource from the _Cache_. Since the Ingress resource references other resources, such as TLS Secrets, the _Control loop_ gets the latest versions of those referenced resources as well.
1. The _Control Loop_ generates TLS certificates and keys from the TLS Secrets and writes them to the filesystem.
1. The _Control Loop_ generates and writes the NGINX _configuration files_, which correspond to the Ingress resource, and writes them to the filesystem.
1. The _Control Loop_ reloads _NGINX_ and waits for _NGINX_ to successfully reload. As part of the reload:
    1. _NGINX_ reads the _TLS certs and keys_.
    1. _NGINX_ reads the _configuration files_.
1. The _Control Loop_ emits an event for the Ingress resource and updates its status. If the reload fails, the event includes the error message.

---

### NGINX Ingress Controller is a Kubernetes controller

With the context from the previous sections, we can generalize how NGINX Ingress Controller works:

*NGINX Ingress Controller constantly processes both new resources and changes to the existing resources in the cluster. As a result, the NGINX configuration stays up-to-date with the resources in the cluster.*

NGINX Ingress Controller is an example of a [Kubernetes Controller](https://kubernetes.io/docs/concepts/architecture/controller/): NGINX Ingress Controller runs a control loop that ensures NGINX is configured according to the desired state (Ingresses and other resources).

The desired state is based on the following built-in Kubernetes resources and Custom Resources (CRs):

- Layer 7 Load balancing configuration:
  - Ingresses
  - VirtualServers (CR)
  - VirtualServerRoutes (CR)
- Layer 7 policies:
  - Policies (CR)
- Layer 4 load balancing configuration:
  - TransportServers (CR)
- Service discovery:
  - Services
  - Endpoints
  - Pods
- Secret configuration:
  - Secrets
- Global Configuration:
  - ConfigMap (only one resource)
  - GlobalConfiguration (CR, only one resource)

NGINX Ingress Controller can watch additional Custom Resources, which are less common and not enabled by default:

- [NGINX App Protect resources]({{< relref "installation/integrations/app-protect-dos/configuration" >}}) (APPolicies, APLogConfs, APUserSigs)
- IngressLink resource (only one resource)

---

## NGINX Ingress Controller process components

In this section, we describe the components of the NGINX Ingress Controller process and how they interact, including:

1. How NGINX Ingress Controller watches for resources changes.
1. The main components of the NGINX Ingress Controller _Control Loop_.
1. How those components process a resource change.
1. Additional components that are crucial for processing changes.

NGINX Ingress Controller is written in [Go](https://golang.org/) and relies heavily on the [Go client for Kubernetes](https://github.com/kubernetes/client-go). Where relevant, we include links to the source code on GitHub.

### Resource caches

In an earlier section, [Processing a New Ingress Resource](#processing-a-new-ingress-resource), we mentioned that NGINX Ingress Controller has a cache of the resources in the cluster that stays in sync with the Kubernetes API by watching them for changes.

We also mentioned that once the cache is updated, it notifies the control loop about the changed resources. The cache is actually a collection of *informers*. The following diagram shows how changes to resources are processed by NGINX Ingress Controller.

{{<img src="img/ic-process-components.png" alt="">}}

- For every resource type that NGINX Ingress Controller monitors, it creates an [_Informer_](https://pkg.go.dev/k8s.io/client-go@v0.21.0/tools/cache#SharedInformer). The _Informer_ includes a _Store_ that holds the resources of that type. To keep the _Store_ in sync with the latest versions of the resources in the cluster, the _Informer_ calls the Watch and List _Kubernetes APIs_ for that resource type (see the arrow _1. Watch and List_ on the diagram).
- When a change happens in the cluster (for example, a new resource is created), the _Informer_ updates its _Store_ and invokes [_Handlers_](https://pkg.go.dev/k8s.io/client-go@v0.21.0/tools/cache#ResourceEventHandler) (See the arrow _2. Invoke_) for that _Informer_.
- NGINX Ingress Controller registers _Handlers_ for every _Informer_. Most of the time, a _Handler_ creates an entry for the affected resource in the _Workqueue_ where a workqueue element includes the type of the resource and its namespace and name (See the arrow _3. Put_).
- The _Workqueue_ always tries to drain itself: if there is an element at the front, the queue will remove the element and send it to the _Controller_ by calling a callback function (See the arrow _4. Send_).
- The _Controller_ is the primary component of NGINX Ingress Controller, which represents the _Control Loop_, explained in [The Control Loop](#the-control-loop) section. To process a workqueue element, the _Controller_ component gets the latest version of the resource from the _Store_ (See the arrow _5. Get_), reconfigures _NGINX_ according to the resource (See the arrow _6. Reconfigure*_, updates the resource status, and emits an event via the _Kubernetes API_ (See the arrow  _7. Update status and emit event_).

---

### The control loop

This section discusses the main components of NGINX Ingress Controller, which comprise the control loop:

- [Controller](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/k8s/controller.go#L90)
  - Runs the NGINX Ingress Controller control loop.
  - Instantiates _Informers_, _Handlers_, the _Workqueue_ and additional helper components.
  - Includes the sync method), which is called by the _Workqueue_ to process a changed resource.
  - Passes changed resources to _Configurator_ to re-configure NGINX.
- [Configurator](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/configs/configurator.go#L95)
  - Generates NGINX configuration files, TLS and cert keys, and JWKs based on the Kubernetes resource.
  - Uses _Manager_ to write the generated files and reload NGINX.
- [Manager](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/nginx/manager.go#L52)
  - Controls the lifecycle of NGINX (starting, reloading, quitting). See [Reloading NGINX](#reloading-nginx) for more details about reloading.
  - Manages the configuration files, TLS keys and certs, and JWKs.

The following diagram shows how the three components interact:

{{<img src="img/control-loop.png" alt="">}}

---

#### The Controller sync method

The Controller [sync](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/k8s/controller.go#L663) method is called by the _Workqueue_ to process a change of a resource. The method determines the _kind_ of the resource and calls the appropriate _sync_ method (Such as _syncIngress_ for Ingress resources).

To explain how the sync methods work, we will examine the most important one: the _syncIngress_ method, and describe how it processes a new Ingress resource.

{{<img src="img/controller-sync.png" alt="">}}

1. The _Workqueue_ calls the _sync_ method and passes a workqueue element to it that includes the changed resource _kind_ and _key_ (The key is the resource namespace/name such as “default/cafe-ingress”).
1. Using the _kind_, the _sync_ method calls the appropriate sync method and passes the resource key. For Ingress resources, the method is _syncIngress_.
1. _syncIngress_ gets the Ingress resource from the *Ingress Store* using the key. The _Store_ is controlled by the _Ingress Informer_. In the code, we use the helper _storeToIngressLister_ type that wraps the _Store_.
1. _syncIngress_ calls _AddOrUpdateIngress_ of the _Configuration_, passing the Ingress along. The [Configuration](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/k8s/configuration.go#L320) is a component that represents a valid collection of load balancing configuration resources (Ingresses, VirtualServers, VirtualServerRoutes, TransportServers), ready to be converted to the NGINX configuration (see the [Configuration section](#configuration) for more details). _AddOrUpdateIngress_ returns a list of [ResourceChanges](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/k8s/configuration.go#L59), which must be reflected in the NGINX config. Typically, for a new Ingress resource, the _Configuration_ returns only a single _ResourceChange_.
1. _syncIngress_ calls _processChanges_, which processes the single Ingress _ResourceChange_.
    1. _processChanges_ creates an extended Ingress resource (_IngressEx_) that includes the original Ingress resource and its dependencies, such as Endpoints and Secrets, to generate the NGINX configuration. For simplicity, we don’t show this step on the diagram.
    1. _processChanges_ calls _AddOrUpdateIngress_ of the _Configurator_ and passes the extended Ingress resource.
1. _Configurator_ generates an NGINX configuration file based on the extended Ingress resource, then:
    1. Calls _Manager’s CreateConfig()_ to  update the config for the Ingress resource.
    1. Calls _Manager’s Reload()_ to reload NGINX.
1. The reload status is propagated from _Manager_ to _processChanges_, and is either a success or a failure with an error message.
1. _processChanges_ calls _updateRegularIngressStatusAndEvent_ to update the status of the Ingress resource and emit an event with the status of the reload: both make an API call to the Kubernetes API.

**Additional notes**:

- Many details are not included for conciseness: the source code provides the most granular detail.
- The _syncVirtualServer_, _syncVirtualServerRoute_, and _syncTransportServer_ methods are similar to _syncIngress_, while other sync methods are different. However, those methods typically find the affected Ingress, VirtualServer, and TransportServer resources and regenerate the configuration for them.
- The _Workqueue_ has only a single worker thread that calls the sync method synchronously, meaning the _Control Loop_ processes only one change at a time.

---

#### Helper components

There are two additional helper components crucial for processing changes: _Configuration_ and _LocalSecretStore_.

---

##### Configuration

[_Configuration_](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/k8s/configuration.go#L320) holds the latest valid state of the NGINX Ingress Controller load balancing configuration resources: Ingresses, VirtualServers, VirtualServerRoutes, TransportServers, and GlobalConfiguration.

The _Configuration_ supports add, update and delete operations on the resources. When you invoke these operations on a resource in the Configuration, it performs the following:

1. Validates the object (For add or update)
1. Calculates the changes to the affected resources that are necessary to propagate to the NGINX configuration, returning the changes to the caller.

For example, when you add a new Ingress resource, the _Configuration_ returns a change requiring NGINX Ingress Controller to add the configuration for that Ingress to the NGINX configuration files. If you made an existing Ingress resource invalid, the _Configuration_ returns a change requiring NGINX Ingress Controller to remove the configuration for that Ingress from the NGINX configuration files.

Additionally, the _Configuration_ ensures that only one Ingress/VirtualServer/TransportServer (TLS Passthrough) resource holds a particular host (For example, cafe.example.com) and only one TransportServer (TCP/UDP) holds a particular listener (Such as port 53 for UDP). This ensures that no host or listener collisions happen in the NGINX configuration.

Ultimately, NGINX Ingress Controller ensures the NGINX config on the filesystem reflects the state of the objects in the _Configuration_ at any point in time.

---

##### LocalSecretStore

[_LocalSecretStore_](https://github.com/nginx/kubernetes-ingress/blob/v1.11.0/internal/k8s/secrets/store.go#L32) (of the _SecretStore_ interface) holds the valid Secret resources and keeps the corresponding files on the filesystem in sync with them. Secrets are used to hold TLS certificates and keys (type `kubernetes.io/tls`), CAs (`nginx.org/ca`), JWKs (`nginx.org/jwk`), and client secrets for an OIDC provider (`nginx.org/oidc`).

When _Controller_ processes a change to a configuration resource like Ingress, it creates an extended version of a resource that includes the dependencies (Such as Secrets) necessary to generate the NGINX configuration. _LocalSecretStore_ allows _Controller_ to reference the filesystem for a secret using the secret key (namespace/name).

---

## Reloading NGINX

The following sections describe how NGINX reloads and how NGINX Ingress Controller specifically affects this process.

---

### How NGINX reloads work

Reloading NGINX is necessary to apply new configuration changes and occurs with these steps:

1. The administrator sends a HUP (hangup) signal to the NGINX master process to trigger a reload.
1. The master process brings down the worker processes with the old configuration and starts worker processes with the new configuration.
1. The administrator verifies the reload has successfully finished.

The [NGINX documentation](https://nginx.org/en/docs/control.html#reconfiguration) has more details about reloading.

---

#### How to reload NGINX and confirm success

The NGINX binary (`nginx`) supports the reload operation with the `-s reload` option. When you run this option:

1. It validates the new NGINX configuration and exits if it is invalid printing the error messages to the stderr.
1. It sends a HUP signal to the NGINX master process and exits.

As an alternative, you can send a HUP signal to the NGINX master process directly.

Once the reload operation has been invoked with `nginx -s reload`, there is no wait period for NGINX to finish reloading. This means it is the responsibility of an administator to check it is finished, for which there are a few options:

- Check if the master process created new worker processes. Two ways are by running `ps` or reading the `/proc` file system.
- Send an HTTP request to NGINX, to see if a new worker process responds. This signifies that NGINX reloaded successfully: this method requires additional NGINX configuration, explained below.

NGINX reloads take roughly 200ms. The factors affecting reload time are configuration size and details, the number of TLS certificates/keys, enabled modules, and available CPU resources.

---

#### Potential problems

Most of the time, if `nginx -s reload` executes, the reload will also succeed. In the rare case a reload fails, the NGINX master process will print the an error message. This is an example:

```shell
2022/07/09 00:56:42 [emerg] 1353#1353: limit_req "one" uses the "$remote_addr" key while previously it used the "$binary_remote_addr" key
```

The operation is graceful; reloading doesn't lead to any traffic loss by NGINX. However, frequent reloads can lead to high memory utilization and potential OOM (Out-Of-Memory) errors, resulting in traffic loss. This can most likely happen if you (1) proxy traffic that utilizes long-lived connections (ex: Websockets, gRPC) and (2) reload frequently. In these scenarios, you can end up with multiple generations of NGINX worker processes that are shutting down which will force old workers to shut down after the timeout). Eventually, all those worker processes can exhaust the system's available memory.

Old NGINX workers will not shut down until all connections are terminated either by clients or backends, unless you configure [worker_shutdown_timeout](https://nginx.org/en/docs/ngx_core_module.html#worker_shutdown_timeout). Since both the old and new NGINX worker processes coexist during a reload, reloading can lead to two spikes in memory utilization. With a lack of available memory, the NGINX master process can fail to create new worker processes.

---

### Reloading in NGINX Ingress Controller

NGINX Ingress Controller reloads NGINX to apply configuration changes.

To facilitate reloading, NGINX Ingress Controller configures a server listening on the Unix socket `unix:/var/lib/nginx/nginx-config-version.sock` that responds with the configuration version for `/configVersion` URI. NGINX Ingress Controller writes the configuration to  `/etc/nginx/config-version.conf`.

Reloads occur with this sequence of steps:

1. NGINX Ingress Controller updates generated configuration files, including any secrets.
1. NGINX Ingress Controller updates the config version in `/etc/nginx/config-version.conf`.
1. NGINX Ingress Controller runs `nginx -s reload`. If the command fails, NGINX Ingress Controller logs the error and considers the reload failed.
1. If the command succeeds, NGINX Ingress Controller periodically checks for the config version by sending an HTTP request to the config version server on  `unix:/var/lib/nginx/nginx-config-version.sock`.
1. Once NGINX Ingress Controller sees the correct config version returned by NGINX, it considers the reload successful. If it doesn't see the correct configuration version after the configurable timeout ( [`-nginx-reload-timeout`]({{<relref "configuration/global-configuration/command-line-arguments">}})), NGINX Ingress Controller considers the reload failed.

The [NGINX Ingress Controller Control Loop](#the-control-loop) stops during a reload so that it cannot affect configuration files or reload NGINX until the current reload succeeds or fails.

---

### When NGINX Ingress Controller reloads NGINX

NGINX Ingress Controller reloads NGINX every time the Control Loop processes a change that affects the generated NGINX configuration. In general, every time a monitored resource is changed, NGINX Ingress Controller will regenerate the configuration and reload NGINX.

There are three special cases:

- *Start*. When NGINX Ingress Controller starts, it processes all resources in the cluster and only then reloads NGINX. This avoids a "reload storm" by reloading only once.
- *Batch updates*. When NGINX Ingress Controller receives a number of concurrent requests from the Kubernetes API, it will pause NGINX reloads until the task queue is empty. This reduces the number of reloads to minimize the impact of batch updates and reduce the risk of OOM (Out of Memory) errors.
- *NGINX Plus*. If NGINX Ingress Controller is using NGINX Plus, it will not reload NGINX Plus for changes to the Endpoints resources. In this case, NGINX Ingress Controller will use the NGINX Plus API to update the corresponding upstreams and skip reloading.
