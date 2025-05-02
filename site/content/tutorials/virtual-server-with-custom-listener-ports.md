---
docs: DOCS-1452
doctypes:
- concept
title: Configuring VirtualServer with custom HTTP and HTTPS listener ports
toc: true
weight: 1800
---

This tutorial outlines how to configure and deploy a VirtualServer resource with custom HTTP and HTTPS listener ports.

## Configuring a VirtualServer with custom HTTP and HTTPS listener ports.

VirtualServer can explicitly define custom HTTP and HTTPS listener ports using the `spec.listener.http` and `spec.listener.https` fields.
Each field must reference a valid listener defined by in a [GlobalConfiguration]({{< relref "/configuration/global-configuration/globalconfiguration-resource.md" >}}) resource.

## Deploy GlobalConfiguration

1. Create a yaml file called `nginx-configuration.yaml` with the below content:
```yaml
apiVersion: k8s.nginx.org/v1
kind: GlobalConfiguration
metadata:
  name: nginx-configuration
  namespace: nginx-ingress
spec:
  listeners:
  - name: http-8083
    port: 8083
    protocol: HTTP
  - name: https-8443
    port: 8443
    protocol: HTTP
    ssl: true
```

2. Deploy `nginx-configuration.yaml` file:
```shell
kubectl apply -f nginx-configuration.yaml
```

## Deploying NGINX Ingress Controller with GlobalConfiguration resource

{{<tabs name="deploy-config-resource">}}

{{%tab name="Using Helm"%}}

1. Add the below arguments to the `values.yaml` file in `controller.globalConfiguration`:
    ```yaml
    spec:
      listeners:
      - name: http-8083
        port: 8083
        protocol: HTTP
      - name: https-8443
        port: 8443
        protocol: HTTP
        ssl: true
    ```

1. Follow the [Installation with Helm]({{< relref "/installation/installing-nic/installation-with-helm.md" >}}) instructions to deploy the NGINX Ingress Controller with custom resources enabled.

1. Ensure your NodePort or LoadBalancer service is configured to expose the custom listener ports. This is set in the `customPorts` section under `controller.service.customPorts`:

    ```yaml
    customPorts:
      - name: http-8083
        port: 8083
        protocol: TCP
        targetPort: 8083
      - name: https-8443
        port: 8443
        protocol: TCP
        targetPort: 8443
    ```

{{%/tab%}}

{{%tab name="Using Manifests"%}}

1. Add the below argument to the manifest file of NGINX Ingress Controller:

    ```yaml
    args:
      - -$(POD_NAMESPACE)/nginx-configuration
    ```

2. Follow the [Installation with Manifests]({{< relref "/installation/installing-nic/installation-with-manifests.md" >}}) instructions to deploy NGINX Ingress Controller with custom resources enabled.

3. Ensure your NodePort or LoadBalancer service is configured to expose the custom listener ports. Below is an example yaml configuration using NodePort, which would also apply to a LoadBalancer service:

    ```yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: nginx-ingress
      namespace: nginx-ingress
    spec:
      type: NodePort
      ports:
      - port: 8083
        targetPort: 8083 # Custom HTTP listener port
        protocol: TCP
        name: http-8083
      - port: 8443
        targetPort: 8443 # Custom HTTPS listener port
        protocol: TCP
        name: https-8443
      selector:
        app: nginx-ingress
    ```

{{%/tab%}}

{{</tabs>}}

## Deploying VirtualServer with custom listeners
Deploy the [custom listeners](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/custom-listeners) resources from the repository examples. It includes all required resources, including VirtualServer.

Below is a snippet of the VirtualServer resource that will be deployed:

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: cafe
spec:
  listener:
    http: http-8083
    https: https-8443
  host: cafe.example.com
  tls:
    secret: cafe-secret
  upstreams:
    ...
```

Below is a snippet of the NGINX configuration for this VirtualServer.

```nginx
server {
    listen 8083;
    listen [::]:8083;

    server_name cafe.example.com;

    set $resource_type "virtualserver";
    set $resource_name "cafe";
    set $resource_namespace "default";

    listen 8443 ssl;
    listen [::]:8443 ssl;

    ssl_certificate /etc/nginx/secrets/default-cafe-secret;
    ssl_certificate_key /etc/nginx/secrets/default-cafe-secret;
}
```

## Testing custom listener ports

You can test that the VirtualServer resource is deployed with non-default port configuration by explicitly defining them when sending requests.

`curl` using port `8443`:

```shell
curl -k https://cafe.example.com:8443/coffee

Server address: 10.32.0.40:8080
Server name: coffee-7dd75bc79b-qmhmv
...
URI: /coffee
...
```

`curl` using port `8083`:

```shell
curl -k http://cafe.example.com:8083/coffee

Server address: 10.32.0.40:8080
Server name: coffee-7dd75bc79b-qmhmv
...
URI: /coffee
...
```
