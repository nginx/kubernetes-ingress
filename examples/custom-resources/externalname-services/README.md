# Support for Type ExternalName Services

The Ingress Controller supports routing requests to services of the type
[ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname).

An ExternalName service is defined by an external DNS name that is resolved into the IP addresses, typically external to
the cluster. This enables to use the Ingress Controller to route requests to the destinations outside of the cluster.

**Note:** With NGINX Open Source, this feature requires NGINX 1.27.3 or later, which is included in the NGINX Ingress
Controller images.

## Prerequisites

To use ExternalName services, first you need to configure one or more resolvers using the ConfigMap. NGINX will use
those resolvers to resolve DNS names of the services.

For example, the following ConfigMap configures one resolver:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-config
  namespace: nginx-ingress
data:
  resolver-addresses: "10.0.0.10"
```

Additional resolver parameters, including the caching of DNS records, are available. Check the corresponding
[ConfigMap](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/)
section.

## Example

In the following yaml file we define an ExternalName service with the name my-service:

```yaml
kind: Service
apiVersion: v1
metadata:
  name: my-service
spec:
  type: ExternalName
  externalName: my.service.example.com
```

In the following Ingress resource we use my-service:

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: example-vs
spec:
  host: example.com
  upstreams:
  - name: my-service
    service: my-service
    port: 80
  routes:
  - path: /
    action:
      pass: my-service

```

As a result, NGINX will route requests for “example.com” to the IP addresses behind the DNS name
my.service.example.com.
