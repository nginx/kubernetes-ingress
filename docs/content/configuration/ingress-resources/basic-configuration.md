---
title: Basic Configuration

description: "The example in this document shows a basic Ingress resource definition."
weight: 1600
doctypes: [""]
toc: true
docs: "DOCS-593"
---


The example below shows a basic Ingress resource definition. It load balances requests for two services -- coffee and tea -- comprising a hypothetical *cafe* app hosted at `cafe.example.com`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress
spec:
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /tea
        pathType: Prefix
        backend:
          service:
            name: tea-svc
            port:
              number: 80
      - path: /coffee
        pathType: Prefix
        backend:
          service:
            name: coffee-svc
            port:
              number: 80
```

Here is a breakdown of what this Ingress resource definition means:

- The `metadata.name` field defines the name of the resource `cafe‑ingress`.
- In the `spec.tls` field we set up SSL/TLS termination:
  - In the `secretName`, we reference a secret resource by its name, `cafe‑secret`. The secret must belong to the same namespace as the Ingress, it must be of the type ``kubernetes.io/tls`` and contain keys named ``tls.crt`` and ``tls.key`` that hold the certificate and private key as described [here](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls>). If the secret doesn't exist or is invalid, NGINX will break any attempt to establish a TLS connection to the hosts to which the secret is applied.
  - In the `hosts` field, we apply the certificate and key to our `cafe.example.com` host.
- In the `spec.rules` field, we define a host with domain name `cafe.example.com`.
- In the `paths` field, we define two path‑based rules:
  - The rule with the path `/tea` instructs NGINX to distribute the requests with the `/tea` URI among the pods of the *tea* service, which is deployed with the name `tea‑svc` in the cluster.
  - The rule with the path `/coffee` instructs NGINX to distribute the requests with the `/coffee` URI among the pods of the *coffee* service, which is deployed with the name `coffee‑svc` in the cluster.
  - Both rules instruct NGINX to distribute the requests to `port 80` of the corresponding service (the `servicePort` field).

> For complete instructions on deploying the Ingress and Secret resources in the cluster, see the [complete example](https://github.com/nginxinc/kubernetes-ingress/tree/v3.3.2/examples/ingress-resources/complete-example) in our GitHub repository.

> To learn more about the Ingress resource, see the [Ingress resource documentation](https://kubernetes.io/docs/concepts/services-networking/ingress/) in the Kubernetes docs.

## New Features Available in Kubernetes 1.18 and Above

Starting from Kubernetes 1.18, you can use the following new features:

- The host field supports wildcard domain names, such as `*.example.com`.
- The path supports different matching rules with the new field `pathType`, which takes the following values: `Prefix` for prefix-based matching, `Exact` for exact matching and `ImplementationSpecific`, which is the default type and is the same as `Prefix`. For example:

  ```yaml
    - path: /tea
      pathType: Prefix
      backend:
        serviceName: tea-svc
        servicePort: 80
    - path: /tea/green
      pathType: Exact
      backend:
          service:
            name: tea-svc
            port:
              number: 80
    - path: /coffee
      pathType: ImplementationSpecific
      backend:
          service:
            name: coffee-svc
            port:
              number: 80
  ```

- The `ingressClassName` field is now supported:

  ```yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: cafe-ingress
    spec:
      ingressClassName: nginx
      tls:
      - hosts:
        - cafe.example.com
        secretName: cafe-secret
      rules:
      - host: cafe.example.com
    . . .
  ```

  When using this filed you need to create the `IngressClass` resource with the corresponding `name`. See Step 3 *Create an IngressClass resource* of the [Create Common Resources](/nginx-ingress-controller/installation/installation-with-manifests/#2-create-common-resources) section.

## Restrictions

The NGINX Ingress Controller imposes the following restrictions on Ingress resources:

- When defining an Ingress resource, the `host` field is required.
- The `host` value needs to be unique among all Ingress and VirtualServer resources unless the Ingress resource is a [mergeable minion](/nginx-ingress-controller/configuration/ingress-resources/cross-namespace-configuration/). See also [Handling Host and Listener Collisions](/nginx-ingress-controller/configuration/handling-host-and-listener-collisions).
- The `path` field in `spec.rules[].http.paths[]` is required for `Exact` and `Prefix` `pathTypes`.
- The ImplementationSpecific `pathType` is treated as equivalent to `Prefix` `pathType`, with the exception that when this `pathType` is configured, the `path` field in `spec.rules[].http.paths[]` is not mandatory. `path` defaults to `/` if not set but the `pathType` is set to ImplementationSpecific.

## Advanced Configuration

The Ingress resource only allows you to use basic NGINX features -- host and path-based routing and TLS termination. Advanced features like rewriting the request URI or inserting additional response headers are available through annotations. See the [Advanced Configuration with Annotations](/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations) doc.

The Ingress Controller generates NGINX configuration by executing a template file that contains configuration options. These options are set via the Ingress resource and the Ingress Controller's ConfigMap. Advanced NGINX users who require more control over the generated NGINX configurations can use snippets to insert raw NGINX config. See [Advanced Configuration with Snippets](/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-snippets) for more information. Additionally, it is possible to customize the template. See [Custom Templates](/nginx-ingress-controller/configuration/global-configuration/custom-templates/) for instructions.
