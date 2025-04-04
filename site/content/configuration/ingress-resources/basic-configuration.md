---
title: Basic configuration
weight: 100
toc: true
type: reference
product: NIC
docs: DOCS-593
---

This document shows a basic Ingress resource definition for F5 NGINX Ingress Controller. It load balances requests for two services as part of a single application.

{{< ghcode `https://raw.githubusercontent.com/nginx/kubernetes-ingress/refs/heads/main/examples/ingress-resources/complete-example/cafe-ingress.yaml`>}}

Here is a breakdown of what this Ingress resource definition means:

- The `metadata.name` field defines the name of the resource `cafe‑ingress`.
- The `spec.tls` field sets up SSL/TLS termination:
  - The `hosts` field applies the certificate and key to the `cafe.example.com` host.
  - The `secretName` references a secret resource by its name, `cafe‑secret`. The secret must belong to the same namespace as the Ingress, of the type ``kubernetes.io/tls`` and contain keys named ``tls.crt`` and ``tls.key`` that hold the certificate and private key as described [here](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls>). If the secret doesn't exist or is invalid, NGINX will break any attempt to establish a TLS connection to the hosts to which the secret is applied.
- The `spec.rules` field defines a host with the domain name `cafe.example.com`.
- The `paths` field defines two path‑based rules:
  - The rule with the path `/tea` instructs NGINX to distribute the requests with the `/tea` URI among the pods of the *tea* service, which is deployed with the name `tea‑svc` in the cluster.
  - The rule with the path `/coffee` instructs NGINX to distribute the requests with the `/coffee` URI among the pods of the *coffee* service, which is deployed with the name `coffee‑svc` in the cluster.
  - Both rules instruct NGINX to distribute the requests to `port 80` of the corresponding service (the `servicePort` field).

To learn more about the Ingress resource, view [the official Kubernetes documentation for Ingress resources](https://kubernetes.io/docs/concepts/services-networking/ingress/).

{{< note >}} For complete instructions on deploying Ingress and Secret resources in the cluster, see the [complete example](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/ingress-resources/complete-example) in the GitHub repository. {{< /note >}}

---

## New features available in Kubernetes 1.18

Starting from Kubernetes 1.18, you can use the following new features:

- The host field supports wildcard domain names, such as `*.example.com`.
- The path supports different matching rules with the new field `pathType`, which takes the following values: `Prefix` for prefix-based matching, `Exact` for exact matching and `ImplementationSpecific`, which is the default type and is the same as `Prefix`. For example:

  ```yaml {hl_lines=[2, 7, 14]}
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

  ```yaml {hl_lines=[6]}
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

  When using this field you need to create the `IngressClass` resource with the corresponding `name`. View the [Create common resources]({{< relref "installation/installing-nic/installation-with-manifests.md#create-common-resources" >}}) section of the Installation with Manifests topic for more information.

---

## Restrictions

NGINX Ingress Controller imposes the following restrictions on Ingress resources:

- When defining an Ingress resource, the `host` field is required.
- The `host` value needs to be unique among all Ingress and VirtualServer resources unless the Ingress resource is a [mergeable minion]({{< relref "configuration/ingress-resources/cross-namespace-configuration.md" >}}). View the [Host and Listener collisions]({{< relref "configuration/host-and-listener-collisions.md" >}}) topic for more information.
- The `path` field in `spec.rules[].http.paths[]` is required for `Exact` and `Prefix` `pathTypes`.
- The ImplementationSpecific `pathType` is treated as equivalent to `Prefix` `pathType`, with the exception that when this `pathType` is configured, the `path` field in `spec.rules[].http.paths[]` is not mandatory. `path` defaults to `/` if not set but the `pathType` is set to ImplementationSpecific.

---

## Advanced configuration

NGINX Ingress Controller generates NGINX configuration by executing a template file that contains the configuration options. 

These options are set with the Ingress resource and NGINX Ingress Controller's ConfigMap.  

The Ingress resource only allows you to use basic NGINX features: host and path-based routing and TLS termination.

For advanced configuration, you have two options:

- [Annotations]({{< ref "/configuration/ingress-resources/advanced-configuration-with-annotations.md" >}}) can be used to rewrite request URIs or inserting additional response headers.
- [Snippets]({{< ref "/configuration/ingress-resources/advanced-configuration-with-snippets" >}}) can be used to insert raw NGINX configuration, changing generated files.

Additionally, it is possible to customize the template, described in the [Custom templates]({{< relref "/configuration/global-configuration/custom-templates.md" >}}) topic.
