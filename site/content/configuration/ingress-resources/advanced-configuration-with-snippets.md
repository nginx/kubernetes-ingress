---
docs: DOCS-592
doctypes:
- ''
title: Advanced configuration with Snippets
toc: true
weight: 400
---

Snippets allow you to insert raw NGINX config into different contexts of the NGINX configurations that F5 NGINX Ingress Controller generates. 

Snippets are intended for advanced NGINX users who need more control over the generated NGINX configuration, and can be used in cases where Annotations and ConfigMap entries would not apply. 



## Disadvantages of snippets

Snippets are configured [using Annotations]({{< relref "configuration/ingress-resources/advanced-configuration-with-annotations.md#snippets-and-custom-templates" >}}), but are disabled by default due to their complexity. They are also available through the [ConfigMap]({{< relref "/configuration/global-configuration/configmap-resource.md#snippets-and-custom-templates" >}}) resource.

To use snippets, set the [`enable-snippets`]({{< relref "configuration/global-configuration/command-line-arguments.md#cmdoption-enable-snippets" >}}) command-line argument.

Snippets have the following disadvantages:

- *Complexity*. Snippets require you to:
  - Understand NGINX configuration primitives and implement a correct NGINX configuration.
  - Understand how NGINX Ingress Controller generates NGINX configuration so that a snippet doesn't interfere with the other features in the configuration.
- *Decreased robustness*. An incorrect snippet can invalidate NGINX configuration, causing reload failures. Until the snippet is fixed, it will prevent any new configuration updates, including updates for the other Ingress resources.
- *Security implications*. Snippets give access to NGINX configuration primitives, which are not validated by NGINX Ingress Controller. For example, a snippet can configure NGINX to serve the TLS certificates and keys used for TLS termination for Ingress resources.

{{< note >}} If the NGINX configuration includes an invalid snippet, NGINX will continue to operate with the last valid configuration. {{< /note >}} 

## Using snippets

The example below shows how to use snippets to customize the NGINX configuration template using annotations.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-with-snippets
  annotations:
    nginx.org/server-snippets: |
      location / {
          return 302 /coffee;
      }
    nginx.org/location-snippets: |
      add_header my-test-header test-value;
spec:
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

These snippets generate the following NGINX configuration:

{{< note >}} The example is shortened for conciseness. {{< /note >}} 

```nginx
server {
    listen 80;


    location / {
        return 302 /coffee;
    }


    location /coffee {
        proxy_http_version 1.1;


        add_header my-test-header test-value;
        ...
        proxy_pass http://default-cafe-ingress-with-snippets-cafe.example.com-coffee-svc-80;
    }

    location /tea {
        proxy_http_version 1.1;

        add_header my-test-header test-value;
        ...
        proxy_pass http://default-cafe-ingress-with-snippets-cafe.example.com-tea-svc-80;
    }
}
```

## Troubleshooting

If a snippet includes an invalid NGINX configuration, NGINX Ingress Controller will fail to reload NGINX. The error will be reported in NGINX Ingress Controller logs and an event with the error will be associated with the Ingress resource:

An example of an error from the logs:

```text
[emerg] 31#31: unknown directive "badd_header" in /etc/nginx/conf.d/default-cafe-ingress-with-snippets.conf:54
Event(v1.ObjectReference{Kind:"Ingress", Namespace:"default", Name:"cafe-ingress-with-snippets", UID:"f9656dc9-63a6-41dd-a499-525b0e0309bb", APIVersion:"extensions/v1beta1", ResourceVersion:"2322030", FieldPath:""}): type: 'Warning' reason: 'AddedOrUpdatedWithError' Configuration for default/cafe-ingress-with-snippets was added or updated, but not applied: Error reloading NGINX for default/cafe-ingress-with-snippets: nginx reload failed: Command /usr/sbin/nginx -s reload stdout: ""
stderr: "nginx: [emerg] unknown directive \"badd_header\" in /etc/nginx/conf.d/default-cafe-ingress-with-snippets.conf:54\n"
finished with error: exit status 1
```

An example of an event with an error (you can view events associated with the Ingress by running `kubectl describe -n nginx-ingress ingress nginx-ingress`):

```text
Events:
Type     Reason                   Age                From                      Message
----     ------                   ----               ----                      -------
Normal   AddedOrUpdated           52m (x3 over 61m)  nginx-ingress-controller  Configuration for default/cafe-ingress-with-snippets was added or updated
finished with error: exit status 1
Warning  AddedOrUpdatedWithError  54s (x2 over 89s)  nginx-ingress-controller  Configuration for default/cafe-ingress-with-snippets was added or updated, but not applied: Error reloading NGINX for default/cafe-ingress-with-snippets: nginx reload failed: Command /usr/sbin/nginx -s reload stdout: ""
stderr: "nginx: [emerg] unknown directive \"badd_header\" in /etc/nginx/conf.d/default-cafe-ingress-with-snippets.conf:54\n"
finished with error: exit status 1
```

Additionally, to help troubleshoot snippets, a number of Prometheus metrics show the stats about failed reloads – `controller_nginx_last_reload_status` and `controller_nginx_reload_errors_total`.
