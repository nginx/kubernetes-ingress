# Custom Templates

The Ingress Controller allows you to customize your templates through a
[ConfigMap](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#snippets-and-custom-templates)
via the following keys:

- `main-template` - Sets the main NGINX configuration template.
- `ingress-template` - Sets the Ingress NGINX configuration template for an Ingress resource.
- `virtualserver-template` - Sets the NGINX configuration template for an VirtualServer resource.
- `transportserver-template` - Sets the NGINX configuration template for a TransportServer resource.

## Example

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-config
  namespace: nginx-ingress
data:
  main-template: |
    worker_processes  {{.WorkerProcesses}};
    ...
        include /etc/nginx/conf.d/*.conf;
    }
  ingress-template: |
    {{range $upstream := .Upstreams}}
    upstream {{$upstream.Name}} {
      {{if $upstream.LBMethod }}{{$upstream.LBMethod}};{{end}}
    ...
    }{{end}}
  virtualserver-template: |
    {{ range $u := .Upstreams }}
    upstream {{ $u.Name }} {
      {{ if ne $u.UpstreamZoneSize "0" }}zone {{ $u.Name }} {{ $u.UpstreamZoneSize }};{{ end }}
    ...
    }
    {{ end }}
  transportserver-template: |
    {{- range $u := .Upstreams }}
    upstream {{ $u.Name }} {
        zone {{ $u.Name }} 256k;
    ...
    }
```

**Notes:**

- The templates are truncated for the clarity of the example.
- The templates for NGINX (the main `nginx.tmpl` and the Ingress `nginx.ingress.tmpl`) and NGINX Plus (the main
  `nginx-plus.tmpl` and the Ingress `nginx-plus.ingress.tmpl`) are located at
  [internal/configs/version1](../../../internal/configs/version1/). The VirtualServer templates for NGINX
  (`nginx.virtualserver.tmpl`) and NGINX Plus (`nginx-plus.virtualserver.tmpl`) are located at
  [internal/configs/version2](../../../internal/configs/version2/).

## Troubleshooting

- If a custom template contained within the ConfigMap is invalid on startup, the Ingress Controller will fail to start,
  the error will be reported in the Ingress Controller logs.

    An example of an error from the logs:

    ```text
    Error updating NGINX main template: template: nginxTemplate:98: unexpected EOF
    ```

- If a custom template contained within the ConfigMap is invalid on update, the Ingress Controller will not update the
  NGINX configuration, the error will be reported in the Ingress Controller logs and an event with the error will be
  associated with the ConfigMap.

    An example of an error from the logs:

    ```text
    Error when updating config from ConfigMap: Invalid nginx configuration detected, not reloading
    ```

  An example of an event with an error (you can view events associated with the ConfigMap by running `kubectl describe
  -n nginx-ingress configmap nginx-config`):

    ```text
    Events:
      Type     Reason            Age                From                      Message
      ----     ------            ----               ----                      -------
      Normal   Updated           12s (x2 over 25s)  nginx-ingress-controller  Configuration from nginx-ingress/nginx-config was updated
      Warning  UpdatedWithError  10s                nginx-ingress-controller  Configuration from nginx-ingress/nginx-config was updated, but not applied: Error when parsing the main template: template: nginxTemplate:98: unexpected EOF
      Warning  UpdatedWithError  8s                 nginx-ingress-controller  Configuration from nginx-ingress/nginx-config was updated, but not applied: Error when writing main Config
    ```
