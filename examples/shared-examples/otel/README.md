# Learn how to use OpenTelemetry with F5 NGINX Ingress Controller

NGINX Ingress Controller supports [OpenTelemetry](https://opentelemetry.io/) with the NGINX module [ngx_otel_module](https://nginx.org/en/docs/ngx_otel_module.html).

## Prerequisites

1. Use a NGINX Ingress Controller image that contains OpenTelemetry.

    - All NGINX Ingress Controller v5.1 images or later will contain support for `ngx_otel_module`.
    - Alternatively, you follow [Build NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/installation/build-nginx-ingress-controller/) using `debian-image` (or `alpine-image` or `ubi-image`) for NGINX or `debian-image-plus` (or `alpine-image-plus`or `ubi-image-plus`) for NGINX Plus.

1. Enable snippets annotations by setting the [`enable-snippets`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-enable-snippets) command-line argument to true.

1. Load the OpenTelemetry module.

    You need to load the module using the following ConfigMap key:

    - `otel-exporter-endpoint`: sets the endpoint to export your OpenTelemetry traces to.

    The following example shows how to use this to export data to an OpenTelemetry collector running in your cluster:

    ```yaml
    otel-exporter-endpoint: "http://otel-collector.default.svc.cluster.local:4317"
    ```

## Enable OpenTelemetry globally

To enable OpenTelemetry globally (for all Ingress, VirtualServer and VirtualServerRoute resources), set the `otel-trace-in-http` ConfigMap key to `true`:

```yaml
otel-trace-in-http: "true"
```

## Enable or disable OpenTelemetry per Ingress resource

You can use annotations to enable or disable OpenTelemetry for a specific Ingress resource. As mentioned in the prerequisites section, `otel-exporter-endpoint` must be configured.

Consider the following two cases:

### OpenTelemetry is globally disabled

1. To enable OpenTelemetry for a specific Ingress resource, use the server snippet annotation:

    ```yaml
    nginx.org/server-snippets: |
        otel_trace on;
    ```

1. To enable OpenTelemetry for specific paths:

    - You need to use [Mergeable Ingress resources](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/cross-namespace-configuration)
    - You need to use the location snippets annotation to enable OpenTelemetry for the paths of a specific Minion Ingress resource:

        ```yaml
        nginx.org/location-snippets: |
            otel_trace on;
        ```

### OpenTelemetry is globally enabled

1. To disable OpenTelemetry for a specific Ingress resource, use the server snippet annotation:

    ```yaml
    nginx.org/server-snippets: |
        otel_trace off;
    ```

1. To disable OpenTelemetry for specific paths:

    - You need to use [Mergeable Ingress resources](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/cross-namespace-configuration)
    - You need to use the location snippets annotation to disable OpenTelemetry for the paths of a specific Minion Ingress resource:

        ```yaml
        nginx.org/location-snippets: |
            otel_trace off;
        ```

## Customize OpenTelemetry

You can customize OpenTelemetry through the supported [OpenTelemetry module directives](https://nginx.org/en/docs/ngx_otel_module.html). Use the `location-snippets` ConfigMap keys or annotations to insert those directives into the generated NGINX configuration.

> Note: At present, the additional directives in the `otel_exporter` block cannot be modified with snippets.
