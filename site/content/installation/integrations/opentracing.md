---
docs: DOCS-618
doctypes:
- ''
title: OpenTracing (Deprecated in v5.0.0)
toc: true
weight: 500
---
OpenTracing support has been deprecated from v5.0.0 of F5 NGINX Ingress Controller.


Learn how to use OpenTracing with F5 NGINX Ingress Controller.

NGINX Ingress Controller supports [OpenTracing](https://opentracing.io/) with the third-party module [opentracing-contrib/nginx-opentracing](https://github.com/opentracing-contrib/nginx-opentracing).

## Prerequisites

1. Use a NGINX Ingress Controller image that contains OpenTracing.

    - You can find the images that include OpenTracing listed [in the technical specs doc]({{< relref "technical-specifications.md#supported-docker-images" >}}).
    - Alternatively, you follow [Build NGINX Ingress Controller]({{< relref "installation/build-nginx-ingress-controller.md" >}}) using `debian-image` (or `alpine-image`) for NGINX or `debian-image-plus` (or `alpine-image-plus`) for NGINX Plus.
    - [Jaeger](https://github.com/jaegertracing/jaeger-client-cpp), [Zipkin](https://github.com/rnburn/zipkin-cpp-opentracing) and [Datadog](https://github.com/DataDog/dd-opentracing-cpp/) tracers are installed by default.

1. Enable snippets annotations by setting the [`enable-snippets`]({{< relref "configuration/global-configuration/command-line-arguments#cmdoption-enable-snippets" >}}) command-line argument to true.

1. Load the OpenTracing module.

    You need to load the module with the configuration for the chosen tracer using the following ConfigMap keys:

    - `opentracing-tracer`: sets the path to the vendor tracer binary plugin. This is the path you used in the COPY line of step *ii* above.
    - `opentracing-tracer-config`: sets the tracer configuration in JSON format.

    The following example shows how to use these two keys to load the module with Jaeger tracer:

    ```yaml
    opentracing-tracer: "/usr/local/lib/libjaegertracing_plugin.so"
    opentracing-tracer-config: |
            {
                "service_name": "nginx-ingress",
                "propagation_format": "w3c",
                "sampler": {
                    "type": "const",
                    "param": 1
                },
                "reporter": {
                    "localAgentHostPort": "jaeger-agent.default.svc.cluster.local:6831"
                }
            }
    ```

## Enable OpenTracing globally

To enable OpenTracing globally (for all Ingress, VirtualServer and VirtualServerRoute resources), set the `opentracing` ConfigMap key to `True`:

```yaml
opentracing: True
```

## Enable or disable OpenTracing per Ingress resource

You can use annotations to enable or disable OpenTracing for a specific Ingress resource. As mentioned in the prerequisites section, both `opentracing-tracer` and `opentracing-tracer-config` must be configured.

Consider the following two cases:

### OpenTracing is globally disabled

1. To enable OpenTracing for a specific Ingress resource, use the server snippet annotation:

    ```yaml
    nginx.org/server-snippets: |
        opentracing on;
    ```

1. To enable OpenTracing for specific paths:

    - You need to use [Mergeable Ingress resources]({{< relref "configuration/ingress-resources/cross-namespace-configuration" >}})
    - You need to use the location snippets annotation to enable OpenTracing for the paths of a specific Minion Ingress resource:

        ```yaml
        nginx.org/location-snippets: |
            opentracing on;
        ```

### OpenTracing is globally enabled

1. To disable OpenTracing for a specific Ingress resource, use the server snippet annotation:

    ```yaml
    nginx.org/server-snippets: |
        opentracing off;
    ```

1. To disable OpenTracing for specific paths:

    - You need to use [Mergeable Ingress resources]({{< relref "configuration/ingress-resources/cross-namespace-configuration" >}})
    - You need to use the location snippets annotation to disable OpenTracing for the paths of a specific Minion Ingress resource:

        ```yaml
        nginx.org/location-snippets: |
            opentracing off;
        ```

## Customize OpenTracing

You can customize OpenTracing through the supported [OpenTracing module directives](https://github.com/opentracing-contrib/nginx-opentracing/blob/master/doc/Reference.md). Use the location-snippets ConfigMap keys or annotations to insert those directives into the generated NGINX configuration.

For example, to propagate the active span context for upstream requests, you need to set the `opentracing_propagate_context` directive, which you can add to an Ingress resource using the location snippets annotation:

```yaml
nginx.org/location-snippets: |
   opentracing_propagate_context;
```

{{< note >}}The `opentracing_propagate_context` and `opentracing_grpc_propagate_context` directives can be used in `http`, `server` or `location` contexts according to the [module documentation](https://github.com/opentracing-contrib/nginx-opentracing/blob/master/doc/Reference.md#opentracing_propagate_context). However, because of the way the module works and how NGINX Ingress Controller generates the NGINX configuration, it is only possible to use the directive in the `location` context.{{< /note >}}
