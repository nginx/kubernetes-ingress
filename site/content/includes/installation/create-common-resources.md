---
docs: DOCS-1464
---

In this section, you'll create resources that most NGINX Ingress Controller installations require:

1. (Optional) Create a secret for the default NGINX server's TLS certificate and key. Complete this step only if you're using the [default server TLS secret]({{< relref "configuration/global-configuration/command-line-arguments#cmdoption-default-server-tls-secret.md" >}}) command-line argument. If you're not, feel free to skip this step.

    By default, the server returns a _404 Not Found_ page for all requests when no ingress rules are set up. Although we provide a self-signed certificate and key for testing purposes, we recommend using your own certificate.

    ```shell
    kubectl apply -f examples/shared-examples/default-server-secret/default-server-secret.yaml
    ```

2. Create a ConfigMap to customize your NGINX settings:

    ```shell
    kubectl apply -f deployments/common/nginx-config.yaml
    ```

3. Create an `IngressClass` resource. NGINX Ingress Controller won't start without an `IngressClass` resource.

    ```shell
    kubectl apply -f deployments/common/ingress-class.yaml
    ```

    If you want to make this NGINX Ingress Controller instance your cluster's default, uncomment the `ingressclass.kubernetes.io/is-default-class` annotation. This action will auto-assign `IngressClass` to new ingresses that don't specify an `ingressClassName`.
