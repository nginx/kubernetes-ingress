---
docs: DOCS-1467
---

For additional context on managing containers using Kubernetes Deployments, refer to the official Kubernetes [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) documentation.

When you deploy NGINX Ingress Controller as a Deployment, Kubernetes automatically sets up a single NGINX Ingress Controller pod.

- For NGINX, run:

    ```shell
    kubectl apply -f deployments/deployment/nginx-ingress.yaml
    ```

- For NGINX Plus, run:

    ```shell
    kubectl apply -f deployments/deployment/nginx-plus-ingress.yaml
    ```

    Update the `nginx-plus-ingress.yaml` file to include your chosen image from the F5 Container registry or your custom container image.
