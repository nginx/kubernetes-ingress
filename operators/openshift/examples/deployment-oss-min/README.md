# Example

In this example we deploy the NGINX Ingress Controller (edge) as a [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) using the NGINX Ingress Operator for NGINX Open Source.

## Prerequisites

Have the NGINX Ingress Operator deployed in your cluster. Follow [installation](../../README.md#installation) steps.
If you would like to use TransportServers, refer to [this section](README.md#TransportServers) for additional pre-requisites.

## Running the example

1. Create a new namespace for our Ingress Controller instance:

    ```shell
    kubectl create -f ns.yaml
    ```

2. Create a new NginxIngressController resource that defines our NGINX Ingress Controller instance (**Note**: If using OpenShift, change the `image.tag` to `edge-ubi`):

    ```shell
    kubectl create -f nginx-ingress-controller.yaml
    ```

This will deploy an NGINX Ingress Controller instance using a [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) in the `my-nginx-controller` namespace.

1. Check if all resources were deployed:

    ```shell
    kubectl -n my-nginx-ingress  get all
    ```

    ```terminaloutput
    NAME                                               READY   STATUS    RESTARTS   AGE
    pod/my-nginx-ingress-controller-666854fb5f-f67fs   1/1     Running   0          3s

    NAME                                  TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
    service/my-nginx-ingress-controller   NodePort   10.103.105.52   <none>        80:30298/TCP,443:32576/TCP   3s

    NAME                                          READY   UP-TO-DATE   AVAILABLE   AGE
    deployment.apps/my-nginx-ingress-controller   1/1     1            1           4s

    NAME                                                     DESIRED   CURRENT   READY   AGE
    replicaset.apps/my-nginx-ingress-controller-666854fb5f   1         1         1       4s
    ```

For more information about how to configure the NGINX Ingress Controller, check the official [documentation](https://docs.nginx.com/nginx-ingress-controller/overview/).

## Remove

1. Delete the NginxIngressController:

    ```shell
    kubectl delete -f nginx-ingress-controller.yaml
    ```

1. Delete the namespace:

    ```shell
    kubectl delete namespace my-nginx-ingress
    ```

## TransportServers

TransportServers provide support for TCP/UDP but are in active development and provided as a preview feature.
A GlobalConfiguration resource is used to specify the TCP/UDP listeners and is required by TransportServers.
To use TransportServers, you must create a GlobalConfiguration resource *after* creating the namespace and *before* starting the Operator.

```text
Step 1. namespace
Step 2. global configuration <--- in this order
Step 3. ingress controller
...
```

```shell
kubectl apply -f global-configuration.yaml
```

Then update the NginxIngressController to use the GlobalConfiguration by adding the following config to `nginx-ingress-controller.yaml`

```yaml
   globalConfiguration: my-nginx-ingress/nginx-configuration
```

For more information, check the official [documentation](https://docs.nginx.com/nginx-ingress-controller/configuration/transportserver-resource/).
