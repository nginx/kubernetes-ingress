# Traffic Splitting

In this example we use the
[VirtualServer](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resource to configure traffic splitting for the cafe application from the [Basic Configuration](../basic-configuration/)
example, for which we have introduced the following changes:

- Instead of one version of the coffee service, we have two: `coffee-v1-svc` and `coffee-v2-svc`. We send 90% of the
  coffee traffic to `coffee-v1-svc` and the remaining 10% to `coffee-v2-svc`.
- To simplify the example, we have removed TLS termination and the tea service.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1 - Deploy the Cafe Application

Create the coffee deployments and services:

```console
kubectl create -f cafe.yaml
```

## Step 2 - Configure Load Balancing

Create the VirtualServer resource:

```console
kubectl create -f cafe-virtual-server.yaml
```

## Step 3 - Test the Configuration

1. Check that the configuration has been successfully applied by inspecting the events of the VirtualServer:

    ```console
    kubectl describe virtualserver cafe
    ```

    ```text
    . . .
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  5s    nginx-ingress-controller  Configuration for default/cafe was added or updated
    ```

1. Access the application using curl. We'll use curl's `--resolve` option to set the IP address and HTTP port of the
   Ingress Controller to the domain name of the cafe application. Try to get coffee multiple times to see how NGINX
   sends requests to different versions of the coffee service:

    ```console
     curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    90% of responses will come from `coffee-v1-svc`:

    ```text
    Server address: 10.16.0.151:80
    Server name: coffee-v1-78754bdcfb-7xp27
    ...
    ```

    10 % of responses will come from `coffee-v2-svc`:

    ```text
    Server address: 10.16.0.152:80
    Server name: coffee-v2-7fd446968b-lwhgcd
    ...
