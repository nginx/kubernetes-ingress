# Cross-Namespace, VirtualServeRoute Selector Configuration

In this example we use the [VirtualServer and
VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resources attached using `routeSelector` to configure load balancing for the cafe application. We have put the load balancing configuration as well as the deployments
and services into multiple namespaces. Instead of one namespace, we now use three: `tea`, `coffee`, and `cafe`.

- In the tea namespace, we create the tea deployment, service, and the corresponding load-balancing configuration.
- In the coffee namespace, we create the coffee deployment, service, and the corresponding load-balancing configuration.
- In the cafe namespace, we create the cafe secret with the TLS certificate and key and the load-balancing configuration for the cafe application.

The example is similar to the [cross-namespace example](../cross-namespace-configuration/README.md).
We use a combination of VirtualServer with a VirtualServerRoute attached using [`routeSelector`](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#routeselector).

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller with custom resources enabled.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Create Namespaces

Create the required tea, coffee, and cafe namespaces:

```console
kubectl create -f namespaces.yaml
```

## Step 2 - Deploy the Cafe Application

1. Create the tea deployment and service in the tea namespace:

    ```console
    kubectl create -f tea.yaml
    ```

1. Create the coffee deployment and service in the coffee namespace:

    ```console
    kubectl create -f coffee.yaml
    ```

## Step 3 - Configure Load Balancing and TLS Termination

1. Create the secret with the TLS certificate and key in the cafe namespace:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

1. Create the VirtualServerRoute resource for tea in the tea namespace:

    ```console
    kubectl create -f tea-virtual-server-route.yaml
    ```

1. Create the VirtualServerRoute resource for coffee in the coffee namespace:

    ```console
    kubectl create -f coffee-virtual-server-route.yaml
    ```

1. Create the VirtualServer resource for the cafe app in the cafe namespace:

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

## Step 3 - Test the Configuration

1. Check that the configuration has been successfully applied by inspecting the events of the VirtualServer:

    ```console
    kubectl describe virtualserver cafe -n cafe
    ```

    ```text
    . . .
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  7s    nginx-ingress-controller  Configuration for default/cafe was added or updated
    ```

1. Access the application using curl. We'll use curl's `--insecure` option to turn off certificate verification of our
   self-signed certificate and `--resolve` option to set the IP address and HTTPS port of the Ingress Controller to the
   domain name of the cafe application:

    To get coffee:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Server address: 10.16.1.182:80
    Server name: coffee-7dbb5795f6-tnbtq
    ...
    ```

    If your prefer tea:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    Server address: 10.16.0.149:80
    Server name: tea-7d57856c44-zlftd
    ...
