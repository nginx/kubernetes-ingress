# Basic, single-namespace VirtualServerRoute Selector

In this example we use the [VirtualServer and
VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resources to configure load balancing for the modified cafe application from the [Basic
Configuration](../basic-configuration/) example. We have put the load balancing configuration as well as the deployments
and services into one default namespace.

- In the default namespace, we create the tea deployment, service, and the corresponding load-balancing configuration.
- In the same namespace, we create the cafe secret with the TLS certificate and key and the load-balancing configuration
  for the cafe application. That configuration references the tea configuration.

## Prerequisites

## Step 1 - Install NGINX Ingress COntroller

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

## Step 2 - Deploy the Cafe Application

1. Create the tea deployment and service in the tea namespace:

    ```console
    kubectl create -f tea.yaml
    ```

1. Create the coffee deployment and service in the default namespace:

    ```console
    kubectl create -f coffee.yaml
    ```

## Step 3 - Configure Load Balancing and TLS Termination

1. Create the VirtualServerRoute resource for tea:

    ```console
    kubectl create -f tea-virtual-server-route.yaml
    ```

1. Create the VirtualServerRoute resource for coffee:

    ```console
    kubectl create -f coffee-virtual-server-route.yaml
    ```

1. Create the secret with the TLS certificate and key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

1. Create the VirtualServer resource for the cafe app:

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

## Step 4 - Test the Configuration

1. Check that the configuration has been successfully applied by inspecting the events of the VirtualServerRoutes and
   VirtualServer:

    ```console
    kubectl describe virtualserverroute tea -n tea
    ```

    ```text
    WIP - add an example
    ```

    ```console
    kubectl describe virtualserverroute coffee
    ```

    ```text
    WIP - add an example
    ```

    ```console
    kubectl describe virtualserver cafe
    ```

    ```text
    WIP - add example
    ```

1. Access the application using curl. We'll use curl's `--insecure` option to turn off certificate verification of our
   self-signed certificate and `--resolve` option to set the IP address and HTTPS port of the Ingress Controller to the
   domain name of the cafe application:

    To get coffee:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Server address: 10.16.1.193:80
    Server name: coffee-7dbb5795f6-mltpf
    ...
    ```

    If your prefer tea:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    Server address: 10.16.0.157:80
    Server name: tea-7d57856c44-674b8
    ...
