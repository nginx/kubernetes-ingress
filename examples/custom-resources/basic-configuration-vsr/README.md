# Basic Configuration with VirtualServerRoute

In this example we configure load balancing with TLS termination for a simple web application using the
[VirtualServer and VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resources. The application, called cafe, lets you get either tea via the tea service or coffee via the coffee service.
You indicate your drink preference with the URI of your HTTP request: URIs ending with `/tea` get you tea and URIs
ending with `/coffee` get you coffee.

This example demonstrates both VirtualServerRoute approaches:

- **Standard VirtualServerRoute**: Direct reference by namespace/name (tea route)  
- **RouteSelector approach**: Automatic attachment via label matching (coffee route)

The VirtualServer configuration shows both methods side-by-side for comparison.

## Prerequisites

1. Run `make secrets` command to generate the necessary secrets for the example.

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy the Cafe Application

1. Create the tea deployment and service:

    ```console
    kubectl create -f tea.yaml
    ```

1. Create the coffee deployment and service:

    ```console
    kubectl create -f coffee.yaml
    ```

## Step 2 - Configure Load Balancing and TLS Termination

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

1. Create the VirtualServer resource (demonstrates both approaches):

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

    This VirtualServer shows:
    - **Standard approach**: `/tea` route directly references `tea` VirtualServerRoute by namespace/name  
    - **RouteSelector approach**: `/` route uses `routeSelector` to automatically attach VirtualServerRoutes with `app: coffee` labels which is specified at the `coffee` VirtualServerRoute

## Step 3 - Test the Configuration

1. Check that the configuration has been successfully applied by inspecting the events of the VirtualServerRoutes and
   VirtualServer:

    ```console
    kubectl describe virtualserverroute tea
    ```

    ```text
    . . .
    Events:
      Type     Reason                 Age   From                      Message
      ----     ------                 ----  ----                      -------
      Normal   AddedOrUpdated         1m    nginx-ingress-controller  Configuration for default/tea was added or updated
    ```

    ```console
    kubectl describe virtualserverroute coffee
    ```

    ```text
    . . .
    Events:
      Type     Reason                 Age   From                      Message
      ----     ------                 ----  ----                      -------
      Normal   AddedOrUpdated         1m    nginx-ingress-controller  Configuration for default/coffee was added or updated
    ```

    ```console
    kubectl describe virtualserver cafe
    ```

    ```text
    . . .
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  1m    nginx-ingress-controller  Configuration for default/cafe was added or updated
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
