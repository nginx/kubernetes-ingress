# Advanced Routing

In this example we use the
[VirtualServer](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resource to configure advanced routing for the cafe application from the [Basic Configuration](../basic-configuration/)
example, for which we have introduced the following changes:

- Instead of one version of the tea service, we have two: `tea-post-svc` and `tea-svc`. We send POST requests for tea to
  `tea-post-svc` and non-POST requests, such as GET requests, to `tea-svc`.
- Instead of one version of the coffee service, we have two: `coffee-v1-svc` and `coffee-v2-svc`. We send requests that
  include the cookie `version` set to `v2` to `coffee-v2-svc` and all other requests to `coffee-v1-svc`.
- To simplify the example, we have removed TLS termination.

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

Create the coffee and the tea deployments and services:

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
      Normal  AddedOrUpdated  2s    nginx-ingress-controller  Configuration for default/cafe was added or updated
    ```

1. Access the tea service using curl. We'll use curl's `--resolve` option to set the IP address and HTTP port of the
   Ingress Controller to the domain name of the cafe application:

    Send a POST request and confirm that the response comes from `tea-post-svc`:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea -X POST
    ```

    ```text
    Server address: 10.16.1.188:80
    Server name: tea-post-b5dd479b4-6ssmh
    . . .
    ```

    Send a GET request and confirm that the response comes from `tea-svc`:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea
    ```

    ```text
    Server address: 10.16.1.189:80
    Server name: tea-7d57856c44-2hsvr
    . . .
    ```

1. Access the coffee service:

    Send a request with the cookie `version=v2` and confirm that the response comes from `coffee-v2-svc`:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee --cookie "version=v2"
    ```

    ```text
    Server address: 10.16.1.187:80
    Server name: coffee-v2-7fd446968b-vkthp
    . . .
    ```

    Send a request without the cookie and confirm that the response comes from `coffee-v1-svc`:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    ```text
    Server address: 10.16.0.153:80
    Server name: coffee-v1-78754bdcfb-bs9nh
    . . .
    ```
