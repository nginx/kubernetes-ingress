# TLS Passthrough

In this example, we show how to use a TransportServer resource to configure TLS Passthrough load balancing.

With the TLS Passthrough feature, the Ingress Controller accepts TLS connections on port 443 and routes them to the
corresponding backend services without decryption. The routing is done based on the
[SNI](https://en.wikipedia.org/wiki/Server_Name_Indication), which allows clients to specify a server name (like
`example.com`) during the SSL handshake. At the same time, the Ingress Controller continues to handle regular HTTPS
traffic on the same port 443, terminating TLS connections using the TLS certificate and keys, specified through
[Ingress](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/basic-configuration/) or
[VirtualServer](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resources.

We will deploy a backend application (we call it the *secure app*) that exposes port 8443 for TLS traffic. Then we will
configure the Ingress Controller to route connections to the secure app using a TransportServer resource.

## About the Secure App

The secure app is an NGINX pod (not to be confused with the Ingress Controller pod, which also includes NGINX)
configured to serve HTTPS traffic on port 8443 for the host `app.example.com`. For TLS termination, a self-signed TLS
certificate and key are used. The app responds to clients HTTPS requests with a simple text response `hello from pod
<hostname of the pod>`.

You can see how the Secure App is implemented in the `secure-app.yaml` file.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller:
    - As part of Step 2 of those instructions, make sure to deploy the custom resource definition for the
      TransportServer resource.
    - Set the
      [`-enable-custom-resources`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-enable-custom-resources)
      and
      [`-enable-tls-passthrough`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-enable-tls-passthrough)
      command-line arguments of the Ingress Controller to enable the TLS Passthrough feature.
    - If you would like to use any other port than 443 for TLS Passthrough, set
      the [`-tls-passthrough-port`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-tls-passthrough-port)
      command-line argument of the Ingress Controller, and configure the load balancer to forward traffic to that port.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller where TLS Passthrough is enabled into a shell variable:

```console
IC_HTTPS_PORT=<port number>
```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy the Secure App

Create the secure app deployment and service:

```console
kubectl apply -f app-tls-secret.yaml
kubectl apply -f secure-app.yaml
```

## Step 2 - Configure Load Balancing

1. Create the TransportServer resource to configure TLS Passthrough:

    ```console
    kubectl apply -f transport-server-passthrough.yaml
    ```

1. Check that the configuration has been successfully applied by inspecting the events of the TransportServer:

    ```console
    kubectl describe ts secure-app
    ```

    ```text
    . . .
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  9s    nginx-ingress-controller  Configuration for default/secure-app was added or updated
    ```

## Step 3 - Test the Configuration

Now we access the secure app using *curl*. We'll use curl's `--insecure` option to turn off certificate verification of
the app self-signed certificate and `--resolve` option to set the IP address and HTTPS port of the Ingress Controller to
the domain name of the cafe application:

```console
curl --resolve app.example.com:$IC_HTTPS_PORT:$IC_IP https://app.example.com:$IC_HTTPS_PORT --insecure
```

```text
hello from pod secure-app-d986bcf6b-jwm2s
```
