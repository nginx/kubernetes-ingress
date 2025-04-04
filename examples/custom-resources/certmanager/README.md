# Example

In this example, we deploy [cert-manager](https://cert-manager.io/docs/installation/#default-static-install) and a
[self-signed certificate issuer](https://cert-manager.io/docs/configuration/selfsigned/#bootstrapping-ca-issuers). Then,
we deploy the NGINX or NGINX Plus Ingress Controller, a simple web application and then configure load balancing for
that application using the VirtualServer resource.

## Deploying the Certmanager and the self-signed authority

1. Deploy cert manager and all dependent resources:

    ```console
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml
    ```

2. Deploy a self-signed certificate issuer:

    ```console
    kubectl apply -f self-signed.yaml
    ```

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller.
   - Set the
     [`-enable-custom-resources`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-enable-custom-resources)
     and
     [`-enable-cert-manager`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-enable-cert-manager)
     command-line arguments of the Ingress Controller to enable the cert-manager for Virtual Server resources feature.

2. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

3. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Cafe Application

Create the coffee and the tea deployments and services:

```console
kubectl create -f cafe.yaml
```

## 3. Configure Load Balancing

1. Create a VirtualServer resource:

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

## 4. Test the Application

1. To access the application, curl the coffee and the tea services. We'll use ```curl```'s --insecure option to turn off
certificate verification of our self-signed certificate and the --resolve option to set the Host header of a request
with ```cafe.example.com```

    To get coffee:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    ```

    If your prefer tea:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    Server address: 10.12.0.19:80
    Server name: tea-7cd44fcb4d-xfw2x
    ...
    ```
