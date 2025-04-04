# Example

In this example we deploy NGINX or NGINX Plus Ingress Controller, a simple web application and then configure load
balancing for that application using the Ingress resource with rate-limiting configures via annotaions.

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installing-nic/installation-with-manifests/)
   instructions to deploy the Ingress Controller.

2. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

3. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Cafe Application

1. Create the coffee and the tea deployments and services:

    ```console
    kubectl create -f cafe.yaml
    ```

## 3. Configure Load Balancing

1. Create a secret with an SSL certificate and a key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

2. Create an Ingress resource:

    ```console
    kubectl create -f cafe-ingress.yaml
    ```

## 4. Test the Application

1. Let's test the configuration. If you access the application at a rate that exceeds one request per second, NGINX will
    start rejecting your requests:

    To get coffee:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    ```

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    <html>
    <head><title>429 Too Many Requests</title></head>
    <body>
    <center><h1>429 Too Many Requests</h1></center>
    </body>
    </html>
    ```
