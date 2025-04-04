# NGINX App Protect Support

In this example we deploy the NGINX Plus Ingress Controller with [NGINX App
Protect](https://www.nginx.com/products/nginx-app-protect/), a simple web application and then configure load balancing
and WAF protection for that application using the Ingress resource.

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with NGINX App Protect.

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

1. Create the syslog service and pod for the App Protect security logs:

    ```console
    kubectl create -f syslog.yaml
    ```

2. Create a secret with an SSL certificate and a key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

3. Create the App Protect policy, log configuration and user defined signature:

    ```console
    kubectl create -f ap-dataguard-alarm-policy.yaml
    kubectl create -f ap-logconf.yaml
    kubectl create -f ap-apple-uds.yaml
    ```

4. Create an Ingress Resource:

    ```console
    kubectl create -f cafe-ingress.yaml
    ```

    Note the App Protect annotations in the Ingress resource. They enable WAF protection by configuring App Protect with
    the policy and log configuration created in the previous step.

## 4. Test the Application

1. To access the application, curl the coffee and the tea services. We'll use `curl`'s --insecure option to turn off
certificate verification of our self-signed certificate and the --resolve option to set the Host header of a request
with `cafe.example.com`

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

    Now, let's try to send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP "https://cafe.example.com:$IC_HTTPS_PORT/tea/<script>" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    Lastly, let's try to send some suspicious data that matches the user defined signature.

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -X POST -d "apple" "https://cafe.example.com:$IC_HTTPS_PORT/tea/" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    As you can see, the suspicious requests were blocked by App Protect

1. To check the security logs in the syslog pod:

    ```console
    kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
    ```
