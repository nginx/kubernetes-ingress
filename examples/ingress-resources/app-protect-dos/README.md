# NGINX App Protect DoS Support

In this example we deploy the NGINX Plus Ingress Controller with [NGINX App Protect
DoS](https://www.nginx.com/products/nginx-app-protect-dos/), a simple web application and then configure load balancing
and DOS protection for that application using the Ingress resource.

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with NGINX App Protect DoS.

2. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

3. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Webapp Application

Create the webapp deployment and service:

```console
kubectl create -f webapp.yaml
```

## 3. Configure Load Balancing

1. Create the syslog services and pod for the App Protect DoS security and access logs:

    ```console
    kubectl create -f syslog.yaml
    kubectl create -f syslog2.yaml
    ```

2. Create a secret with an SSL certificate and a key:

    ```console
    kubectl create -f webapp-secret.yaml
    ```

3. Create the App Protect DoS Protected Resource:

    ```console
    kubectl create -f apdos-protected.yaml
    ```

4. Create the App Protect DoS policy and log configuration:

    ```console
    kubectl create -f apdos-policy.yaml
    kubectl create -f apdos-logconf.yaml
    ```

5. Create an Ingress Resource:

    ```console
    kubectl create -f webapp-ingress.yaml
    ```

    Note the App Protect DoS annotation in the Ingress resource. This enables DOS protection by specifying the DOS
    protected resource configuration that applies to this Ingress.

## 4. Test the Application

1. To access the application, curl the Webapp service. We'll use `curl`'s --insecure option to turn off certificate
verification of our self-signed certificate and the --resolve option to set the Host header of a request with
`webapp.example.com`

    Send a request to the application:

    ```console
    curl --resolve webapp.example.com:$IC_HTTPS_PORT:$IC_IP https://webapp.example.com:$IC_HTTPS_PORT/ --insecure
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    ```

2. To check the security logs in the syslog pod:

    ```console
    kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
    ```

3. To check the access logs in the syslog pod:

 ```console
 kubectl exec -it <SYSLOG_2_POD> -- cat /var/log/messages
 ```
