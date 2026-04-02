# WAF

In this example we deploy the NGINX Plus Ingress Controller with [NGINX App
Protect](https://www.nginx.com/products/nginx-app-protect/), a simple web application and then configure load balancing
and WAF protection for that application using an Ingress resource and a Policy resource.

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with NGINX App Protect.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1. Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Deploy the AP Policy

1. Create the syslog service and pod for the App Protect security logs:

    ```console
    kubectl apply -f syslog.yaml
    ```

1. Create the User Defined Signature, App Protect policy and log configuration:

    ```console
    kubectl apply -f ap-apple-uds.yaml
    kubectl apply -f ap-dataguard-alarm-policy.yaml
    kubectl apply -f ap-logconf.yaml
    ```

## Step 3 - Deploy the WAF Policy

1. Create the WAF policy

    ```console
    kubectl apply -f waf-policy.yaml
    ```

Note the App Protect configuration settings in the Policy resource. They enable WAF protection by configuring App
Protect with the policy and log configuration created in the previous step.

## Step 4 - Configure Load Balancing

1. Create the Ingress resource:

    ```console
    kubectl apply -f cafe-ingress.yaml
    ```

Note that the Ingress references the policy `waf-policy` created in Step 3 through the `nginx.com/policies` annotation.

## Step 5 - Test the Application

To access the application, curl the coffee and the tea services. We'll use the --resolve option to set the Host header
of a request with `cafe.example.com`.

1. Send a request to the tea service:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/tea --insecure
    ```

    ```text
    Server address: 10.84.0.15:80
    Server name: tea-86c974779-mddq4
    Date: 25/Mar/2026:16:59:51 +0000
    URI: /tea
    Request ID: ea672c3a314dc88d240ebfa3ae4691a7
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP "http://cafe.example.com:$IC_HTTP_PORT/tea/<script>" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>The requested URL was rejected.
    Please consult with your administrator.<br><br>Your support ID is: 15927712737850083417
    <br><br><a href='javascript:history.back();'>[Go Back]</a></body></html>%
    ```

1. Send suspicious data that matches the user defined signature:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP -X POST -d "apple" http://cafe.example.com:$IC_HTTP_PORT/tea --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>The requested URL was rejected. 
    Please consult with your administrator.<br><br>Your support ID is: 9073217841502734526
    <br><br><a href='javascript:history.back();'>[Go Back]</a></body></html>% 
    ```
