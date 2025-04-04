# WAF

This example describes how to deploy the NGINX Plus Ingress Controller with [NGINX App
Protect](https://www.nginx.com/products/nginx-app-protect/) and [NGINX Agent](https://docs.nginx.com/nginx-agent/overview/) in order to integrate with [NGINX Management Suite Security Monitoring](https://docs.nginx.com/nginx-management-suite/security/). It involves deploying a simple web application, then configure load balancing and WAF protection for the application using the VirtualServer resource. Afterwards, we configure NGINX App Protect to send logs to the NGINX Agent syslog listener, which is then sent to the Security Monitoring dashboard in NGINX Instance Manager.

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX
   Ingress Controller with NGINX App Protect and NGINX Agent. Configure NGINX Agent to connect to a deployment of NGINX Instance Manager with Security Monitoring, and verify your NGINX Ingress Controller deployment is online in NGINX Instance Manager.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of NGINX Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1. Deploy a web application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 2 - Deploy the AP Policy

1. Create the User Defined Signature, App Protect policy and log configuration:

    ```console
    kubectl apply -f ap-apple-uds.yaml
    kubectl apply -f ap-dataguard-alarm-policy.yaml
    kubectl apply -f ap-logconf.yaml
    ```

Note the log configuration in `ap-logconf.yaml` is a specific format required by NGINX Agent for integration with Security Monitoring.

## Step 3 - Deploy the WAF Policy

1. Create the WAF policy

    ```console
    kubectl apply -f waf.yaml
    ```

Note the App Protect configuration settings in the Policy resource. They enable WAF protection by configuring App
Protect with the policy and log configuration created in the previous step.

## Step 4 - Configure Load Balancing

1. Create the VirtualServer Resource:

    ```console
    kubectl apply -f virtual-server.yaml
    ```

Note that the VirtualServer references the policy `waf-policy` created in Step 3.

## Step 5 - Test the Application

To access the application, **curl`** the coffee and the tea services. Use the --resolve option to set the Host header
of a request with `webapp.example.com`

1. Send a request to the application:

    ```console
    curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: webapp-7586895968-r26zn
    ...
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP "http://webapp.example.com:$IC_HTTP_PORT/<script>"
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

1. Finally, send some suspicious data that matches the user defined signature.

    ```console
    curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP -X POST -d "apple" http://webapp.example.com:$IC_HTTP_PORT/
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    The suspicious requests are demonstrably blocked by App Protect.

1. Access the Security Monitoring dashboard in NGINX Instance Manager to view details for the blocked requests.
