# WAF

In this example we deploy the NGINX Plus Ingress Controller with [NGINX App
Protect WAF version 5](https://www.nginx.com/products/nginx-app-protect/), a simple web application and then configure load balancing
and WAF protection for that application using an Ingress resource with the `nginx.com/policies` annotation.

Before applying a policy and security log configuration, a WAF v5 policy and logconf bundle must be created, then copied to a volume mounted to `/etc/app_protect/bundles`.

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy the
   Ingress Controller with NGINX App Protect version 5.

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

## Step 2 - Create and Deploy the WAF Policy Bundle

1. Create a WAF v5 and logconf bundle then copy it to a volume mounted to `/etc/app_protect/bundles`.

## Step 3 - Create and Deploy the WAF Policy

1. Create the WAF policy:

    ```console
    kubectl apply -f waf.yaml
    ```

Note that this Policy enables WAF by referencing the `compiled_policy.tgz` bundle.

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
    Server address: 10.84.0.19:80
    Server name: tea-86c974779-wcjmw
    Date: 25/Mar/2026:17:25:11 +0000
    URI: /tea
    Request ID: a71dbc6ada4e1be2a974726ca78
    

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP "http://cafe.example.com:$IC_HTTP_PORT/tea/<script>" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>The requested URL was rejected.
    Please consult with your administrator.<br><br>Your support ID is: 14768892540526094947
    <br><br><a href='javascript:history.back();'>[Go Back]</a></body></html>%
    ```
