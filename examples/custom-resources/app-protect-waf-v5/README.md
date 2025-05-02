# WAF

In this example we deploy the NGINX Plus Ingress Controller with [NGINX App
Protect WAF version 5](https://www.nginx.com/products/nginx-app-protect/), a simple web application and then configure load balancing
and WAF protection for that application using the VirtualServer resource.

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
kubectl apply -f webapp.yaml
```

## Step 2 - Create and Deploy the WAF Policy Bundle

1. Create a WAF v5 policy bundle (`<your_policy_bundle.tgz>`) and copy the bundle to a volume mounted to `/etc/app_protect/bundles`.

## Step 3 - Create and Deploy the WAF Policy

1. Create the syslog service and pod for the App Protect security logs:

    ```console
    kubectl apply -f syslog.yaml
    ```

1. Create the WAF policy

    ```console
    kubectl apply -f waf.yaml
    ```

## Step 4 - Configure Load Balancing

1. Create the VirtualServer Resource:

    ```console
    kubectl apply -f virtual-server.yaml
    ```

Note that the VirtualServer references the policy `waf-policy` created in Step 3.

## Step 5 - Test the Application

To access the application, curl the coffee and the tea services. We'll use the --resolve option to set the Host header
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

1. Now, let's try to send a request with a suspicious URL:

    ```console
    curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP "http://webapp.example.com:$IC_HTTP_PORT/<script>"
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

1. To check the security logs in the syslog pod:

    Note that this step applies only if the `syslog.yaml` was created (Step 2).

    ```console
    kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
    ```
