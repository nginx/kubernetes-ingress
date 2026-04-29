# WAF

This example describes how to deploy the NGINX Plus Ingress Controller with [NGINX App
Protect](https://www.nginx.com/products/nginx-app-protect/) and [NGINX Agent](https://docs.nginx.com/nginx-agent/overview/) in order to integrate with NGINX Security Monitoring. It involves deploying a simple web application, then configure load balancing and WAF protection for the application using the VirtualServer resource. Afterwards, we configure NGINX App Protect to send logs to the NGINX Agent syslog listener, which is then sent to the Security Monitoring dashboard.

This example works with both:

- **NGINX Instance Manager** (Agent 2.*) - See the [Security Monitoring tutorial](https://docs.nginx.com/nginx-ingress-controller/tutorials/security-monitoring/) for agent configuration.
- **NGINX One Console** (Agent 3.9.*) - See the [Connect NGINX Ingress Controller to NGINX One Console](https://docs.nginx.com/nginx-one-console/k8s/add-nic/) guide for agent configuration.

> **Note**: Starting with NGINX Ingress Controller 5.5.0, images with the `-agent` suffix include NGINX Agent 3.9.*and are pre-configured for NGINX One Console. Images without the `-agent` suffix include NGINX Agent 2.* for NGINX Instance Manager. See the [Technical Specifications](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/) for available image variants.

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX
   Ingress Controller with NGINX App Protect and NGINX Agent. Configure NGINX Agent to connect to either a deployment of NGINX Instance Manager with Security Monitoring, or to NGINX One Console, and verify your NGINX Ingress Controller deployment is online.

1. Confirm which version of NGINX Agent is running in your Ingress Controller pod:

    ```console
    kubectl exec -it <nginx-ingress-pod> -c nginx-ingress -- nginx-agent -v
    ```

    The output will show either `2.x.x` or `3.x.x`. Use this to choose the correct log configuration in Step 2 below.

    - **Agent 2.***: connects to NGINX Instance Manager
    - **Agent 3.9.***: connects to NGINX One Console

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

1. Create the User Defined Signature and App Protect policy:

    ```console
    kubectl apply -f ap-apple-uds.yaml
    kubectl apply -f ap-dataguard-alarm-policy.yaml
    ```

1. Apply the log configuration that matches your agent version:

    **Agent 2.* (NGINX Instance Manager)**:

    ```console
    kubectl apply -f ap-logconf.yaml
    ```

    **Agent 3.9.* (NGINX One Console)**:

    ```console
    kubectl apply -f ap-logconf-agent-v3.yaml
    ```

    Two log configurations are provided because the two agent versions require different formats:

    - **Agent 2.***: comma-separated `user-defined` format parsed by the `nap_monitoring` extension.
    - **Agent 3.9.***: the `secops-dashboard-log` format with exactly 28 pipe-separated (`|`) fields in a specific order. NGINX Agent 3.9's embedded OpenTelemetry `securityviolationsfilter` processor validates the first received log record against this schema. If the wrong format is used, the processor closes its gate permanently and drops all events until the agent is restarted.

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
of a request with`webapp.example.com`

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

1. Access the Security Monitoring dashboard in NGINX Instance Manager or NGINX One Console to view details for the blocked requests.
