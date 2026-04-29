# NGINX Security Monitoring

This example describes how to deploy NGINX Plus Ingress Controller with [NGINX App
Protect](https://www.nginx.com/products/nginx-app-protect/) and [NGINX Agent](https://docs.nginx.com/nginx-agent/overview/) in order to integrate with NGINX Security Monitoring. It involves deploying a simple web application, then configuring load balancing and WAF protection for the application using the Ingress resource. We then configure logging for NGINX App Protect to send logs to the NGINX Agent syslog listener, which is sent to the Security Monitoring dashboard.

This example works with both:

- **NGINX Instance Manager** (Agent 2.*) - See the [Security Monitoring tutorial](https://docs.nginx.com/nginx-ingress-controller/tutorials/security-monitoring/) for agent configuration.
- **NGINX One Console** (Agent 3.9.*) - See the [Connect NGINX Ingress Controller to NGINX One Console](https://docs.nginx.com/nginx-one-console/k8s/add-nic/) guide for agent configuration.

> **Note**: Starting with NGINX Ingress Controller 5.5.0, images with the `-agent` suffix include NGINX Agent 3.9.*and are pre-configured for NGINX One Console. Images without the `-agent` suffix include NGINX Agent 2.* for NGINX Instance Manager. See the [Technical Specifications](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/) for available image variants.

## Running the example

## 1. Deploy NGINX Ingress Controller

1. Run `make secrets` command to generate the necessary secrets for the example.

2. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX
   Ingress Controller with NGINX App Protect and NGINX Agent. Configure NGINX Agent to connect to either a deployment of NGINX Instance Manager with Security Monitoring, or to NGINX One Console, and verify your NGINX Ingress Controller deployment is online.

3. Confirm which version of NGINX Agent is running in your Ingress Controller pod:

    ```console
    kubectl exec -it <nginx-ingress-pod> -c nginx-ingress -- nginx-agent -v
    ```

    The output will show either `2.x.x` or `3.x.x`. Use this to choose the correct log configuration in step 3 below.

    - **Agent 2.***: connects to NGINX Instance Manager
    - **Agent 3.9.***: connects to NGINX One Console

4. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

5. Save the HTTPS port of NGINX Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Cafe application

Create the coffee and the tea deployments and services:

```console
kubectl create -f cafe.yaml
```

## 3. Configure load balancing

1. Create a secret with an SSL certificate and a key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

2. Create the App Protect policy and user defined signature:

    ```console
    kubectl create -f ap-dataguard-alarm-policy.yaml
    kubectl create -f ap-apple-uds.yaml
    ```

    Apply the log configuration that matches your agent version:

    **Agent 2.* (NGINX Instance Manager)**:

    ```console
    kubectl create -f ap-logconf.yaml
    ```

    **Agent 3.9.* (NGINX One Console)**:

    ```console
    kubectl create -f ap-logconf-agent-v3.yaml
    ```

    Two log configurations are provided because the two agent versions require different formats:

    - **Agent 2.***: comma-separated `user-defined` format parsed by the `nap_monitoring` extension.
    - **Agent 3.9.***: the `secops-dashboard-log` format with exactly 28 pipe-separated (`|`) fields in a specific order. NGINX Agent 3.9's embedded OpenTelemetry `securityviolationsfilter` processor validates the first received log record against this schema. If the wrong format is used, the processor closes its gate permanently and drops all events until the agent is restarted.

3. Create an Ingress Resource:

    ```console
    kubectl create -f cafe-ingress.yaml
    ```

    Note the App Protect annotations in the Ingress resource. They enable WAF protection by configuring App Protect with
    the policy and log configuration created in the previous step.

## 4. Test the application

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

    If get tea:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    Server address: 10.12.0.19:80
    Server name: tea-7cd44fcb4d-xfw2x
    ...
    ```

    Send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP "https://cafe.example.com:$IC_HTTPS_PORT/tea/<script>" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    Finally, send some suspicious data that matches the user defined signature.

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP -X POST -d "apple" "https://cafe.example.com:$IC_HTTPS_PORT/tea/" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    The suspicious requests were demonstrably blocked by App Protect.

1. Access the Security Monitoring dashboard in NGINX Instance Manager or NGINX One Console to view details for the blocked requests.
