# NGINX Security Monitoring with F5 WAF for NGINX v5

This example describes how to deploy NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and [NGINX Agent](https://docs.nginx.com/nginx-agent/overview/) to integrate with NGINX Security Monitoring. It deploys a simple web application, configures WAF protection using compiled policy and log bundles, and forwards security logs to the Security Monitoring dashboard via syslog.

This example works with both:

- **NGINX Instance Manager** (Agent 2.*) - See the [Security Monitoring tutorial](https://docs.nginx.com/nginx-ingress-controller/tutorials/security-monitoring/) for agent configuration.
- **NGINX One Console** (Agent 3.9.*) - See the [Connect NGINX Ingress Controller to NGINX One Console](https://docs.nginx.com/nginx-one-console/k8s/add-nic/) guide for agent configuration.

> **Note**: Starting with NGINX Ingress Controller 5.5.0, images with the `-agent` suffix include NGINX Agent 3.9.*and are pre-configured for NGINX One Console. Images without the `-agent` suffix include NGINX Agent 2.* for NGINX Instance Manager. See the [Technical Specifications](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/) for available image variants.

## Running the example

## 1. Deploy NGINX Ingress Controller

1. Run `make secrets` to generate the necessary secrets for the example.

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX
   Ingress Controller with F5 WAF for NGINX v5 and NGINX Agent. Configure NGINX Agent to connect to either a deployment of NGINX Instance Manager with Security Monitoring, or to NGINX One Console, and verify that your NGINX Ingress Controller deployment is online.

1. Confirm which version of NGINX Agent is running in your Ingress Controller pod:

    ```console
    kubectl exec -it <nginx-ingress-pod> -c nginx-ingress -- nginx-agent -v
    ```

    The output will show either `2.x.x` or `3.x.x`. Use this to choose the correct WAF policy in step 4 below.

    - **Agent 2.***: connects to NGINX Instance Manager
    - **Agent 3.9.***: connects to NGINX One Console

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of NGINX Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Cafe Application

Create the coffee and tea deployments and services:

```console
kubectl apply -f cafe.yaml
```

## 3. Create and Deploy the WAF Policy and Log Bundles

1. Compile your WAF policy JSON into a policy bundle (`compiled_policy.tgz`) and a log configuration bundle (`compiled_log.tgz`) using the `waf-compiler` image:

    ```console
    docker run --rm \
        -v /tmp:/tmp \
        private-registry.nginx.com/nap/waf-compiler:<version> \
        -p /tmp/your_policy.json \
        -o /tmp/compiled_policy.tgz
    ```

    Refer to the [F5 WAF for NGINX documentation](https://docs.nginx.com/waf/) for details on compiling policy and log bundles. The log bundle must be compiled from a log profile that matches the format required by NGINX Security Monitoring.

1. Copy both bundles to the volume mounted at `/etc/app_protect/bundles` in the Ingress Controller pod:

    ```console
    kubectl cp ./compiled_policy.tgz <pod-name>:/etc/app_protect/bundles/compiled_policy.tgz -c nginx-ingress
    kubectl cp ./compiled_log.tgz <pod-name>:/etc/app_protect/bundles/compiled_log.tgz -c nginx-ingress
    ```

## 4. Configure Load Balancing

1. Create a secret with an SSL certificate and key:

    ```console
    kubectl apply -f cafe-secret.yaml
    ```

1. If using Agent 2.* (NGINX Instance Manager), create the syslog service and pod that receives App Protect security logs:

    ```console
    kubectl apply -f syslog.yaml
    ```

    If you are using Agent 3.9.*(NGINX One Console), skip this step. NGINX Agent 3.9.* listens for security logs locally on `127.0.0.1:1514` using its embedded OpenTelemetry collector.

1. Create the WAF policy referencing the compiled bundles. Choose the file that matches your agent version:

    **Agent 2.* (NGINX Instance Manager)** — logs sent to the syslog service:

    ```console
    kubectl apply -f waf.yaml
    ```

    **Agent 3.9.* (NGINX One Console)** — logs sent directly to the local NGINX Agent listener:

    ```console
    kubectl apply -f waf-agent-v3.yaml
    ```

1. Create the Ingress resource:

    ```console
    kubectl apply -f cafe-ingress.yaml
    ```

    Note the `nginx.com/policies` annotation in the Ingress resource. It enables WAF protection by referencing the `waf-policy` created in the previous step.

## 5. Test the Application

1. To get coffee:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    ```

1. To get tea:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    Server address: 10.12.0.19:80
    Server name: tea-7cd44fcb4d-xfw2x
    ...
    ```

1. Send a request with a suspicious URL:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP "https://cafe.example.com:$IC_HTTPS_PORT/tea/<script>" --insecure
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```

    The suspicious request is blocked by F5 WAF for NGINX.

1. If using Agent 2.*, check the security logs in the syslog pod:

    ```console
    kubectl exec -it <syslog-pod-name> -- cat /var/log/messages
    ```

1. Access the Security Monitoring dashboard in NGINX Instance Manager or NGINX One Console to view details for the blocked requests.
