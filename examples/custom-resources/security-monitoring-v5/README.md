# WAF Security Monitoring with F5 WAF for NGINX v5

This example describes how to deploy NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and [NGINX Agent](https://docs.nginx.com/nginx-agent/overview/) to integrate with NGINX Security Monitoring. It deploys a simple web application and configures WAF protection using compiled policy and log bundles, forwarding security logs to the Security Monitoring dashboard via syslog.

This example works with both:

- **NGINX Instance Manager** (Agent 2.*) - See the [Security Monitoring tutorial](https://docs.nginx.com/nginx-ingress-controller/tutorials/security-monitoring/) for agent configuration.
- **NGINX One Console** (Agent 3.*) - See the [Connect NGINX Ingress Controller to NGINX One Console](https://docs.nginx.com/nginx-one-console/k8s/add-nic/) guide for agent configuration.

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX
   Ingress Controller with F5 WAF for NGINX v5 and NGINX Agent. Configure NGINX Agent to connect to either a deployment of NGINX Instance Manager with Security Monitoring, or to NGINX One Console, and verify your NGINX Ingress Controller deployment is online.

1. Confirm which version of NGINX Agent is running in your Ingress Controller pod:

    ```console
    kubectl exec -it <nginx-ingress-pod> -c nginx-ingress -- nginx-agent -v
    ```

    The output will show either `2.x.x` or `3.x.x`. Use this to choose the correct WAF policy in Step 4 below.

    - **Agent 2.***: connects to NGINX Instance Manager
    - **Agent 3.***: connects to NGINX One Console (requires 3.9.0 or later for security monitoring)

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of NGINX Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1. Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 2 - Create and Deploy the WAF Policy and Log Bundles

1. Compile your WAF policy JSON into a policy bundle (`compiled_policy.tgz`) and a log configuration bundle (`compiled_log.tgz`) using the `waf-compiler` image:

    ```console
    docker run --rm \
        -v /tmp:/tmp \
        private-registry.nginx.com/nap/waf-compiler:<version> \
        -p /tmp/your_policy.json \
        -o /tmp/compiled_policy.tgz
    ```

    Refer to the [F5 WAF for NGINX documentation](https://docs.nginx.com/waf/) for details on compiling policy and log bundles.

1. Copy both bundles to the volume mounted at `/etc/app_protect/bundles` in the Ingress Controller pod:

    ```console
    kubectl cp ./compiled_policy.tgz <pod-name>:/etc/app_protect/bundles/compiled_policy.tgz -c nginx-ingress
    kubectl cp ./compiled_log.tgz <pod-name>:/etc/app_protect/bundles/compiled_log.tgz -c nginx-ingress
    ```

## Step 3 - Deploy the Syslog Service (Agent 2.* only)

If you are using Agent 2.* (NGINX Instance Manager), create the syslog service and pod that receives App Protect security logs:

```console
kubectl apply -f syslog.yaml
```

If you are using Agent 3.*(NGINX One Console), skip this step. NGINX Agent 3.* listens for security logs locally on `127.0.0.1:1514` using its embedded OpenTelemetry collector.

## Step 4 - Deploy the WAF Policy

Create the WAF policy referencing the compiled bundles. Choose the file that matches your agent version:

**Agent 2.* (NGINX Instance Manager)** — logs sent to the syslog service:

```console
kubectl apply -f waf.yaml
```

**Agent 3.* (NGINX One Console)** — logs sent directly to the local NGINX Agent listener:

```console
kubectl apply -f waf-agent-v3.yaml
```

Note the log bundle referenced in the `apLogBundle` field must be compiled from a log profile that matches the format required by NGINX Security Monitoring.

## Step 5 - Configure Load Balancing

Create the VirtualServer resource:

```console
kubectl apply -f virtual-server.yaml
```

## Step 6 - Test the Application

1. Send a valid request to the application:

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

    The suspicious request is blocked by F5 WAF for NGINX.

1. If using Agent 2.*, check the security logs in the syslog pod:

    ```console
    kubectl exec -it <syslog-pod-name> -- cat /var/log/messages
    ```

1. Access the Security Monitoring dashboard in NGINX Instance Manager or NGINX One Console to view details for the blocked requests.
