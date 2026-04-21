# WAF Security Monitoring with F5 WAF for NGINX v5

This example describes how to deploy NGINX Plus Ingress Controller with [F5 WAF for NGINX v5](https://docs.nginx.com/waf/) and [NGINX Agent](https://docs.nginx.com/nginx-agent/overview/) to integrate with [NGINX Instance Manager Security Monitoring](https://docs.nginx.com/nginx-instance-manager/security-monitoring/). It deploys a simple web application and configures WAF protection using compiled policy and log bundles, forwarding security logs to the Security Monitoring dashboard via syslog.

## Prerequisites

1. Follow the installation [instructions](https://docs.nginx.com/nginx-ingress-controller/installation) to deploy NGINX
   Ingress Controller with F5 WAF for NGINX v5 and NGINX Agent. Configure NGINX Agent to connect to a deployment of NGINX Instance Manager with Security Monitoring, and verify your NGINX Ingress Controller deployment is online in NGINX Instance Manager.

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

## Step 3 - Deploy the Syslog Service

Create the syslog service and pod that receives App Protect security logs:

```console
kubectl apply -f syslog.yaml
```

## Step 4 - Deploy the WAF Policy

Create the WAF policy referencing the compiled bundles:

```console
kubectl apply -f waf.yaml
```

The `waf.yaml` Policy resource configures WAF protection using the compiled policy bundle and sends security logs to the syslog service using the compiled log bundle.

Note the log configuration in the `apLogBundle` must be compiled from a log profile that matches the format required by NGINX Instance Manager Security Monitoring.

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

1. To check the security logs in the syslog pod:

    ```console
    kubectl exec -it <syslog-pod-name> -- cat /var/log/messages
    ```

1. Access the Security Monitoring dashboard in NGINX Instance Manager to view details for the blocked requests.
