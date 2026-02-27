# WAF

In this example we deploy the NGINX Plus Ingress Controller with [NGINX App
Protect](https://www.nginx.com/products/nginx-app-protect/), a simple web application and then configure load balancing
and WAF protection for that application using the VirtualServer resource.

## Prerequisites

1. Install PLM using Helm. Make a note of:

   - the FQDN and port of the Seaweed Filer endpoint - it will be in the format `<PLM helm chart name>-f5-waf-seaweed-filer.<PLM namespace>.svc.cluster.local:8333`

   - the name of the Secret for accessing the Seaweed Filer endpoint - it will be in the format `<PLM namespace>/<PLM helm chart name>-f5-waf-seaweedfs-auth`

1. If required, use the `build-nap-dev-image.sh` script in the `scripts/` folder in the root of the repo to build the NIC image with a dev version of the NAP module installed.

1. Deploy the Ingress Controller with NGINX App Protect - include the following values for Helm installation:

    ```text
       controller:
          nginxplus: true
          ## Support for App Protect WAF
          appprotect:
            ## Enable the App Protect WAF module in the Ingress Controller.
            enable: true
            ## Enables App Protect WAF v5.
            v5: true
            plm:
              ## URL of the PLM storage service. Accepts host or host:port (e.g. "seaweedfs.example.com:8333").
              storageUrl: "my-plm-f5-waf-seaweed-filer.plm.svc.cluster.local:8333"
              ## Secret name containing S3 credentials (must have a seaweedfs_admin_secret field).
              storageCredentialsSecret: "plm/my-plm-f5-waf-seaweedfs-auth"
    ```

    You may also need to configure the NIC, enforcer and config-mgr images.

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

## Step 2 - Deploy the AP Policy

1. Create the syslog service and pod for the App Protect security logs:

    ```console
    kubectl apply -f syslog.yaml
    ```

1. Create the App Protect policy and log configuration:

    ```console
    kubectl apply -f ap-dataguard-alarm-policy.yaml
    kubectl apply -f ap-logconf.yaml
    ```

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

    ```console
    kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
    ```
