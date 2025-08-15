# Support for Backup Directive in Virtual Server

Backup service is defined by the
[ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname) service type.
The backup service enables to use the Ingress Controller to route requests to the destinations outside the cluster.

> [!NOTE]
> Support of the services of type
> [ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname)
> is only available in NGINX Plus.

In this example we will deploy two variations of the `cafe` example from our
[basic-configuration](/examples/custom-resources/basic-configuration).
The first is the typical `cafe` application that is configured with a `backup` service for the `coffee` upstream.
The second is the `external-cafe` that will response to requests sent to `/coffee`
if the pods for the `cafe` application go down.
In this example, we will replicate this behaviour by scaling down the application to zero pods.
When this happens, you should get a response from the `external-cafe` instead.

## Prerequisites

1. Configure the NGINX Ingress Controller deployment with the following flags:

   ```shell
   -enable-custom-resources
   -watch-namespace=nginx-ingress,default
   ```

   We configure the `-watch-namespace` flag to only watch the `nginx-ingress` and `default` namespaces.
   This ensures that NGINX Ingress Controller will treat our service in the `external-ns` namespace
   as an external service.

2. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy NGINX Ingress Controller.

3. Save the public IP address of the Ingress Controller into a shell variable:

    ```shell
    IC_IP=XXX.YYY.ZZZ.III
    ```

4. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```shell
    IC_HTTPS_PORT=<port number>
    ```

## Deployment

### 1. Deploy the external service

This is the service that will respond to our requests when the `coffee` application goes down

   ```shell
   kubectl apply -f external-cafe.yaml
   ```

### 2. Deploy a ConfigMap configured with a resolved

   ```shell
   kubectl apply -f nginx-config.yaml
   ```

### 3. Deploy the backup service of type external name

   ```shell
   kubectl apply -f backup-svc.yaml
   ```

### 4. Deploy the cafe application

   ```shell
   kubectl apply -f cafe.yaml
   ```

### 5. Configure TLS Termination

   ```shell
   kubectl apply -f cafe-secret.yaml
   ```

### 6. Deploy a VirtualServer configured with a backup service

   ```shell
   kubectl apply -f cafe-virtual-server-backup.yaml
   ```

Note that the backup service is configured with cluster domain name of the external service.

### 7. Test the configuration

Run the below curl command to get a response from your application. In this example we hit the `/coffee` endpoint:

   ```shell
   curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
   ```

   ```shell
   Server address: 10.32.1.9:8080
   Server name: coffee-7dd75bc79b-rmfp7
   Date: 09/Dec/2023:16:15:45 +0000
   URI: /coffee
   Request ID: 51635a6ab2b359fe91014e43aff75854
   ```

### 8. Test the configuration using the backup service

1. Scale the coffee deployment to zero pods.
   This is done to ensure that the external `backup` service will respond to our requests.

   ```shell
   kubectl scale deployment coffee --replicas=0
   ```

2. Run the below curl command. Notice that Server name in the response is `coffee-backup-<id>` instead of `coffee-<id>`

   ```shell
   curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
   ```

3. Check response from the backup service

   ```shell
   Server address: 10.32.2.19:8080
   Server name: coffee-backup-7c64b6b5b6-h4rnx
   Date: 09/Dec/2023:16:18:17 +0000
   URI: /coffee
   Request ID: 8140ea6975983d12feaf56eed203f922
   ```
