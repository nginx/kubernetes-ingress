# Support for Backup Directive in Transport Server

F5 NGINX Ingress Controller supports routing requests to a service called `backup`.
`backup` is an [ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname) service.

> [!NOTE]
> The [ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname) service is only
available with NGINX Plus.

For this example, we will use two [tls-passthrough](/examples/custom-resources/tls-passthrough) configurations.
One will be deployed in the `default` namespace, and the other in the `external-ns` namespace.

The application in the `external-ns` namespace will respond to our requests when main application is unavailable.

## Prerequisites

1. Configure the F5 NGINX Ingress Controller deployment with the following flags:

   ```shell
   -enable-custom-resources
   -enable-tls-passthrough
   -watch-namespace=nginx-ingress,default
   ```

   We configure the `-watch-namespace` flag to only watch the `nginx-ingress` and `default` namespaces.
   This ensures that NGINX Ingress Controller will treat our service in the `external-ns` namespace
   as an external service.

2. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy NGINX Ingress Controller.

3. Save the public IP address of the F5 NGINX Ingress Controller into a shell variable:

    ```shell
    IC_IP=XXX.YYY.ZZZ.III
    ```

4. Save the HTTPS port of NGINX Ingress Controller into a shell variable:

    ```shell
    IC_HTTPS_PORT=<port number>
    ```

## Deployment

### 1. Deploy ConfigMap with defined resolver

   ```shell
   kubectl create -f nginx-config.yaml
   ```

### 2. Deploy Backup ExternalName service

   ```shell
   kubectl create -f backup-svc.yaml
   ```

### 3. Deploy the tls-passthrough secret

   ```shell
   kubectl create -f app-tls-secret.yaml
   ```

### 4. Deploy the tls-passthrough application

   ```shell
   kubectl create -f secure-app.yaml
   ```

### 5. Deploy TransportServer

   ```shell
   kubectl create -f transport-server-passthrough.yaml
   ```

### 6. Test the Configuration

   Run the below curl command to get a response from your application:

   ```shell
   curl --resolve app.example.com:$IC_HTTPS_PORT:$IC_IP https://app.example.com:$IC_HTTPS_PORT --insecure
   ```

   ```shell
   hello from pod secure-app-694bc784b-qh8ng
   ```

### 7. Create the external namespace

   ```shell
   kubectl create namespace external-ns
   ```

### 8. Deploy the second tls-passthrough secret to the external namespace

   ```shell
   kubectl apply -n external-ns -f app-tls-secret.yaml
   ```

### 9. Deploy the second tls-passthrough application to the external namespace

   ```shell
   kubectl apply -f external-secure-app.yaml
   ```

### 10. Test the configuration using the backup service

1. Scale down `secure-app` deployment to 0.
   This is done to ensure that the external `backup` service will respond to our requests.

    ```shell
    kubectl scale deployment secure-app --replicas=0
    ```

2. Verify if the application is working by sending a request and check if the response is coming from the "external
   backend pod"

    ```shell
    curl --resolve app.example.com:$IC_HTTPS_PORT:$IC_IP https://app.example.com:$IC_HTTPS_PORT --insecure
    ```

3. Check response from the backup service

    ```shell
    HELLO FROM EXTERNAL APP pod secure-app-backup-7d98dd8d78-p8q7d
    ```
