# Support for Type ExternalName Services in Transport Server

The Ingress Controller supports routing requests to services of the type
[ExternalName](https://kubernetes.io/docs/concepts/services-networking/service/#externalname).

An ExternalName service is defined by an external DNS name that is resolved into the IP addresses, typically external to
the cluster. This enables to use the Ingress Controller to route requests to the destinations outside of the cluster.

**Note:** This feature is only available in NGINX Plus.

## Prerequisites

For illustration purposes, we will run NGINX Ingress Controller (referred to as NIC in the examples) with the
```-watch-namespace=nginx-ingress,default``` option. The option enables NIC to watch selected namespaces.

Any application deployed in other namespaces will be treated as an external service.

We will use the ```examples/custom-resources/tls-passthrough``` application example as our backend app that will be
responding to requests.

## Example

### 1. Deploy the tls-passthrough application

1. Deploy the backend application as described in the ```examples/custom-resources/tls-passthrough``` example, and make
   sure it is working as described.

### 2. Deploy external service to external namespace

1. Create the external namespace

   ```shell
   kubectl create namespace external-ns
   ```

2. Deploy the tls secret to the external namespace

   ```shell
   kubectl apply -n external-ns -f app-tls-secret.yaml
   ```

3. Deploy backend application to external namespace (```external-ns```). Note that the namespace is not being watched by
   ```NIC```.

    ```console
    kubectl apply -f secure-app-external.yaml
    ```

### 3. Setup ExternalName service

1. Create the service of type ```ExternalName```

    ```console
    kubectl apply -f externalname-svc.yaml
    ```

2. Apply the config map

    ```console
    kubectl apply -f nginx-config.yaml
    ```

### 4. Change the Transport Server to point to the ExternalName and verify if it is working correctly

1. Navigate to the tls-passthrough example ```examples/custom-resources/tls-passthrough``` and open the
   ```transport-server-passthrough.yaml``` file.

2. Replace the service name ```secure-app``` with ```externalname-service``` and apply the change.

    ```yaml
    apiVersion: k8s.nginx.org/v1
    kind: TransportServer
    metadata:
      name: secure-app
    spec:
      listener:
        name: tls-passthrough
        protocol: TLS_PASSTHROUGH
      host: app.example.com
      upstreams:
      - name: secure-app
        service: externalname-service
        port: 8443
      action:
        pass: secure-app
    ```

    ```console
    kubectl apply -f transport-server-passthrough.yaml
    ```

3. Verify if the application is working by sending a request and check if the response is coming from the "external
   backend pod" (refer to to the tls-passthrough example)

    ```console
    curl --resolve app.example.com:$IC_HTTPS_PORT:$IC_IP https://app.example.com:$IC_HTTPS_PORT --insecure
    ```

    Response

    ```console
    hello from pod secure-app-external-backend-5fbf4fb494-x7bkl
    ```
