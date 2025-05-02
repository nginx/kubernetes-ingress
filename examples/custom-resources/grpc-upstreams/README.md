# gRPC support

To support a gRPC application using VirtualServer resources with NGINX Ingress Controller, you need to add the **type:
grpc** field to an upstream. The protocol defaults to http if left unset.

## Prerequisites

1. HTTP/2 must be enabled using the `http2` [ConfigMap key](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#listeners).

2. Configure TLS termination for VirtualServer and VirtualServerRoute resources.

3. A working [`grpcurl`](https://github.com/fullstorydev/grpcurl) installation.

4. [Install NGINX Ingress Controller using Manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)

5. Save the public IP address of NGINX Ingress Controller into a shell variable:

    ```shell
    IC_IP=XXX.YYY.ZZZ.III
    ```

6. Save the HTTPS port of NGINX Ingress Controller into a shell variable:

    ```shell
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Update ConfigMap with `http2: "true"`

```shell
kubectl apply -f nginx-config
```

## Step 2 - Deploy the Cafe Application

Create the coffee and the tea deployments and services:

```shell
kubectl apply -f greeter-app.yaml
```

## Step 3 - Configure TLS termination and Load balancing

1. Create the secret with the TLS certificate and key:

    ```shell
    kubectl create -f greeter-secret.yaml
    ```

2. Create the VirtualServer resource:

    ```shell
    kubectl create -f greeter-virtual-server.yaml
    ```

## Step 4 - Test the Configuration

Access the application using `grpcurl`. Use the `-insecure` flag to turn off certificate verification for the self-signed certificate.

```shell
grpcurl -insecure -proto helloworld.proto -authority greeter.example.com $IC_IP:$IC_HTTPS_PORT helloworld.Greeter/SayHello
```

```shell
{
  "message": "Hello"
}
```
