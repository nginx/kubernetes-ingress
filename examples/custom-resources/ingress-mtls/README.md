# Ingress MTLS

In this example, we deploy a web application, configure load balancing for it via a VirtualServer, and apply an Ingress
MTLS policy.

> Note: The Ingress MTLS policy supports configuring a Certificate Revocation List (CRL). See [Using a Certificate
> Revocation
> List](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#using-a-certificate-revocation-list)
> for details on how to set this option.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 2 - Deploy the Ingress MTLS Secret

Create a secret with the name `ingress-mtls-secret` that will be used for Ingress MTLS validation:

```console
kubectl apply -f ingress-mtls-secret.yaml
```

## Step 3 - Deploy the Ingress MTLS Policy

Create a policy with the name `ingress-mtls-policy` that references the secret from the previous step:

```console
kubectl apply -f ingress-mtls.yaml
```

## Step 4 - Configure Load Balancing and TLS Termination

1. Create the secret with the TLS certificate and key:

    ```console
    kubectl create -f tls-secret.yaml
    ```

2. Create a VirtualServer resource for the web application:

    ```console
    kubectl apply -f virtual-server.yaml
    ```

Note that the VirtualServer references the policy `ingress-mtls-policy` created in Step 3.

## Step 5 - Test the Configuration

If you attempt to access the application without providing a valid Client certificate and key, NGINX will reject your
requests for that VirtualServer:

```console
curl --insecure --resolve webapp.example.com:$IC_HTTPS_PORT:$IC_IP https://webapp.example.com:$IC_HTTPS_PORT/
```

```text
<html>
<head><title>400 No required SSL certificate was sent</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>No required SSL certificate was sent</center>
</body>
</html>
```

If you provide a valid Client certificate and key, your request will succeed:

```console
curl --insecure --resolve webapp.example.com:$IC_HTTPS_PORT:$IC_IP https://webapp.example.com:$IC_HTTPS_PORT/ --cert ./client-cert.pem --key ./client-key.pem
```

```text
Server address: 10.244.0.8:8080
Server name: webapp-7c6d448df9-9ts8x
Date: 23/Sep/2020:07:18:52 +0000
URI: /
Request ID: acb0f48057ccdfd250debe5afe58252a
```
