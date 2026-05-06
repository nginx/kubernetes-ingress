# Ingress MTLS

In this example, we deploy the cafe application and attach the IngressMTLS policy to Ingress resources using the `nginx.org/policies` annotation.

> Note: The Ingress MTLS policy supports configuring a Certificate Revocation List (CRL). See [Using a Certificate
> Revocation
> List](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#using-a-certificate-revocation-list)
> for details on how to set this option.

## Prerequisites

1. Run `make secrets` command to generate the necessary secrets for the example.
1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy the Cafe Application

Create the coffee and the tea deployments and services:

```console
kubectl apply -f cafe.yaml
```

## Step 2 - Deploy the Ingress MTLS Secret

Create a secret with the name `ingress-mtls-secret` that will be used for Ingress MTLS validation:

```console
kubectl apply -f ingress-mtls-secret.yaml
```

## Step 3 - Deploy the Ingress MTLS Policy

Create a policy with the name `ingress-mtls-policy` that references the secret from the previous step:

```console
kubectl apply -f ingress-mtls-policy.yaml
```

## Step 4 - Configure Load Balancing and TLS Termination

1. Create the secret with the TLS certificate and key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

2. Create an Ingress resource for the web application:

    ```console
    kubectl apply -f cafe-ingress.yaml
    ```

Note that the Ingress references the policy `ingress-mtls-policy` created in Step 3.

## Step 5 - Test the Configuration

If you attempt to access the application without providing a valid Client certificate and key, NGINX will reject your
requests:

```console
curl --insecure --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea
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
curl --insecure --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --cert ./client-cert.pem --key ./client-key.pem
```

```text
Server address: 10.244.0.8:8080
Server name: cafe-7c6d448df9-9ts8x
Date: 23/Sep/2020:07:18:52 +0000
URI: /tea
Request ID: acb0f48057ccdfd250debe5afe58252a
```
