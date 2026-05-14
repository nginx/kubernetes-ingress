# Mergeable Ingress Without a Host

This example shows how to use [mergeable Ingress](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/cross-namespace-configuration/) with no `host` field. A single master Ingress owns the default server, and minion Ingresses contribute paths to it. Because minions are independent Ingress resources, they can live in separate namespaces.

## Running the Example

### 1. Deploy the Ingress Controller

1. Run `make secrets` to generate the default server TLS secret for this example.

2. Deploy the default server TLS secret:

   ```console
   kubectl create -f default-server-secret.yaml
   ```

3. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests) instructions to deploy the Ingress Controller with the following additional arguments:

   ```text
   -allow-empty-ingress-host=true
   -default-server-tls-secret=default/default-server-secret
   ```

4. Save the public IP address of the Ingress Controller into a shell variable:

   ```console
   IC_IP=XXX.YYY.ZZZ.III
   ```

5. Save the HTTPS port of the Ingress Controller into a shell variable:

   ```console
   IC_HTTPS_PORT=<port number>
   ```

### 2. Deploy the Cafe Application

Create the coffee and tea deployments and services:

```console
kubectl create -f cafe.yaml
```

### 3. Configure Load Balancing

1. Create the master Ingress resource:

   ```console
   kubectl create -f cafe-master.yaml
   ```

2. Create the minion Ingress resource for the coffee service:

   ```console
   kubectl create -f coffee-minion.yaml
   ```

3. Create the minion Ingress resource for the tea service:

   ```console
   kubectl create -f tea-minion.yaml
   ```

### 4. Test the Application

Access the coffee and tea services. The default server TLS certificate is self-signed, so use `--insecure` to skip verification:

```console
curl --insecure https://$IC_IP:$IC_HTTPS_PORT/coffee
```

```text
Server address: 10.12.0.18:8080
Server name: coffee-7586895968-r26zn
Date: 07/Nov/2025:11:23:09 +0000
URI: /coffee
Request ID: c224b3e06d79b66f8f33e86cef046c32
```

```console
curl --insecure https://$IC_IP:$IC_HTTPS_PORT/tea
```

```text
Server address: 10.12.0.19:8080
Server name: tea-7cd44fcb4d-xfw2x
Date: 07/Nov/2025:11:23:15 +0000
URI: /tea
Request ID: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```
