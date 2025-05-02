# JWKS

In this example we deploy a web application, configure load balancing with a VirtualServer, and apply a JWT policy.
Instead of using a local secret to verify the client request such as in the
[jwt](https://github.com/nginx/kubernetes-ingress/tree/main/examples/custom-resources/jwt) example, we will define an
external Identity Provider (IdP) using the `JwksURI` field.

We will be using a deployment of [KeyCloak](https://www.keycloak.org/) to work as our IdP in this example. In this
example, KeyCloak is deployed as a single container for the purpose of exposing it with an Ingress Controller.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller.

2. Save the public IP address of the Ingress Controller into `/etc/hosts` of your machine:

    ```text
    ...

    XXX.YYY.ZZZ.III webapp.example.com
    XXX.YYY.ZZZ.III keycloak.example.com
    ```

   Here `webapp.example.com` is the domain for the web application and `keycloak.example.com` is the domain for
   Keycloak.

## Step 1 - Deploy a TLS Secret

Create a secret with the TLS certificate and key that will be used for TLS termination of the Keycloak application:

```console
kubectl apply -f tls-secret.yaml
```

## Step 2 - Deploy a Web Application

Create the application deployment and service:

```console
kubectl apply -f webapp.yaml
```

## Step 3 - Deploy Keycloak

1. Create the Keycloak deployment and service:

    ```console
    kubectl apply -f keycloak.yaml
    ```

1. Create a VirtualServer resource for Keycloak:

    ```console
    kubectl apply -f virtual-server-idp.yaml
    ```

## Step 4 - Configure Keycloak

To set up Keycloak:

1. To connect to Keycloak, use `https://keycloak.example.com`.

2. Create a new Realm. We will use `jwks-example` for this example. This can be done by selecting the dropdown menu on
   the left and selecting `Create Realm`

3. Create a new Client called `jwks-client`. This can be done by selecting the `Client`s tab on the left and then
   selecting `Create client`.
   - When creating the Client, ensure both `Client authentication` and `Authorization` are enabled.

4. Once the client is created, navigate to the `Credentials` tab for that client and copy the client secret.
   - This can be saved in the `SECRET` shell variable for later:

      ```console
      export SECRET=<client secret>
      ```

5. Create a new User called `jwks-user` by selecting the Users tab on the left and then selecting Create client.

6. Once the user is created, navigate to the `Credentials` tab for that user and select `Set password`. For this example
   the password can be whatever you want.
   - This can be saved in the `PASSWORD` shell variable for later:

     ```console
     export PASSWORD=<user password>
     ```

## Step 5 - Deploy the JWT Policy

Create a policy with the name `jwt-policy` and configure the `JwksURI` field so that it only permits requests to our
web application that contain a valid JWT. In the example policy below, replace `<your_realm>` with the realm created in
Step 4. We used `jwks-example` as our realm name. The value of `spec.jwt.token` is set to `$http_token` in this example
as we are sending the client token in an HTTP header.

  ```yaml
  apiVersion: k8s.nginx.org/v1
  kind: Policy
  metadata:
    name: jwt-policy
  spec:
    jwt:
      realm: MyProductAPI
      token: $http_token
      jwksURI: http://keycloak.default.svc.cluster.local:8080/realms/<your_realm>/protocol/openid-connect/certs
      keyCache: 1h
  ```

Deploy the policy:

  ```console
  kubectl apply -f jwks.yaml
  ```

## Step 6 - Deploy a config map with a resolver

If the value of `jwksURI` uses a hostname, the Ingress Controller will need to reference a resolver. This can be done by
deploying a ConfigMap with the `resolver-addresses` data field

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-config
  namespace: nginx-ingress
data:
  resolver-addresses: <resolver-address>
```

In this example, we create a ConfigMap using Kubernetes' default DNS `kube-dns.kube-system.svc.cluster.local` for the
resolver address. For more information on `resolver-addresses` and other related ConfigMap keys, please refer to our
documentation [ConfigMap
Resource](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#summary-of-configmap-keys)
and our blog post [Using DNS for Service Discovery with NGINX and NGINX
Plus](https://www.nginx.com/blog/dns-service-discovery-nginx-plus)

NOTE: When setting the value of `jwksURI` in Step 5, the response will differ depending on the IDP used. In some cases
the response will be too large for NGINX to properly handle. If this occurs you will need to configure the
[subrequest_output_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#subrequest_output_buffer_size)
directive in the http context. This can currently be done using `http-snippets`. Please refer to our document on
[snippets and custom
templates](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#snippets-and-custom-templates)
for details on how to configure this directive.

The code block below is an example of the updated configmap which adds `subrequest_output_buffer_size` under the http
context in the nginx.conf.

NOTE: The value of `subrequest_output_buffer_size` is only an example value and should be changed to suit your
environment.

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-config
  namespace: nginx-ingress
data:
  resolver-addresses: <resolver-address>
  http-snippets: |
    subrequest_output_buffer_size 64k;
```

```console
kubectl apply -f nginx-config.yaml
```

## Step 7 - Configure Load Balancing

Create a VirtualServer resource for the web application:

```console
kubectl apply -f virtual-server.yaml
```

Note that the VirtualServer references the policy `jwt-policy` created in Step 5.

## Step 8 - Get the client token

For the client to have permission to send requests to the web application they must send a Bearer token to the
application. To get this token, run the following `curl` command:

```console
export TOKEN=$(curl -k -L -X POST 'https://keycloak.example.com/realms/jwks-example/protocol/openid-connect/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode grant_type=password \
--data-urlencode scope=openid \
--data-urlencode client_id=jwks-client \
--data-urlencode client_secret=$SECRET \
--data-urlencode username=jwks-user \
--data-urlencode password=$PASSWORD \
| jq -r .access_token)
```

This command will save the token in the `TOKEN` shell variable.

## Step 9 - Test the Configuration

If you attempt to access the application without providing the bearer token, NGINX will reject your requests for that
VirtualServer:

```console
curl -H 'Accept: application/json' webapp.example.com
```

```text
<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>
```

If a valid bearer token is provided, the request will succeed:

```console
curl -H 'Accept: application/json' -H "token: ${TOKEN}" webapp.example.com
```

```text
Server address: 10.42.0.7:8080
Server name: webapp-5c6fdbcbf9-pt9tp
Date: 13/Dec/2022:14:50:33 +0000
URI: /
Request ID: f1241390ac51318afa4fcc39d2341359
```
