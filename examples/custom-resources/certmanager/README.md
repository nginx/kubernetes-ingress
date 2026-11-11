# Example

In this example, we deploy [cert-manager](https://cert-manager.io/docs/installation/#default-static-install) and a
[self-signed certificate issuer](https://cert-manager.io/docs/configuration/selfsigned/#bootstrapping-ca-issuers). Then,
we deploy the NGINX or NGINX Plus Ingress Controller, a simple web application and then configure load balancing for
that application using the VirtualServer resource.

## Deploying the Certmanager and the self-signed authority

1. Deploy cert manager and all dependent resources:

    ```console
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.20.0/cert-manager.yaml
    ```

2. Deploy a self-signed certificate issuer:

    ```console
    kubectl apply -f self-signed.yaml
    ```

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller.
   - Set the
     [`-enable-custom-resources`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-enable-custom-resources)
     and
     [`-enable-cert-manager`](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#cmdoption-enable-cert-manager)
     command-line arguments of the Ingress Controller to enable the cert-manager for Virtual Server resources feature.

2. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

3. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Cafe Application

Create the coffee and the tea deployments and services:

```console
kubectl create -f cafe.yaml
```

## 3. Configure Load Balancing

1. Create a VirtualServer resource:

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

## 4. Test the Application

1. To access the application, curl the coffee and the tea services. We'll use ```curl```'s --insecure option to turn off
certificate verification of our self-signed certificate and the --resolve option to set the Host header of a request
with ```cafe.example.com```

    To get coffee:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    ```

    ```text
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    ```

    If your prefer tea:

    ```console
    curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    ```

    ```text
    Server address: 10.12.0.19:80
    Server name: tea-7cd44fcb4d-xfw2x
    ...
    ```

## ACME HTTP-01 challenges with TLS redirect and authentication

When cert-manager uses an ACME issuer with the HTTP-01 solver, the ACME server must reach
`http://<host>/.well-known/acme-challenge/<token>` over plain HTTP. The Ingress Controller detects these challenge
locations automatically, so the HTTPS redirect and authentication policies on the VirtualServer no longer block the
challenge. You do not need any extra configuration, and you do not need `issue-temp-cert` just because `tls.redirect`
is enabled.

A location is treated as an ACME HTTP-01 challenge location only when its path starts with
`/.well-known/acme-challenge/` and its backend Service name starts with `cm-acme-http-solver-` (the Service that
cert-manager creates for its solver). For VirtualServers, only routes built from cert-manager's solver Ingress qualify
(this requires `-enable-cert-manager`), and the solver Ingress must be in the same namespace as the VirtualServer.

While a challenge is active for a host:

- Plain HTTP requests to any path under `/.well-known/acme-challenge/` on that host skip the `tls.redirect` HTTPS
  redirect.
- The challenge location skips basic auth, JWT, API key, external auth and OIDC policies.
- Access control (IP allow/deny), WAF and rate limiting policies referenced in the VirtualServer `spec.policies` still
  apply, because they are rendered at the server level. Policies referenced on individual routes or subroutes do not
  apply, because the challenge location is not part of any VirtualServer route.
- The challenge location is an exact-match location (`location = /.well-known/acme-challenge/<token>`), so NGINX
  selects it before any regular expression route, such as `~ ^/`, that would otherwise match the token path.

If a VirtualServer or VirtualServerRoute already defines an exact-match route for the same challenge token path, the
Ingress Controller keeps that route, does not generate the challenge location, and reports a warning on the
VirtualServer.

When no challenge is active, the generated NGINX configuration is unchanged.

For example, the following VirtualServer redirects HTTP to HTTPS and can still complete HTTP-01 challenges. It assumes
an ACME `ClusterIssuer` named `letsencrypt-prod` that uses the HTTP-01 solver, instead of the self-signed issuer used
earlier in this example. It replaces the earlier `cafe` VirtualServer; replace `cafe.example.com` with a publicly
reachable host that you control and that is served on port 80:

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: cafe
spec:
  host: cafe.example.com
  tls:
    secret: cafe-secret
    redirect:
      enable: true
    cert-manager:
      cluster-issuer: letsencrypt-prod
  upstreams:
  - name: coffee
    service: coffee-svc
    port: 80
  routes:
  - path: /coffee
    action:
      pass: coffee
```

> **Note**: While a challenge is active, the redirect is skipped for every path under `/.well-known/acme-challenge/`
> on that host, not only the challenge token path. Only real challenge locations skip authentication, so other paths
> under that prefix still require credentials, but clients could send those credentials over plain HTTP for the
> lifetime of the challenge (typically seconds to minutes).

Ingress resources get the same redirect exemption (`ssl-redirect` and `redirect-to-https`), and the challenge path
skips basic auth, JWT, external auth and OIDC, when cert-manager adds the challenge path to the existing Ingress with
the `acme.cert-manager.io/http01-edit-in-place: "true"` annotation.
Edit-in-place is required: if cert-manager creates a separate solver Ingress for a host that another Ingress already
owns, the existing Ingress keeps the host and the challenge is not served.
Access control (IP allow/deny) and WAF configured on the Ingress through policies or annotations, and the
`nginx.org/limit-req-*` rate limiting annotations, still apply to the challenge path.

For mergeable Ingresses, the TLS configuration and the `cert-manager.io/*` annotations live on the master, but
edit-in-place does not work on the master. A master cannot have paths, so its rule has no `http` section, and
cert-manager can only add the challenge path to a rule that already has one. The challenge path is never added and the
challenge does not complete. Instead, point the solver at one of the minions, which already have paths, by setting
`solvers[].http01.ingress.name` in the issuer to the name of that minion Ingress.
