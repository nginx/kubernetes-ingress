---
title: Policy resources
weight: 500
toc: true
type: how-to
product: NIC
docs: DOCS-596
---

The Policy resource allows you to configure features like access control and rate-limiting, which you can add to your [VirtualServer and VirtualServerRoute resources](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/).

The resource is implemented as a [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

This document is the reference documentation for the Policy resource. An example of a Policy for access control is available in our [GitHub repository](https://github.com/nginx/kubernetes-ingress/blob/v{{< nic-version >}}/examples/custom-resources/access-control).

## Prerequisites

Policies work together with [VirtualServer and VirtualServerRoute resources](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/), which you need to create separately.

## Policy Specification

Below is an example of a policy that allows access for clients from the subnet `10.0.0.0/8` and denies access for any other clients:

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: allow-localhost
spec:
  accessControl:
    allow:
    - 10.0.0.0/8
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``accessControl`` | The access control policy based on the client IP address. | [accessControl](#accesscontrol) | No |
|``ingressClassName`` | Specifies which instance of NGINX Ingress Controller must handle the Policy resource. | ``string`` | No |
|``rateLimit`` | The rate limit policy controls the rate of processing requests per a defined key. | [rateLimit](#ratelimit) | No |
|``apiKey`` | The API Key policy configures NGINX to authorize requests which provide a valid API Key in a specified header or query param. | [apiKey](#apikey) | No |
|``basicAuth`` | The basic auth policy configures NGINX to authenticate client requests using HTTP Basic authentication credentials. | [basicAuth](#basicauth) | No |
|``jwt`` | The JWT policy configures NGINX Plus to authenticate client requests using JSON Web Tokens. | [jwt](#jwt) | No |
|``ingressMTLS`` | The IngressMTLS policy configures client certificate verification. | [ingressMTLS](#ingressmtls) | No |
|``egressMTLS`` | The EgressMTLS policy configures upstreams authentication and certificate verification. | [egressMTLS](#egressmtls) | No |
|``waf`` | The WAF policy configures WAF and log configuration policies for [NGINX AppProtect]({{< relref "installation/integrations/app-protect-waf/configuration.md" >}}) | [WAF](#waf) | No |
{{% /table %}}

\* A policy must include exactly one policy.

### AccessControl

The access control policy configures NGINX to deny or allow requests from clients with the specified IP addresses/subnets.

For example, the following policy allows access for clients from the subnet `10.0.0.0/8` and denies access for any other clients:

```yaml
accessControl:
  allow:
  - 10.0.0.0/8
```

In contrast, the policy below does the opposite: denies access for clients from `10.0.0.0/8` and allows access for any other clients:

```yaml
accessControl:
  deny:
  - 10.0.0.0/8
```
{{< note >}}

The feature is implemented using the NGINX [ngx_http_access_module](http://nginx.org/en/docs/http/ngx_http_access_module.html). NGINX Ingress Controller access control policy supports either allow or deny rules, but not both (as the module does).

{{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``allow`` | Allows access for the specified networks or addresses. For example, ``192.168.1.1`` or ``10.1.1.0/16``. | ``[]string`` | No |
|``deny`` | Denies access for the specified networks or addresses. For example, ``192.168.1.1`` or ``10.1.1.0/16``. | ``[]string`` | No | \* an accessControl must include either `allow` or `deny`. |
{{% /table %}}

#### AccessControl Merging Behavior

A VirtualServer/VirtualServerRoute can reference multiple access control policies. For example, here we reference two policies, each with configured allow lists:

```yaml
policies:
- name: allow-policy-one
- name: allow-policy-two
```

When you reference more than one access control policy, NGINX Ingress Controller will merge the contents into a single allow list or a single deny list.

Referencing both allow and deny policies, as shown in the example below, is not supported. If both allow and deny lists are referenced, NGINX Ingress Controller uses just the allow list policies.

```yaml
policies:
- name: deny-policy
- name: allow-policy-one
- name: allow-policy-two
```

### RateLimit

The rate limit policy configures NGINX to limit the processing rate of requests.

For example, the following policy will limit all subsequent requests coming from a single IP address once a rate of 10 requests per second is exceeded:

```yaml
rateLimit:
  rate: 10r/s
  zoneSize: 10M
  key: ${binary_remote_addr}
```
{{< note >}}

The feature is implemented using the NGINX [ngx_http_limit_req_module](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html).

{{< /note >}}

{{< note >}}

When the [Zone Sync feature]({{< ref "/configuration/global-configuration/configmap-resource.md#zone-sync" >}}) is enabled with NGINX Plus, the rate limiting zone will be synchronized across all replicas in the cluster.  This means all replicas are aware of the requests that have been rate limited by other replicas in the cluster.

{{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``rate`` | The rate of requests permitted. The rate is specified in requests per second (r/s) or requests per minute (r/m). | ``string`` | Yes |
|``key`` | The key to which the rate limit is applied. Can contain text, variables, or a combination of them. Variables must be surrounded by ``${}``. For example: ``${binary_remote_addr}``. Accepted variables are ``$binary_remote_addr``, ``$request_uri``,``$request_method``, ``$url``, ``$http_``, ``$args``, ``$arg_``, ``$cookie_``, ``$jwt_claim_``. | ``string`` | Yes |
|``zoneSize`` | Size of the shared memory zone. Only positive values are allowed. Allowed suffixes are ``k`` or ``m``, if none are present ``k`` is assumed. | ``string`` | Yes |
|``delay`` | The delay parameter specifies a limit at which excessive requests become delayed. If not set all excessive requests are delayed. | ``int`` | No |
|``noDelay`` | Disables the delaying of excessive requests while requests are being limited. Overrides ``delay`` if both are set. | ``bool`` | No |
|``burst`` | Excessive requests are delayed until their number exceeds the ``burst`` size, in which case the request is terminated with an error. | ``int`` | No |
|``dryRun`` | Enables the dry run mode. In this mode, the rate limit is not actually applied, but the number of excessive requests is accounted as usual in the shared memory zone. | ``bool`` | No |
|``logLevel`` | Sets the desired logging level for cases when the server refuses to process requests due to rate exceeding, or delays request processing. Allowed values are ``info``, ``notice``, ``warn`` or ``error``. Default is ``error``. | ``string`` | No |
|``rejectCode`` | Sets the status code to return in response to rejected requests. Must fall into the range ``400..599``. Default is ``503``. | ``int`` | No |
|``scale`` | Enables a constant rate-limit by dividing the configured rate by the number of nginx-ingress pods currently serving traffic. This adjustment ensures that the rate-limit remains consistent, even as the number of nginx-pods fluctuates due to autoscaling. **This will not work properly if requests from a client are not evenly distributed across all ingress pods** (Such as with sticky sessions, long lived TCP Connections with many requests, and so forth). In such cases using [zone-sync]({{< ref "/configuration/global-configuration/configmap-resource.md#zone-sync" >}}) instead would give better results.  Enabling `zone-sync` will suppress this setting. | ``bool`` | No |
|``condition`` | Add a condition to a rate-limit policy. | [ratelimit.condition](#ratelimitcondition) | No |
{{% /table %}}

{{< note >}}

For each policy referenced in a VirtualServer and/or its VirtualServerRoutes, NGINX Ingress Controller will generate a single rate limiting zone defined by the [`limit_req_zone`](http://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone) directive. If two VirtualServer resources reference the same policy, NGINX Ingress Controller will generate two different rate limiting zones, one zone per VirtualServer.

{{< /note >}}

#### RateLimit Merging Behavior

A VirtualServer/VirtualServerRoute can reference multiple rate limit policies. For example, here we reference two policies:

```yaml
policies:
- name: rate-limit-policy-one
- name: rate-limit-policy-two
```

When you reference more than one rate limit policy, NGINX Ingress Controller will configure NGINX to use all referenced rate limits. When you define multiple policies, each additional policy inherits the `dryRun`, `logLevel`, and `rejectCode` parameters from the first policy referenced (`rate-limit-policy-one`, in the example above).

### RateLimit.Condition

RateLimit.Condition defines a condition for a rate limit policy. For example:

```yaml
condition:
  jwt:
    claim: user_details.level
    match: premium
  default: true
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``jwt`` | defines a JWT condition to rate limit against. | [ratelimit.condition.jwt](#ratelimitconditionjwt) | No |
|``default`` | sets the rate limit in this policy to be the default if no conditions are met. In a group of policies with the same JWT condition, only one policy can be the default. | ``bool`` | No |
{{% /table %}}

The rate limit policy with condition is designed to be used in combination with one or more rate limit policies. For example, multiple rate limit policies with [RateLimit.Condition.JWT](#ratelimitconditionjwt) can be used to apply different tiers of rate limit based on the value of a JWT claim. For a practical example of tiered rate limiting by the value of a JWT claim, see the example in our [GitHub repository](https://github.com/nginx/kubernetes-ingress/tree/v{{< nic-version >}}/examples/custom-resources/rate-limit-tiered-jwt-claim/README.md).

### RateLimit.Condition.JWT
{{< note >}}

This feature is only available with NGINX Plus.

{{< /note >}}

RateLimit.Condition.JWT defines a condition for a rate limit by JWT claim. For example, here we define a condition for a rate limit policy that only applies to requests with a JWT claim `user_details.level` with a value `premium`:

```yaml
jwt:
  claim: user_details.level
  match: premium
```

The rate limit policy will only apply to requests that contain a JWT with the specified claim and value. For example, the following JWT payload will match the JWT condition:

```json
{
  "user_details": {
    "level": "premium"
  }, 
  "sub": "client1"
}
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``claim`` | Claim is the JWT claim to be rate limit by. Nested claims should be separated by ".". | ``string`` | Yes |
|``match`` | the value of the claim to match against. | ``string`` | Yes |
{{% /table %}}

### APIKey

The API Key auth policy configures NGINX to authorize client requests based on the presence of a valid API Key in a header or query param specified in the policy.

{{< note >}}

The feature is implemented using NGINX [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) and [NGINX JavaScript (NJS)](https://nginx.org/en/docs/njs/).

{{< /note >}}

The policies' API keys are securely stored using SHA-256 hashing. When a client sends an API Key, it is hashed by NJS and then compared to the hashed API Key in the NGINX config.

If the hashed keys match, the NGINX JavaScript (NJS) subrequest issues a 204 No Content response to the `auth_request` directive, indicating successful authorization. Conversely, if no API Key is provided in the specified header or query parameter, a 401 Unauthorized response is returned. Similarly, if an invalid key is presented in the expected header or query parameter, a 403 Forbidden response is issued, denying access.

It is possible to use the [errorPages](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#errorpage) property on a route, to change the default behaviour of 401 or 403 errors.

At least one header or query param is required.

The policy below configures NGINX Ingress Controller to require the API Key `password` in the header "my-header".

```yaml
apiKey:
    suppliedIn:
      header:
      - "my-header"
    clientSecret: api-key-secret
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-key-secret
type: nginx.org/apikey
data:
    client1: cGFzc3dvcmQ= # password
```

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``suppliedIn`` | `header` or `query`. | | Yes |
|``suppliedIn.header`` | An array of headers that the API Key may appear in. | ``string[]`` | No |
|``suppliedIn.query`` | An array of query params that the API Key may appear in. | ``string[]`` | No |
|``clientSecret`` | The name of the Kubernetes secret that stores the API Key(s). It must be in the same namespace as the Policy resource. The secret must be of the type ``nginx.org/apikey``, and the API Key(s) must be stored in a key: val format where each key is a unique clientID and each value is a unique base64 encoded API Key  | ``string`` | Yes |
{{% /table %}}

{{<important>}}An APIKey Policy must include a minimum of one of the `suppliedIn.header` or `suppliedIn.query` parameters.  Both can also be supplied.{{</important>}}

#### APIKey Merging Behavior

A VirtualServer or VirtualServerRoute can be associated with only one API Key policy per route or subroute. However, it is possible to replace an API Key policy from a higher-level with a different policy defined on a more specific route.

For example, a VirtualServer can implement different API Key policies at various levels. In the configuration below, the server-wide api-key-policy-server applies to /backend1 for authorization, as it lacks a more specific policy. Meanwhile, /backend2 uses the api-key-policy-route defined at the route level.

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: virtual-server
spec:
  host: virtual-server.example.com
  policies:
  - name: api-key-policy-server
  upstreams:
  - name: backend2
    service: backend2-svc
    port: 80
  - name: backend1
    service: backend1-svc
    port: 80
  routes:
  - path: /backend1
    action:
      pass: backend1
  - path: /backend2
    action:
      pass: backend2
    policies:
      - name: api-key-policy-route
```

### BasicAuth

The basic auth policy configures NGINX to authenticate client requests using the [HTTP Basic authentication scheme](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication).

For example, the following policy will reject all requests that do not include a valid username/password combination in the HTTP header `Authentication`

```yaml
basicAuth:
  secret: htpasswd-secret
  realm: "My API"
```
{{< note >}}
The feature is implemented using the NGINX [ngx_http_auth_basic_module](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html).
{{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``secret`` | The name of the Kubernetes secret that stores the Htpasswd configuration. It must be in the same namespace as the Policy resource. The secret must be of the type ``nginx.org/htpasswd``, and the config must be stored in the secret under the key ``htpasswd``, otherwise the secret will be rejected as invalid. | ``string`` | Yes |
|``realm`` | The realm for the basic authentication. | ``string`` | No |
{{% /table %}}

#### BasicAuth Merging Behavior

A VirtualServer/VirtualServerRoute can reference multiple basic auth policies. However, only one can be applied. Every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: basic-auth-policy-one
- name: basic-auth-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `basic-auth-policy-one`, and ignores `basic-auth-policy-two`.

### JWT Using Local Kubernetes Secret

{{< note >}}

This feature is only available with NGINX Plus.

{{< /note >}}

The JWT policy configures NGINX Plus to authenticate client requests using JSON Web Tokens.

The following example policy will reject all requests that do not include a valid JWT in the HTTP header `token`:

```yaml
jwt:
  secret: jwk-secret
  realm: "My API"
  token: $http_token
```

You can pass the JWT claims and JOSE headers to the upstream servers. For example:

```yaml
action:
  proxy:
    upstream: webapp
    requestHeaders:
      set:
      - name: user
        value: ${jwt_claim_user}
      - name: alg
        value: ${jwt_header_alg}
```

We use the `requestHeaders` of the [Action.Proxy](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#actionproxy) to set the values of two headers that NGINX will pass to the upstream servers.

The value of the `${jwt_claim_user}` variable is the `user` claim of a JWT. For other claims, use `${jwt_claim_name}`, where `name` is the name of the claim. Note that nested claims and claims that include a period (`.`) are not supported. Similarly, use `${jwt_header_name}` where `name` is the name of a header. In our example, we use the `alg` header.

{{< note >}}

This feature is implemented using the NGINX Plus [ngx_http_auth_jwt_module](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).

{{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``secret`` | The name of the Kubernetes secret that stores the JWK. It must be in the same namespace as the Policy resource. The secret must be of the type ``nginx.org/jwk``, and the JWK must be stored in the secret under the key ``jwk``, otherwise the secret will be rejected as invalid. | ``string`` | Yes |
|``realm`` | The realm of the JWT. | ``string`` | Yes |
|``token`` | The token specifies a variable that contains the JSON Web Token. By default the JWT is passed in the ``Authorization`` header as a Bearer Token. JWT may be also passed as a cookie or a part of a query string, for example: ``$cookie_auth_token``. Accepted variables are ``$http_``, ``$arg_``, ``$cookie_``. | ``string`` | No |
{{% /table %}}

#### JWT Merging Behavior

A VirtualServer/VirtualServerRoute can reference multiple JWT policies. However, only one can be applied: every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: jwt-policy-one
- name: jwt-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `jwt-policy-one`, and ignores `jwt-policy-two`.

### JWT Using JWKS From Remote Location

{{< note >}}

This feature is only available with NGINX Plus.

{{< /note >}}

The JWT policy configures NGINX Plus to authenticate client requests using JSON Web Tokens, allowing import of the keys (JWKS) for JWT policy by means of a URL (for a remote server or an identity provider) as a result they don't have to be copied and updated to the IC pod.

The following example policy will reject all requests that do not include a valid JWT in the HTTP header fetched from the identity provider:

```yaml
jwt:
  realm: MyProductAPI
  token: $http_token
  jwksURI: <uri_to_remote_server_or_idp>
  keyCache: 1h
```

{{< note >}}

This feature is implemented using the NGINX Plus directive [auth_jwt_key_request](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html#auth_jwt_key_request) under [ngx_http_auth_jwt_module](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).

{{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``jwksURI`` | The remote URI where the request will be sent to retrieve JSON Web Key set| ``string`` | Yes |
|``keyCache`` | Enables in-memory caching of JWKS (JSON Web Key Sets) that are obtained from the ``jwksURI`` and sets a valid time for expiration. | ``string`` | Yes |
|``realm`` | The realm of the JWT. | ``string`` | Yes |
|``token`` | The token specifies a variable that contains the JSON Web Token. By default the JWT is passed in the ``Authorization`` header as a Bearer Token. JWT may be also passed as a cookie or a part of a query string, for example: ``$cookie_auth_token``. Accepted variables are ``$http_``, ``$arg_``, ``$cookie_``. | ``string`` | No |
{{% /table %}}

{{< note >}}

Content caching is enabled by default for each JWT policy with a default time of 12 hours.

This is done to ensure to improve resiliency by allowing the JWKS (JSON Web Key Set) to be retrieved from the cache even when it has expired.

{{< /note >}}

#### JWT Merging Behavior

This behavior is similar to using a local Kubernetes secret where a VirtualServer/VirtualServerRoute can reference multiple JWT policies. However, only one can be applied: every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: jwt-policy-one
- name: jwt-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `jwt-policy-one`, and ignores `jwt-policy-two`.

### IngressMTLS

The IngressMTLS policy configures client certificate verification.

For example, the following policy will verify a client certificate using the CA certificate specified in the `ingress-mtls-secret`:

```yaml
ingressMTLS:
  clientCertSecret: ingress-mtls-secret
  verifyClient: "on"
  verifyDepth: 1
```

Below is an example of the `ingress-mtls-secret` using the secret type `nginx.org/ca`

```yaml
kind: Secret
metadata:
  name: ingress-mtls-secret
apiVersion: v1
type: nginx.org/ca
data:
  ca.crt: <base64encoded-certificate>
```

A VirtualServer that references an IngressMTLS policy must:

- Enable [TLS termination](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#virtualservertls).
- Reference the policy in the VirtualServer [`spec`](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#virtualserver-specification). It is not allowed to reference an IngressMTLS policy in a [`route`](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#virtualserverroute) or in a VirtualServerRoute [`subroute`](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#virtualserverroutesubroute).

If the conditions above are not met, NGINX will send the `500` status code to clients.

You can pass the client certificate details, including the certificate, to the upstream servers. For example:

```yaml
action:
  proxy:
    upstream: webapp
    requestHeaders:
      set:
      - name: client-cert-subj-dn
        value: ${ssl_client_s_dn} # subject DN
      - name: client-cert
        value: ${ssl_client_escaped_cert} # client certificate in the PEM format (urlencoded)
```

We use the `requestHeaders` of the [Action.Proxy](/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#actionproxy) to set the values of the two headers that NGINX will pass to the upstream servers. See the [list of embedded variables](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#variables) that are supported by the `ngx_http_ssl_module`, which you can use to pass the client certificate details.

{{< note >}}

 The feature is implemented using the NGINX [ngx_http_ssl_module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).

 {{< /note >}}

#### Using a Certificate Revocation List

The IngressMTLS policy supports configuring at CRL for your policy.
This can be done in one of two ways.

{{< note >}}

 Only one of these configurations options can be used at a time.

{{< /note >}}

1. Adding the `ca.crl` field to the `nginx.org/ca` secret type, which accepts a base64 encoded certificate revocation list (crl).
   Example YAML:

```yaml
kind: Secret
metadata:
  name: ingress-mtls-secret
apiVersion: v1
type: nginx.org/ca
data:
  ca.crt: <base64encoded-certificate>
  ca.crl: <base64encoded-crl>
```

2. Adding the `crlFileName` field to your IngressMTLS policy spec with the name of the CRL file.

{{< note >}}

This configuration option should only be used when using a CRL that is larger than 1MiB.

Otherwise we recommend using the `nginx.org/ca` secret type for managing your CRL.

{{< /note >}}

Example YAML:

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: ingress-mtls-policy
spec:
ingressMTLS:
    clientCertSecret: ingress-mtls-secret
    crlFileName: webapp.crl
    verifyClient: "on"
    verifyDepth: 1
```

**IMPORTANT NOTE**
When configuring a CRL with the `ingressMTLS.crlFileName` field, there is additional context to keep in mind:

1. NGINX Ingress Controller will expect the CRL, in this case `webapp.crl`, will be in `/etc/nginx/secrets`. A volume mount will need to be added to NGINX Ingress Controller deployment add your CRL to `/etc/nginx/secrets`
2. When updating the content of your CRL (e.g a new certificate has been revoked), NGINX will need to be reloaded to pick up the latest changes. Depending on your environment this may require updating the name of your CRL and applying this update to your `ingress-mtls.yaml` policy to ensure NGINX picks up the latest CRL.

Please refer to the Kubernetes documentation on [volumes](https://kubernetes.io/docs/concepts/storage/volumes/) to find the best implementation for your environment.

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``clientCertSecret`` | The name of the Kubernetes secret that stores the CA certificate. It must be in the same namespace as the Policy resource. The secret must be of the type ``nginx.org/ca``, and the certificate must be stored in the secret under the key ``ca.crt``, otherwise the secret will be rejected as invalid. | ``string`` | Yes |
|``verifyClient`` | Verification for the client. Possible values are ``"on"``, ``"off"``, ``"optional"``, ``"optional_no_ca"``. The default is ``"on"``. | ``string`` | No |
|``verifyDepth`` | Sets the verification depth in the client certificates chain. The default is ``1``. | ``int`` | No |
|``crlFileName`` | The file name of the Certificate Revocation List. NGINX Ingress Controller will look for this file in `/etc/nginx/secrets` | ``string`` | No |
{{% /table %}}

#### IngressMTLS Merging Behavior

A VirtualServer can reference only a single IngressMTLS policy. Every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: ingress-mtls-policy-one
- name: ingress-mtls-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `ingress-mtls-policy-one`, and ignores `ingress-mtls-policy-two`.

### EgressMTLS

The EgressMTLS policy configures upstreams authentication and certificate verification.

For example, the following policy will use `egress-mtls-secret` to authenticate with the upstream application and `egress-trusted-ca-secret` to verify the certificate of the application:

```yaml
egressMTLS:
  tlsSecret: egress-mtls-secret
  trustedCertSecret: egress-trusted-ca-secret
  verifyServer: on
  verifyDepth: 2
```

{{< note >}}

The feature is implemented using the NGINX [ngx_http_proxy_module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).

{{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``tlsSecret`` | The name of the Kubernetes secret that stores the TLS certificate and key. It must be in the same namespace as the Policy resource. The secret must be of the type ``kubernetes.io/tls``, the certificate must be stored in the secret under the key ``tls.crt``, and the key must be stored under the key ``tls.key``, otherwise the secret will be rejected as invalid. | ``string`` | No |
|``trustedCertSecret`` | The name of the Kubernetes secret that stores the CA certificate. It must be in the same namespace as the Policy resource. The secret must be of the type ``nginx.org/ca``, and the certificate must be stored in the secret under the key ``ca.crt``, otherwise the secret will be rejected as invalid. | ``string`` | No |
|``verifyServer`` | Enables verification of the upstream HTTPS server certificate. | ``bool`` | No |
|``verifyDepth`` | Sets the verification depth in the proxied HTTPS server certificates chain. The default is ``1``. | ``int`` | No |
|``sessionReuse`` | Enables reuse of SSL sessions to the upstreams. The default is ``true``. | ``bool`` | No |
|``serverName`` | Enables passing of the server name through ``Server Name Indication`` extension. | ``bool`` | No |
|``sslName`` | Allows overriding the server name used to verify the certificate of the upstream HTTPS server. | ``string`` | No |
|``ciphers`` | Specifies the enabled ciphers for requests to an upstream HTTPS server. The default is ``DEFAULT``. | ``string`` | No |
|``protocols`` | Specifies the protocols for requests to an upstream HTTPS server. The default is ``TLSv1 TLSv1.1 TLSv1.2``. | ``string`` | No | > Note: the value of ``ciphers`` and ``protocols`` is not validated by NGINX Ingress Controller. As a result, NGINX can fail to reload the configuration. To ensure that the configuration for a VirtualServer/VirtualServerRoute that references the policy was successfully applied, check its [status](/nginx-ingress-controller/configuration/global-configuration/reporting-resources-status/#virtualserver-and-virtualserverroute-resources). The validation will be added in the future releases. |
{{% /table %}}

#### EgressMTLS Merging Behavior

A VirtualServer/VirtualServerRoute can reference multiple EgressMTLS policies. However, only one can be applied. Every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: egress-mtls-policy-one
- name: egress-mtls-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `egress-mtls-policy-one`, and ignores `egress-mtls-policy-two`.

### OIDC

{{< tip >}}

This feature is disabled by default. To enable it, set the [enable-oidc]({{< relref "configuration/global-configuration/command-line-arguments.md#cmdoption-enable-oidc" >}}) command-line argument of NGINX Ingress Controller.

{{< /tip >}}

The OIDC policy configures NGINX Plus as a relying party for OpenID Connect authentication.

For example, the following policy will use the client ID `nginx-plus` and the client secret `oidc-secret` to authenticate with the OpenID Connect provider `https://idp.example.com`:

```yaml
spec:
  oidc:
    clientID: nginx-plus
    clientSecret: oidc-secret
    authEndpoint: https://idp.example.com/openid-connect/auth
    tokenEndpoint: https://idp.example.com/openid-connect/token
    jwksURI: https://idp.example.com/openid-connect/certs
    endSessionEndpoint: https://idp.example.com/openid-connect/logout
    postLogoutRedirectURI: /
    accessTokenEnable: true
    pkceEnable: false
```

NGINX Plus will pass the ID of an authenticated user to the backend in the HTTP header `username`.

{{< note >}}

The feature is implemented using the [reference implementation](https://github.com/nginxinc/nginx-openid-connect/) of NGINX Plus as a relying party for OpenID Connect authentication.

{{< /note >}}

#### Prerequisites

In order to use OIDC, you need to enable [zone synchronization](https://docs.nginx.com/nginx/admin-guide/high-availability/zone_sync/). If you don't set up zone synchronization, NGINX Plus will fail to reload.
You also need to configure a resolver, which NGINX Plus will use to resolve the IDP authorization endpoint. You can find an example configuration [in our GitHub repository](https://github.com/nginx/kubernetes-ingress/blob/v{{< nic-version >}}/examples/custom-resources/oidc#step-7---configure-nginx-plus-zone-synchronization-and-resolver).

{{< warning >}}

The configuration in the example doesn't enable TLS and the synchronization between the replica happens in clear text. This could lead to the exposure of tokens.

{{< /warning >}}

#### Limitations

The OIDC policy defines a few internal locations that can't be customized: `/_jwks_uri`, `/_token`, `/_refresh`, `/_id_token_validation`, `/logout`. In addition, as explained below, `/_codexch` is the default value for redirect URI, and `/_logout` is the default value for post logout redirect URI, both of which can be customized. Specifying one of these locations as a route in the VirtualServer or VirtualServerRoute will result in a collision and NGINX Plus will fail to reload.

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``clientID`` | The client ID provided by your OpenID Connect provider. | ``string`` | Yes |
|``clientSecret`` | The name of the Kubernetes secret that stores the client secret provided by your OpenID Connect provider. It must be in the same namespace as the Policy resource. The secret must be of the type ``nginx.org/oidc``, and the secret under the key ``client-secret``, otherwise the secret will be rejected as invalid. If PKCE is enabled, this should be not configured. | ``string`` | Yes |
|``authEndpoint`` | URL for the authorization endpoint provided by your OpenID Connect provider. | ``string`` | Yes |
|``authExtraArgs`` | A list of extra URL arguments to pass to the authorization endpoint provided by your OpenID Connect provider. Arguments must be URL encoded, multiple arguments may be included in the list, for example ``[ arg1=value1, arg2=value2 ]`` | ``string[]`` | No |
|``tokenEndpoint`` | URL for the token endpoint provided by your OpenID Connect provider. | ``string`` | Yes |
|``endSessionEndpoint`` | URL provided by your OpenID Connect provider to request the end user be logged out. | ``string`` | No |
|``jwksURI`` | URL for the JSON Web Key Set (JWK) document provided by your OpenID Connect provider. | ``string`` | Yes |
|``scope`` | List of OpenID Connect scopes. The scope ``openid`` always needs to be present and others can be added concatenating them with a ``+`` sign, for example ``openid+profile+email``, ``openid+email+userDefinedScope``. The default is ``openid``. | ``string`` | No |
|``redirectURI`` | Allows overriding the default redirect URI. The default is ``/_codexch``. | ``string`` | No |
|``postLogoutRedirectURI`` | URI to redirect to after the logout has been performed. Requires ``endSessionEndpoint``. The default is ``/_logout``. | ``string`` | No |
|``zoneSyncLeeway`` | Specifies the maximum timeout in milliseconds for synchronizing ID/access tokens and shared values between Ingress Controller pods. The default is ``200``. | ``int`` | No |
|``accessTokenEnable`` | Option of whether Bearer token is used to authorize NGINX to access protected backend. | ``boolean`` | No |
|``pkceEnable`` | Switches Proof Key for Code Exchange on. The OpenID client needs to be in public mode. `clientSecret` is not used in this mode. | ``boolean`` | No |
{{% /table %}}

{{< note >}}

Only one OIDC policy can be referenced in a VirtualServer and its VirtualServerRoutes. However, the same policy can still be applied to different routes in the VirtualServer and VirtualServerRoutes.

{{< /note >}}

#### OIDC Merging Behavior

A VirtualServer/VirtualServerRoute can reference only a single OIDC policy. Every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: oidc-policy-one
- name: oidc-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `oidc-policy-one`, and ignores `oidc-policy-two`.

## Using Policy

You can use the usual `kubectl` commands to work with Policy resources, just as with built-in Kubernetes resources.

For example, the following command creates a Policy resource defined in `access-control-policy-allow.yaml` with the name `webapp-policy`:

```shell
kubectl apply -f access-control-policy-allow.yaml

policy.k8s.nginx.org/webapp-policy configured
```

You can get the resource by running:

```shell
kubectl get policy webapp-policy

NAME            AGE
webapp-policy   27m
```

For `kubectl get` and similar commands, you can also use the short name `pol` instead of `policy`.

### WAF {#waf}

{{< note >}} The feature is implemented using the NGINX Plus [NGINX App Protect WAF Module](https://docs.nginx.com/nginx-app-protect/configuration/). {{< /note >}}

The WAF policy configures NGINX Plus to secure client requests using App Protect WAF policies.

For example, the following policy will enable the referenced APPolicy. You can configure multiple APLogConfs with log destinations:

```yaml
waf:
  enable: true
  apPolicy: "default/dataguard-alarm"
  securityLogs:
  - enable: true
    apLogConf: "default/logconf"
    logDest: "syslog:server=syslog-svc.default:514"
  - enable: true
    apLogConf: "default/logconf"
    logDest: "syslog:server=syslog-svc-secondary.default:514"
```

{{< note >}} The field `waf.securityLog` is deprecated and will be removed in future releases.It will be ignored if `waf.securityLogs` is populated. {{< /note >}}

{{% table %}}
|Field | Description | Type | Required |
| ---| ---| ---| --- |
|``enable`` | Enables NGINX App Protect WAF. | ``bool`` | Yes |
|``apPolicy`` | The [App Protect WAF policy]({{< relref "installation/integrations/app-protect-waf/configuration.md#waf-policies" >}}) of the WAF. Accepts an optional namespace. Mutually exclusive with ``apBundle``. | ``string`` | No |
|``apBundle`` | The [App Protect WAF policy bundle]({{< relref "installation/integrations/app-protect-waf/configuration.md#waf-bundles" >}}). Mutually exclusive with ``apPolicy``. | ``string`` | No |
|``securityLog.enable`` | Enables security log. | ``bool`` | No |
|``securityLog.apLogConf`` | The [App Protect WAF log conf]({{< relref "installation/integrations/app-protect-waf/configuration.md#waf-logs" >}}) resource. Accepts an optional namespace. Only works with ``apPolicy``. | ``string`` | No |
|``securityLog.apLogBundle`` | The [App Protect WAF log bundle]({{< relref "installation/integrations/app-protect-waf/configuration.md#waf-bundles" >}}) resource. Only works with ``apBundle``. | ``string`` | No |
|``securityLog.logDest`` | The log destination for the security log. Only accepted variables are ``syslog:server=<ip-address &#124; localhost; fqdn>:<port>``, ``stderr``, ``<absolute path to file>``. | ``string`` | No |
{{% /table %}}

#### WAF Merging Behavior

A VirtualServer/VirtualServerRoute can reference multiple WAF policies. However, only one can be applied. Every subsequent reference will be ignored. For example, here we reference two policies:

```yaml
policies:
- name: waf-policy-one
- name: waf-policy-two
```

In this example NGINX Ingress Controller will use the configuration from the first policy reference `waf-policy-one`, and ignores `waf-policy-two`.

### Applying Policies

You can apply policies to both VirtualServer and VirtualServerRoute resources. For example:

- VirtualServer:

    ```yaml
    apiVersion: k8s.nginx.org/v1
    kind: VirtualServer
    metadata:
      name: cafe
      namespace: cafe
    spec:
      host: cafe.example.com
      tls:
        secret: cafe-secret
      policies: # spec policies
      - name: policy1
      upstreams:
      - name: coffee
        service: coffee-svc
        port: 80
      routes:
      - path: /tea
        policies: # route policies
        - name: policy2
          namespace: cafe
        route: tea/tea
      - path: /coffee
        policies: # route policies
        - name: policy3
          namespace: cafe
        action:
          pass: coffee
      ```

      For VirtualServer, you can apply a policy:
  * to all routes (spec policies)
  * to a specific route (route policies)

      Route policies of the *same type* override spec policies. In the example above, if the type of the policies `policy-1` and `policy-3` is `accessControl`, then for requests to `cafe.example.com/coffee`, NGINX will apply `policy-3`.

      The overriding is enforced by NGINX: the spec policies are implemented in the `server` context of the config, and the route policies are implemented in the `location` context. As a result, the route policies of the same type win.

- VirtualServerRoute, which is referenced by the VirtualServer above:

    ```yaml
    apiVersion: k8s.nginx.org/v1
    kind: VirtualServerRoute
    metadata:
      name: tea
      namespace: tea
    spec:
      host: cafe.example.com
      upstreams:
      - name: tea
        service: tea-svc
        port: 80
      subroutes: # subroute policies
      - path: /tea
        policies:
        - name: policy4
          namespace: tea
        action:
          pass: tea
    ```

    For VirtualServerRoute, you can apply a policy to a subroute (subroute policies).

    Subroute policies of the same type override spec policies. In the example above, if the type of the policies `policy-1` (in the VirtualServer) and `policy-4` is `accessControl`, then for requests to `cafe.example.com/tea`, NGINX will apply `policy-4`. As with the VirtualServer, the overriding is enforced by NGINX.

    Subroute policies always override route policies no matter the types. For example, the policy `policy-2` in the VirtualServer route will be ignored for the subroute `/tea`, because the subroute has its own policies (in our case, only one policy `policy4`). If the subroute didn't have any policies, then the `policy-2` would be applied. This overriding is enforced by NGINX Ingress Controller -- the `location` context for the subroute will either have route policies or subroute policies, but not both.

### Invalid Policies

NGINX will treat a policy as invalid if one of the following conditions is met:

- The policy doesn't pass the [comprehensive validation](#comprehensive-validation).
- The policy isn't present in the cluster.
- The policy doesn't meet its type-specific requirements. For example, an `ingressMTLS` policy requires TLS termination enabled in the VirtualServer.

For an invalid policy, NGINX returns the 500 status code for client requests with the following rules:

- If a policy is referenced in a VirtualServer `route` or a VirtualServerRoute `subroute`, then NGINX will return the 500 status code for requests for the URIs of that route/subroute.
- If a policy is referenced in the VirtualServer `spec`, then NGINX will return the 500 status code for requests for all URIs of that VirtualServer.

If a policy is invalid, the VirtualServer or VirtualServerRoute will have the [status](/nginx-ingress-controller/configuration/global-configuration/reporting-resources-status#virtualserver-and-virtualserverroute-resources) with the state `Warning` and the message explaining why the policy wasn't considered invalid.

### Validation

Two types of validation are available for the Policy resource:

- *Structural validation*, done by `kubectl` and the Kubernetes API server.
- *Comprehensive validation*, done by NGINX Ingress Controller.

#### Structural Validation

The custom resource definition for the Policy includes a structural OpenAPI schema, which describes the type of every field of the resource.

If you try to create (or update) a resource that violates the structural schema -- for example, the resource uses a string value instead of an array of strings in the `allow` field -- `kubectl` and the Kubernetes API server will reject the resource.

- Example of `kubectl` validation:

    ```shell
    kubectl apply -f access-control-policy-allow.yaml

    error: error validating "access-control-policy-allow.yaml": error validating data: ValidationError(Policy.spec.accessControl.allow): invalid type for org.nginx.k8s.v1.Policy.spec.accessControl.allow: got "string", expected "array"; if you choose to ignore these errors, turn validation off with --validate=false
    ```

- Example of Kubernetes API server validation:

    ```shell
    kubectl apply -f access-control-policy-allow.yaml --validate=false

    The Policy "webapp-policy" is invalid: spec.accessControl.allow: Invalid value: "string": spec.accessControl.allow in body must be of type array: "string"
    ```

If a resource passes structural validation, then NGINX Ingress Controller's comprehensive validation runs.

#### Comprehensive Validation

NGINX Ingress Controller validates the fields of a Policy resource. If a resource is invalid, NGINX Ingress Controller will reject it. The resource will continue to exist in the cluster, but NGINX Ingress Controller will ignore it.

You can use `kubectl` to check whether or not NGINX Ingress Controller successfully applied a Policy configuration. For our example `webapp-policy` Policy, we can run:

```shell
kubectl describe pol webapp-policy

. . .
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  11s   nginx-ingress-controller  Policy default/webapp-policy was added or updated
```

Note how the events section includes a Normal event with the AddedOrUpdated reason that informs us that the configuration was successfully applied.

If you create an invalid resource, NGINX Ingress Controller will reject it and emit a Rejected event. For example, if you create a Policy `webapp-policy` with an invalid IP `10.0.0.` in the `allow` field, you will get:

```shell
kubectl describe policy webapp-policy

. . .
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  7s    nginx-ingress-controller  Policy default/webapp-policy is invalid and was rejected: spec.accessControl.allow[0]: Invalid value: "10.0.0.": must be a CIDR or IP
```

Note how the events section includes a Warning event with the Rejected reason.

Additionally, this information is also available in the `status` field of the Policy resource. Note the Status section of the Policy:

```shell
kubectl describe pol webapp-policy

. . .
Status:
  Message:  Policy default/webapp-policy is invalid and was rejected: spec.accessControl.allow[0]: Invalid value: "10.0.0.": must be a CIDR or IP
  Reason:   Rejected
  State:    Invalid
```

**Note**: If you make an existing resource invalid, NGINX Ingress Controller will reject it.
