# Support for JSON Web Tokens (JWTs)

NGINX Plus supports validating JWTs with
[ngx_http_auth_jwt_module](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html).

The Ingress Controller provides the following 4 annotations for configuring JWT validation:

- Required: ```nginx.com/jwt-key: "secret"``` -- specifies a Secret resource with keys for validating JWTs. The keys
  must be stored in the `jwk` data field. The type of the secret can be `Opaque` or `nginx.org/jwk`.
- Optional: ```nginx.com/jwt-realm: "realm"``` -- specifies a realm.
- Optional: ```nginx.com/jwt-token: "token"``` -- specifies a variable that contains JSON Web Token. By default, a JWT
  is expected in the `Authorization` header as a Bearer Token.
- Optional: ```nginx.com/jwt-login-url: "url"``` -- specifies a URL to which a client is redirected in case of an
  invalid or missing JWT.

## Example 1: the Same JWT Key for All Paths

In the following example we enable JWT validation for the cafe-ingress Ingress for all paths using the same key
`cafe-jwk`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress
  annotations:
    nginx.com/jwt-key: "cafe-jwk"
    nginx.com/jwt-realm: "Cafe App"
    nginx.com/jwt-token: "$cookie_auth_token"
    nginx.com/jwt-login-url: "https://login.example.com"
spec:
  tls:
  - hosts:
    - cafe.example.com
    secretName: cafe-secret
  rules:
  - host: cafe.example.com
    http:
      paths:
      - path: /tea
        backend:
          serviceName: tea-svc
          servicePort: 80
      - path: /coffee
        backend:
          serviceName: coffee-svc
          servicePort: 80
```

- The keys must be deployed separately in the Secret `cafe-jwk`.
- The realm is  `Cafe App`.
- The token is extracted from the `auth_token` cookie.
- The login URL is `https://login.example.com`.

## Example 2: a Separate JWT Key Per Path

In the following example we enable JWT validation for the [mergeable Ingresses](../mergeable-ingress-types) with a
separate JWT key per path:

- Master:

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: cafe-ingress-master
    annotations:
      nginx.org/mergeable-ingress-type: "master"
  spec:
    ingressClassName: nginx
    tls:
    - hosts:
      - cafe.example.com
      secretName: cafe-secret
    rules:
    - host: cafe.example.com
  ```

- Tea minion:

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: cafe-ingress-tea-minion
    annotations:
      nginx.org/mergeable-ingress-type: "minion"
      nginx.com/jwt-key: "tea-jwk"
      nginx.com/jwt-realm: "Tea"
      nginx.com/jwt-token: "$cookie_auth_token"
      nginx.com/jwt-login-url: "https://login-tea.cafe.example.com"
  spec:
    ingressClassName: nginx
    rules:
    - host: cafe.example.com
      http:
        paths:
        - path: /tea
          pathType: Prefix
          backend:
            service:
              name: tea-svc
              port:
                number: 80
  ```

- Coffee minion:

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: cafe-ingress-coffee-minion
    annotations:
      nginx.org/mergeable-ingress-type: "minion"
      nginx.com/jwt-key: "coffee-jwk"
      nginx.com/jwt-realm: "Coffee"
      nginx.com/jwt-token: "$cookie_auth_token"
      nginx.com/jwt-login-url: "https://login-coffee.cafe.example.com"
  spec:
    ingressClassName: nginx
    rules:
    - host: cafe.example.com
      http:
        paths:
        - path: /coffee
          pathType: Prefix
          backend:
            service:
              name: coffee-svc
              port:
                number: 80
  ```
