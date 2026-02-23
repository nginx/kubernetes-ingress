# Support for Access Control policy in Ingress

This example demonstrates how to use the Access Control policy in Ingress to restrict access to specific paths.

The example consists of the following example Ingress resources:

- AccessControl Allow policy:

  ```yaml
    apiVersion: k8s.nginx.org/v1
    kind: Policy
    metadata:
      name: webapp-policy-allow
    spec:
      accessControl:
      allow:
        - 10.0.0.0/8
  ```

- AccessControl Deny policy:

  ```yaml
    apiVersion: k8s.nginx.org/v1
    kind: Policy
    metadata:
      name: webapp-policy-deny
    spec:
      accessControl:
      allow:
        - 10.1.1.0/8
  ```

- Ingress resource that references the above policies:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress
  annotations:
    nginx.org/policies: "webapp-policy-allow, webapp-policy-deny"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - cafe.example.com
    secretName: tls-secret
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
      - path: /coffee
        pathType: Prefix
        backend:
          service:
            name: coffee-svc
            port:
              number: 80
  ```

In this example, the Access Control policy allows access for clients with IP addresses in the `10.0.0.1/8` range,
while access is denied for clients with IP addresses in the `10.1.1.0/8` range.

***Clients with IP addresses outside of these ranges will be denied access to both paths.***
