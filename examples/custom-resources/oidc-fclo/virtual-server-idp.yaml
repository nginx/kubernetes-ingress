apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: keycloak
spec:
  host: keycloak.example.com
  tls:
    secret: tls-secret
    redirect:
      enable: true
  upstreams:
    - name: keycloak
      service: keycloak
      port: 8080
  routes:
    - path: /
      action:
        pass: keycloak
