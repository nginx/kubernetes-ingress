apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: webapp
spec:
  host: webapp.example.com
  tls:
    secret: tls-secret
    redirect:
      enable: true
  upstreams:
    - name: webapp
      service: webapp-svc
      port: 80
  routes:
    - path: /
      policies:
      - name: oidc-policy
      action:
        pass: webapp
