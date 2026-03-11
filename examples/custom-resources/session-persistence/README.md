# Session Persistence

*As of NGINX 1.29.6 this feature is also available in NGINX OSS.*

It is often required that the requests from a client are always passed to the same backend container. You can enable
such behavior with [Session Persistence](https://www.nginx.com/products/session-persistence/), available in the NGINX
Plus Ingress Controller.

NGINX supports *the sticky cookie* method. With this method, NGINX adds a session cookie to the first response
from the backend container, identifying the container that sent the response. When a client issues the next request, it
will send the cookie value and NGINX will route the request to the same container.

## Syntax

To enable session persistence for one or multiple services, configure the sessionCookie block of the upstream definition
for the particular service. The annotation specifies services that should have session persistence enabled as well as
various attributes of the cookie. The annotation syntax is as follows:

See the [sticky directive](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#sticky) in the NGINX Plus
configuration.

## Example

In the following example we enable session persistence for two services -- the *tea-svc* service and the *coffee-svc*
service:

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: cafe
spec:
  host: cafe.example.com
  tls:
    secret: cafe-secret
  upstreams:
  - name: tea
    service: tea-svc
    port: 80
    sessionCookie:
      enable: true
      name: srv_id
      path: /tea
      expires: 2h
  - name: coffee
    service: coffee-svc
    port: 80
    sessionCookie:
      enable: true
      name: srv_id
      path: /coffee
      expires: 1h
  routes:
  - path: /tea
    action:
      pass: tea
  - path: /coffee
    action:
      pass: coffee
```

For both services, the sticky cookie has the same *srv_id* name. However, we specify the different values of expiration
time and path.

### Deploy the example

```shell
kubectl apply -f examples/custom-resources/session-persistence/cafe-vs-with-session-cookie.yml
```

Check the nginx configuration to verify that the session cookie is configured correctly:

```shell
~ $> kubectl exec -it <nginx-plus-ingress-controller-pod> -- cat /etc/nginx/conf.d/vs_default_cafe.conf

upstream vs_default_cafe_coffee {
    random two least_conn;
    server 10.244.0.38:8080 max_fails=1 fail_timeout=10s max_conns=0;
    server 10.244.0.40:8080 max_fails=1 fail_timeout=10s max_conns=0;
    sticky cookie srv_id expires=1h path=/coffee;
}

upstream vs_default_cafe_tea {
    random two least_conn;
    server 10.244.0.39:8080 max_fails=1 fail_timeout=10s max_conns=0;
    server 10.244.0.41:8080 max_fails=1 fail_timeout=10s max_conns=0;
    server 10.244.0.42:8080 max_fails=1 fail_timeout=10s max_conns=0;
    sticky cookie srv_id expires=2h path=/tea;
}

server {
  ...
```

## Notes

Session persistence **works** even in the case where you have more than one replicas of the NGINX Ingress
Controller running.
