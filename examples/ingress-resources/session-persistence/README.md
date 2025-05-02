# Session Persistence

It is often required that the requests from a client are always passed to the same backend container. You can enable
such behavior with [Session Persistence](https://www.nginx.com/products/session-persistence/), available in the NGINX
Plus Ingress Controller.

NGINX Plus supports *the sticky cookie* method. With this method, NGINX Plus adds a session cookie to the first response
from the backend container, identifying the container that sent the response. When a client issues the next request, it
will send the cookie value and NGINX Plus will route the request to the same container.

## Syntax

To enable session persistence for one or multiple services, add the **nginx.com/sticky-cookie-services** annotation to
your Ingress resource definition. The annotation specifies services that should have session persistence enabled as well
as various attributes of the cookie. The annotation syntax is as follows:

```yaml
nginx.com/sticky-cookie-services: "service1[;service2;...]"
```

Here each service follows the following syntactic rule:

```text
serviceName=serviceName cookieName [expires=time] [domain=domain] [httponly] [secure] [path=path]
```

The syntax of the *cookieName*, *expires*, *domain*, *httponly*, *secure* and *path* parameters is the same as for the
[sticky directive](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#sticky) in the NGINX Plus configuration.

## Example

In the following example we enable session persistence for two services -- the *tea-svc* service and the *coffee-svc*
service:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cafe-ingress-with-session-persistence
  annotations:
    nginx.com/sticky-cookie-services: "serviceName=coffee-svc srv_id expires=1h path=/coffee;serviceName=tea-svc srv_id expires=2h path=/tea"
spec:
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

For both services, the sticky cookie has the same *srv_id* name. However, we specify the different values of expiration
time and  a path.

## Notes

Session persistence **works** even in the case where you have more than one replicas of the NGINX Plus Ingress
Controller running.

## Advanced Session Persistence

The NGINX Plus Ingress Controller supports only one of the three session persistence methods available in NGINX Plus.
Visit [this page](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-load-balancer/#enabling-session-persistence) to learn about all of the methods. If your
session persistence requirements are more complex than the ones in the example above, you will have to use a different
approach to deploying and configuring NGINX Plus without the Ingress Controller. You can read the [Load Balancing
Kubernetes Services with NGINX Plus](https://www.nginx.com/blog/load-balancing-kubernetes-services-nginx-plus/) blog
post to find out more.
