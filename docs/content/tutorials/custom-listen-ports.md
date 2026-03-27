---
title: Customizing NGINX Ingress Controller Ports
description: |
  How to customize F5 NGINX Ingress Controller ports.
weight: 1800
doctypes: ["concept"]
toc: true
---
## Customizing NGINX Ingress Controller Ports

This document explains how to change the default ports that NGINX Ingress Controller is configured to use, as well as how to add additional `listen` settings. For more information, please read the [NGINX Listen documentation](http://nginx.org/en/docs/http/ngx_http_core_module.html#listen).

## Changing Default Ports

By default, NGINX Ingress Controller listens on ports 80 and 443. These ports can be changed easily, but modifying the `listen` ports for your NGINX Ingress resources will require the editing of `.tmpl` files.

If you are using NGINX Ingress Controller CRDs (VirtualServer):

- `nginx-plus-virtualserver.tmpl` for NGINX Plus
- `nginx-virtualserver.tmpl` if using NGINX OSS

If you are using `Ingress` resource you will need to modify:

- `nginx-plus-ingress.tmpl` if using NGINX Plus
- `nginx-ingress.tmpl` if using NGINX OSS

In this example, we will use the `nginx-virtualserver.tmpl` template to change the port from 80 to 85.
You can find the [nginx-virtualserver template files in our repository](https://github.com/nginxinc/kubernetes-ingress/tree/main/internal/configs/version2).

We start by modifying `nginx-virtualserver.tmpl` to change the port setting:

```nginx
server {
    listen 80{{ if $s.ProxyProtocol }} proxy_protocol{{ end }};

    server_name {{ $s.ServerName }};

    set $resource_type "virtualserver";
    set $resource_name "{{$s.VSName}}";
    set $resource_namespace "{{$s.VSNamespace}}";
```

To change the listen port from `80` to `85`, edit the `listen` line at the start of the server configuration block.

After changing the number, the file looks like this:

```nginx
server {
    listen 85{{ if $s.ProxyProtocol }} proxy_protocol{{ end }};

    server_name {{ $s.ServerName }};

    set $resource_type "virtualserver";
    set $resource_name "{{$s.VSName}}";
    set $resource_namespace "{{$s.VSNamespace}}";
```

Modify the file you need (per the example above). In the example, we modified `nginx-plus-virtualserver.tmpl`:

## Rebuild the NGINX Ingress Controller image

You must rebuild the NGINX Ingress Controller image for the new port settings to take effect.
Once the image is built and pushed, make sure you update your deployment to point to the new image and deploy.
Once deployed, create a new `VirtualServer` resource and run `nginx -T` to confirm if the port change has taken effect.

Ensure that your `Deployment` and your `Service` match up to the new port you configured in the templates.
Below is an example of  `Deployment` and `Service` matching to the new port that NGINX Ingress Controller now listens on.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-ingress
  namespace: nginx-ingress
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-ingress
  template:
    metadata:
      labels:
        app: nginx-ingress
      annotations:
       prometheus.io/scrape: "true"
       prometheus.io/port: "9113"
       prometheus.io/scheme: http
    spec:
      serviceAccountName: nginx-ingress
      containers:
      - image: nginx/nginx-ingress:3.3.2
        imagePullPolicy: IfNotPresent
        name: nginx-ingress
        ports:
        - name: http
          containerPort: 85
        - name: https
          containerPort: 443
        - name: readiness-port
          containerPort: 8081
        - name: prometheus
          containerPort: 9113
        readinessProbe:
          httpGet:
            path: /nginx-ready
            port: readiness-port
          periodSeconds: 1
        securityContext:
```

Notice that now, the `http` port is set to `85`, which reflects the change we made in the template file.

Here is the `service` file:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-ingress
  namespace: nginx-ingress
spec:
  externalTrafficPolicy: Local
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 85
    protocol: TCP
    name: http
  - port: 8443
    targetPort: 8443
    protocol: TCP
    name: https
  selector:
    app: nginx-ingress
```

Since NGINX Ingress Controller is now listening on ports 85 and 8443, you must modify the `targetPort` in the NGINX Ingress Controller service to match the change in the deployment to ensure traffic will be sent to the proper port.

The parameter to change above is `targetPort`. Since we have changed NGINX Ingress Controller to listen on port 85, we need to match that in the service: requests will be sent to NGINX Ingress Controller on port 85 instead of the default value, port 80.

If you view the `NGINX` configuration .conf file using `nginx -T`, you should see the port you defined in the .template file is now set on the `listen` line.

Here is an example output of the `NGINX` configuration that has been generated:

```console
kubectl exec -it -n nginx-ingress nginx-ingress-54bffd78d9-v7bns -- nginx -T
```

```nginx
server {
    listen 85;
    listen [::]:85;
    listen 8011;

    server_name cafe.example.com;

    set $resource_type "virtualserver";
    set $resource_name "cafe";
    set $resource_namespace "default";
```
