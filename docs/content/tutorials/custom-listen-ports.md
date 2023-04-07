## Customizing the `listen` line in NGINX Ingress Controller.

This document will explain how to change the default ports that NGINX Ingress Controller is configured for, as well as add additional `listen` settings. For more information, please read the [NGINX Listen documentation](http://nginx.org/en/docs/http/ngx_http_core_module.html#listen).


## Changing Default Ports

By default, NGINX Ingress Controller listens on ports 80 and 443. These ports can be changed easily, but modifying the `listen` ports for your NGINX Ingress resources will require the editing of .tmpl files.

If you are using `ingress` resource you will need to modify:
- `nginx-plus-ingress.tmpl` if using NGINX Plus
- `nginx-ingress.tmpl` if using NGINX OSS

If you are using NGINX Ingress Controller CRDs (virtualServer):
- `nginx-plus-virtualserver.tmpl` for NGINX Plus
- `nginx-virtualserver.tmpl` if using NGINX OSS

For this example, we are going to use the `nginx-virtualserver.tmpl` to change the port from 80 to 85. [nginx-virtualserver template files](https://github.com/nginxinc/kubernetes-ingress/tree/main/internal/configs/version2)   

Here we modify `nginx-virtualserver.tmpl` to change the port setting:

```
server {
    listen 80{{ if $s.ProxyProtocol }} proxy_protocol{{ end }};

    server_name {{ $s.ServerName }};

    set $resource_type "virtualserver";
    set $resource_name "{{$s.VSName}}";
    set $resource_namespace "{{$s.VSNamespace}}";
```
To change the listen port from `80` to `85`, we modify the `listen` line at the start of the server configuration block.

It would then look like this:
```
server {
    listen 85{{ if $s.ProxyProtocol }} proxy_protocol{{ end }};

    server_name {{ $s.ServerName }};

    set $resource_type "virtualserver";
    set $resource_name "{{$s.VSName}}";
    set $resource_namespace "{{$s.VSNamespace}}";
```

Edit the file you need (per the example above). In my case, I edited, `nginx-plus-virtualserver.tmpl`:


## Rebuild your NGINX Ingress controller image

You will need to build your new NGINX Ingress controller image for the new port settings to take affect.
Once the image is built and pushed, make sure you update your deployment to point to the new image and deploy.
Once deployed, create a new `virtualServer` resource and then run `nginx -T` to see if the port takes affect.

Ensure that your `deployment` and your `service` match up to the new port you configured in the templates.
Here is simple example of my `deployment` and my `service` matching to the new port that NGINX Ingress controller now listens on.

```
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
      - image: nginx/nginx-ingress:3.0.2
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

Notice that now, my `http` port is set to `85`, which reflects the change I made in the template file.

Here is my `service` file:

```
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

Since NGINX Ingress controller is now listening on ports 85 and 8443, we modify the `targetPort` in the NGINX Ingress controller service, to match what we have changed in our deployment, to ensure traffic will be sent to the proper port.
The key part above is the `targetPort` section. Since I change NGINX Ingress to listen on port 85, I need to match that in the service. That way, requests will be sent to NGINX Ingress controller on port 85 instead of the default value which is port 80.


If you view the `NGINX` configuration .conf file using `nginx -T`, you should see the port you defined in the .template file, now is set on the `listen` line.

```
server {
    listen 85;
    listen [::]:85;
    listen 8011;
```
