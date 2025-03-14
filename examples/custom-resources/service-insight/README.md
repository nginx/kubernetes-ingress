# Support for Service Insight

  > The Service Insight feature is available only for F5 NGINX Plus.

To use the [Service Insight](https://docs.nginx.com/nginx-ingress-controller/logging-and-monitoring/service-insight/)
feature provided by F5 NGINX Ingress Controller you must enable it by setting `serviceInsight.create=true` in your `helm
install/upgrade...` command OR  [manifest](../../../deployments/deployment/nginx-plus-ingress.yaml) depending on your
preferred installation method.

The following example demonstrates how to enable the Service Insight for NGINX Ingress Controller using [manifests
(Deployment)](../../../deployments/deployment/nginx-plus-ingress.yaml):

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
        app.kubernetes.io/name: nginx-ingress
    spec:
      serviceAccountName: nginx-ingress
      automountServiceAccountToken: true
      securityContext:
      ...
      containers:
      - image: nginx-plus-ingress:4.0.1
        imagePullPolicy: IfNotPresent
        name: nginx-plus-ingress
        ports:
        - name: http
          containerPort: 80
        - name: https
          containerPort: 443
        - name: readiness-port
          containerPort: 8081
        - name: prometheus
          containerPort: 9113
        - name: service-insight
          containerPort: 9114
        readinessProbe:
          httpGet:
            path: /nginx-ready
            port: readiness-port
          periodSeconds: 1
        resources:
        ...
        securityContext:
        ...
        env:
        ...
        args:
          - -nginx-plus
          - -nginx-configmaps=$(POD_NAMESPACE)/nginx-config
        ...
          - -enable-service-insight

```

## Deployment

[Install NGINX Ingress
Controller](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), and uncomment
the `-enable-service-insight` option: this will allow Service Insight to interact with it.

The examples below use the `nodeport` service.

## Configuration

First, get the pod name in namespace `nginx-ingress`:

```console
kubectl get pods -n nginx-ingress
```

```text
NAME                             READY   STATUS    RESTARTS   AGE
nginx-ingress-5b99f485fb-vflb8   1/1     Running   0          72m
```

Using the id, forward the service insight port (9114) to localhost port 9114:

```console
kubectl port-forward -n nginx-ingress nginx-ingress-5b99f485fb-vflb8 9114:9114
```

## Virtual Servers

### Deployment

Follow the [basic configuration example](../basic-configuration/) to deploy `cafe` app and `cafe virtual server`.

### Testing

Verify that the virtual server is running, and check the hostname:

```text
kubectl get vs cafe
NAME   STATE   HOST               IP    PORTS   AGE
cafe   Valid   cafe.example.com                 16m
```

Scale down the `tea` and `coffee` deployments:

```console
kubectl scale deployment tea --replicas=1
```

```console
kubectl scale deployment coffee --replicas=1
```

Verify `tea` deployment:

```console
kubectl get deployments.apps tea
```

```text
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
tea    1/1     1            1           19m
```

Verify `coffee` deployment:

```console
kubectl get deployments.apps coffee
```

```text
NAME     READY   UP-TO-DATE   AVAILABLE   AGE
coffee   1/1     1            1           20m
```

Send a `GET` request to the service insight endpoint to check statistics:

Request:

```console
curl http://localhost:9114/probe/cafe.example.com
```

Response:

```json
{"Total":2,"Up":2,"Unhealthy":0}
```

Scale up deployments:

```console
kubectl scale deployment tea --replicas=3
```

```console
kubectl scale deployment coffee --replicas=3
```

Verify deployments:

```console
kubectl get deployments.apps tea
```

```text
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
tea    3/3     3            3           31m
```

```console
kubectl get deployments.apps coffee
```

```text
NAME     READY   UP-TO-DATE   AVAILABLE   AGE
coffee   3/3     3            3           31m
```

Send a `GET` HTTP request to the service insight endpoint to check statistics:

```console
curl http://localhost:9114/probe/cafe.example.com
```

Response:

```json
{"Total":6,"Up":6,"Unhealthy":0}
```

## Transport Servers

[Install NGINX Ingress
Controller](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), and uncomment
the `-enable-service-insight`, `-enable-custom-resources`, and `-enable-tls-passthrough` options.

The examples below use the `nodeport` service.

First, get the nginx-ingress pod id:

```console
kubectl get pods -n nginx-ingress
```

```text
NAME                             READY   STATUS    RESTARTS   AGE
nginx-ingress-67978954cc-l6gvq   1/1     Running   0          72m
```

Using the id, forward the service insight port (9114) to localhost port 9114:

```console
kubectl port-forward -n nginx-ingress nginx-ingress-67978954cc-l6gvq 9114:9114 &
```

### Deployment

Follow the [tls passthrough example](../tls-passthrough/) to deploy the `secure-app` and configure load balancing.

### Testing

Verify that the transport server is running, and check the app name:

```text
kubectl get ts secure-app
NAME         STATE   REASON           AGE
secure-app   Valid   AddedOrUpdated   5h37m
```

Scale down the `secure-app` deployment:

```console
kubectl scale deployment secure-app --replicas=1
```

Verify `secure-app` deployment:

```text
kubectl get deployments.apps secure-app
NAME         READY   UP-TO-DATE   AVAILABLE   AGE
secure-app   1/1     1            1           5h41m
```

Send a `GET` request to the service insight endpoint to check statistics:

Request:

```console
curl http://localhost:9114/probe/ts/secure-app
```

Response:

```json
{"Total":1,"Up":1,"Unhealthy":0}
```

Scale up deployments:

```console
kubectl scale deployment secure-app --replicas=3
```

Verify deployments:

```console
kubectl get deployments.apps secure-app
```

```text
NAME         READY   UP-TO-DATE   AVAILABLE   AGE
secure-app   3/3     3            3           5h53m
```

Send a `GET` HTTP request to the service insight endpoint to check statistics:

Request:

```console
curl http://localhost:9114/probe/ts/secure-app
```

Response:

```json
{"Total":3,"Up":3,"Unhealthy":0}
```

## Service Insight with TLS

The following example demonstrates how to enable the Service Insight for NGINX Ingress Controller with **TLS** using
[manifests (Deployment)](../../../deployments/deployment/nginx-plus-ingress.yaml):

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
        app.kubernetes.io/name: nginx-ingress
    spec:
      serviceAccountName: nginx-ingress
      automountServiceAccountToken: true
      securityContext:
      ...
      containers:
      - image: nginx-plus-ingress:4.0.1
        imagePullPolicy: IfNotPresent
        name: nginx-plus-ingress
        ports:
        - name: http
          containerPort: 80
        - name: https
          containerPort: 443
        - name: readiness-port
          containerPort: 8081
        - name: prometheus
          containerPort: 9113
        - name: service-insight
          containerPort: 9114
        readinessProbe:
          httpGet:
            path: /nginx-ready
            port: readiness-port
          periodSeconds: 1
        resources:
        ...
        securityContext:
        ...
        env:
        ...
        args:
          - -nginx-plus
          - -nginx-configmaps=$(POD_NAMESPACE)/nginx-config
        ...
          - -enable-service-insight
          - -service-insight-tls-secret=default/service-insight-secret
```

The example below uses the `nodeport` service.

First, create and verify the secret:

```console
kubectl apply -f service-insight-secret.yaml
```

```console
kubectl get secrets service-insight-secret
```

```text
NAME                     TYPE                DATA   AGE
service-insight-secret   kubernetes.io/tls   2      55s
```

Get the nginx-ingress pod id:

```console
kubectl get pods -n nginx-ingress
```

```text
NAME                             READY   STATUS    RESTARTS   AGE
nginx-ingress-687d9c6764-g6vwx   1/1     Running   0          2m8s
```

Verify the nginx-ingress configuration parameters:

```console
kubectl describe pods -n nginx-ingress nginx-ingress-687d9c6764-g6vwx
```

```yaml
...
Containers:
  nginx-plus-ingress:
    Container ID:  containerd://fdff9038d747cada877cd547d88aa4a94af3d243e43956445d81f1e9d641be86
    Image:         nginx-plus-ingress:jjplus
    Image ID:      docker.io/library/import-2023-03-27@sha256:85120b9f157bd6bb8e4469fa4aee3bbeac62c0a494d2707b47daab66b6b0b199
    Ports:         80/TCP, 443/TCP, 8081/TCP, 9113/TCP, 9114/TCP
    Host Ports:    0/TCP, 0/TCP, 0/TCP, 0/TCP, 0/TCP
    Args:
      -nginx-plus
      -nginx-configmaps=$(POD_NAMESPACE)/nginx-config
      ...
      -enable-service-insight
      -service-insight-tls-secret=default/service-insight-secret
      ...
    State:          Running
      Started:      Wed, 29 Mar 2023 14:32:25 +0100
...
```

Using the nginx-ingress pod id, forward the service insight port (9114) to localhost port 9114:

```console
kubectl port-forward -n nginx-ingress nginx-ingress-687d9c6764-g6vwx 9114:9114 &
```

Follow the [basic configuration example](../basic-configuration/) to deploy `cafe` app and `cafe virtual server`.

Send a `GET` request to the service insight (TLS) endpoint to check statistics:

Request:

```console
curl https://localhost:9114/probe/cafe.example.com --insecure
```

Response:

```json
{"Total":2,"Up":2,"Unhealthy":0}
```
