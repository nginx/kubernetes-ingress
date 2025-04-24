---
title: Install NGINX Ingress Controller and NGINX App Protect WAF with Docker and Helm
toc: true
weight: 500
type: how-to
product: NIC
docs: DOCS-609
---

This document describes how to build a local F5 NGINX App Protect WAF v5 Docker image with NGINX Plus Ingress 
Controller, which can be used to compile WAF policies.

This is accomplished with the following steps:

- Prepare license secrets to enable a Kubernetes deployment
- Use a NGINX App Protect WAF Docker image to transform a policy JSON file into a compiled bundle
- Configure PersistentVolumes so the deployed NGINX App Protect WAF instance can access the compiled bundle
- Deploy NGINX Plus Ingress Controller with NGINX App Protect
- Test example services to validate that the WAF policies work

---

## Prepare Secrets and credentials

1. Download your NGINX Ingress Controller subscription's JSON Web Token, SSL Certificate, and Private Key from MyF5. 
   You can use the same JSON Web Token, Certificate, and Key as NGINX Plus in your MyF5 portal.
1. Rename the files to the following:
   - `nginx-repo.crt`
   - `nginx-repo.key`
   - `nginx-repo.jwt`
1. Log in to the Docker registry using the contents of the JSON Web Token file:
   ```shell
   docker login private-registry.nginx.com --username=$(cat nginx-repo.jwt) --password=none
   ```

---

## Compile WAF Policy from JSON to Bundle

Pull the `waf-compiler` image with:

```shell
docker pull private-registry.nginx.com/nap/waf-compiler:5.6.0
```

Download the [provided WAF Policy JSON](https://raw.githubusercontent.com/nginx/kubernetes-ingress/main/tests/data/ap-waf-v5/wafv5.json):

```shell
curl -LO https://raw.githubusercontent.com/nginx/kubernetes-ingress/main/tests/data/ap-waf-v5/wafv5.json
```

Use your pulled NAP Docker image (`private-registry.nginx.com/nap/waf-compiler:5.6.0`) to compile the policy bundle:

```shell
# Using your newly created image
docker run --rm \
    -v $(pwd):$(pwd) \
    private-registry.nginx.com/nap/waf-compiler:5.6.0 \
    -p $(pwd)/wafv5.json \
    -o $(pwd)/compiled_policy.tgz
```

After this command, your workspace should contain:

```
├── nginx-repo.crt
├── nginx-repo.key
├── nginx-repo.jwt
├── wafv5.json
└── compiled_policy.tgz
```

---

## Create the persistent volume and claim to store the policy bundle

Save the following configuration data as `pvc.yaml` in the same directory.

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: task-pv-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/tmp/"

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: task-pv-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

This sets up a 1Gi disk and attaches a claim to it that you will reference in the deployment chart.

Create these with:

```shell
kubectl apply -f pvc.yaml
```

Verify that the persistent volume and claim are created:

```shell
# For the persistent volume
kubectl get pv

# For the persistent volume claim
kubectl get pvc
```

## Deploy NGINX Plus NIC Controller with NAP Enabled using Helm

Add the official NGINX Helm repository:

```shell
helm repo add nginx-stable https://helm.nginx.com/stable
helm repo update
```

Create Kubernetes Docker and licensing secrets:
```shell
kubectl create secret \
    docker-registry regcred \
    --docker-server=private-registry.nginx.com \
    --docker-username=$(cat nginx-repo.jwt) \
    --docker-password=none

kubectl create secret \
    generic license-token \
    --from-file=license.jwt=./nginx-repo.jwt \
    --type=nginx.com/license
```

Install the required CRDs for NGINX Ingress Controller:

```shell
kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/v5.0.0/deploy/crds.yaml
```

Using Helm, install NGINX Ingress Controller

```shell
helm upgrade --install nic nginx-stable/nginx-ingress \
   --set controller.image.repository="private-registry.nginx.com/nginx-ic-nap-v5/nginx-plus-ingress" \
   --set controller.image.tag="5.0.0-alpine-fips" \
   --set controller.nginxplus=true \
   --set controller.appprotect.enable=true \
   --set controller.appprotect.v5=true \
   --set-json 'controller.appprotect.volumes=[
      {"name":"app-protect-bd-config","emptyDir":{}},
      {"name":"app-protect-config","emptyDir":{}},
      {"name":"app-protect-bundles","persistentVolumeClaim":{"claimName":"task-pv-claim"}}
   ]' \
   --set controller.serviceAccount.imagePullSecretName=regcred \
   --set 'controller.volumeMounts[0].name=app-protect-bundles' \
   --set 'controller.volumeMounts[0].mountPath=/etc/app_protect/bundles/'

```

Verify deployment success:

```shell
kubectl get pods
```

---

## Copy the policy bundle into the running instance

Get the name of the pod from the `kubectl get pods` command above.

Copy the file into the `nginx-ingress` container within the pod:

```shell
kubectl cp ./compiled_policy.tgz \
    <pod name>:/etc/app_protect/bundles/compiled_policy.tgz \
    -c nginx-ingress
```

Replace `<pod name>` with the actual name of the pod, for example:

```shell
kubectl cp ./compiled_policy.tgz \
    nic-nginx-ingress-controller-9bd89589d-j925h:/etc/app_protect/bundles/compiled_policy.tgz \
    -c nginx-ingress
```

Confirm that the policy file is in the pod. The following command should list `compiled_policy.tgz`.

```shell
kubectl exec --stdin --tty \
    -c nginx-ingress \
    <pod name> \
    -- ls -la /etc/app_protect/bundles
```

## Confirm that the WAF policies work

Save the following kubernetes config file as `webapp.yaml`:

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: webapp
spec:
  host: webapp.example.com
  policies:
  - name: waf-policy
  upstreams:
  - name: webapp
    service: webapp-svc
    port: 80
  routes:
  - path: /
    action:
      pass: webapp
---
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: waf-policy
spec:
  waf:
    enable: true
    apBundle: "compiled_policy.tgz"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webapp
  template:
    metadata:
      labels:
        app: webapp
    spec:
      containers:
        - name: webapp
          image: nginxdemos/nginx-hello:plain-text
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: webapp-svc
spec:
  ports:
    - port: 80
      targetPort: 8080
      protocol: TCP
      name: http
  selector:
    app: webapp
```

Create the services with
```shell
kubectl apply -f webapp.yaml
```

Confirm that the services have started with

```shell
kubectl get pods
```

### Save the public IP and PORT in environment variables

Get the public IP and port of your instance with the following command:

```shell
kubectl get svc
```

Save them in the following environment variables:

```shell
IC_IP=XXX.YYY.ZZZ.III
IC_HTTP_PORT=<port number>
```

### Validate that the WAF works

Send a valid request to the deployed application:

```shell
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP http://webapp.example.com:$IC_HTTP_PORT/
```

```text
Server address: 10.92.2.13:8080
Server name: webapp-7b7dfbff54-dtxzt
Date: 18/Apr/2025:19:39:18 +0000
URI: /
Request ID: 4f378a01fb8a36ae27e2c3059d264527
```

And send one that should be rejected

```shell
curl --resolve webapp.example.com:$IC_HTTP_PORT:$IC_IP "http://webapp.example.com:$IC_HTTP_PORT/<script>"
```

```text
<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your 
administrator.<br><br>Your support ID is: 11241918873745059631<br><br>
<a href='javascript:history.back();'>[Go Back]</a></body></html>
```

This is mostly the same as the [examples/custom_resources/app-protect-waf-v5](https://github.com/nginx/kubernetes-ingress/tree/main/examples/custom-resources/app-protect-waf-v5)
deployment in a single file with the policy bundle already set.

You now have a fully operational NGINX Ingress Controller instance with NGINX App Protect deployed in your Kubernetes environment. 

For further details, troubleshooting, or support, refer to the [official NGINX documentation](https://docs.nginx.com) or reach out directly to your F5/NGINX account team.
