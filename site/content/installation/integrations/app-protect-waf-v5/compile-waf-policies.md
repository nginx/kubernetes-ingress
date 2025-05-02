---
title: Compile NGINX App Protect WAF policies using NGINX Instance Manager
weight: 300
toc: true
type: how-to
product: NIC
docs: DOCS-000
---

## Overview

This guide describes how to use F5 NGINX Instance Manager to compile NGINX App Protect WAF Policies for use with NGINX Ingress Controller.

NGINX App Protect WAF uses policies to configure which security features are set. When these policies are changed, they need to be compiled so that the engine can begin to use them. Compiling policies can take a large amount of time and resources. You can do this with the NGINX Instance Manager. This reduces the impact on a NGINX Ingress Controller deployment.

By using NGINX Instance Manager to compile WAF policies, the policy bundle can also be used immediately by NGINX Ingress Controller without reloading.

The following steps describe how to use the NGINX Instance Manager API to create a new security policy, compile a bundle, then add it to NGINX Ingress Controller.

---

## Before you start

### Requirements
- A working [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager/deploy/) instance.
- An [NGINX Instance Manager user](https://docs.nginx.com/nginx-instance-manager/admin-guide/rbac/overview-rbac/) for API requests.
- A NGINX Ingress Controller [deployment with NGINX App Protect WAF]({{< relref "/installation/integrations/app-protect-waf/installation.md" >}}).

---

## Create a new security policy

{{< tip >}} You can skip this step if you intend to use an existing security policy. {{< /tip >}}

Create a [new security policy](https://docs.nginx.com/nginx-instance-manager/nginx-app-protect/manage-waf-security-policies/#create-security-policy) using the API: this will require the use of a tool such as [`curl`](https://curl.se/) or [Postman](https://www.postman.com/)

Create the file `simple-policy.json` with the contents below:

```json
{
  "metadata": {
    "name": "Nginxbundletest",
    "displayName": "Nginxbundletest",
    "description": "Ignore cross-site scripting is a security policy that intentionally ignores cross site scripting."
  },
  "content": "ewoJInBvbGljeSI6IHsKCQkibmFtZSI6ICJzaW1wbGUtYmxvY2tpbmctcG9saWN5IiwKCQkic2lnbmF0dXJlcyI6IFsKCQkJewoJCQkJInNpZ25hdHVyZUlkIjogMjAwMDAxODM0LAoJCQkJImVuYWJsZWQiOiBmYWxzZQoJCQl9CgkJXSwKCQkidGVtcGxhdGUiOiB7CgkJCSJuYW1lIjogIlBPTElDWV9URU1QTEFURV9OR0lOWF9CQVNFIgoJCX0sCgkJImFwcGxpY2F0aW9uTGFuZ3VhZ2UiOiAidXRmLTgiLAoJCSJlbmZvcmNlbWVudE1vZGUiOiAiYmxvY2tpbmciCgl9Cn0="
}
```

{{< warning >}} The `content` value must be base64 encoded or you will encounter an error. {{< /warning >}}

Upload the policy JSON files with the API, which is the same method to create the bundle later.

In the same directory you created `simple-policy.json`, create a POST request for NGINX Instance Manager using the API.

```shell
curl -X POST https://{{NMS_FQDN}}/api/platform/v1/security/policies \
    -H "Authorization: Bearer <access token>" \
    -d @simple-policy.json
```

You should receive an API response similar to the following output, indicating the policy has been successfully created.

```json
{
    "metadata": {
        "created": "2024-06-12T20:28:08.152171922Z",
        "description": "Ignore cross-site scripting is a security policy that intentionally ignores cross site scripting.",
        "displayName": "Nginxbundletest",
        "externalId": "",
        "externalIdType": "",
        "modified": "2024-06-12T20:28:08.152171922Z",
        "name": "Nginxbundletest",
        "revisionTimestamp": "2024-06-12T20:28:08.152171922Z",
        "uid": "6af9f261-658b-4be1-b07a-cebd83e917a1"
    },
    "selfLink": {
        "rel": "/api/platform/v1/security/policies/6af9f261-658b-4be1-b07a-cebd83e917a1"
    }
}
```

{{< important >}}

Take note of the *uid* field: `"uid": "6af9f261-658b-4be1-b07a-cebd83e917a1"`
It is one of two unique IDs we will use to download the bundle: it will be referenced as *policy-UID*.

{{< /important >}}

---

## Create a new security bundle

Once you have created (Or selected) a security policy, [create a security bundle](https://docs.nginx.com/nginx-instance-manager/nginx-app-protect/manage-waf-security-policies/#create-security-policy-bundles) using the API. The version in the bundle you create **must** match the WAF compiler version you intend to use.

You can check which version is installed in NGINX Instance Manager by checking the operating system packages. If the wrong version is noted in the JSON payload, you will receive an error similar to below:

```text
{"code":13018,"message":"Error compiling the security policy set: One or more of the specified compiler versions does not exist. Check the compiler versions, then try again."}
```

Create the file `security-policy-bundles.json`:

```json
{
  "bundles": [
    {
      "appProtectWAFVersion": "4.815.0",
      "policyName": "Nginxbundletest",
      "policyUID": "",
      "attackSignatureVersionDateTime": "latest",
      "threatCampaignVersionDateTime": "latest"
    }
  ]
}
```

The *policyUID* value is left blank, as it is generated as part of the creating the bundle.

Send a POST request to create the bundle through the API:

```shell
curl -X POST https://{{NMS_FQDN}}/api/platform/v1/security/policies/bundles \
    -H "Authorization: Bearer <access token>" \
    -d @security-policy-bundles.json
```

You should receive a response similar to the following:

```json
{
    "items": [
        {
            "compilationStatus": {
                "message": "",
                "status": "compiling"
            },
            "content": "",
            "metadata": {
                "appProtectWAFVersion": "4.815.0",
                "attackSignatureVersionDateTime": "2024.02.21",
                "created": "2024-06-12T13:28:20.023775785-07:00",
                "modified": "2024-06-12T13:28:20.023775785-07:00",
                "policyName": "Nginxbundletest",
                "policyUID": "6af9f261-658b-4be1-b07a-cebd83e917a1",
                "threatCampaignVersionDateTime": "2024.02.25",
                "uid": "cbdf9577-6d81-43d6-8ce1-2e3d4714e8b5"
            }
        }
    ]
}
```

You can use the API to list the security bundles, verifying the new addition:

```shell
curl --location 'https://127.0.0.1/api/platform/v1/security/policies/bundles' \
-H "Authorization: Bearer <access_token>"
```
```json
{
    "items": [
        {
            "compilationStatus": {
                "message": "",
                "status": "compiled"
            },
            "content": "",
            "metadata": {
                "appProtectWAFVersion": "4.815.0",
                "attackSignatureVersionDateTime": "2024.02.21",
                "created": "2024-06-13T09:09:10.809-07:00",
                "modified": "2024-06-13T09:09:20-07:00",
                "policyName": "Nginxbundletest",
                "policyUID": "ec8681eb-1e25-4b71-93bd-b91f67c5ac99",
                "threatCampaignVersionDateTime": "2024.02.25",
                "uid": "de08b324-99d8-4155-b2eb-fe687b21034e"
            }
        }
    ]
}
```

{{< important >}}

Take note of the *uid* field: `"uid": "de08b324-99d8-4155-b2eb-fe687b21034e"`

It is one of two unique IDs we will use to download the bundle: it will be referenced as *bundle-UID*.

{{< /important >}}

---

## Download the security bundle

Use a GET request to download the security bundle using the policy and bundle IDs:

```shell
curl -X GET "https://{NMS_FQDN}/api/platform/v1/security/policies/<policy-UID>/bundles/<bundle-UID>" -H "Authorization: Bearer <access token>" | jq -r '.content' | base64 -d > security-policy-bundle.tgz
```

This GET request uses the policy and bundle IDs from the previous examples:

```shell
curl -X GET -k 'https://127.0.0.1/api/platform/v1/security/policies/6af9f261-658b-4be1-b07a-cebd83e917a1/bundles/de08b324-99d8-4155-b2eb-fe687b21034e' \
    -H "Authorization: Basic YWRtaW46UncxQXBQS3lRRTRuQXRXOFRYa1J4ZFdVSWVTSGtU" \
     | jq -r '.content' | base64 -d > security-policy-bundle.tgz
```

---

## Add volumes and volumeMounts

To use WAF security bundles, your NGINX Ingress Controller instance must have *volumes* and *volumeMounts*. Precise paths are used to detect when bundles are uploaded to the cluster.

Here is an example of what to add:

```yaml
volumes:
- name: <volume_name>
persistentVolumeClaim:
    claimName: <claim_name>

volumeMounts:
- name: <volume_mount_name>
    mountPath: /etc/app_protect/bundles
```

A full example of a deployment file with `volumes` and `volumeMounts` could look like the following:

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
     #annotations:
       #prometheus.io/scrape: "true"
       #prometheus.io/port: "9113"
       #prometheus.io/scheme: http
    spec:
      serviceAccountName: nginx-ingress
      automountServiceAccountToken: true
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      volumes:
      - name: nginx-bundle-mount
        emptydir: {}
      containers:
      - image: <replace>
        imagePullPolicy: IfNotPresent
        name: nginx-ingress
        ports:
        - name: http
          containerPort: 80
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
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
         #limits:
         #  cpu: "1"
         #  memory: "1Gi"
        securityContext:
          allowPrivilegeEscalation: false
          runAsUser: 101 #nginx
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        volumeMounts:
        -  name: bundle-mount
           mountPath: /etc/app_protect/bundles
        env:
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        args:
          - -nginx-configmaps=$(POD_NAMESPACE)/nginx-config
          - -report-ingress-status
          - -external-service=nginx-ingress
```

---

## Create WAF policy

To process a bundle, you must create a new WAF policy. This policy is added to `/etc/app_protect/bundles`, allowing NGINX Ingress Controller to load it into WAF.

The example below shows the required WAF policy, and the *apBundle* and *apLogConf* fields you must use for the security bundle binary file (A tar ball).

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: <waf-policy-name>
spec:
  waf:
    enable: true
    apBundle: "<bundle-name>.tgz"
    securityLogs:
    - enable: true
        apLogBundle: "<bundle-name>.tgz"
        logDest: "<security-log-destination-URL>"
```

---

## Create VirtualServer resource and apply policy

Once the WAF policy has been created, link it to your *virtualServer resource*.

```yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServer
metadata:
  name: webapp
spec:
  host: webapp.example.com
  policies:
  - name: <waf-policy-name>
  upstreams:
  - name: webapp
    service: webapp-svc
    port: 80
  routes:
  - path: /
    action:
      pass: webapp
```

---

## Upload the security bundle

To finish adding a security bundle, upload the binary file to the NGINX Ingress Controller pods.

```shell
kubectl cp /your/local/path/<bundle_name>.tgz  <namespace>/<pod-name>:etc/app_protect/bundles<bundle_name>.tgz -c nginx-plus-ingress
```

Once the bundle has been uploaded to the cluster, NGINX Ingress Controller will detect and automatically load the new WAF policy.
