# WAF with F5 WAF Policy Controller (Ingress)

In this example we deploy the NGINX Plus Ingress Controller with F5 WAF for NGINX, where
the policy and log configuration bundles are compiled by the F5 WAF Policy Controller
(PLM), and apply WAF protection to an Ingress resource.

PLM owns the `APPolicy` and `APLogConf` lifecycle and publishes the compiled bundles to
SeaweedFS. NGINX Ingress Controller (NIC) watches the referenced resources and fetches a
bundle once its `status.bundle.state` becomes `ready`.

For VirtualServer equivalents, see [custom-resources/waf-plm](../../custom-resources/waf-plm/).
For sourcing bundles from NGINX Instance Manager or NGINX One Console instead, see
[waf-management-plane](../waf-management-plane/).

## Prerequisites

1. Install the F5 WAF Policy Controller (PLM). PLM installs and owns the
   `appprotect.f5.com/v1` CRDs (`APPolicy`, `APLogConf`, `APUserSig`, `APSignatures`)
   and runs the compiler and SeaweedFS bundle store.

1. Confirm the CRDs are installed and served at `v1`:

    ```console
    kubectl describe crd appolicies.appprotect.f5.com aplogconfs.appprotect.f5.com
    ```

## Step 1 - Create the PLM Policy and Log Configuration

Create the `APPolicy` and `APLogConf` resources. PLM compiles each resource and publishes
the resulting bundle to SeaweedFS.

```console
kubectl apply -f ap-dataguard-alarm-policy.yaml
kubectl apply -f ap-logconf.yaml
```

## Step 2 - Verify Both Bundles Are Ready

Check that PLM reports `ready` for both resources. NIC does not fetch a bundle before
this point.

```console
kubectl describe appolicy dataguard-alarm
kubectl describe aplogconf logconf
```

Each resource reports the compiled bundle under `Status`:

- for appolicy:

   ```text
   Status:
   Bundle:
      Compiler Version:  5.14.0
      Location:          s3://default/bundles/dataguard-alarm20260807160340-dataguard-alarm-1-1786118620559717186.tgz
      sha256:            47a6fdcd07b9adafaaa415fa9fd2ab2cab84b54b26a91fd518a4ff5e2dab3f8d
      Signatures:
         Attack Signatures:  2026-07-18T13:39:26Z
         Bot Signatures:     2026-07-16T07:35:37Z
         Threat Campaigns:   2026-07-13T11:56:06Z
      State:                ready
   Observed Generation:    1
   Observed Policy Name:   dataguard-alarm
   Policy Location:        s3://default/policies/dataguard-alarm.json
   Processing:
      Datetime:     2026-08-07T16:03:46Z
      Is Compiled:  true
   ```

- for aplogconf:

   ```text
   Status:
   Bundle:
      Compiler Version:   5.14.0
      Location:           s3://default/bundles/logconf20260807160340.tgz
      sha256:             0728d1cc822e32af2b880f49c433f7fe8ef28bd5fcf1761af2be4f04acace9de
      State:              ready
   Observed Generation:  1
   Processing:
      Datetime:     2026-08-07T16:03:46Z
      Is Compiled:  true
   Events:           <none>
   ```

If a resource never reaches `ready`, inspect the PLM policy-controller and compiler logs
before continuing.

## Step 3 - Install the Ingress Controller

Deploy NIC with NGINX Plus, App Protect, and PLM storage enabled. PLM storage is
configured with cluster-wide command-line arguments, which the Helm chart renders from
`controller.appprotect.plmStorage`:

| Argument | Purpose |
| --- | --- |
| `-plm-storage-url` | SeaweedFS S3 endpoint. Enables the PLM integration and makes NIC watch the `appprotect.f5.com/v1` CRDs. |
| `-plm-storage-credentials-secret` | Secret holding the SeaweedFS admin key under `seaweedfs_admin_secret`. Required. |
| `-plm-storage-ca-secret` | Optional Secret containing `ca.crt` for TLS verification. |
| `-plm-storage-client-ssl-secret` | Optional Secret containing `tls.crt` and `tls.key` for mTLS. |
| `-plm-storage-insecure-skip-verify` | Disables TLS verification. Development and testing only. |

Secret references use the `namespace/name` format. For a PLM installation with TLS and
mTLS enabled, the Helm values are:

```yaml
controller:
  nginxplus: true
  appprotect:
    enable: true
    v5: true
    plmStorage:
      url: "https://<plm_release>-f5-waf-seaweed-filer.<plm_namespace>.svc.cluster.local:9333"
      credentialsSecret: "<plm_namespace>/<plm_release>-f5-waf-seaweedfs-auth"
      caSecret: "<plm_namespace>/<plm_release>-f5-waf-seaweedfs-ca-cert"
      clientSSLSecret: "<plm_namespace>/<plm_release>-f5-waf-seaweedfs-client-cert"
      insecureSkipVerify: false
```

For an installation without TLS, use the HTTP endpoint on port `8333` and leave
`caSecret` and `clientSSLSecret` empty. The endpoint scheme must match how PLM was
installed: a plaintext `http://` request sent to the TLS port fails.

Because PLM owns the App Protect CRDs, install NIC with `--skip-crds` so it does not
overwrite them, and create the rest of the CRDs before installation otherwise the NIC pod
won't become ready.

If `controller.watchNamespace` is restricted, include the namespace holding the
`APPolicy` and `APLogConf` resources so NIC can watch their status. If
`controller.watchSecretNamespace` is restricted, include the namespace holding the
storage Secrets so NIC observes their rotation.

Then save the public IP address and HTTP port of the Ingress Controller into shell
variables:

```console
IC_IP=XXX.YYY.ZZZ.III
IC_HTTP_PORT=<port number>
```

## Step 4 - Deploy the Application and WAF Policy

1. Create the application deployments and services:

    ```console
    kubectl apply -f cafe.yaml
    ```

1. Create the syslog service and pod for the security logs:

    ```console
    kubectl apply -f syslog.yaml
    ```

1. Create the WAF policy:

    ```console
    kubectl apply -f waf-plm.yaml
    ```

PLM sources do not use `url`, `secret`, `trustedCertSecret`, `enablePolling`,
`pollInterval`, or `verifyChecksum`. NIC reads the bundle location and SHA-256 from the
referenced resource status, and bundle updates are driven by status watch events rather
than polling.

## Step 5 - Check the Policy Status

The Policy becomes valid once NIC has fetched both bundles from SeaweedFS:

```console
kubectl describe policy waf-policy
```

```text
Events:
  Type    Reason          Message
  ----    ------          -------
  Normal  AddedOrUpdated  Policy default/waf-policy was added or updated
```

A `BundleFetchFailed` warning means NIC reached the fetch stage but could not retrieve
the bundle. Verify the storage endpoint, credentials, and TLS settings from Step 3.

## Step 6 - Check policy and logconf bundles

Optional but you can check for the presence of compiled bundles in pod file-system

```console
kubectl exec -it -n <NIC_NAMESPACE> <ANY_NIC_POD> -c nginx-ingress -- ls -ltr /etc/app_protect/bundles
```

```text
-rw------- 1 nginx nginx 1901282 Aug  7 16:26 fetched_default_waf-policy_policy.tgz
-rw------- 1 nginx nginx    1655 Aug  7 16:26 fetched_default_waf-policy_log_0.tgz
```

## Step 7 - Configure Load Balancing

Create the Ingress resource, which references the `waf-policy` created in Step 4 through
the `nginx.com/policies` annotation:

```console
kubectl apply -f cafe-ingress.yaml
```

## Step 8 - Test the Application

1. Send a request to the application:

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP http://cafe.example.com:$IC_HTTP_PORT/coffee
    ```

    ```text
    Server address: 10.76.1.11:80
    Server name: coffee-55c788878b-j4tgm
    Date: 10/Aug/2026:11:05:10 +0000
    URI: /coffee
    Request ID: 20734e6c3a0ec54874d984c32804c266
    ```

1. Send a request that triggers the data guard violation.

    ```console
    curl --resolve cafe.example.com:$IC_HTTP_PORT:$IC_IP "http://cafe.example.com:$IC_HTTP_PORT/coffee/</script>"
    ```

    ```text
    <html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: 3607539252134092173<br><br><a href='javascript:history.back();'>[Go Back]</a></body></html>% 
    ```

1. Check the security logs in the syslog pod:

    ```console
    kubectl exec -it <SYSLOG_POD> -- cat /var/log/messages
    ```

    ```text
    Aug 10 11:05:15 nic-nginx-ingress-controller-f6c988865-9b84b ASM:attack_type="Non-browser Client,Abuse of Functionality,Cross Site Scripting (XSS),Other Application Activity",blocking_exception_reason="N/A",date_time="2026-08-10 11:05:15",dest_port="80",ip_client="87.192.103.246",is_truncated="false",method="GET",policy_name="dataguard-alarm",protocol="HTTP",request_status="blocked",response_code="0",severity="Critical",sig_cves="N/A",sig_ids="200000093",sig_names="XSS script tag end (URI)",sig_set_names="{High Accuracy Signatures;Cross Site Scripting Signatures}",src_port="60437",sub_violations="N/A",support_id="3607539252134092173",threat_campaign_names="N/A",unit_hostname="nic-nginx-ingress-controller-f6c988865-9b84b",uri="/coffee/</script>"
    .
    .
    .
    ```
