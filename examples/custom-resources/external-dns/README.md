# External DNS

In this example we configure a VirtualServer resource to integrate with
[ExternalDNS](https://github.com/kubernetes-sigs/external-dns) to make the resource discoverable via a public DNS
server. In this example, we deploy an ExternalDNS deployment with the AWS provider enabled.

## Prerequisites

1. Run `make secrets` command to generate the necessary secrets for the example.
1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled. Additionally, the Ingress Controller
   must be configured to report the VirtualServer status by setting either the `external-service` command line argument,
   or setting the `external-status-address` key in the ConfigMap resource (see the [Reporting Resources Status
   docs](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/reporting-resources-status#virtualserver-and-virtualserverroute-resources)
   for more details).

### Selecting the DNSEndpoint API group

NGINX Ingress Controller can write `DNSEndpoint` resources to one of two API groups:

- `externaldns.nginx.org/v1` (default) — NGINX Ingress Controller's own group, kept as the default for backwards compatibility. The CRD is shipped by the NGINX Ingress Controller Helm chart / manifests.
- `externaldns.k8s.io/v1alpha1` — the upstream external-dns group. The CRD is **not** shipped by NGINX Ingress Controller to avoid ownership conflicts with the external-dns Helm chart; install it separately from the [external-dns repo](https://github.com/kubernetes-sigs/external-dns).

Which group you need depends on your external-dns version:

- external-dns **v0.20.x and earlier** reads **either** group. It builds its CRD client from whatever you pass to `--crd-source-apiversion`, so it works equally well with `externaldns.nginx.org/v1` and `externaldns.k8s.io/v1alpha1`.
- external-dns **v0.21.0 and newer** reads **only** `externaldns.k8s.io/v1alpha1`. The group is hard-coded, and `--crd-source-apiversion` no longer selects it.

Because v0.20.x accepts both, you can move to the upstream group before upgrading external-dns. See
[Migrating an existing deployment](#migrating-an-existing-deployment) below.

Toggle groups with the `-external-dns-group-version` command-line flag (or `controller.externalDNSGroupVersion` Helm value). This example uses `externaldns.k8s.io/v1alpha1` and pins external-dns to v0.21.0.

Start NGINX Ingress Controller with:

```shell
-external-dns-group-version=externaldns.k8s.io/v1alpha1
```

### Migrating an existing deployment

If you already run NGINX Ingress Controller with ExternalDNS enabled on `externaldns.nginx.org/v1`, you can move to the upstream group
without dropping a DNS record. NGINX Ingress Controller never deletes `DNSEndpoint` resources and does not convert existing ones, so the
cut-over is a sequence you drive yourself.

Migrate **before** upgrading external-dns to v0.21.0+, while it still accepts either group. Complete each step's check
before starting the next one:

| Step | Action | Check before continuing |
| ---- | ------ | ----------------------- |
| 0 | Install the upstream CRD. NGINX Ingress Controller does not ship it, so it will not arrive with an NGINX Ingress Controller upgrade. | `kubectl get crd dnsendpoints.externaldns.k8s.io` succeeds. |
| 1 | Upgrade NGINX Ingress Controller, leaving `externalDNSGroupVersion` at its `externaldns.nginx.org/v1` default. | Records unchanged. The `externaldns.nginx.org/v1` object is still present and current. |
| 2 | Set `controller.externalDNSGroupVersion: externaldns.k8s.io/v1alpha1` (Helm) or `-external-dns-group-version=externaldns.k8s.io/v1alpha1` (flag). | **Blocking.** The `externaldns.k8s.io/v1alpha1` object exists *and* its `.spec.endpoints` matches the old object's targets and TTL. Check NGINX Ingress Controller's logs for `DNSEndpoint` informer errors. |
| 3 | Remove `--crd-source-apiversion` from your external-dns v0.20.x configuration. Its default is already `externaldns.k8s.io/v1alpha1`, so removing it selects the upstream group. | `status.observedGeneration` matches `metadata.generation` on the new object, and one full sync interval logs `All records are already up to date`. |
| 4 | Upgrade external-dns to v0.21.0 or newer. | Same check as step 3. |
| 5 | Delete the old `externaldns.nginx.org/v1` object. | Records unchanged. |

Steps 3–5 cause no record churn because both objects share a name and namespace. external-dns derives its ownership
label from those (`crd/<namespace>/<name>`), so the TXT registry record is identical before and after the switch and the
reconciliation plan comes out empty.

Keep step 2 and step 3 as separate changes. Step 4 switches the group on its own — v0.21.0+ ignores
`--crd-source-apiversion` entirely — but doing the group switch and the version upgrade in one move means a records
change gives you no way to tell which caused it.

To confirm external-dns has read the new object, compare its observed generation to its generation:

```console
kubectl get dnsendpoints.externaldns.k8s.io <name> -o jsonpath='{.status.observedGeneration}/{.metadata.generation}'
```

Matching values mean external-dns has picked the resource up. external-dns stamps `status.observedGeneration` when it
reads the resource, which happens before it pushes records to your DNS provider — so treat it as confirmation that the
resource was seen, not that the record is already live.

#### Why step 0 and the step 2 check matter

Skipping the CRD install does not fail loudly. NGINX Ingress Controller registers an informer for a resource that does not exist, that
informer never syncs, and NGINX Ingress Controller's ExternalDNS control loop stalls before it processes anything — no `DNSEndpoint` is
created or updated for any VirtualServer. Meanwhile the old object is still in place and external-dns is still reading
it, so DNS looks healthy. The only signal is list/watch errors in NGINX Ingress Controller's log and the absence of the new object.

The damage lands later, at step 3 or 4, and depends on your external-dns `--policy`:

- A **missing CRD or missing RBAC** makes external-dns fail to start. No records change.
- A **present CRD with no objects in it** is a successful, empty result. Under `--policy=sync` external-dns concludes
  every record it owns has been released and deletes them. Under `--policy=upsert-only` deletions are stripped and the
  records survive.

So on `--policy=sync` the difference between a safe failure and a destructive one is whether the CRD was applied before
you flipped NGINX Ingress Controller. Treat the step 2 check as a gate, not a glance — an object that exists but is empty or stale is as
dangerous as no object at all.

Two further points:

- **Never let external-dns read the upstream group before NGINX Ingress Controller has populated it.** That is the same empty-desired-set
  condition described above.
- **Keep the window between steps 2 and 3 short.** NGINX Ingress Controller stops updating the old object as soon as you flip the toggle, but
  external-dns is still reading it, so VirtualServer changes in that window are not published.

#### Aborting a migration

Up to and including step 4, the old object has not been deleted, so you can return to the starting state by reverting
**both** settings together:

1. `controller.externalDNSGroupVersion` back to `externaldns.nginx.org/v1`.
2. `--crd-source-apiversion=externaldns.nginx.org/v1` back onto external-dns (and roll back to v0.20.x if you have
   already upgraded — v0.21.0+ cannot read that group).

Revert them together. Reverting only one leaves external-dns pointed at a group NGINX Ingress Controller is not writing to, which is the
empty-desired-set condition.

If you skip step 5, the old object is not left behind permanently: NGINX Ingress Controller sets an owner reference to the VirtualServer, so
Kubernetes garbage-collects it when the VirtualServer is deleted. Step 5 is a `kubectl delete` either way — NGINX Ingress Controller only
manages the group it is configured for and never deletes the object in the other one.

RBAC differs between installation methods, which matters if you want to delete the old object with NGINX Ingress Controller's service
account rather than your own: the Helm chart grants only the selected group, so after step 2 NGINX Ingress Controller no longer holds any
permission on `externaldns.nginx.org`, while the manifest-based install (`deployments/rbac/rbac.yaml`) grants both
groups.

## Step 1: Deploy external-dns

Install the upstream DNSEndpoint CRD (needed because NGINX Ingress Controller does not ship it):

```console
kubectl apply --server-side=true -f https://raw.githubusercontent.com/kubernetes-sigs/external-dns/v0.21.0/config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml
```

Update `external-dns-route53.yaml` with your Domain Name and Hosted Zone ID, and apply the file.

```console
kubectl apply -f external-dns-route53.yaml
```

## Step 2 - Deploy the Cafe Application

Create the coffee and the tea deployments and services:

```console
kubectl create -f cafe.yaml
```

## Step 3 - Configure Load Balancing and TLS Termination

1. Create the secret with the TLS certificate and key:

    ```console
    kubectl create -f cafe-secret.yaml
    ```

2. Update the `spec.host` field in the `cafe-virtual-server.yaml` to correspond to your Domain Name and create the
   VirtualServer resource:

    ```console
    kubectl create -f cafe-virtual-server.yaml
    ```

## Step 4 - Test the Configuration

Using a browser, navigate to `https://cafe.<YOUR_DOMAIN_NAME>/coffee`, making sure to update <YOUR_DOMAIN_NAME> as
listed in the `spec.host` of the virtual server. You should see something like the following in the browser window:

```text
Server address: 192.168.86.30:8080
Server name: coffee-6f4b79b975-l484q
Date: 28/Jun/2022:16:01:26 +0000
URI: /coffee
Request ID: 9af5fd7329495819bfb6c6c0f3686a64
```

## Cleaning up DNS records

The external-dns deployment in this example runs with `--policy=upsert-only`, which strips deletions from every
reconciliation plan. With that policy external-dns only ever creates and updates records, so **deleting a `DNSEndpoint`
resource — or the VirtualServer that owns it — does not remove the DNS record**, nor its `externaldns-` TXT ownership
record. Both remain at your DNS provider.

This is expected external-dns behaviour, not a resource leak. The `DNSEndpoint` resource itself does go away —
Kubernetes garbage-collects it with the VirtualServer that owns it — but removing the DNS record is external-dns's
decision, and `upsert-only` forbids it.

To have records removed when the resources that created them go away, run external-dns with `--policy=sync`. Otherwise,
delete leftover records at your DNS provider yourself.
