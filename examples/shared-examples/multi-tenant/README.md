# Multi-tenant installation

This example installs two independent NGINX Ingress Controllers, one for team-a and one for team-b.
Each team installs and runs its own Ingress Controller with permissions in its own namespaces only.

Installation has two phases:

- **Platform phase.** A cluster admin applies the CRDs and the tenant aggregate manifest once per
  cluster, then installs one `platform` release per team. That release creates the team's
  IngressClass and a read-only ClusterRole for the team's Ingress Controller.
- **Tenant phase.** An admin of the team's namespaces installs the `nginx-ingress-tenant` chart. It
  creates namespaced resources only, with a Role in each namespace the Ingress Controller watches.

| Team | Release namespace | Watched namespaces | IngressClass |
| --- | --- | --- | --- |
| team-a | `team-a` | `team-a`, `team-a-apps` | `team-a` |
| team-b | `team-b` | `team-b` | `team-b` |

## 1. Apply the cluster prerequisites (cluster admin, once per cluster)

1. Apply the CRDs:

   ```console
   kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/main/deploy/crds.yaml
   ```

1. Apply the tenant aggregate manifest. It adds the permissions of the tenant Role, and the right to
   manage NGINX Ingress Controller resources, to the built-in `admin` role in every namespace:

   ```console
   kubectl apply -f https://raw.githubusercontent.com/nginx/kubernetes-ingress/main/deployments/rbac/nic-tenant-aggregate.yaml
   ```

## 2. Install the platform releases (cluster admin, once per team)

Install each platform release in a namespace the team can't modify, so the team can't delete the
release:

```console
kubectl create namespace nic-platform
helm install nic-team-a-platform oci://ghcr.io/nginx/charts/nginx-ingress \
  -n nic-platform --skip-crds -f platform-team-a.yaml
helm install nic-team-b-platform oci://ghcr.io/nginx/charts/nginx-ingress \
  -n nic-platform --skip-crds -f platform-team-b.yaml
```

Each IngressClass name must be unique.

## 3. Install the tenant releases (namespace admin)

A team installing an Ingress Controller must be admin in every namespace it watches. Check before
installing:

```console
for ns in team-a team-a-apps; do kubectl auth can-i create roles -n "$ns"; done
```

Then install the tenant chart:

```console
helm install nic oci://ghcr.io/nginx/charts/nginx-ingress-tenant -n team-a -f tenant-team-a.yaml
```

team-b does the same in its namespace:

```console
helm install nic oci://ghcr.io/nginx/charts/nginx-ingress-tenant -n team-b -f tenant-team-b.yaml
```

`controller.serviceAccount.name` and `controller.ingressClass.name` must match the team's platform
release.

## 4. Use the Ingress Controller

Set `ingressClassName` on each Ingress, VirtualServer, VirtualServerRoute and TransportServer to the
team's IngressClass. An Ingress Controller only sees resources in the namespaces it watches.

## Notes

- Without the CRDs or the aggregate manifest, the tenant install fails with a `forbidden` error, and
  the Ingress Controller logs a named error for each missing CRD or permission.
- To skip the read-only ClusterRole, set `platform.tenantReader.create: false` in the platform
  release and `controller.ingressClass.validation: skip` in the tenant release. Telemetry, license
  reporting and topology-aware routing then run with less information.
- Upgrade in this order: the CRDs and the aggregate manifest, then the platform releases, then the
  tenant releases.
