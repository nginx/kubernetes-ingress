# Multi-tenant installation

This example installs two independent NGINX Ingress Controllers, one for team-a and one for team-b.
Each team installs and runs its own Ingress Controller with permissions in its own namespaces only.

Installation has two phases:

- **Platform phase.** A cluster admin applies the CRDs and the tenant aggregate manifest once per
  cluster, then installs one `platform` release per team. That release creates the team's
  IngressClass and a read-only ClusterRole for the team's Ingress Controller.
- **Tenant phase.** An admin of the team's namespaces installs a `tenant` release. It creates
  namespaced resources only, with a Role in each namespace the Ingress Controller watches.

| Team | Admin user | Release namespace | Watched namespaces | IngressClass |
| --- | --- | --- | --- | --- |
| team-a | `team-a-admin` | `team-a` | `team-a`, `team-a-apps` | `team-a` |
| team-b | `team-b-admin` | `team-b` | `team-b` | `team-b` |

Run the commands from the root of this repository, with a kubectl context that has cluster-admin
rights. The tenant steps impersonate each team's admin user with `--as` and `--kube-as-user`, so
they run with that user's permissions only.

## Prerequisites

1. A Kubernetes cluster, `kubectl`, `helm` and `curl`.
1. An NGINX Ingress Controller image built from this repository that the cluster can pull. Save its
   repository and tag:

   ```console
   export IMAGE_REPOSITORY=<image repository>
   export IMAGE_TAG=<image tag>
   ```

## 1. Apply the cluster prerequisites (cluster admin, once per cluster)

1. Apply the CRDs:

   ```console
   kubectl apply -f deploy/crds.yaml
   ```

1. Apply the tenant aggregate manifest. It adds the permissions of the tenant Role, and the right to
   manage NGINX Ingress Controller resources, to the built-in `admin` role in every namespace:

   ```console
   kubectl apply -f deployments/rbac/nic-tenant-aggregate.yaml
   ```

1. Create the team namespaces and make each team's user an admin of its namespaces:

   ```console
   kubectl create namespace team-a
   kubectl create namespace team-a-apps
   kubectl create namespace team-b
   kubectl create rolebinding team-a-admin --clusterrole=admin --user=team-a-admin -n team-a
   kubectl create rolebinding team-a-admin --clusterrole=admin --user=team-a-admin -n team-a-apps
   kubectl create rolebinding team-b-admin --clusterrole=admin --user=team-b-admin -n team-b
   ```

## 2. Install the platform releases (cluster admin, once per team)

Install each platform release in a namespace the team can't modify, so the team can't delete the
release:

```console
kubectl create namespace nic-platform
helm install nic-team-a-platform charts/nginx-ingress -n nic-platform --skip-crds \
  -f examples/shared-examples/multi-tenant/platform-team-a.yaml
helm install nic-team-b-platform charts/nginx-ingress -n nic-platform --skip-crds \
  -f examples/shared-examples/multi-tenant/platform-team-b.yaml
```

Each IngressClass name must be unique.

## 3. Install the tenant releases (namespace admin)

A team installing an Ingress Controller must be admin in every namespace it watches. Check before
installing:

```console
for ns in team-a team-a-apps; do kubectl auth can-i create roles -n "$ns" --as team-a-admin; done
```

Then install each team's release as its admin. `--skip-crds` is required: the CRDs are a platform
prerequisite, and a namespace admin can't install them.

```console
helm install nic charts/nginx-ingress -n team-a --skip-crds --kube-as-user team-a-admin \
  -f examples/shared-examples/multi-tenant/tenant-team-a.yaml \
  --set controller.image.repository="$IMAGE_REPOSITORY" --set controller.image.tag="$IMAGE_TAG"
helm install nic charts/nginx-ingress -n team-b --skip-crds --kube-as-user team-b-admin \
  -f examples/shared-examples/multi-tenant/tenant-team-b.yaml \
  --set controller.image.repository="$IMAGE_REPOSITORY" --set controller.image.tag="$IMAGE_TAG"
```

`controller.serviceAccount.name` and `controller.ingressClass.name` must match the team's platform
release.

## 4. Use the Ingress Controller

Set `ingressClassName` on each Ingress, VirtualServer, VirtualServerRoute and TransportServer to the
team's IngressClass. An Ingress Controller only sees resources in the namespaces it watches.

1. As team-a's admin, deploy an application and an Ingress in `team-a-apps`:

   ```console
   kubectl apply -n team-a-apps --as team-a-admin -f examples/ingress-resources/complete-example/cafe.yaml
   kubectl create ingress cafe -n team-a-apps --as team-a-admin --class=team-a \
     --rule="cafe.team-a.example.com/coffee*=coffee-svc:80"
   ```

1. Save the public IP address and the HTTP port of each team's Ingress Controller into shell
   variables.

   ```console
   IC_A_IP=XXX.YYY.ZZZ.III
   IC_A_HTTP_PORT=<port number>
   IC_B_IP=XXX.YYY.ZZZ.III
   IC_B_HTTP_PORT=<port number>
   ```

1. team-a's Ingress Controller serves the application. The response contains `Server name: coffee-...`:

   ```console
   curl --resolve cafe.team-a.example.com:$IC_A_HTTP_PORT:$IC_A_IP http://cafe.team-a.example.com:$IC_A_HTTP_PORT/coffee
   ```

1. team-b's Ingress Controller doesn't serve it, and returns `404`:

   ```console
   curl --resolve cafe.team-a.example.com:$IC_B_HTTP_PORT:$IC_B_IP http://cafe.team-a.example.com:$IC_B_HTTP_PORT/coffee
   ```

## Notes

- Without the aggregate manifest, the tenant install fails with a `forbidden` error. Without the
  CRDs, the install succeeds, but the Ingress Controller logs an error naming each missing CRD and
  doesn't become ready until a cluster admin applies them.
- To skip the read-only ClusterRole, set `platform.tenantReader.create: false` in the platform
  release and `controller.ingressClass.validation: skip` in the tenant release. Telemetry, license
  reporting and topology-aware routing then run with less information.
- Upgrade in this order: the CRDs and the aggregate manifest, then the platform releases, then the
  tenant releases.
