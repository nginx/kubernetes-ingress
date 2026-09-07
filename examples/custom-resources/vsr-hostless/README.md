# Hostless VirtualServerRoute

This example demonstrates the **hostless VirtualServerRoute** feature: a
VirtualServerRoute whose `spec.host` field is omitted can be referenced by
any number of VirtualServers, regardless of each VirtualServer's own host.

Use this pattern when you want to share a common set of upstreams and
subroutes (for example, a `coffee` microservice) across multiple hostnames
without duplicating the route configuration.

## Overview

The example creates:

| Resource | Kind | Description |
| --- | --- | --- |
| `coffee` | VirtualServerRoute | **Hostless** — serves `/coffee` from the `coffee-svc` upstream |
| `tea` | VirtualServerRoute | Host-bound to `cafe.example.com` — serves `/tea` |
| `cafe` | VirtualServer | `cafe.example.com` — references both VSRs by name |
| `cafe2` | VirtualServer | `cafe2.example.com` — references the hostless `coffee` VSR via a `routeSelector` |
| `cafe3` | VirtualServer | `cafe3.example.com` — references the hostless `coffee` VSR by name |

Because the `coffee` VSR has no `spec.host` field, it can be attached to
`cafe`, `cafe2`, and `cafe3` simultaneously. Its `status.referencedBy` field
lists all three VirtualServers.

The `tea` VSR sets `spec.host: cafe.example.com` and therefore can only be
used by VirtualServers that share that same host.

## Prerequisites

1. Run `make secrets` at the repository root to generate the TLS secret
   manifest (`common-secrets/cafe-secret.yaml`) used by all three
   VirtualServers.
2. Follow the [installation instructions](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   to deploy the Ingress Controller with custom resources enabled.
3. Save the public IP and HTTPS port of the Ingress Controller:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    IC_HTTPS_PORT=<port>
    ```

## Step 1 — Deploy the applications

```console
kubectl apply -f coffee.yaml
kubectl apply -f tea.yaml
```

## Step 2 — Create the TLS secret

```console
kubectl apply -f cafe-secret.yaml
```

## Step 3 — Create the policies

```console
kubectl apply -f rate-limit.yaml
kubectl apply -f access-control-policy-allow.yaml
```

- `rate-limit-policy` is applied at the VirtualServer level on `cafe`.
- `access-control-policy-allow` is applied at the subroute level on the
  hostless `coffee` VSR — every VirtualServer that attaches this VSR
  inherits the policy.

## Step 4 — Create the VirtualServerRoutes

The hostless `coffee` VSR has no `spec.host`:

```yaml
# coffee-virtual-server-route.yaml
apiVersion: k8s.nginx.org/v1
kind: VirtualServerRoute
metadata:
  name: coffee
  labels:
    app: cafe          # matched by cafe2's routeSelector
spec:
  # spec.host is intentionally omitted — hostless mode
  upstreams:
  - name: coffee
    service: coffee-svc
    port: 80
  subroutes:
  - path: /coffee
    action:
      pass: coffee
    policies:
    - name: access-control-policy-allow
```

```console
kubectl apply -f coffee-virtual-server-route.yaml
kubectl apply -f tea-virtual-server-route.yaml
```

At this point neither VSR has a referencing VirtualServer, so both will
show a `NoVirtualServerFound` warning event. This is expected.

## Step 5 — Create the VirtualServers

```console
kubectl apply -f cafe-virtual-server.yaml    # references tea + coffee by name
kubectl apply -f cafe2-virtual-server.yaml   # references coffee via routeSelector
kubectl apply -f cafe3-virtual-server.yaml   # references coffee by name
```

## Step 6 — Verify

Inspect the shared hostless VSR:

```console
kubectl describe virtualserverroute coffee
```

The `status.referencedBy` field should list all three VirtualServers:

```text
Status:
  Referenced By:  default/cafe, default/cafe2, default/cafe3
  State:          Valid
```

Send traffic to each hostname:

```console
# cafe — hostless coffee VSR + host-bound tea VSR
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure

# cafe2 — hostless coffee VSR attached via routeSelector
curl --resolve cafe2.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe2.example.com:$IC_HTTPS_PORT/coffee --insecure

# cafe3 — hostless coffee VSR attached by name
curl --resolve cafe3.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe3.example.com:$IC_HTTPS_PORT/coffee --insecure
```

All three `/coffee` requests are served by the same `coffee` VSR and share
the `access-control-policy-allow` policy defined on its subroute.

## Transition: making a hostless VSR host-bound

Setting `spec.host` on the `coffee` VSR restricts it to a single host:

```console
kubectl patch virtualserverroute coffee --type=merge \
  -p '{"spec":{"host":"cafe.example.com"}}'
```

- `cafe` keeps the route (host matches).
- `cafe2` and `cafe3` drop the route and emit an
  `AddedOrUpdatedWithWarning` event — the VSR's host no longer matches
  theirs.

Removing `spec.host` again restores hostless behaviour and re-attaches the
VSR to all three VirtualServers.
