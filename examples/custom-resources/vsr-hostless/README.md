# Hostless VirtualServerRoute

This example demonstrates the **hostless VirtualServerRoute** feature: a
VirtualServerRoute whose `spec.host` is omitted can be referenced by any
number of VirtualServers, regardless of each VirtualServer's host.

Use this pattern when you want to share a common set of upstreams and routes
(for example, a coffee microservice) across multiple hostnames without
duplicating the route configuration.

## Overview

The example creates:

| Resource | Namespace | Description |
| --- | --- | --- |
| `coffee` VirtualServerRoute | `default` | Hostless — serves `/coffee` using the `coffee-svc` upstream |
| `tea` VirtualServerRoute | `default` | Host-bound to `cafe.example.com` — serves `/tea` |
| `cafe` VirtualServer | `default` | `cafe.example.com` — references both VSRs by name |
| `cafe2` VirtualServer | `default` | `cafe2.example.com` — references the hostless `coffee` VSR by name |
| `cafe3` VirtualServer | `default` | `cafe3.example.com` — references the hostless `coffee` VSR via a label selector |

The `coffee` VSR has no `spec.host` field set (hostless mode), so it can be
attached to `cafe`, `cafe2`, and `cafe3` simultaneously.  Its
`status.referencedBy` field will list all three VirtualServers.

The `tea` VSR has `spec.host: cafe.example.com` and can only be used by
VirtualServers that share that same host.

## Prerequisites

1. Follow the [installation instructions](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   to deploy the Ingress Controller with custom resources enabled.
2. Save the public IP of the Ingress Controller:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    IC_HTTPS_PORT=<port>
    ```

## Step 1 — Deploy the application

```console
kubectl apply -f coffee.yaml
kubectl apply -f tea.yaml
```

## Step 2 — Create Policies

```console
kubectl apply -f rate-limit.yaml
kubectl apply -f access-control-policy-allow.yaml
```

## Step 3 — Create TLS secret

```console
kubectl apply -f cafe-secret.yaml
```

## Step 4 — Create the VirtualServerRoutes

The hostless coffee VSR has no `spec.host`:

```yaml
# coffee-virtual-server-route.yaml (abridged)
apiVersion: k8s.nginx.org/v1
kind: VirtualServerRoute
metadata:
  name: coffee
  labels:
    app: cafe          # matched by cafe3's routeSelector
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
```

```console
kubectl apply -f coffee-virtual-server-route.yaml
kubectl apply -f tea-virtual-server-route.yaml
```

At this point neither VSR has a referencing VirtualServer, so both will show
a `NoVirtualServerFound` warning event.  This is expected.

## Step 5 — Create the VirtualServers

```console
kubectl apply -f cafe-virtual-server.yaml   # references tea + coffee by name
kubectl apply -f cafe2-virtual-server.yaml  # references coffee by name
kubectl apply -f cafe3-virtual-server.yaml  # references coffee by routeSelector
```

## Step 6 — Verify

Check the status of the shared hostless VSR:

```console
kubectl describe virtualserverroute coffee
```

The `status.referencedBy` field should list all three VirtualServers:

```text
Status:
  Referenced By:  default/cafe, default/cafe2, default/cafe3
  State:          Valid
```

Test traffic to each hostname:

```console
# cafe
curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure

# cafe2 (same hostless VSR, different host)
curl --resolve cafe2.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe2.example.com:$IC_HTTPS_PORT/coffee --insecure

# cafe3 (matched via routeSelector)
curl --resolve cafe3.example.com:$IC_HTTPS_PORT:$IC_IP \
  https://cafe3.example.com:$IC_HTTPS_PORT/coffee --insecure
```

All three requests should return a response from the `coffee` upstream.

## Transition: making a hostless VSR host-bound

If you later set `spec.host` on the coffee VSR:

```console
kubectl patch virtualserverroute coffee --type=merge \
  -p '{"spec":{"host":"cafe.example.com"}}'
```

- `cafe` keeps the route (host matches).
- `cafe2` and `cafe3` drop the route and emit an
  `AddedOrUpdatedWithWarning` event — the VSR's host no longer matches
  their host.

Removing `spec.host` again restores the hostless behaviour and re-attaches
the VSR to all three VirtualServers.
