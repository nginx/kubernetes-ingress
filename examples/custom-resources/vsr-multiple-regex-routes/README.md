# Multiple Regex Routes per VirtualServerRoute

In this example we demonstrate how a single
[VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
can be referenced by multiple regex routes in a
[VirtualServer](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/).
This allows route delegation to be grouped by concern — for example, all `/api` regex paths go to one team's
VirtualServerRoute and all `/images` regex paths go to another — while keeping the VirtualServer itself concise.

No application deployment is required. Each route uses an
[ActionReturn](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#actionreturn)
directive that responds with the matched VSR name, path directive, and request URI.

## How It Works

When the Ingress Controller processes a VirtualServer, it collects all regex routes (`~` or `~*`) that reference the
same VirtualServerRoute and validates them together. The VSR's subroutes must form an **exact set match** with those
collected VS paths — every VS path must appear as a VSR subroute, and every VSR subroute must be referenced by a VS
path. If either side has a path the other does not, the VSR is rejected and the VS enters a warning state.

## Path Normalization

The Ingress Controller normalises whitespace between the regex modifier and the path before matching. This means
`~/api/v2` and `~ /api/v2` are treated as equivalent. You can use either form in your VS or VSR and the controller
will accept the configuration as long as the normalized paths match.

In `vsr-api.yaml` the second subroute is written as `~ /api/v2` (with a space), while the VirtualServer declares
`~/api/v2` (without a space). The controller accepts this because both normalize to the same path.

## Route and VSR Mapping

| VS Path | Modifier | VSR | Expected Response |
| --- | --- | --- | --- |
| `/health` | prefix | _(direct return, no VSR)_ | `OK` |
| `~/api/v1` | case-sensitive regex | `vsr-api` | `API v1` |
| `~/api/v2` | case-sensitive regex | `vsr-api` | `API v2` |
| `~*/images/jpg` | case-insensitive regex | `vsr-media` | `JPEG image` |
| `~*/images/png` | case-insensitive regex | `vsr-media` | `PNG image` |

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled.

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1 - Deploy the VirtualServerRoutes

Create both VirtualServerRoute resources:

```console
kubectl apply -f vsr-api.yaml
kubectl apply -f vsr-media.yaml
```

## Step 2 - Deploy the VirtualServer

```console
kubectl apply -f virtual-server.yaml
```

## Step 3 - Verify the Configuration

Check that all three resources were accepted by inspecting their events:

```console
kubectl describe virtualserverroute vsr-api
```

```text
. . .
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  5s    nginx-ingress-controller  Configuration for default/vsr-api was added or updated
```

```console
kubectl describe virtualserverroute vsr-media
```

```text
. . .
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  5s    nginx-ingress-controller  Configuration for default/vsr-media was added or updated
```

```console
kubectl describe virtualserver api-gateway
```

```text
. . .
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  5s    nginx-ingress-controller  Configuration for default/api-gateway was added or updated
```

## Step 4 - Test the Configuration

Use curl's `--resolve` option to direct requests to the Ingress Controller without a DNS entry.

**Health check (direct VS return, no VSR involved):**

```console
curl --resolve api-gateway.example.com:$IC_HTTP_PORT:$IC_IP \
  http://api-gateway.example.com:$IC_HTTP_PORT/health
```

```text
OK
```

**API v1 (matched by `vsr-api`, path `~/api/v1`):**

```console
curl --resolve api-gateway.example.com:$IC_HTTP_PORT:$IC_IP \
  http://api-gateway.example.com:$IC_HTTP_PORT/api/v1
```

```text
API v1
VSR: vsr-api
Path directive: ~/api/v1
Request URI: /api/v1
```

**API v2 (matched by `vsr-api`, path `~/api/v2` in VS — `~ /api/v2` in VSR):**

```console
curl --resolve api-gateway.example.com:$IC_HTTP_PORT:$IC_IP \
  http://api-gateway.example.com:$IC_HTTP_PORT/api/v2
```

```text
API v2
VSR: vsr-api
Path directive: ~/api/v2
Request URI: /api/v2
```

This response is served by the `~ /api/v2` subroute in `vsr-api.yaml`, demonstrating that the space between the
modifier and path is normalised and the VS's `~/api/v2` matches the VSR's `~ /api/v2`.

**JPEG images (matched by `vsr-media`, case-insensitive):**

```console
curl --resolve api-gateway.example.com:$IC_HTTP_PORT:$IC_IP \
  http://api-gateway.example.com:$IC_HTTP_PORT/images/jpg
```

```text
JPEG image
VSR: vsr-media
Path directive: ~*/images/jpg
Request URI: /images/jpg
```

**PNG images (matched by `vsr-media`):**

```console
curl --resolve api-gateway.example.com:$IC_HTTP_PORT:$IC_IP \
  http://api-gateway.example.com:$IC_HTTP_PORT/images/png
```

```text
PNG image
VSR: vsr-media
Path directive: ~*/images/png
Request URI: /images/png
```

---

## Validation Error Cases

The following examples use the same `virtual-server.yaml` and demonstrate what happens when the bidirectional
coverage constraint is violated. In each case `vsr-api` is rejected and the VirtualServer enters a warning state,
but `vsr-media` and the `/health` route are unaffected and continue to serve traffic normally.

### Case 1 - VS References a Path Not Covered by the VSR

`vsr-api-missing-subroute.yaml` declares only `~/api/v1`. The VirtualServer also references `~/api/v2` via this
VSR, so the controller rejects the VSR because it does not cover all VS-declared paths.

Apply the broken VSR:

```console
kubectl apply -f vsr-api-missing-subroute.yaml
```

Inspect the events:

```console
kubectl describe virtualserverroute vsr-api
```

```text
. . .
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  3s    nginx-ingress-controller  VirtualServerRoute default/vsr-api is invalid: spec.subroutes: Invalid value: "subroutes": subroute with path '~/api/v2' is missing; all VS route paths must be covered by VSR subroutes
```

```console
kubectl describe virtualserver api-gateway
```

```text
. . .
Events:
  Type     Reason                  Age   From                      Message
  ----     ------                  ----  ----                      -------
  Warning  AddedOrUpdatedWithWarning  3s  nginx-ingress-controller  Configuration for default/api-gateway was added or updated with warning(s): VirtualServerRoute default/vsr-api is invalid: ...
```

Restore the valid VSR when you are done:

```console
kubectl apply -f vsr-api.yaml
```

### Case 2 - VSR Contains a Path Not Referenced by the VS

`vsr-api-extra-subroute.yaml` adds `~/api/v3` which the VirtualServer never references via this VSR. The controller
rejects the VSR because every VSR subroute must be backed by a VS route.

Apply the broken VSR:

```console
kubectl apply -f vsr-api-extra-subroute.yaml
```

Inspect the events:

```console
kubectl describe virtualserverroute vsr-api
```

```text
. . .
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  3s    nginx-ingress-controller  VirtualServerRoute default/vsr-api is invalid: spec.subroutes[2].path: Invalid value: "~/api/v3": subroute path '~/api/v3' is not referenced by any VS route; all VSR subroutes must be referenced
```

Restore the valid VSR when you are done:

```console
kubectl apply -f vsr-api.yaml
```

### Case 3 - VSR Contains Duplicate Paths After Normalization

`vsr-api-duplicate-paths.yaml` declares both `~/api/v1` and `~ /api/v1`. These two paths normalize to the same
value, which is a duplicate error. The controller rejects the VSR regardless of whether the set would otherwise
match the VS paths.

Apply the broken VSR:

```console
kubectl apply -f vsr-api-duplicate-paths.yaml
```

Inspect the events:

```console
kubectl describe virtualserverroute vsr-api
```

```text
. . .
Events:
  Type     Reason    Age   From                      Message
  ----     ------    ----  ----                      -------
  Warning  Rejected  3s    nginx-ingress-controller  VirtualServerRoute default/vsr-api is invalid: spec.subroutes[0].path: Duplicate value: "~/api/v1", spec.subroutes[1].path: Duplicate value: "~ /api/v1"
```

Note that this is a hard rejection, not a warning. Using `~ /api/v2` in a subroute to _match_ a VS path written as
`~/api/v2` is valid (as shown in the main example above). Having _two separate subroutes_ that resolve to the same
normalized path is always an error.

Restore the valid VSR when you are done:

```console
kubectl apply -f vsr-api.yaml
```
