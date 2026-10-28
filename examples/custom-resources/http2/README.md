# HTTP/2

In this example we turn HTTP/2 on and off for a single VirtualServer with the `http2` field, which overrides the
`http2` ConfigMap key for that VirtualServer only.

| Setting | Scope |
| --- | --- |
| `http2` ConfigMap key | Default for every server. Off if not set. |
| VirtualServer `spec.http2` | This VirtualServer. If not set, the ConfigMap key applies. |

Unencrypted HTTP/2 (h2c) on the default HTTP listener only works when the ConfigMap key is on, because NGINX decides
whether to accept h2c on a port from that port's default server. Over TLS, HTTP/2 is negotiated per host.

## Prerequisites

1. Run `make secrets` to generate the TLS secret used by the example.
1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled. Leave the `http2` ConfigMap key unset.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTPS port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTPS_PORT=<port number>
    ```

## Step 1 - Deploy the Cafe Application and the VirtualServer

```console
kubectl apply -f ../basic-configuration/cafe.yaml
kubectl apply -f ../basic-configuration/cafe-secret.yaml
kubectl apply -f cafe-virtual-server.yaml
```

## Step 2 - Check that HTTP/2 is on

The VirtualServer sets `http2: true`, so HTTP/2 is on for `cafe.example.com` although the ConfigMap key is off. Ask
curl to print the HTTP version it used:

```console
curl --http2 --insecure --silent --output /dev/null --write-out '%{http_version}\n' \
  --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee
```

```text
2
```

## Step 3 - Turn HTTP/2 off

```console
kubectl patch virtualserver cafe --type merge --patch '{"spec":{"http2":false}}'
```

Repeat the request from Step 2. curl falls back to HTTP/1.1:

```text
1.1
```

With `http2: false`, HTTP/2 stays off for this VirtualServer even if you set `http2: "true"` in the ConfigMap.
