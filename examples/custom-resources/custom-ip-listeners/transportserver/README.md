# Custom IPv4 and IPv6 Address Listeners

In this example, we will configure a TransportServer resource with custom IPv4 and IPv6 Address using TCP/UDP listeners.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/)
   instructions to deploy the Ingress Controller with custom resources enabled.
2. Ensure the Ingress Controller is configured with the `-global-configuration` argument:

   ```console
   args:
      - -global-configuration=$(POD_NAMESPACE)/nginx-configuration
   ```

**Note:**

- **No Updates for GC:** If a GlobalConfiguration resource already exists, delete the previous one before applying the new configuration.
- **Single Replica:** Only one replica is allowed when using this configuration.

## Step 1 - Deploy the GlobalConfiguration resource

Similar to how listeners are configured in our [custom-listeners](../../custom-listeners) examples,
here we deploy a GlobalConfiguration resource with the listeners we want to use in our VirtualServer.

   ```yaml
apiVersion: k8s.nginx.org/v1
kind: GlobalConfiguration
metadata:
  name: nginx-configuration
  namespace: nginx-ingress
spec:
  listeners:
  - name: tcp-ip-dns-listener
    port: 5353
    protocol: TCP 
    ipv4: 127.0.0.1
  - name: udp-ip-dns-listener
    port: 5252 
    protocol: UDP 
    ipv4: 127.0.0.2
    ipv6: ::1
   ```

   ```console
   kubectl create -f global-configuration.yaml
   ```

## Step 2 - Deploy the DNS Application

Create the dns deployment and service:

   ```console
   kubectl create -f dns.yaml
   ```

## Step 3 - Deploy the TransportServers with custom listeners

The first TransportServer is set to use the udp listener defined in the GlobalConfiguration resource
that was deployed in Step 1. Below is the yaml of this example TransportServer:

```yaml
apiVersion: k8s.nginx.org/v1
kind: TransportServer
metadata:
  name: dns-udp
spec:
  listener:
    name: udp-ip-dns-listener
    protocol: UDP
  upstreams:
  - name: dns-app
    service: coredns
    port: 5252
  upstreamParameters:
    udpRequests: 1
    udpResponses: 1
  action:
    pass: dns-app
```

Create the TransportServer resource:

```console
kubectl create -f udp-transport-server.yaml
```

The second TransportServer is set to use the tcp listener defined in the GlobalConfiguration resource.

```yaml
apiVersion: k8s.nginx.org/v1
kind: TransportServer
metadata:
  name: tcp-dns
spec:
  listener:
    name: tcp-ip-dns-listener
    protocol: TCP
  upstreams:
  - name: dns-app
    service: coredns
    port: 5353
  action:
    pass: dns-app
```

Create the TransportServer resource:

```console
kubectl create -f tcp-transport-server.yaml
```

## Step 4 - Test the Configuration

1. Check that the configuration has been successfully applied by inspecting the events of the TransportServer and the GlobalConfiguration:

    ```console
    kubectl describe ts udp-dns 
    ```

    Below you will see the events as well as the new `Listeners` field

    ```console
    . . .
    Spec:
      Listener:
          name:   udp-ip-dns-listener
          protocol: UDP 
          
    . . .
    Routes:
    . . .
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  1s    nginx-ingress-controller  Configuration for default/udp-dns was added or updated
    ```

    ```console
    kubectl describe globalconfiguration nginx-configuration -n nginx-ingress
    ```

    ```console
    . . .
    Spec:
      Listeners:
        ipv4:      127.0.0.1
        Name:      tcp-ip-dns-listener
        Port:      5353 
        Protocol:  TCP 
        ipv4:      127.0.0.2
        ipv6:      ::1
        Name:      udp-ip-dns-listener
        Port:      5252 
        Protocol:  UDP 

    Events:
      Type    Reason   Age   From                      Message
      ----    ------   ----  ----                      -------
      Normal  Updated  10s   nginx-ingress-controller  GlobalConfiguration nginx-ingress/nginx-configuration was added or updated
    ```

2. Since the deployed TransportServer is using port `5252` this example. you can see that the specific ips and ports
are set and listening by using the below commands:

   Access the NGINX Pod:

    ```console
    kubectl get pods -n nginx-ingress
    ```

    ```text
    NAME                             READY   STATUS    RESTARTS   AGE
    nginx-ingress-5cc9c8f66-4dg2t    1/1     Running   0          50s
    ```

    ```console
    kubectl debug -it nginx-ingress-5cc9c8f66-4dg2t --image=busybox:1.28 --target=nginx-ingress
    ```

    ```console
    / # netstat -tulpn
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
    tcp        0      0 127.0.0.1:5353          0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
    tcp        0      0 :::9113                 :::*                    LISTEN      -
    tcp        0      0 :::80                   :::*                    LISTEN      -
    tcp        0      0 :::443                  :::*                    LISTEN      -
    tcp        0      0 :::8080                 :::*                    LISTEN      -
    tcp        0      0 :::8081                 :::*                    LISTEN      -
    udp        0      0 127.0.0.2:5252          0.0.0.0:*                           -
    udp        0      0 ::1:5252                :::*                                -
    / #
    ```

    We can see here that the two IPv4 addresses (`127.0.0.1:5353` and `127.0.0.2:5252`) and the one IPv6 address (`::1:5252`) are listed.

3. Examine the NGINX config using the following command:

    ```console
    kubectl exec -it nginx-ingress-5cc9c8f66-4dg2t -n nginx-ingress -- cat /etc/nginx/stream-conf.d/ts_default_dns-udp.conf
    ```

    ```console
        ...
        server {
            listen 127.0.0.2:5252 udp;
            listen [::1]:5252 udp;

            ...
        }
    ```
