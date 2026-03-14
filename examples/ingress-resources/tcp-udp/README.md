# Support for  TCP/UDP Load Balancing

In this example we deploy the NGINX or NGINX Plus Ingress Controller, a DNS server and then configure both TCP and UDP
load balancing for the DNS server using the `stream-snippets` [ConfigMap
key](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/).

The standard Kubernetes Ingress resources assume that all traffic is HTTP-based; they do not cater for the case of basic
TCP or UDP load balancing.  In this example, we use the `stream-snippets` ConfigMap key to embed the required TCP and
UDP load-balancing configuration directly into the `stream{}` block of the NGINX configuration file.

With NGINX, we’ll use the DNS name or virtual IP address to identify the service, and rely on kube-proxy to perform the
internal load-balancing across the pool of pods.  With NGINX Plus, we can use a
[headless](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services) service and its DNS name
to obtain the real IP addresses of the pods behind the service, and load-balance across these.  NGINX Plus re-resolves
the DNS name frequently, so will update automatically when new pods are deployed or removed.

## Prerequisites

- We use `dig` for testing. Make sure it is installed on your machine.
- We use built-in NGINX configuration to configure TCP/UDP load balancing. If you'd like to better understand the example
  configuration, read about [TCP/UDP load
  balancing](https://docs.nginx.com/nginx/admin-guide/load-balancer/tcp-udp-load-balancer/) and [DNS service
  discovery](https://www.nginx.com/blog/dns-service-discovery-nginx-plus/) in NGINX/NGINX Plus.

## Running the Example

### 1. Deploy the Ingress Controller

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
instructions to deploy the Ingress Controller. Make sure to expose port 5353 of the Ingress Controller both for TCP and
UDP traffic.

2. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

    **Note**: If you'd like to expose the Ingress Controller via a service with the type LoadBalancer, it is not allowed
    to create a type LoadBalancer service for both TCP and UDP protocols. To overcome this limitation, create two
    separate services, one for TCP and the other for UDP.  In this case you will end up with two separate public IPs,
    one for TCP and the other for UDP. Use the former in Step 4.2 and the latter in Step 4.1.
3. Save port 5353 of the Ingress Controller into a shell variable:

    ```console
    IC_5353_PORT=<port number>
    ```

### 2. Deploy the DNS Server

We deploy two replicas of [CoreDNS](https://coredns.io/), configured to forward DNS queries to `8.8.8.8`. We also create
two services for CoreDNS pods -- `coredns` and `coredns-headless`. The reason for that is explained in Steps 3.1 and
3.2.

Deploy the DNS server:

```console
kubectl apply -f dns.yaml
```

### 3. Configure Load Balancing

We use `stream-snippets` ConfigMap key to configure TCP and UDP load balancing for our CoreDNS pods.

1. Create load balancing configuration. In our example we create one server that listens for TCP traffic on port 5353
   and one server that listens for UDP traffic on the same port. Both servers load balance the incoming traffic to our
   CoreDNS pods:

    - For NGINX, we use the following configuration:

        ```nginx
        upstream coredns-udp {
            server coredns.default.svc.cluster.local:53;
        }

        server {
            listen 5353 udp;
            listen [::]:5353 udp;
            proxy_pass coredns-udp;
            proxy_responses 1;
        }

        upstream coredns-tcp {
            server coredns.default.svc.cluster.local:53;
        }

        server {
            listen 5353;
            listen [::]:5353;
            proxy_pass coredns-tcp;
        }
        ```

        We define upstream servers using a DNS name. When NGINX is reloaded, the DNS name will be resolved into the
        virtual IP of the `coredns` service.

        **Note**: NGINX will fail to reload if the DNS name `coredns.default.svc.cluster.local` cannot be resolved. To
        avoid that, you can define the upstream servers using the virtual IP of the `coredns` service instead of the DNS
        name.

    - For NGINX Plus, we use a different configuration:

        ```nginx
        resolver kube-dns.kube-system.svc.cluster.local valid=5s;

        upstream coredns-udp {
            zone coredns-udp 64k;
            server coredns-headless.default.svc.cluster.local service=_dns._udp resolve;
        }

        server {
            listen 5353 udp;
            listen [::]:5353 udp;
            proxy_pass coredns-udp;
            proxy_responses 1;
            status_zone coredns-udp;
        }

        upstream coredns-tcp {
            zone coredns-tcp 64k;
            server coredns-headless.default.svc.cluster.local service=_dns-tcp._tcp resolve;
        }

        server {
            listen 5353;
            listen [::]:5353;
            proxy_pass coredns-tcp;
            status_zone coredns-tcp;
        }
        ```

        NGINX Plus supports re-resolving DNS names with the `resolve` parameter of the `upstream` directive, which we
        take an advantage of in our example. Additionally, when the `resolve` parameter is used, NGINX Plus will not
        fail to reload if the name of an upstream cannot be resolved, in contrast with NGINX. In addition to IP
        addresses, NGINX Plus will discover ports through DNS SRV records.

        To resolve IP addresses and ports, NGINX Plus uses the Kube-DNS, defined with the `resolver` directive. We also
        set the `valid` parameter to `5s` to make NGINX Plus re-resolve DNS names every 5s.

        Instead of `coredns` service, we use `coredns-headless` service. This service is created as a [headless
        service](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services), meaning that no
        virtual IP is allocated for that service and NGINX Plus will be able to resolve the IP addresses of all the
        CoreDNS pods.

        **Note**: NGINX Plus will fail to reload if the DNS name, specified in the `resolver` directive, cannot be
        resolved. To avoid that, you can define the resolver using the virtual IP of the `kube-dns` service instead of
        the DNS name.

1. Update the ConfigMap with the `stream-snippets` containing the load balancing configuration:
    - For NGINX, run:

        ```console
        kubectl apply -f nginx-config.yaml
        ```

    - For NGINX Plus, run:

        ```console
        kubectl apply -f nginx-plus-config.yaml
        ```

1. Make sure NGINX or NGINX Plus is successfully reloaded:

    ```console
    kubectl describe configmap nginx-config -n nginx-ingress
    ```

    ```text
    . . .
    Events:
    Type    Reason   Age   From                      Message
    ----    ------   ----  ----                      -------
    Normal  Updated  3s    nginx-ingress-controller  Configuration from nginx-ingress/nginx-config was updated
    ```

### 4. Test the DNS Server

To test that the configured TCP/UDP load balancing works, we resolve the name `kubernetes.io` using our DNS server
available through the Ingress Controller:

1. Resolve `kubernetes.io` through UDP:

    ```console
    dig @$IC_IP -p $IC_5353_PORT kubernetes.io
    ```

    ```text
    ; <<>> DiG 9.10.6 <<>> @<REDACTED>> -p 5353 kubernetes.io
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33368
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ;; QUESTION SECTION:
    ;kubernetes.io.                 IN      A

    ;; ANSWER SECTION:
    kubernetes.io.          299     IN      A       45.54.44.100

    ;; Query time: 111 msec
    ;; SERVER:<REDACTED>#5353(<REDACTED>)
    ;; WHEN: Fri Aug 17 12:49:54 BST 2018
    ;; MSG SIZE  rcvd: 71
    ```

1. Resolve `kubernetes.io` through TCP:

    ```console
    dig @$IC_IP -p $IC_5353_PORT kubernetes.io +tcp
    ```

    ```text
    ; <<>> DiG 9.10.6 <<>> @<REDACTED> -p 5353 kubernetes.io +tcp
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49032
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ;; QUESTION SECTION:
    ;kubernetes.io.                 IN      A

    ;; ANSWER SECTION:
    kubernetes.io.          146     IN      A       45.54.44.100

    ;; Query time: 95 msec
    ;; SERVER: <REDACTED>#5353(<REDACTED>)
    ;; WHEN: Fri Aug 17 12:52:25 BST 2018
    ;; MSG SIZE  rcvd: 71
    ```

1. Look at the Ingress Controller logs:

    ```console
    kubectl logs <nginx-ingress-pod> -n nginx-ingress
    ```

    ```text
    . . .
    <REDACTED> [17/Aug/2018:11:49:54 +0000] UDP 200 71 42 0.016
    <REDACTED> [17/Aug/2018:11:52:25 +0000] TCP 200 73 44 0.098
    ```
