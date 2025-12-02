# Basic TCP/UDP Load Balancing

In this example, we deploy a DNS server in a cluster and configure TCP and UDP load balancing for it using the
TransportServer resource.  As a result, NGINX will pass any connections or datagrams coming to its port 5353 to the DNS
server pods.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller:
   - As part of Step 2 of those instructions, make sure to deploy the GlobalConfiguration resource and configure the
     Ingress Controller to use it.
   - Expose port 5353 of the Ingress Controller both for TCP and UDP traffic.
     (Make use of [controller.customPorts](https://docs.nginx.com/nginx-ingress-controller/install/helm#configuration)
     and [controller.service.customPorts](https://docs.nginx.com/nginx-ingress-controller/install/helm#configuration)
     for exposing Pod and LoadBalancer Port(s) respectively)

1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save port 5353 of the Ingress Controller into a shell variable:

    ```console
    IC_5353_PORT=<port number>
    ```

    **Note**: If you'd like to expose the Ingress Controller via a service with the type LoadBalancer, it is not allowed
    to create a type LoadBalancer service for both TCP and UDP protocols. To overcome this limitation, create two
    separate services, one for TCP and the other for UDP.  In this case, you will end up with two separate public IPs,
    one for TCP and the other for UDP. Use the former in Step 4.1 and the latter in Step 4.2.
1. We use `dig` for testing. Make sure it is installed on your machine.

**Note**: We assume that as part of the Ingress Controller installation, you deployed the GlobalConfiguration resource
in the namespace `nginx-ingress` with the name `nginx-configuration`. If this is not the case, make sure to update the
file `global-configuration.yaml` to use the correct namespace and/or name.

## Step 1 - Deploy the DNS Server

We deploy two replicas of [CoreDNS](https://coredns.io/), configured to forward DNS queries to `8.8.8.8`. We also create
a service for CoreDNS pods with the name `coredns` that exposes two ports: `5353` for TCP and `5353` for UDP:

```console
kubectl apply -f dns.yaml
```

## Step 2 - Configure Listeners

1. Update the GlobalConfiguration resource with two listeners - a TCP listener for port 5353 and a UDP listener for port
   5353:

    ```console
    kubectl apply -f global-configuration.yaml
    ```

2. Check that the configuration has been successfully applied by inspecting the events of the GlobalConfiguration:

    ```console
    kubectl describe gc nginx-configuration -n nginx-ingress
    ```

    ```text
    . . .
    Events:
      Type    Reason   Age               From                      Message
      ----    ------   ----              ----                      -------
      Normal  Updated  0s (x2 over 10s)  nginx-ingress-controller  GlobalConfiguration nginx-ingress/nginx-configuration was updated
    ```

## Step 3 - Configure Load Balancing

1. Create the TransportServer resource to configure TCP load balancing:

    ```console
    kubectl apply -f transport-server-tcp.yaml
    ```

1. Check that the configuration has been successfully applied by inspecting the events of the TransportServer:

    ```console
    kubectl describe ts dns-tcp
    ```

    ```text
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  3s    nginx-ingress-controller  Configuration for default/dns-tcp was added or updated
    ```

1. Create the TransportServer resource to configure UDP load balancing:

    ```console
    kubectl apply -f transport-server-udp.yaml
    ```

1. Check that the configuration has been successfully applied by inspecting the events of the TransportServer:

    ```console
    kubectl describe ts dns-udp
    ```

    ```text
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  0s    nginx-ingress-controller  Configuration for default/dns-udp was added or updated
    ```

## Step 4 - Test the Configuration

To test that the configured TCP/UDP load balancing works, we resolve the name `kubernetes.io` using our DNS server
available through the Ingress Controller.

1. Resolve `kubernetes.io` through TCP:

    ```console
    dig @$IC_IP -p $IC_5353_PORT kubernetes.io +tcp
    ```

    ```text
    ; <<>> DiG 9.10.3-P4-Debian <<>> @<REDACTED> -p 5353 kubernetes.io +tcp
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44784
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 4096
    ;; QUESTION SECTION:
    ;kubernetes.io.                 IN      A

    ;; ANSWER SECTION:
    kubernetes.io.          3596    IN      A       147.75.40.148

    ;; Query time: 134 msec
    ;; SERVER: <REDACTED>#5353(<REDACTED>)
    ;; WHEN: Thu Mar 12 22:01:55 UTC 2020
    ;; MSG SIZE  rcvd: 71
    ```

1. Resolve `kubernetes.io` through UDP:

    ```console
    dig @$IC_IP -p $IC_5353_PORT kubernetes.io
    ```

    ```text
    ; <<>> DiG 9.10.3-P4-Debian <<>> @<REDACTED> -p 5353 kubernetes.io
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39087
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 4096
    ;; QUESTION SECTION:
    ;kubernetes.io.                 IN      A

    ;; ANSWER SECTION:
    kubernetes.io.          2157    IN      A       147.75.40.148

    ;; Query time: 134 msec
    ;; SERVER: <REDACTED>#5353(<REDACTED>)
    ;; WHEN: Thu Mar 12 22:02:12 UTC 2020
    ;; MSG SIZE  rcvd: 71
    ```
