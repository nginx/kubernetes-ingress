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

- `externaldns.nginx.org/v1` (default) — for use with external-dns **v0.20.x and earlier**. The CRD is shipped by the NIC Helm chart / manifests.
- `externaldns.k8s.io/v1alpha1` — required by external-dns **v0.21.0 and newer**. The CRD is **not** shipped by NIC to avoid ownership conflicts with the external-dns Helm chart; install it separately from the [external-dns repo](https://github.com/kubernetes-sigs/external-dns).

Toggle groups with the `-external-dns-group-version` command-line flag (or `controller.externalDNSGroupVersion` Helm value). This example uses `externaldns.k8s.io/v1alpha1` and pins external-dns to v0.21.0.

Start NIC with:

```shell
-external-dns-group-version=externaldns.k8s.io/v1alpha1
```

## Step 1: Deploy external-dns

Install the upstream DNSEndpoint CRD (needed because NIC does not ship it):

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
