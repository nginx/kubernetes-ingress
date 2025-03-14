---
title: Releases
weight: 2100
toc: true
type: reference
product: NIC
docs: DOCS-616
---
## 4.0.1

07 Feb 2025

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [7295](https://github.com/nginx/kubernetes-ingress/pull/7295) Clean up and fix for NIC Pod failing to bind when NGINX exits unexpectedly

### <i class="fa-solid fa-box"></i> Helm Chart
- [7188](https://github.com/nginx/kubernetes-ingress/pull/7188) Correct typo in helm lease annotations template

### <i class="fa-solid fa-upload"></i> Dependencies
- [7301](https://github.com/nginx/kubernetes-ingress/pull/7301), [7307](https://github.com/nginx/kubernetes-ingress/pull/7307) & [7310](https://github.com/nginx/kubernetes-ingress/pull/7310) Update to nginx 1.27.4
- [7163](https://github.com/nginx/kubernetes-ingress/pull/7163) Bump Go version to 1.23.5
- [7024](https://github.com/nginx/kubernetes-ingress/pull/7024), [7061](https://github.com/nginx/kubernetes-ingress/pull/7061), [7113](https://github.com/nginx/kubernetes-ingress/pull/7113), [7145](https://github.com/nginx/kubernetes-ingress/pull/7145), [7148](https://github.com/nginx/kubernetes-ingress/pull/7148), [7154](https://github.com/nginx/kubernetes-ingress/pull/7154), [7164](https://github.com/nginx/kubernetes-ingress/pull/7164), [7229](https://github.com/nginx/kubernetes-ingress/pull/7229), [7265](https://github.com/nginx/kubernetes-ingress/pull/7265), [7250](https://github.com/nginx/kubernetes-ingress/pull/7250), [7296](https://github.com/nginx/kubernetes-ingress/pull/7296) & [7321](https://github.com/nginx/kubernetes-ingress/pull/7321) Bump Go dependencies
- [7012](https://github.com/nginx/kubernetes-ingress/pull/7012), [7022](https://github.com/nginx/kubernetes-ingress/pull/7022), [7028](https://github.com/nginx/kubernetes-ingress/pull/7028), [7144](https://github.com/nginx/kubernetes-ingress/pull/7144), [7152](https://github.com/nginx/kubernetes-ingress/pull/7152), [7155](https://github.com/nginx/kubernetes-ingress/pull/7155), [7181](https://github.com/nginx/kubernetes-ingress/pull/7181), [7267](https://github.com/nginx/kubernetes-ingress/pull/7267), [7302](https://github.com/nginx/kubernetes-ingress/pull/7302), [7304](https://github.com/nginx/kubernetes-ingress/pull/7304) & [7320](https://github.com/nginx/kubernetes-ingress/pull/7320) Bump Docker dependencies

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 4.0.1 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=4.0.1),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 4.0.1 images from the F5 Container registry or build your own image using the 4.0.1 source code
- For Helm, use version 2.0.1 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.32.

## 4.0.0

16 Dec 2024

With added support for [NGINX R33](https://docs.nginx.com/nginx/releases/#nginxplusrelease-33-r33), deployments of F5 NGINX Ingress Controller using NGINX Plus now require a valid JSON Web Token to run.
Please see the [Upgrading to v4]({{< relref "installation/installing-nic/upgrade-to-v4#create-license-secret" >}}) for full details on setting up your license `Secret`.

API Version `v1alpha1` of `GlobalConfiguration`, `Policy` and `TransportServer` resources are now deprecated.
Please see [Update custom resource apiVersion]({{< relref "installation/installing-nic/upgrade-to-v4#update-custom-resource-apiversion" >}}) for full details on updating your resources.

Updates have been made to our logging library. For a while, F5 NGINX Ingress Controller has been using the [golang/glog](https://github.com/golang/glog). For this release, we have moved to the native golang library [log/slog](https://pkg.go.dev/log/slog).
This change was made for these reasons:
1. By using a standard library, we ensure that updates are more consistent, and any known vulnerabilities are more likely to be addressed in a timely manner.
2. By moving to `log/slog`, we enable support for a wider range of logging formats, as well as allowing log outputs to be displayed in a Structured format, and for faster log parsing.

Layer 4 applications got some love this release, with added support for SNI based routing with our TransportServer resource!
In scenarios where you have multiple applications hosted on a single node, this feature enables routing to those applications through the host header.
For more details on what this feature does, and how to configure it yourself, please look to our [examples section in Github](https://github.com/nginx/kubernetes-ingress/tree/v4.0.0/examples/custom-resources/transport-server-sni#transportserver-sni)

### <i class="fa-solid fa-bomb"></i> Breaking Changes
- [6903](https://github.com/nginx/kubernetes-ingress/pull/6903) & [6921](https://github.com/nginx/kubernetes-ingress/pull/6921) Add support for NGINX Plus R33
- [6800](https://github.com/nginx/kubernetes-ingress/pull/6800) Deprecate v1alpha1 CRDs for GlobalConfiguration, Policy & TransportServer
- [6520](https://github.com/nginx/kubernetes-ingress/pull/6520) & [6474](https://github.com/nginx/kubernetes-ingress/pull/6474) Add structured logging

### <i class="fa-solid fa-rocket"></i> Features
- [6605](https://github.com/nginx/kubernetes-ingress/pull/6605) TransportServer SNI
- [6819](https://github.com/nginx/kubernetes-ingress/pull/6819) Add events to configmap
- [6878](https://github.com/nginx/kubernetes-ingress/pull/6878) Add events when special secrets update

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [6583](https://github.com/nginx/kubernetes-ingress/pull/6583) Generate valid yaml for ReadOnly FS
- [6635](https://github.com/nginx/kubernetes-ingress/pull/6635) UpstreamServer Fields Logs Displayed as Memory Addresses
- [6661](https://github.com/nginx/kubernetes-ingress/pull/6661) Revert to original main-template without pod downtime
- [6733](https://github.com/nginx/kubernetes-ingress/pull/6733) Add nil check to apikey suppliedIn
- [6780](https://github.com/nginx/kubernetes-ingress/pull/6780) Use default VS and TS templates when CfgMap obj is deleted

### <i class="fa-solid fa-box"></i> Helm Chart
- [6667](https://github.com/nginx/kubernetes-ingress/pull/6667) Helm schema examples
- [6998](https://github.com/nginx/kubernetes-ingress/pull/6998) Update kubernetes version to v1.32.0 in helm schema

### <i class="fa-solid fa-upload"></i> Dependencies
- [6485](https://github.com/nginx/kubernetes-ingress/pull/6485), [6497](https://github.com/nginx/kubernetes-ingress/pull/6497), [6512](https://github.com/nginx/kubernetes-ingress/pull/6512), [6533](https://github.com/nginx/kubernetes-ingress/pull/6533), [6543](https://github.com/nginx/kubernetes-ingress/pull/6543), [6557](https://github.com/nginx/kubernetes-ingress/pull/6557), [6580](https://github.com/nginx/kubernetes-ingress/pull/6580), [6607](https://github.com/nginx/kubernetes-ingress/pull/6607), [6638](https://github.com/nginx/kubernetes-ingress/pull/6638), [6654](https://github.com/nginx/kubernetes-ingress/pull/6654), [6657](https://github.com/nginx/kubernetes-ingress/pull/6657), [6676](https://github.com/nginx/kubernetes-ingress/pull/6676), [6685](https://github.com/nginx/kubernetes-ingress/pull/6685), [6699](https://github.com/nginx/kubernetes-ingress/pull/6699), [6697](https://github.com/nginx/kubernetes-ingress/pull/6697), [6719](https://github.com/nginx/kubernetes-ingress/pull/6719), [6717](https://github.com/nginx/kubernetes-ingress/pull/6717), [6747](https://github.com/nginx/kubernetes-ingress/pull/6747), [6743](https://github.com/nginx/kubernetes-ingress/pull/6743), [6775](https://github.com/nginx/kubernetes-ingress/pull/6775), [6789](https://github.com/nginx/kubernetes-ingress/pull/6789), [6762](https://github.com/nginx/kubernetes-ingress/pull/6762), [6786](https://github.com/nginx/kubernetes-ingress/pull/6786), [6845](https://github.com/nginx/kubernetes-ingress/pull/6845), [6864](https://github.com/nginx/kubernetes-ingress/pull/6864), [6880](https://github.com/nginx/kubernetes-ingress/pull/6880), [6862](https://github.com/nginx/kubernetes-ingress/pull/6862), [6897](https://github.com/nginx/kubernetes-ingress/pull/6897), [6890](https://github.com/nginx/kubernetes-ingress/pull/6890), [6905](https://github.com/nginx/kubernetes-ingress/pull/6905), [6906](https://github.com/nginx/kubernetes-ingress/pull/6906), [6909](https://github.com/nginx/kubernetes-ingress/pull/6909), [6919](https://github.com/nginx/kubernetes-ingress/pull/6919), [6936](https://github.com/nginx/kubernetes-ingress/pull/6936), [6945](https://github.com/nginx/kubernetes-ingress/pull/6945), [6971](https://github.com/nginx/kubernetes-ingress/pull/6971) & [6982](https://github.com/nginx/kubernetes-ingress/pull/6982) Bump the Docker dependencies
- [6483](https://github.com/nginx/kubernetes-ingress/pull/6483), [6496](https://github.com/nginx/kubernetes-ingress/pull/6496), [6522](https://github.com/nginx/kubernetes-ingress/pull/6522), [6540](https://github.com/nginx/kubernetes-ingress/pull/6540), [6559](https://github.com/nginx/kubernetes-ingress/pull/6559), [6589](https://github.com/nginx/kubernetes-ingress/pull/6589), [6614](https://github.com/nginx/kubernetes-ingress/pull/6614), [6643](https://github.com/nginx/kubernetes-ingress/pull/6643), [6669](https://github.com/nginx/kubernetes-ingress/pull/6669), [6683](https://github.com/nginx/kubernetes-ingress/pull/6683), [6704](https://github.com/nginx/kubernetes-ingress/pull/6704), [6712](https://github.com/nginx/kubernetes-ingress/pull/6712), [6728](https://github.com/nginx/kubernetes-ingress/pull/6728), [6745](https://github.com/nginx/kubernetes-ingress/pull/6745), [6767](https://github.com/nginx/kubernetes-ingress/pull/6767), [6782](https://github.com/nginx/kubernetes-ingress/pull/6782), [6815](https://github.com/nginx/kubernetes-ingress/pull/6815), [6826](https://github.com/nginx/kubernetes-ingress/pull/6826), [6835](https://github.com/nginx/kubernetes-ingress/pull/6835), [6842](https://github.com/nginx/kubernetes-ingress/pull/6842), [6861](https://github.com/nginx/kubernetes-ingress/pull/6861), [6916](https://github.com/nginx/kubernetes-ingress/pull/6916), [6908](https://github.com/nginx/kubernetes-ingress/pull/6908), [6931](https://github.com/nginx/kubernetes-ingress/pull/6931), [6969](https://github.com/nginx/kubernetes-ingress/pull/6969), [6973](https://github.com/nginx/kubernetes-ingress/pull/6973), [6988](https://github.com/nginx/kubernetes-ingress/pull/6988) & [6994](https://github.com/nginx/kubernetes-ingress/pull/6994) Bump the go dependencies

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 4.0.0 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=4.0.0),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 4.0.0 images from the F5 Container registry or build your own image using the 4.0.0 source code
- For Helm, use version 2.0.0 of the chart.
- [Upgrading to v4]({{< relref "installation/installing-nic/upgrade-to-v4" >}})

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.32.


---
## 3.7.2

25 Nov 2024

{{< note >}}
In our next major release, `v4.0.0`, the default log library for NGINX Ingress Controller will be changed from `golang/glog` to `log/slog`.
This will mean that logs generated by NGINX Ingress Controller will be in a structured format with the option to choose a `string` or `json` output.
This will not affect logs generated by NGINX.
To ensure backwards compatibility, we will ensure the existing log format, `glog`, will be maintained through a configuration option for the next 3 releases.
{{< /note >}}

{{< important >}}
CRD version removal notice.
In our next major release, `v4.0.0`, support for the following apiVersions for these listed CRDs will be dropped:
1. `k8s.nginx.org/v1alpha` for `GlobalConfiguration`
2. `k8s.nginx.org/v1alpha` for `Policy`
3. `k8s.nginx.org/v1alpha` for `TransportServer`

Prior to upgrading, **please ensure** that any of these resources deployed as `apiVersion: k8s.nginx.org/v1alpha1` are upgraded to `apiVersion: k8s.nginx.org/v1`
If a resource of `kind: GlobalConfiguration`, `kind: Policy` or `kind: TransportServer` are deployed as `apiVersion: k8s.nginx.org/v1alpha1`, these resources will be **deleted** when upgrading from, at least, `v3.4.0` to `v4.0.0`

When `v4.0.0` is released, the release notes will contain the required upgrade steps to go from `v3.X.X` to `v4.X.X`
{{< /important >}}

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [6838](https://github.com/nginx/kubernetes-ingress/pull/6838) Update oidc_template and conf

### <i class="fa-solid fa-upload"></i> Dependencies
- [6779](https://github.com/nginx/kubernetes-ingress/pull/6779), [6790](https://github.com/nginx/kubernetes-ingress/pull/6790) & [6851](https://github.com/nginx/kubernetes-ingress/pull/6851) Bump the Docker dependencies
- [6791](https://github.com/nginx/kubernetes-ingress/pull/6791), [6849](https://github.com/nginx/kubernetes-ingress/pull/6849) & [6839](https://github.com/nginx/kubernetes-ingress/pull/6839) Bump the go dependencies

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.7.2 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.7.2),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.7.2 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.7.2 source code
- For Helm, use version 1.4.2 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.31.

---
## 3.7.1

06 Nov 2024

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [6735](https://github.com/nginx/kubernetes-ingress/pull/6735) Add nil check to apikey suppliedIn
- [6761](https://github.com/nginx/kubernetes-ingress/pull/6761) Add OIDC fix for ID token nonce claim validation

### <i class="fa-solid fa-upload"></i> Dependencies
- [6545](https://github.com/nginx/kubernetes-ingress/pull/6545), [6560](https://github.com/nginx/kubernetes-ingress/pull/6560), [6560](https://github.com/nginx/kubernetes-ingress/pull/6560), [6619](https://github.com/nginx/kubernetes-ingress/pull/6619), [6640](https://github.com/nginx/kubernetes-ingress/pull/6640), [6664](https://github.com/nginx/kubernetes-ingress/pull/6664), [6686](https://github.com/nginx/kubernetes-ingress/pull/6686), [6703](https://github.com/nginx/kubernetes-ingress/pull/6703), [6720](https://github.com/nginx/kubernetes-ingress/pull/6720), [6755](https://github.com/nginx/kubernetes-ingress/pull/6755) & [6751](https://github.com/nginx/kubernetes-ingress/pull/6751) Bump the Docker dependencies
- [6553](https://github.com/nginx/kubernetes-ingress/pull/6553), [6591](https://github.com/nginx/kubernetes-ingress/pull/6591), [6618](https://github.com/nginx/kubernetes-ingress/pull/6618), [6648](https://github.com/nginx/kubernetes-ingress/pull/6648), [6688](https://github.com/nginx/kubernetes-ingress/pull/6688), [6674](https://github.com/nginx/kubernetes-ingress/pull/6674), [6707](https://github.com/nginx/kubernetes-ingress/pull/6707), [6730](https://github.com/nginx/kubernetes-ingress/pull/6730) & [6751](https://github.com/nginx/kubernetes-ingress/pull/6751) Bump the go dependencies
- [6570](https://github.com/nginx/kubernetes-ingress/pull/6570) & [6549](https://github.com/nginx/kubernetes-ingress/pull/6549) Bump the go version

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.7.1 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.7.1),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.7.1 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.7.1 source code
- For Helm, use version 1.4.1 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.31.

---
## 3.7.0

30 Sept 2024

Added support for VirtualServer & TransportServer to listen on a specific IP when configuring a listener, allowing NGINX to bind to a specific interface. This is also useful in for scenarios where pods need to connect to multiple networks i.e. multi-homed.
Allow an End Session Endpoint to be configured for OIDC providers via Policy. This allows a user to be fully logged out from their idp session. This change also adds support for configuring a post-logout redirect URI, allowing a users to be redirected to a custom logout page.

The `access_log` directive can now be configured to point to a syslog log server. Previously, access logs defaulted to standard out. This change allows for log parsers aggregators to ingest access logs from NGINX.

When installing NGINX Ingress Controller via Helm, a uniquely named lease object will be created automatically. This allows for multiple deployments of NGINX Ingress Controller in the same namespace when leader election is enabled, without requiring a unique name to be specified manually for each deployment.

### <i class="fa-solid fa-rocket"></i> Features
- [5968](https://github.com/nginx/kubernetes-ingress/pull/5968) Add BUILD_OS to Telemetry
- [6014](https://github.com/nginx/kubernetes-ingress/pull/6014) Sync oidc repo
- [6092](https://github.com/nginx/kubernetes-ingress/pull/6092) Support End Session Endpoint for OIDC and allow customizable Post-logout Redirect URI
- [5648](https://github.com/nginx/kubernetes-ingress/pull/5648) Make access_log in http context configurable
- [6180](https://github.com/nginx/kubernetes-ingress/pull/6180) Add ip as an option to listeners for VirtualServer
- [6367](https://github.com/nginx/kubernetes-ingress/pull/6367) Add ip as an option to listeners for TransportServer

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [5786](https://github.com/nginx/kubernetes-ingress/pull/5786) Change log level, to Info and above, before calling prometheus exporter functions
- [5838](https://github.com/nginx/kubernetes-ingress/pull/5838) Fix api key policy undefined routes
- [5885](https://github.com/nginx/kubernetes-ingress/pull/5885) Add default telemetry endpoint
- [5899](https://github.com/nginx/kubernetes-ingress/pull/5899) GRPC healthcheck should not have keepalive time
- [6125](https://github.com/nginx/kubernetes-ingress/pull/6125) Don't log errors for not implemented grpc metrics
- [6232](https://github.com/nginx/kubernetes-ingress/pull/6232) Fix panic when creating VirtualServer
- [6372](https://github.com/nginx/kubernetes-ingress/pull/6372) Create unique lease obj for each NIC installed via Helm
- [6406](https://github.com/nginx/kubernetes-ingress/pull/6406) Fix udp/http listener validation logic
- [6446](https://github.com/nginx/kubernetes-ingress/pull/6446) Disable batch reload when batch finishes

### <i class="fa-solid fa-box"></i> Helm Chart
- [5817](https://github.com/nginx/kubernetes-ingress/pull/5817) Remove include-year and includeYear flag
- [5335](https://github.com/nginx/kubernetes-ingress/pull/5335) Choose NodePort values for controller.service.type = LoadBalancer
- [6235](https://github.com/nginx/kubernetes-ingress/pull/6235) Update helm docs by @vepatel

### <i class="fa-solid fa-upload"></i> Dependencies
- [5789](https://github.com/nginx/kubernetes-ingress/pull/5789), [5804](https://github.com/nginx/kubernetes-ingress/pull/5804), [5821](https://github.com/nginx/kubernetes-ingress/pull/5821), [5870](https://github.com/nginx/kubernetes-ingress/pull/5870), [5880](https://github.com/nginx/kubernetes-ingress/pull/5880), [5907](https://github.com/nginx/kubernetes-ingress/pull/5907), [5949](https://github.com/nginx/kubernetes-ingress/pull/5949), [5959](https://github.com/nginx/kubernetes-ingress/pull/5959), [5993](https://github.com/nginx/kubernetes-ingress/pull/5993), [6010](https://github.com/nginx/kubernetes-ingress/pull/6010), [6071](https://github.com/nginx/kubernetes-ingress/pull/6071), [6105](https://github.com/nginx/kubernetes-ingress/pull/6105), [6132](https://github.com/nginx/kubernetes-ingress/pull/6132), [6186](https://github.com/nginx/kubernetes-ingress/pull/6186), [6195](https://github.com/nginx/kubernetes-ingress/pull/6195), [6200](https://github.com/nginx/kubernetes-ingress/pull/6200), [6215](https://github.com/nginx/kubernetes-ingress/pull/6215), [6229](https://github.com/nginx/kubernetes-ingress/pull/6229), [6266](https://github.com/nginx/kubernetes-ingress/pull/6266), [6283](https://github.com/nginx/kubernetes-ingress/pull/6283), [6287](https://github.com/nginx/kubernetes-ingress/pull/6287), [6299](https://github.com/nginx/kubernetes-ingress/pull/6299), [6310](https://github.com/nginx/kubernetes-ingress/pull/6310), [6358](https://github.com/nginx/kubernetes-ingress/pull/6358), [6364](https://github.com/nginx/kubernetes-ingress/pull/6364), [6397](https://github.com/nginx/kubernetes-ingress/pull/6397), [6412](https://github.com/nginx/kubernetes-ingress/pull/6412), [6459](https://github.com/nginx/kubernetes-ingress/pull/6459) Bump the go dependencies
- [5929](https://github.com/nginx/kubernetes-ingress/pull/5929), [6337](https://github.com/nginx/kubernetes-ingress/pull/6337), [6350](https://github.com/nginx/kubernetes-ingress/pull/6350) & [6368](https://github.com/nginx/kubernetes-ingress/pull/6368) Bump the go version
- [6052](https://github.com/nginx/kubernetes-ingress/pull/6052) Replace promlog with go-kit
- [6205](https://github.com/nginx/kubernetes-ingress/pull/6205) Update Kubernetes version to v1.31.0
- [5808](https://github.com/nginx/kubernetes-ingress/pull/5808), [5804](https://github.com/nginx/kubernetes-ingress/pull/5804), [5821](https://github.com/nginx/kubernetes-ingress/pull/5821), [5870](https://github.com/nginx/kubernetes-ingress/pull/5870), [5822](https://github.com/nginx/kubernetes-ingress/pull/5822), [5819](https://github.com/nginx/kubernetes-ingress/pull/5819), [5881](https://github.com/nginx/kubernetes-ingress/pull/5881), [5910](https://github.com/nginx/kubernetes-ingress/pull/5910), [5928](https://github.com/nginx/kubernetes-ingress/pull/5928), [5944](https://github.com/nginx/kubernetes-ingress/pull/5944), [5965](https://github.com/nginx/kubernetes-ingress/pull/5965), [5985](https://github.com/nginx/kubernetes-ingress/pull/5985), [6003](https://github.com/nginx/kubernetes-ingress/pull/6003), [6066](https://github.com/nginx/kubernetes-ingress/pull/6066), [6093](https://github.com/nginx/kubernetes-ingress/pull/6093), [6122](https://github.com/nginx/kubernetes-ingress/pull/6122), [6130](https://github.com/nginx/kubernetes-ingress/pull/6130), [6156](https://github.com/nginx/kubernetes-ingress/pull/6156), [6174](https://github.com/nginx/kubernetes-ingress/pull/6174), [6187](https://github.com/nginx/kubernetes-ingress/pull/6187), [6218](https://github.com/nginx/kubernetes-ingress/pull/6218), [6224](https://github.com/nginx/kubernetes-ingress/pull/6224), [6246](https://github.com/nginx/kubernetes-ingress/pull/6246), [6267](https://github.com/nginx/kubernetes-ingress/pull/6267), [6290](https://github.com/nginx/kubernetes-ingress/pull/6290), [6303](https://github.com/nginx/kubernetes-ingress/pull/6303), [6330](https://github.com/nginx/kubernetes-ingress/pull/6330), [6359](https://github.com/nginx/kubernetes-ingress/pull/6359), [6365](https://github.com/nginx/kubernetes-ingress/pull/6365), [6371](https://github.com/nginx/kubernetes-ingress/pull/6371), [6382](https://github.com/nginx/kubernetes-ingress/pull/6382), [6391](https://github.com/nginx/kubernetes-ingress/pull/6391), [6413](https://github.com/nginx/kubernetes-ingress/pull/6413), [6399](https://github.com/nginx/kubernetes-ingress/pull/6399), [6434](https://github.com/nginx/kubernetes-ingress/pull/6434) Bump the Docker dependencies

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.7.0 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.7.0),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.7.0 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.7.0 source code
- For Helm, use version 1.4.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.31.

---
## 3.6.2

19 Aug 2024

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [6125](https://github.com/nginx/kubernetes-ingress/pull/6125) Don't log errors for not implemented grpc metrics
- [6223](https://github.com/nginx/kubernetes-ingress/pull/6223) Re-order mounting debian apt source file

### <i class="fa-solid fa-upload"></i> Dependencies
- [5974](https://github.com/nginx/kubernetes-ingress/pull/5974), [6021](https://github.com/nginx/kubernetes-ingress/pull/6021), [5998](https://github.com/nginx/kubernetes-ingress/pull/5998), [6081](https://github.com/nginx/kubernetes-ingress/pull/6081), [6120](https://github.com/nginx/kubernetes-ingress/pull/6120), [6141](https://github.com/nginx/kubernetes-ingress/pull/6141), [6196](https://github.com/nginx/kubernetes-ingress/pull/6196), [6204](https://github.com/nginx/kubernetes-ingress/pull/6204), [6211](https://github.com/nginx/kubernetes-ingress/pull/6211), [6222](https://github.com/nginx/kubernetes-ingress/pull/6204) & [6234](https://github.com/nginx/kubernetes-ingress/pull/6234) Go dependencies
- [5967](https://github.com/nginx/kubernetes-ingress/pull/5967), [6013](https://github.com/nginx/kubernetes-ingress/pull/6013), [6070](https://github.com/nginx/kubernetes-ingress/pull/6070), [6098](https://github.com/nginx/kubernetes-ingress/pull/6098), [6126](https://github.com/nginx/kubernetes-ingress/pull/6126), [6158](https://github.com/nginx/kubernetes-ingress/pull/6158), [6179](https://github.com/nginx/kubernetes-ingress/pull/6179), [6191](https://github.com/nginx/kubernetes-ingress/pull/6191), [6226](https://github.com/nginx/kubernetes-ingress/pull/6226) & [6233](https://github.com/nginx/kubernetes-ingress/pull/6233) Docker base image updates

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.6.2 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.6.2),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.6.2 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.6.2 source code
- For Helm, use version 1.3.2 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.31.

---
## 3.6.1

04 Jul 2024

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [5921](https://github.com/nginx/kubernetes-ingress/pull/5921) GRPC healthcheck should not have keepalive time
- [5889](https://github.com/nginx/kubernetes-ingress/pull/5889) Add default telemetry endpoint

### <i class="fa-solid fa-upload"></i> Dependencies
- [5930](https://github.com/nginx/kubernetes-ingress/pull/5930) Bump Go version to 1.22.5
- [5947](https://github.com/nginx/kubernetes-ingress/pull/5947), [5923](https://github.com/nginx/kubernetes-ingress/pull/5923), [5943](https://github.com/nginx/kubernetes-ingress/pull/5943), [5939](https://github.com/nginx/kubernetes-ingress/pull/5939) and [5882](https://github.com/nginx/kubernetes-ingress/pull/5882) Docker image updates
- [5951](https://github.com/nginx/kubernetes-ingress/pull/5951), [5933](https://github.com/nginx/kubernetes-ingress/pull/5933), [5884](https://github.com/nginx/kubernetes-ingress/pull/5884) and [5877](https://github.com/nginx/kubernetes-ingress/pull/5877) Go dependencies update

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.6.1 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.6.1),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.6.1 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking), the [Azure Marketplace](https://azuremarketplace.microsoft.com/en-gb/marketplace/apps/category/containers?page=1&search=f5&subcategories=container-apps)
or build your own image using the 3.6.1 source code
- For Helm, use version 1.3.1 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.30.

---
## 3.6.0

25 Jun 2024

Added support for the latest generation of NGINX App Protect Web Application Firewall, v5. NGINX Ingress Controller will continue to support the NGINX App Protect v4 family to allow customers to implement new Policy Bundle workflow at their own pace.
NGINX App Protect WAF v5 does not accept the JSON based policies, instead requiring users to compile a Policy Bundle outside of the NGINX Ingress Controller pod. Policy bundles contain a combination of custom Policy, signatures, and campaigns. Bundles can be compiled using either App Protect [compiler](https://docs.nginx.com/nginx-app-protect-waf/v5/admin-guide/compiler/), or [NGINX Instance Manager](https://docs.nginx.com/nginx-instance-manager/nginx-app-protect/manage-waf-security-policies/#list-security-policy-bundles).  Learn more here, https://docs.nginx.com/nginx-ingress-controller/installation/integrations/app-protect-waf-v5/.

With this release, NGINX Ingress Controller is implementing a new image maintenance policy. Container images for subscribed users will be updated on a regular basis in-between releases to reduce the CVE vulnerabilities.
Customers can observe the 3.6.x tag when listing images in the registry and select the latest image to update to for the current release.

### <i class="fa-solid fa-rocket"></i> Features
- [5698](https://github.com/nginx/kubernetes-ingress/pull/5698), [5771](https://github.com/nginx/kubernetes-ingress/pull/5771) & [5784](https://github.com/nginx/kubernetes-ingress/pull/5784) Add support for F5 NGINX AppProtect WAF v5
- [5580](https://github.com/nginx/kubernetes-ingress/pull/5580) & [5752](https://github.com/nginx/kubernetes-ingress/pull/5752) Add APIKey Authentication policy
- [5205](https://github.com/nginx/kubernetes-ingress/pull/5205) Preserve valid listeners when invalid listeners are present in GlobalConfiguration
- [5366](https://github.com/nginx/kubernetes-ingress/pull/5366) Add proxy-set-headers annotation for ingress
- [5406](https://github.com/nginx/kubernetes-ingress/pull/5406), [5408](https://github.com/nginx/kubernetes-ingress/pull/5408), [5418](https://github.com/nginx/kubernetes-ingress/pull/5418), [5404](https://github.com/nginx/kubernetes-ingress/pull/5404) & [5415](https://github.com/nginx/kubernetes-ingress/pull/5415) Add additional telemetry data

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [5350](https://github.com/nginx/kubernetes-ingress/pull/5350) Fix ap-waf flag in error message
- [5318](https://github.com/nginx/kubernetes-ingress/pull/5318) Don't reload when `use-cluster-ip` endpoints update, and change the ingress `use-cluster-ip` implementation to use the cluster ip instead of the fqdn
- [5375](https://github.com/nginx/kubernetes-ingress/pull/5375) Fix status for invalid vs and vsr, for weight changes dynamic reload

### <i class="fa-solid fa-box"></i> Helm Chart
- [5313](https://github.com/nginx/kubernetes-ingress/pull/5313) Update helm flag in docs for enableWeightChangesDynamicReload

### <i class="fa-solid fa-upload"></i> Dependencies
- [5693](https://github.com/nginx/kubernetes-ingress/pull/5693) Bump Go version to v1.22.4
- [5368](https://github.com/nginx/kubernetes-ingress/pull/5368), [5331](https://github.com/nginx/kubernetes-ingress/pull/5331) & [5423](https://github.com/nginx/kubernetes-ingress/pull/5423) Bump the go dependencies
- [5298](https://github.com/nginx/kubernetes-ingress/pull/5298), [5344](https://github.com/nginx/kubernetes-ingress/pull/5344), [5345](https://github.com/nginx/kubernetes-ingress/pull/5345),[5371](https://github.com/nginx/kubernetes-ingress/pull/5371), [5378](https://github.com/nginx/kubernetes-ingress/pull/5378), [5379](https://github.com/nginx/kubernetes-ingress/pull/5379), [5398](https://github.com/nginx/kubernetes-ingress/pull/5398), [5397](https://github.com/nginx/kubernetes-ingress/pull/5397), [5399](https://github.com/nginx/kubernetes-ingress/pull/5399) & [5400](https://github.com/nginx/kubernetes-ingress/pull/5400) Bump base Docker images

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.6.0 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.6.0),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.6.0 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking), the [Azure Marketplace](https://azuremarketplace.microsoft.com/en-gb/marketplace/apps/category/containers?page=1&search=f5&subcategories=container-apps)
or build your own image using the 3.6.0 source code
- For Helm, use version 1.3.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.30.

---
## 3.5.2

31 May 2024

### <i class="fa-solid fa-triangle-exclamation"></i> Important

- Bundles compiled on NAP WAF versions <= v4.8.x are not compatible with NAP WAF versions >= 4.9.x, this release of NIC includes NAP WAF v4.10 so recompilation of policy bundles is required. JSON based [WAF Policies](https://docs.nginx.com/nginx-ingress-controller/installation/integrations/app-protect-waf/configuration/#waf-policies) aren't affected with this change.

### <i class="fa-solid fa-upload"></i> Dependencies

- [5654](https://github.com/nginx/kubernetes-ingress/pull/5654) NGINX 1.27.0 and [NGINX Plus R32](https://www.f5.com/company/blog/nginx/nginx-plus-r32-released)
- [5590](https://github.com/nginx/kubernetes-ingress/pull/5590), [5631](https://github.com/nginx/kubernetes-ingress/pull/5631), [5638](https://github.com/nginx/kubernetes-ingress/pull/5638), [5662](https://github.com/nginx/kubernetes-ingress/pull/5662), [5623](https://github.com/nginx/kubernetes-ingress/pull/5623) Go updates
- [5579](https://github.com/nginx/kubernetes-ingress/pull/5579), [5642](https://github.com/nginx/kubernetes-ingress/pull/5642), [5573](https://github.com/nginx/kubernetes-ingress/pull/5573), [5630](https://github.com/nginx/kubernetes-ingress/pull/5630), [5665](https://github.com/nginx/kubernetes-ingress/pull/5665), [5673](https://github.com/nginx/kubernetes-ingress/pull/5673) Container base image updates


### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.5.2 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.5.2),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.5.2 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking), the [Azure Marketplace](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/nginxinc.nginx_ingress_premium?tab=Overview),
or build your own image using the 3.5.2 source code
- For Helm, use version 1.2.2 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.25-1.30.

## 3.5.1

08 May 2024

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [5463](https://github.com/nginx/kubernetes-ingress/pull/5463) Don't reload when use-cluster-ip endpoints update
- [5464](https://github.com/nginx/kubernetes-ingress/pull/5464) Fix status for invalid vs and vsr, for weight changes dynamic reload
- [5470](https://github.com/nginx/kubernetes-ingress/pull/5470) Add support for named ports in ingresses which use-cluster-ip

### <i class="fa-solid fa-box"></i> Helm Chart
- [5315](https://github.com/nginx/kubernetes-ingress/pull/5315) Update helm flag in docs for enableWeightChangesDynamicReload

### <i class="fa-solid fa-upload"></i> Dependencies
- [5511](https://github.com/nginx/kubernetes-ingress/pull/5511) & [5391](https://github.com/nginx/kubernetes-ingress/pull/5391) Go updates
- [5490](https://github.com/nginx/kubernetes-ingress/pull/5490) Pin app-protect module version to 4.8.1

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.5.1 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.5.1),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.5.1 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.5.1 source code
- For Helm, use version 1.2.1 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.23-1.29.

## 3.5.0

26 Mar 2024

NGINX Ingress Controller and NGINX App Protect WAF users can can now view violations through NGINX Instance Manager Security Monitor.  Security Monitor can be used to build Policy bundles, reducing reload time impacts on NGINX Ingress Controller.  Read more information in [NGINX App Protect WAF Bundles](https://docs.nginx.com/nginx-ingress-controller/installation/integrations/app-protect-waf/configuration/#waf-bundles) and [Security Monitoring](https://docs.nginx.com/nginx-instance-manager/monitoring/security-monitoring/).

When using NGINX Plus for two version [split rollouts](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#split), you can now control progressive rollouts of a new backend version without reloading NGINX using the [**-weight-changes-dynamic-reload**](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-weight-changes-dynamic-reload) command line argument.

The [**use-cluster-ip**](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#backend-services-upstreams) annotation is now available for the Ingress resource.
**use-cluster-ip** supports service meshes and specific use cases where the backend service should be the target instead of individual backend service pods, bypassing upstream load balancing.

### <i class="fa-solid fa-rocket"></i> Features
- [5179](https://github.com/nginx/kubernetes-ingress/pull/5179) & [5051](https://github.com/nginx/kubernetes-ingress/pull/5051) Add NIM Security Dashboard integration for App Protect WAF security violations
- [5212](https://github.com/nginx/kubernetes-ingress/pull/5212) Weight changes Dynamic Reload
- [4862](https://github.com/nginx/kubernetes-ingress/pull/4862) Add use-cluster-ip annotation for ingress resources
- [4660](https://github.com/nginx/kubernetes-ingress/pull/4660) Add annotations for controlling request rate limiting
- [5083](https://github.com/nginx/kubernetes-ingress/pull/5083) Update default values for keepalive-requests and keepalive-timeout
- [5084](https://github.com/nginx/kubernetes-ingress/pull/5084) Allow securityContext and podSecurityContext to be configurable via helm parameters
- [5199](https://github.com/nginx/kubernetes-ingress/pull/5199) Update zone size for transportserver resource
- [4896](https://github.com/nginx/kubernetes-ingress/pull/4896), [5095](https://github.com/nginx/kubernetes-ingress/pull/5095), [5147](https://github.com/nginx/kubernetes-ingress/pull/5147), [5155](https://github.com/nginx/kubernetes-ingress/pull/5155), [5170](https://github.com/nginx/kubernetes-ingress/pull/5170), [5176](https://github.com/nginx/kubernetes-ingress/pull/5176), [5217](https://github.com/nginx/kubernetes-ingress/pull/5217), [5245](https://github.com/nginx/kubernetes-ingress/pull/5245), [5237](https://github.com/nginx/kubernetes-ingress/pull/5237), [5256](https://github.com/nginx/kubernetes-ingress/pull/5256), [5167](https://github.com/nginx/kubernetes-ingress/pull/5167) & [5261](https://github.com/nginx/kubernetes-ingress/pull/5261) Export Telemetry data to XCDF

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [5211](https://github.com/nginx/kubernetes-ingress/pull/5211) Move set above rewrite to fix uninitialized variable
- [5175](https://github.com/nginx/kubernetes-ingress/pull/5175) Initialize `stopCh` channel for ExternalDNS
- [5053](https://github.com/nginx/kubernetes-ingress/pull/5053) Ensure `backup` server is removed from upstreams when the Backup Service is deleted

### <i class="fa-solid fa-box"></i> Helm Chart
- [5159](https://github.com/nginx/kubernetes-ingress/pull/5159) Refactor volumes and volumeMounts to common helpers
- [5179](https://github.com/nginx/kubernetes-ingress/pull/5179) Move common pod label definitions to helpers

### <i class="fa-solid fa-upload"></i> Dependencies
- [4803](https://github.com/nginx/kubernetes-ingress/pull/4803), [4846](https://github.com/nginx/kubernetes-ingress/pull/4846), [4873](https://github.com/nginx/kubernetes-ingress/pull/4873), [4905](https://github.com/nginx/kubernetes-ingress/pull/4905), [5098](https://github.com/nginx/kubernetes-ingress/pull/5098), [5108](https://github.com/nginx/kubernetes-ingress/pull/5108), [5125](https://github.com/nginx/kubernetes-ingress/pull/5125), [5132](https://github.com/nginx/kubernetes-ingress/pull/5132), [5207](https://github.com/nginx/kubernetes-ingress/pull/5207), [5234](https://github.com/nginx/kubernetes-ingress/pull/5234), [5267](https://github.com/nginx/kubernetes-ingress/pull/5267), [5272](https://github.com/nginx/kubernetes-ingress/pull/5272) & [5218](https://github.com/nginx/kubernetes-ingress/pull/5218) Go Dependency updates
- [5208](https://github.com/nginx/kubernetes-ingress/pull/5208) Bump Go version to 1.22.1

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.5.0 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.5.0),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.5.0 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.5.0 source code
- For Helm, use version 1.2.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.23-1.29.

## 3.4.3

19 Feb 2024

### <i class="fa-solid fa-bug-slash"></i> Fixes
- [5008](https://github.com/nginx/kubernetes-ingress/pull/5008) Remove redundant Prometheus variable labels
- [4744](https://github.com/nginx/kubernetes-ingress/pull/4744) Fixed validation for VSR exact & regex subroutes.  Thanks to [jo-carter](https://github.com/jo-carter).
- [4832](https://github.com/nginx/kubernetes-ingress/pull/4832) Fix new lines in snippets
- [5020](https://github.com/nginx/kubernetes-ingress/pull/5020) Fix template file spacing for `ssl_protocols` directive
- [5041](https://github.com/nginx/kubernetes-ingress/pull/5041) Allow waf users to build without dos repo access

### <i class="fa-solid fa-box"></i> Helm Chart
- [4953](https://github.com/nginx/kubernetes-ingress/pull/4953) Add docs links to helm NOTES.txt

### <i class="fa-solid fa-upload"></i> Dependencies
- [5073](https://github.com/nginx/kubernetes-ingress/pull/5073), [5029](https://github.com/nginx/kubernetes-ingress/pull/5029) Bump redhat/ubi8 base image
- [4992](https://github.com/nginx/kubernetes-ingress/pull/4992) Bump ubi base image
- [4994](https://github.com/nginx/kubernetes-ingress/pull/4994) Bump redhat/ubi9-minimal base image
- [5074](https://github.com/nginx/kubernetes-ingress/pull/5074), [4927](https://github.com/nginx/kubernetes-ingress/pull/4927) Bump opentracing/nginx-opentracing
- [5072](https://github.com/nginx/kubernetes-ingress/pull/5072), [5028](https://github.com/nginx/kubernetes-ingress/pull/5028), [5019](https://github.com/nginx/kubernetes-ingress/pull/5019), [5012](https://github.com/nginx/kubernetes-ingress/pull/5012), [5003](https://github.com/nginx/kubernetes-ingress/pull/5003), [4926](https://github.com/nginx/kubernetes-ingress/pull/4926), [5119](https://github.com/nginx/kubernetes-ingress/pull/5119) Bump nginx image
- [4925](https://github.com/nginx/kubernetes-ingress/pull/4925) Bump the debian base image
- [5004](https://github.com/nginx/kubernetes-ingress/pull/5004), [4984](https://github.com/nginx/kubernetes-ingress/pull/4984), [4928](https://github.com/nginx/kubernetes-ingress/pull/4928) Bump golang build image
- [5033](https://github.com/nginx/kubernetes-ingress/pull/5033) Updates `kindest/node` from v1.29.0 to v1.29.1
- [4909](https://github.com/nginx/kubernetes-ingress/pull/4909), [4924](https://github.com/nginx/kubernetes-ingress/pull/4924), [4939](https://github.com/nginx/kubernetes-ingress/pull/4939), [4949](https://github.com/nginx/kubernetes-ingress/pull/4949), [4971](https://github.com/nginx/kubernetes-ingress/pull/4971), [5022](https://github.com/nginx/kubernetes-ingress/pull/5022), [5034](https://github.com/nginx/kubernetes-ingress/pull/5034), [5055](https://github.com/nginx/kubernetes-ingress/pull/5055) Bump the go dependencies

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.4.3 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.4.3),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.4.3 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.4.3 source code
- For Helm, use version 1.1.3 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.23-1.29.

## 3.4.2

16 Jan 2024

### <i class="fa-solid fa-bug-slash"></i> Fixes
[4934](https://github.com/nginx/kubernetes-ingress/pull/4934) GCR & AWS Plus image publishing fix

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.4.2 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.4.2),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.4.2 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.4.2 source code
- For Helm, use version 1.1.2 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.23-1.29.

## 3.4.1

15 Jan 2024

### <i class="fa-solid fa-upload"></i> Dependencies
[4886](https://github.com/nginx/kubernetes-ingress/pull/4886) Update N+ to R31
[4886](https://github.com/nginx/kubernetes-ingress/pull/4886) Bump Go dependencies.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.4.1 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.4.1),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.4.1 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.4.1 source code
- For Helm, use version 1.1.1 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.23-1.29.

## 3.4.0

19 Dec 2023

The default_server listeners for ports 80 and 443 can now be fully customized giving you the flexibility to shift the HTTP and HTTPS default listeners to other ports as your needs require.

Traffic splits now support weights from 0 - 100 giving you the control that you expect when performing canary roll outs of your back end services.

A new capability of "upstream backup" has been introduced for NGINX Plus customers. This gives you the control to set a backup service for any path. This takes advantage of NGINX health checks and will automatically forward traffic to the backup service when all pods of the primary service stop responding.

Dynamic reloading of SSL certificates takes advantage of native NGINX functionality to dynamically load updated certificates when they are requested and thus not require a reload when certificates update.

A number of Helm enhancements have come directly from our community and range from giving greater flexibility for HPA, namespace sharing for custom sidecars, and supporting multiple image pull secrets for greater deployment flexibility.

To make sure NGINX Ingress Controller follows Helm best practices, we've refactored our helm chart location. You can now find our helm charts under `charts\nginx-ingress`.

We’ve added the functionality to define App Protect WAF bundles for VirtualServers by creating policy bundles and putting them on a mounted volume accessible from NGINX Ingress Controller.

### <i class="fa-solid fa-rocket"></i> Features

- [4574](https://github.com/nginx/kubernetes-ingress/pull/4574) Graduate TransportServer and GlobalConfiguration to v1.
- [4464](https://github.com/nginx/kubernetes-ingress/pull/4464) Allow default_server listeners to be customised.
- [4526](https://github.com/nginx/kubernetes-ingress/pull/4526) Update use of http2 listen directive to align with deprecation.
- [4276](https://github.com/nginx/kubernetes-ingress/pull/4276) Use Lease for leader election.
- [4655](https://github.com/nginx/kubernetes-ingress/pull/4655) Support weights 0 and 100 in traffic splitting.
- [4653](https://github.com/nginx/kubernetes-ingress/pull/4653) Add support for backup directive for VS and TS.
- [4788](https://github.com/nginx/kubernetes-ingress/pull/4788) Dynamic reload of SSL certificates
- [4428](https://github.com/nginx/kubernetes-ingress/pull/4428) Add option for installing CRDs from a single remote yaml.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [4504](https://github.com/nginx/kubernetes-ingress/pull/4504) Delete the DNSEndpoint resource when VS is deleted & Ratelimit requeues on errors.
- [4575](https://github.com/nginx/kubernetes-ingress/pull/4575) update dockerfile for debian NGINX Plus.

### <i class="fa-solid fa-box"></i> Helm Chart

- [4306](https://github.com/nginx/kubernetes-ingress/pull/4306) Refactor Helm Chart location.
- [4391](https://github.com/nginx/kubernetes-ingress/pull/4391) Add HPA Custom Behavior.  Thanks to [saedx1](https://github.com/saedx1).
- [4559](https://github.com/nginx/kubernetes-ingress/pull/4559) Add process namespace sharing for ingress controller.  Thanks to [panzouh](https://github.com/panzouh).
- [4651](https://github.com/nginx/kubernetes-ingress/pull/4651) Add initContainerResources Helm configuration.
- [4656](https://github.com/nginx/kubernetes-ingress/pull/4656) Allows multiple imagePullSecrets in the helm chart.  Thanks to [AlessioCasco](https://github.com/AlessioCasco).

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.4.0 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.4.0),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.4.0 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.4.0 source code
- For Helm, use version 1.1.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by
its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes
versions: 1.22-1.29.
<hr>

## 3.3.2

1 Nov 2023

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [4578](https://github.com/nginx/kubernetes-ingress/pull/4578) Update Dockerfile to add user creation for NGINX Plus images.

### <i class="fa-solid fa-upload"></i> Dependencies

- [4572](https://github.com/nginx/kubernetes-ingress/pull/4572) Update NGINX version to 1.25.3.
- [4569](https://github.com/nginx/kubernetes-ingress/pull/4569), [4591](https://github.com/nginx/kubernetes-ingress/pull/4591) Bump Go dependencies.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.3.2 images from our
[DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.3.2),
[GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress),
[Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.3.2 images from the F5 Container registry,
the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE),
the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking)
or build your own image using the 3.3.2 source code
- For Helm, use version 1.0.2 of the chart.

<hr>

## 3.3.1

13 Oct 2023

### <i class="fa-solid fa-magnifying-glass"></i> Overview

This releases updates NGINX Plus to R30 P1 and dependencies to mitigate HTTP/2 Rapid Reset Attack vulnerability [CVE-2023-44487](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487).

### <i class="fa-solid fa-upload"></i> Dependencies

- [4501](https://github.com/nginx/kubernetes-ingress/pull/4501) Bump Go to 1.21.3
- [4502](https://github.com/nginx/kubernetes-ingress/pull/4502), [4514](https://github.com/nginx/kubernetes-ingress/pull/4514) Bump Go dependencies.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.3.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.3.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.3.1 images from the F5 Container registry, the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE), the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking) or build your own image using the 3.3.1 source code

<hr>

## 3.3.0

26 Sep 2023

### <i class="fa-solid fa-magnifying-glass"></i> Overview

With release 3.3, NGINX Ingress Controller continues to advance capabilities for an ever-demanding set of use cases
that go beyond simple layer 7 routing for services running exclusively in Kubernetes.

When involved in diagnostic operations and viewing the NGINX Plus console or when viewing the enhanced NGINX Plus
metrics through Prometheus, customers now enjoy the added dimension of the backend service being available to aide in
identification of issues as well as observing performance.

50% of our users continue to rely heavily on the Ingress resource and its "mergeable Ingress" usage pattern, to enhance
the experience for these customers we have added the path-regex annotation with support for case sensitive, case
insensitive, as well as exact regex match patterns.

Prometheus continues to be the most popular metrics platform for Kubernetes users. To further enhance ease of setting up
integration with Prometheus we have finalized support for the Prometheus serviceMonitor capability. Providing better
scraping controls for Prometheus admins.

For our most demanding customers performing a blue / green upgrade of the Ingress Controller itself supports the ability
to provide their business customers an enhanced experience with no loss of session fidelity. Support for this pattern
and others has been added through Helm chart enhancement that allows two deployments to share a single ingressClass
resource and duplicate the same configuration.

To accommodate these enhancements, several new values have been added to our Helm chart, as well as modifications to
existing values. Due to the potential impacts of these changes we have issued a major release to the Helm chart,
advancing to v1.0.0

To better align with the demands of supporting additional protocols such as MQTT and QUIC, NGINX Ingress Controller
is changing how listeners are defined for HTTP traffic. You have always had controls over the ports defined for
TCP/UDP traffic through the GlobalConfiguration and TransportServer objects. That same flexibility has been introduced
for HTTP/S traffic and the VirtualServer. This area will continue to expand to give customers full control over NGINX
listeners so they can tailor to their specific needs and policies.

### <i class="fa-solid fa-rocket"></i> Features

- [4023](https://github.com/nginx/kubernetes-ingress/pull/4023) Read Prometheus key/cert from memory.
- [4080](https://github.com/nginx/kubernetes-ingress/pull/4080) Expose Location Zones metrics.
- [4127](https://github.com/nginx/kubernetes-ingress/pull/4127), [4200](https://github.com/nginx/kubernetes-ingress/pull/4200), [4223](https://github.com/nginx/kubernetes-ingress/pull/4223) Add path-regex annotation for ingress.
- [4108](https://github.com/nginx/kubernetes-ingress/pull/4108) Add command line argument for custom TLS Passthrough port.
- [4271](https://github.com/nginx/kubernetes-ingress/pull/4271) Add custom listener controls to VirtualServer.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [4160](https://github.com/nginx/kubernetes-ingress/pull/4160) Update JWT/JWKS policy validation.
- [4371](https://github.com/nginx/kubernetes-ingress/pull/4371) Improve runtime batch reloads.

### <i class="fa-solid fa-box"></i> Helm Chart

- [3977](https://github.com/nginx/kubernetes-ingress/pull/3977) Add support for controller.selectorLabels. Thanks to [Youqing Han](https://github.com/hanyouqing).
- [4058](https://github.com/nginx/kubernetes-ingress/pull/4058) Add clusterIP to service if specified in values. Thanks to [EutiziStefano](https://github.com/EutiziStefano).
- [4252](https://github.com/nginx/kubernetes-ingress/pull/4252) Make containerPort and hostPort customizable.
- [4331](https://github.com/nginx/kubernetes-ingress/pull/4331) Expose Prometheus metrics through a headless Service.
- [4351](https://github.com/nginx/kubernetes-ingress/pull/4351) Update helm values file to move controller.serviceMonitor to prometheus.serviceMonitor.
- [4333](https://github.com/nginx/kubernetes-ingress/pull/4333) Allow installing IC without creating a new ingress class.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.3.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.3.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.3.0 images from the F5 Container registry, the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE), the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking) or build your own image using the 3.3.0 source code
- For Helm, use version 1.0.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.22-1.28.

<hr>

## 3.2.1

17 Aug 2023

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.25.2.
- Update NGINX Plus version to R30.
- Update Go to 1.21 and Go dependencies.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.2.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.2.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.2.1 images from the F5 Container registry, the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE), the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking) or build your own image using the 3.2.1 source code
- For Helm, use version 0.18.1 of the chart.

<hr>

## 3.2.0

27 June 2023

### <i class="fa-solid fa-rocket"></i> Features

- [3790](https://github.com/nginx/kubernetes-ingress/pull/3790) Gunzip for VS
- [3863](https://github.com/nginx/kubernetes-ingress/pull/3863) OIDC - relaxed OIDC scope validation
- [3925](https://github.com/nginx/kubernetes-ingress/pull/3925) Specify runAsNonRoot in daemon-set manifests. Thanks to [Valters Jansons](https://github.com/sigv).
- [3951](https://github.com/nginx/kubernetes-ingress/pull/3951) Add NGINX Plus images to Google Marketplace.
- [3954](https://github.com/nginx/kubernetes-ingress/pull/3954) Add utilization tracking for supported (paid) customers.
- [4001](https://github.com/nginx/kubernetes-ingress/pull/4001) Add support for the SameSite sticky cookie attribute.
- [4022](https://github.com/nginx/kubernetes-ingress/pull/4022) Add document to tutorial section for configuring the default OIDC implementation.
- [4031](https://github.com/nginx/kubernetes-ingress/pull/4031) Add NGINX Plus Alpine image with FIPS inside for supported (paid) customers.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3737](https://github.com/nginx/kubernetes-ingress/pull/3737) Update VirtualServer to ignore CRL for EgressMTLS.
- [3798](https://github.com/nginx/kubernetes-ingress/pull/3798) Update VirtualServer template to generate an internal jwt auth location per policy applied.
- [3844](https://github.com/nginx/kubernetes-ingress/pull/3844) Fix gunzip support for VS and add python tests.
- [3870](https://github.com/nginx/kubernetes-ingress/pull/3870) Add Funcs() method to UpdateVirtualServerTemplate method. Thanks to [Bryan Hendryx](https://github.com/coolbry95).
- [3933](https://github.com/nginx/kubernetes-ingress/pull/3933) fix --external-service flag when using serviceNameOverride. Thanks to [Tim N](https://github.com/timnee).

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.25.1.
- Update Debian to 12 for NGINX Plus images (except for images containing the NGINX App Protect modules).
- Update Alpine to 3.18 for NGINX Plus images.

### <i class="fa-solid fa-box"></i> Helm Chart

- [3814](https://github.com/nginx/kubernetes-ingress/pull/3814) Remove semverCompare for allocateLoadBalancerNodePorts. Thanks to [Alex Wied](https://github.com/centromere).
- [3905](https://github.com/nginx/kubernetes-ingress/pull/3905) Reverse order of NAPDOS maxDaemons and maxWorkers in Helm chart.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.2.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.2.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.2.0 images from the F5 Container registry, the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE), the [GCP Marketplace](https://console.cloud.google.com/marketplace/browse?filter=partner:F5,%20Inc.&filter=solution-type:k8s&filter=category:networking) or build your own image using the 3.2.0 source code.
- For Helm, use version 0.18.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.22-1.27.

<hr>

## 3.1.1

04 May 2023

### <i class="fa-solid fa-magnifying-glass"></i> Overview

This release reverts the changes made in 3.1.0 to use sysctls to bind to lower level ports without the NET_BIND_SERVICE capability. It also adds support for serviceNameOverride in the Helm chart, that can be used to override the service name for NGINX Ingress Controller. This is useful especially during an upgrade from versions prior to 3.1.0, to avoid downtime due to the service name change. To use this feature, set the `serviceNameOverride` value in the Helm chart to the name of the existing service.

For example, if the existing service name is `my-release-nginx-ingress`, you can use `--set serviceNameOverride=my-release-nginx-ingress` when running the upgrade command.
Here is an example upgrade command that keeps the existing service name `my-release-nginx-ingress` for a deployment named `my-release`:

```console
helm upgrade my-release oci://ghcr.io/nginx/charts/nginx-ingress --version 0.17.1 --set serviceNameOverride=my-release-nginx-ingress
```

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3737](https://github.com/nginx/kubernetes-ingress/pull/3737) Update VirtualServer to ignore CRL for EgressMTLS.
- [3722](https://github.com/nginx/kubernetes-ingress/pull/3722) Inherit NET_BIND_SERVICE from IC to Nginx. Thanks to [Valters Jansons](https://github.com/sigv).
- [3798](https://github.com/nginx/kubernetes-ingress/pull/3798) Update VirtualServer template to generate an internal jwt auth location per policy applied.

### <i class="fa-solid fa-rocket"></i> Features

- [3491](https://github.com/nginx/kubernetes-ingress/pull/3491) Egress via Ingress VirtualServer Resource.

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.23.4.
- Update NGINX Plus version to R29.

### <i class="fa-solid fa-box"></i> Helm Chart

- [3602](https://github.com/nginx/kubernetes-ingress/pull/3602) Updated NGINX Service Mesh references in Helm templates. Thanks to [Jared Byers](https://github.com/jbyers19).
- [3773](https://github.com/nginx/kubernetes-ingress/pull/3773) Swap cpu and memory in HPA template. Thanks to [Bryan Hendryx](https://github.com/coolbry95).
- [3802](https://github.com/nginx/kubernetes-ingress/pull/3802) Add serviceNameOverride. Thanks to [Tim N](https://github.com/timnee).
- [3815](https://github.com/nginx/kubernetes-ingress/pull/3815) Fix GlobalConfiguration name in Helm Chart.
- [3862](https://github.com/nginx/kubernetes-ingress/pull/3862) Add correct indentation to controller-leader-election configmap helm template.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.1.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.1.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.1.1 images from the F5 Container registry or build your own image using the 3.1.1 source code.
- For Helm, use version 0.17.1 of the chart.

<hr>

## 3.1.0

29 Mar 2023

### <i class="fa-solid fa-magnifying-glass"></i> Overview

- Beginning with release 3.1.0 the NET_BIND_SERVICE capability is no longer used, and instead relies on net.ipv4.ip_unprivileged_port_start sysctl to allow port binding. Kubernetes 1.22 or later is required for this sysctl to be [classified as safe](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/#safe-and-unsafe-sysctls). **Ensure that you are using the latest updated `deployment` and `daemonset` example yaml files available in the repo.**
- *The minimum supported version of Kubernetes is now 1.22*. NGINX Ingress Controller now uses `sysctls` to [bind to lower level ports without additional privileges](https://github.com/nginx/kubernetes-ingress/pull/3573/). This removes the need to use `NET_BIND_SERVICE` to bind to these ports. Thanks to [Valters Jansons](https://github.com/sigv) for making this feature possible!
- Added support for loading pre-compiled [AppProtect Policy Bundles](https://github.com/nginx/kubernetes-ingress/pull/3560) when using the `-enable-app-protect` cli argument. This feature removes the need for the Ingress Controller to compile NGINX App Protect Policy when NGINX App Protect Policy is updated.
- IngressMTLS policy now supports configuring a Certificate Revocation Lists(CRL). When using this feature requests made using a revoked certificate will be rejected. See [Using a Certificate Revocation List](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/#using-a-certificate-revocation-list) for details on configuring this option.
- NGINX Ingress Controller now supports [running with a Read-only Root Filesystem](https://github.com/nginx/kubernetes-ingress/pull/3548). This improves the security posture of NGINX Ingress Controller by protecting the file system from unknown writes. See [Configure root filesystem as read-only](https://docs.nginx.com/nginx-ingress-controller/configuration/security/#configure-root-filesystem-as-read-only) for details on configuring this option with both HELM and Manifest. Thanks to [Valters Jansons](https://github.com/sigv) for making this feature possible!
- HELM deployments can now set [custom environment variables with controller.env](https://github.com/nginx/kubernetes-ingress/pull/3326). Thanks to [Aaron Shiels](https://github.com/AaronShiels) for making this possible!
- HELM deployments can now configure a [pod disruption budget](https://github.com/nginx/kubernetes-ingress/pull/3248) allowing deployments to configure either a minimum number or a maximum unavailable number of pods. Thanks to [Bryan Hendryx](https://github.com/coolbry95) for making this possible!
- NGINX Ingress Controller uses the latest OIDC reference implementation which now supports [forwarding access tokens to upstreams / backends](https://github.com/nginx/kubernetes-ingress/pull/3474). Thanks to [Shawn Kim](https://github.com/shawnhankim) for making this possible!
- The default TLS secret is now optional. This improves the security posture of NGINX Ingress Controller through enabling [ssl_reject_handshake](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake). This has the impact of immediately terminating the SSL handshake and not revealing TLS or cypher settings to calls that do not match a configured hostname.

### <i class="fa-solid fa-rocket"></i> Features

- [3034](https://github.com/nginx/kubernetes-ingress/pull/3034) Allow extra args to be provided to the OIDC auth endpoint. Thanks to [Alan Wilkie](https://github.com/alanwilkie-finocomp).
- [3474](https://github.com/nginx/kubernetes-ingress/pull/3474) Add access token support in the OIDC. Thanks to [Shawn Kim](https://github.com/shawnhankim).
- [3326](https://github.com/nginx/kubernetes-ingress/pull/3326) Add support for custom environment variables on the Nginx Controller container. Thanks to [Aaron Shiels](https://github.com/AaronShiels).
- [3527](https://github.com/nginx/kubernetes-ingress/pull/3527) Change controller.topologySpreadConstraints schema to array. Thanks to [Marco Londero](https://github.com/marcuz).
- [3248](https://github.com/nginx/kubernetes-ingress/pull/3248) Add Pod disruption budget option to HELM based installations. Thanks to [Bryan Hendryx](https://github.com/coolbry95).
- [3462](https://github.com/nginx/kubernetes-ingress/pull/3462) Add initial support for SSL termination for TransportServer.
- [3451](https://github.com/nginx/kubernetes-ingress/pull/3451) Enable keepalive-time for healthchecks in VS and VSR.
- [3560](https://github.com/nginx/kubernetes-ingress/pull/3560) Add support for load a pre-compiles AppProtect Policy Bundle.
- [3632](https://github.com/nginx/kubernetes-ingress/pull/3632) Update nginx.org/ca secret type & crl field to IngressMTLS to support CRL.
- [3629](https://github.com/nginx/kubernetes-ingress/pull/3629) Use the "runtime default" seccomp profile. Thanks to [Valters Jansons](https://github.com/sigv).
- [3573](https://github.com/nginx/kubernetes-ingress/pull/3573) Rework port binding logic without privileges. Thanks to [Valters Jansons](https://github.com/sigv).
- [3646](https://github.com/nginx/kubernetes-ingress/pull/3646) Remove app protect agent.
- [3507](https://github.com/nginx/kubernetes-ingress/pull/3507) Support empty path for ImplementationSpecific pathType.
- [3482](https://github.com/nginx/kubernetes-ingress/pull/3482) Use new NSM Spiffe and Cert rotation library.
- [3442](https://github.com/nginx/kubernetes-ingress/pull/3442) Add websocket protocol option to monitor directive.
- [3674](https://github.com/nginx/kubernetes-ingress/pull/3674) Move NAP DoS chart to new repo.
- [3302](https://github.com/nginx/kubernetes-ingress/pull/3302) Make default-server-secret optional.
- [3586](https://github.com/nginx/kubernetes-ingress/pull/3586) Add new labels and metadata to add version information to pods.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3463](https://github.com/nginx/kubernetes-ingress/pull/3463) Support non-vs created Challenge Ingress.
- [3475](https://github.com/nginx/kubernetes-ingress/pull/3475) Ensure leader election is correctly disabled when option is set to `false` in helm template.
- [3481](https://github.com/nginx/kubernetes-ingress/pull/3481) Add missing OSS internal routes for integration with NSM.
- [3541](https://github.com/nginx/kubernetes-ingress/pull/3541) Ensure non-ready endpoints are not added to upstreams.
- [3583](https://github.com/nginx/kubernetes-ingress/pull/3583) Update keyCache path for JWKs to avoid conflict with OIDC.
- [3607](https://github.com/nginx/kubernetes-ingress/pull/3607) Clear Content-Length headers for requests processed by internal JWKS routes.
- [3660](https://github.com/nginx/kubernetes-ingress/pull/3660) Remove unwanted chars from label value.

### <i class="fa-solid fa-box"></i> Helm Chart

- [3581](https://github.com/nginx/kubernetes-ingress/pull/3581) Push edge Helm Chart to OCI registries.
- [3449](https://github.com/nginx/kubernetes-ingress/pull/3449) Correct values.schema.json nodeSelector.
- [3448](https://github.com/nginx/kubernetes-ingress/pull/3448) Fix Helm Chart Schema for priorityClassName.
- [3519](https://github.com/nginx/kubernetes-ingress/pull/3519) Add OnDelete to allowed strategy values.
- [3537](https://github.com/nginx/kubernetes-ingress/pull/3537) Update schema references to k8s v1.26.1.
- [3606](https://github.com/nginx/kubernetes-ingress/pull/3606) Fix Helm Chart labels and templates. Move version update to labels.

### <i class="fa-solid fa-download"></i> Upgrade

- Make sure the Kubernetes version is in the supported platforms listed below.
- For NGINX, use the 3.1.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.1.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.1.0 images from the F5 Container registry or build your own image using the 3.1.0 source code.
- For Helm, use version 0.17.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.22-1.26.

<hr>

## 3.0.2

13 Feb 2023

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3519](https://github.com/nginx/kubernetes-ingress/pull/3519) Add OnDelete to allowed strategy values
- [3541](https://github.com/nginx/kubernetes-ingress/pull/3541) Ensure non-ready endpoints are not added to upstreams
- [3527](https://github.com/nginx/kubernetes-ingress/pull/3527) Fix controller.topologySpreadConstraints schema, thanks to [Marco Londero](https://github.com/marcuz)

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.0.2 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.0.2), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.0.2 images from the F5 Container registry or build your own image using the 3.0.2 source code.
- For Helm, use version 0.16.2 of the chart.

<hr>

## 3.0.1

25 Jan 2023

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3448](https://github.com/nginx/kubernetes-ingress/pull/3448) Fix Helm Chart Schema for priorityClassName
- [3449](https://github.com/nginx/kubernetes-ingress/pull/3449) Correct nodeSelector in the Helm Chart Schema
- [3463](https://github.com/nginx/kubernetes-ingress/pull/3463) Support non-VS created Challenge Ingress
- [3481](https://github.com/nginx/kubernetes-ingress/pull/3481) Add missing OSS internal routes for NGINX Service Mesh

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 3.0.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.0.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 3.0.1 images from the F5 Container registry or build your own image using the 3.0.1 source code.
- For Helm, use version 0.16.1 of the chart.

<hr>

## 3.0.0

12 January 2023

### <i class="fa-solid fa-magnifying-glass"></i> Overview

- Added support for [Deep Service Insight](https://docs.nginx.com/nginx-ingress-controller/logging-and-monitoring/service-insight) for VirtualServer and TransportServer using the [-enable-service-insight](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-enable-service-insight) cli argument.
- *The minimum supported version of Kubernetes is now 1.21*. NGINX Ingress Controller 3.0.0 removes support for `k8s.io/v1/Endpoints` API in favor of `discovery.k8s.io/v1/EndpointSlices`. For older Kubernetes versions, use the 2.4.x release of the Ingress Controller.
- Added support for [EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/).
- Added support to dynamically reconfigure namespace watchers using labels  [-watch-namespace-label](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-watch-namespace-label-string) and watching secrets using the [-watch-secret-namespace](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-watch-secret-namespace-string) cli arguments.
- Allow configuration of NGINX directives `map-hash-bucket-size` and `map-hash-max-size` using the [ConfigMap resource](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource#general-customization) .
- Added support for [fetching JWKs from a remote URL](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource#jwt-using-jwks-from-remote-location
) to dynamically validate JWT tokens and optimize performance through caching.
- Beginning with NGINX Service Mesh release 1.7 it will include support for the free version of NGINX Ingress Controller as well as the paid version.
- NGINX Ingress Controller + NGINX App Protect Denial of Service is now available through the AWS Marketplace.

### <i class="fa-solid fa-bomb"></i> Breaking Changes

- [3260](https://github.com/nginx/kubernetes-ingress/pull/3260) Added support for EndpointSlices.

### <i class="fa-solid fa-rocket"></i> Features

- [3299](https://github.com/nginx/kubernetes-ingress/pull/3299) Support Dynamic namespaces using Labels.
- [3261](https://github.com/nginx/kubernetes-ingress/pull/3261) Deep service insight endpoint for VirtualServer CR.
- [3361](https://github.com/nginx/kubernetes-ingress/pull/3361) Added healthcheck for TransportServer CR.
- [3347](https://github.com/nginx/kubernetes-ingress/pull/3347) Import JWKS from URL on JWT policy.
- [3274](https://github.com/nginx/kubernetes-ingress/pull/3274) Allow configuration of map-hash-bucket-size and map-hash-max-size directives.
- [3376](https://github.com/nginx/kubernetes-ingress/pull/3376) NGINX Service Mesh will support the free version of NGINX Ingress Controller when using NGINX open source.
- [3170](https://github.com/nginx/kubernetes-ingress/pull/3170) Watch subset of namespaces for secrets. Thanks to [Hans Feldt](https://github.com/hafe).
- [3341](https://github.com/nginx/kubernetes-ingress/pull/3341) Set value of `$remote_addr` to client IP when TLSPassthrough and Proxy Protocol are enabled.
- [3131](https://github.com/nginx/kubernetes-ingress/pull/3131) NAP DoS images are now available in the AWS Marketplace.
- [3231](https://github.com/nginx/kubernetes-ingress/pull/3231) Always print build info and flags used at the start to provide better supportability.
- [2735](https://github.com/nginx/kubernetes-ingress/pull/2735) Support default client proxy headers to be overwritten in VirtualServer. Thanks to [Alex Wied](https://github.com/centromere).
- [3133](https://github.com/nginx/kubernetes-ingress/pull/3133) Added caseSensitiveHttpHeaders to APPolicy CRD. Thanks to [Pavel Galitskiy](https://github.com/galitskiy).

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3139](https://github.com/nginx/kubernetes-ingress/pull/3139) Remove all IPV6 listeners in ingress resources with `-disable-ipv6` command line.

### <i class="fa-solid fa-box"></i> Helm Chart

- [3113](https://github.com/nginx/kubernetes-ingress/pull/3113) Added JSON Schema.
- [3143](https://github.com/nginx/kubernetes-ingress/pull/3143) Added annotations for deployment and daemonset.
- [3136](https://github.com/nginx/kubernetes-ingress/pull/3136) Added controller.dnsPolicy. Thanks to [Dong Wang](https://github.com/wd).
- [3065](https://github.com/nginx/kubernetes-ingress/pull/3065) Added annotations to the service account. Thanks to [0m1xa](https://github.com/0m1xa).
- [3276](https://github.com/nginx/kubernetes-ingress/pull/3276) Added horizontalpodautoscaler. Thanks to [Bryan Hendryx](https://github.com/coolbry95).

### <i class="fa-solid fa-download"></i> Upgrade

- Make sure the Kubernetes version is in the supported platforms listed below.
- For NGINX, use the 3.0.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=3.0.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 3.0.0 images from the F5 Container registry or the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE) or build your own image using the 3.0.0 source code.
- For Helm, use version 0.16.0 of the chart. Helm does not upgrade the CRDs. If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to `true`), after running the `helm upgrade` command, run `kubectl apply -f deployments/helm-chart/crds` to upgrade the CRDs.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.21-1.26.

<hr>

## 2.4.2

30 Nov 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX Plus version to R28.
- Update NGINX App Protect WAF version to 4.0.
- Update NGINX App Protect DoS version to 3.1.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.4.2 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.4.2), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 2.4.2 images from the F5 Container registry or build your own image using the 2.4.2 source code.
- For Helm, use version 0.15.2 of the chart.

<hr>

## 2.4.1

19 October 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- [3183](https://github.com/nginx/kubernetes-ingress/pull/3183) Update NGINX version to 1.23.2.
- [3175](https://github.com/nginx/kubernetes-ingress/pull/3175) Update Go dependencies.
- Update NGINX Plus version to R27 P1.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [3139](https://github.com/nginx/kubernetes-ingress/pull/3139) Remove all IPV6 listeners in ingress resources with -disable-ipv6 command line.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.4.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.4.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 2.4.1 images from the F5 Container registry or the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE) or build your own image using the 2.4.1 source code.
- For Helm, use version 0.15.1 of the chart.

<hr>

## 1.12.5

19 October 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.23.2.
- Update NGINX Plus version to R27 P1.
- Update Alpine to 3.16.
- Update Go to 1.19 and Go dependencies.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.12.5 image from our DockerHub: `nginx/nginx-ingress:1.12.5`, `nginx/nginx-ingress:1.12.5-alpine` or `nginx/nginx-ingress:1.12.5-ubi`
- For NGINX Plus, please build your own image using the 1.12.5 source code.
- For Helm, use version 0.10.5 of the chart.

<hr>

## 2.4.0

04 October 2022

### <i class="fa-solid fa-magnifying-glass"></i> Overview

- Added support for enabling [proxy_protocol](https://github.com/nginx/kubernetes-ingress/tree/v2.4.0/examples/shared-examples/proxy-protocol) when port 443 is being used for both HTTPS traffic and [TLS Passthrough traffic](https://github.com/nginx/kubernetes-ingress/tree/v2.4.0/examples/custom-resources/tls-passthrough).
- Updates to the TransportServer resource to support using [ExternalName services](https://kubernetes.io/docs/concepts/services-networking/service/#externalname). For examples, see [externalname-services](https://github.com/nginx/kubernetes-ingress/tree/v2.4.0/examples/custom-resources/externalname-services).
- VirtualServer resource now supports [wildcard hostname](https://kubernetes.io/docs/concepts/services-networking/ingress/#hostname-wildcards).
- NGINX Ingress Controller images including the combined NGINX AppProtect WAF and NGINX AppProtect DoS solutions are now published to our registry. See [Images with NGINX Plus](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/#images-with-nginx-plus) for a detailed list of images in our registry.
- Added support for watching multiple namespaces using the [-watch-namespace](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-watch-namespace-string) cli argument. This can configured by passing a comma-separated list of namespaces to the `-watch-namespace` CLI argument (e.g. `-watch-namespace=ns-1,ns-2`).
- A new cli argument has been added: [-include-year](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-include-year). This appends the current year to the log output from the Ingress Controller. Example output: `I20220512 09:20:42.345457`.
- Post-startup configuration reloads have been optimized to reduce traffic impacts. When many resources are modified at the same time, changes are combined to reduce the number of data plane reloads.

### <i class="fa-solid fa-rocket"></i> Features

- [2986](https://github.com/nginx/kubernetes-ingress/pull/2986) Batch reloads at runtime.
- [2914](https://github.com/nginx/kubernetes-ingress/pull/2914) Support watching multiple namespaces.
- [2884](https://github.com/nginx/kubernetes-ingress/pull/2884) Include year in logs.
- [2993](https://github.com/nginx/kubernetes-ingress/pull/2993) Accept proxy protocol when TLS passthrough enabled.
- [3041](https://github.com/nginx/kubernetes-ingress/pull/3041) Support external name service for TransportServer.
- [2939](https://github.com/nginx/kubernetes-ingress/pull/2939) Add support for wildcard hostname in VirtualServer.
- [3040](https://github.com/nginx/kubernetes-ingress/pull/3040) Add command line argument to manually disable IPV6 listeners for unsupported clusters.
- [3088](https://github.com/nginx/kubernetes-ingress/pull/3088) Filter secrets of type helm.sh/release.v1.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2971](https://github.com/nginx/kubernetes-ingress/pull/2971) fix: Correct error message on missing path in path validation. Thanks to [Zachary Seguin](https://github.com/zachomedia).
- [3095](https://github.com/nginx/kubernetes-ingress/pull/3095) do not create configmap if customConfigMap is used. Thanks to [Bryan Hendryx](https://github.com/coolbry95).

### <i class="fa-solid fa-box"></i> Helm Chart

- [3087](https://github.com/nginx/kubernetes-ingress/pull/3087) Allow omitting the default server secret from Helm installs.
- [2831](https://github.com/nginx/kubernetes-ingress/pull/2831) Add ServiceMonitor to Helm Chart. Thanks to [araineUnity](https://github.com/araineUnity).
- [2855](https://github.com/nginx/kubernetes-ingress/pull/2854) Add initialDelaySeconds to helm charts. Thanks to [Daniel Edgar](https://github.com/aknot242).
- [2979](https://github.com/nginx/kubernetes-ingress/pull/2979) Allow to specify image with digest in helm chart. Thanks to [Hans Feldt](https://github.com/hafe).
- [3031](https://github.com/nginx/kubernetes-ingress/pull/3031) Adding automountServiceAccountToken to helm chart.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.4.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.4.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.4.0 images from the F5 Container registry or the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE) or build your own image using the 2.4.0 source code.
- For Helm, use version 0.15.0 of the chart. If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to `true`), after you run the `helm upgrade` command, the CRDs will not be upgraded. After running the `helm upgrade` command, run `kubectl apply -f deployments/helm-chart/crds` to upgrade the CRDs.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and that passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.19-1.25.

<hr>

## 2.3.1

16 September 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- [3048](https://github.com/nginx/kubernetes-ingress/pull/3048) Bump NGINX to 1.23.1
- [3049](https://github.com/nginx/kubernetes-ingress/pull/3049) Update Go dependencies.

### <i class="fa-solid fa-box"></i> Helm Chart

- [3031](https://github.com/nginx/kubernetes-ingress/pull/3031) Add automountServiceAccountToken to helm chart

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.3.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.3.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress), [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress) or [Quay.io](https://quay.io/repository/nginx/nginx-ingress).
- For NGINX Plus, use the 2.3.1 images from the F5 Container registry or build your own image using the 2.3.1 source code.
- For Helm, use version 0.14.1 of the chart.

<hr>

## 2.3.0

12 July 2022

### <i class="fa-solid fa-magnifying-glass"></i> Overview

- Support making VirtualServer resources discoverable via public DNS servers using [external-dns](https://kubernetes-sigs.github.io/external-dns). Examples for configuring external-dns with NGINX Ingress Controller can be found [here](https://github.com/nginx/kubernetes-ingress/tree/v2.3.0/examples/custom-resources/external-dns).
- Resolves [CVE-2022-30535](https://support.f5.com/csp/article/K52125139). This vulnerability impacted the visibility of secrets accessible by NGINX Ingress Controller. In some cases, secrets visible to NGINX Ingress Controller could be exposed to any authenticated user with permission to create and update Ingress objects. This vulnerability affected Ingress objects only - our Custom Resources (VirtualServer and TransportServer) were not affected. Customers unable to upgrade should migrate any Ingress resources to VirtualServer resources where possible, and use RBAC to restrict write access for users for Ingress objects.
- Support using HTTP basic authentication with [VirtualServer](https://github.com/nginx/kubernetes-ingress/tree/v2.3.1/examples/custom-resources/basic-auth) and [Ingress](https://github.com/nginx/kubernetes-ingress/tree/v2.3.0/examples/basic-auth) resources. Special thanks to [Simon Wachter](https://github.com/svvac).
- Support HTTP01 type ACME Issuers for use with VirtualServer resources with [cert-manager](https://cert-manager.io/docs/).

### <i class="fa-solid fa-rocket"></i> Features

- [2581](https://github.com/nginx/kubernetes-ingress/pull/2581) Add OpenTracing to all Debian and Alpine based images.
- [2328](https://github.com/nginx/kubernetes-ingress/pull/2328) Add handling of multiple log destinations.
- [2691](https://github.com/nginx/kubernetes-ingress/pull/2691) AP: log-conf escaping chars.
- [2759](https://github.com/nginx/kubernetes-ingress/pull/2759) Add support for HTTP01 Challenges on VirtualServer resources.
- [2762](https://github.com/nginx/kubernetes-ingress/pull/2762) Add DNSEndpoint CRD for integration with ExternalDNS.
- [2801](https://github.com/nginx/kubernetes-ingress/pull/2801) Add SBOMs to release.
- [2269](https://github.com/nginx/kubernetes-ingress/pull/2269) HTTP basic auth support. Thanks to [Simon Wachter](https://github.com/svvac).
- [2800](https://github.com/nginx/kubernetes-ingress/pull/2800) Integrate external-dns with VirtualServer resources.
- [2583](https://github.com/nginx/kubernetes-ingress/pull/2583) Add runAsNonRoot in deployments.
- [2484](https://github.com/nginx/kubernetes-ingress/pull/2484) Add container resource requests.
- [2627](https://github.com/nginx/kubernetes-ingress/pull/2627) Update InternalRoute server_name.
- [2742](https://github.com/nginx/kubernetes-ingress/pull/2742) Add additional unit tests to confirm special characters can't be used in the lb-method annotation.
- [2730](https://github.com/nginx/kubernetes-ingress/pull/2730) Add string sanitisation for proxy-pass-headers & proxy-hide-headers.
- [2733](https://github.com/nginx/kubernetes-ingress/pull/2733) Add string validation to server-tokens annotation.
- [2734](https://github.com/nginx/kubernetes-ingress/pull/2734) Validate rewrite annotation.
- [2754](https://github.com/nginx/kubernetes-ingress/pull/2754) Validate JWT key, realm and login url for ingress resources annotations.
- [2751](https://github.com/nginx/kubernetes-ingress/pull/2751) Add string validation to sticky-cookie-services annotation.
- [2775](https://github.com/nginx/kubernetes-ingress/pull/2775) Add validation to Ingress path.
- [2774](https://github.com/nginx/kubernetes-ingress/pull/2774) Sanitize nginx.com/jwt-token.
- [2783](https://github.com/nginx/kubernetes-ingress/pull/2783) Update validation regex for path spec.
- [2781](https://github.com/nginx/kubernetes-ingress/pull/2781) Report Hostname in ExternalEndpoint for VS and VSR resources.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2617](https://github.com/nginx/kubernetes-ingress/pull/2617) Fix Dockerfile for amd64 microarchitectures.
- [2637](https://github.com/nginx/kubernetes-ingress/pull/2637) Add terminationGracePeriodSeconds to deployment. Thanks to [Maksym Iv](https://github.com/maksym-iv).
- [2654](https://github.com/nginx/kubernetes-ingress/pull/2654) Sync changes from OIDC repo, add field in policy.
- [2673](https://github.com/nginx/kubernetes-ingress/pull/2673) Fix status.loadbalancer.hostname deletion on OOMKill. Thanks to [Heiko Voigt](https://github.com/hvoigt).
- [2718](https://github.com/nginx/kubernetes-ingress/pull/2718) Fix cases where CM enabled but no TLS block specified in VS.

### <i class="fa-solid fa-box"></i> Helm Chart

- [2418](https://github.com/nginx/kubernetes-ingress/pull/2418) Add support for allocateLoadBalancerNodePorts, ipFamilyPolicy and ipFamilies. Thanks to [centromere](https://github.com/centromere).
- [2672](https://github.com/nginx/kubernetes-ingress/pull/2672) Add minReadySeconds & strategy support. Thanks to [Ciaran](https://github.com/cmk-pcs).
- [2625](https://github.com/nginx/kubernetes-ingress/pull/2625) allow configuring topologySpreadConstraints in Helm chart. Thanks to [Kamil Domański](https://github.com/kdomanski).

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.3.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.3.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.3.0 images from the F5 Container registry or the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE) or build your own image using the 2.3.0 source code.
- For Helm, use version 0.14.0 of the chart. If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to `true`), after you run the `helm upgrade` command, the CRDs will not be upgraded. After running the `helm upgrade` command, run `kubectl apply -f deployments/helm-chart/crds` to upgrade the CRDs.
- When upgrading using the [manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), make sure to update the [ClusterRole](https://github.com/nginx/kubernetes-ingress/blob/v2.3.1/deployments/rbac/rbac.yaml). This is required to enable the ExternalDNS for VirtualServer resources integration.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and which passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.19-1.24.

<hr>

## 2.2.2

23 May 2022

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2627](https://github.com/nginx/kubernetes-ingress/pull/2627) Update InternalRoute server_name.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.2.2 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.2.2), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.2.2 images from the F5 Container registry or build your own image using the 2.2.2 source code.
- For Helm, use version 0.13.2 of the chart.

<hr>

## 2.2.1

17 May 2022

### <i class="fa-solid fa-upload"></i> Dependencies
the documentation here

- Update Go dependencies.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2654](https://github.com/nginx/kubernetes-ingress/pull/2654) Sync changes from [nginx-openid-connect](https://github.com/nginxinc/nginx-openid-connect) repo, add zoneSyncLeeway field in policy. For more information on the fixes, see [pull request 52](https://github.com/nginxinc/nginx-openid-connect/pull/52).

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.2.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.2.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.2.1 images from the F5 Container registry or build your own image using the 2.2.1 source code.
- For Helm, use version 0.13.1 of the chart.

<hr>

## 2.2.0

12 April 2022

### <i class="fa-solid fa-magnifying-glass"></i> Overview

- Support for automatic provisioning and management of Certificate resources for VirtualServer resources using [cert-manager](https://cert-manager.io/docs/). Examples for configuring cert-manager with NGINX Ingress Controller can be found [here](https://github.com/nginx/kubernetes-ingress/tree/v2.2.0/examples/custom-resources/certmanager). Please note that HTTP01 type ACME Issuers are not yet supported for use with VirtualServer resources.

- Full support for IPv6 using the NGINX Ingress Controller [VirtualServer and VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources) custom resources, and Ingress resources.

- The [-enable-preview-policies](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-enable-preview-policies) cli argument has been deprecated and is no longer required for the usage of any Policy resource type. This argument will be removed completely in v2.6.0.

- A new [-enable-oidc](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/command-line-arguments/#-enable-oidc) cli argument has been added to enable OIDC policies. Previously, this behaviour was achieved through the usage of the `-enable-preview-policies` cli argument.

### <i class="fa-solid fa-rocket"></i> Features

- [2576](https://github.com/nginx/kubernetes-ingress/pull/2576) Add support for IPv6.
- [2572](https://github.com/nginx/kubernetes-ingress/pull/2572) Automate provisioning of Certificate resources for VirtualServer resources using cert-manager.
- [2346](https://github.com/nginx/kubernetes-ingress/pull/2346) Use os.ReadDir for lightweight directory reading. Thanks to [Eng Zer Jun](https://github.com/Juneezee).
- [2360](https://github.com/nginx/kubernetes-ingress/pull/2360) Add NGINX App Protect reconnect period directive.
- [2479](https://github.com/nginx/kubernetes-ingress/pull/2479) Add cli argument to configure NGINX App Protect log level.
- [2455](https://github.com/nginx/kubernetes-ingress/pull/2455) Increase memory available for NGINX App Protect xml parser.
- [2580](https://github.com/nginx/kubernetes-ingress/pull/2580) Create -enable-oidc command line argument for OIDC policy.
- [2566](https://github.com/nginx/kubernetes-ingress/pull/2566) Unbind policy from preview policies.
- [2582](https://github.com/nginx/kubernetes-ingress/pull/2582) Rename Make targets from `openshift` to `ubi`.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2378](https://github.com/nginx/kubernetes-ingress/pull/2378) Fix healthcheck ports.
- [2404](https://github.com/nginx/kubernetes-ingress/pull/2404) Start nginx with -e stderr parameter.
- [2414](https://github.com/nginx/kubernetes-ingress/pull/2414) Fix in file nginx-plus.virtualserver.tmpl ApDosMonitor->ApDosMonitorURI.

### <i class="fa-solid fa-box"></i> Helm Chart

- [2525](https://github.com/nginx/kubernetes-ingress/pull/2525) Extend helm chart to include NGINX Service Mesh fields.
- [2294](https://github.com/nginx/kubernetes-ingress/pull/2294) Add extra containers to helm chart. Thanks to [Márk Sági-Kazár](https://github.com/sagikazarmark).

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.2.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.2.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.2.0 images from the F5 Container registry or the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE) or build your own image using the 2.2.0 source code.
- For Helm, use version 0.13.0 of the chart. If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to `true`), after you run the `helm upgrade` command, the CRDs will not be upgraded. After running the `helm upgrade` command, run `kubectl apply -f deployments/helm-chart/crds` to upgrade the CRDs.
- When upgrading using the [manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), make sure to update the [ClusterRole](https://github.com/nginx/kubernetes-ingress/blob/v2.2.0/deployments/rbac/rbac.yaml). This is required to enable the cert-manager for VirtualServer resources integration.
- The -enable-preview-policies cli argument has been deprecated, and is no longer required for any Policy resources.
- Enabling OIDC Policies now requires the use of -enable-oidc cli argument instead of the -enable-preview-policies cli argument.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and which passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.19-1.23.

<hr>

## 2.1.2

29 March 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- Update UBI based images to 8.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.1.2 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.1.2), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.1.2 images from the F5 Container registry or the [AWS Marketplace](https://aws.amazon.com/marketplace/search/?CREATOR=741df81b-dfdc-4d36-b8da-945ea66b522c&FULFILLMENT_OPTION_TYPE=CONTAINER&filters=CREATOR%2CFULFILLMENT_OPTION_TYPE) or build your own image using the 2.1.2 source code.
- For Helm, use version 0.12.2 of the chart.

<hr>

## 1.12.4

23 March 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.21.6.
- Update NGINX Plus version to R26.
- Update Debian to Bullseye.
- Update Alpine to 3.15.
- Update UBI to 8.
- Update Go to 1.17 and Go dependencies.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- Fix OpenTracing not working with NGINX Plus.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.12.4 image from our DockerHub: `nginx/nginx-ingress:1.12.4`, `nginx/nginx-ingress:1.12.4-alpine` or `nginx/nginx-ingress:1.12.4-ubi`
- For NGINX Plus, please build your own image using the 1.12.4 source code.
- For Helm, use version 0.10.4 of the chart.

<hr>

## 2.1.1

17 February 2022

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.21.6.
- Update NGINX Plus version to R26.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.1.1 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.1.1), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.1.1 images from the F5 Container registry or build your own image using the 2.1.1 source code.
- For Helm, use version 0.12.1 of the chart.

<hr>

## 2.1.0

06 January 2022

### <i class="fa-solid fa-magnifying-glass"></i> Overview

- Support for NGINX App Protect Denial of Service protection with NGINX Ingress Controller. More information about [NGINX App Protect DoS](https://www.nginx.com/products/nginx-app-protect/denial-of-service/). Examples for configuring NGINX App Protect DoS with NGINX Ingress Controller can be found [here](https://github.com/nginx/kubernetes-ingress/tree/v2.1.1/examples/appprotect-dos).

- Full support for gRPC services using the NGINX Ingress Controller [VirtualServer and VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources) custom resource definitions.  This makes configuring and supporting gRPC services much easier, giving a simple YAML configuration and removing the need for snippets. Resource definition examples for gRPC can be found [here](https://github.com/nginx/kubernetes-ingress/tree/v2.1.1/examples/custom-resources/grpc-upstreams).

- Implementation of NGINX mandatory and persistent health checks in VirtualServer and VirtualServerRoute to further reduce interruptions to your service traffic as configuration changes continuously happen in your dynamic Kubernetes environment(s). Health checks have been extended to include `mandatory` and `persistent` fields. Mandatory health checks ensures that a new upstream server starts receiving traffic only after the health check passes. Mandatory health checks can be marked as persistent, so that the previous state is remembered when the Ingress Controller reloads NGINX Plus configuration. When combined with the slow-start parameter, the mandatory health check give a new upstream server more time to connect to databases and “warm up” before being asked to handle their full share of traffic. See the settings [here](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#upstreamhealthcheck). More about the [NGINX Plus mandatory and persistent health check features](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/#mandatory-health-checks).
Mandatory health checks can be marked as persistent, so that the previous state is remembered when reloading configuration. When combined with the slow-start parameter, it gives a new service pod more time to connect to databases and “warm up” before being asked to handle their full share of traffic.
See the settings [here](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#upstreamhealthcheck).
More about the [NGINX Plus mandatory and persistent health check features](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/#mandatory-health-checks)

### <i class="fa-solid fa-rocket"></i> Features

- [2251](https://github.com/nginx/kubernetes-ingress/pull/2251) Enable setting mandatory and persistent in upstream healthchecks in VS and VSR.
- [2241](https://github.com/nginx/kubernetes-ingress/pull/2241) Add support for NGINX App Protect DoS.
- [2200](https://github.com/nginx/kubernetes-ingress/pull/2200) Add Alpine image with OpenTracing.
- [2178](https://github.com/nginx/kubernetes-ingress/pull/2178) Support healthchecks in gRPC upstreams.
- [2110](https://github.com/nginx/kubernetes-ingress/pull/2110) Support gRPC in the Upstreams of the virtual server resources. Particular thanks to [Chiyu Zhong](https://github.com/CatTail) for all their work.
- [2149](https://github.com/nginx/kubernetes-ingress/pull/2149) Add metric about total number of TransportServers.
- [2100](https://github.com/nginx/kubernetes-ingress/pull/2100) Add support for initContainers. Thanks to [Gunnar Scherf](https://github.com/g10f).
- [1827](https://github.com/nginx/kubernetes-ingress/pull/1827) Add support for wildcard cert in VirtualServer resources. Thanks to [Simon Wachter](https://github.com/svvac).
- [2107](https://github.com/nginx/kubernetes-ingress/pull/2107) Add option to download the NGINX Ingress Controller binary. Introduced a new `TARGET` `download` in the `Makefile` which can be used when building the NGINX Ingress Controller Docker image. With this option the Ingress Controller binary will be downloaded instead of built from source.
- [2044](https://github.com/nginx/kubernetes-ingress/pull/2044) Upload NGINX Ingress Controller binaries to release.
- [2094](https://github.com/nginx/kubernetes-ingress/pull/2094) AP: update appolicies crd.
- [2216](https://github.com/nginx/kubernetes-ingress/pull/2216) Add grpc_status to the logs.
- [2237](https://github.com/nginx/kubernetes-ingress/pull/2237) Unbind app-protect from -preview-policies.
- [2273](https://github.com/nginx/kubernetes-ingress/pull/2273) Make the resource comparison more informative in case of an error. Thanks to [Andrey Karpov](https://github.com/ndk).
- [2124](https://github.com/nginx/kubernetes-ingress/pull/2124) Apply -enable-snippets cli arg to Ingresses. This PR extends the existing -enable-snippets cli argument to apply to Ingress resources. If snippets are not enabled, the Ingress Controller will reject any Ingress resources with snippets annotations. Previously, the argument only applied to VirtualServer, VirtualServerRoute and TransportServer resources. Please Note: this is a breaking change. See the `UPGRADE` instructions below.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2267](https://github.com/nginx/kubernetes-ingress/pull/2267) Fix URI rewrite in VirtualServers and VirtualServerRoutes.
- [2260](https://github.com/nginx/kubernetes-ingress/pull/2260) Check if refresh token is `undefined` and do not store it in this case. Thanks to [tippexs](https://github.com/tippexs) for the fix.
- [2215](https://github.com/nginx/kubernetes-ingress/pull/2215) enableSnippets should not depend from enableCustomResources. Thanks to [Alessio Casco](https://github.com/AlessioCasco) for the fix.
- [1934](https://github.com/nginx/kubernetes-ingress/pull/1934) AP: fix watch-namespace for NAP resources.
- [2125](https://github.com/nginx/kubernetes-ingress/pull/2125) Allow empty string in server-tokens annotation for NGINX Plus.
- [2042](https://github.com/nginx/kubernetes-ingress/pull/2042) Use release specific repo for NGINX Plus on Debian.

### <i class="fa-solid fa-upload"></i> Dependencies

- [2173](https://github.com/nginx/kubernetes-ingress/pull/2173) Update Debian to Bullseye.
- Update NGINX Plus version to R25.
- Update NGINX version to 1.21.5.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.1.0 images from our [DockerHub](https://hub.docker.com/r/nginx/nginx-ingress/tags?page=1&ordering=last_updated&name=2.1.0), [GitHub Container](https://github.com/nginx/kubernetes-ingress/pkgs/container/kubernetes-ingress) or [Amazon ECR Public Gallery](https://gallery.ecr.aws/nginx/nginx-ingress).
- For NGINX Plus, use the 2.1.0 images from the F5 Container registry or build your own image using the 2.1.0 source code.
- For Helm, use version 0.12.0 of the chart.
- We changed the behaviour of snippets in Ingress resources by extending the existing -enable-snippets cli argument to apply to Ingress resources as well as VirtualServer, VirtualServerRoute and TransportServer resources. Because the default value of -enable-snippets is false, if you are using snippets in Ingress resources, you must explicitly set the -enable-snippets to true before upgrading the Ingress Controller, so that the new version of the Ingress Controller doesn't reject Ingresses with snippets annotations.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and which passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.19-1.23.

<hr>

## 2.0.3

28 October 2021

### <i class="fa-solid fa-bomb"></i> Breaking Changes

- [2124](https://github.com/nginx/kubernetes-ingress/pull/2124) Apply -enable-snippets cli arg to Ingresses. This PR extends the existing -enable-snippets cli argument to apply to Ingress resources. If snippets are not enabled, the Ingress Controller will reject any Ingress resources with snippets annotations. Previously, the argument only applied to VirtualServer, VirtualServerRoute and TransportServer resources. Please Note: this is a breaking change. See the `UPGRADE` instructions below.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2132](https://github.com/nginx/kubernetes-ingress/pull/2132) Install libcurl on OpenTracing for NGINX Plus.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.0.3 image from our DockerHub: `nginx/nginx-ingress:2.0.3`, `nginx/nginx-ingress:2.0.3-alpine` or `nginx/nginx-ingress:2.0.3-ubi`
- For NGINX Plus, please build your own image using the 2.0.3 source code.
- For Helm, use version 0.11.3 of the chart.
- We changed the behaviour of snippets in Ingress resources by extending the existing -enable-snippets cli argument to apply to Ingress resources as well as VirtualServer, VirtualServerRoute and TransportServer resources. Because the default value of -enable-snippets is false, if you are using snippets in Ingress resources, you must explicitly set the -enable-snippets to true before upgrading the Ingress Controller, so that the new version of the Ingress Controller doesn't reject Ingresses with snippets annotations.

<hr>

## 1.12.3

28 October 2021

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2133](https://github.com/nginx/kubernetes-ingress/pull/2133) Use release specific repo for the App Protect packages on Debian. This fixes an error when building Debian-based images with NGINX Plus with App Protect: previously, building an image would fail with the error `nginx-plus-module-appprotect : Depends: app-protect-plugin (= 3.639.0-1~buster) but 3.671.0-1~buster is to be installed`. The bug first appeared when NGINX App Protect version 3.6 was released on 13 October 2021.
- [2134](https://github.com/nginx/kubernetes-ingress/pull/2134) Apply -enable-snippets cli arg to Ingresses. This PR extends the existing -enable-snippets cli argument to apply to Ingress resources. If snippets are not enabled, the Ingress Controller will reject any Ingress resources with snippets annotations. Previously, the argument only applied to VirtualServer, VirtualServerRoute and TransportServer resources. Please Note: this is a breaking change. See the `UPGRADE` instructions below.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.12.3 image from our DockerHub: `nginx/nginx-ingress:1.12.3`, `nginx/nginx-ingress:1.12.3-alpine` or `nginx/nginx-ingress:1.12.3-ubi`
- For NGINX Plus, please build your own image using the 1.12.3 source code.
- For Helm, use version 0.10.3 of the chart.
- We changed the behaviour of snippets in Ingress resources by extending the existing -enable-snippets cli argument to apply to Ingress resources as well as VirtualServer, VirtualServerRoute and TransportServer resources. Because the default value of -enable-snippets is false, if you are using snippets in Ingress resources, you must explicitly set the -enable-snippets to true before upgrading the Ingress Controller, so that the new version of the Ingress Controller doesn't reject Ingresses with snippets annotations.

<hr>

## 2.0.2

13 October 2021

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX App Protect version to 3.6.
- Update NGINX Plus version to R25 in NGINX App Protect enabled images.

### <i class="fa-solid fa-rocket"></i> Features

- [2074](https://github.com/nginx/kubernetes-ingress/pull/2074) Update JWT library to `golang-jwt/jwt`. Previously, the Ingress Controller used `dgrijalva/jwt-go`, which has a vulnerability [CVE-2020-26160](https://nvd.nist.gov/vuln/detail/CVE-2020-26160). Note that the Ingress Controller wasn’t affected by this vulnerability, and the jwt library was used only in the NGINX Plus images from AWS Marketplace for Containers.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.0.2 image from our DockerHub.
- For NGINX Plus, use the 2.0.2 from the F5 Container registry or build your own image using the 2.0.2 source code.
- For Helm, use version 0.11.2 of the chart.

<hr>

## 2.0.1

07 October 2021

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2051](https://github.com/nginx/kubernetes-ingress/pull/2051) Use release specific repo for NGINX Plus on Debian. This fixes an error when building the Debian-based image with NGINX Plus and App Protect: previously, building the image would fail with the error `Package 'nginx-plus-r24' has no installation candidate`.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.0.1 image from our DockerHub.
- For NGINX Plus, use the 2.0.1 from the F5 Container registry or build your own image using the 2.0.1 source code.
- For Helm, use version 0.11.1 of the chart.

<hr>

## 1.12.2

7 October 2021

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [2048](https://github.com/nginx/kubernetes-ingress/pull/2048) Use release specific repo for NGINX Plus on Debian. This fixes an error when building Debian-based images with NGINX Plus: previously, building an image would fail with the error `Package 'nginx-plus-r24' has no installation candidate`. The bug first appeared when NGINX Plus R25 was released on 28 September 2021.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.12.2 image from our DockerHub: `nginx/nginx-ingress:1.12.2`, `nginx/nginx-ingress:1.12.2-alpine` or `nginx/nginx-ingress:1.12.2-ubi`
- For NGINX Plus, please build your own image using the 1.12.2 source code.
- For Helm, use version 0.10.2 of the chart.

<hr>

## 2.0.0

28 September 2021

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 2.0.0 includes:

- *Support for Ingress networking.k8s.io/v1*. Kubernetes 1.22 removes support for networking.k8s.io/v1beta1. To support Kubernetes 1.22, NGINX Ingress Controller 2.0 is also compatible with only the networking.k8s.io/v1 version of the Ingress and IngressClass resources.  This has the following implications:
  1. The minimum supported version of Kubernetes is now 1.19. For older Kubernetes versions, use the 1.12.x release of the Ingress Controller.
  2. For Kubernetes versions 1.19-1.21, you can continue using the `networking.k8s.io/v1beta1` of the Ingress and IngressClass resources.
  3. For Kubernetes 1.22, you need to migrate your Ingress and IngressClass resources to `networking.k8s.io/v1`.
  4. If you are using the deprecated `kubernetes.io/ingress.class` annotation in your Ingress resources, it is recommended to switch to the `ingressClassName` field.

     We migrated all our documentation and examples to use `networking.k8s.io/v1` and the `ingressClassName` field of the Ingress resource.
- *Scalability improvements*. We improved the time for an Ingress Controller pod to become ready and start receiving traffic. This is especially noticeable when you have hundreds of Ingress or other configuration resources like VirtualServers: instead of several minutes or more in rare cases, a pod will become ready within a few minutes.
- *Documentation improvements* We changed the look and feel of our documentation at <https://docs.nginx.com/nginx-ingress-controller> as well as the underlying publishing technology, which will allow us to bring even more improvements in the next releases.
- *Upgrade path for k8s.nginx.org/v1alpha1 Policy resource* If you’re running release 1.9.0 and using the k8s.nginx.org/v1alpha1 Policy, the Ingress Controller now supports an upgrade path from v1alpha1 to v1 Policy version without downtime. See UPDATING POLICIES section below.

You will find the complete changelog for release 2.0.0, including bug fixes, improvements, and changes below.

### <i class="fa-solid fa-bomb"></i> Breaking Changes

- [1850](https://github.com/nginx/kubernetes-ingress/pull/1850) Support Ingress and IngressClass v1.

### <i class="fa-solid fa-rocket"></i> Features

- [1908](https://github.com/nginx/kubernetes-ingress/pull/1908) Add NTLM support to VirtualServer and VirtualServerRoute upstreams.
- [1746](https://github.com/nginx/kubernetes-ingress/pull/1746) Add ingressClassName field to Policy.
- [1956](https://github.com/nginx/kubernetes-ingress/pull/1956) Add v1alpha1 version back to policy CRD.
- [1907](https://github.com/nginx/kubernetes-ingress/pull/1907) Remove libs compilation for OpenTracing in Dockerfile; add Zipkin and Datadog in addition to the already supported Jaeger tracer; additionally, for NGINX we now publish a Docker image with the tracers and the OpenTracing module on DockerHub: `nginx-ic/nginx-plus-ingress:1.12.0-ot`. Also thanks to [MatyRi](https://github.com/MatyRi) for upgrading OpenTracing in [1883](https://github.com/nginx/kubernetes-ingress/pull/1883).
- [1788](https://github.com/nginx/kubernetes-ingress/pull/1788) Reload only once during the start. This significantly reduces the time it takes for an Ingress Controller pod to become ready when hundreds of Ingress or other supported resources are created in the cluster.
- [1721](https://github.com/nginx/kubernetes-ingress/pull/1721) Increase default reload timeout to 60s: the Ingress Controller will wait for 60s for NGINX to start or reload. Previously, the default was 4 seconds.
- [2009](https://github.com/nginx/kubernetes-ingress/pull/2009) Increase default upstream zone size for NGINX Plus. See the INCREASED UPSTREAM ZONES section below.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [1926](https://github.com/nginx/kubernetes-ingress/pull/1926) Fix increased IC pod startup time when hundreds of VirtualServerRoutes are used
- [1712](https://github.com/nginx/kubernetes-ingress/pull/1712) Allow `make` to build image when .git directory is missing.

### <i class="fa-solid fa-file"></i> Documentation

- [1932](https://github.com/nginx/kubernetes-ingress/pull/1932) Add IAM instructions for NGINX Plus AWS Marketplace images.
- [1927](https://github.com/nginx/kubernetes-ingress/pull/1927) Fix function name comments typo. Thanks to [Sven Nebel](https://github.com/snebel29).
- [1898](https://github.com/nginx/kubernetes-ingress/pull/1898) Add instructions for configuring MyF5 JWT as a Docker registry secret for the F5 Container registry for NGINX Plus images.
- [1851](https://github.com/nginx/kubernetes-ingress/pull/1851) Update docs and examples to use networking.k8s.io/v1.
- [1765](https://github.com/nginx/kubernetes-ingress/pull/1765) Create documentation for pulling NGINX Plus images from the F5 Container registry.
- [1740](https://github.com/nginx/kubernetes-ingress/pull/1740) Publish docs using Hugo and Netlify.
- [1702](https://github.com/nginx/kubernetes-ingress/pull/1702) Add security recommendations documentation.

### <i class="fa-solid fa-box"></i> Helm Chart

- Add new parameters to the Chart: `controller.pod.extraLabels`. Added in [1884](https://github.com/nginx/kubernetes-ingress/pull/1884).

### <i class="fa-solid fa-upload"></i> Dependencies

- [1855](https://github.com/nginx/kubernetes-ingress/pull/1855) Update minimum Kubernetes version to 1.19; remove the `-use-ingress-class-only` command-line argument, which doesn't work with Kubernetes >= 1.19.
- Update NGINX Plus version to R25. **Note**: images with NGINX App Protect will continue to use R24 until App Protect 3.6 is released.
- Update NGINX version to 1.21.3.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 2.0.0 image from our DockerHub.
- For NGINX Plus, use the 2.0.0 from the F5 Container registry or build your own image using the 2.0.0 source code.
- For Helm, use version 0.11.0 of the chart.

See the complete list of supported images for NGINX and NGINX Plus on the [Technical Specifications](https://docs.nginx.com/nginx-ingress-controller/technical-specifications/#supported-docker-images) page.

INCREASED UPSTREAM ZONES

We increased the default size of an upstream zone from 256K to 512K to accommodate a change in NGINX Plus R25. The change makes NGINX Plus allocate more memory for storing upstream server (peer) data, which means upstream server zones will use more memory to account for that new data.

The increase in the zone size is to prevent NGINX Plus configuration reload failures after an upgrade to release 1.13.0. Note that If a zone becomes full, NGINX Plus will fail to reload and fail to add more upstream servers via the API.

The new 512K default value will be able to hold ~270 upstream servers per upstream, similarly to how the old 256K value was able to hold the same number of upstream servers in the previous Ingress Controller releases. You can understand the utilization of the upstream zones via [NGINX Plus API](http://nginx.org/en/docs/http/ngx_http_api_module.html#slabs) and the [NGINX Plus dashboard](https://docs.nginx.com/nginx-ingress-controller/logging-and-monitoring/status-page/#accessing-live-activity-monitoring-dashboard) (the shared zones tab).

If you have a large number of upstream in the NGINX Plus configuration of the Ingress Controller, expect that after an upgrade NGINX Plus will consume more memory: +256K per upstream. If you don’t have upstreams with huge number of upstream serves and you’d like to reduce the memory usage of NGINX Plus, you can configure the `upstream-zone-size` [ConfigMap key](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/#backend-services-upstreams) with a lower value. Additionally, the Ingress resource supports `nginx.org/upstream-zone-size` [annotation](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#backend-services-upstreams) to configure zone sizes for the upstreams of an Ingress resource rather than globally.

UPDATING POLICIES

This section is only relevant if you’re running release 1.9.0 and planning to upgrade to release 2.0.0.

Release 1.10 removed the `k8s.nginx.org/v1alpha1 version` of the Policy resource and introduced the `k8s.nginx.org/v1` version. This means that to upgrade to release 1.10 users had to re-create v1alpha1 Policies with the v1 version, which caused downtime for their applications. Release 2.0.0 brings back the support for the v1alpha1 Policy, which makes it possible to upgrade from 1.9.0 to 2.0.0 release without causing downtime:

- If the Policy is marked as a preview feature in the [documentation](https://docs.nginx.com/nginx-ingress-controller/configuration/policy-resource/), make sure the -enable-preview-policies command-line argument is set in 2.0.0 Ingress Controller.
- During the upgrade, the existing Policies will not be removed.
- After the upgrade, make sure to update the Policy manifests to k8s.nginx.org/v1 version.

Please also read the [release 1.10 changelog](https://docs.nginx.com/nginx-ingress-controller/releases/#nginx-ingress-controller-1100) for the instructions on how to update Secret resources, which is also necessary since some of the Policies reference Secrets.

Note that 2.1.0 will remove support for the v1alpha1 version of the Policy.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and which passes the Kubernetes conformance tests. This release was fully tested on the following Kubernetes versions: 1.19-1.22.

<hr>

## 1.12.1

8 September 2021

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX App Protect version to 3.5.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.12.1 image from our DockerHub: `nginx/nginx-ingress:1.12.1`, `nginx/nginx-ingress:1.12.1-alpine` or `nginx/nginx-ingress:1.12.1-ubi`
- For NGINX Plus, use the 1.12.1 image from the F5 Container Registry - see [the documentation here]({{< ref "/installation/nic-images/get-registry-image.md">}})
- Alternatively, you can also build your own image using the 1.12.1 source code.
- For Helm, use version 0.10.1 of the chart.

<hr>

## 1.12.0

30 June 2021

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.12.0 includes:

- The introduction of pre-built containers for advanced capabilities with NGINX Plus through the F5 Container Registry.
- TransportServer supports TCP/UDP connections through the NGINX streams module adding support for matching specific health check response patterns for granular availability testing of your application, maximum connections to protect your applications from overload, supporting fine tuning of load balancing behavior, and snippets for advanced capability support as soon as you are ready to implement.
- Availability through the AWS Container marketplace supporting Elastic Kubernetes Service.
- NGINX App Protect capabilities have been extended to support the latest version and its capabilities.

You will find the complete changelog for release 1.12.0, including bug fixes, improvements, and changes below.

### <i class="fa-solid fa-rocket"></i> Features

- [1633](https://github.com/nginx/kubernetes-ingress/pull/1633) Support match in TransportServer health checks.
- [1619](https://github.com/nginx/kubernetes-ingress/pull/1619) Add AWS Marketplace Entitlement verification.
- [1480](https://github.com/nginx/kubernetes-ingress/pull/1480) Add max connections to TransportServer.
- [1479](https://github.com/nginx/kubernetes-ingress/pull/1479) Add load balancing method to TransportServer.
- [1466](https://github.com/nginx/kubernetes-ingress/pull/1466) Support snippets in TransportServer.
- [1578](https://github.com/nginx/kubernetes-ingress/pull/1578) Add support for CSRF protection in APPolicy.
- [1513](https://github.com/nginx/kubernetes-ingress/pull/1513) Support multiple log security configs in Ingresses.
- [1481](https://github.com/nginx/kubernetes-ingress/pull/1481) Add support for user defined browsers in APPolicy.
- [1411](https://github.com/nginx/kubernetes-ingress/pull/1411) Add unary gRPC support in APPolicy.
- [1671](https://github.com/nginx/kubernetes-ingress/pull/1671) Simplify Dockerfile stages for Debian.
- [1652](https://github.com/nginx/kubernetes-ingress/pull/1652) Add HTTPS option to Prometheus endpoint.
- [1646](https://github.com/nginx/kubernetes-ingress/pull/1646) Improve Dockerfile.
- [1574](https://github.com/nginx/kubernetes-ingress/pull/1574) Add Docker image for Alpine with NGINX Plus.
- [1512](https://github.com/nginx/kubernetes-ingress/pull/1512) Don't require default server TLS secret.
- [1500](https://github.com/nginx/kubernetes-ingress/pull/1500) Support ssl_reject_handshake in Ingress and VS.
- [1494](https://github.com/nginx/kubernetes-ingress/pull/1494) Add logs around NGINX Plus binary/flag mismatch.
- [1492](https://github.com/nginx/kubernetes-ingress/pull/1492) Update the IC so that GlobalConfiguration is not mandatory when configured.
- [1500](https://github.com/nginx/kubernetes-ingress/pull/1500) Support ssl_reject_handshake in Ingress and VS. Previously, to handle missing or invalid TLS Secrets in Ingress and VirtualServer resources, the Ingress Controller would configure NGINX to break any attempts for clients to establish TLS connections to the affected hosts using `ssl_ciphers NULL;` in the NGINX configuration. The method didn't work for TLS v1.3. Now the Ingress Controller uses `ssl_reject_handshake on;`, which works for TLS v1.3.
- Documentation improvements: [1649](https://github.com/nginx/kubernetes-ingress/pull/1649).

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [1658](https://github.com/nginx/kubernetes-ingress/pull/1658) Add missing njs module to the openshift-image-nap-plus image.
- [1654](https://github.com/nginx/kubernetes-ingress/pull/1654) Fix incorrect configuration and unexpected warnings about Secrets at the IC start.
- [1501](https://github.com/nginx/kubernetes-ingress/pull/1501) Fix ungraceful shutdown of NGINX.
- Documentation fixes: [1668](https://github.com/nginx/kubernetes-ingress/pull/1668), [1594](https://github.com/nginx/kubernetes-ingress/pull/1594) thanks to [shaggy245](https://github.com/shaggy245), [1563](https://github.com/nginx/kubernetes-ingress/pull/1563), [1551](https://github.com/nginx/kubernetes-ingress/pull/1551).

### <i class="fa-solid fa-box"></i> Helm Chart

- Add new parameters to the Chart: `prometheus.scheme`, `prometheus.secret`. Added in [1652](https://github.com/nginx/kubernetes-ingress/pull/1652).

### <i class="fa-solid fa-upload"></i> Dependencies

- [1604](https://github.com/nginx/kubernetes-ingress/pull/1604) Update NGINX Plus to R24. Previously, the Dockerfile had a fixed NGINX Plus version. Now the Dockerfile has a floating version that corresponds to the latest major NGINX Plus version. In the event of a patch version of NGINX Plus being released, make sure to rebuild your image to get the latest version (previously, we released a new Ingress Controller release in that case). Additionally, the AppProtect related packages are no longer fixed -- the Dockerfile will always install the latest version of the packages that work with the latest NGINX Plus version.
- Update NGINX version to 1.21.0.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.12.0 image from our DockerHub: `nginx/nginx-ingress:1.12.0`, `nginx/nginx-ingress:1.12.0-alpine` or `nginx-ingress:1.12.0-ubi`
- For NGINX Plus, please build your own image using the 1.12.0 source code.
- For Helm, use version 0.10.0 of the chart.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and which passes the Kubernetes conformance tests.  This release was fully tested on the following Kubernetes versions: 1.16-1.21.

<hr>

## 1.11.3

25 May 2021

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.21.0.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.11.3 image from our DockerHub: `nginx/nginx-ingress:1.11.3`, `nginx/nginx-ingress:1.11.3-alpine` or `nginx/nginx-ingress:1.11.3-ubi`
- For NGINX Plus, please build your own image using the 1.11.3 source code.
- For Helm, use version 0.9.3 of the chart.

<hr>

## 1.11.2

19 May 2021

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX Plus version to R23 P1.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.11.2 image from our DockerHub: `nginx/nginx-ingress:1.11.2`, `nginx/nginx-ingress:1.11.2-alpine` or `nginx/nginx-ingress:1.11.2-ubi`
- For NGINX Plus, please build your own image using the 1.11.2 source code.
- For Helm, use version 0.9.2 of the chart.

<hr>

## 1.11.1

7 April 2021

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.19.9.
- Update the OpenSSL libraries used in the UBI images

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.11.1 image from our DockerHub: `nginx/nginx-ingress:1.11.1`, `nginx/nginx-ingress:1.11.1-alpine` or `nginx/nginx-ingress:1.11.1-ubi`
- For NGINX Plus, please build your own image using the 1.11.1 source code.
- For Helm, use version 0.9.1 of the chart.

<hr>

## 1.11.0

31 March 2021

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.11.0 includes:

- Native NGINX Ingress Controller App Protect (WAF) policy
- TransportServer improvements in terms of reliability, added features and operational aspects
- Integration of NGINX Ingress Controller with Istio service mesh

You will find the complete changelog for release 1.11.0, including bug fixes, improvements, and changes below.

### <i class="fa-solid fa-rocket"></i> Features

- [1317](https://github.com/nginx/kubernetes-ingress/pull/1317) Add status field to Policy resource.
- [1449](https://github.com/nginx/kubernetes-ingress/pull/1449) Add support for ClusterIP in upstreams in VirtualServers/VirtualServerRoutes.
- [1413](https://github.com/nginx/kubernetes-ingress/pull/1413) Add serverSnippets to TransportServer.
- [1425](https://github.com/nginx/kubernetes-ingress/pull/1425) Add status field to TransportServer resource.
- [1384](https://github.com/nginx/kubernetes-ingress/pull/1384) Add active health checks to TransportServer.
- [1382](https://github.com/nginx/kubernetes-ingress/pull/1382) Add passive health checks to TransportServer.
- [1346](https://github.com/nginx/kubernetes-ingress/pull/1346) Add configurable timeouts to TransportServer.
- [1297](https://github.com/nginx/kubernetes-ingress/pull/1297) Support custom return in the default server. Thanks to [030](https://github.com/030).
- [1378](https://github.com/nginx/kubernetes-ingress/pull/1378) Add WAF Policy.
- [1420](https://github.com/nginx/kubernetes-ingress/pull/1420) Support IngressClassName in TransportServer.
- [1415](https://github.com/nginx/kubernetes-ingress/pull/1415) Handle host and listener collisions for TransportServer resource.
- [1322](https://github.com/nginx/kubernetes-ingress/pull/1322) Improve VirtualServer/VirtualServerRoute warnings for Policies.
- [1288](https://github.com/nginx/kubernetes-ingress/pull/1288) Add stricter validation for some ingress annotations.
- [1241](https://github.com/nginx/kubernetes-ingress/pull/1241) Refactor Dockerfile and Makefile.
- Documentation improvements: [1320](https://github.com/nginx/kubernetes-ingress/pull/1320), [1326](https://github.com/nginx/kubernetes-ingress/pull/1326), and [1377](https://github.com/nginx/kubernetes-ingress/pull/1377).

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [1457](https://github.com/nginx/kubernetes-ingress/pull/1457) Wait for caches to sync when the Ingress Controller starts.
- [1444](https://github.com/nginx/kubernetes-ingress/pull/1444) Fix setting host header in action proxy in VirtualServer/VirtualServerRoute.
- [1396](https://github.com/nginx/kubernetes-ingress/pull/1396) Fix reload timeout calculation for verifying NGINX reloads.

### <i class="fa-solid fa-upload"></i> Dependencies

- [1455](https://github.com/nginx/kubernetes-ingress/pull/1455) Update NGINX version to 1.19.8.
- [1428](https://github.com/nginx/kubernetes-ingress/pull/1428) Update Nginx App Protect version to 3.0. **Note**:  [The Advanced gRPC Protection for Unary Traffic](/nginx-app-protect/configuration/#advanced-grpc-protection-for-unary-traffic) is not currently supported.

### <i class="fa-solid fa-bug"></i> Known Issues

- [1448](https://github.com/nginx/kubernetes-ingress/issues/1448) When an Ingress Controller pod starts, it can report warnings about missing secrets for Ingress and other resources that reference secrets. Those warnings are intermittent - once the Ingress Controller fully processes the resources of the cluster, it will clear the warnings. Only after that, the Ingress Controller will become ready to accept client traffic - its readiness probe will succeed.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.11.0 image from our DockerHub: `nginx/nginx-ingress:1.11.0`, `nginx/nginx-ingress:1.11.0-alpine` or `nginx-ingress:1.11.0-ubi`
- For NGINX Plus, please build your own image using the 1.11.0 source code.
- For Helm, use version 0.9.0 of the chart.
- [1241](https://github.com/nginx/kubernetes-ingress/pull/1241) improved the Makefile. As a result, the commands for building the Ingress Controller image were changed. See the updated commands [here]({{< relref "/installation/build-nginx-ingress-controller.md" >}}).
- [1241](https://github.com/nginx/kubernetes-ingress/pull/1241) also consolidated all Dockerfiles into a single Dockerfile. If you customized any of the Dockerfiles, make sure to port the changes to the new Dockerfile.
- [1288](https://github.com/nginx/kubernetes-ingress/pull/1288) further improved validation of Ingress annotations. See this [document](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#validation) to learn more about which annotations are validated. Note that the Ingress Controller will reject resources with invalid annotations, which means clients will see `404` responses from NGINX.  Before upgrading, ensure the Ingress resources don't have annotations with invalid values. Otherwise, after the upgrade, the Ingress Controller will reject such resources.
- [1457](https://github.com/nginx/kubernetes-ingress/pull/1457) fixed the bug when an Ingress Controller pod could become ready before it generated the configuration for all relevant resources in the cluster. The fix also requires that the Ingress Controller can successfully list the relevant resources from the Kubernetes API. For example, if the `-enable-custom-resources` cli argument is `true` (which is the default), the VirtualServer, VirtualServerRoute, TransportServer, and Policy CRDs must be created in the cluster, so that the Ingress Controller can list them. This is similar to other custom resources -- see the list [here](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/#create-custom-resources). Thus, before upgrading, make sure that the CRDs are created in the cluster. Otherwise, the Ingress Controller pods will not become ready.

### <i class="fa-solid fa-life-ring"></i> Supported Platforms

We will provide technical support for NGINX Ingress Controller on any Kubernetes platform that is currently supported by its provider and which passes the Kubernetes conformance tests.  This release was fully tested on the following Kubernetes versions: 1.16-1.20.

<hr>

## 1.10.1

16 March 2021

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.19.8.
- Add Kubernetes 1.20 support.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [1373](https://github.com/nginx/kubernetes-ingress/pull/1373), [1439](https://github.com/nginx/kubernetes-ingress/pull/1439), [1440](https://github.com/nginx/kubernetes-ingress/pull/1440): Fix various issues in the Makefile. In 1.10.0, a bug was introduced that prevented building Ingress Controller images on versions of make < 4.1.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.10.1 image from our DockerHub: `nginx/nginx-ingress:1.10.1`, `nginx/nginx-ingress:1.10.1-alpine` or `nginx/nginx-ingress:1.10.1-ubi`
- For NGINX Plus, please build your own image using the 1.10.1 source code.
- For Helm, use version 0.8.1 of the chart.

<hr>

## 1.10.0

26 January 2021

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.10.0 includes:

- Open ID Connect authentication policy.
- Improved handling of Secret resources with extended validation and error reporting.
- Improved visibility with Prometheus metrics for the configuration workqueue and the ability to annotate NGINX logs with the metadata of Kubernetes resources.
- NGINX App Protect User-Defined signatures support.
- Improved validation of Ingress annotations.

You will find the complete changelog for release 1.10.0, including bug fixes, improvements, and changes below.

### <i class="fa-solid fa-rocket"></i> Features

- [1304](https://github.com/nginx/kubernetes-ingress/pull/1304) Add Open ID Connect policy.
- [1281](https://github.com/nginx/kubernetes-ingress/pull/1281) Add support for App Protect User Defined Signatures.
- [1266](https://github.com/nginx/kubernetes-ingress/pull/1266) Add workqueue metrics to Prometheus metrics.
- [1233](https://github.com/nginx/kubernetes-ingress/pull/1233) Annotate tcp metrics with k8s object labels.
- [1231](https://github.com/nginx/kubernetes-ingress/pull/1231) Support k8s objects variables in log format.
- [1270](https://github.com/nginx/kubernetes-ingress/pull/1270) and [1277](https://github.com/nginx/kubernetes-ingress/pull/1277) Improve validation of Ingress annotations.
- [1265](https://github.com/nginx/kubernetes-ingress/pull/1265) Report warnings for misconfigured TLS and JWK secrets.
- [1262](https://github.com/nginx/kubernetes-ingress/pull/1262) Use setcap(8) only once. [1263](https://github.com/nginx/kubernetes-ingress/pull/1263) Use chown(8) only once. [1264](https://github.com/nginx/kubernetes-ingress/pull/1264) Use mkdir(1) only once. Thanks to [Sergey A. Osokin](https://github.com/osokin).
- [1256](https://github.com/nginx/kubernetes-ingress/pull/1256) and [1260](https://github.com/nginx/kubernetes-ingress/pull/1260) Improve handling of secret resources.
- [1240](https://github.com/nginx/kubernetes-ingress/pull/1240) Validate TLS and CA secrets.
- [1235](https://github.com/nginx/kubernetes-ingress/pull/1235) Use buildkit secret flag for NGINX plus images.
- [1290](https://github.com/nginx/kubernetes-ingress/pull/1290) Graduate policy resource and accessControl policy to generally available.
- [1225](https://github.com/nginx/kubernetes-ingress/pull/1225) Require secrets to have types.
- [1237](https://github.com/nginx/kubernetes-ingress/pull/1237) Deprecate support for helm2 clients.
- Documentation improvements: [1282](https://github.com/nginx/kubernetes-ingress/pull/1282), [1293](https://github.com/nginx/kubernetes-ingress/pull/1293), [1303](https://github.com/nginx/kubernetes-ingress/pull/1303), [1315](https://github.com/nginx/kubernetes-ingress/pull/1315).

### <i class="fa-solid fa-box"></i> Helm Chart

- [1290](https://github.com/nginx/kubernetes-ingress/pull/1290) Add new preview policies parameter to chart. `controller.enablePreviewPolicies` was added.
- [1232](https://github.com/nginx/kubernetes-ingress/pull/1232) Replace deprecated imagePullSecrets helm setting. `controller.serviceAccount.imagePullSecrets` was removed. `controller.serviceAccount.imagePullSecretName` was added.
- [1228](https://github.com/nginx/kubernetes-ingress/pull/1228) Fix installation of ingressclass on Kubernetes versions `v1.18.x-*`

### <i class="fa-solid fa-upload"></i> Dependencies

- [1299](https://github.com/nginx/kubernetes-ingress/pull/1299) Update NGINX App Protect version to 2.3 and debian distribution to `debian:buster-slim`.
- [1291](https://github.com/nginx/kubernetes-ingress/pull/1291) Update NGINX OSS to `1.19.6`. Update NGINX Plus to `R23`.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.10.0 image from our DockerHub: `nginx/nginx-ingress:1.10.0`, `nginx/nginx-ingress:1.10.0-alpine` or `nginx-ingress:1.10.0-ubi`
- For NGINX Plus, please build your own image using the 1.10.0 source code.
- For Helm, use version 0.8.0 of the chart.
- As a result of [1270](https://github.com/nginx/kubernetes-ingress/pull/1270) and [1277](https://github.com/nginx/kubernetes-ingress/pull/1277), the Ingress Controller improved validation of Ingress annotations: more annotations are validated and validation errors are reported via events for Ingress resources. Additionally, the default behavior for invalid annotation values was changed: instead of using the default values, the Ingress Controller will reject a resource with an invalid annotation value, which will make clients see `404` responses from NGINX. See this [document](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/#validation) to learn more. Before upgrading, ensure the Ingress resources don't have annotations with invalid values. Otherwise, after the upgrade, the Ingress Controller will reject such resources.
- In [1232](https://github.com/nginx/kubernetes-ingress/pull/1232) `controller.serviceAccount.imagePullSecrets` was removed. Use the new `controller.serviceAccount.imagePullSecretName` instead.
- The Policy resource was promoted to `v1`. If you used the `alpha1` version, the policies are needed to be recreated with the `v1` version. Before upgrading the Ingress Controller, run the following command to remove the `alpha1` policies CRD (that will also remove all existing `alpha1` policies):

    ```console
     kubectl delete crd policies.k8s.nginx.org
    ```

  As part of the upgrade, make sure to create the `v1` policies CRD. See the corresponding instructions for the [manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/#create-custom-resources) and [Helm](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/#upgrading-the-crds) installations.

  Also note that all policies except for `accessControl` are still in preview. To enable them, run the Ingress Controller with `- -enable-preview-policies` command-line argument (`controller.enablePreviewPolicies` Helm parameter).
- It is necessary to update secret resources. See the section UPDATING SECRETS below.

UPDATING SECRETS:

In [1225](https://github.com/nginx/kubernetes-ingress/pull/1225), as part of improving how the Ingress Controller handles secret resources, we added a requirement for secrets to be of one of the following types:

- `kubernetes.io/tls` for TLS secrets.
- `nginx.org/jwk` for JWK secrets.
- `nginx.org/ca` for CA secrets.

The Ingress Controller now ignores secrets that are not of a supported type. As a consequence, special upgrade steps are required.

Before upgrading, ensure that the secrets referenced in Ingress, VirtualServer or Policies resources are of a supported type, which is configured via the `type` field. Because that field is immutable, it is necessary to either:

- Recreate the secrets. Note that in this case, the client traffic for the affected resources will be rejected for the period during which a secret doesn't exist in the cluster.
- Create copies of the secrets and update the affected resources to reference the copies. The copies need to be of a supported type. In contrast with the previous options, this will not make NGINX reject the client traffic.

It is also necessary to update the default server secret and the wildcard secret (if it was configured) in case their type is not `kubernetes.io/tls`. The steps depend on how you installed the Ingress Controller: via manifests or Helm. Performing the steps will not lead to a disruption of the client traffic, as the Ingress Controller retains the default and wildcard secrets if they are removed.

For *manifests installation*:

1. Recreate the default server secret and the wildcard secret with the type `kubernetes.io/tls`.
1. Upgrade the Ingress Controller.

For *Helm installation*, there two cases:

1. If Helm created the secrets (you configured `controller.defaultTLS.cert` and `controller.defaultTLS.key` for the default secret and `controller.wildcardTLS.cert` and `controller.wildcardTLS.key` for the wildcard secret), then no special upgrade steps are required: during the upgrade, the Helm will remove the existing default and wildcard secrets and create new ones with different names with the type `kubernetes.io/tls`.
1. If you created the secrets separately from Helm (you configured `controller.defaultTLS.secret` for the default secret and `controller.wildcardTLS.secret` for the wildcard secret):
    1. Recreate the secrets with the type `kubernetes.io/tls`.
    1. Upgrade to the new Helm release.

NOTES:

- Helm 2 clients are no longer supported due to reaching End of Life: <https://helm.sh/blog/helm-2-becomes-unsupported/>

<hr>

## 1.9.1

23 November 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update the base ubi images to 8.3.

### <i class="fa-solid fa-rocket"></i> Features

- Fix deployment of ingressclass resource via helm on some versions of Kubernetes.
- Renew CA cert for egress-mtls example.
- Add imagePullSecretName support to helm chart.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.9.1 image from our DockerHub: `nginx/nginx-ingress:1.9.1`, `nginx/nginx-ingress:1.9.1-alpine` or `nginx/nginx-ingress:1.9.1-ubi`
- For NGINX Plus, please build your own image using the 1.9.1 source code.
- For Helm, use version 0.7.1 of the chart.

<hr>

## 1.9.0

20 October 2020

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.9.0 includes:

- Support for new Prometheus metrics and enhancements of the existing ones, including configuration reload reason, NGINX worker processes count, upstream latency, and more.
- Support for rate limiting, JWT authentication, ingress(client) and egress(upstream) mutual TLS via the Policy resource.
- Support for the latest Ingress resource features and the IngressClass resource.
- Support for NGINX Service Mesh.

You will find the complete changelog for release 1.9.0, including bug fixes, improvements, and changes below.

### <i class="fa-solid fa-rocket"></i> Features

- [1180](https://github.com/nginx/kubernetes-ingress/pull/1180) Add support for EgressMTLS.
- [1166](https://github.com/nginx/kubernetes-ingress/pull/1166) Add IngressMTLS policy support.
- [1154](https://github.com/nginx/kubernetes-ingress/pull/1154) Add JWT policy support.
- [1120](https://github.com/nginx/kubernetes-ingress/pull/1120) Add RateLimit policy support.
- [1058](https://github.com/nginx/kubernetes-ingress/pull/1058) Support policies in VS routes and VSR subroutes.
- [1147](https://github.com/nginx/kubernetes-ingress/pull/1147) Add option to specify other log destinations in AppProtect.
- [1131](https://github.com/nginx/kubernetes-ingress/pull/1131) Update packages and CRDs to AppProtect 2.0. This update includes features such as: [JSON Schema Validation](https://docs.nginx.com/nginx-app-protect/configuration#applying-a-json-schema), [User-Defined URLs](https://docs.nginx.com/nginx-app-protect/configuration/#user-defined-urls) and [User-Defined Parameters](https://docs.nginx.com/nginx-app-protect/configuration/#user-defined-parameters). See the [release notes](https://docs.nginx.com/nginx-app-protect/releases/#release-2-0) for a complete feature list.
- [1100](https://github.com/nginx/kubernetes-ingress/pull/1100) Add external references to AppProtect.
- [1085](https://github.com/nginx/kubernetes-ingress/pull/1085) Add installation of threat campaigns package.
- [1133](https://github.com/nginx/kubernetes-ingress/pull/1133) Add support for IngressClass resources.
- [1130](https://github.com/nginx/kubernetes-ingress/pull/1130) Add prometheus latency collector.
- [1076](https://github.com/nginx/kubernetes-ingress/pull/1076) Add prometheus worker process metrics.
- [1075](https://github.com/nginx/kubernetes-ingress/pull/1075) Add support for NGINX Service Mesh internal routes.
- [1178](https://github.com/nginx/kubernetes-ingress/pull/1178) Resolve host collisions in VirtualServer and Ingresses.
- [1158](https://github.com/nginx/kubernetes-ingress/pull/1158) Support variables in action proxy headers.
- [1137](https://github.com/nginx/kubernetes-ingress/pull/1137) Add pod_owner label to metrics when -spire-agent-address is set.
- [1107](https://github.com/nginx/kubernetes-ingress/pull/1107) Extend Upstream Servers with pod_name label.
- [1099](https://github.com/nginx/kubernetes-ingress/pull/1099) Add reason label to total_reload metrics.
- [1088](https://github.com/nginx/kubernetes-ingress/pull/1088) Extend Upstream Servers and Server Zones metrics, thanks to [Raúl](https://github.com/Rulox).
- [1080](https://github.com/nginx/kubernetes-ingress/pull/1080) Support pathType field in the Ingress resource.
- [1078](https://github.com/nginx/kubernetes-ingress/pull/1078) Remove trailing blank lines in vs/vsr snippets.
- Documentation improvements: [1083](https://github.com/nginx/kubernetes-ingress/pull/1083), [1092](https://github.com/nginx/kubernetes-ingress/pull/1092), [1089](https://github.com/nginx/kubernetes-ingress/pull/1089), [1174](https://github.com/nginx/kubernetes-ingress/pull/1174), [1175](https://github.com/nginx/kubernetes-ingress/pull/1175), [1171](https://github.com/nginx/kubernetes-ingress/pull/1171).

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [1179](https://github.com/nginx/kubernetes-ingress/pull/1179) Fix TransportServers in debian AppProtect image.
- [1129](https://github.com/nginx/kubernetes-ingress/pull/1129) Support real-ip in default server.
- [1110](https://github.com/nginx/kubernetes-ingress/pull/1110) Add missing threat campaigns key to AppProtect CRD.

### <i class="fa-solid fa-box"></i> Helm Chart

- [1105](https://github.com/nginx/kubernetes-ingress/pull/1105) Fix GlobalConfiguration support in helm chart.
- Add new parameters to the Chart: `controller.setAsDefaultIngress`, `controller.enableLatencyMetrics`. Added in [1133](https://github.com/nginx/kubernetes-ingress/pull/1133) and [1148](https://github.com/nginx/kubernetes-ingress/pull/1148).

### <i class="fa-solid fa-upload"></i> Dependencies

- [1182](https://github.com/nginx/kubernetes-ingress/pull/1182) Update NGINX version to 1.19.3.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.9.0 image from our DockerHub: `nginx/nginx-ingress:1.9.0`, `nginx/nginx-ingress:1.9.0-alpine` or `nginx-ingress:1.9.0-ubi`
- For NGINX Plus, please build your own image using the 1.9.0 source code.
- For Helm, use version 0.7.0 of the chart.

For Kubernetes >= 1.18, when upgrading using the [manifests](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-manifests/), make sure to update the [ClusterRole](https://github.com/nginx/kubernetes-ingress/blob/v1.9.0/deployments/rbac/rbac.yaml) and create the [IngressClass resource](https://github.com/nginx/kubernetes-ingress/blob/v1.9.0/deployments/common/ingress-class.yaml), which is required for Kubernetes >= 1.18. Otherwise, the Ingress Controller will fail to start. If you run multiple NGINX Ingress Controllers in the cluster, each Ingress Controller must have its own IngressClass resource. As the `-use-ingress-class-only` argument is now ignored (see NOTES), make sure your Ingress resources have the `ingressClassName` field or the `kubernetes.io/ingress.class` annotation set to the name of the IngressClass resource. Otherwise, the Ingress Controller will ignore them.

#### Helm Upgrade

- If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to `true`), after you run the `helm upgrade` command, the CRDs will not be upgraded. After running the `helm upgrade` command, run `kubectl apply -f deployments/helm-chart/crds` to upgrade the CRDs.
- For Kubernetes >= 1.18, a dedicated IngressClass resource, which is configured by `controller.ingressClass`, is required per helm release. Ensure `controller.ingressClass` is not set to the name of the IngressClass of other releases or Ingress Controllers. As the `controller.useIngressClassOnly` parameter is now ignored (see NOTES), make sure your Ingress resources have the `ingressClassName` field or the `kubernetes.io/ingress.class` annotation set to the value of `controller.ingressClass`. Otherwise, the Ingress Controller will ignore them.

### Notes

- When using Kubernetes >= 1.18, the `-use-ingress-class-only` command-line argument is now ignored, and the Ingress Controller will only process resources that belong to its class. See [IngressClass doc]({{< ref "/installation/run-multiple-ingress-controllers.md#ingress-class" >}}) for more details.
- For Kubernetes >= 1.18, a dedicated IngressClass resource, which is configured by `controller.ingressClass`, is required per helm release. When upgrading or installing releases, ensure `controller.ingressClass` is not set to the name of the IngressClass of other releases or Ingress Controllers.

<hr>

## 1.8.1

14 August 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.19.2.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.8.1 image from our DockerHub: `nginx/nginx-ingress:1.8.1`, `nginx/nginx-ingress:1.8.1-alpine` or `nginx/nginx-ingress:1.8.1-ubi`
- For NGINX Plus, please build your own image using the 1.8.1 source code.
- For Helm, use version 0.6.1 of the chart.

<hr>

## 1.8.0

22 July 2020

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.8.0 includes:

- Support for NGINX App Protect Web Application Firewall.
- Support for configuration snippets and custom template for VirtualServer and VirtualServerRoute resources.
- Support for request/response header manipulation and request URI rewriting for VirtualServer/VirtualServerRoute.
- Introducing a new configuration resource - Policy - with the first policy for IP-based access control.

You will find the complete changelog for release 1.8.0, including bug fixes, improvements, and changes below.

FEATURES FOR VIRTUALSERVER AND VIRTUALSERVERROUTE RESOURCES:

- [1036](https://github.com/nginx/kubernetes-ingress/pull/1036): Add VirtualServer custom template support.
- [1028](https://github.com/nginx/kubernetes-ingress/pull/1028): Add access control policy.
- [1019](https://github.com/nginx/kubernetes-ingress/pull/1019): Add VirtualServer/VirtualServerRoute snippets support.
- [1006](https://github.com/nginx/kubernetes-ingress/pull/1006): Add request/response modifiers to VS and VSR.
- [994](https://github.com/nginx/kubernetes-ingress/pull/994): Support Class Field in VS/VSR.
- [973](https://github.com/nginx/kubernetes-ingress/pull/973): Add status to VirtualServer and VirtualServerRoute.

### <i class="fa-solid fa-rocket"></i> Features

- [1035](https://github.com/nginx/kubernetes-ingress/pull/1035): Support for App Protect module.
- [1029](https://github.com/nginx/kubernetes-ingress/pull/1029): Add readiness endpoint.
- [995](https://github.com/nginx/kubernetes-ingress/pull/995): Emit event for orphaned VirtualServerRoutes.
- [1029](https://github.com/nginx/kubernetes-ingress/pull/1029): Add readiness endpoint. The Ingress Controller now exposes a readiness endpoint on port `8081` and the path `/nginx-ready`. The endpoint returns a `200` response after the Ingress Controller finishes the initial configuration of NGINX at the start. The pod template was updated to use that endpoint in a readiness probe.
- [980](https://github.com/nginx/kubernetes-ingress/pull/980): Enable leader election by default.
- Documentation improvements: [946](https://github.com/nginx/kubernetes-ingress/pull/946) thanks to [谭九鼎](https://github.com/imba-tjd), [948](https://github.com/nginx/kubernetes-ingress/pull/948), [972](https://github.com/nginx/kubernetes-ingress/pull/972), [965](https://github.com/nginx/kubernetes-ingress/pull/965).

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [1030](https://github.com/nginx/kubernetes-ingress/pull/1030): Fix port range validation in cli arguments.
- [953](https://github.com/nginx/kubernetes-ingress/pull/953): Fix error logging of master/minion ingresses.

### <i class="fa-solid fa-box"></i> Helm Chart

- Add new parameters to the Chart: `controller.appprotect.enable`, `controller.globalConfiguration.create`, `controller.globalConfiguration.spec`, `controller.readyStatus.enable`, `controller.readyStatus.port`, `controller.config.annotations`, `controller.reportIngressStatus.annotations`. Added in  [1035](https://github.com/nginx/kubernetes-ingress/pull/1035), [1034](https://github.com/nginx/kubernetes-ingress/pull/1034), [1029](https://github.com/nginx/kubernetes-ingress/pull/1029), [1003](https://github.com/nginx/kubernetes-ingress/pull/1003) thanks to [RubyLangdon](https://github.com/RubyLangdon).
- [1047](https://github.com/nginx/kubernetes-ingress/pull/1047) and [1009](https://github.com/nginx/kubernetes-ingress/pull/1009): Change how Helm manages the custom resource definitions (CRDs) to support installing multiple Ingress Controller releases. **Note**: If you're using the custom resources (`controller.enableCustomResources` is set to `true`), this is a breaking change. See the HELM UPGRADE section below for the upgrade instructions.

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.19.1.
- Update NGINX Plus to R22.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.8.0 image from our DockerHub: `nginx/nginx-ingress:1.8.0`, `nginx/nginx-ingress:1.8.0-alpine` or `nginx-ingress:1.8.0-ubi`
- For NGINX Plus, please build your own image using the 1.8.0 source code.
- For Helm, use version 0.6.0 of the chart.

#### Helm Upgrade

If you're using custom resources like VirtualServer and TransportServer (`controller.enableCustomResources` is set to `true`), after you run the `helm upgrade` command, the CRDs and the corresponding custom resources will be removed from the cluster. Before upgrading, make sure to back up the custom resources. After running the `helm upgrade` command, run `kubectl apply -f deployments/helm-chart/crds` to re-install the CRDs and then restore the custom resources.

### Notes

- As part of installing a release, Helm will install the CRDs unless that step is disabled (see the [corresponding doc](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/)). The installed CRDs include the CRDs for all Ingress Controller features, including the ones disabled by default (like App Protect with `aplogconfs.appprotect.f5.com` and `appolicies.appprotect.f5.com` CRDs).

<hr>

## 1.7.2

23 June 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX Plus version to R22.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.7.2 image from our DockerHub: `nginx/nginx-ingress:1.7.2`, `nginx/nginx-ingress:1.7.2-alpine` or `nginx/nginx-ingress:1.7.2-ubi`
- For NGINX Plus, please build your own image using the 1.7.2 source code.
- For Helm, use version 0.5.2 of the chart.

<hr>

## 1.7.1

4 June 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.19.0.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.7.1 image from our DockerHub: `nginx/nginx-ingress:1.7.1`, `nginx/nginx-ingress:1.7.1-alpine` or `nginx/nginx-ingress:1.7.1-ubi`
- For NGINX Plus, please build your own image using the 1.7.1 source code.
- For Helm, use version 0.5.1 of the chart.

<hr>

## 1.7.0

30 April 2020

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.7.0 includes:

- Support for TCP, UDP, and TLS Passthrough load balancing with the new configuration resources: TransportServer and GlobalConfiguration. The resources allow users to deliver complex, non-HTTP-based applications from Kubernetes using NGINX Ingress Controller.
- Support for error pages in VirtualServer and VirtualServerRoute resources. A user can now specify custom error responses for errors returned by backend applications or generated by NGINX, such as a 502 response.
- Improved validation of VirtualServer and VirtualServerRoute resources. kubectl and the Kubernetes API server can now detect violations of the structure of VirtualServer/VirtualServerRoute resources and return an error.
- Support for an operator which manages the lifecycle of the Ingress Controller on Kubernetes or OpenShift. See the [NGINX Ingress Operator GitHub repo](https://github.com/nginxinc/nginx-ingress-operator).

See the [1.7.0 release announcement blog post](https://www.nginx.com/blog/announcing-nginx-ingress-controller-for-kubernetes-release-1-7-0/), which includes an overview of each feature.

You will find the complete changelog for release 1.7.0, including bug fixes, improvements, and changes below.

FEATURES FOR VIRTUALSERVER AND VIRTUALSERVERROUTE RESOURCES:

- [868](https://github.com/nginx/kubernetes-ingress/pull/868): Add OpenAPI CRD schema validation.
- [847](https://github.com/nginx/kubernetes-ingress/pull/847): Add support for error pages for VS/VSR.

### <i class="fa-solid fa-rocket"></i> Features

- [902](https://github.com/nginx/kubernetes-ingress/pull/902): Add TransportServer and GlobalConfiguration Resources.
- [894](https://github.com/nginx/kubernetes-ingress/pull/894): Add Dockerfile for NGINX Open Source for Openshift.
- [857](https://github.com/nginx/kubernetes-ingress/pull/857): Add Openshift Dockerfile for NGINX Plus.
- [852](https://github.com/nginx/kubernetes-ingress/pull/852): Add default-server-access-log-off to configmap.
- [845](https://github.com/nginx/kubernetes-ingress/pull/845): Add log-format-escaping and stream-log-format-escaping configmap keys. Thanks to [Alexey Maslov](https://github.com/alxmsl).
- [827](https://github.com/nginx/kubernetes-ingress/pull/827): Add ingress class label to all Prometheus metrics.
- [850](https://github.com/nginx/kubernetes-ingress/pull/850): Extend redirect URI validation with protocol check in VS/VSR.
- [832](https://github.com/nginx/kubernetes-ingress/pull/832): Update the examples to run the `nginxdemos/nginx-hello:plain-text` image, that doesn't require root user.
- [825](https://github.com/nginx/kubernetes-ingress/pull/825): Add multi-stage docker builds.
- [852](https://github.com/nginx/kubernetes-ingress/pull/852): Add default-server-access-log-off to configmap. The access logs for the default server are now enabled by default.
- [847](https://github.com/nginx/kubernetes-ingress/pull/847): Add support for error pages for VS/VSR. The PR affects how the Ingress Controller generates configuration for VirtualServer and VirtualServerRoutes. See [this comment](https://github.com/nginx/kubernetes-ingress/pull/847) for more details.
- [827](https://github.com/nginx/kubernetes-ingress/pull/827): Add ingress class label to all Prometheus metrics. Every Prometheus metric exposed by the Ingress Controller now includes the label `class` with the value of the Ingress Controller class (by default `nginx`),
- [825](https://github.com/nginx/kubernetes-ingress/pull/825): Add multi-stage docker builds. When building the Ingress Controller image in Docker, we now use a multi-stage docker build.

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [828](https://github.com/nginx/kubernetes-ingress/pull/828): Fix error messages for actions of the type return.

### <i class="fa-solid fa-box"></i> Helm Chart

- Add new parameters to the Chart: `controller.enableTLSPassthrough`, `controller.volumes`, `controller.volumeMounts`, `controller.priorityClassName`. Added in [921](https://github.com/nginx/kubernetes-ingress/pull/921), [878](https://github.com/nginx/kubernetes-ingress/pull/878), [807](https://github.com/nginx/kubernetes-ingress/pull/807) thanks to [Greg Snow](https://github.com/gsnegovskiy).

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.17.10.
- Update NGINX Plus to R21.
- [854](https://github.com/nginx/kubernetes-ingress/pull/854): Update the Debian base images for NGINX Plus to `debian:buster-slim`.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.7.0 image from our DockerHub: `nginx/nginx-ingress:1.7.0`, `nginx/nginx-ingress:1.7.0-alpine` or `nginx-ingress:1.7.0-ubi`
- For NGINX Plus, please build your own image using the 1.7.0 source code.
- For Helm, use version 0.5.0 of the chart.

When upgrading using the [manifests](/nginx-ingress-controller/installation/installation-with-manifests/), make sure to deploy the new TransportServer CRD (`common/ts-definition.yaml`), as it is required by the Ingress Controller. Otherwise, you will get error messages in the Ingress Controller logs.

<hr>

## 1.6.3

6 March 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.17.9.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.6.3 image from our DockerHub: `nginx/nginx-ingress:1.6.3` or `nginx/nginx-ingress:1.6.3-alpine`
- For NGINX Plus, please build your own image using the 1.6.3 source code.
- For Helm, use version 0.4.3 of the chart.

<hr>

## 1.6.2

6 February 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.17.8.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.6.2 image from our DockerHub: `nginx/nginx-ingress:1.6.2` or `nginx/nginx-ingress:1.6.2-alpine`
- For NGINX Plus, please build your own image using the 1.6.2 source code.
- For Helm, use version 0.4.2 of the chart.

<hr>

## 1.6.1

14 January 2020

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX version to 1.17.7.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.6.1 image from our DockerHub: `nginx/nginx-ingress:1.6.1` or `nginx/nginx-ingress:1.6.1-alpine`
- For NGINX Plus, please build your own image using the 1.6.1 source code.
- For Helm, use version 0.4.1 of the chart.

<hr>

## 1.6.0

19 December 2019

### <i class="fa-solid fa-magnifying-glass"></i> Overview

Release 1.6.0 includes:

- Improvements to VirtualServer and VirtualServerRoute resources, adding support for richer load balancing behavior, more sophisticated request routing, redirects, direct responses, and blue-green and circuit breaker patterns. The VirtualServer and VirtualServerRoute resources are enabled by default and are ready for production use.
- Support for OpenTracing, helping you to monitor and debug complex transactions.
- An improved security posture, with support to run the Ingress Controller as a non-root user.

The release announcement blog post includes the overview for each feature. See <https://www.nginx.com/blog/announcing-nginx-ingress-controller-for-kubernetes-release-1-6-0/>

You will find the complete changelog for release 1.6.0, including bug fixes, improvements, and changes below.

FEATURES FOR VIRTUALSERVER AND VIRTUALSERVERROUTE RESOURCES:

- [780](https://github.com/nginx/kubernetes-ingress/pull/780): Add support for canned responses to VS/VSR.
- [778](https://github.com/nginx/kubernetes-ingress/pull/778): Add redirect support in VS/VSR.
- [766](https://github.com/nginx/kubernetes-ingress/pull/766): Add exact matches and regex support to location paths in VS/VSR.
- [748](https://github.com/nginx/kubernetes-ingress/pull/748): Add TLS redirect support in Virtualserver.
- [745](https://github.com/nginx/kubernetes-ingress/pull/745): Improve routing rules in VS/VSR
- [728](https://github.com/nginx/kubernetes-ingress/pull/728): Add session persistence in VS/VSR.
- [724](https://github.com/nginx/kubernetes-ingress/pull/724): Add VS/VSR Prometheus metrics.
- [712](https://github.com/nginx/kubernetes-ingress/pull/712): Add service subselector support in vs/vsr.
- [707](https://github.com/nginx/kubernetes-ingress/pull/707): Emit warning events in VS/VSR.
- [701](https://github.com/nginx/kubernetes-ingress/pull/701): Add support queue in upstreams for plus in VS/VSR.
- [693](https://github.com/nginx/kubernetes-ingress/pull/693): Add ServerStatusZones support in vs/vsr.
- [670](https://github.com/nginx/kubernetes-ingress/pull/670): Add buffering support for vs/vsr.
- [660](https://github.com/nginx/kubernetes-ingress/pull/660): Add ClientBodyMaxSize support in vs/vsr.
- [659](https://github.com/nginx/kubernetes-ingress/pull/659): Support configuring upstream zone sizes in VS/VSR.
- [655](https://github.com/nginx/kubernetes-ingress/pull/655): Add slow-start support in vs/vsr.
- [653](https://github.com/nginx/kubernetes-ingress/pull/653): Add websockets support for vs/vsr upstreams.
- [641](https://github.com/nginx/kubernetes-ingress/pull/641): Add support for ExternalName Services for vs/vsr.
- [635](https://github.com/nginx/kubernetes-ingress/pull/635): Add HealthChecks support for vs/vsr.
- [634](https://github.com/nginx/kubernetes-ingress/pull/634): Add Active Connections support to vs/vsr.
- [628](https://github.com/nginx/kubernetes-ingress/pull/628): Add retries support for vs/vsr.
- [621](https://github.com/nginx/kubernetes-ingress/pull/621): Add TLS support for vs/vsr upstreams.
- [617](https://github.com/nginx/kubernetes-ingress/pull/617): Add keepalive support to vs/vsr.
- [612](https://github.com/nginx/kubernetes-ingress/pull/612): Add timeouts support to vs/vsr.
- [607](https://github.com/nginx/kubernetes-ingress/pull/607): Add fail-timeout and max-fails support to vs/vsr.
- [596](https://github.com/nginx/kubernetes-ingress/pull/596): Add lb-method support in vs and vsr.

### <i class="fa-solid fa-rocket"></i> Features

- [750](https://github.com/nginx/kubernetes-ingress/pull/750): Add support for health status uri customisation.
- [691](https://github.com/nginx/kubernetes-ingress/pull/691): Helper Functions for custom annotations.
- [631](https://github.com/nginx/kubernetes-ingress/pull/631): Add max_conns support for NGINX plus.
- [629](https://github.com/nginx/kubernetes-ingress/pull/629): Added upstream zone directive annotation. Thanks to [Victor Regalado](https://github.com/vrrs).
- [616](https://github.com/nginx/kubernetes-ingress/pull/616): Add proxy-send-timeout to configmap key and annotation.
- [615](https://github.com/nginx/kubernetes-ingress/pull/615): Add support for Opentracing.
- [614](https://github.com/nginx/kubernetes-ingress/pull/614): Add max-conns annotation. Thanks to [Victor Regalado](https://github.com/vrrs).
- [678](https://github.com/nginx/kubernetes-ingress/pull/678): Increase defaults for server-names-hash-max-size and servers-names-hash-bucket-size ConfigMap keys.
- [694](https://github.com/nginx/kubernetes-ingress/pull/694): Reject VS/VSR resources with enabled plus features for OSS.
- [799](https://github.com/nginx/kubernetes-ingress/pull/779): Enable CRDs by default. VirtualServer and VirtualServerRoute resources are now enabled by default.
- [772](https://github.com/nginx/kubernetes-ingress/pull/772): Update VS/VSR version from v1alpha1 to v1. Make sure to update the `apiVersion` of your VirtualServer and VirtualServerRoute resources.
- [748](https://github.com/nginx/kubernetes-ingress/pull/748): Add TLS redirect support in VirtualServer. The `redirect-to-https` and `ssl-redirect` ConfigMap keys no longer have any effect on generated configs for VirtualServer resources.
- [745](https://github.com/nginx/kubernetes-ingress/pull/745): Improve routing rules. Update the spec of VirtualServer and VirtualServerRoute accordingly. See YAML examples of the changes [here](https://github.com/nginx/kubernetes-ingress/pull/745).
- [710](https://github.com/nginx/kubernetes-ingress/pull/710): Run IC as non-root. Make sure to use the updated manifests to install/upgrade the Ingress Controller.
- [603](https://github.com/nginx/kubernetes-ingress/pull/603): Update apiVersion in Deployments and DaemonSets to apps/v1.
- Documentation improvements: [713](https://github.com/nginx/kubernetes-ingress/pull/713) thanks to [Matthew Wahner](https://github.com/mattwahner).

### <i class="fa-solid fa-bug-slash"></i> Fixes

- [788](https://github.com/nginx/kubernetes-ingress/pull/788): Fix VSR updates when namespace is set implicitly.
- [736](https://github.com/nginx/kubernetes-ingress/pull/736): Init Ingress labeled metrics on start.
- [686](https://github.com/nginx/kubernetes-ingress/pull/686): Check if config map created for leader-election.
- [664](https://github.com/nginx/kubernetes-ingress/pull/664): Fix reporting events for Ingress minions.
- [632](https://github.com/nginx/kubernetes-ingress/pull/632): Fix hsts support when not using SSL. Thanks to [Martín Fernández](https://github.com/bilby91).

### <i class="fa-solid fa-box"></i> Helm Chart

- Add new parameters to the Chart: `controller.healthCheckURI`, `controller.resources`, `controller.logLevel`, `controller.customPorts`, `controller.service.customPorts`. Added in [750](https://github.com/nginx/kubernetes-ingress/pull/750), [636](https://github.com/nginx/kubernetes-ingress/pull/636) thanks to [Guilherme Oki](https://github.com/guilhermeoki), [600](https://github.com/nginx/kubernetes-ingress/pull/600), [581](https://github.com/nginx/kubernetes-ingress/pull/581) thanks to [Alex Meijer](https://github.com/ameijer-corsha).
- [722](https://github.com/nginx/kubernetes-ingress/pull/722): Fix trailing leader election cm when using helm. This change might lead to a failed upgrade. See the helm upgrade instruction below.
- [573](https://github.com/nginx/kubernetes-ingress/pull/573): Use Controller name value for app selectors.

### <i class="fa-solid fa-upload"></i> Dependencies

- Update NGINX versions to 1.17.6.
- Update NGINX Plus version to R20.

### <i class="fa-solid fa-download"></i> Upgrade

- For NGINX, use the 1.6.0 image from our DockerHub: `nginx/nginx-ingress:1.6.0` or `nginx/nginx-ingress:1.6.0-alpine`
- For NGINX Plus, please build your own image using the 1.6.0 source code.
- For Helm, use version 0.4.0 of the chart.

#### Helm upgrade

If leader election (the `controller.reportIngressStatus.enableLeaderElection` parameter) is enabled, when upgrading to the new version of the Helm chart:

1. Make sure to specify a new ConfigMap lock name (`controller.reportIngressStatus.leaderElectionLockName`) different from the one that was created by the current version. To find out the current name, check ConfigMap resources in the namespace where the Ingress Controller is running.
1. After the upgrade, delete the old ConfigMap.

Otherwise, the helm upgrade will not succeed.

<hr>

## Previous Releases

To see the previous releases, see the [Releases page](https://github.com/nginx/kubernetes-ingress/releases) on the Ingress Controller GitHub repo.
