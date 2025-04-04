---
docs: DOCS-616
---

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
