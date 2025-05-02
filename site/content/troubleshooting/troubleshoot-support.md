---
title: Commercial support
weight: 100
docs: DOCS-000
---

F5 NGINX Ingress Controller adheres to the support policy detailed in the following knowledge base article: [K000140156](https://my.f5.com/manage/s/article/K000140156).

After opening a support ticket, F5 staff will request additional information to better understand the problem.

The [nginx-supportpkg-for-k8s](https://github.com/nginxinc/nginx-supportpkg-for-k8s) plugin collects the information needed by F5 Technical Support to assist with troubleshooting your issue.

When used, the plugin will generate a tarball of the collected information which can be shared with the support channels.


The plugin uses [krew](https://krew.sigs.k8s.io), the plugin manager for the Kubernetes [kubectl](https://kubernetes.io/docs/reference/kubectl/) command-line tool.

The plugin may collect some or all of the following global and namespace-specific information:

* K8s version, nodes information, and Custom Resources (kubectl describe output)
* Pods' logs
* List of Pods, events, ConfigMaps, Services, Deployments, Daemonsets, StatefulSets, ReplicaSets, and Leases
* K8s metrics
* Helm deployments
* `nginx -T` output from NGINX-related pods

This plugin **does not** collect secrets or coredumps.

Visit the [project’s GitHub repository](https://github.com/nginxinc/nginx-supportpkg-for-k8s) for further details.


## Support channels

- If you experience issues with NGINX Ingress Controller, please [open an issue](https://github.com/nginx/kubernetes-ingress/issues/new?assignees=&labels=bug%2Cneeds+triage&projects=&template=BUG-REPORT.yml&title=%5BBug%5D%3A+) in GitHub.

- If you have any enhancement requests, please [open a feature request](https://github.com/nginx/kubernetes-ingress/issues/new?assignees=&labels=proposal&projects=&template=feature_request.md&title=) in GitHub.

- If you have any ideas or suggestions to discuss, please [open an idea discussion](https://github.com/nginx/kubernetes-ingress/discussions/categories/ideas) in GitHub.
