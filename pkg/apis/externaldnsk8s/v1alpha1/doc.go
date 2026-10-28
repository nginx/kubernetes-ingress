// +k8s:deepcopy-gen=package
// +groupName=externaldns.k8s.io
// +groupGoName=ExternaldnsK8s

// Package v1alpha1 mirrors the upstream external-dns DNSEndpoint type
// (externaldns.k8s.io/v1alpha1). It is wire-compatible with
// github.com/kubernetes-sigs/external-dns/endpoint so that NIC can produce
// DNSEndpoint objects consumed by external-dns v0.21.0+.
package v1alpha1
