package externaldns

import (
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/discovery"
)

// dnsEndpointResource is the plural resource name of the DNSEndpoint CRD in
// both the legacy and upstream API groups.
const dnsEndpointResource = "dnsendpoints"

// Supported values for the --external-dns-group-version flag / Helm
// controller.externalDNSGroupVersion value. These control which DNSEndpoint
// API group NIC writes to.
const (
	// GroupVersionNginx is NIC's own external-dns compatible API group.
	// external-dns must be started with --crd-source-apiversion=externaldns.nginx.org/v1
	// (supported by external-dns <= v0.20.x).
	GroupVersionNginx = "externaldns.nginx.org/v1"

	// GroupVersionUpstream is the upstream external-dns API group that
	// external-dns v0.21.0+ hard-codes as the only accepted CRD source.
	GroupVersionUpstream = "externaldns.k8s.io/v1alpha1"
)

// SupportedGroupVersions returns the allowed values for the group-version flag.
func SupportedGroupVersions() []string {
	return []string{GroupVersionNginx, GroupVersionUpstream}
}

// IsSupportedGroupVersion reports whether the given value is a recognized group-version.
func IsSupportedGroupVersion(gv string) bool {
	for _, v := range SupportedGroupVersions() {
		if v == gv {
			return true
		}
	}
	return false
}

// CheckDNSEndpointCRD reports whether the DNSEndpoint CRD for groupVersion is
// installed and served by the API server. A non-nil error means either the
// group/version is not served at all, or it is served but does not expose the
// dnsendpoints resource.
//
// Without this check, a group/version whose CRD is missing fails silently:
// the DNSEndpoint informer never syncs and the ExternalDNS control loop
// stalls without creating or updating any DNSEndpoint.
func CheckDNSEndpointCRD(d discovery.DiscoveryInterface, groupVersion string) error {
	resources, err := d.ServerResourcesForGroupVersion(groupVersion)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("API group/version %q is not served by the cluster; install the DNSEndpoint CRD for it", groupVersion)
	}
	if err != nil {
		return fmt.Errorf("failed to check for the DNSEndpoint CRD in %q: %w", groupVersion, err)
	}
	for _, r := range resources.APIResources {
		if r.Name == dnsEndpointResource {
			return nil
		}
	}
	return fmt.Errorf("API group/version %q is served but does not expose the %q resource; install the DNSEndpoint CRD for it",
		groupVersion, dnsEndpointResource)
}
