package externaldns

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
