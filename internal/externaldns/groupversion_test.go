package externaldns

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

// TestIsSupportedGroupVersion guards the -external-dns-group-version allowlist.
// It exercises IsSupportedGroupVersion directly rather than mustValidateFlags,
// which calls the fatal logger path.
func TestIsSupportedGroupVersion(t *testing.T) {
	t.Parallel()

	// Every value SupportedGroupVersions returns must itself be accepted, so
	// the two lists cannot drift apart.
	supported := SupportedGroupVersions()
	if len(supported) == 0 {
		t.Fatal("SupportedGroupVersions() returned no values")
	}
	for _, gv := range supported {
		if !IsSupportedGroupVersion(gv) {
			t.Errorf("IsSupportedGroupVersion(%q) = false, want true (returned by SupportedGroupVersions)", gv)
		}
	}

	invalid := []string{
		"",
		"v1",
		"externaldns.k8s.io",
		// external-dns has not promoted the upstream CRD to v1beta1 yet; this
		// is deliberately rejected until it is a real, tested backend.
		"externaldns.k8s.io/v1beta1",
		"EXTERNALDNS.K8S.IO/v1alpha1",
		"externaldns.k8s.io/v1alpha1 ",
		"externaldns.nginx.org/v1/extra",
		"externaldns.nginx.org",
	}
	for _, gv := range invalid {
		if IsSupportedGroupVersion(gv) {
			t.Errorf("IsSupportedGroupVersion(%q) = true, want false", gv)
		}
	}
}

func TestCheckDNSEndpointCRD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		groupVersion string
		resources    []*metav1.APIResourceList
		wantErr      bool
	}{
		{
			name:         "CRD present",
			groupVersion: GroupVersionNginx,
			resources: []*metav1.APIResourceList{
				{
					GroupVersion: GroupVersionNginx,
					APIResources: []metav1.APIResource{{Name: dnsEndpointResource}},
				},
			},
			wantErr: false,
		},
		{
			name:         "group/version served but dnsendpoints resource missing",
			groupVersion: GroupVersionUpstream,
			resources: []*metav1.APIResourceList{
				{
					GroupVersion: GroupVersionUpstream,
					APIResources: []metav1.APIResource{{Name: "somethingelse"}},
				},
			},
			wantErr: true,
		},
		{
			name:         "group/version not served at all",
			groupVersion: GroupVersionUpstream,
			resources:    nil,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &fake.FakeDiscovery{
				Fake: &clienttesting.Fake{Resources: tc.resources},
			}

			err := CheckDNSEndpointCRD(d, tc.groupVersion)
			if (err != nil) != tc.wantErr {
				t.Errorf("CheckDNSEndpointCRD(%q) error = %v, wantErr %v", tc.groupVersion, err, tc.wantErr)
			}
		})
	}
}
