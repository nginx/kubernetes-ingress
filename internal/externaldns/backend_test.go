package externaldns

import (
	"testing"

	extdnsapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1"
	extdnsk8sapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldnsk8s/v1alpha1"
	conf_scheme "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/reference"
)

// TestDNSEndpointEventReferenceAPIVersion guards the API group reported in
// Events emitted for a DNSEndpoint.
//
// record.EventRecorder builds its ObjectReference with reference.GetReference,
// which reads the object's own TypeMeta and only falls back to the runtime
// scheme when that is empty. Both backends hand the reconciler the canonical
// *extdnsapi.DNSEndpoint type, which the scheme maps to
// externaldns.nginx.org/v1 — so without explicit TypeMeta an Event for an
// object living in externaldns.k8s.io/v1alpha1 would claim the legacy group.
func TestDNSEndpointEventReferenceAPIVersion(t *testing.T) {
	t.Parallel()

	meta := metav1.ObjectMeta{
		Name:      "cafe",
		Namespace: "default",
		UID:       "f1448443-2549-4a0d-aab3-a3aeee09f784",
	}

	tests := []struct {
		name string
		obj  *extdnsapi.DNSEndpoint
		want string
	}{
		{
			name: "upstream backend result reports the upstream group",
			obj:  fromUpstream(&extdnsk8sapi.DNSEndpoint{ObjectMeta: meta}),
			want: GroupVersionUpstream,
		},
		{
			name: "legacy backend result reports the nginx group",
			obj:  &extdnsapi.DNSEndpoint{ObjectMeta: meta},
			want: GroupVersionNginx,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := runtime.NewScheme()
			if err := conf_scheme.AddToScheme(s); err != nil {
				t.Fatalf("failed to build scheme: %v", err)
			}

			ref, err := reference.GetReference(s, tc.obj)
			if err != nil {
				t.Fatalf("GetReference() error = %v", err)
			}
			if ref.APIVersion != tc.want {
				t.Errorf("APIVersion = %q, want %q", ref.APIVersion, tc.want)
			}
			if ref.Kind != dnsEndpointKind {
				t.Errorf("Kind = %q, want %q", ref.Kind, dnsEndpointKind)
			}
			if ref.Name != meta.Name || ref.Namespace != meta.Namespace || ref.UID != meta.UID {
				t.Errorf("reference identity = %s/%s (%s), want %s/%s (%s)",
					ref.Namespace, ref.Name, ref.UID, meta.Namespace, meta.Name, meta.UID)
			}
		})
	}
}

// TestToUpstreamOmitsTypeMeta pins the wire-side behavior that makes the
// TypeMeta set by fromUpstream safe: an object read back through the upstream
// backend and then passed to Update must not carry the canonical type's
// TypeMeta into the request body, where it would contradict the typed client's
// own group/version.
func TestToUpstreamOmitsTypeMeta(t *testing.T) {
	t.Parallel()

	roundTripped := toUpstream(fromUpstream(&extdnsk8sapi.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cafe", Namespace: "default"},
	}))

	if got := roundTripped.TypeMeta; got != (metav1.TypeMeta{}) {
		t.Errorf("TypeMeta = %+v, want empty so the typed client sets it", got)
	}
}
