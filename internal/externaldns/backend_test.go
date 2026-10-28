package externaldns

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/nsregistry"
	vsapi "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	extdnsapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1"
	extdnsk8sapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldnsk8s/v1alpha1"
	"github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	conf_scheme "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/scheme"
	extdnsk8slisters "github.com/nginx/kubernetes-ingress/pkg/client/listers/externaldnsk8s/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
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

// TestSyncFn_UpstreamBackend drives SyncFnFor through the upstream backend
// (externaldns.k8s.io/v1alpha1) with a fake clientset: a create, then an update
// of the object it created. Nothing may be written to externaldns.nginx.org/v1.
func TestSyncFn_UpstreamBackend(t *testing.T) {
	t.Parallel()

	const ns, name = "default", "cafe"
	ctx := context.Background()

	client := fake.NewSimpleClientset()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	nsi := &namespacedInformer{backend: &upstreamBackend{
		client: client,
		lister: extdnsk8slisters.NewDNSEndpointLister(indexer),
	}}
	ig := nsregistry.New[namespacedInformer]()
	ig.Set(ns, nsi)
	fn := SyncFnFor(EventRecorder{}, ig)

	vs := &vsapi.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: "f1448443-2549-4a0d-aab3-a3aeee09f784"},
		Spec: vsapi.VirtualServerSpec{
			Host: "cafe.example.com",
			ExternalDNS: vsapi.ExternalDNS{
				Enable:           true,
				RecordTTL:        60,
				Labels:           map[string]string{"team": "a"},
				ProviderSpecific: []vsapi.ProviderSpecificProperty{{Name: "aws/weight", Value: "10"}},
			},
		},
		Status: vsapi.VirtualServerStatus{
			ExternalEndpoints: []vsapi.ExternalEndpoint{{IP: "10.10.10.20"}},
		},
	}

	assertUpstream := func(t *testing.T, ip string, ttl int64) *extdnsk8sapi.DNSEndpoint {
		t.Helper()
		got, err := client.ExternaldnsK8sV1alpha1().DNSEndpoints(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("upstream DNSEndpoint not found: %v", err)
		}
		want := []*extdnsk8sapi.Endpoint{{
			DNSName:          "cafe.example.com",
			Targets:          extdnsk8sapi.Targets{ip},
			RecordType:       "A",
			RecordTTL:        extdnsk8sapi.TTL(ttl),
			Labels:           extdnsk8sapi.Labels{"team": "a"},
			ProviderSpecific: extdnsk8sapi.ProviderSpecific{{Name: "aws/weight", Value: "10"}},
		}}
		if diff := cmp.Diff(want, got.Spec.Endpoints); diff != "" {
			t.Errorf("endpoints mismatch (-want +got):\n%s", diff)
		}
		ref := metav1.GetControllerOf(got)
		if ref == nil || ref.Kind != "VirtualServer" || ref.Name != name || ref.UID != vs.UID {
			t.Errorf("controller owner reference = %+v, want VirtualServer %s/%s", ref, name, vs.UID)
		}
		if _, err := client.ExternaldnsV1().DNSEndpoints(ns).Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("externaldns.nginx.org/v1 Get error = %v, want NotFound", err)
		}
		return got
	}

	if err := fn(ctx, vs); err != nil {
		t.Fatalf("create sync: %v", err)
	}
	created := assertUpstream(t, "10.10.10.20", 60)

	// Make the lister see the object, as the informer would.
	if err := indexer.Add(created); err != nil {
		t.Fatal(err)
	}

	vs.Status.ExternalEndpoints = []vsapi.ExternalEndpoint{{IP: "10.10.10.30"}}
	vs.Spec.ExternalDNS.RecordTTL = 120
	if err := fn(ctx, vs); err != nil {
		t.Fatalf("update sync: %v", err)
	}
	updated := assertUpstream(t, "10.10.10.30", 120)
	if updated.Name != created.Name || updated.Namespace != created.Namespace {
		t.Errorf("update changed identity to %s/%s", updated.Namespace, updated.Name)
	}
}
