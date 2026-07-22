package externaldns

import (
	"context"

	extdnsapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1"
	extdnsk8sapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldnsk8s/v1alpha1"
	clientset "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
	k8s_nginx_informers "github.com/nginx/kubernetes-ingress/pkg/client/informers/externalversions"
	extdnslisters "github.com/nginx/kubernetes-ingress/pkg/client/listers/externaldns/v1"
	extdnsk8slisters "github.com/nginx/kubernetes-ingress/pkg/client/listers/externaldnsk8s/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// dnsEndpointBackend abstracts DNSEndpoint API access for a single
// namespaced informer. It hides the concrete API group (either
// externaldns.nginx.org/v1 or externaldns.k8s.io/v1alpha1) behind the
// canonical extdnsapi.DNSEndpoint type used internally by sync logic.
type dnsEndpointBackend interface {
	Get(namespace, name string) (*extdnsapi.DNSEndpoint, error)
	Create(ctx context.Context, ep *extdnsapi.DNSEndpoint) (*extdnsapi.DNSEndpoint, error)
	Update(ctx context.Context, ep *extdnsapi.DNSEndpoint) (*extdnsapi.DNSEndpoint, error)
}

// registerDNSEndpointInformer wires up the DNSEndpoint informer for the group
// selected by groupVersion and returns a backend that reads/writes through
// the matching typed client + lister. The returned HasSynced funcs must be
// added to the namespacedInformer's mustSync list.
func registerDNSEndpointInformer(
	groupVersion string,
	factory k8s_nginx_informers.SharedInformerFactory,
	client clientset.Interface,
	handler cache.ResourceEventHandler,
) (dnsEndpointBackend, []cache.InformerSynced, error) {
	switch groupVersion {
	case GroupVersionUpstream:
		informer := factory.ExternaldnsK8s().V1alpha1().DNSEndpoints()
		if _, err := informer.Informer().AddEventHandler(handler); err != nil {
			return nil, nil, err
		}
		return &upstreamBackend{
			client: client,
			lister: informer.Lister(),
		}, []cache.InformerSynced{informer.Informer().HasSynced}, nil
	default:
		informer := factory.Externaldns().V1().DNSEndpoints()
		if _, err := informer.Informer().AddEventHandler(handler); err != nil {
			return nil, nil, err
		}
		return &nginxBackend{
			client: client,
			lister: informer.Lister(),
		}, []cache.InformerSynced{informer.Informer().HasSynced}, nil
	}
}

// nginxBackend implements dnsEndpointBackend against externaldns.nginx.org/v1.
type nginxBackend struct {
	client clientset.Interface
	lister extdnslisters.DNSEndpointLister
}

func (b *nginxBackend) Get(namespace, name string) (*extdnsapi.DNSEndpoint, error) {
	return b.lister.DNSEndpoints(namespace).Get(name)
}

func (b *nginxBackend) Create(ctx context.Context, ep *extdnsapi.DNSEndpoint) (*extdnsapi.DNSEndpoint, error) {
	return b.client.ExternaldnsV1().DNSEndpoints(ep.Namespace).Create(ctx, ep, metav1.CreateOptions{})
}

func (b *nginxBackend) Update(ctx context.Context, ep *extdnsapi.DNSEndpoint) (*extdnsapi.DNSEndpoint, error) {
	return b.client.ExternaldnsV1().DNSEndpoints(ep.Namespace).Update(ctx, ep, metav1.UpdateOptions{})
}

// upstreamBackend implements dnsEndpointBackend against externaldns.k8s.io/v1alpha1.
// v1 and v1alpha1 structs are wire-compatible; we convert at the boundary.
type upstreamBackend struct {
	client clientset.Interface
	lister extdnsk8slisters.DNSEndpointLister
}

func (b *upstreamBackend) Get(namespace, name string) (*extdnsapi.DNSEndpoint, error) {
	out, err := b.lister.DNSEndpoints(namespace).Get(name)
	if err != nil {
		return nil, err
	}
	return fromUpstream(out), nil
}

func (b *upstreamBackend) Create(ctx context.Context, ep *extdnsapi.DNSEndpoint) (*extdnsapi.DNSEndpoint, error) {
	out, err := b.client.ExternaldnsK8sV1alpha1().DNSEndpoints(ep.Namespace).Create(ctx, toUpstream(ep), metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUpstream(out), nil
}

func (b *upstreamBackend) Update(ctx context.Context, ep *extdnsapi.DNSEndpoint) (*extdnsapi.DNSEndpoint, error) {
	out, err := b.client.ExternaldnsK8sV1alpha1().DNSEndpoints(ep.Namespace).Update(ctx, toUpstream(ep), metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUpstream(out), nil
}

// toUpstream converts the canonical extdnsapi.DNSEndpoint (externaldns.nginx.org/v1)
// to the upstream extdnsk8sapi.DNSEndpoint (externaldns.k8s.io/v1alpha1).
func toUpstream(in *extdnsapi.DNSEndpoint) *extdnsk8sapi.DNSEndpoint {
	if in == nil {
		return nil
	}
	endpoints := make([]*extdnsk8sapi.Endpoint, 0, len(in.Spec.Endpoints))
	for _, e := range in.Spec.Endpoints {
		if e == nil {
			continue
		}
		endpoints = append(endpoints, &extdnsk8sapi.Endpoint{
			DNSName:          e.DNSName,
			Targets:          extdnsk8sapi.Targets(append([]string(nil), e.Targets...)),
			RecordType:       e.RecordType,
			RecordTTL:        extdnsk8sapi.TTL(e.RecordTTL),
			Labels:           extdnsk8sapi.Labels(copyStringMap(e.Labels)),
			ProviderSpecific: toUpstreamProviderSpecific(e.ProviderSpecific),
		})
	}
	return &extdnsk8sapi.DNSEndpoint{
		ObjectMeta: *in.ObjectMeta.DeepCopy(),
		Spec:       extdnsk8sapi.DNSEndpointSpec{Endpoints: endpoints},
		Status:     extdnsk8sapi.DNSEndpointStatus{ObservedGeneration: in.Status.ObservedGeneration},
	}
}

// fromUpstream is the inverse of toUpstream.
func fromUpstream(in *extdnsk8sapi.DNSEndpoint) *extdnsapi.DNSEndpoint {
	if in == nil {
		return nil
	}
	endpoints := make([]*extdnsapi.Endpoint, 0, len(in.Spec.Endpoints))
	for _, e := range in.Spec.Endpoints {
		if e == nil {
			continue
		}
		endpoints = append(endpoints, &extdnsapi.Endpoint{
			DNSName:          e.DNSName,
			Targets:          extdnsapi.Targets(append([]string(nil), e.Targets...)),
			RecordType:       e.RecordType,
			RecordTTL:        extdnsapi.TTL(e.RecordTTL),
			Labels:           extdnsapi.Labels(copyStringMap(e.Labels)),
			ProviderSpecific: fromUpstreamProviderSpecific(e.ProviderSpecific),
		})
	}
	return &extdnsapi.DNSEndpoint{
		ObjectMeta: *in.ObjectMeta.DeepCopy(),
		Spec:       extdnsapi.DNSEndpointSpec{Endpoints: endpoints},
		Status:     extdnsapi.DNSEndpointStatus{ObservedGeneration: in.Status.ObservedGeneration},
	}
}

func toUpstreamProviderSpecific(in extdnsapi.ProviderSpecific) extdnsk8sapi.ProviderSpecific {
	if in == nil {
		return nil
	}
	out := make(extdnsk8sapi.ProviderSpecific, len(in))
	for i, p := range in {
		out[i] = extdnsk8sapi.ProviderSpecificProperty{Name: p.Name, Value: p.Value}
	}
	return out
}

func fromUpstreamProviderSpecific(in extdnsk8sapi.ProviderSpecific) extdnsapi.ProviderSpecific {
	if in == nil {
		return nil
	}
	out := make(extdnsapi.ProviderSpecific, len(in))
	for i, p := range in {
		out[i] = extdnsapi.ProviderSpecificProperty{Name: p.Name, Value: p.Value}
	}
	return out
}

func copyStringMap[M ~map[string]string](m M) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// keyFromDNSEndpoint returns the workqueue key for a DNSEndpoint of either
// supported API group, or ("", false) if the object is not a recognized
// DNSEndpoint kind.
func keyFromDNSEndpoint(obj interface{}) (metav1.Object, bool) {
	switch e := obj.(type) {
	case *extdnsapi.DNSEndpoint:
		return e, true
	case *extdnsk8sapi.DNSEndpoint:
		return e, true
	default:
		return nil, false
	}
}
