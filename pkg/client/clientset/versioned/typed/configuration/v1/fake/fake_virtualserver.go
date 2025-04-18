// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	configurationv1 "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/typed/configuration/v1"
	gentype "k8s.io/client-go/gentype"
)

// fakeVirtualServers implements VirtualServerInterface
type fakeVirtualServers struct {
	*gentype.FakeClientWithList[*v1.VirtualServer, *v1.VirtualServerList]
	Fake *FakeK8sV1
}

func newFakeVirtualServers(fake *FakeK8sV1, namespace string) configurationv1.VirtualServerInterface {
	return &fakeVirtualServers{
		gentype.NewFakeClientWithList[*v1.VirtualServer, *v1.VirtualServerList](
			fake.Fake,
			namespace,
			v1.SchemeGroupVersion.WithResource("virtualservers"),
			v1.SchemeGroupVersion.WithKind("VirtualServer"),
			func() *v1.VirtualServer { return &v1.VirtualServer{} },
			func() *v1.VirtualServerList { return &v1.VirtualServerList{} },
			func(dst, src *v1.VirtualServerList) { dst.ListMeta = src.ListMeta },
			func(list *v1.VirtualServerList) []*v1.VirtualServer { return gentype.ToPointerSlice(list.Items) },
			func(list *v1.VirtualServerList, items []*v1.VirtualServer) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
