// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	context "context"

	configurationv1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	scheme "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// VirtualServersGetter has a method to return a VirtualServerInterface.
// A group's client should implement this interface.
type VirtualServersGetter interface {
	VirtualServers(namespace string) VirtualServerInterface
}

// VirtualServerInterface has methods to work with VirtualServer resources.
type VirtualServerInterface interface {
	Create(ctx context.Context, virtualServer *configurationv1.VirtualServer, opts metav1.CreateOptions) (*configurationv1.VirtualServer, error)
	Update(ctx context.Context, virtualServer *configurationv1.VirtualServer, opts metav1.UpdateOptions) (*configurationv1.VirtualServer, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, virtualServer *configurationv1.VirtualServer, opts metav1.UpdateOptions) (*configurationv1.VirtualServer, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*configurationv1.VirtualServer, error)
	List(ctx context.Context, opts metav1.ListOptions) (*configurationv1.VirtualServerList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *configurationv1.VirtualServer, err error)
	VirtualServerExpansion
}

// virtualServers implements VirtualServerInterface
type virtualServers struct {
	*gentype.ClientWithList[*configurationv1.VirtualServer, *configurationv1.VirtualServerList]
}

// newVirtualServers returns a VirtualServers
func newVirtualServers(c *K8sV1Client, namespace string) *virtualServers {
	return &virtualServers{
		gentype.NewClientWithList[*configurationv1.VirtualServer, *configurationv1.VirtualServerList](
			"virtualservers",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *configurationv1.VirtualServer { return &configurationv1.VirtualServer{} },
			func() *configurationv1.VirtualServerList { return &configurationv1.VirtualServerList{} },
		),
	}
}
