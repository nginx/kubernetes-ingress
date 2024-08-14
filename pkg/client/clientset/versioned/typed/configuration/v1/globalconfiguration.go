// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	scheme "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// GlobalConfigurationsGetter has a method to return a GlobalConfigurationInterface.
// A group's client should implement this interface.
type GlobalConfigurationsGetter interface {
	GlobalConfigurations(namespace string) GlobalConfigurationInterface
}

// GlobalConfigurationInterface has methods to work with GlobalConfiguration resources.
type GlobalConfigurationInterface interface {
	Create(ctx context.Context, globalConfiguration *v1.GlobalConfiguration, opts metav1.CreateOptions) (*v1.GlobalConfiguration, error)
	Update(ctx context.Context, globalConfiguration *v1.GlobalConfiguration, opts metav1.UpdateOptions) (*v1.GlobalConfiguration, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.GlobalConfiguration, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.GlobalConfigurationList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.GlobalConfiguration, err error)
	GlobalConfigurationExpansion
}

// globalConfigurations implements GlobalConfigurationInterface
type globalConfigurations struct {
	*gentype.ClientWithList[*v1.GlobalConfiguration, *v1.GlobalConfigurationList]
}

// newGlobalConfigurations returns a GlobalConfigurations
func newGlobalConfigurations(c *K8sV1Client, namespace string) *globalConfigurations {
	return &globalConfigurations{
		gentype.NewClientWithList[*v1.GlobalConfiguration, *v1.GlobalConfigurationList](
			"globalconfigurations",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1.GlobalConfiguration { return &v1.GlobalConfiguration{} },
			func() *v1.GlobalConfigurationList { return &v1.GlobalConfigurationList{} }),
	}
}
