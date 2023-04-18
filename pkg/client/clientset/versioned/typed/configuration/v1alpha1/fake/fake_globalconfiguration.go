// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeGlobalConfigurations implements GlobalConfigurationInterface
type FakeGlobalConfigurations struct {
	Fake *FakeK8sV1alpha1
	ns   string
}

var globalconfigurationsResource = v1alpha1.SchemeGroupVersion.WithResource("globalconfigurations")

var globalconfigurationsKind = v1alpha1.SchemeGroupVersion.WithKind("GlobalConfiguration")

// Get takes name of the globalConfiguration, and returns the corresponding globalConfiguration object, and an error if there is any.
func (c *FakeGlobalConfigurations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.GlobalConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(globalconfigurationsResource, c.ns, name), &v1alpha1.GlobalConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.GlobalConfiguration), err
}

// List takes label and field selectors, and returns the list of GlobalConfigurations that match those selectors.
func (c *FakeGlobalConfigurations) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.GlobalConfigurationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(globalconfigurationsResource, globalconfigurationsKind, c.ns, opts), &v1alpha1.GlobalConfigurationList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.GlobalConfigurationList{ListMeta: obj.(*v1alpha1.GlobalConfigurationList).ListMeta}
	for _, item := range obj.(*v1alpha1.GlobalConfigurationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested globalConfigurations.
func (c *FakeGlobalConfigurations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(globalconfigurationsResource, c.ns, opts))

}

// Create takes the representation of a globalConfiguration and creates it.  Returns the server's representation of the globalConfiguration, and an error, if there is any.
func (c *FakeGlobalConfigurations) Create(ctx context.Context, globalConfiguration *v1alpha1.GlobalConfiguration, opts v1.CreateOptions) (result *v1alpha1.GlobalConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(globalconfigurationsResource, c.ns, globalConfiguration), &v1alpha1.GlobalConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.GlobalConfiguration), err
}

// Update takes the representation of a globalConfiguration and updates it. Returns the server's representation of the globalConfiguration, and an error, if there is any.
func (c *FakeGlobalConfigurations) Update(ctx context.Context, globalConfiguration *v1alpha1.GlobalConfiguration, opts v1.UpdateOptions) (result *v1alpha1.GlobalConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(globalconfigurationsResource, c.ns, globalConfiguration), &v1alpha1.GlobalConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.GlobalConfiguration), err
}

// Delete takes name of the globalConfiguration and deletes it. Returns an error if one occurs.
func (c *FakeGlobalConfigurations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(globalconfigurationsResource, c.ns, name, opts), &v1alpha1.GlobalConfiguration{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeGlobalConfigurations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(globalconfigurationsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.GlobalConfigurationList{})
	return err
}

// Patch applies the patch and returns the patched globalConfiguration.
func (c *FakeGlobalConfigurations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.GlobalConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(globalconfigurationsResource, c.ns, name, pt, data, subresources...), &v1alpha1.GlobalConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.GlobalConfiguration), err
}
