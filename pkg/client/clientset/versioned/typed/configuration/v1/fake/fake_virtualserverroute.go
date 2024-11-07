// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeVirtualServerRoutes implements VirtualServerRouteInterface
type FakeVirtualServerRoutes struct {
	Fake *FakeK8sV1
	ns   string
}

var virtualserverroutesResource = v1.SchemeGroupVersion.WithResource("virtualserverroutes")

var virtualserverroutesKind = v1.SchemeGroupVersion.WithKind("VirtualServerRoute")

// Get takes name of the virtualServerRoute, and returns the corresponding virtualServerRoute object, and an error if there is any.
func (c *FakeVirtualServerRoutes) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.VirtualServerRoute, err error) {
	emptyResult := &v1.VirtualServerRoute{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(virtualserverroutesResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.VirtualServerRoute), err
}

// List takes label and field selectors, and returns the list of VirtualServerRoutes that match those selectors.
func (c *FakeVirtualServerRoutes) List(ctx context.Context, opts metav1.ListOptions) (result *v1.VirtualServerRouteList, err error) {
	emptyResult := &v1.VirtualServerRouteList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(virtualserverroutesResource, virtualserverroutesKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.VirtualServerRouteList{ListMeta: obj.(*v1.VirtualServerRouteList).ListMeta}
	for _, item := range obj.(*v1.VirtualServerRouteList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested virtualServerRoutes.
func (c *FakeVirtualServerRoutes) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(virtualserverroutesResource, c.ns, opts))

}

// Create takes the representation of a virtualServerRoute and creates it.  Returns the server's representation of the virtualServerRoute, and an error, if there is any.
func (c *FakeVirtualServerRoutes) Create(ctx context.Context, virtualServerRoute *v1.VirtualServerRoute, opts metav1.CreateOptions) (result *v1.VirtualServerRoute, err error) {
	emptyResult := &v1.VirtualServerRoute{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(virtualserverroutesResource, c.ns, virtualServerRoute, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.VirtualServerRoute), err
}

// Update takes the representation of a virtualServerRoute and updates it. Returns the server's representation of the virtualServerRoute, and an error, if there is any.
func (c *FakeVirtualServerRoutes) Update(ctx context.Context, virtualServerRoute *v1.VirtualServerRoute, opts metav1.UpdateOptions) (result *v1.VirtualServerRoute, err error) {
	emptyResult := &v1.VirtualServerRoute{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(virtualserverroutesResource, c.ns, virtualServerRoute, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.VirtualServerRoute), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeVirtualServerRoutes) UpdateStatus(ctx context.Context, virtualServerRoute *v1.VirtualServerRoute, opts metav1.UpdateOptions) (result *v1.VirtualServerRoute, err error) {
	emptyResult := &v1.VirtualServerRoute{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(virtualserverroutesResource, "status", c.ns, virtualServerRoute, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.VirtualServerRoute), err
}

// Delete takes name of the virtualServerRoute and deletes it. Returns an error if one occurs.
func (c *FakeVirtualServerRoutes) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(virtualserverroutesResource, c.ns, name, opts), &v1.VirtualServerRoute{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeVirtualServerRoutes) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(virtualserverroutesResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.VirtualServerRouteList{})
	return err
}

// Patch applies the patch and returns the patched virtualServerRoute.
func (c *FakeVirtualServerRoutes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.VirtualServerRoute, err error) {
	emptyResult := &v1.VirtualServerRoute{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(virtualserverroutesResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.VirtualServerRoute), err
}
