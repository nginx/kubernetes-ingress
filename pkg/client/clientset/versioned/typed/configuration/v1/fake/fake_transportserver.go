// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeTransportServers implements TransportServerInterface
type FakeTransportServers struct {
	Fake *FakeK8sV1
	ns   string
}

var transportserversResource = v1.SchemeGroupVersion.WithResource("transportservers")

var transportserversKind = v1.SchemeGroupVersion.WithKind("TransportServer")

// Get takes name of the transportServer, and returns the corresponding transportServer object, and an error if there is any.
func (c *FakeTransportServers) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.TransportServer, err error) {
	emptyResult := &v1.TransportServer{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(transportserversResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.TransportServer), err
}

// List takes label and field selectors, and returns the list of TransportServers that match those selectors.
func (c *FakeTransportServers) List(ctx context.Context, opts metav1.ListOptions) (result *v1.TransportServerList, err error) {
	emptyResult := &v1.TransportServerList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(transportserversResource, transportserversKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.TransportServerList{ListMeta: obj.(*v1.TransportServerList).ListMeta}
	for _, item := range obj.(*v1.TransportServerList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested transportServers.
func (c *FakeTransportServers) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(transportserversResource, c.ns, opts))

}

// Create takes the representation of a transportServer and creates it.  Returns the server's representation of the transportServer, and an error, if there is any.
func (c *FakeTransportServers) Create(ctx context.Context, transportServer *v1.TransportServer, opts metav1.CreateOptions) (result *v1.TransportServer, err error) {
	emptyResult := &v1.TransportServer{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(transportserversResource, c.ns, transportServer, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.TransportServer), err
}

// Update takes the representation of a transportServer and updates it. Returns the server's representation of the transportServer, and an error, if there is any.
func (c *FakeTransportServers) Update(ctx context.Context, transportServer *v1.TransportServer, opts metav1.UpdateOptions) (result *v1.TransportServer, err error) {
	emptyResult := &v1.TransportServer{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(transportserversResource, c.ns, transportServer, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.TransportServer), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeTransportServers) UpdateStatus(ctx context.Context, transportServer *v1.TransportServer, opts metav1.UpdateOptions) (result *v1.TransportServer, err error) {
	emptyResult := &v1.TransportServer{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(transportserversResource, "status", c.ns, transportServer, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.TransportServer), err
}

// Delete takes name of the transportServer and deletes it. Returns an error if one occurs.
func (c *FakeTransportServers) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(transportserversResource, c.ns, name, opts), &v1.TransportServer{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeTransportServers) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(transportserversResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.TransportServerList{})
	return err
}

// Patch applies the patch and returns the patched transportServer.
func (c *FakeTransportServers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.TransportServer, err error) {
	emptyResult := &v1.TransportServer{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(transportserversResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.TransportServer), err
}
