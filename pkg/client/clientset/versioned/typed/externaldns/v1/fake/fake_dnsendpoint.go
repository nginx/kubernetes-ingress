// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/externaldns/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeDNSEndpoints implements DNSEndpointInterface
type FakeDNSEndpoints struct {
	Fake *FakeExternaldnsV1
	ns   string
}

var dnsendpointsResource = v1.SchemeGroupVersion.WithResource("dnsendpoints")

var dnsendpointsKind = v1.SchemeGroupVersion.WithKind("DNSEndpoint")

// Get takes name of the dNSEndpoint, and returns the corresponding dNSEndpoint object, and an error if there is any.
func (c *FakeDNSEndpoints) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.DNSEndpoint, err error) {
	emptyResult := &v1.DNSEndpoint{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(dnsendpointsResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.DNSEndpoint), err
}

// List takes label and field selectors, and returns the list of DNSEndpoints that match those selectors.
func (c *FakeDNSEndpoints) List(ctx context.Context, opts metav1.ListOptions) (result *v1.DNSEndpointList, err error) {
	emptyResult := &v1.DNSEndpointList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(dnsendpointsResource, dnsendpointsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.DNSEndpointList{ListMeta: obj.(*v1.DNSEndpointList).ListMeta}
	for _, item := range obj.(*v1.DNSEndpointList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested dNSEndpoints.
func (c *FakeDNSEndpoints) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(dnsendpointsResource, c.ns, opts))

}

// Create takes the representation of a dNSEndpoint and creates it.  Returns the server's representation of the dNSEndpoint, and an error, if there is any.
func (c *FakeDNSEndpoints) Create(ctx context.Context, dNSEndpoint *v1.DNSEndpoint, opts metav1.CreateOptions) (result *v1.DNSEndpoint, err error) {
	emptyResult := &v1.DNSEndpoint{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(dnsendpointsResource, c.ns, dNSEndpoint, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.DNSEndpoint), err
}

// Update takes the representation of a dNSEndpoint and updates it. Returns the server's representation of the dNSEndpoint, and an error, if there is any.
func (c *FakeDNSEndpoints) Update(ctx context.Context, dNSEndpoint *v1.DNSEndpoint, opts metav1.UpdateOptions) (result *v1.DNSEndpoint, err error) {
	emptyResult := &v1.DNSEndpoint{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(dnsendpointsResource, c.ns, dNSEndpoint, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.DNSEndpoint), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeDNSEndpoints) UpdateStatus(ctx context.Context, dNSEndpoint *v1.DNSEndpoint, opts metav1.UpdateOptions) (result *v1.DNSEndpoint, err error) {
	emptyResult := &v1.DNSEndpoint{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(dnsendpointsResource, "status", c.ns, dNSEndpoint, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.DNSEndpoint), err
}

// Delete takes name of the dNSEndpoint and deletes it. Returns an error if one occurs.
func (c *FakeDNSEndpoints) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(dnsendpointsResource, c.ns, name, opts), &v1.DNSEndpoint{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeDNSEndpoints) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(dnsendpointsResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.DNSEndpointList{})
	return err
}

// Patch applies the patch and returns the patched dNSEndpoint.
func (c *FakeDNSEndpoints) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.DNSEndpoint, err error) {
	emptyResult := &v1.DNSEndpoint{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(dnsendpointsResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.DNSEndpoint), err
}
