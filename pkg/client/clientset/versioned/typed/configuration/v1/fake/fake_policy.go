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

// FakePolicies implements PolicyInterface
type FakePolicies struct {
	Fake *FakeK8sV1
	ns   string
}

var policiesResource = v1.SchemeGroupVersion.WithResource("policies")

var policiesKind = v1.SchemeGroupVersion.WithKind("Policy")

// Get takes name of the policy, and returns the corresponding policy object, and an error if there is any.
func (c *FakePolicies) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.Policy, err error) {
	emptyResult := &v1.Policy{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(policiesResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Policy), err
}

// List takes label and field selectors, and returns the list of Policies that match those selectors.
func (c *FakePolicies) List(ctx context.Context, opts metav1.ListOptions) (result *v1.PolicyList, err error) {
	emptyResult := &v1.PolicyList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(policiesResource, policiesKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.PolicyList{ListMeta: obj.(*v1.PolicyList).ListMeta}
	for _, item := range obj.(*v1.PolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested policies.
func (c *FakePolicies) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(policiesResource, c.ns, opts))

}

// Create takes the representation of a policy and creates it.  Returns the server's representation of the policy, and an error, if there is any.
func (c *FakePolicies) Create(ctx context.Context, policy *v1.Policy, opts metav1.CreateOptions) (result *v1.Policy, err error) {
	emptyResult := &v1.Policy{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(policiesResource, c.ns, policy, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Policy), err
}

// Update takes the representation of a policy and updates it. Returns the server's representation of the policy, and an error, if there is any.
func (c *FakePolicies) Update(ctx context.Context, policy *v1.Policy, opts metav1.UpdateOptions) (result *v1.Policy, err error) {
	emptyResult := &v1.Policy{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(policiesResource, c.ns, policy, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Policy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakePolicies) UpdateStatus(ctx context.Context, policy *v1.Policy, opts metav1.UpdateOptions) (result *v1.Policy, err error) {
	emptyResult := &v1.Policy{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(policiesResource, "status", c.ns, policy, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Policy), err
}

// Delete takes name of the policy and deletes it. Returns an error if one occurs.
func (c *FakePolicies) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(policiesResource, c.ns, name, opts), &v1.Policy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakePolicies) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(policiesResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.PolicyList{})
	return err
}

// Patch applies the patch and returns the patched policy.
func (c *FakePolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Policy, err error) {
	emptyResult := &v1.Policy{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(policiesResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Policy), err
}
