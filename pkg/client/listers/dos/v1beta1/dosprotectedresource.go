// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/dos/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// DosProtectedResourceLister helps list DosProtectedResources.
// All objects returned here must be treated as read-only.
type DosProtectedResourceLister interface {
	// List lists all DosProtectedResources in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.DosProtectedResource, err error)
	// DosProtectedResources returns an object that can list and get DosProtectedResources.
	DosProtectedResources(namespace string) DosProtectedResourceNamespaceLister
	DosProtectedResourceListerExpansion
}

// dosProtectedResourceLister implements the DosProtectedResourceLister interface.
type dosProtectedResourceLister struct {
	listers.ResourceIndexer[*v1beta1.DosProtectedResource]
}

// NewDosProtectedResourceLister returns a new DosProtectedResourceLister.
func NewDosProtectedResourceLister(indexer cache.Indexer) DosProtectedResourceLister {
	return &dosProtectedResourceLister{listers.New[*v1beta1.DosProtectedResource](indexer, v1beta1.Resource("dosprotectedresource"))}
}

// DosProtectedResources returns an object that can list and get DosProtectedResources.
func (s *dosProtectedResourceLister) DosProtectedResources(namespace string) DosProtectedResourceNamespaceLister {
	return dosProtectedResourceNamespaceLister{listers.NewNamespaced[*v1beta1.DosProtectedResource](s.ResourceIndexer, namespace)}
}

// DosProtectedResourceNamespaceLister helps list and get DosProtectedResources.
// All objects returned here must be treated as read-only.
type DosProtectedResourceNamespaceLister interface {
	// List lists all DosProtectedResources in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.DosProtectedResource, err error)
	// Get retrieves the DosProtectedResource from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.DosProtectedResource, error)
	DosProtectedResourceNamespaceListerExpansion
}

// dosProtectedResourceNamespaceLister implements the DosProtectedResourceNamespaceLister
// interface.
type dosProtectedResourceNamespaceLister struct {
	listers.ResourceIndexer[*v1beta1.DosProtectedResource]
}
