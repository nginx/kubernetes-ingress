// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// GlobalConfigurationLister helps list GlobalConfigurations.
// All objects returned here must be treated as read-only.
type GlobalConfigurationLister interface {
	// List lists all GlobalConfigurations in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.GlobalConfiguration, err error)
	// GlobalConfigurations returns an object that can list and get GlobalConfigurations.
	GlobalConfigurations(namespace string) GlobalConfigurationNamespaceLister
	GlobalConfigurationListerExpansion
}

// globalConfigurationLister implements the GlobalConfigurationLister interface.
type globalConfigurationLister struct {
	listers.ResourceIndexer[*v1alpha1.GlobalConfiguration]
}

// NewGlobalConfigurationLister returns a new GlobalConfigurationLister.
func NewGlobalConfigurationLister(indexer cache.Indexer) GlobalConfigurationLister {
	return &globalConfigurationLister{listers.New[*v1alpha1.GlobalConfiguration](indexer, v1alpha1.Resource("globalconfiguration"))}
}

// GlobalConfigurations returns an object that can list and get GlobalConfigurations.
func (s *globalConfigurationLister) GlobalConfigurations(namespace string) GlobalConfigurationNamespaceLister {
	return globalConfigurationNamespaceLister{listers.NewNamespaced[*v1alpha1.GlobalConfiguration](s.ResourceIndexer, namespace)}
}

// GlobalConfigurationNamespaceLister helps list and get GlobalConfigurations.
// All objects returned here must be treated as read-only.
type GlobalConfigurationNamespaceLister interface {
	// List lists all GlobalConfigurations in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.GlobalConfiguration, err error)
	// Get retrieves the GlobalConfiguration from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.GlobalConfiguration, error)
	GlobalConfigurationNamespaceListerExpansion
}

// globalConfigurationNamespaceLister implements the GlobalConfigurationNamespaceLister
// interface.
type globalConfigurationNamespaceLister struct {
	listers.ResourceIndexer[*v1alpha1.GlobalConfiguration]
}
