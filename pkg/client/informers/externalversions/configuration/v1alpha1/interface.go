// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/nginxinc/kubernetes-ingress/v3/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// GlobalConfigurations returns a GlobalConfigurationInformer.
	GlobalConfigurations() GlobalConfigurationInformer
	// Policies returns a PolicyInformer.
	Policies() PolicyInformer
	// TransportServers returns a TransportServerInformer.
	TransportServers() TransportServerInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// GlobalConfigurations returns a GlobalConfigurationInformer.
func (v *version) GlobalConfigurations() GlobalConfigurationInformer {
	return &globalConfigurationInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Policies returns a PolicyInformer.
func (v *version) Policies() PolicyInformer {
	return &policyInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// TransportServers returns a TransportServerInformer.
func (v *version) TransportServers() TransportServerInformer {
	return &transportServerInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
