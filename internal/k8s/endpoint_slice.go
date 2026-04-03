package k8s

import (
	"reflect"

	discovery_v1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"

	configs "github.com/nginx/kubernetes-ingress/internal/configs"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// createEndpointSliceHandlers builds the handler funcs for EndpointSlices
func createEndpointSliceHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			endpointSlice := obj.(*discovery_v1.EndpointSlice)
			nl.Debugf(lbc.Logger, "Adding EndpointSlice: %v", endpointSlice.Name)
			lbc.AddSyncQueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			endpointSlice, isEndpointSlice := obj.(*discovery_v1.EndpointSlice)
			if !isEndpointSlice {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				endpointSlice, ok = deletedState.Obj.(*discovery_v1.EndpointSlice)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-EndpointSlice object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing EndpointSlice: %v", endpointSlice.Name)
			lbc.AddSyncQueue(obj)
		}, UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				nl.Debugf(lbc.Logger, "EndpointSlice %v changed, syncing", cur.(*discovery_v1.EndpointSlice).Name)
				lbc.AddSyncQueue(cur)
			}
		},
	}
}

// addEndpointSliceHandler adds the handler for EndpointSlices to the controller
func (nsi *namespacedInformer) addEndpointSliceHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.sharedInformerFactory.Discovery().V1().EndpointSlices().Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	var el storeToEndpointSliceLister
	el.Store = informer.GetStore()
	nsi.endpointSliceLister = el

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// nolint:gocyclo
func (lbc *LoadBalancerController) syncEndpointSlices(task task) bool {
	key := task.Key
	var obj interface{}
	var endpointSliceExists bool
	var err error
	var resourcesFound bool

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, endpointSliceExists, err = lbc.getNamespacedInformer(ns).endpointSliceLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return false
	}

	if !endpointSliceExists {
		return false
	}

	endpointSlice := obj.(*discovery_v1.EndpointSlice)
	svcName := endpointSlice.Labels["kubernetes.io/service-name"]
	svcResource := lbc.configuration.FindResourcesForService(endpointSlice.Namespace, svcName)

	// check if this is the endpointslice for the controller's own service
	if lbc.statusUpdater.namespace == endpointSlice.Namespace && lbc.statusUpdater.externalServiceName == svcName {
		return lbc.updateNumberOfIngressControllerReplicas(*endpointSlice)
	}

	resourceExes := lbc.createExtendedResources(svcResource)

	if len(resourceExes.IngressExes) > 0 {
		for _, ingEx := range resourceExes.IngressExes {
			if lbc.ingressRequiresEndpointsUpdate(ingEx, svcName) {
				resourcesFound = true
				nl.Debugf(lbc.Logger, "Updating EndpointSlices for %v", resourceExes.IngressExes)
				cfgWarnings, err := lbc.configurator.UpdateEndpoints(resourceExes.IngressExes)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error updating EndpointSlices for %v: %v", resourceExes.IngressExes, err)
				}
				lbc.updateEndpointSliceWarningState(svcResource, resourceExes, cfgWarnings)
				break
			}
		}
	}

	if len(resourceExes.MergeableIngresses) > 0 {
		for _, mergeableIngresses := range resourceExes.MergeableIngresses {
			if lbc.mergeableIngressRequiresEndpointsUpdate(mergeableIngresses, svcName) {
				resourcesFound = true
				nl.Debugf(lbc.Logger, "Updating EndpointSlices for %v", resourceExes.MergeableIngresses)
				cfgWarnings, err := lbc.configurator.UpdateEndpointsMergeableIngress(resourceExes.MergeableIngresses)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error updating EndpointSlices for %v: %v", resourceExes.MergeableIngresses, err)
				}
				lbc.updateEndpointSliceWarningState(svcResource, resourceExes, cfgWarnings)
				break
			}
		}
	}

	if lbc.areCustomResourcesEnabled {
		if len(resourceExes.VirtualServerExes) > 0 {
			for _, vsEx := range resourceExes.VirtualServerExes {
				if lbc.virtualServerRequiresEndpointsUpdate(vsEx, svcName) {
					resourcesFound = true
					nl.Debugf(lbc.Logger, "Updating EndpointSlices for %v", resourceExes.VirtualServerExes)
					err := lbc.configurator.UpdateEndpointsForVirtualServers(resourceExes.VirtualServerExes)
					if err != nil {
						nl.Errorf(lbc.Logger, "Error updating EndpointSlices for %v: %v", resourceExes.VirtualServerExes, err)
					}
					break
				}
			}
		}

		if len(resourceExes.TransportServerExes) > 0 {
			resourcesFound = true
			nl.Debugf(lbc.Logger, "Updating EndpointSlices for %v", resourceExes.TransportServerExes)
			err := lbc.configurator.UpdateEndpointsForTransportServers(resourceExes.TransportServerExes)
			if err != nil {
				nl.Errorf(lbc.Logger, "Error updating EndpointSlices for %v: %v", resourceExes.TransportServerExes, err)
			}
		}
	}
	return resourcesFound
}

// updateResourceStatusOnEndpointSliceChangeWithWarnings updates the status and events for
// resources affected by an EndpointSlice change. It delegates to the general
// updateResourcesStatusAndEvents which correctly sets Warning state when warnings exist
// and resets to Valid when they don't, ensuring resources recover from Warning state
// when the underlying issue (e.g. missing endpoints) resolves.
// Configuration warnings from the config generation step already include "no endpoints"
// warnings for services without endpoints (generated by generateEndpointsForUpstream),
// so no additional endpoint checks are needed here.
func (lbc *LoadBalancerController) updateResourceStatusOnEndpointSliceChangeWithWarnings(
	svcResources []Resource,
	resourceExes configs.ExtendedResources,
	cfgWarnings configs.Warnings,
) {
	resourcesWithWarnings := mergeExtendedResourceWarnings(svcResources, resourceExes)

	for _, r := range resourcesWithWarnings {
		lbc.updateResourcesStatusAndEvents([]Resource{r}, cfgWarnings, nil)
	}
}

// updateEndpointSliceWarningState calls updateResourceStatusOnEndpointSliceChangeWithWarnings
// only when the warning state for any affected resource transitions — either clean→warning
// or warning→clean. This avoids emitting spurious status events on every endpoint update
// (e.g. during a normal pod scale-up) while still correctly signaling when external auth
// endpoints disappear or recover.
func (lbc *LoadBalancerController) updateEndpointSliceWarningState(
	svcResources []Resource,
	resourceExes configs.ExtendedResources,
	cfgWarnings configs.Warnings,
) {
	hasWarnings := len(cfgWarnings) > 0

	hadWarnings := false
	for _, r := range svcResources {
		if lbc.endpointSliceWarnings[r.GetKeyWithKind()] {
			hadWarnings = true
			break
		}
	}

	// Only update status on a transition: clean→warning or warning→clean.
	if !hasWarnings && !hadWarnings {
		return
	}

	lbc.updateResourceStatusOnEndpointSliceChangeWithWarnings(svcResources, resourceExes, cfgWarnings)

	// Update the tracking map to reflect the new state.
	for _, r := range svcResources {
		key := r.GetKeyWithKind()
		if hasWarnings {
			lbc.endpointSliceWarnings[key] = true
		} else {
			delete(lbc.endpointSliceWarnings, key)
		}
	}
}
