package k8s

import (
	"fmt"
	"reflect"

	configs "github.com/nginx/kubernetes-ingress/internal/configs"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	discovery_v1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"
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
				err = lbc.configurator.UpdateEndpoints(resourceExes.IngressExes)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error updating EndpointSlices for %v: %v", resourceExes.IngressExes, err)
				}
				lbc.updateResourceStatusOnEndpointSliceChange(svcResource, endpointSlice, svcName)
				break
			}
		}
	}

	if len(resourceExes.MergeableIngresses) > 0 {
		for _, mergeableIngresses := range resourceExes.MergeableIngresses {
			if lbc.mergeableIngressRequiresEndpointsUpdate(mergeableIngresses, svcName) {
				resourcesFound = true
				nl.Debugf(lbc.Logger, "Updating EndpointSlices for %v", resourceExes.MergeableIngresses)
				err = lbc.configurator.UpdateEndpointsMergeableIngress(resourceExes.MergeableIngresses)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error updating EndpointSlices for %v: %v", resourceExes.MergeableIngresses, err)
				}
				lbc.updateResourceStatusOnEndpointSliceChange(svcResource, endpointSlice, svcName)
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
					lbc.updateResourceStatusOnEndpointSliceChange(svcResource, endpointSlice, svcName)
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

// updateResourceStatusOnEndpointSliceChange updates the status and events for resources
// affected by an EndpointSlice change. If the EndpointSlice has no endpoints, warnings
// are generated only for the specific resources that reference the service.
func (lbc *LoadBalancerController) updateResourceStatusOnEndpointSliceChange(
	svcResources []Resource,
	endpointSlice *discovery_v1.EndpointSlice,
	svcName string,
) {
	hasEndpoints := len(endpointSlice.Endpoints) > 0

	for _, r := range svcResources {
		var warnings configs.Warnings
		if !hasEndpoints {
			warnings = lbc.buildNoEndpointWarnings(r, endpointSlice.Namespace, svcName)
		}
		lbc.updateResourcesStatusAndEvents([]Resource{r}, warnings, nil)
	}
}

// buildNoEndpointWarnings creates a warnings map for resources that reference a service
// with no endpoints. Only the specific sub-resources (e.g. VS, VSR, Ingress, minion)
// that actually reference the service are included.
func (lbc *LoadBalancerController) buildNoEndpointWarnings(r Resource, svcNamespace, svcName string) configs.Warnings {
	warnings := make(configs.Warnings)
	noEndpointsMsg := []string{fmt.Sprintf("No endpoints found for service %v", svcName)}

	switch impl := r.(type) {
	case *VirtualServerConfiguration:
		if lbc.configuration.IsServiceReferencedByVirtualServer(svcNamespace, svcName, impl.VirtualServer) {
			warnings[impl.VirtualServer] = noEndpointsMsg
		}
		for _, vsr := range impl.VirtualServerRoutes {
			if lbc.configuration.IsServiceReferencedByVirtualServerRoute(svcNamespace, svcName, vsr) {
				warnings[vsr] = noEndpointsMsg
			}
		}
	case *IngressConfiguration:
		if lbc.configuration.IsServiceReferencedByIngress(svcNamespace, svcName, impl.Ingress) {
			warnings[impl.Ingress] = noEndpointsMsg
		}
		for _, minion := range impl.Minions {
			if lbc.configuration.IsServiceReferencedByMinion(svcNamespace, svcName, minion.Ingress) {
				warnings[minion.Ingress] = noEndpointsMsg
			}
		}
	}

	return warnings
}
