package k8s

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// createServiceHandlers builds the handler funcs for services.
//
// In the update handlers below we catch two cases:
// (1) the service is the external service
// (2) the service had a change like a change of the port field of a service port (for such a change Kubernetes doesn't
// update the corresponding endpoints resource, that we monitor as well)
// or a change of the externalName field of an ExternalName service.
//
// In both cases we enqueue the service to be processed by syncService
func createServiceHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*v1.Service)

			nl.Infof(lbc.Logger, "Adding service: %v", svc.Name)
			lbc.AddSyncQueue(svc)
		},
		DeleteFunc: func(obj interface{}) {
			svc, isSvc := obj.(*v1.Service)
			if !isSvc {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Infof(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				svc, ok = deletedState.Obj.(*v1.Service)
				if !ok {
					nl.Infof(lbc.Logger, "Error DeletedFinalStateUnknown contained non-Service object: %v", deletedState.Obj)
					return
				}
			}

			nl.Infof(lbc.Logger, "Removing service: %v", svc.Name)
			lbc.AddSyncQueue(svc)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				curSvc := cur.(*v1.Service)
				if lbc.IsExternalServiceForStatus(curSvc) {
					lbc.AddSyncQueue(curSvc)
					return
				}
				oldSvc := old.(*v1.Service)
				if hasServiceChanges(oldSvc, curSvc) {
					nl.Infof(lbc.Logger, "Service %v changed, syncing", curSvc.Name)
					lbc.AddSyncQueue(curSvc)
				}
			}
		},
	}
}

// isHeadless returns true if the Service is headless (clusterIP == "None").
func isHeadless(svc *v1.Service) bool {
	return svc.Spec.ClusterIP == v1.ClusterIPNone
}

// hasServicedChanged checks if the service has changed based on custom rules we define (eg. port).
func hasServiceChanges(oldSvc, curSvc *v1.Service) bool {
	if hasServicePortChanges(oldSvc.Spec.Ports, curSvc.Spec.Ports) {
		return true
	}
	if hasServiceExternalNameChanges(oldSvc, curSvc) {
		return true
	}

	if isHeadless(oldSvc) || isHeadless(curSvc) {
		return true
	}

	return false
}

// hasServiceExternalNameChanges only compares Service.Spec.Externalname for Type ExternalName services.
func hasServiceExternalNameChanges(oldSvc, curSvc *v1.Service) bool {
	return curSvc.Spec.Type == v1.ServiceTypeExternalName && oldSvc.Spec.ExternalName != curSvc.Spec.ExternalName
}

// hasServicePortChanges only compares ServicePort.Name and .Port.
func hasServicePortChanges(oldServicePorts []v1.ServicePort, curServicePorts []v1.ServicePort) bool {
	if len(oldServicePorts) != len(curServicePorts) {
		return true
	}

	sort.Sort(portSort(oldServicePorts))
	sort.Sort(portSort(curServicePorts))

	for i := range oldServicePorts {
		if oldServicePorts[i].Port != curServicePorts[i].Port ||
			oldServicePorts[i].Name != curServicePorts[i].Name {
			return true
		}
	}
	return false
}

type portSort []v1.ServicePort

func (a portSort) Len() int {
	return len(a)
}

func (a portSort) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a portSort) Less(i, j int) bool {
	if a[i].Name == a[j].Name {
		return a[i].Port < a[j].Port
	}
	return a[i].Name < a[j].Name
}

// addServiceHandler adds the handler for services to the controller
func (nsi *namespacedInformer) addServiceHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.sharedInformerFactory.Core().V1().Services().Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.svcLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (lbc *LoadBalancerController) syncZoneSyncHeadlessService(svcName string) error {
	if lbc.configurator.CfgParams.ZoneSync.Enable && lbc.configurator.CfgParams.ZoneSync.Port != 0 {
		_, err := lbc.client.CoreV1().Services(lbc.metadata.namespace).Get(context.Background(), svcName, meta_v1.GetOptions{})
		if err == nil {
			return nil
		}

		newSvc := &v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      svcName,
				Namespace: lbc.metadata.namespace,
				OwnerReferences: []meta_v1.OwnerReference{
					{
						APIVersion:         "v1",
						Kind:               "ConfigMap",
						Name:               lbc.configMap.Name,
						UID:                lbc.configMap.UID,
						Controller:         commonhelpers.BoolToPointerBool(true),
						BlockOwnerDeletion: commonhelpers.BoolToPointerBool(true),
					},
				},
			},
			Spec: v1.ServiceSpec{
				ClusterIP: v1.ClusterIPNone,
				Selector: map[string]string{
					"app": lbc.metadata.namespace,
				},
			},
		}

		createdSvc, err := lbc.client.CoreV1().Services(lbc.metadata.namespace).Create(context.Background(), newSvc, meta_v1.CreateOptions{})
		if err != nil {
			lbc.recorder.Eventf(lbc.metadata.pod, v1.EventTypeWarning, nl.EventReasonServiceFailedToCreate, "error creating headless service: %+v", newSvc)
			return fmt.Errorf("error creating headless service: %w", err)
		}
		nl.Infof(lbc.Logger, "successfully created headless service: %s/%s", lbc.metadata.namespace, createdSvc.Name)
		return nil
	}

	if lbc.isNginxReady {
		_, err := lbc.client.CoreV1().Services(lbc.metadata.namespace).Get(context.Background(), svcName, meta_v1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
				return nil
			}
			return fmt.Errorf("error retrieving headless service: %w", err)
		}

		err = lbc.client.CoreV1().Services(lbc.metadata.namespace).Delete(context.Background(), svcName, meta_v1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsForbidden(err) {
			return fmt.Errorf("error deleting headless service: %w", err)
		}

		nl.Infof(lbc.Logger, "successfully deleted headless service: %s/%s", lbc.metadata.namespace, svcName)
	}
	return nil
}

func (lbc *LoadBalancerController) syncService(task task) {
	key := task.Key

	var obj interface{}
	var exists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, exists, err = lbc.getNamespacedInformer(ns).svcLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	// First case: the service is the external service for the Ingress Controller
	// In that case we need to update the statuses of all resources
	if lbc.IsExternalServiceKeyForStatus(key) {
		nl.Infof(lbc.Logger, "Syncing service %v", key)

		if !exists {
			// service got removed
			lbc.statusUpdater.ClearStatusFromExternalService()
		} else {
			// service added or updated
			lbc.statusUpdater.SaveStatusFromExternalService(obj.(*v1.Service))
		}

		if lbc.reportStatusEnabled() {
			ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

			nl.Infof(lbc.Logger, "Updating status for %v Ingresses", len(ingresses))

			err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
			if err != nil {
				nl.Errorf(lbc.Logger, "error updating ingress status in syncService: %v", err)
			}
		}

		if lbc.areCustomResourcesEnabled && lbc.reportCustomResourceStatusEnabled() {
			virtualServers := lbc.configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})

			nl.Infof(lbc.Logger, "Updating status for %v VirtualServers", len(virtualServers))

			err := lbc.statusUpdater.UpdateExternalEndpointsForResources(virtualServers)
			if err != nil {
				nl.Infof(lbc.Logger, "error updating VirtualServer/VirtualServerRoute status in syncService: %v", err)
			}
		}

		// we don't return here because technically the same service could be used in the second case
	}

	// Second case: the service is referenced by some resources in the cluster

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	resources := lbc.configuration.FindResourcesForService(namespace, name)

	if len(resources) == 0 {
		return
	}
	nl.Infof(lbc.Logger, "Syncing service %v", key)

	nl.Infof(lbc.Logger, "Updating %v resources", len(resources))

	resourceExes := lbc.createExtendedResources(resources)

	warnings, updateErr := lbc.configurator.AddOrUpdateResources(resourceExes, true)
	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
}
