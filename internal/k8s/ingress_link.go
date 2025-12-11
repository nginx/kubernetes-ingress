package k8s

import (
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

func createIngressLinkHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			link := obj.(*unstructured.Unstructured)
			nl.Debugf(lbc.Logger, "Adding IngressLink: %v", link.GetName())
			lbc.AddSyncQueue(link)
		},
		DeleteFunc: func(obj interface{}) {
			link, isUnstructured := obj.(*unstructured.Unstructured)

			if !isUnstructured {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				link, ok = deletedState.Obj.(*unstructured.Unstructured)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-Unstructured object: %v", deletedState.Obj)
					return
				}
			}

			nl.Debugf(lbc.Logger, "Removing IngressLink: %v", link.GetName())
			lbc.AddSyncQueue(link)
		},
		UpdateFunc: func(old, cur interface{}) {
			oldLink := old.(*unstructured.Unstructured)
			curLink := cur.(*unstructured.Unstructured)
			different, err := areResourcesDifferent(lbc.Logger, oldLink, curLink)
			if err != nil {
				nl.Debugf(lbc.Logger, "Error when comparing IngressLinks: %v", err)
				lbc.AddSyncQueue(curLink)
			}
			if different {
				nl.Debugf(lbc.Logger, "IngressLink %v changed, syncing", oldLink.GetName())
				lbc.AddSyncQueue(curLink)
			}
		},
	}
}

func (lbc *LoadBalancerController) addIngressLinkHandler(handlers cache.ResourceEventHandlerFuncs, name string) {
	optionsModifier := func(options *meta_v1.ListOptions) {
		options.FieldSelector = fields.Set{"metadata.name": name}.String()
	}

	informer := dynamicinformer.NewFilteredDynamicInformer(lbc.dynClient, ingressLinkGVR, lbc.metadata.namespace, lbc.resync,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, optionsModifier)

	informer.Informer().AddEventHandlerWithResyncPeriod(handlers, lbc.resync) //nolint:errcheck,gosec

	lbc.ingressLinkInformer = informer.Informer()
	lbc.ingressLinkLister = informer.Informer().GetStore()

	lbc.cacheSyncs = append(lbc.cacheSyncs, lbc.ingressLinkInformer.HasSynced)
}

func (lbc *LoadBalancerController) syncIngressLink(task task) {
	key := task.Key
	nl.Debugf(lbc.Logger, "Adding, Updating or Deleting IngressLink: %v", key)

	obj, exists, err := lbc.ingressLinkLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !exists {
		// IngressLink got removed
		lbc.statusUpdater.ClearStatusFromIngressLink()
	} else {
		// IngressLink is added or updated
		link := obj.(*unstructured.Unstructured)

		// spec.virtualServerAddress contains the IP of the BIG-IP device
		ip, found, err := unstructured.NestedString(link.Object, "spec", "virtualServerAddress")
		if err != nil {
			nl.Errorf(lbc.Logger, "Failed to get virtualServerAddress from IngressLink %s: %v", key, err)
			lbc.statusUpdater.ClearStatusFromIngressLink()
		} else if !found {
			nl.Errorf(lbc.Logger, "virtualServerAddress is not found in IngressLink %s", key)
			lbc.statusUpdater.ClearStatusFromIngressLink()
		} else if ip == "" {
			nl.Warnf(lbc.Logger, "IngressLink %s has the empty virtualServerAddress field", key)
			lbc.statusUpdater.ClearStatusFromIngressLink()
		} else {
			lbc.statusUpdater.SaveStatusFromIngressLink(ip)
		}
	}

	if lbc.reportStatusEnabled() {
		ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

		nl.Debugf(lbc.Logger, "Updating status for %v Ingresses", len(ingresses))

		err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
		if err != nil {
			nl.Errorf(lbc.Logger, "Error updating ingress status in syncIngressLink: %v", err)
		}
	}

	if lbc.areCustomResourcesEnabled && lbc.reportCustomResourceStatusEnabled() {
		virtualServers := lbc.configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})

		nl.Debugf(lbc.Logger, "Updating status for %v VirtualServers", len(virtualServers))

		err := lbc.statusUpdater.UpdateExternalEndpointsForResources(virtualServers)
		if err != nil {
			nl.Debugf(lbc.Logger, "Error updating VirtualServer/VirtualServerRoute status in syncIngressLink: %v", err)
		}
	}
}
