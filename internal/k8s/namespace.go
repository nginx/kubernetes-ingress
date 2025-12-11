package k8s

import (
	"context"
	"reflect"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// createNamespaceHandlers builds the handler funcs for namespaces
func createNamespaceHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns := obj.(*api_v1.Namespace)
			nl.Debugf(lbc.Logger, "Adding Namespace to list of watched Namespaces: %v", ns.Name)
			lbc.AddSyncQueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			ns, isNs := obj.(*api_v1.Namespace)
			if !isNs {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				ns, ok = deletedState.Obj.(*api_v1.Namespace)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-Namespace object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing Namespace from list of watched Namespaces: %v", ns.Name)
			lbc.AddSyncQueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				nl.Debugf(lbc.Logger, "Namespace %v changed, syncing", cur.(*api_v1.Namespace).Name)
				lbc.AddSyncQueue(cur)
			}
		},
	}
}

func (lbc *LoadBalancerController) addNamespaceHandler(handlers cache.ResourceEventHandlerFuncs, nsLabel string) {
	optionsModifier := func(options *meta_v1.ListOptions) {
		options.LabelSelector = nsLabel
	}
	nsInformer := informers.NewSharedInformerFactoryWithOptions(lbc.client, lbc.resync, informers.WithTweakListOptions(optionsModifier)).Core().V1().Namespaces().Informer()
	nsInformer.AddEventHandler(handlers) //nolint:errcheck,gosec
	lbc.namespaceLabeledLister = nsInformer.GetStore()
	lbc.namespaceWatcherController = nsInformer

	lbc.cacheSyncs = append(lbc.cacheSyncs, nsInformer.HasSynced)
}

func (lbc *LoadBalancerController) syncNamespace(task task) {
	key := task.Key
	// process namespace and add to / remove from watched namespace list
	_, exists, err := lbc.namespaceLabeledLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !exists {
		// Check if change is because of a new label, or because of a deleted namespace
		ns, _ := lbc.client.CoreV1().Namespaces().Get(context.TODO(), key, meta_v1.GetOptions{})

		if ns != nil && ns.Status.Phase == api_v1.NamespaceActive {
			// namespace still exists
			nl.Infof(lbc.Logger, "Removing Configuration for Unwatched Namespace: %v", key)
			// Watched label for namespace was removed
			// delete any now unwatched namespaced informer groups if required
			nsi := lbc.getNamespacedInformer(key)
			if nsi != nil {
				lbc.cleanupUnwatchedNamespacedResources(nsi)
				delete(lbc.namespacedInformers, key)
			}
		} else {
			nl.Infof(lbc.Logger, "Deleting Watchers for Deleted Namespace: %v", key)
			nsi := lbc.getNamespacedInformer(key)
			if nsi != nil {
				lbc.removeNamespacedInformer(nsi, key)
			}
		}
		if lbc.certManagerController != nil {
			lbc.certManagerController.RemoveNamespacedInformer(key)
		}
		if lbc.externalDNSController != nil {
			lbc.externalDNSController.RemoveNamespacedInformer(key)
		}
	} else {
		// check if informer group already exists
		// if not create new namespaced informer group
		// update cert-manager informer group if required
		// update external-dns informer group if required
		nl.Debugf(lbc.Logger, "Adding or Updating Watched Namespace: %v", key)
		nsi := lbc.getNamespacedInformer(key)
		if nsi == nil {
			nl.Infof(lbc.Logger, "Adding New Watched Namespace: %v", key)
			nsi = lbc.newNamespacedInformer(key)
			nsi.start()
		}
		if lbc.certManagerController != nil {
			lbc.certManagerController.AddNewNamespacedInformer(key)
		}
		if lbc.externalDNSController != nil {
			lbc.externalDNSController.AddNewNamespacedInformer(key)
		}
		if !cache.WaitForCacheSync(nsi.stopCh, nsi.cacheSyncs...) {
			return
		}
	}
}
