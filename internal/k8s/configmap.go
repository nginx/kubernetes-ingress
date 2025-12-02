package k8s

import (
	"reflect"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

// createConfigMapHandlers builds the handler funcs for config maps
func createConfigMapHandlers(lbc *LoadBalancerController, name string) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			configMap := obj.(*v1.ConfigMap)
			if configMap.Name == name {
				nl.Debugf(lbc.Logger, "Adding ConfigMap: %v", configMap.Name)
				lbc.AddSyncQueue(obj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			configMap, isConfigMap := obj.(*v1.ConfigMap)
			if !isConfigMap {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				configMap, ok = deletedState.Obj.(*v1.ConfigMap)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-ConfigMap object: %v", deletedState.Obj)
					return
				}
			}
			if configMap.Name == name {
				nl.Debugf(lbc.Logger, "Removing ConfigMap: %v", configMap.Name)
				lbc.AddSyncQueue(obj)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				configMap := cur.(*v1.ConfigMap)
				if configMap.Name == name {
					nl.Debugf(lbc.Logger, "ConfigMap %v changed, syncing", cur.(*v1.ConfigMap).Name)
					lbc.AddSyncQueue(cur)
				}
			}
		},
	}
}

func (lbc *LoadBalancerController) getConfigMapHandlerOptions(handlers cache.ResourceEventHandlerFuncs, namespace string) cache.InformerOptions {
	return cache.InformerOptions{
		ListerWatcher: cache.NewListWatchFromClient(
			lbc.client.CoreV1().RESTClient(),
			"configmaps",
			namespace,
			fields.Everything()),
		ObjectType:   &v1.ConfigMap{},
		ResyncPeriod: lbc.resync,
		Handler:      handlers,
	}
}

// addConfigMapHandler adds the handler for config maps to the controller
func (lbc *LoadBalancerController) addConfigMapHandler(handlers cache.ResourceEventHandlerFuncs, namespace string) {
	options := lbc.getConfigMapHandlerOptions(handlers, namespace)

	lbc.configMapLister.Store, lbc.configMapController = cache.NewInformerWithOptions(options)
	lbc.cacheSyncs = append(lbc.cacheSyncs, lbc.configMapController.HasSynced)
}

func (lbc *LoadBalancerController) addMGMTConfigMapHandler(handlers cache.ResourceEventHandlerFuncs, namespace string) {
	options := lbc.getConfigMapHandlerOptions(handlers, namespace)

	lbc.mgmtConfigMapLister.Store, lbc.mgmtConfigMapController = cache.NewInformerWithOptions(options)
	lbc.cacheSyncs = append(lbc.cacheSyncs, lbc.mgmtConfigMapController.HasSynced)
}

func (lbc *LoadBalancerController) syncConfigMap(task task) {
	key := task.Key
	nl.Debugf(lbc.Logger, "Syncing configmap %v", key)

	if key == lbc.mgmtConfigMapName && lbc.isPodMarkedForDeletion() {
		nl.Debugf(lbc.Logger, "Pod is shutting down, skipping management ConfigMap sync")
		return
	}

	switch key {
	case lbc.nginxConfigMapName:
		obj, configExists, err := lbc.configMapLister.GetByKey(key)
		if err != nil {
			lbc.syncQueue.Requeue(task, err)
			return
		}
		if configExists {
			lbc.configMap = obj.(*v1.ConfigMap)
			externalStatusAddress, exists := lbc.configMap.Data["external-status-address"]
			if exists {
				lbc.statusUpdater.SaveStatusFromExternalStatus(externalStatusAddress)
			}
		} else {
			lbc.configMap = nil
		}
	case lbc.mgmtConfigMapName:
		obj, configExists, err := lbc.mgmtConfigMapLister.GetByKey(key)
		if err != nil {
			lbc.syncQueue.Requeue(task, err)
			return
		}
		if configExists {
			lbc.mgmtConfigMap = obj.(*v1.ConfigMap)
		} else {
			lbc.mgmtConfigMap = nil
		}
	}

	if !lbc.isNginxReady {
		nl.Debugf(lbc.Logger, "Skipping ConfigMap update because the pod is not ready yet")
		return
	}

	if lbc.batchSyncEnabled {
		nl.Debugf(lbc.Logger, "Skipping ConfigMap update because batch sync is on")
		return
	}
	if err := lbc.ctx.Err(); err != nil {
		nl.Debugf(lbc.Logger, "Context canceled, skipping ConfigMap sync for %v: %v", task.Key, err)
		return
	}
	lbc.updateAllConfigs()
}
