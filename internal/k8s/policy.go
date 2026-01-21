package k8s

import (
	"fmt"
	"reflect"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

func createPolicyHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pol := obj.(*conf_v1.Policy)
			nl.Debugf(lbc.Logger, "Adding Policy: %v", pol.Name)
			lbc.AddSyncQueue(pol)
		},
		DeleteFunc: func(obj interface{}) {
			pol, isPol := obj.(*conf_v1.Policy)
			if !isPol {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				pol, ok = deletedState.Obj.(*conf_v1.Policy)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-Policy object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing Policy: %v", pol.Name)
			lbc.AddSyncQueue(pol)
		},
		UpdateFunc: func(old, cur interface{}) {
			curPol := cur.(*conf_v1.Policy)
			oldPol := old.(*conf_v1.Policy)
			if !reflect.DeepEqual(oldPol.Spec, curPol.Spec) {
				nl.Debugf(lbc.Logger, "Policy %v changed, syncing", curPol.Name)
				lbc.AddSyncQueue(curPol)
			}
		},
	}
}

func (nsi *namespacedInformer) addPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().Policies().Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.policyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (lbc *LoadBalancerController) syncPolicy(task task) {
	key := task.Key
	var obj interface{}
	var polExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, polExists, err = lbc.getNamespacedInformer(ns).policyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	nl.Debugf(lbc.Logger, "Adding, Updating or Deleting Policy: %v\n", key)

	if polExists && lbc.HasCorrectIngressClass(obj) {
		pol := obj.(*conf_v1.Policy)
		err := validation.ValidatePolicy(pol, lbc.isNginxPlus, lbc.enableOIDC, lbc.appProtectEnabled)
		if err != nil {
			msg := fmt.Sprintf("Policy %v/%v is invalid and was rejected: %v", pol.Namespace, pol.Name, err)
			lbc.recorder.Eventf(pol, api_v1.EventTypeWarning, nl.EventReasonRejected, msg)

			if lbc.reportCustomResourceStatusEnabled() {
				err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateInvalid, "Rejected", msg)
				if err != nil {
					nl.Debugf(lbc.Logger, "Failed to update policy %s status: %v", key, err)
				}
			}
		} else {
			msg := fmt.Sprintf("Policy %v/%v was added or updated", pol.Namespace, pol.Name)
			lbc.recorder.Eventf(pol, api_v1.EventTypeNormal, nl.EventReasonAddedOrUpdated, msg)

			if lbc.reportCustomResourceStatusEnabled() {
				err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateValid, "AddedOrUpdated", msg)
				if err != nil {
					nl.Debugf(lbc.Logger, "Failed to update policy %s status: %v", key, err)
				}
			}
		}
	}

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	resources := lbc.configuration.FindResourcesForPolicy(namespace, name)
	resourceExes := lbc.createExtendedResources(resources)

	// Only VirtualServers support policies
	if len(resourceExes.VirtualServerExes) == 0 {
		return
	}

	warnings, updateErr := lbc.configurator.AddOrUpdateVirtualServers(resourceExes.VirtualServerExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)

	// Note: updating the status of a policy based on a reload is not needed.
}
