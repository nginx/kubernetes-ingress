package k8s

import (
	"fmt"
	"reflect"

	"github.com/nginx/kubernetes-ingress/internal/configs"
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
		err := validation.ValidatePolicy(pol, lbc.policyValidationConfig())
		if err != nil {
			msg := fmt.Sprintf("Policy %v/%v is invalid and was rejected: %v", pol.Namespace, pol.Name, err)
			lbc.recorder.Eventf(pol, api_v1.EventTypeWarning, nl.EventReasonRejected, msg)

			if lbc.reportCustomResourceStatusEnabled() {
				// Defer policy status updates during startup to avoid serial
				// API calls that block readiness. See flushPendingStatusesAsync().
				if !lbc.isNginxReady {
					lbc.pendingStatusPolicies = append(lbc.pendingStatusPolicies, pendingPolicyStatus{
						pol: pol, state: conf_v1.StateInvalid, reason: "Rejected", message: msg,
					})
				} else {
					err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateInvalid, "Rejected", msg)
					if err != nil {
						nl.Errorf(lbc.Logger, "Failed to update policy %s status: %v", key, err)
					}
				}
			}
		} else {
			msg := fmt.Sprintf("Policy %v/%v was added or updated", pol.Namespace, pol.Name)
			lbc.recorder.Eventf(pol, api_v1.EventTypeNormal, nl.EventReasonAddedOrUpdated, msg)

			if lbc.reportCustomResourceStatusEnabled() {
				// Defer policy status updates during startup to avoid serial
				// API calls that block readiness. See flushPendingStatusesAsync().
				if !lbc.isNginxReady {
					lbc.pendingStatusPolicies = append(lbc.pendingStatusPolicies, pendingPolicyStatus{
						pol: pol, state: conf_v1.StateValid, reason: "AddedOrUpdated", message: msg,
					})
				} else {
					err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateValid, "AddedOrUpdated", msg)
					if err != nil {
						nl.Errorf(lbc.Logger, "Failed to update policy %s status: %v", key, err)
					}
				}
			}
		}
	}

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	// Track external auth service references so that service/endpoint changes
	// for the auth service can be correlated back to VirtualServers that use it.
	if polExists && lbc.HasCorrectIngressClass(obj) {
		pol := obj.(*conf_v1.Policy)
		if pol.Spec.ExternalAuth != nil && pol.Spec.ExternalAuth.AuthServiceName != "" {
			lbc.configuration.UpdatePolicyServiceRef(namespace, name, pol.Spec.ExternalAuth.AuthServiceName)
		} else {
			lbc.configuration.DeletePolicyServiceRef(namespace, name)
		}
	} else {
		lbc.configuration.DeletePolicyServiceRef(namespace, name)
	}

	resources := lbc.configuration.FindResourcesForPolicy(namespace, name)

	// Loop through the resources that reference this policy and check if the policy type is supported on the resource. If not, log an error and emit an event.
	// Note: if we ever support all policy types on all resources, this loop can be removed.
	for _, res := range resources {
		switch impl := res.(type) {
		// We only check for Ingress resources because VirtualServer and VirtualServerRoute support all policy types.
		//   If a new resource type is added that supports a subset of policy types, a new case should be added here to check for supported policy types on that resource.
		case *IngressConfiguration:
			if !polExists {
				continue
			}
			pol := obj.(*conf_v1.Policy)
			switch {
			case pol.Spec.CORS != nil:
				// CORS policy is supported on Ingress
				continue
			case pol.Spec.AccessControl != nil:
				// Access Control policy is supported on Ingress
				continue
			case pol.Spec.WAF != nil:
				// WAF policy is supported on Ingress
				continue
			case pol.Spec.ExternalAuth != nil:
				// External Auth policy is supported on Ingress
			case pol.Spec.IngressMTLS != nil:
				// IngressMTLS policy is supported on Ingress
				continue
			case pol.Spec.EgressMTLS != nil:
				// Egress MTLS policy is supported on Ingress
				continue
			default: // Unsupported policy type on Ingress
				msg := fmt.Sprintf("Policy %s/%s has unsupported type on Ingress resource %s/%s",
					pol.Namespace, pol.Name, impl.Ingress.Namespace, impl.Ingress.Name)
				nl.Error(lbc.Logger, msg)
				lbc.recorder.Eventf(impl.Ingress, api_v1.EventTypeWarning, nl.EventReasonRejected, msg)
			}
		default:
			continue
		}
	}

	resourceExes := lbc.createExtendedResources(resources)

	// Only VirtualServers and Ingresses support policies
	if len(resourceExes.VirtualServerExes) == 0 && len(resourceExes.IngressExes) == 0 && len(resourceExes.MergeableIngresses) == 0 {
		return
	}

	var virtualServerWarnings configs.Warnings
	var virtualServerErr error

	var ingressWarnings configs.Warnings
	var ingressErr error

	var mergeableIngressWarnings configs.Warnings
	mergeableIngressErrors := make(map[string]error)

	if len(resourceExes.VirtualServerExes) > 0 {
		warnings, updateErr := lbc.configurator.AddOrUpdateVirtualServers(resourceExes.VirtualServerExes)
		virtualServerWarnings = mergeWarningsMaps(virtualServerWarnings, warnings)
		if updateErr != nil {
			virtualServerErr = updateErr
		}
	}

	if len(resourceExes.IngressExes) > 0 {
		warnings, updateErr := lbc.configurator.AddOrUpdateIngresses(resourceExes.IngressExes)
		ingressWarnings = mergeWarningsMaps(ingressWarnings, warnings)
		if updateErr != nil {
			ingressErr = updateErr
		}
	}

	if len(resourceExes.MergeableIngresses) > 0 {
		for _, mergeableIngress := range resourceExes.MergeableIngresses {
			warnings, updateErr := lbc.configurator.AddOrUpdateMergeableIngress(mergeableIngress)
			mergeableIngressWarnings = mergeWarningsMaps(mergeableIngressWarnings, warnings)
			if updateErr != nil {
				mergeableIngressErrors[getResourceKey(&mergeableIngress.Master.Ingress.ObjectMeta)] = updateErr
			}
		}
	}

	// Merge policy warnings from extended resources back into resources
	resourcesWithWarnings := mergeExtendedResourceWarnings(resources, resourceExes)

	var virtualServerResources []Resource
	var ingressResources []Resource
	var mergeableIngressResources []Resource

	for _, res := range resourcesWithWarnings {
		switch impl := res.(type) {
		case *VirtualServerConfiguration:
			virtualServerResources = append(virtualServerResources, res)
		case *IngressConfiguration:
			if impl.IsMaster {
				mergeableIngressResources = append(mergeableIngressResources, res)
				continue
			}
			ingressResources = append(ingressResources, res)
		}
	}

	lbc.updateResourcesStatusAndEvents(virtualServerResources, virtualServerWarnings, virtualServerErr)
	lbc.updateResourcesStatusAndEvents(ingressResources, ingressWarnings, ingressErr)
	for _, mergeableIngressResource := range mergeableIngressResources {
		ingressCfg := mergeableIngressResource.(*IngressConfiguration)
		mergeableIngressErr := mergeableIngressErrors[getResourceKey(&ingressCfg.Ingress.ObjectMeta)]
		lbc.updateResourcesStatusAndEvents([]Resource{mergeableIngressResource}, mergeableIngressWarnings, mergeableIngressErr)
	}

	// Note: updating the status of a policy based on a reload is not needed.
}
