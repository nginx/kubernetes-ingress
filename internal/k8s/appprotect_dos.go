package k8s

import (
	"fmt"
	"reflect"

	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotectdos"
	nl "github.com/nginxinc/kubernetes-ingress/internal/logger"
	"github.com/nginxinc/kubernetes-ingress/pkg/apis/dos/v1beta1"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func createAppProtectDosPolicyHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pol := obj.(*unstructured.Unstructured)
			nl.Debugf(lbc.logger, "Adding AppProtectDosPolicy: %v", pol.GetName())
			lbc.AddSyncQueue(pol)
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldPol := oldObj.(*unstructured.Unstructured)
			newPol := obj.(*unstructured.Unstructured)
			different, err := areResourcesDifferent(lbc.logger, oldPol, newPol)
			if err != nil {
				nl.Debugf(lbc.logger, "Error when comparing policy %v", err)
				lbc.AddSyncQueue(newPol)
			}
			if different {
				nl.Debugf(lbc.logger, "ApDosPolicy %v changed, syncing", oldPol.GetName())
				lbc.AddSyncQueue(newPol)
			}
		},
		DeleteFunc: func(obj interface{}) {
			lbc.AddSyncQueue(obj)
		},
	}
	return handlers
}

func createAppProtectDosLogConfHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			conf := obj.(*unstructured.Unstructured)
			nl.Debugf(lbc.logger, "Adding AppProtectDosLogConf: %v", conf.GetName())
			lbc.AddSyncQueue(conf)
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldConf := oldObj.(*unstructured.Unstructured)
			newConf := obj.(*unstructured.Unstructured)
			different, err := areResourcesDifferent(lbc.logger, oldConf, newConf)
			if err != nil {
				nl.Debugf(lbc.logger, "Error when comparing DosLogConfs %v", err)
				lbc.AddSyncQueue(newConf)
			}
			if different {
				nl.Debugf(lbc.logger, "ApDosLogConf %v changed, syncing", oldConf.GetName())
				lbc.AddSyncQueue(newConf)
			}
		},
		DeleteFunc: func(obj interface{}) {
			lbc.AddSyncQueue(obj)
		},
	}
	return handlers
}

func createAppProtectDosProtectedResourceHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			conf := obj.(*v1beta1.DosProtectedResource)
			nl.Debugf(lbc.logger, "Adding DosProtectedResource: %v", conf.GetName())
			lbc.AddSyncQueue(conf)
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldConf := oldObj.(*v1beta1.DosProtectedResource)
			newConf := obj.(*v1beta1.DosProtectedResource)

			if !reflect.DeepEqual(oldConf.Spec, newConf.Spec) {
				nl.Debugf(lbc.logger, "DosProtectedResource %v changed, syncing", oldConf.GetName())
				lbc.AddSyncQueue(newConf)
			}
		},
		DeleteFunc: func(obj interface{}) {
			lbc.AddSyncQueue(obj)
		},
	}
	return handlers
}

// addAppProtectDosPolicyHandler creates dynamic informers for custom appprotectdos policy resource
func (nsi *namespacedInformer) addAppProtectDosPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotectdos.DosPolicyGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.appProtectDosPolicyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// addAppProtectDosLogConfHandler creates dynamic informer for custom appprotectdos logging config resource
func (nsi *namespacedInformer) addAppProtectDosLogConfHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotectdos.DosLogConfGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.appProtectDosLogConfLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// addAppProtectDosLogConfHandler creates dynamic informers for custom appprotectdos logging config resource
func (nsi *namespacedInformer) addAppProtectDosProtectedResourceHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.Appprotectdos().V1beta1().DosProtectedResources().Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.appProtectDosProtectedLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (lbc *LoadBalancerController) syncAppProtectDosPolicy(task task) {
	key := task.Key
	nl.Debugf(lbc.logger, "Syncing AppProtectDosPolicy %v", key)
	var obj interface{}
	var polExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, polExists, err = lbc.getNamespacedInformer(ns).appProtectDosPolicyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotectdos.Change
	var problems []appprotectdos.Problem

	if !polExists {
		nl.Debugf(lbc.logger, "Deleting APDosPolicy: %v\n", key)
		changes, problems = lbc.dosConfiguration.DeletePolicy(key)
	} else {
		nl.Debugf(lbc.logger, "Adding or Updating APDosPolicy: %v\n", key)
		changes, problems = lbc.dosConfiguration.AddOrUpdatePolicy(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectDosChanges(changes)
	lbc.processAppProtectDosProblems(problems)
}

func (lbc *LoadBalancerController) syncAppProtectDosLogConf(task task) {
	key := task.Key
	nl.Debugf(lbc.logger, "Syncing APDosLogConf %v", key)
	var obj interface{}
	var confExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, confExists, err = lbc.getNamespacedInformer(ns).appProtectDosLogConfLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotectdos.Change
	var problems []appprotectdos.Problem

	if !confExists {
		nl.Debugf(lbc.logger, "Deleting APDosLogConf: %v\n", key)
		changes, problems = lbc.dosConfiguration.DeleteLogConf(key)
	} else {
		nl.Debugf(lbc.logger, "Adding or Updating APDosLogConf: %v\n", key)
		changes, problems = lbc.dosConfiguration.AddOrUpdateLogConf(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectDosChanges(changes)
	lbc.processAppProtectDosProblems(problems)
}

func (lbc *LoadBalancerController) syncDosProtectedResource(task task) {
	key := task.Key
	nl.Debugf(lbc.logger, "Syncing DosProtectedResource %v", key)
	var obj interface{}
	var confExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, confExists, err = lbc.getNamespacedInformer(ns).appProtectDosProtectedLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotectdos.Change
	var problems []appprotectdos.Problem

	if confExists {
		nl.Debugf(lbc.logger, "Adding or Updating DosProtectedResource: %v\n", key)
		changes, problems = lbc.dosConfiguration.AddOrUpdateDosProtectedResource(obj.(*v1beta1.DosProtectedResource))
	} else {
		nl.Debugf(lbc.logger, "Deleting DosProtectedResource: %v\n", key)
		changes, problems = lbc.dosConfiguration.DeleteProtectedResource(key)
	}

	lbc.processAppProtectDosChanges(changes)
	lbc.processAppProtectDosProblems(problems)
}

func (lbc *LoadBalancerController) processAppProtectDosChanges(changes []appprotectdos.Change) {
	nl.Debugf(lbc.logger, "Processing %v App Protect Dos changes", len(changes))

	for _, c := range changes {
		if c.Op == appprotectdos.AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *appprotectdos.DosProtectedResourceEx:
				nl.Debugf(lbc.logger, "handling change UPDATE OR ADD for DOS protected %s/%s", impl.Obj.Namespace, impl.Obj.Name)
				resources := lbc.configuration.FindResourcesForAppProtectDosProtected(impl.Obj.Namespace, impl.Obj.Name)
				resourceExes := lbc.createExtendedResources(resources)
				warnings, err := lbc.configurator.AddOrUpdateResourcesThatUseDosProtected(resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)
				lbc.updateResourcesStatusAndEvents(resources, warnings, err)
				msg := fmt.Sprintf("Configuration for %s/%s was added or updated", impl.Obj.Namespace, impl.Obj.Name)
				lbc.recorder.Event(impl.Obj, api_v1.EventTypeNormal, "AddedOrUpdated", msg)
			case *appprotectdos.DosPolicyEx:
				msg := "Configuration was added or updated"
				lbc.recorder.Event(impl.Obj, api_v1.EventTypeNormal, "AddedOrUpdated", msg)
			case *appprotectdos.DosLogConfEx:
				eventType := api_v1.EventTypeNormal
				eventTitle := "AddedOrUpdated"
				msg := "Configuration was added or updated"
				if impl.ErrorMsg != "" {
					msg += fmt.Sprintf(" ; with warning(s): %s", impl.ErrorMsg)
					eventTitle = "AddedOrUpdatedWithWarning"
					eventType = api_v1.EventTypeWarning
				}
				lbc.recorder.Event(impl.Obj, eventType, eventTitle, msg)
			}
		} else if c.Op == appprotectdos.Delete {
			switch impl := c.Resource.(type) {
			case *appprotectdos.DosPolicyEx:
				lbc.configurator.DeleteAppProtectDosPolicy(impl.Obj)

			case *appprotectdos.DosLogConfEx:
				lbc.configurator.DeleteAppProtectDosLogConf(impl.Obj)

			case *appprotectdos.DosProtectedResourceEx:
				nl.Debugf(lbc.logger, "handling change DELETE for DOS protected %s/%s", impl.Obj.Namespace, impl.Obj.Name)
				resources := lbc.configuration.FindResourcesForAppProtectDosProtected(impl.Obj.Namespace, impl.Obj.Name)
				resourceExes := lbc.createExtendedResources(resources)
				warnings, err := lbc.configurator.AddOrUpdateResourcesThatUseDosProtected(resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)
				lbc.updateResourcesStatusAndEvents(resources, warnings, err)
			}
		}
	}
}

func (lbc *LoadBalancerController) processAppProtectDosProblems(problems []appprotectdos.Problem) {
	nl.Debugf(lbc.logger, "Processing %v App Protect Dos problems", len(problems))

	for _, p := range problems {
		eventType := api_v1.EventTypeWarning
		lbc.recorder.Event(p.Object, eventType, p.Reason, p.Message)
	}
}

func (lbc *LoadBalancerController) cleanupUnwatchedAppDosResources(nsi *namespacedInformer) {
	for _, obj := range nsi.appProtectDosPolicyLister.List() {
		dosPol := obj.((*unstructured.Unstructured))
		namespace := dosPol.GetNamespace()
		name := dosPol.GetName()

		changes, problems := lbc.dosConfiguration.DeletePolicy(namespace + "/" + name)
		lbc.processAppProtectDosChanges(changes)
		lbc.processAppProtectDosProblems(problems)
	}
	for _, obj := range nsi.appProtectDosProtectedLister.List() {
		dosPol := obj.((*unstructured.Unstructured))
		namespace := dosPol.GetNamespace()
		name := dosPol.GetName()

		changes, problems := lbc.dosConfiguration.DeleteProtectedResource(namespace + "/" + name)
		lbc.processAppProtectDosChanges(changes)
		lbc.processAppProtectDosProblems(problems)
	}
	for _, obj := range nsi.appProtectDosLogConfLister.List() {
		dosPol := obj.((*unstructured.Unstructured))
		namespace := dosPol.GetNamespace()
		name := dosPol.GetName()

		changes, problems := lbc.dosConfiguration.DeleteLogConf(namespace + "/" + name)
		lbc.processAppProtectDosChanges(changes)
		lbc.processAppProtectDosProblems(problems)
	}
}
