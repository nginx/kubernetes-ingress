package k8s

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
	"github.com/nginxinc/kubernetes-ingress/internal/configs"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotect"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotectcommon"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func createAppProtectPolicyHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pol := obj.(*unstructured.Unstructured)
			glog.V(3).Infof("Adding AppProtectPolicy: %v", pol.GetName())
			lbc.AddSyncQueue(pol)
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldPol := oldObj.(*unstructured.Unstructured)
			newPol := obj.(*unstructured.Unstructured)
			different, err := areResourcesDifferent(oldPol, newPol)
			if err != nil {
				glog.V(3).Infof("Error when comparing policy %v", err)
				lbc.AddSyncQueue(newPol)
			}
			if different {
				glog.V(3).Infof("ApPolicy %v changed, syncing", oldPol.GetName())
				lbc.AddSyncQueue(newPol)
			}
		},
		DeleteFunc: func(obj interface{}) {
			lbc.AddSyncQueue(obj)
		},
	}
	return handlers
}

func createAppProtectLogConfHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			conf := obj.(*unstructured.Unstructured)
			glog.V(3).Infof("Adding AppProtectLogConf: %v", conf.GetName())
			lbc.AddSyncQueue(conf)
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldConf := oldObj.(*unstructured.Unstructured)
			newConf := obj.(*unstructured.Unstructured)
			different, err := areResourcesDifferent(oldConf, newConf)
			if err != nil {
				glog.V(3).Infof("Error when comparing LogConfs %v", err)
				lbc.AddSyncQueue(newConf)
			}
			if different {
				glog.V(3).Infof("ApLogConf %v changed, syncing", oldConf.GetName())
				lbc.AddSyncQueue(newConf)
			}
		},
		DeleteFunc: func(obj interface{}) {
			lbc.AddSyncQueue(obj)
		},
	}
	return handlers
}

func createAppProtectUserSigHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			sig := obj.(*unstructured.Unstructured)
			glog.V(3).Infof("Adding AppProtectUserSig: %v", sig.GetName())
			lbc.AddSyncQueue(sig)
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldSig := oldObj.(*unstructured.Unstructured)
			newSig := obj.(*unstructured.Unstructured)
			different, err := areResourcesDifferent(oldSig, newSig)
			if err != nil {
				glog.V(3).Infof("Error when comparing UserSigs %v", err)
				lbc.AddSyncQueue(newSig)
			}
			if different {
				glog.V(3).Infof("ApUserSig %v changed, syncing", oldSig.GetName())
				lbc.AddSyncQueue(newSig)
			}
		},
		DeleteFunc: func(obj interface{}) {
			lbc.AddSyncQueue(obj)
		},
	}
	return handlers
}

// addAppProtectPolicyHandler creates dynamic informers for custom appprotect policy resource
func (nsi *namespacedInformer) addAppProtectPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.PolicyGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.appProtectPolicyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// addAppProtectLogConfHandler creates dynamic informer for custom appprotect logging config resource
func (nsi *namespacedInformer) addAppProtectLogConfHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.LogConfGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.appProtectLogConfLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// addAppProtectUserSigHandler creates dynamic informer for custom appprotect user defined signature resource
func (nsi *namespacedInformer) addAppProtectUserSigHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.UserSigGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.appProtectUserSigLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (lbc *LoadBalancerController) syncAppProtectPolicy(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectPolicy %v", key)

	var obj interface{}
	var polExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, polExists, err = lbc.getNamespacedInformer(ns).appProtectPolicyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotect.Change
	var problems []appprotect.Problem

	if !polExists {
		glog.V(2).Infof("Deleting AppProtectPolicy: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.DeletePolicy(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectPolicy: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.AddOrUpdatePolicy(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectChanges(changes)
	lbc.processAppProtectProblems(problems)
}

func (lbc *LoadBalancerController) syncAppProtectLogConf(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectLogConf %v", key)
	var obj interface{}
	var confExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, confExists, err = lbc.getNamespacedInformer(ns).appProtectLogConfLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []appprotect.Change
	var problems []appprotect.Problem

	if !confExists {
		glog.V(2).Infof("Deleting AppProtectLogConf: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.DeleteLogConf(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectLogConf: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.AddOrUpdateLogConf(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectChanges(changes)
	lbc.processAppProtectProblems(problems)
}

func (lbc *LoadBalancerController) syncAppProtectUserSig(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectUserSig %v", key)
	var obj interface{}
	var sigExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, sigExists, err = lbc.getNamespacedInformer(ns).appProtectUserSigLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var change appprotect.UserSigChange
	var problems []appprotect.Problem

	if !sigExists {
		glog.V(2).Infof("Deleting AppProtectUserSig: %v\n", key)

		change, problems = lbc.appProtectConfiguration.DeleteUserSig(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectUserSig: %v\n", key)

		change, problems = lbc.appProtectConfiguration.AddOrUpdateUserSig(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectUserSigChange(change)
	lbc.processAppProtectProblems(problems)
}

func getWAFPoliciesForAppProtectPolicy(pols []*conf_v1.Policy, key string) []*conf_v1.Policy {
	var policies []*conf_v1.Policy

	for _, pol := range pols {
		if pol.Spec.WAF != nil && isMatchingResourceRef(pol.Namespace, pol.Spec.WAF.ApPolicy, key) {
			policies = append(policies, pol)
		}
	}

	return policies
}

func getWAFPoliciesForAppProtectLogConf(pols []*conf_v1.Policy, key string) []*conf_v1.Policy {
	var policies []*conf_v1.Policy

	for _, pol := range pols {
		if pol.Spec.WAF != nil && pol.Spec.WAF.SecurityLog != nil && isMatchingResourceRef(pol.Namespace, pol.Spec.WAF.SecurityLog.ApLogConf, key) {
			policies = append(policies, pol)
		}
		if pol.Spec.WAF != nil && pol.Spec.WAF.SecurityLogs != nil {
			for _, logConf := range pol.Spec.WAF.SecurityLogs {
				if isMatchingResourceRef(pol.Namespace, logConf.ApLogConf, key) {
					policies = append(policies, pol)
				}
			}
		}
	}

	return policies
}

func isMatchingResourceRef(ownerNs, resRef, key string) bool {
	hasNamespace := strings.Contains(resRef, "/")
	if !hasNamespace {
		resRef = fmt.Sprintf("%v/%v", ownerNs, resRef)
	}
	return resRef == key
}

// addWAFPolicyRefs ensures the app protect resources that are referenced in policies exist.
// nolint:gocyclo
func (lbc *LoadBalancerController) addWAFPolicyRefs(
	apPolRef, logConfRef map[string]*unstructured.Unstructured,
	policies []*conf_v1.Policy,
) error {
	for _, pol := range policies {
		if pol.Spec.WAF == nil {
			continue
		}

		if pol.Spec.WAF.ApPolicy != "" {
			apPolKey := pol.Spec.WAF.ApPolicy
			if !strings.Contains(pol.Spec.WAF.ApPolicy, "/") {
				apPolKey = fmt.Sprintf("%v/%v", pol.Namespace, apPolKey)
			}

			apPolicy, err := lbc.appProtectConfiguration.GetAppResource(appprotect.PolicyGVK.Kind, apPolKey)
			if err != nil {
				return fmt.Errorf("WAF policy %q is invalid: %w", apPolKey, err)
			}
			apPolRef[apPolKey] = apPolicy
		}

		if pol.Spec.WAF.SecurityLog != nil && pol.Spec.WAF.SecurityLogs == nil {
			if pol.Spec.WAF.SecurityLog.ApLogConf != "" {
				logConfKey := pol.Spec.WAF.SecurityLog.ApLogConf
				if !strings.Contains(pol.Spec.WAF.SecurityLog.ApLogConf, "/") {
					logConfKey = fmt.Sprintf("%v/%v", pol.Namespace, logConfKey)
				}

				logConf, err := lbc.appProtectConfiguration.GetAppResource(appprotect.LogConfGVK.Kind, logConfKey)
				if err != nil {
					return fmt.Errorf("WAF policy %q is invalid: %w", logConfKey, err)
				}
				logConfRef[logConfKey] = logConf
			}
		}

		if pol.Spec.WAF.SecurityLogs != nil {
			for _, SecLog := range pol.Spec.WAF.SecurityLogs {
				if SecLog.ApLogConf != "" {
					logConfKey := SecLog.ApLogConf
					if !strings.Contains(SecLog.ApLogConf, "/") {
						logConfKey = fmt.Sprintf("%v/%v", pol.Namespace, logConfKey)
					}

					logConf, err := lbc.appProtectConfiguration.GetAppResource(appprotect.LogConfGVK.Kind, logConfKey)
					if err != nil {
						return fmt.Errorf("WAF policy %q is invalid: %w", logConfKey, err)
					}
					logConfRef[logConfKey] = logConf
				}
			}
		}
	}
	return nil
}

func (lbc *LoadBalancerController) getAppProtectLogConfAndDst(ing *networking.Ingress) ([]configs.AppProtectLog, error) {
	var apLogs []configs.AppProtectLog
	if _, exists := ing.Annotations[configs.AppProtectLogConfDstAnnotation]; !exists {
		return apLogs, fmt.Errorf("error: %v requires %v in %v", configs.AppProtectLogConfAnnotation, configs.AppProtectLogConfDstAnnotation, ing.Name)
	}

	logDsts := strings.Split(ing.Annotations[configs.AppProtectLogConfDstAnnotation], ",")
	logConfNsNs := appprotectcommon.ParseResourceReferenceAnnotationList(ing.Namespace, ing.Annotations[configs.AppProtectLogConfAnnotation])
	if len(logDsts) != len(logConfNsNs) {
		return apLogs, fmt.Errorf("error Validating App Protect Destination and Config for Ingress %v: LogConf and LogDestination must have equal number of items", ing.Name)
	}

	for i, logConfNsN := range logConfNsNs {
		logConf, err := lbc.appProtectConfiguration.GetAppResource(appprotect.LogConfGVK.Kind, logConfNsN)
		if err != nil {
			return apLogs, fmt.Errorf("error retrieving App Protect Log Config for Ingress %v: %w", ing.Name, err)
		}
		apLogs = append(apLogs, configs.AppProtectLog{
			LogConf: logConf,
			Dest:    logDsts[i],
		})
	}

	return apLogs, nil
}

func (lbc *LoadBalancerController) getAppProtectPolicy(ing *networking.Ingress) (apPolicy *unstructured.Unstructured, err error) {
	polNsN := appprotectcommon.ParseResourceReferenceAnnotation(ing.Namespace, ing.Annotations[configs.AppProtectPolicyAnnotation])

	apPolicy, err = lbc.appProtectConfiguration.GetAppResource(appprotect.PolicyGVK.Kind, polNsN)
	if err != nil {
		return nil, fmt.Errorf("error retrieving App Protect Policy for Ingress %v: %w", ing.Name, err)
	}

	return apPolicy, nil
}

func (lbc *LoadBalancerController) processAppProtectChanges(changes []appprotect.Change) {
	glog.V(3).Infof("Processing %v App Protect changes", len(changes))

	for _, c := range changes {
		if c.Op == appprotect.AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *appprotect.PolicyEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectPolicyAnnotation(namespace, name)

				for _, wafPol := range getWAFPoliciesForAppProtectPolicy(lbc.getAllPolicies(), namespace+"/"+name) {
					resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
				}

				resourceExes := lbc.createExtendedResources(resources)

				warnings, updateErr := lbc.configurator.AddOrUpdateAppProtectResource(impl.Obj, resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)
				lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
				lbc.recorder.Eventf(impl.Obj, api_v1.EventTypeNormal, "AddedOrUpdated", "AppProtectPolicy %v was added or updated", namespace+"/"+name)
			case *appprotect.LogConfEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectLogConfAnnotation(namespace, name)

				for _, wafPol := range getWAFPoliciesForAppProtectLogConf(lbc.getAllPolicies(), namespace+"/"+name) {
					resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
				}

				resourceExes := lbc.createExtendedResources(resources)

				warnings, updateErr := lbc.configurator.AddOrUpdateAppProtectResource(impl.Obj, resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)
				lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
				lbc.recorder.Eventf(impl.Obj, api_v1.EventTypeNormal, "AddedOrUpdated", "AppProtectLogConfig %v was added or updated", namespace+"/"+name)
			}
		} else if c.Op == appprotect.Delete {
			switch impl := c.Resource.(type) {
			case *appprotect.PolicyEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectPolicyAnnotation(namespace, name)

				for _, wafPol := range getWAFPoliciesForAppProtectPolicy(lbc.getAllPolicies(), namespace+"/"+name) {
					resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
				}

				resourceExes := lbc.createExtendedResources(resources)

				warnings, deleteErr := lbc.configurator.DeleteAppProtectPolicy(impl.Obj, resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)

				lbc.updateResourcesStatusAndEvents(resources, warnings, deleteErr)

			case *appprotect.LogConfEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectLogConfAnnotation(namespace, name)

				for _, wafPol := range getWAFPoliciesForAppProtectLogConf(lbc.getAllPolicies(), namespace+"/"+name) {
					resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
				}

				resourceExes := lbc.createExtendedResources(resources)

				warnings, deleteErr := lbc.configurator.DeleteAppProtectLogConf(impl.Obj, resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)

				lbc.updateResourcesStatusAndEvents(resources, warnings, deleteErr)
			}
		}
	}
}

func (lbc *LoadBalancerController) processAppProtectUserSigChange(change appprotect.UserSigChange) {
	var delPols []string
	var allIngExes []*configs.IngressEx
	var allMergeableIngresses []*configs.MergeableIngresses
	var allVsExes []*configs.VirtualServerEx
	var allResources []Resource

	for _, poladd := range change.PolicyAddsOrUpdates {
		resources := lbc.configuration.FindResourcesForAppProtectPolicyAnnotation(poladd.GetNamespace(), poladd.GetName())

		for _, wafPol := range getWAFPoliciesForAppProtectPolicy(lbc.getAllPolicies(), appprotectcommon.GetNsName(poladd)) {
			resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
		}

		resourceExes := lbc.createExtendedResources(resources)
		allIngExes = append(allIngExes, resourceExes.IngressExes...)
		allMergeableIngresses = append(allMergeableIngresses, resourceExes.MergeableIngresses...)
		allVsExes = append(allVsExes, resourceExes.VirtualServerExes...)
		allResources = append(allResources, resources...)
	}
	for _, poldel := range change.PolicyDeletions {
		resources := lbc.configuration.FindResourcesForAppProtectPolicyAnnotation(poldel.GetNamespace(), poldel.GetName())

		polNsName := appprotectcommon.GetNsName(poldel)
		for _, wafPol := range getWAFPoliciesForAppProtectPolicy(lbc.getAllPolicies(), polNsName) {
			resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
		}

		resourceExes := lbc.createExtendedResources(resources)
		allIngExes = append(allIngExes, resourceExes.IngressExes...)
		allMergeableIngresses = append(allMergeableIngresses, resourceExes.MergeableIngresses...)
		allVsExes = append(allVsExes, resourceExes.VirtualServerExes...)
		allResources = append(allResources, resources...)
		if len(resourceExes.IngressExes)+len(resourceExes.MergeableIngresses)+len(resourceExes.VirtualServerExes) > 0 {
			delPols = append(delPols, polNsName)
		}
	}

	warnings, err := lbc.configurator.RefreshAppProtectUserSigs(change.UserSigs, delPols, allIngExes, allMergeableIngresses, allVsExes)
	if err != nil {
		glog.Errorf("Error when refreshing App Protect Policy User defined signatures: %v", err)
	}
	lbc.updateResourcesStatusAndEvents(allResources, warnings, err)
}

func (lbc *LoadBalancerController) processAppProtectProblems(problems []appprotect.Problem) {
	glog.V(3).Infof("Processing %v App Protect problems", len(problems))

	for _, p := range problems {
		eventType := api_v1.EventTypeWarning
		lbc.recorder.Event(p.Object, eventType, p.Reason, p.Message)
	}
}

func (lbc *LoadBalancerController) cleanupUnwatchedAppWafResources(nsi *namespacedInformer) {
	for _, obj := range nsi.appProtectPolicyLister.List() {
		glog.V(3).Infof("Cleaning up unwatched appprotect policies in namespace: %v", nsi.namespace)
		appPol := obj.((*unstructured.Unstructured))
		namespace := appPol.GetNamespace()
		name := appPol.GetName()

		changes, problems := lbc.appProtectConfiguration.DeletePolicy(namespace + "/" + name)
		lbc.processAppProtectChanges(changes)
		lbc.processAppProtectProblems(problems)
	}
	for _, obj := range nsi.appProtectLogConfLister.List() {
		glog.V(3).Infof("Cleaning up unwatched approtect logconfs in namespace: %v", nsi.namespace)
		appLogConf := obj.((*unstructured.Unstructured))
		namespace := appLogConf.GetNamespace()
		name := appLogConf.GetName()

		changes, problems := lbc.appProtectConfiguration.DeleteLogConf(namespace + "/" + name)
		lbc.processAppProtectChanges(changes)
		lbc.processAppProtectProblems(problems)
	}
	for _, obj := range nsi.appProtectUserSigLister.List() {
		glog.V(3).Infof("Cleaning up unwatched usersigs in namespace: %v", nsi.namespace)
		appUserSig := obj.((*unstructured.Unstructured))
		namespace := appUserSig.GetNamespace()
		name := appUserSig.GetName()

		changes, problems := lbc.appProtectConfiguration.DeleteUserSig(namespace + "/" + name)
		lbc.processAppProtectUserSigChange(changes)
		lbc.processAppProtectProblems(problems)
	}
}
