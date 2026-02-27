package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotect"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// createPLMPolicyHandlers returns event handlers for APPolicy v1 resources watched in PLM mode.
// Update events are filtered to only enqueue when status.bundle changes.
func createPLMPolicyHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pol := obj.(*unstructured.Unstructured)
			nl.Debugf(lbc.Logger, "PLM: Adding APPolicy v1: %v/%v", pol.GetNamespace(), pol.GetName())
			lbc.syncQueue.queue.Add(task{Kind: plmPolicy, Key: pol.GetNamespace() + "/" + pol.GetName()})
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldPol := oldObj.(*unstructured.Unstructured)
			newPol := obj.(*unstructured.Unstructured)
			oldStatus := appprotect.ExtractPLMBundleStatus(oldPol)
			newStatus := appprotect.ExtractPLMBundleStatus(newPol)
			if oldStatus == newStatus {
				return
			}
			nl.Debugf(lbc.Logger, "PLM: APPolicy v1 bundle status changed: %v/%v state=%v", newPol.GetNamespace(), newPol.GetName(), newStatus.State)
			lbc.syncQueue.queue.Add(task{Kind: plmPolicy, Key: newPol.GetNamespace() + "/" + newPol.GetName()})
		},
		DeleteFunc: func(obj interface{}) {
			pol, ok := obj.(*unstructured.Unstructured)
			if !ok {
				// Handle tombstone
				if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					pol = d.Obj.(*unstructured.Unstructured)
				}
			}
			if pol != nil {
				nl.Debugf(lbc.Logger, "PLM: Deleting APPolicy v1: %v/%v", pol.GetNamespace(), pol.GetName())
				lbc.syncQueue.queue.Add(task{Kind: plmPolicy, Key: pol.GetNamespace() + "/" + pol.GetName()})
			}
		},
	}
}

// createPLMLogConfHandlers returns event handlers for APLogConf v1 resources watched in PLM mode.
func createPLMLogConfHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			conf := obj.(*unstructured.Unstructured)
			nl.Debugf(lbc.Logger, "PLM: Adding APLogConf v1: %v/%v", conf.GetNamespace(), conf.GetName())
			lbc.syncQueue.queue.Add(task{Kind: plmLogConf, Key: conf.GetNamespace() + "/" + conf.GetName()})
		},
		UpdateFunc: func(oldObj, obj interface{}) {
			oldConf := oldObj.(*unstructured.Unstructured)
			newConf := obj.(*unstructured.Unstructured)
			oldStatus := appprotect.ExtractPLMBundleStatus(oldConf)
			newStatus := appprotect.ExtractPLMBundleStatus(newConf)
			if oldStatus == newStatus {
				return
			}
			nl.Debugf(lbc.Logger, "PLM: APLogConf v1 bundle status changed: %v/%v state=%v", newConf.GetNamespace(), newConf.GetName(), newStatus.State)
			lbc.syncQueue.queue.Add(task{Kind: plmLogConf, Key: newConf.GetNamespace() + "/" + newConf.GetName()})
		},
		DeleteFunc: func(obj interface{}) {
			conf, ok := obj.(*unstructured.Unstructured)
			if !ok {
				if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					conf = d.Obj.(*unstructured.Unstructured)
				}
			}
			if conf != nil {
				nl.Debugf(lbc.Logger, "PLM: Deleting APLogConf v1: %v/%v", conf.GetNamespace(), conf.GetName())
				lbc.syncQueue.queue.Add(task{Kind: plmLogConf, Key: conf.GetNamespace() + "/" + conf.GetName()})
			}
		},
	}
}

// addPLMPolicyHandler registers a dynamic informer for APPolicy v1 resources.
func (nsi *namespacedInformer) addPLMPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.PLMPolicyGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.plmPolicyLister = informer.GetStore()
	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// addPLMLogConfHandler registers a dynamic informer for APLogConf v1 resources.
func (nsi *namespacedInformer) addPLMLogConfHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.dynInformerFactory.ForResource(appprotect.PLMLogConfGVR).Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.plmLogConfLister = informer.GetStore()
	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// syncPLMPolicy handles a PLM APPolicy v1 bundle-ready event:
// downloads the bundle from S3 and triggers NGINX reconfiguration.
func (lbc *LoadBalancerController) syncPLMPolicy(t task) {
	key := t.Key
	nl.Debugf(lbc.Logger, "PLM: Syncing APPolicy %v", key)

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	nsi := lbc.getNamespacedInformer(ns)
	if nsi == nil {
		nl.Errorf(lbc.Logger, "PLM: No informer found for namespace %v", ns)
		return
	}

	obj, exists, err := nsi.plmPolicyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(t, err)
		return
	}
	if !exists {
		// Resource deleted: bundle file stays on disk; NGINX continues to use it until next reload.
		nl.Debugf(lbc.Logger, "PLM: APPolicy %v deleted, no action needed", key)
		return
	}

	pol := obj.(*unstructured.Unstructured)
	bundleStatus := appprotect.ExtractPLMBundleStatus(pol)
	if bundleStatus.State != appprotect.BundleStateReady {
		nl.Debugf(lbc.Logger, "PLM: APPolicy %v not ready (state=%v), skipping", key, bundleStatus.State)
		return
	}

	bundleBytes, err := lbc.fetchPLMBundle(bundleStatus.Location)
	if err != nil {
		nl.Errorf(lbc.Logger, "PLM: Failed to fetch bundle for APPolicy %v (location=%v): %v", key, bundleStatus.Location, err)
		return
	}

	bundleName := pol.GetNamespace() + "_" + pol.GetName() + ".tgz"
	lbc.configurator.WritePLMBundle(bundleName, bundleBytes)
	nl.Debugf(lbc.Logger, "PLM: Wrote bundle for APPolicy %v to %v", key, bundleName)

	lbc.triggerPLMPolicyReload(pol)
}

// syncPLMLogConf handles a PLM APLogConf v1 bundle-ready event.
func (lbc *LoadBalancerController) syncPLMLogConf(t task) {
	key := t.Key
	nl.Debugf(lbc.Logger, "PLM: Syncing APLogConf %v", key)

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	nsi := lbc.getNamespacedInformer(ns)
	if nsi == nil {
		nl.Errorf(lbc.Logger, "PLM: No informer found for namespace %v", ns)
		return
	}

	obj, exists, err := nsi.plmLogConfLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(t, err)
		return
	}
	if !exists {
		nl.Debugf(lbc.Logger, "PLM: APLogConf %v deleted, no action needed", key)
		return
	}

	conf := obj.(*unstructured.Unstructured)
	bundleStatus := appprotect.ExtractPLMBundleStatus(conf)
	if bundleStatus.State != appprotect.BundleStateReady {
		nl.Debugf(lbc.Logger, "PLM: APLogConf %v not ready (state=%v), skipping", key, bundleStatus.State)
		return
	}

	bundleBytes, err := lbc.fetchPLMBundle(bundleStatus.Location)
	if err != nil {
		nl.Errorf(lbc.Logger, "PLM: Failed to fetch bundle for APLogConf %v (location=%v): %v", key, bundleStatus.Location, err)
		return
	}

	bundleName := conf.GetNamespace() + "_" + conf.GetName() + ".tgz"
	lbc.configurator.WritePLMBundle(bundleName, bundleBytes)
	nl.Debugf(lbc.Logger, "PLM: Wrote bundle for APLogConf %v to %v", key, bundleName)

	lbc.triggerPLMLogConfReload(conf)
}

// fetchPLMBundle downloads a bundle from PLM storage.
// location format: "s3://bucket/key" or "bucket/key" (e.g. "s3://default/bundles/policy.tgz")
func (lbc *LoadBalancerController) fetchPLMBundle(location string) ([]byte, error) {
	location = strings.TrimPrefix(location, "s3://")
	parts := strings.SplitN(location, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid bundle location %q: expected \"bucket/key\" format", location)
	}
	bucket, key := parts[0], parts[1]
	return lbc.wafFetcher.GetObject(context.Background(), bucket, key)
}

// triggerPLMPolicyReload finds all VS/Ingress resources using the given APPolicy and triggers NGINX reload.
func (lbc *LoadBalancerController) triggerPLMPolicyReload(pol *unstructured.Unstructured) {
	namespace := pol.GetNamespace()
	name := pol.GetName()
	key := namespace + "/" + name

	resources := lbc.configuration.FindResourcesForAppProtectPolicyAnnotation(namespace, name)
	for _, wafPol := range getWAFPoliciesForAppProtectPolicy(lbc.getAllPolicies(), key) {
		resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
	}

	if len(resources) == 0 {
		nl.Debugf(lbc.Logger, "PLM: No resources reference APPolicy %v, skipping reload", key)
		return
	}

	resourceExes := lbc.createExtendedResources(resources)
	warnings, err := lbc.configurator.AddOrUpdateAppProtectResource(pol, resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, err)
}

// triggerPLMLogConfReload finds all VS/Ingress resources using the given APLogConf and triggers NGINX reload.
func (lbc *LoadBalancerController) triggerPLMLogConfReload(conf *unstructured.Unstructured) {
	namespace := conf.GetNamespace()
	name := conf.GetName()
	key := namespace + "/" + name

	resources := lbc.configuration.FindResourcesForAppProtectLogConfAnnotation(namespace, name)
	for _, wafPol := range getWAFPoliciesForAppProtectLogConf(lbc.getAllPolicies(), key) {
		resources = append(resources, lbc.configuration.FindResourcesForPolicy(wafPol.Namespace, wafPol.Name)...)
	}

	if len(resources) == 0 {
		nl.Debugf(lbc.Logger, "PLM: No resources reference APLogConf %v, skipping reload", key)
		return
	}

	resourceExes := lbc.createExtendedResources(resources)
	warnings, err := lbc.configurator.AddOrUpdateAppProtectResource(conf, resourceExes.IngressExes, resourceExes.MergeableIngresses, resourceExes.VirtualServerExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, err)
}
