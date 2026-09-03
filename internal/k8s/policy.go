package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/wafbundle"
	"github.com/nginx/kubernetes-ingress/internal/helpers"
	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotect"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func (nsi *namespacedInformer) addPolicyHandler(handlers cache.ResourceEventHandlerFuncs) error {
	informer := nsi.confSharedInformerFactory.K8s().V1().Policies().Informer()
	if _, err := informer.AddEventHandler(handlers); err != nil {
		return fmt.Errorf("failed to add Policy event handler: %w", err)
	}
	nsi.policyLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
	return nil
}

func (lbc *LoadBalancerController) syncPolicy(task task) {
	key := task.Key
	var obj interface{}
	var polExists bool
	var err error

	ns, n, _ := cache.SplitMetaNamespaceKey(key)
	l := lbc.Logger.With(logNamespaceKey, ns, logKindKey, policyKind, logNameKey, n)
	nsi := lbc.getNamespacedInformer(ns)
	if nsi == nil {
		return
	}
	obj, polExists, err = nsi.policyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	nl.Debugf(l, "Adding, Updating or Deleting Policy: %v\n", key)

	if polExists && lbc.HasCorrectIngressClass(obj) {
		pol := obj.(*conf_v1.Policy)
		err := validation.ValidatePolicy(pol, lbc.policyValidationConfig())
		if err != nil {
			msg := fmt.Sprintf("Policy %v/%v is invalid and was rejected: %v", pol.Namespace, pol.Name, err)
			lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonRejected, msg)

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
						nl.Errorf(l, "Failed to update policy %s status: %v", key, err)
					}
				}
			}
		} else {
			msg := fmt.Sprintf("Policy %v/%v was added or updated", pol.Namespace, pol.Name)
			lbc.recorder.Event(pol, api_v1.EventTypeNormal, nl.EventReasonAddedOrUpdated, msg)

			if lbc.reportCustomResourceStatusEnabled() {
				// If the policy uses bundle sources and the files are not yet on disk,
				// set Warning instead of Valid. performInitialFetch will update with the
				// specific error on failure, or the poller's syncCb will trigger a re-sync
				// that sets Valid after a successful fetch.
				state := conf_v1.StateValid
				reason := "AddedOrUpdated"
				statusMsg := msg
				if lbc.hasBundleSource(pol) && !lbc.bundleFilesReady(pol) {
					state = conf_v1.StateWarning
					reason = "BundlePending"
					statusMsg = fmt.Sprintf("Policy %v/%v: WAF bundle fetch pending", pol.Namespace, pol.Name)
				}
				// Defer policy status updates during startup to avoid serial
				// API calls that block readiness. See flushPendingStatusesAsync().
				if !lbc.isNginxReady {
					lbc.pendingStatusPolicies = append(lbc.pendingStatusPolicies, pendingPolicyStatus{
						pol: pol, state: state, reason: reason, message: statusMsg,
					})
				} else {
					err = lbc.statusUpdater.UpdatePolicyStatus(pol, state, reason, statusMsg)
					if err != nil {
						nl.Errorf(l, "Failed to update policy %s status: %v", key, err)
					}
				}
			}
		}
	}

	// WAF bundle source management — initial fetch + poller reconciliation.
	// Failures are isolated to this policy and never block other resources.
	if lbc.bundlePollerMgr != nil {
		if polExists && lbc.HasCorrectIngressClass(obj) {
			pol := obj.(*conf_v1.Policy)
			if pol.Spec.WAF != nil && lbc.hasBundleSource(pol) {
				lbc.syncWAFBundleSource(pol)
			} else {
				lbc.bundlePollerMgr.StopPoller(key)
				lbc.cleanupFetchedBundles(key)
			}
		} else {
			lbc.bundlePollerMgr.StopPoller(key)
			lbc.cleanupFetchedBundles(key)
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
		// If Ingress support for a policy type is added in the future, the policy Spec must also be added in IsPolicySupportedOnIngress() in internal/configs/policy.go.
		case *IngressConfiguration:
			if !polExists {
				continue
			}
			pol := obj.(*conf_v1.Policy)
			if !configs.IsPolicySupportedOnIngress(pol) {
				msg := fmt.Sprintf("Policy %s/%s has unsupported type on Ingress resource %s/%s",
					pol.Namespace, pol.Name, impl.Ingress.Namespace, impl.Ingress.Name)
				nl.Error(l, msg)
				lbc.recorder.Event(impl.Ingress, api_v1.EventTypeWarning, nl.EventReasonRejected, msg)
				// The reload still proceeds so that generatePolicies() surfaces the error
				// (ErrorReturn 500) consistently regardless of which path triggered the sync.
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

// parseAPRef splits a "namespace/name" App Protect reference. The namespace
// defaults to polNamespace when the reference is unqualified.
func parseAPRef(ref, polNamespace string) (namespace, name string) {
	if parsedNs, parsedName, err := helpers.ParseNamespaceName(ref); err == nil {
		return parsedNs, parsedName
	}
	return polNamespace, ref
}

// effectivePLMPolicyRef returns the (namespace, name) that NIC should fetch as a PLM
// policy bundle, or ok=false when the Policy has no PLM-eligible reference. Under
// -plm-storage-url an apPolicy reference is fetched as a PLM bundle; apBundleSource
// remains the HTTPS/NIM/N1C path.
func (lbc *LoadBalancerController) effectivePLMPolicyRef(pol *conf_v1.Policy) (namespace, name string, ok bool) {
	if !lbc.plmEnabled || pol.Spec.WAF == nil || pol.Spec.WAF.ApPolicy == "" {
		return "", "", false
	}
	ns, n := parseAPRef(pol.Spec.WAF.ApPolicy, pol.Namespace)
	return ns, n, true
}

// effectivePLMLogRef is the securityLogs counterpart of effectivePLMPolicyRef.
func (lbc *LoadBalancerController) effectivePLMLogRef(sl *conf_v1.SecurityLog, polNamespace string) (namespace, name string, ok bool) {
	if !lbc.plmEnabled || sl == nil || sl.ApLogConf == "" {
		return "", "", false
	}
	ns, n := parseAPRef(sl.ApLogConf, polNamespace)
	return ns, n, true
}

// hasBundleSource reports whether a Policy has any bundle source fields that require
// fetching: either a top-level apBundleSource or any securityLogs entry with an
// apLogBundleSource. Under PLM, apPolicy/apLogConf references also require fetching.
func (lbc *LoadBalancerController) hasBundleSource(pol *conf_v1.Policy) bool {
	if pol.Spec.WAF == nil {
		return false
	}
	if pol.Spec.WAF.ApBundleSource != nil {
		return true
	}
	if _, _, ok := lbc.effectivePLMPolicyRef(pol); ok {
		return true
	}
	for _, sl := range pol.Spec.WAF.SecurityLogs {
		if sl != nil && sl.ApLogBundleSource != nil {
			return true
		}
		if _, _, ok := lbc.effectivePLMLogRef(sl, pol.Namespace); ok {
			return true
		}
	}
	return false
}

// bundleFilesReady reports whether all expected bundle files for pol exist on disk.
// Returns true for policies that have no bundle sources.
// A false return means at least one bundle is still pending its initial fetch,
// so syncPolicy should not set the policy status to Valid prematurely.
func (lbc *LoadBalancerController) bundleFilesReady(pol *conf_v1.Policy) bool {
	if pol.Spec.WAF == nil || lbc.wafBundlePath == "" {
		return true
	}
	if lbc.policyBundleExpected(pol) {
		path := filepath.Join(lbc.wafBundlePath,
			wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, "policy"))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	for idx, sl := range pol.Spec.WAF.SecurityLogs {
		if !lbc.logBundleExpected(sl, pol.Namespace) {
			continue
		}
		path := filepath.Join(lbc.wafBundlePath,
			wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, fmt.Sprintf("log_%d", idx)))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// policyBundleExpected reports whether syncWAFBundleSource will fetch a policy bundle
// for pol. Mirrors the branch selection in syncWAFBundleSource so that bundleFilesReady
// only demands a file when one is actually being produced.
func (lbc *LoadBalancerController) policyBundleExpected(pol *conf_v1.Policy) bool {
	if pol.Spec.WAF == nil {
		return false
	}
	if pol.Spec.WAF.ApBundleSource != nil {
		return true
	}
	_, _, ok := lbc.effectivePLMPolicyRef(pol)
	return ok
}

// logBundleExpected is the securityLogs counterpart of policyBundleExpected.
func (lbc *LoadBalancerController) logBundleExpected(sl *conf_v1.SecurityLog, polNamespace string) bool {
	if sl == nil {
		return false
	}
	if sl.ApLogBundleSource != nil {
		return true
	}
	_, _, ok := lbc.effectivePLMLogRef(sl, polNamespace)
	return ok
}

// syncWAFBundleSource performs initial bundle fetches (if files are absent on disk)
// and reconciles the background poller for the given WAF policy.
// Initial fetches are performed asynchronously to avoid blocking the sync queue.
func (lbc *LoadBalancerController) syncWAFBundleSource(pol *conf_v1.Policy) {
	polKey := pol.Namespace + "/" + pol.Name

	// Reconcile the poller on every return path so non-PLM sources with
	// EnablePolling=true still retry after a failed initial fetch.
	defer lbc.reconcileBundlePoller(pol, polKey)

	if !lbc.syncPolicyBundle(pol, polKey) {
		return
	}

	for idx, sl := range pol.Spec.WAF.SecurityLogs {
		if !lbc.syncLogBundle(pol, polKey, sl, idx) {
			return
		}
	}
}

// reconcileBundlePoller sets up the background poller for pol's bundle sources.
func (lbc *LoadBalancerController) reconcileBundlePoller(pol *conf_v1.Policy, polKey string) {
	var policyAuth *wafbundle.BundleAuth
	if bs := pol.Spec.WAF.ApBundleSource; bs != nil {
		if a, err := lbc.resolveWAFBundleAuth(bs, pol.Namespace); err == nil {
			policyAuth = a
		}
	}

	sources := lbc.buildPollSources(pol, policyAuth)
	if len(sources) > 0 {
		lbc.bundlePollerMgr.ReconcilePoller(polKey, sources)
	} else {
		lbc.bundlePollerMgr.StopPoller(polKey)
	}
}

// syncPolicyBundle handles the top-level policy bundle for pol. It returns true when
// processing may continue (bundle up-to-date or no bundle to fetch) and false when an
// async fetch has been kicked off or a fatal error was recorded — in either case the
// caller must not proceed with the securityLogs loop or poller reconciliation.
func (lbc *LoadBalancerController) syncPolicyBundle(pol *conf_v1.Policy, polKey string) bool {
	// PLM policy bundle: reference by APPolicy CR, cluster-wide credentials.
	if ns, name, ok := lbc.effectivePLMPolicyRef(pol); ok {
		status := lbc.resolvePLMBundleStatus(pol, ns, name, wafbundle.PolicyBundle)
		if status == nil {
			return false
		}
		policyPath := filepath.Join(lbc.wafBundlePath,
			wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, "policy"))
		if !lbc.bundleNeedsFetch(policyPath, status) {
			return true
		}
		req := plmFetchRequest(ns, name, wafbundle.PolicyBundle, status)
		lbc.fetchBundleAsyncRaw(pol, req, policyPath, wafbundle.PolicyBundle)
		return false
	}

	// HTTPS/NIM/N1C policy bundle via apBundleSource.
	bs := pol.Spec.WAF.ApBundleSource
	if bs == nil {
		return true
	}
	auth, err := lbc.resolveWAFBundleAuth(bs, pol.Namespace)
	if err != nil {
		msg := fmt.Sprintf("WAF bundle secret resolution failed: %v", err)
		lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonInvalidConfiguration, msg)
		if lbc.reportCustomResourceStatusEnabled() {
			if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateWarning, nl.EventReasonInvalidConfiguration, msg); updateErr != nil {
				nl.Errorf(lbc.Logger, "Failed to update policy %s status: %v", polKey, updateErr)
			}
		}
		return false
	}
	policyPath := filepath.Join(lbc.wafBundlePath,
		wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, "policy"))
	if !lbc.bundleNeedsFetch(policyPath, nil) {
		return true
	}
	lbc.fetchBundleAsync(pol, bs, auth, policyPath, wafbundle.PolicyBundle)
	return false
}

// syncLogBundle handles one securityLogs entry. Same true/false semantics as syncPolicyBundle.
func (lbc *LoadBalancerController) syncLogBundle(pol *conf_v1.Policy, polKey string, sl *conf_v1.SecurityLog, idx int) bool {
	logFilename := wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, fmt.Sprintf("log_%d", idx))
	logPath := filepath.Join(lbc.wafBundlePath, logFilename)

	if ns, name, ok := lbc.effectivePLMLogRef(sl, pol.Namespace); ok {
		status := lbc.resolvePLMBundleStatus(pol, ns, name, wafbundle.LogProfileBundle)
		if status == nil {
			return true // continue to next log entry; warning already recorded
		}
		if !lbc.bundleNeedsFetch(logPath, status) {
			return true
		}
		req := plmFetchRequest(ns, name, wafbundle.LogProfileBundle, status)
		lbc.fetchBundleAsyncRaw(pol, req, logPath, wafbundle.LogProfileBundle)
		return false
	}

	if sl == nil || sl.ApLogBundleSource == nil {
		return true
	}
	logAuth, logErr := lbc.resolveWAFBundleAuth(sl.ApLogBundleSource, pol.Namespace)
	if logErr != nil {
		msg := fmt.Sprintf("WAF log profile bundle: invalid or missing secret: %v", logErr)
		lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonInvalidConfiguration, msg)
		if lbc.reportCustomResourceStatusEnabled() {
			if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateWarning, nl.EventReasonInvalidConfiguration, msg); updateErr != nil {
				nl.Errorf(lbc.Logger, "Failed to update policy %s status: %v", polKey, updateErr)
			}
		}
		return true // continue: mirrors previous non-PLM behavior
	}
	if !lbc.bundleNeedsFetch(logPath, nil) {
		return true
	}
	lbc.fetchBundleAsync(pol, sl.ApLogBundleSource, logAuth, logPath, wafbundle.LogProfileBundle)
	return false
}

// plmFetchRequest constructs a wafbundle.Request for a PLM bundle. Location and
// checksum come from the referenced APPolicy/APLogConf's .status.bundle; the S3 config
// (endpoint, credentials, TLS) is resolved by PLMAwareFetcher at fetch time.
func plmFetchRequest(ns, name string, kind wafbundle.BundleType, status *wafbundle.BundleStatus) wafbundle.Request {
	return wafbundle.Request{
		Type:             wafbundle.SourceTypePLM,
		BundleKind:       kind,
		URL:              status.Location,
		Name:             name,
		Namespace:        ns,
		ExpectedChecksum: status.SHA256,
	}
}

// resolvePLMBundleStatus reads the referenced APPolicy/APLogConf CR's .status.bundle.
// It returns a non-nil, Ready BundleStatus on success, or nil after recording a Warning
// event + policy status when the CR is missing, malformed, or its bundle is not yet ready.
// A nil return means "do not fetch now"; the next APPolicy status change re-enqueues the policy.
func (lbc *LoadBalancerController) resolvePLMBundleStatus(pol *conf_v1.Policy, ns, name string, kind wafbundle.BundleType) *wafbundle.BundleStatus {
	polKey := pol.Namespace + "/" + pol.Name

	if ns == "" {
		ns = pol.Namespace
	}
	refKey := ns + "/" + name

	gvkKind := appprotect.PolicyGVK.Kind
	if kind == wafbundle.LogProfileBundle {
		gvkKind = appprotect.LogConfGVK.Kind
	}

	nsi := lbc.getNamespacedInformer(ns)
	if nsi == nil {
		lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: namespace %q is not watched", ns))
		return nil
	}

	var store cache.Store
	if kind == wafbundle.LogProfileBundle {
		store = nsi.appProtectLogConfLister
	} else {
		store = nsi.appProtectPolicyLister
	}
	if store == nil {
		lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: %s informer is unavailable", gvkKind))
		return nil
	}

	obj, exists, err := store.GetByKey(refKey)
	if err != nil {
		lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: cannot read %s %q: %v", gvkKind, refKey, err))
		return nil
	}
	if !exists {
		lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: %s %q not found", gvkKind, refKey))
		return nil
	}

	apResource, ok := obj.(*unstructured.Unstructured)
	if !ok {
		lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: %s %q has unexpected type %T", gvkKind, refKey, obj))
		return nil
	}

	var status *wafbundle.BundleStatus
	if kind == wafbundle.LogProfileBundle {
		parsed, parseErr := wafbundle.ParseAPLogConfStatus(apResource)
		if parseErr != nil {
			lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: cannot read %s %q status: %v", gvkKind, refKey, parseErr))
			return nil
		}
		status = parsed.Bundle
	} else {
		parsed, parseErr := wafbundle.ParseAPPolicyStatus(apResource)
		if parseErr != nil {
			lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: cannot read %s %q status: %v", gvkKind, refKey, parseErr))
			return nil
		}
		status = parsed.Bundle
	}

	if !status.IsReady() {
		state := "pending"
		if status != nil && status.State != "" {
			state = status.State
		}
		lbc.recordPLMPending(pol, fmt.Sprintf("WAF PLM bundle: %s %q bundle state is %q, not ready", gvkKind, refKey, state))
		return nil
	}

	nl.Debugf(lbc.Logger, "Resolved PLM bundle for policy %s from %s %q: location=%s sha256=%s",
		polKey, gvkKind, refKey, status.Location, status.SHA256)
	return status
}

// recordPLMPending records a Warning event and (when enabled) a StateWarning policy status
// for a PLM bundle that is not yet available. It does not fail the controller.
func (lbc *LoadBalancerController) recordPLMPending(pol *conf_v1.Policy, msg string) {
	polKey := pol.Namespace + "/" + pol.Name
	nl.Debugf(lbc.Logger, "PLM bundle pending for policy %s: %s", polKey, msg)
	lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonBundleFetchFailed, msg)
	if lbc.reportCustomResourceStatusEnabled() {
		if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateWarning, nl.EventReasonBundleFetchFailed, msg); updateErr != nil {
			nl.Errorf(lbc.Logger, "Failed to update policy %s status: %v", polKey, updateErr)
		}
	}
}

// bundleNeedsFetch reports whether the bundle at path must be (re-)fetched. A missing
// file always needs a fetch. For PLM (plmStatus non-nil), a fetch is also needed when the
// on-disk bundle's SHA-256 differs from the checksum PLM published, so recompiled policies
// are picked up event-driven. For non-PLM sources the initial fetch is triggered only when
// the file is absent (updates are handled by the poller).
func (lbc *LoadBalancerController) bundleNeedsFetch(path string, plmStatus *wafbundle.BundleStatus) bool {
	if plmStatus == nil {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	}
	// PLM: compare the on-disk bundle against the checksum PLM published.
	data, err := os.ReadFile(path) // #nosec G304, path is controller-constructed (bundle destination dir + generated filename
	if err != nil {
		return true // missing or unreadable — re-fetch
	}
	return !strings.EqualFold(wafbundle.ComputeChecksum(data), plmStatus.SHA256)
}

// policyNeedsPLMBundleFetch reports whether any PLM policy or log bundle for
// pol is missing or differs from the checksum published by its referenced AP resource.
func (lbc *LoadBalancerController) policyNeedsPLMBundleFetch(pol *conf_v1.Policy) bool {
	if pol.Spec.WAF == nil || lbc.wafBundlePath == "" {
		return false
	}

	if ns, name, ok := lbc.effectivePLMPolicyRef(pol); ok {
		status := lbc.resolvePLMBundleStatus(pol, ns, name, wafbundle.PolicyBundle)
		path := filepath.Join(lbc.wafBundlePath, wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, "policy"))
		if status != nil && lbc.bundleNeedsFetch(path, status) {
			return true
		}
	}

	for index, securityLog := range pol.Spec.WAF.SecurityLogs {
		ns, name, ok := lbc.effectivePLMLogRef(securityLog, pol.Namespace)
		if !ok {
			continue
		}
		status := lbc.resolvePLMBundleStatus(pol, ns, name, wafbundle.LogProfileBundle)
		path := filepath.Join(lbc.wafBundlePath, wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, fmt.Sprintf("log_%d", index)))
		if status != nil && lbc.bundleNeedsFetch(path, status) {
			return true
		}
	}

	return false
}

// fetchBundleAsync launches performInitialFetch for an apBundleSource in a background
// goroutine. It re-enqueues the policy only when the fetch succeeds; non-PLM sources
// retry through their configured poller interval. PLM fetches use fetchBundleAsyncRaw.
func (lbc *LoadBalancerController) fetchBundleAsync(
	pol *conf_v1.Policy,
	bs *conf_v1.BundleSource,
	auth *wafbundle.BundleAuth,
	path string,
	kind wafbundle.BundleType,
) {
	req := lbc.buildFetchRequest(bs, auth, kind)
	timeout := wafbundle.DefaultTimeout
	if bs.Timeout != nil && bs.Timeout.Duration > 0 {
		timeout = bs.Timeout.Duration
	}
	lbc.fetchBundleAsyncRawWithTimeout(pol, req, path, kind, timeout)
}

// fetchBundleAsyncRaw launches an async fetch from an already-constructed Request
// (used for PLM, where the request is built from AP CR status rather than a BundleSource).
func (lbc *LoadBalancerController) fetchBundleAsyncRaw(
	pol *conf_v1.Policy,
	req wafbundle.Request,
	path string,
	kind wafbundle.BundleType,
) {
	lbc.fetchBundleAsyncRawWithTimeout(pol, req, path, kind, wafbundle.DefaultTimeout)
}

func (lbc *LoadBalancerController) fetchBundleAsyncRawWithTimeout(
	pol *conf_v1.Policy,
	req wafbundle.Request,
	path string,
	kind wafbundle.BundleType,
	timeout time.Duration,
) {
	go func() {
		if lbc.performInitialFetch(pol, req, path, kind, timeout) {
			lbc.AddSyncQueue(pol)
		}
	}()
}

// performInitialFetch synchronously fetches a single bundle and writes it to destPath.
// It reports whether the policy should be re-enqueued: true when the bundle was
// written (or was unchanged), false when the fetch/write failed. On failure it
// records a Warning status; PLM retries are triggered by AP resource status or
// configured storage Secret updates, while non-PLM retries use the poller.
func (lbc *LoadBalancerController) performInitialFetch(
	pol *conf_v1.Policy,
	req wafbundle.Request,
	destPath string,
	kind wafbundle.BundleType,
	timeout time.Duration,
) bool {
	polKey := pol.Namespace + "/" + pol.Name
	l := lbc.Logger.With(logNamespaceKey, pol.Namespace, logKindKey, policyKind, logNameKey, pol.Name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result wafbundle.Result
	var fetchErr error
	if kind == wafbundle.LogProfileBundle {
		result, fetchErr = lbc.bundleFetcher.FetchLogProfileBundle(ctx, &req)
	} else {
		result, fetchErr = lbc.bundleFetcher.FetchPolicyBundle(ctx, &req)
	}

	if fetchErr != nil {
		msg := fmt.Sprintf("WAF bundle not active: initial fetch failed: %v", fetchErr)
		nl.Warnf(l, "Initial WAF bundle fetch failed for policy %s (will retry): %v", polKey, fetchErr)
		lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonBundleFetchFailed, msg)
		if lbc.reportCustomResourceStatusEnabled() {
			if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateWarning, nl.EventReasonBundleFetchFailed, msg); updateErr != nil {
				nl.Errorf(l, "Failed to update policy %s status: %v", polKey, updateErr)
			}
		}
		return false
	}
	if result.Unchanged {
		return true
	}
	if err := wafbundle.WriteAtomicBundle(destPath, result.Data); err != nil {
		msg := "WAF bundle not active: failed to write bundle to disk"
		nl.Errorf(l, "Failed to write WAF bundle for policy %s: %v", polKey, err)
		lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonBundleFetchFailed, msg)
		if lbc.reportCustomResourceStatusEnabled() {
			if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateWarning, nl.EventReasonBundleFetchFailed, msg); updateErr != nil {
				nl.Errorf(l, "Failed to update policy %s status: %v", polKey, updateErr)
			}
		}
		return false
	}

	// Update status to Valid after successful bundle write.
	if lbc.reportCustomResourceStatusEnabled() {
		if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateValid, "BundleReady", "WAF bundle fetched and ready"); updateErr != nil {
			nl.Errorf(l, "Failed to update policy %s status: %v", polKey, updateErr)
		}
	}
	return true
}

// handleBundleRefreshFailure surfaces refresh-path fetch failures as policy warnings.
// Existing bundle files remain active and continue protecting traffic.
func (lbc *LoadBalancerController) handleBundleRefreshFailure(polKey string, fetchErr error) {
	ns, n, _ := cache.SplitMetaNamespaceKey(polKey)
	l := lbc.Logger.With(logNamespaceKey, ns, logKindKey, policyKind, logNameKey, n)

	parts := strings.SplitN(polKey, "/", 2)
	if len(parts) != 2 {
		nl.Warnf(l, "invalid policy key for bundle refresh failure callback: %q", polKey)
		return
	}

	nsi := lbc.getNamespacedInformer(parts[0])
	if nsi == nil {
		nl.Debugf(l, "skipping refresh failure status update for unwatched namespace in key %q", polKey)
		return
	}

	obj, exists, err := nsi.policyLister.GetByKey(polKey)
	if err != nil {
		nl.Errorf(l, "failed to get policy %s for refresh failure handling: %v", polKey, err)
		return
	}
	if !exists {
		return
	}

	pol, ok := obj.(*conf_v1.Policy)
	if !ok {
		nl.Errorf(l, "unexpected object type for policy key %s during refresh failure handling", polKey)
		return
	}
	if !lbc.HasCorrectIngressClass(pol) {
		return
	}

	msg := fmt.Sprintf("Failed to fetch new bundle, keeping existing active bundle: %v", fetchErr)
	lbc.recorder.Event(pol, api_v1.EventTypeWarning, nl.EventReasonBundleFetchFailed, msg)
	if lbc.reportCustomResourceStatusEnabled() {
		if updateErr := lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateWarning, nl.EventReasonBundleFetchFailed, msg); updateErr != nil {
			nl.Errorf(l, "Failed to update policy %s status: %v", polKey, updateErr)
		}
	}
}

// buildPollSources constructs the PollSource slice for a policy's bundle sources.
// buildPollSources constructs the PollSource slice for a policy's bundle sources.
// PLM sources are not represented here — PLM updates are event-driven via the
// APPolicy/APLogConf status watch, not polled — and the CRD only exposes
// apBundleSource for HTTPS/NIM/N1C, so no PLM entries can appear.
func (lbc *LoadBalancerController) buildPollSources(pol *conf_v1.Policy, policyAuth *wafbundle.BundleAuth) []wafbundle.PollSource {
	var sources []wafbundle.PollSource

	if bs := pol.Spec.WAF.ApBundleSource; bs != nil && bs.EnablePolling {
		sources = append(sources, wafbundle.PollSource{
			Filename: wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, "policy"),
			Kind:     wafbundle.PolicyBundle,
			Req:      lbc.buildFetchRequest(bs, policyAuth, wafbundle.PolicyBundle),
			Interval: effectivePollInterval(bs),
		})
	}

	for idx, sl := range pol.Spec.WAF.SecurityLogs {
		if sl == nil || sl.ApLogBundleSource == nil || !sl.ApLogBundleSource.EnablePolling {
			continue
		}
		logAuth, err := lbc.resolveWAFBundleAuth(sl.ApLogBundleSource, pol.Namespace)
		if err != nil {
			nl.Warnf(lbc.Logger, "Skipping log bundle poller for %s/%s log %d: %v", pol.Namespace, pol.Name, idx, err)
			continue
		}
		sources = append(sources, wafbundle.PollSource{
			Filename: wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, fmt.Sprintf("log_%d", idx)),
			Kind:     wafbundle.LogProfileBundle,
			Req:      lbc.buildFetchRequest(sl.ApLogBundleSource, logAuth, wafbundle.LogProfileBundle),
			Interval: effectivePollInterval(sl.ApLogBundleSource),
		})
	}

	return sources
}

// buildFetchRequest constructs a wafbundle.Request from a BundleSource and resolved auth.
// Used for HTTPS/NIM/N1C sources; PLM requests are constructed by plmFetchRequest at the
// point where AP CR status is resolved.
func (lbc *LoadBalancerController) buildFetchRequest(bs *conf_v1.BundleSource, auth *wafbundle.BundleAuth, kind wafbundle.BundleType) wafbundle.Request {
	srcType := wafbundle.SourceTypeHTTPS
	switch bs.Type {
	case conf_v1.BundleSourceTypeN1C:
		srcType = wafbundle.SourceTypeN1C
	case conf_v1.BundleSourceTypeNIM:
		srcType = wafbundle.SourceTypeNIM
	}
	req := wafbundle.Request{
		Type:               srcType,
		BundleKind:         kind,
		URL:                bs.URL,
		Auth:               auth,
		Name:               bs.Name,
		Namespace:          bs.Namespace,
		NAPRelease:         lbc.wafVersion,
		InsecureSkipVerify: bs.InsecureSkipVerify,
		VerifyChecksum:     bs.VerifyChecksum,
	}
	if auth != nil {
		req.TLSCA = auth.TLSCA
	}
	if bs.Timeout != nil {
		req.Timeout = bs.Timeout.Duration
	}
	if bs.RetryAttempts != nil {
		req.RetryAttempts = *bs.RetryAttempts
	}
	return req
}

// resolveWAFBundleAuth resolves authentication credentials from the referenced Secret.
func (lbc *LoadBalancerController) resolveWAFBundleAuth(bs *conf_v1.BundleSource, namespace string) (*wafbundle.BundleAuth, error) {
	if bs.Secret == "" && bs.TrustedCertSecret == "" {
		return nil, nil
	}

	auth := &wafbundle.BundleAuth{}

	if bs.Secret != "" {
		if err := lbc.resolveWAFBundleSecret(bs, namespace, auth); err != nil {
			return nil, err
		}
	}

	if bs.TrustedCertSecret != "" {
		if err := lbc.resolveWAFTrustedCert(bs.TrustedCertSecret, namespace, auth); err != nil {
			return nil, err
		}
	}

	if auth.APIToken == "" && auth.BearerToken == "" && auth.Username == "" && auth.TLSCert == nil && auth.TLSKey == nil && auth.TLSCA == nil {
		return nil, nil
	}

	return auth, nil
}

// resolveWAFBundleSecret resolves the primary auth secret into the given BundleAuth.
func (lbc *LoadBalancerController) resolveWAFBundleSecret(bs *conf_v1.BundleSource, namespace string, auth *wafbundle.BundleAuth) error {
	secretKey := namespace + "/" + bs.Secret
	ref := lbc.secretStore.GetSecret(secretKey)
	if ref == nil || ref.Error != nil {
		var msg string
		if ref != nil {
			msg = ref.Error.Error()
		}
		return fmt.Errorf("secret %s not found or invalid: %s", secretKey, msg)
	}

	if bs.Type == conf_v1.BundleSourceTypeN1C || bs.Type == conf_v1.BundleSourceTypeNIM {
		if err := secrets.ValidateWAFBundleSecret(ref.Secret); err != nil {
			return fmt.Errorf("secret %s: %w", secretKey, err)
		}
	} else { // HTTPS
		if err := secrets.ValidateTLSSecret(ref.Secret); err != nil {
			return fmt.Errorf("secret %s: %w", secretKey, err)
		}
	}

	data := ref.Secret.Data
	auth.TLSCA = data[secrets.CAKey]

	switch bs.Type {
	case conf_v1.BundleSourceTypeN1C:
		tok := string(data["token"])
		if tok == "" {
			return fmt.Errorf("N1C secret %s must contain a 'token' field (type nginx.com/waf-bundle)", secretKey)
		}
		auth.APIToken = tok
	case conf_v1.BundleSourceTypeNIM:
		if tok := string(data["token"]); tok != "" {
			auth.BearerToken = tok
		} else if usr := string(data["username"]); usr != "" {
			auth.Username = usr
			auth.Password = string(data["password"])
		} else {
			return fmt.Errorf("NIM secret %s must contain 'token' or 'username'+'password' (type nginx.com/waf-bundle)", secretKey)
		}
	default: // HTTPS
		auth.TLSCert = data["tls.crt"]
		auth.TLSKey = data["tls.key"]
	}
	return nil
}

// resolveWAFTrustedCert resolves the trusted CA certificate secret.
func (lbc *LoadBalancerController) resolveWAFTrustedCert(secretName, namespace string, auth *wafbundle.BundleAuth) error {
	caSecretKey := namespace + "/" + secretName
	caRef := lbc.secretStore.GetSecret(caSecretKey)
	if caRef == nil || caRef.Error != nil {
		var msg string
		if caRef != nil {
			msg = caRef.Error.Error()
		}
		return fmt.Errorf("trusted cert secret %s not found or invalid: %s", caSecretKey, msg)
	}
	if err := secrets.ValidateCASecret(caRef.Secret); err != nil {
		return fmt.Errorf("trusted cert secret %s: %w", caSecretKey, err)
	}
	auth.TLSCA = caRef.Secret.Data[secrets.CAKey]
	return nil
}

// cleanupFetchedBundles removes any fetched bundle files for the given polKey.
func (lbc *LoadBalancerController) cleanupFetchedBundles(polKey string) {
	if lbc.wafBundlePath == "" {
		return
	}
	ns, name, _ := helpers.ParseNamespaceName(polKey)
	_ = os.Remove(filepath.Join(lbc.wafBundlePath, wafbundle.FetchedBundleFilename(ns, name, "policy")))

	// Glob for all log bundles belonging to this policy to avoid a hardcoded upper limit.
	pattern := filepath.Join(lbc.wafBundlePath, fmt.Sprintf("fetched_%s_%s_log_*.tgz", ns, name))
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

func effectivePollInterval(bs *conf_v1.BundleSource) time.Duration {
	if bs.PollInterval != nil && bs.PollInterval.Duration > 0 {
		return bs.PollInterval.Duration
	}
	return wafbundle.DefaultPollInterval
}
