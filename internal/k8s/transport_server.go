package k8s

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func createTransportServerHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ts := obj.(*conf_v1.TransportServer)
			nl.Debugf(lbc.Logger, "Adding TransportServer: %v", ts.Name)
			lbc.AddSyncQueue(ts)
		},
		DeleteFunc: func(obj interface{}) {
			ts, isTs := obj.(*conf_v1.TransportServer)
			if !isTs {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				ts, ok = deletedState.Obj.(*conf_v1.TransportServer)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-TransportServer object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing TransportServer: %v", ts.Name)
			lbc.AddSyncQueue(ts)
		},
		UpdateFunc: func(old, cur interface{}) {
			curTs := cur.(*conf_v1.TransportServer)
			if !reflect.DeepEqual(old, cur) {
				nl.Debugf(lbc.Logger, "TransportServer %v changed, syncing", curTs.Name)
				lbc.AddSyncQueue(curTs)
			}
		},
	}
}

func (nsi *namespacedInformer) addTransportServerHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().TransportServers().Informer()
	informer.AddEventHandler(handlers) //nolint:errcheck,gosec
	nsi.transportServerLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (lbc *LoadBalancerController) syncTransportServer(task task) {
	key := task.Key
	var obj interface{}
	var tsExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, tsExists, err = lbc.getNamespacedInformer(ns).transportServerLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !tsExists {
		nl.Debugf(lbc.Logger, "Deleting TransportServer: %v\n", key)
		changes, problems = lbc.configuration.DeleteTransportServer(key)
	} else {
		nl.Debugf(lbc.Logger, "Adding or Updating TransportServer: %v\n", key)
		ts := obj.(*conf_v1.TransportServer)
		changes, problems = lbc.configuration.AddOrUpdateTransportServer(ts)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) updateTransportServerStatusAndEventsOnDelete(tsConfig *TransportServerConfiguration, changeError string, deleteErr error) {
	eventType := api_v1.EventTypeWarning
	eventTitle := nl.EventReasonRejected
	eventWarningMessage := ""
	var state string

	// TransportServer either became invalid or lost its host or listener
	if changeError != "" {
		state = conf_v1.StateInvalid
		eventWarningMessage = fmt.Sprintf("with error: %s", changeError)
	} else if len(tsConfig.Warnings) > 0 {
		state = conf_v1.StateWarning
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(tsConfig.Warnings))
	}

	// we don't need to report anything if eventWarningMessage is empty
	// in that case, the resource was deleted because its class became incorrect
	// (some other Ingress Controller will handle it)

	if eventWarningMessage != "" {
		if deleteErr != nil {
			eventType = api_v1.EventTypeWarning
			eventTitle = nl.EventReasonRejectedWithError
			eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, deleteErr)
			state = conf_v1.StateInvalid
		}

		msg := fmt.Sprintf("TransportServer %s was rejected %s", getResourceKey(&tsConfig.TransportServer.ObjectMeta), eventWarningMessage)
		lbc.recorder.Eventf(tsConfig.TransportServer, eventType, eventTitle, msg)

		if lbc.reportCustomResourceStatusEnabled() {
			err := lbc.statusUpdater.UpdateTransportServerStatus(tsConfig.TransportServer, state, eventTitle, msg)
			if err != nil {
				nl.Errorf(lbc.Logger, "Error when updating the status for TransportServer %v/%v: %v", tsConfig.TransportServer.Namespace, tsConfig.TransportServer.Name, err)
			}
		}
	}
}

func (lbc *LoadBalancerController) updateTransportServerStatusAndEvents(tsConfig *TransportServerConfiguration, warnings configs.Warnings, operationErr error) {
	eventTitle := nl.EventReasonAddedOrUpdated
	eventType := api_v1.EventTypeNormal
	eventWarningMessage := ""
	state := conf_v1.StateValid

	if len(tsConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(tsConfig.Warnings))
		state = conf_v1.StateWarning
	}

	if messages, ok := warnings[tsConfig.TransportServer]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(messages))
		state = conf_v1.StateWarning
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithError
		eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, operationErr)
		state = conf_v1.StateInvalid
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated %s", getResourceKey(&tsConfig.TransportServer.ObjectMeta), eventWarningMessage)
	lbc.recorder.Eventf(tsConfig.TransportServer, eventType, eventTitle, msg)

	if lbc.reportCustomResourceStatusEnabled() {
		err := lbc.statusUpdater.UpdateTransportServerStatus(tsConfig.TransportServer, state, eventTitle, msg)
		if err != nil {
			nl.Errorf(lbc.Logger, "Error when updating the status for TransportServer %v/%v: %v", tsConfig.TransportServer.Namespace, tsConfig.TransportServer.Name, err)
		}
	}
}

func (lbc *LoadBalancerController) updateTransportServersStatusFromEvents() error {
	var allErrs []error
	for _, nsi := range lbc.namespacedInformers {
		for _, obj := range nsi.transportServerLister.List() {
			ts := obj.(*conf_v1.TransportServer)

			events, err := lbc.client.CoreV1().Events(ts.Namespace).List(context.TODO(),
				meta_v1.ListOptions{FieldSelector: fmt.Sprintf("involvedObject.name=%v,involvedObject.uid=%v", ts.Name, ts.UID)})
			if err != nil {
				allErrs = append(allErrs, fmt.Errorf("error trying to get events for TransportServer %v/%v: %w", ts.Namespace, ts.Name, err))
				break
			}

			if len(events.Items) == 0 {
				continue
			}

			var timestamp time.Time
			var latestEvent api_v1.Event
			for _, event := range events.Items {
				if event.CreationTimestamp.After(timestamp) {
					latestEvent = event
				}
			}

			err = lbc.statusUpdater.UpdateTransportServerStatus(ts, getStatusFromEventTitle(latestEvent.Reason), latestEvent.Reason, latestEvent.Message)
			if err != nil {
				allErrs = append(allErrs, err)
			}
		}
	}

	if len(allErrs) > 0 {
		return fmt.Errorf("not all TransportServers statuses were updated: %v", allErrs)
	}

	return nil
}

func (lbc *LoadBalancerController) createTransportServerEx(transportServer *conf_v1.TransportServer, listenerPort int, ipv4 string, ipv6 string) *configs.TransportServerEx {
	endpoints := make(map[string][]string)
	externalNameSvcs := make(map[string]bool)
	podsByIP := make(map[string]string)
	disableIPV6 := lbc.configuration.isIPV6Disabled

	for _, u := range transportServer.Spec.Upstreams {
		podEndps, external, err := lbc.getEndpointsForUpstream(transportServer.Namespace, u.Service, uint16(u.Port)) //nolint:gosec
		if err == nil && external && lbc.isNginxPlus {
			externalNameSvcs[configs.GenerateExternalNameSvcKey(transportServer.Namespace, u.Service)] = true
		}
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting Endpoints for Upstream %v: %v", u.Name, err)
		}

		// subselector is not supported yet in TransportServer upstreams. That's why we pass "nil" here
		endpointsKey := configs.GenerateEndpointsKey(transportServer.Namespace, u.Service, nil, uint16(u.Port)) //nolint:gosec

		endps := getIPAddressesFromEndpoints(podEndps)
		endpoints[endpointsKey] = endps

		if lbc.isNginxPlus && lbc.isPrometheusEnabled {
			for _, endpoint := range podEndps {
				podsByIP[endpoint.Address] = endpoint.PodName
			}
		}

		if u.Backup != "" && u.BackupPort != nil {
			bendps, backupEndpointsKey := lbc.getTransportServerBackupEndpointsAndKey(transportServer, u, externalNameSvcs)
			endpoints[backupEndpointsKey] = bendps
		}
	}

	scrtRefs := make(map[string]*secrets.SecretReference)

	if transportServer.Spec.TLS != nil && transportServer.Spec.TLS.Secret != "" {
		scrtKey := transportServer.Namespace + "/" + transportServer.Spec.TLS.Secret

		scrtRef := lbc.secretStore.GetSecret(scrtKey)
		if scrtRef.Error != nil {
			nl.Warnf(lbc.Logger, "Error trying to get the secret %v for TransportServer %v: %v", scrtKey, transportServer.Name, scrtRef.Error)
		}

		scrtRefs[scrtKey] = scrtRef
	}

	return &configs.TransportServerEx{
		ListenerPort:     listenerPort,
		IPv4:             ipv4,
		IPv6:             ipv6,
		TransportServer:  transportServer,
		Endpoints:        endpoints,
		PodsByIP:         podsByIP,
		ExternalNameSvcs: externalNameSvcs,
		DisableIPV6:      disableIPV6,
		SecretRefs:       scrtRefs,
	}
}

func (lbc *LoadBalancerController) updateTransportServerMetrics() {
	if !lbc.areCustomResourcesEnabled {
		return
	}

	metrics := lbc.configuration.GetTransportServerMetrics()
	lbc.metricsCollector.SetTransportServers(metrics.TotalTLSPassthrough, metrics.TotalTCP, metrics.TotalUDP)
}
