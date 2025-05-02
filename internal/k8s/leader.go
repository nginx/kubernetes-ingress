package k8s

import (
	"context"
	"fmt"
	"os"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
)

// newLeaderElector creates a new LeaderElection and returns the Elector.
func newLeaderElector(client kubernetes.Interface, callbacks leaderelection.LeaderCallbacks, namespace string, lockName string) (*leaderelection.LeaderElector, error) {
	podName := os.Getenv("POD_NAME")

	broadcaster := record.NewBroadcaster()
	hostname, _ := os.Hostname()

	source := v1.EventSource{Component: "nginx-ingress-leader-elector", Host: hostname}
	recorder := broadcaster.NewRecorder(scheme.Scheme, source)

	lc := resourcelock.ResourceLockConfig{
		Identity:      podName,
		EventRecorder: recorder,
	}

	leaseMeta := metav1.ObjectMeta{
		Namespace: namespace,
		Name:      lockName,
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta:  leaseMeta,
		Client:     client.CoordinationV1(),
		LockConfig: lc,
	}

	ttl := 30 * time.Second
	return leaderelection.NewLeaderElector(
		leaderelection.LeaderElectionConfig{
			Lock:          lock,
			LeaseDuration: ttl,
			RenewDeadline: ttl / 2,
			RetryPeriod:   ttl / 4,
			Callbacks:     callbacks,
		})
}

// createLeaderHandler builds the handler funcs for leader handling
func createLeaderHandler(lbc *LoadBalancerController) leaderelection.LeaderCallbacks {
	return leaderelection.LeaderCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			nl.Debug(lbc.Logger, "started leading")
			// Closing this channel allows the leader to start the telemetry reporting process
			if lbc.telemetryChan != nil {
				close(lbc.telemetryChan)
			}
			if lbc.reportIngressStatus {
				ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

				nl.Debugf(lbc.Logger, "Updating status for %v Ingresses", len(ingresses))

				err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
				if err != nil {
					nl.Debugf(lbc.Logger, "error updating status when starting leading: %v", err)
				}
			}

			if lbc.areCustomResourcesEnabled {
				nl.Debug(lbc.Logger, "updating VirtualServer and VirtualServerRoutes status")

				err := lbc.updateVirtualServersStatusFromEvents()
				if err != nil {
					nl.Debugf(lbc.Logger, "error updating VirtualServers status when starting leading: %v", err)
				}

				err = lbc.updateVirtualServerRoutesStatusFromEvents()
				if err != nil {
					nl.Debugf(lbc.Logger, "error updating VirtualServerRoutes status when starting leading: %v", err)
				}

				err = lbc.updatePoliciesStatus()
				if err != nil {
					nl.Debugf(lbc.Logger, "error updating Policies status when starting leading: %v", err)
				}

				err = lbc.updateTransportServersStatusFromEvents()
				if err != nil {
					nl.Debugf(lbc.Logger, "error updating TransportServers status when starting leading: %v", err)
				}
			}
		},
		OnStoppedLeading: func() {
			nl.Debug(lbc.Logger, "stopped leading")
		},
	}
}

// addLeaderHandler adds the handler for leader election to the controller
func (lbc *LoadBalancerController) addLeaderHandler(leaderHandler leaderelection.LeaderCallbacks) {
	var err error
	lbc.leaderElector, err = newLeaderElector(lbc.client, leaderHandler, lbc.metadata.namespace, lbc.leaderElectionLockName)
	if err != nil {
		nl.Debugf(lbc.Logger, "Error starting LeaderElection: %v", err)
	}
}

func (lbc *LoadBalancerController) updatePoliciesStatus() error {
	var allErrs []error
	for _, nsi := range lbc.namespacedInformers {
		for _, obj := range nsi.policyLister.List() {
			pol := obj.(*conf_v1.Policy)

			err := validation.ValidatePolicy(pol, lbc.isNginxPlus, lbc.enableOIDC, lbc.appProtectEnabled)
			if err != nil {
				msg := fmt.Sprintf("Policy %v/%v is invalid and was rejected: %v", pol.Namespace, pol.Name, err)
				err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateInvalid, "Rejected", msg)
				if err != nil {
					allErrs = append(allErrs, err)
				}
			} else {
				msg := fmt.Sprintf("Policy %v/%v was added or updated", pol.Namespace, pol.Name)
				err = lbc.statusUpdater.UpdatePolicyStatus(pol, conf_v1.StateValid, "AddedOrUpdated", msg)
				if err != nil {
					allErrs = append(allErrs, err)
				}
			}
		}
	}

	if len(allErrs) != 0 {
		return fmt.Errorf("not all Policies statuses were updated: %v", allErrs)
	}

	return nil
}
