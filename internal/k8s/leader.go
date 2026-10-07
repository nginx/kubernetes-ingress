package k8s

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"

	coordinationv1 "k8s.io/api/coordination/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
)

// leaseOwnerLookupTimeout bounds the Lease owner lookup and update.
const leaseOwnerLookupTimeout = 10 * time.Second

// newLeaderElector creates a LeaderElector. If owner is set, a Lease it
// creates is owned by the controller workload.
func newLeaderElector(client kubernetes.Interface, callbacks leaderelection.LeaderCallbacks, namespace string, lockName string, identity string, owner *metav1.OwnerReference) (*leaderelection.LeaderElector, error) {
	return newLeaderElectorWithTimings(client, callbacks, namespace, lockName, identity, owner, defaultLeaderElectionTimings)
}

// leaderElectionTimings holds the leader election intervals.
type leaderElectionTimings struct {
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

var defaultLeaderElectionTimings = leaderElectionTimings{
	LeaseDuration: 30 * time.Second,
	RenewDeadline: 15 * time.Second,
	RetryPeriod:   7500 * time.Millisecond,
}

func newLeaderElectorWithTimings(client kubernetes.Interface, callbacks leaderelection.LeaderCallbacks, namespace string, lockName string, identity string, owner *metav1.OwnerReference, timings leaderElectionTimings) (*leaderelection.LeaderElector, error) {
	broadcaster := record.NewBroadcaster()
	hostname, _ := os.Hostname()

	source := v1.EventSource{Component: "nginx-ingress-leader-elector", Host: hostname}
	recorder := broadcaster.NewRecorder(scheme.Scheme, source)

	lc := resourcelock.ResourceLockConfig{
		Identity:      identity,
		EventRecorder: recorder,
	}

	lock := newOwnedLeaseLock(client, namespace, lockName, lc, owner)

	return leaderelection.NewLeaderElector(
		leaderelection.LeaderElectionConfig{
			Lock:          lock,
			LeaseDuration: timings.LeaseDuration,
			RenewDeadline: timings.RenewDeadline,
			RetryPeriod:   timings.RetryPeriod,
			Callbacks:     callbacks,
			// ReleaseOnCancel is left off: status writes can still be in
			// flight on shutdown, and a successor taking over immediately
			// could have its status overwritten.
		},
	)
}

// leaderElectionIdentity returns the pod name used as the Lease holder.
func (lbc *LoadBalancerController) leaderElectionIdentity() string {
	if lbc.metadata.pod != nil && lbc.metadata.pod.Name != "" {
		return lbc.metadata.pod.Name
	}
	return os.Getenv("POD_NAME")
}

// runLeaderElector runs leader election until ctx is canceled.
// Run also returns when the Lease is lost, so loop to compete for it again.
func (lbc *LoadBalancerController) runLeaderElector(ctx context.Context) {
	lbc.ensureLeaseOwner(ctx)
	for {
		lbc.leaderElector.Run(ctx)
		if ctx.Err() != nil {
			return
		}
		nl.Warnf(lbc.Logger, "Lost leader election Lease %s/%s, trying to acquire it again",
			lbc.metadata.namespace, lbc.leaderElectionLockName)
	}
}

// ensureLeaseOwner adds the workload as the Lease owner. Errors are only
// logged, and the call is bounded so it never holds up leader election.
func (lbc *LoadBalancerController) ensureLeaseOwner(ctx context.Context) {
	lbc.ensureLeaseOwnerWithin(ctx, leaseOwnerLookupTimeout)
}

func (lbc *LoadBalancerController) ensureLeaseOwnerWithin(ctx context.Context, timeout time.Duration) {
	if lbc.leaseOwner == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ensureLeaseOwnerReference(ctx, lbc.client, lbc.metadata.namespace, lbc.leaderElectionLockName, *lbc.leaseOwner); err != nil {
		nl.Warnf(lbc.Logger, "Could not set owner reference on leader election Lease %s/%s, it will not be garbage-collected: %v",
			lbc.metadata.namespace, lbc.leaderElectionLockName, err)
	}
}

// leaseOwnerReference returns the Deployment, DaemonSet or StatefulSet that
// manages the pod, or nil if there is none. Deployments are used rather than
// ReplicaSets because old ReplicaSets are deleted during rollouts.
func leaseOwnerReference(ctx context.Context, client kubernetes.Interface, pod *v1.Pod) (*metav1.OwnerReference, error) {
	if pod == nil {
		return nil, nil
	}
	podOwner := metav1.GetControllerOf(pod)
	if podOwner == nil {
		return nil, nil
	}

	switch podOwner.Kind {
	case "DaemonSet", "StatefulSet":
		return ownerReferenceFor(podOwner.APIVersion, podOwner.Kind, podOwner.Name, podOwner.UID), nil
	case "ReplicaSet":
		rs, err := client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, podOwner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("getting ReplicaSet %s/%s: %w", pod.Namespace, podOwner.Name, err)
		}
		if rsOwner := metav1.GetControllerOf(rs); rsOwner != nil && rsOwner.Kind == "Deployment" {
			return ownerReferenceFor(rsOwner.APIVersion, rsOwner.Kind, rsOwner.Name, rsOwner.UID), nil
		}
		return ownerReferenceFor("apps/v1", "ReplicaSet", rs.Name, rs.UID), nil
	default:
		return nil, nil
	}
}

// ownerReferenceFor builds an owner reference. BlockOwnerDeletion is left
// unset as it would need extra RBAC.
func ownerReferenceFor(apiVersion, kind, name string, uid types.UID) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        uid,
	}
}

// ownedLeaseLock is a LeaseLock that sets the owner reference when it
// creates the Lease.
type ownedLeaseLock struct {
	*resourcelock.LeaseLock
	client kubernetes.Interface
	owner  *metav1.OwnerReference
}

func newOwnedLeaseLock(client kubernetes.Interface, namespace, name string, lc resourcelock.ResourceLockConfig, owner *metav1.OwnerReference) *ownedLeaseLock {
	return &ownedLeaseLock{
		LeaseLock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Namespace: namespace, Name: name},
			Client:     client.CoordinationV1(),
			LockConfig: lc,
		},
		client: client,
		owner:  owner,
	}
}

// Create creates the Lease with the owner, then reads it back so the embedded
// LeaseLock can Update it.
func (l *ownedLeaseLock) Create(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	if l.owner == nil {
		return l.LeaseLock.Create(ctx, ler)
	}
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:            l.LeaseMeta.Name,
			Namespace:       l.LeaseMeta.Namespace,
			OwnerReferences: []metav1.OwnerReference{*l.owner},
		},
		Spec: resourcelock.LeaderElectionRecordToLeaseSpec(&ler),
	}
	if _, err := l.client.CoordinationV1().Leases(l.LeaseMeta.Namespace).Create(ctx, lease, metav1.CreateOptions{}); err != nil {
		return err
	}
	_, _, err := l.Get(ctx)
	return err
}

// ensureLeaseOwnerReference creates the Lease with the owner, or adds the
// owner to an existing Lease.
func ensureLeaseOwnerReference(ctx context.Context, client kubernetes.Interface, namespace, name string, owner metav1.OwnerReference) error {
	leases := client.CoordinationV1().Leases(namespace)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease, err := leases.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = leases.Create(ctx, &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{
					Name:            name,
					Namespace:       namespace,
					OwnerReferences: []metav1.OwnerReference{owner},
				},
			}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				// Created by another replica; retry.
				return apierrors.NewConflict(coordinationv1.Resource("leases"), name, err)
			}
			return err
		}
		if err != nil {
			return err
		}

		for _, ref := range lease.OwnerReferences {
			if ref.UID == owner.UID {
				return nil
			}
		}
		lease.OwnerReferences = append(lease.OwnerReferences, owner)
		_, err = leases.Update(ctx, lease, metav1.UpdateOptions{})
		return err
	})
}

// createLeaderHandler builds the handler funcs for leader handling
func createLeaderHandler(lbc *LoadBalancerController) leaderelection.LeaderCallbacks {
	// A replica can lead more than once; start telemetry only once.
	var startTelemetry sync.Once
	return leaderelection.LeaderCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			nl.Debug(lbc.Logger, "started leading")
			// Closing this channel allows the leader to start the telemetry reporting process
			if lbc.telemetryChan != nil {
				startTelemetry.Do(func() { close(lbc.telemetryChan) })
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

// leaseOwnerCheckedCallback wraps OnStartedLeading to first restore the Lease
// owner, which an older replica may have dropped. It skips the handler if
// leadership ended meanwhile, so no status is written after losing the Lease.
func (lbc *LoadBalancerController) leaseOwnerCheckedCallback(onStartedLeading func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
		lbc.ensureLeaseOwner(ctx)
		if ctx.Err() != nil {
			return
		}
		onStartedLeading(ctx)
	}
}

// addLeaderHandler adds the handler for leader election to the controller
func (lbc *LoadBalancerController) addLeaderHandler(leaderHandler leaderelection.LeaderCallbacks) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseOwnerLookupTimeout)
	defer cancel()
	owner, err := leaseOwnerReference(ctx, lbc.client, lbc.metadata.pod)
	if err != nil {
		nl.Warnf(lbc.Logger, "Could not determine the owner of leader election Lease %s/%s, it will not be garbage-collected: %v",
			lbc.metadata.namespace, lbc.leaderElectionLockName, err)
	}
	lbc.leaseOwner = owner

	if owner != nil && leaderHandler.OnStartedLeading != nil {
		leaderHandler.OnStartedLeading = lbc.leaseOwnerCheckedCallback(leaderHandler.OnStartedLeading)
	}

	lbc.leaderElector, err = newLeaderElector(lbc.client, leaderHandler, lbc.metadata.namespace, lbc.leaderElectionLockName, lbc.leaderElectionIdentity(), owner)
	if err != nil {
		nl.Debugf(lbc.Logger, "Error starting LeaderElection: %v", err)
	}
}

func (lbc *LoadBalancerController) updatePoliciesStatus() error {
	var allErrs []error
	// Collect under the read lock; the API calls below must not run under it.
	var groups [][]*conf_v1.Policy
	lbc.namespacedInformers.ForEach(func(nsi *namespacedInformer) {
		var group []*conf_v1.Policy
		for _, obj := range nsi.policyLister.List() {
			group = append(group, obj.(*conf_v1.Policy))
		}
		groups = append(groups, group)
	})

	for _, group := range groups {
		for _, pol := range group {

			err := validation.ValidatePolicy(pol, lbc.policyValidationConfig())
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
