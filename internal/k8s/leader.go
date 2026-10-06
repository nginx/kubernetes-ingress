package k8s

import (
	"context"
	"fmt"
	"os"
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

// leaseOwnerLookupTimeout bounds the API calls used to resolve the Lease owner
// at startup.
const leaseOwnerLookupTimeout = 10 * time.Second

// newLeaderElector creates a new LeaderElection and returns the Elector.
// When owner is not nil, a Lease created by the elector carries it as an owner
// reference so it is garbage-collected together with the controller workload.
func newLeaderElector(client kubernetes.Interface, callbacks leaderelection.LeaderCallbacks, namespace string, lockName string, identity string, owner *metav1.OwnerReference) (*leaderelection.LeaderElector, error) {
	broadcaster := record.NewBroadcaster()
	hostname, _ := os.Hostname()

	source := v1.EventSource{Component: "nginx-ingress-leader-elector", Host: hostname}
	recorder := broadcaster.NewRecorder(scheme.Scheme, source)

	lc := resourcelock.ResourceLockConfig{
		Identity:      identity,
		EventRecorder: recorder,
	}

	lock := newOwnedLeaseLock(client, namespace, lockName, lc, owner)

	ttl := 30 * time.Second
	return leaderelection.NewLeaderElector(
		leaderelection.LeaderElectionConfig{
			Lock:          lock,
			LeaseDuration: ttl,
			RenewDeadline: ttl / 2,
			RetryPeriod:   ttl / 4,
			Callbacks:     callbacks,
			// Clear the holder on graceful shutdown so another replica can
			// take over immediately instead of waiting for the lease to expire.
			ReleaseOnCancel: true,
		},
	)
}

// leaderElectionIdentity returns the name of the controller pod, which
// identifies this replica in the leader election Lease.
func (lbc *LoadBalancerController) leaderElectionIdentity() string {
	if lbc.metadata.pod != nil && lbc.metadata.pod.Name != "" {
		return lbc.metadata.pod.Name
	}
	return os.Getenv("POD_NAME")
}

// runLeaderElector makes sure an existing leader election Lease is owned by
// the controller workload, so Kubernetes garbage-collects it when the workload
// is deleted, and then runs leader election until ctx is canceled.
// Failing to set the owner never blocks leader election.
func (lbc *LoadBalancerController) runLeaderElector(ctx context.Context) {
	lbc.ensureLeaseOwner(ctx)
	lbc.leaderElector.Run(ctx)
}

// ensureLeaseOwner adds the controller workload as an owner of the leader
// election Lease, logging instead of failing so leader election is never blocked.
func (lbc *LoadBalancerController) ensureLeaseOwner(ctx context.Context) {
	if lbc.leaseOwner == nil {
		return
	}
	if err := ensureLeaseOwnerReference(ctx, lbc.client, lbc.metadata.namespace, lbc.leaderElectionLockName, *lbc.leaseOwner); err != nil {
		nl.Warnf(lbc.Logger, "Could not set owner reference on leader election Lease %s/%s, it will not be garbage-collected: %v",
			lbc.metadata.namespace, lbc.leaderElectionLockName, err)
	}
}

// leaseOwnerReference returns the owner reference of the top-level workload
// (Deployment, DaemonSet or StatefulSet) that manages the given pod.
// It returns nil when the pod has no supported controller.
// Deployment pods are resolved through their ReplicaSet to the Deployment,
// because old ReplicaSets are garbage-collected during rollouts.
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

// ownerReferenceFor builds a plain owner reference. Controller and
// BlockOwnerDeletion are left unset: the Lease is not managed by the workload
// controller, and blocking deletion would require extra RBAC on the owner.
func ownerReferenceFor(apiVersion, kind, name string, uid types.UID) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        uid,
	}
}

// ownedLeaseLock is a resourcelock.LeaseLock that sets an owner reference on
// the Lease whenever it has to create it. client-go's LeaseLock.Create only
// sets labels, so without this a Lease that is deleted while the controller is
// running (for example by `helm upgrade` removing the Lease that older charts
// created) would be recreated without an owner and never garbage-collected.
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

// Create creates the Lease with the owner reference, then reads it back
// through the embedded LeaseLock so its internal state is initialized for
// later Update calls.
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

// ensureLeaseOwnerReference creates the leader election Lease with the given
// owner, or adds the owner to an existing Lease (for example one created by an
// older version of the controller or by the Helm chart).
// The Lease spec, labels and annotations are left untouched.
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
				// Another replica created it first; retry to add the owner.
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
	ctx, cancel := context.WithTimeout(context.Background(), leaseOwnerLookupTimeout)
	defer cancel()
	owner, err := leaseOwnerReference(ctx, lbc.client, lbc.metadata.pod)
	if err != nil {
		nl.Warnf(lbc.Logger, "Could not determine the owner of leader election Lease %s/%s, it will not be garbage-collected: %v",
			lbc.metadata.namespace, lbc.leaderElectionLockName, err)
	}
	lbc.leaseOwner = owner

	if owner != nil && leaderHandler.OnStartedLeading != nil {
		onStartedLeading := leaderHandler.OnStartedLeading
		leaderHandler.OnStartedLeading = func(ctx context.Context) {
			// The Lease may have been recreated without an owner since startup,
			// for example by a replica running an older version during an upgrade.
			lbc.ensureLeaseOwner(ctx)
			onStartedLeading(ctx)
		}
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
