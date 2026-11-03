package k8s

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	"github.com/nginx/kubernetes-ingress/internal/nsregistry"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// registryFrom builds a registry pre-populated from m. Tests construct informer
// groups as a plain map for readability; the controller itself always builds the
// registry empty and fills it via Set.
func registryFrom(m map[string]*namespacedInformer) *nsregistry.Registry[namespacedInformer] {
	r := nsregistry.New[namespacedInformer]()
	for ns, nsi := range m {
		r.Set(ns, nsi)
	}
	return r
}

// TestStatusUpdaterSharesControllerRegistry pins the invariant the whole
// registry depends on: the controller and its statusUpdater must hold the same
// instance. Were statusUpdater given its own, every namespace would resolve as
// unwatched on the status path and status updates would stop without any error.
func TestStatusUpdaterSharesControllerRegistry(t *testing.T) {
	t.Parallel()

	lbc := NewLoadBalancerController(NewLoadBalancerControllerInput{
		KubeClient:    fake.NewClientset(),
		LoggerContext: context.Background(),
	})

	if lbc.namespacedInformers == nil {
		t.Fatal("controller registry is nil")
	}
	if lbc.statusUpdater.namespacedInformers != lbc.namespacedInformers {
		t.Error("statusUpdater holds a different registry than the controller; they must share one instance")
	}
}

// TestRemoveNamespacedInformerUnregistersAndStops checks that removal both
// unregisters the group and stops it. The ordering between the two is enforced
// by the API rather than by this test: Remove returns the group, so there is
// nothing to stop until it has already been unregistered.
func TestRemoveNamespacedInformerUnregistersAndStops(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{namespace: "doomed", stopCh: make(chan struct{})}
	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"doomed": nsi}),
		configuration:       createTestConfiguration(),
	}

	lbc.removeNamespacedInformer("doomed")

	if got := lbc.namespacedInformers.Get("doomed"); got != nil {
		t.Errorf("Get after removeNamespacedInformer = %v, want nil", got)
	}
	select {
	case <-nsi.stopCh:
		// stopped, as expected
	default:
		t.Error("informer was unregistered but never stopped")
	}
}

// TestUnwatchNamespaceCleansUpBeforeUnregistering pins the ordering the WAF and
// DoS fan-out depends on. Cleanup resolves dependants through getAllPolicies,
// which walks the registry, so unregistering first would hide this namespace's
// Policy CRs and leave VirtualServers elsewhere that reference them stale.
func TestUnwatchNamespaceCleansUpBeforeUnregistering(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{namespace: "unlabelled", stopCh: make(chan struct{})}
	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"unlabelled": nsi}),
		configuration:       createTestConfiguration(),
	}

	var (
		cleanupCalls         int
		registeredAtCleanup  bool
		stoppedBeforeCleanup bool
	)
	lbc.unwatchNamespace("unlabelled", func(got *namespacedInformer) {
		cleanupCalls++
		if got != nsi {
			t.Errorf("cleanup got informer %v, want %v", got, nsi)
		}
		registeredAtCleanup = lbc.namespacedInformers.Get("unlabelled") == nsi
		select {
		case <-nsi.stopCh:
			stoppedBeforeCleanup = true
		default:
		}
	})

	if cleanupCalls != 1 {
		t.Errorf("cleanup called %d times, want 1", cleanupCalls)
	}
	if !registeredAtCleanup {
		t.Error("namespace was already unregistered during cleanup; WAF policy fan-out cannot see its Policy CRs")
	}
	if stoppedBeforeCleanup {
		t.Error("informer was stopped before cleanup ran")
	}
	if got := lbc.namespacedInformers.Get("unlabelled"); got != nil {
		t.Errorf("Get after unwatchNamespace = %v, want nil", got)
	}
	select {
	case <-nsi.stopCh:
		// stopped, as expected
	default:
		t.Error("informer was cleaned up but never stopped")
	}
}

// TestUnwatchNamespaceSkipsUnwatchedNamespace checks an unwatched key is a no-op
// rather than a nil cleanup call.
func TestUnwatchNamespaceSkipsUnwatchedNamespace(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{}),
	}

	lbc.unwatchNamespace("never-watched", func(*namespacedInformer) {
		t.Error("cleanup ran for a namespace that was never watched")
	})
}

// TestNamespacedInformerStopIsIdempotent covers shutdown: Stop sweeps every
// registered group while the sync queue worker may be unregistering one, so both
// can reach the same group. A second close of stopCh would panic.
func TestNamespacedInformerStopIsIdempotent(t *testing.T) {
	t.Parallel()

	nsi := &namespacedInformer{namespace: "ns", stopCh: make(chan struct{})}

	nsi.stop()
	nsi.stop()

	select {
	case <-nsi.stopCh:
	default:
		t.Error("stopCh was not closed")
	}
}

// TestStopReleasesWorkerWaitingOnNamespaceCaches drives Stop against a sync
// queue worker that is blocked in syncNamespace waiting for a watched
// namespace's caches, as happens with an unreachable API server. Stop shuts the
// queue down before sweeping the registry, so the worker must give up on the
// canceled run context rather than on its group's stopCh; otherwise Stop hangs.
// It then checks the sweep stopped every registered group.
func TestStopReleasesWorkerWaitingOnNamespaceCaches(t *testing.T) {
	t.Parallel()

	waiting := make(chan struct{})
	var once sync.Once
	neverSynced := func() bool {
		once.Do(func() { close(waiting) })
		return false
	}

	stuck := &namespacedInformer{
		namespace:  "stuck",
		stopCh:     make(chan struct{}),
		cacheSyncs: []cache.InformerSynced{neverSynced},
	}
	other := &namespacedInformer{namespace: "other", stopCh: make(chan struct{})}

	labeled := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := labeled.Add(&api_v1.Namespace{ObjectMeta: meta_v1.ObjectMeta{Name: "stuck"}}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	lbc := &LoadBalancerController{
		Logger:                 logger,
		namespaceLabeledLister: labeled,
		namespacedInformers: registryFrom(map[string]*namespacedInformer{
			"stuck": stuck,
			"other": other,
		}),
	}
	lbc.ctx, lbc.cancel = context.WithCancel(context.Background())
	lbc.syncQueue = newTaskQueue(logger, lbc.syncNamespace)
	lbc.syncQueue.Enqueue(&api_v1.Namespace{ObjectMeta: meta_v1.ObjectMeta{Name: "stuck"}})
	go lbc.syncQueue.Run(time.Second, lbc.ctx.Done())

	select {
	case <-waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("worker never started waiting for the namespace caches")
	}

	stopped := make(chan struct{})
	go func() {
		lbc.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return while the worker was waiting for namespace caches")
	}

	for _, nsi := range []*namespacedInformer{stuck, other} {
		select {
		case <-nsi.stopCh:
		default:
			t.Errorf("namespace %q was not stopped by Stop", nsi.namespace)
		}
	}
}

// TestRemoveNamespacedInformerPurgesPolicySnapshots pins the fix for the Policy
// snapshot leak on namespace teardown (see Configuration.DeletePoliciesForNamespace).
// It covers two things in one test:
//
//  1. The pending-delete race: a Policy's syncPolicy delete task can still be queued
//     when its namespace is unwatched. By the time removeNamespacedInformer runs, the
//     informer's policyLister has already evicted the Policy (ns-a's lister here is
//     empty), but Configuration.policies has not — so purging by iterating the lister
//     (the old behavior) would miss it. Purging by namespace key prefix instead must
//     catch it regardless of lister contents.
//  2. Scoping: a Policy in a different namespace (ns-b) must survive ns-a's teardown.
func TestRemoveNamespacedInformerPurgesPolicySnapshots(t *testing.T) {
	t.Parallel()

	conf := createTestConfiguration()
	polA := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Name: "auth-pol", Namespace: "ns-a"},
		Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/auth", AuthServiceName: "auth-svc"}},
	}
	polB := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Name: "auth-pol", Namespace: "ns-b"},
	}
	conf.AddOrUpdatePolicy(polA)
	conf.AddOrUpdatePolicy(polB)
	conf.UpdatePolicyServiceRef("ns-a", "auth-pol", "auth-svc")
	conf.UpdatePolicyServiceRef("ns-b", "auth-pol", "other-svc")

	// ns-a's policyLister is empty, simulating a delete already observed by the
	// informer while the corresponding syncPolicy task is still queued.
	nsi := &namespacedInformer{
		namespace:    "ns-a",
		stopCh:       make(chan struct{}),
		policyLister: cache.NewStore(cache.MetaNamespaceKeyFunc),
	}
	lbc := &LoadBalancerController{
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"ns-a": nsi}),
		configuration:       conf,
	}

	lbc.removeNamespacedInformer("ns-a")

	if got := conf.GetPolicy("ns-a/auth-pol"); got != nil {
		t.Errorf("GetPolicy(\"ns-a/auth-pol\") after teardown = %+v, want nil", got)
	}
	if _, exists := conf.serviceReferenceChecker.policyServices["ns-a/auth-pol"]; exists {
		t.Error("policyServices still has an entry for ns-a/auth-pol after teardown")
	}

	if got := conf.GetPolicy("ns-b/auth-pol"); got != polB {
		t.Errorf("GetPolicy(\"ns-b/auth-pol\") after ns-a teardown = %+v, want %+v (unrelated namespace must survive)", got, polB)
	}
	if _, exists := conf.serviceReferenceChecker.policyServices["ns-b/auth-pol"]; !exists {
		t.Error("policyServices lost the entry for ns-b/auth-pol after an unrelated namespace's teardown")
	}
}

// TestSyncNamespaceDeletedBranchPurgesPolicySnapshots drives the actual deleted-
// namespace branch of syncNamespace (as opposed to the label-removed branch covered by
// TestUnwatchNamespaceCleansUpBeforeUnregistering), which previously did no Policy
// cleanup at all — not even the lister-based cleanup the label-removed branch had.
func TestSyncNamespaceDeletedBranchPurgesPolicySnapshots(t *testing.T) {
	t.Parallel()

	conf := createTestConfiguration()
	pol := &conf_v1.Policy{ObjectMeta: meta_v1.ObjectMeta{Name: "auth-pol", Namespace: "gone-ns"}}
	conf.AddOrUpdatePolicy(pol)

	nsi := &namespacedInformer{namespace: "gone-ns", stopCh: make(chan struct{})}
	lbc := &LoadBalancerController{
		Logger:              nl.LoggerFromContext(context.Background()),
		client:              fake.NewClientset(),
		configuration:       conf,
		namespacedInformers: registryFrom(map[string]*namespacedInformer{"gone-ns": nsi}),
		// Empty: "gone-ns" is absent, taking syncNamespace's !exists branch. The
		// follow-up client.Get (also a miss) is what distinguishes "label removed"
		// from "namespace deleted" within that branch.
		namespaceLabeledLister: cache.NewStore(cache.MetaNamespaceKeyFunc),
	}

	lbc.syncNamespace(task{Key: "gone-ns"})

	if got := lbc.namespacedInformers.Get("gone-ns"); got != nil {
		t.Errorf("namespacedInformers.Get(\"gone-ns\") after syncNamespace = %v, want nil", got)
	}
	if got := conf.GetPolicy("gone-ns/auth-pol"); got != nil {
		t.Errorf("GetPolicy(\"gone-ns/auth-pol\") after syncNamespace deleted the namespace = %+v, want nil", got)
	}
}
