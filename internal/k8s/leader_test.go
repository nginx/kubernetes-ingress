package k8s

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	apps_v1 "k8s.io/api/apps/v1"
	coordination_v1 "k8s.io/api/coordination/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	testLeaseNamespace = "nginx-ingress"
	testLeaseName      = "my-release-nginx-ingress-leader-election"
)

func boolPtr(b bool) *bool { return &b }

func controllerRef(apiVersion, kind, name, uid string) meta_v1.OwnerReference {
	return meta_v1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID(uid),
		Controller: boolPtr(true),
	}
}

func testPod(owners ...meta_v1.OwnerReference) *api_v1.Pod {
	return &api_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:            "nginx-ingress-pod",
			Namespace:       testLeaseNamespace,
			OwnerReferences: owners,
		},
	}
}

func testDeploymentReplicaSet() *apps_v1.ReplicaSet {
	return &apps_v1.ReplicaSet{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "nginx-ingress-controller-5d8f7",
			Namespace: testLeaseNamespace,
			OwnerReferences: []meta_v1.OwnerReference{
				controllerRef("apps/v1", "Deployment", "nginx-ingress-controller", "deploy-uid"),
			},
		},
	}
}

func TestLeaseOwnerReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pod     *api_v1.Pod
		objects []runtime.Object
		want    *meta_v1.OwnerReference
	}{
		{
			name:    "deployment pod is owned by the Deployment, not the ReplicaSet",
			pod:     testPod(controllerRef("apps/v1", "ReplicaSet", "nginx-ingress-controller-5d8f7", "rs-uid")),
			objects: []runtime.Object{testDeploymentReplicaSet()},
			want: &meta_v1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "nginx-ingress-controller",
				UID:        "deploy-uid",
			},
		},
		{
			name: "daemonset pod is owned by the DaemonSet",
			pod:  testPod(controllerRef("apps/v1", "DaemonSet", "nginx-ingress-controller", "ds-uid")),
			want: &meta_v1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "nginx-ingress-controller",
				UID:        "ds-uid",
			},
		},
		{
			name: "statefulset pod is owned by the StatefulSet",
			pod:  testPod(controllerRef("apps/v1", "StatefulSet", "nginx-ingress-controller", "sts-uid")),
			want: &meta_v1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "StatefulSet",
				Name:       "nginx-ingress-controller",
				UID:        "sts-uid",
			},
		},
		{
			name: "bare pod has no owner",
			pod:  testPod(),
			want: nil,
		},
		{
			name: "nil pod has no owner",
			pod:  nil,
			want: nil,
		},
		{
			name: "non-controller owner reference is ignored",
			pod: testPod(meta_v1.OwnerReference{
				APIVersion: "apps/v1", Kind: "DaemonSet", Name: "other", UID: "other-uid",
			}),
			want: nil,
		},
		{
			name: "unsupported owner kind is ignored",
			pod:  testPod(controllerRef("batch/v1", "Job", "some-job", "job-uid")),
			want: nil,
		},
		{
			name: "replicaset not found yields no owner",
			pod:  testPod(controllerRef("apps/v1", "ReplicaSet", "missing-rs", "rs-uid")),
			want: nil,
		},
		{
			name: "replicaset without a Deployment owner is used directly",
			pod:  testPod(controllerRef("apps/v1", "ReplicaSet", "bare-rs", "rs-uid")),
			objects: []runtime.Object{&apps_v1.ReplicaSet{
				ObjectMeta: meta_v1.ObjectMeta{Name: "bare-rs", Namespace: testLeaseNamespace, UID: "rs-uid"},
			}},
			want: &meta_v1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "bare-rs",
				UID:        "rs-uid",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := fake.NewClientset(tc.objects...)

			got, _ := leaseOwnerReference(context.Background(), client, tc.pod)

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("leaseOwnerReference() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func deploymentOwnerRef() meta_v1.OwnerReference {
	return meta_v1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "nginx-ingress-controller",
		UID:        "deploy-uid",
	}
}

func getTestLease(t *testing.T, client *fake.Clientset) *coordination_v1.Lease {
	t.Helper()
	lease, err := client.CoordinationV1().Leases(testLeaseNamespace).Get(context.Background(), testLeaseName, meta_v1.GetOptions{})
	if err != nil {
		t.Fatalf("getting lease: %v", err)
	}
	return lease
}

func TestEnsureLeaseOwnerReference_CreatesLeaseWithOwner(t *testing.T) {
	t.Parallel()
	client := fake.NewClientset()
	owner := deploymentOwnerRef()

	if err := ensureLeaseOwnerReference(context.Background(), client, testLeaseNamespace, testLeaseName, owner); err != nil {
		t.Fatalf("ensureLeaseOwnerReference() returned error: %v", err)
	}

	lease := getTestLease(t, client)
	if diff := cmp.Diff([]meta_v1.OwnerReference{owner}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references mismatch (-want +got):\n%s", diff)
	}
	if lease.Spec.HolderIdentity != nil {
		t.Errorf("expected new lease to have no holder, got %q", *lease.Spec.HolderIdentity)
	}
}

func TestEnsureLeaseOwnerReference_AddsOwnerToExistingLease(t *testing.T) {
	t.Parallel()
	holder := "nginx-ingress-pod"
	existing := &coordination_v1.Lease{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:        testLeaseName,
			Namespace:   testLeaseNamespace,
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "Helm"},
			Annotations: map[string]string{"meta.helm.sh/release-name": "my-release"},
		},
		Spec: coordination_v1.LeaseSpec{HolderIdentity: &holder},
	}
	client := fake.NewClientset(existing)
	owner := deploymentOwnerRef()

	if err := ensureLeaseOwnerReference(context.Background(), client, testLeaseNamespace, testLeaseName, owner); err != nil {
		t.Fatalf("ensureLeaseOwnerReference() returned error: %v", err)
	}

	lease := getTestLease(t, client)
	if diff := cmp.Diff([]meta_v1.OwnerReference{owner}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(existing.Spec, lease.Spec); diff != "" {
		t.Errorf("lease spec must be preserved (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(existing.Labels, lease.Labels); diff != "" {
		t.Errorf("lease labels must be preserved (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(existing.Annotations, lease.Annotations); diff != "" {
		t.Errorf("lease annotations must be preserved (-want +got):\n%s", diff)
	}
}

func TestEnsureLeaseOwnerReference_KeepsUnrelatedOwners(t *testing.T) {
	t.Parallel()
	other := meta_v1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "other-uid"}
	existing := &coordination_v1.Lease{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:            testLeaseName,
			Namespace:       testLeaseNamespace,
			OwnerReferences: []meta_v1.OwnerReference{other},
		},
	}
	client := fake.NewClientset(existing)
	owner := deploymentOwnerRef()

	if err := ensureLeaseOwnerReference(context.Background(), client, testLeaseNamespace, testLeaseName, owner); err != nil {
		t.Fatalf("ensureLeaseOwnerReference() returned error: %v", err)
	}

	lease := getTestLease(t, client)
	if diff := cmp.Diff([]meta_v1.OwnerReference{other, owner}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references mismatch (-want +got):\n%s", diff)
	}
}

func TestEnsureLeaseOwnerReference_NoUpdateWhenAlreadyOwned(t *testing.T) {
	t.Parallel()
	owner := deploymentOwnerRef()
	existing := &coordination_v1.Lease{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:            testLeaseName,
			Namespace:       testLeaseNamespace,
			OwnerReferences: []meta_v1.OwnerReference{owner},
		},
	}
	client := fake.NewClientset(existing)

	if err := ensureLeaseOwnerReference(context.Background(), client, testLeaseNamespace, testLeaseName, owner); err != nil {
		t.Fatalf("ensureLeaseOwnerReference() returned error: %v", err)
	}

	for _, action := range client.Actions() {
		if action.GetVerb() == "update" || action.GetVerb() == "create" {
			t.Errorf("expected no writes for an already-owned lease, got %s", action.GetVerb())
		}
	}
}

func TestOwnedLeaseLock_CreateSetsOwnerReference(t *testing.T) {
	t.Parallel()
	client := fake.NewClientset()
	owner := deploymentOwnerRef()
	lock := newOwnedLeaseLock(client, testLeaseNamespace, testLeaseName, resourcelock.ResourceLockConfig{Identity: "pod-a"}, &owner)

	record := resourcelock.LeaderElectionRecord{HolderIdentity: "pod-a", LeaseDurationSeconds: 30}
	if err := lock.Create(context.Background(), record); err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	lease := getTestLease(t, client)
	if diff := cmp.Diff([]meta_v1.OwnerReference{owner}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references mismatch (-want +got):\n%s", diff)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "pod-a" {
		t.Errorf("expected holder pod-a, got %v", lease.Spec.HolderIdentity)
	}

	record.HolderIdentity = "pod-a"
	record.LeaderTransitions = 1
	if err := lock.Update(context.Background(), record); err != nil {
		t.Fatalf("Update() after Create() returned error: %v", err)
	}
	lease = getTestLease(t, client)
	if lease.Spec.LeaseTransitions == nil || *lease.Spec.LeaseTransitions != 1 {
		t.Errorf("expected update to be persisted, got %v", lease.Spec.LeaseTransitions)
	}
	if diff := cmp.Diff([]meta_v1.OwnerReference{owner}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references lost on update (-want +got):\n%s", diff)
	}
}

func TestOwnedLeaseLock_CreateWithoutOwner(t *testing.T) {
	t.Parallel()
	client := fake.NewClientset()
	lock := newOwnedLeaseLock(client, testLeaseNamespace, testLeaseName, resourcelock.ResourceLockConfig{Identity: "pod-a"}, nil)

	if err := lock.Create(context.Background(), resourcelock.LeaderElectionRecord{HolderIdentity: "pod-a"}); err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	if lease := getTestLease(t, client); len(lease.OwnerReferences) != 0 {
		t.Errorf("expected no owner references, got %v", lease.OwnerReferences)
	}
}

func TestNewLeaderElector_CreatesOwnedLeaseAndReleasesOnCancel(t *testing.T) {
	t.Parallel()
	client := fake.NewClientset()
	owner := deploymentOwnerRef()

	started := make(chan struct{})
	stopped := make(chan struct{})
	elector, err := newLeaderElector(client, leaderelection.LeaderCallbacks{
		OnStartedLeading: func(context.Context) { close(started) },
		OnStoppedLeading: func() { close(stopped) },
	}, testLeaseNamespace, testLeaseName, "pod-a", &owner)
	if err != nil {
		t.Fatalf("newLeaderElector() returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go elector.Run(ctx)

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting to become leader")
	}

	lease := getTestLease(t, client)
	if diff := cmp.Diff([]meta_v1.OwnerReference{owner}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references mismatch (-want +got):\n%s", diff)
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting to stop leading")
	}

	lease = getTestLease(t, client)
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" {
		t.Errorf("expected lease to be released on cancel, holder is %q", *lease.Spec.HolderIdentity)
	}
}

func TestAddLeaderHandler_SetsLeaseOwnerOnStartedLeading(t *testing.T) {
	t.Parallel()
	existing := &coordination_v1.Lease{
		ObjectMeta: meta_v1.ObjectMeta{Name: testLeaseName, Namespace: testLeaseNamespace},
	}
	client := fake.NewClientset(existing, testDeploymentReplicaSet())
	lbc := &LoadBalancerController{
		client:                 client,
		Logger:                 nl.LoggerFromContext(context.Background()),
		leaderElectionLockName: testLeaseName,
		metadata: controllerMetadata{
			namespace: testLeaseNamespace,
			pod:       testPod(controllerRef("apps/v1", "ReplicaSet", "nginx-ingress-controller-5d8f7", "rs-uid")),
		},
	}

	started := make(chan struct{})
	lbc.addLeaderHandler(leaderelection.LeaderCallbacks{
		OnStartedLeading: func(context.Context) { close(started) },
		OnStoppedLeading: func() {},
	})
	if lbc.leaderElector == nil {
		t.Fatal("expected leader elector to be created")
	}
	// An older replica recreates the Lease without an owner.
	if err := client.CoordinationV1().Leases(testLeaseNamespace).Delete(context.Background(), testLeaseName, meta_v1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting lease: %v", err)
	}
	if _, err := client.CoordinationV1().Leases(testLeaseNamespace).Create(context.Background(), existing, meta_v1.CreateOptions{}); err != nil {
		t.Fatalf("recreating lease: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go lbc.leaderElector.Run(ctx)

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting to become leader")
	}

	lease := getTestLease(t, client)
	if diff := cmp.Diff([]meta_v1.OwnerReference{deploymentOwnerRef()}, lease.OwnerReferences); diff != "" {
		t.Errorf("owner references mismatch (-want +got):\n%s", diff)
	}
}

func TestCreateLeaderHandler_StartedLeadingTwiceDoesNotPanic(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{
		Logger:        nl.LoggerFromContext(context.Background()),
		telemetryChan: make(chan struct{}),
	}
	handler := createLeaderHandler(lbc)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("OnStartedLeading panicked when leading for the second time: %v", r)
		}
	}()
	handler.OnStartedLeading(context.Background())
	handler.OnStartedLeading(context.Background())

	select {
	case <-lbc.telemetryChan:
	default:
		t.Error("expected telemetryChan to be closed after leading")
	}
}

// Reproduces #4506.
func TestRunLeaderElector_ReacquiresLeadershipAfterLosingIt(t *testing.T) {
	t.Parallel()
	client := fake.NewClientset()

	var failLeaseUpdates atomic.Bool
	client.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failLeaseUpdates.Load() {
			return true, nil, errors.New("simulated API server outage")
		}
		return false, nil, nil
	})
	client.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failLeaseUpdates.Load() {
			return true, nil, errors.New("simulated API server outage")
		}
		return false, nil, nil
	})

	started := make(chan struct{}, 4)
	stopped := make(chan struct{}, 4)
	lbc := &LoadBalancerController{
		client:                 client,
		Logger:                 nl.LoggerFromContext(context.Background()),
		leaderElectionLockName: testLeaseName,
		metadata:               controllerMetadata{namespace: testLeaseNamespace, pod: testPod()},
	}
	callbacks := leaderelection.LeaderCallbacks{
		OnStartedLeading: func(context.Context) { started <- struct{}{} },
		OnStoppedLeading: func() { stopped <- struct{}{} },
	}
	elector, err := newLeaderElectorWithTimings(client, callbacks, testLeaseNamespace, testLeaseName, "pod-a", nil, fastLeaderElectionTimings)
	if err != nil {
		t.Fatalf("creating leader elector: %v", err)
	}
	lbc.leaderElector = elector

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		lbc.runLeaderElector(ctx)
		close(done)
	}()

	waitFor := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatalf("timed out waiting for %s", what)
		}
	}

	waitFor(started, "initial leadership")
	failLeaseUpdates.Store(true)
	waitFor(stopped, "leadership to be lost")
	failLeaseUpdates.Store(false)
	waitFor(started, "leadership to be re-acquired")
	if !lbc.leaderElector.IsLeader() {
		t.Error("expected the replica to be leader again")
	}

	cancel()
	waitFor(done, "runLeaderElector to return after cancel")
}

func TestRunLeaderElector_ReturnsWhenContextCanceled(t *testing.T) {
	t.Parallel()
	client := fake.NewClientset()
	started := make(chan struct{}, 1)
	var stoppedCount atomic.Int32
	lbc := &LoadBalancerController{
		client:                 client,
		Logger:                 nl.LoggerFromContext(context.Background()),
		leaderElectionLockName: testLeaseName,
		metadata:               controllerMetadata{namespace: testLeaseNamespace, pod: testPod()},
	}
	elector, err := newLeaderElectorWithTimings(client, leaderelection.LeaderCallbacks{
		OnStartedLeading: func(context.Context) { started <- struct{}{} },
		OnStoppedLeading: func() { stoppedCount.Add(1) },
	}, testLeaseNamespace, testLeaseName, "pod-a", nil, fastLeaderElectionTimings)
	if err != nil {
		t.Fatalf("creating leader elector: %v", err)
	}
	lbc.leaderElector = elector

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		lbc.runLeaderElector(ctx)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for leadership")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runLeaderElector did not return after the context was canceled")
	}
	if got := stoppedCount.Load(); got != 1 {
		t.Errorf("expected exactly one OnStoppedLeading call on shutdown, got %d", got)
	}
}

var fastLeaderElectionTimings = leaderElectionTimings{
	LeaseDuration: 400 * time.Millisecond,
	RenewDeadline: 200 * time.Millisecond,
	RetryPeriod:   100 * time.Millisecond,
}

// releaseDelayingClient returns a fake client that delays the Lease update
// sent when the leader releases the Lease on shutdown.
func releaseDelayingClient(delay time.Duration, released *atomic.Bool) *fake.Clientset {
	client := fake.NewClientset()
	client.PrependReactor("update", "leases", func(action k8stesting.Action) (bool, runtime.Object, error) {
		lease, ok := action.(k8stesting.UpdateAction).GetObject().(*coordination_v1.Lease)
		if ok && (lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "") {
			time.Sleep(delay)
			released.Store(true)
		}
		return false, nil, nil
	})
	return client
}

func newTestLeaderLBC(t *testing.T, client *fake.Clientset, started chan struct{}) *LoadBalancerController {
	t.Helper()
	lbc := &LoadBalancerController{
		client:                 client,
		Logger:                 nl.LoggerFromContext(context.Background()),
		leaderElectionLockName: testLeaseName,
		metadata:               controllerMetadata{namespace: testLeaseNamespace, pod: testPod()},
	}
	elector, err := newLeaderElectorWithTimings(client, leaderelection.LeaderCallbacks{
		OnStartedLeading: func(context.Context) { close(started) },
		OnStoppedLeading: func() {},
	}, testLeaseNamespace, testLeaseName, "pod-a", nil, fastLeaderElectionTimings)
	if err != nil {
		t.Fatalf("creating leader elector: %v", err)
	}
	lbc.leaderElector = elector
	return lbc
}

func TestStopLeaderElector_WaitsForLeaseRelease(t *testing.T) {
	t.Parallel()
	var released atomic.Bool
	client := releaseDelayingClient(150*time.Millisecond, &released)
	started := make(chan struct{})
	lbc := newTestLeaderLBC(t, client, started)

	ctx, cancel := context.WithCancel(context.Background())
	lbc.startLeaderElector(ctx)
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for leadership")
	}

	cancel()
	lbc.waitForLeaderElector(5 * time.Second)

	if !released.Load() {
		t.Fatal("expected the Lease to be released before waitForLeaderElector returned")
	}
	if holder := getTestLease(t, client).Spec.HolderIdentity; holder != nil && *holder != "" {
		t.Errorf("expected the Lease holder to be cleared, got %q", *holder)
	}
}

func TestStopLeaderElector_WaitIsBounded(t *testing.T) {
	t.Parallel()
	var released atomic.Bool
	client := releaseDelayingClient(3*time.Second, &released)
	started := make(chan struct{})
	lbc := newTestLeaderLBC(t, client, started)

	ctx, cancel := context.WithCancel(context.Background())
	lbc.startLeaderElector(ctx)
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for leadership")
	}

	cancel()
	start := time.Now()
	lbc.waitForLeaderElector(100 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waitForLeaderElector took %v, expected it to give up after the timeout", elapsed)
	}
}

func TestStopLeaderElector_NoElector(t *testing.T) {
	t.Parallel()
	lbc := &LoadBalancerController{Logger: nl.LoggerFromContext(context.Background())}
	lbc.waitForLeaderElector(time.Second)
}
