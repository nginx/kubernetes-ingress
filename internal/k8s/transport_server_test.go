package k8s

import (
	"context"
	"testing"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	fake_versioned "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestUpdateTransportServersStatusFromEvents_FiltersEventsByReportingController(t *testing.T) {
	t.Parallel()

	tsName := "test-ts"
	tsNamespace := "default"

	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		events         []api_v1.Event
		expectedState  string
		expectedReason string
	}{
		{
			name: "only NIC event - should use NIC event",
			events: []api_v1.Event{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-nic",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime),
					Reason:              "AddedOrUpdated",
					Message:             "Configuration for TransportServer was added or updated",
					ReportingController: EventReporterName,
				},
			},
			expectedState:  conf_v1.StateValid,
			expectedReason: "AddedOrUpdated",
		},
		{
			name: "third-party event newer than NIC event - should ignore third-party and use NIC event",
			events: []api_v1.Event{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-nic",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime.Add(-1 * time.Minute)),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime.Add(-1 * time.Minute)),
					Reason:              "AddedOrUpdated",
					Message:             "Configuration for TransportServer was added or updated",
					ReportingController: EventReporterName,
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-kyverno",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime),
					Reason:              "PolicyViolation",
					Message:             "policy ns-policy/require-labels: validation error",
					ReportingController: "kyverno-admission",
				},
			},
			expectedState:  conf_v1.StateValid,
			expectedReason: "AddedOrUpdated",
		},
		{
			name: "only third-party events - should leave the existing status untouched",
			events: []api_v1.Event{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-kyverno",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime),
					Reason:              "PolicyViolation",
					Message:             "policy ns-policy/require-labels: validation error",
					ReportingController: "kyverno-admission",
				},
			},
			expectedState:  conf_v1.StateWarning,
			expectedReason: "AddedOrUpdatedWithWarning",
		},
		{
			name: "multiple NIC events - should use latest NIC event",
			events: []api_v1.Event{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-nic-old",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime.Add(-2 * time.Minute)),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime.Add(-2 * time.Minute)),
					Reason:              "AddedOrUpdatedWithError",
					Message:             "Configuration was rejected",
					ReportingController: EventReporterName,
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-nic-new",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime),
					Reason:              "AddedOrUpdated",
					Message:             "Configuration for TransportServer was added or updated",
					ReportingController: EventReporterName,
				},
			},
			expectedState:  conf_v1.StateValid,
			expectedReason: "AddedOrUpdated",
		},
		{
			name: "NIC event re-emitted after a newer NIC event - should use the re-emitted event",
			events: []api_v1.Event{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-nic-valid",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime.Add(-10 * time.Minute)),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime),
					Count:               2,
					Reason:              "AddedOrUpdated",
					Message:             "Configuration for TransportServer was added or updated",
					ReportingController: EventReporterName,
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:              "event-nic-error",
						Namespace:         tsNamespace,
						CreationTimestamp: meta_v1.NewTime(baseTime.Add(-5 * time.Minute)),
					},
					InvolvedObject: api_v1.ObjectReference{
						Name: tsName,
						UID:  "test-ts-uid",
					},
					LastTimestamp:       meta_v1.NewTime(baseTime.Add(-5 * time.Minute)),
					Reason:              "AddedOrUpdatedWithError",
					Message:             "Configuration was rejected",
					ReportingController: EventReporterName,
				},
			},
			expectedState:  conf_v1.StateValid,
			expectedReason: "AddedOrUpdated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := &conf_v1.TransportServer{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      tsName,
					Namespace: tsNamespace,
					UID:       "test-ts-uid",
				},
				Spec: conf_v1.TransportServerSpec{
					Listener: conf_v1.TransportServerListener{
						Name:     "dns-udp",
						Protocol: "UDP",
					},
				},
				Status: conf_v1.TransportServerStatus{
					State:   conf_v1.StateWarning,
					Reason:  "AddedOrUpdatedWithWarning",
					Message: "Configuration for TransportServer was added or updated with warning",
				},
			}

			var runtimeObjects []runtime.Object
			for i := range tc.events {
				runtimeObjects = append(runtimeObjects, &tc.events[i])
			}
			fakeK8sClient := fake.NewClientset(runtimeObjects...)

			fakeConfClient := fake_versioned.NewSimpleClientset(
				&conf_v1.TransportServerList{
					Items: []conf_v1.TransportServer{*ts},
				},
			)

			tsLister := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
			if err := tsLister.Add(ts); err != nil {
				t.Fatalf("Error adding TransportServer to lister: %v", err)
			}

			nsi := map[string]*namespacedInformer{
				tsNamespace: {
					transportServerLister:     tsLister,
					areCustomResourcesEnabled: true,
				},
			}

			su := &statusUpdater{
				namespacedInformers: nsi,
				confClient:          fakeConfClient,
				keyFunc:             cache.DeletionHandlingMetaNamespaceKeyFunc,
				logger:              nl.LoggerFromContext(context.Background()),
			}

			lbc := &LoadBalancerController{
				client:              fakeK8sClient,
				ingressClass:        "nginx",
				namespacedInformers: nsi,
				statusUpdater:       su,
				Logger:              nl.LoggerFromContext(context.Background()),
			}

			if err := lbc.updateTransportServersStatusFromEvents(); err != nil {
				t.Fatalf("updateTransportServersStatusFromEvents() returned error: %v", err)
			}

			updatedTs, err := fakeConfClient.K8sV1().TransportServers(tsNamespace).Get(context.TODO(), tsName, meta_v1.GetOptions{})
			if err != nil {
				t.Fatalf("Error getting TransportServer: %v", err)
			}

			if updatedTs.Status.State != tc.expectedState {
				t.Errorf("expected state %q, got %q", tc.expectedState, updatedTs.Status.State)
			}
			if updatedTs.Status.Reason != tc.expectedReason {
				t.Errorf("expected reason %q, got %q", tc.expectedReason, updatedTs.Status.Reason)
			}
		})
	}
}

// TestSyncTransportServerNamespaceNotWatched guards against a nil pointer dereference
// panic (see getNamespacedInformer) when a TransportServer task for a namespace that is
// no longer watched (e.g. its watch-namespace-label was removed) is processed.
func TestSyncTransportServerNamespaceNotWatched(t *testing.T) {
	t.Parallel()

	lbc := &LoadBalancerController{
		namespacedInformers: map[string]*namespacedInformer{},
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	lbc.syncTransportServer(task{Kind: transportserver, Key: "not-watched/some-transportserver"})
}
