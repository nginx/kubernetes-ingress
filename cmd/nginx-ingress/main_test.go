package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	"github.com/stretchr/testify/assert"
	apps_v1 "k8s.io/api/apps/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	pkgversion "k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLogFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		wantre string
	}{
		{
			name:   "glog format message",
			format: "glog",
			wantre: `^I\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "json format message",
			format: "json",
			wantre: `^{"time":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+.*","level":"INFO","source":\{"file":"[^"]+\.go","line":\d+\},"msg":".*}`,
		},
		{
			name:   "text format message",
			format: "text",
			wantre: `^time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+.*level=\w+\ssource=[^:]+\.go:\d+\smsg=\w+`,
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := initLogger(tc.format, levels.LevelInfo, &buf)
			l := nl.LoggerFromContext(ctx)
			l.Log(ctx, levels.LevelInfo, "test")
			got := buf.String()
			re := regexp.MustCompile(tc.wantre)
			if !re.MatchString(got) {
				t.Errorf("\ngot:\n%q\nwant:\n%q", got, tc.wantre)
			}
		})
	}
}

func TestK8sVersionValidation(t *testing.T) {
	testCases := []struct {
		name        string
		kubeVersion string
	}{
		{
			name:        "Earliest version 1.22.0",
			kubeVersion: "1.22.0",
		},
		{
			name:        "Minor version 1.22.5",
			kubeVersion: "1.22.5",
		},
		{
			name:        "Close to current 1.32.0",
			kubeVersion: "1.32.0",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup logger
			l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
			ctx := nl.ContextWithLogger(context.Background(), l)

			// setup kube client with version
			clientset := fake.NewSimpleClientset()
			fakeDiscovery, _ := clientset.Discovery().(*fakediscovery.FakeDiscovery)
			fakeDiscovery.FakedServerVersion = &pkgversion.Info{GitVersion: tc.kubeVersion}

			// run test
			err := validateKubernetesVersionInfo(ctx, clientset)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestK8sVersionValidationBad(t *testing.T) {
	testCases := []struct {
		name        string
		kubeVersion string
	}{
		{
			name:        "Before earliest version 1.21.0",
			kubeVersion: "1.21.0",
		},
		{
			name:        "Empty version",
			kubeVersion: "",
		},
		{
			name:        "Garbage",
			kubeVersion: "xyzabc",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup logger
			l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
			ctx := nl.ContextWithLogger(context.Background(), l)

			// setup kube client with version
			clientset := fake.NewSimpleClientset()
			fakeDiscovery, _ := clientset.Discovery().(*fakediscovery.FakeDiscovery)
			fakeDiscovery.FakedServerVersion = &pkgversion.Info{GitVersion: tc.kubeVersion}

			// run test
			err := validateKubernetesVersionInfo(ctx, clientset)
			if err == nil {
				t.Error("Wanted an error here")
			}
		})
	}
}

func TestCreateHeadlessService(t *testing.T) {
	logger := nl.LoggerFromContext(context.Background())
	controllerNamespace := "default"
	configMapName := "test-configmap"
	configMapNamespace := "default"
	configMapNamespacedName := fmt.Sprintf("%s/%s", configMapNamespace, configMapName)
	podName := "test-pod"

	podLabels := map[string]string{
		"app.kubernetes.io/name":     "nginx-ingress",
		"app.kubernetes.io/instance": "my-release",
		"pod-template-hash":          "abc123",
	}

	svcName := "test-hl-service"

	configMap := &api_v1.ConfigMap{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      configMapName,
			Namespace: configMapNamespace,
			UID:       types.UID("uid-cm"),
		},
	}

	expectedOwnerReferences := []meta_v1.OwnerReference{
		{
			APIVersion:         "v1",
			Kind:               "ConfigMap",
			Name:               configMap.Name,
			UID:                configMap.UID,
			Controller:         commonhelpers.BoolToPointerBool(true),
			BlockOwnerDeletion: commonhelpers.BoolToPointerBool(true),
		},
	}

	testCases := []struct {
		name                string
		ownerKind           string
		controllerName      string
		controllerSelectors map[string]string
		expectedSelector    map[string]string
		existingService     *api_v1.Service
		expectedAction      string
		expectedOwnerRefs   []meta_v1.OwnerReference
	}{
		{
			name:           "Create service for ReplicaSet controller",
			ownerKind:      "ReplicaSet",
			controllerName: "nginx-ingress-123",
			controllerSelectors: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
				"pod-template-hash":          "abc123",
			},
			// For ReplicaSet, pod-template-hash should be excluded
			expectedSelector: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			expectedAction:    "create",
			expectedOwnerRefs: expectedOwnerReferences,
		},
		{
			name:           "Create service for DaemonSet controller",
			ownerKind:      "DaemonSet",
			controllerName: "nginx-ingress-ds",
			controllerSelectors: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			expectedSelector: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			expectedAction:    "create",
			expectedOwnerRefs: expectedOwnerReferences,
		},
		{
			name:           "Create service for StatefulSet controller",
			ownerKind:      "StatefulSet",
			controllerName: "nginx-ingress-sts",
			controllerSelectors: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			expectedSelector: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			expectedAction:    "create",
			expectedOwnerRefs: expectedOwnerReferences,
		},
		{
			name:           "Skip update if selectors match",
			ownerKind:      "ReplicaSet",
			controllerName: "nginx-ingress-123",
			controllerSelectors: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
				"pod-template-hash":          "abc123",
			},
			expectedSelector: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			existingService: &api_v1.Service{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:            svcName,
					Namespace:       controllerNamespace,
					OwnerReferences: expectedOwnerReferences,
				},
				Spec: api_v1.ServiceSpec{
					Selector: map[string]string{
						"app.kubernetes.io/name":     "nginx-ingress",
						"app.kubernetes.io/instance": "my-release",
					},
				},
			},
			expectedAction:    "none",
			expectedOwnerRefs: expectedOwnerReferences,
		},
		{
			name:           "Update service if selectors differ",
			ownerKind:      "ReplicaSet",
			controllerName: "nginx-ingress-123",
			controllerSelectors: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
				"pod-template-hash":          "abc123",
			},
			expectedSelector: map[string]string{
				"app.kubernetes.io/name":     "nginx-ingress",
				"app.kubernetes.io/instance": "my-release",
			},
			existingService: &api_v1.Service{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:            svcName,
					Namespace:       controllerNamespace,
					OwnerReferences: expectedOwnerReferences,
				},
				Spec: api_v1.ServiceSpec{
					Selector: map[string]string{"old-label": "true"},
				},
			},
			expectedAction:    "update",
			expectedOwnerRefs: expectedOwnerReferences,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create pod with owner reference to the controller
			pod := &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      podName,
					Namespace: controllerNamespace,
					Labels:    podLabels,
					OwnerReferences: []meta_v1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       tc.ownerKind,
							Name:       tc.controllerName,
							UID:        types.UID("controller-uid-123"),
							Controller: commonhelpers.BoolToPointerBool(true),
						},
					},
				},
			}

			// Create the appropriate controller object
			var controllerObj runtime.Object
			switch tc.ownerKind {
			case "ReplicaSet":
				controllerObj = &apps_v1.ReplicaSet{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      tc.controllerName,
						Namespace: controllerNamespace,
					},
					Spec: apps_v1.ReplicaSetSpec{
						Selector: &meta_v1.LabelSelector{
							MatchLabels: tc.controllerSelectors,
						},
					},
				}
			case "DaemonSet":
				controllerObj = &apps_v1.DaemonSet{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      tc.controllerName,
						Namespace: controllerNamespace,
					},
					Spec: apps_v1.DaemonSetSpec{
						Selector: &meta_v1.LabelSelector{
							MatchLabels: tc.controllerSelectors,
						},
					},
				}
			case "StatefulSet":
				controllerObj = &apps_v1.StatefulSet{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      tc.controllerName,
						Namespace: controllerNamespace,
					},
					Spec: apps_v1.StatefulSetSpec{
						Selector: &meta_v1.LabelSelector{
							MatchLabels: tc.controllerSelectors,
						},
					},
				}
			}

			clientObjects := []runtime.Object{pod, configMap, controllerObj}
			if tc.existingService != nil {
				clientObjects = append(clientObjects, tc.existingService)
			}
			clientset := fake.NewSimpleClientset(clientObjects...)

			err := createHeadlessService(logger, clientset, controllerNamespace, svcName, configMapNamespacedName, pod)
			assert.NoError(t, err)

			service, err := clientset.CoreV1().Services(controllerNamespace).Get(context.Background(), svcName, meta_v1.GetOptions{})
			assert.NoError(t, err, "Failed to get service after create/update")

			if err == nil {
				assert.Equal(t, tc.expectedSelector, service.Spec.Selector, "Service selector mismatch")
				assert.Equal(t, tc.expectedOwnerRefs, service.OwnerReferences, "Service OwnerReferences mismatch")
			}

			actions := clientset.Actions()
			var serviceCreated, serviceUpdated bool
			for _, action := range actions {
				if action.Matches("create", "services") {
					serviceCreated = true
				}
				if action.Matches("update", "services") {
					serviceUpdated = true
				}
			}

			switch tc.expectedAction {
			case "create":
				assert.True(t, serviceCreated, "service to be created")
				assert.False(t, serviceUpdated, "no service update when creation is expected")
			case "update":
				assert.True(t, serviceUpdated, "service to be updated")
				assert.False(t, serviceCreated, "no service creation when update is expected")
			case "none":
				assert.False(t, serviceCreated, "no service creation when no action is expected")
				assert.False(t, serviceUpdated, "no service update when no action is expected")
			default:
				t.Fatalf("Invalid expectedAction: %s", tc.expectedAction)
			}
		})
	}
}
