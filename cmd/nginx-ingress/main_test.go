package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/k8s"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	"github.com/stretchr/testify/assert"
	apps_v1 "k8s.io/api/apps/v1"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	pkgversion "k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

func TestLogTimeFormats(t *testing.T) {
	testCases := []struct {
		name      string
		logFormat string
		wantre    string
	}{
		// JSON format tests
		{
			name:      "json default time format",
			logFormat: "json",
			wantre:    `^{"time":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+.*","level":"INFO","source":\{"file":"[^"]+\.go","line":\d+\},"msg":".*}`,
		},
		{
			name:      "json unix time format",
			logFormat: "json-unix",
			wantre:    `^{"time":\d{10},"level":"INFO","source":\{"file":"[^"]+\.go","line":\d+\},"msg":".*}`,
		},
		{
			name:      "json unix-ms time format",
			logFormat: "json-unix-ms",
			wantre:    `^{"time":\d{13},"level":"INFO","source":\{"file":"[^"]+\.go","line":\d+\},"msg":".*}`,
		},
		// TEXT format tests
		{
			name:      "text default time format",
			logFormat: "text",
			wantre:    `^time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+.*level=\w+\ssource=[^:]+\.go:\d+\smsg=\w+`,
		},
		{
			name:      "text unix time format",
			logFormat: "text-unix",
			wantre:    `^time=\d{10}\slevel=\w+\ssource=[^:]+\.go:\d+\smsg=\w+`,
		},
		{
			name:      "text unix-ms time format",
			logFormat: "text-unix-ms",
			wantre:    `^time=\d{13}\slevel=\w+\ssource=[^:]+\.go:\d+\smsg=\w+`,
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := initLogger(tc.logFormat, levels.LevelInfo, &buf)
			l := nl.LoggerFromContext(ctx)
			l.Log(ctx, levels.LevelInfo, "test")
			got := buf.String()
			re := regexp.MustCompile(tc.wantre)
			if !re.MatchString(got) {
				t.Errorf("\ngot:\n%q\nwant regex:\n%q", got, tc.wantre)
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
			clientset := fake.NewClientset()
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
			clientset := fake.NewClientset()
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
			Controller:         new(true),
			BlockOwnerDeletion: new(true),
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
							Controller: new(true),
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
			clientset := fake.NewClientset(clientObjects...)

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

func TestGetAndValidateSecret(t *testing.T) {
	t.Parallel()

	jwkSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{Name: "jwk-secret", Namespace: "default"},
		Type:       api_v1.SecretTypeOpaque,
		Data:       map[string][]byte{"jwk": []byte("{}")},
	}

	tests := []struct {
		name         string
		secretNsName string
		role         secrets.SecretRole
		wantErr      string
	}{
		{
			name:         "valid for the role whose required key it carries",
			secretNsName: "default/jwk-secret",
			role:         secrets.RoleJWK,
		},
		{
			name:         "invalid for a role whose required keys it lacks",
			secretNsName: "default/jwk-secret",
			role:         secrets.RoleTLS,
			wantErr:      `default/jwk-secret is invalid: secret is missing required key "tls.crt"`,
		},
		{
			name:         "secret absent from the cluster",
			secretNsName: "default/nope",
			role:         secrets.RoleJWK,
			wantErr:      "could not find default/nope",
		},
		{
			name:         "unparseable secret reference",
			secretNsName: "not-a-namespaced-name",
			role:         secrets.RoleJWK,
			wantErr:      "could not parse the not-a-namespaced-name argument",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			clientset := fake.NewClientset(jwkSecret)

			secret, err := getAndValidateSecret(clientset, test.secretNsName, test.role)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("getAndValidateSecret() unexpected error: %v", err)
				}
				if secret == nil || secret.Name != "jwk-secret" {
					t.Errorf("getAndValidateSecret() returned %v, want jwk-secret", secret)
				}
				return
			}

			if err == nil {
				t.Fatalf("getAndValidateSecret() expected an error containing %q, got none", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("getAndValidateSecret() error = %q, want it to contain %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestValidateIngressClass(t *testing.T) {
	t.Parallel()

	ingressClass := func(name, controller string) *networking.IngressClass {
		return &networking.IngressClass{
			ObjectMeta: meta_v1.ObjectMeta{Name: name},
			Spec:       networking.IngressClassSpec{Controller: controller},
		}
	}

	tests := []struct {
		name      string
		mode      string
		objects   []runtime.Object
		forbidden bool
		wantErr   string
		wantCalls int
		wantWarn  bool
	}{
		{
			name:      "strict with a valid IngressClass",
			mode:      ingressClassValidationStrict,
			objects:   []runtime.Object{ingressClass("nginx", k8s.IngressControllerName)},
			wantCalls: 1,
		},
		{
			name:      "strict with a missing IngressClass",
			mode:      ingressClassValidationStrict,
			wantErr:   `error when getting IngressClass nginx: ingressclasses.networking.k8s.io "nginx" not found`,
			wantCalls: 1,
		},
		{
			name:      "strict with an IngressClass owned by another controller",
			mode:      ingressClassValidationStrict,
			objects:   []runtime.Object{ingressClass("nginx", "example.com/other-controller")},
			wantErr:   "IngressClass with name nginx has an invalid Spec.Controller example.com/other-controller; expected nginx.org/ingress-controller",
			wantCalls: 1,
		},
		{
			name:      "strict with a forbidden read",
			mode:      ingressClassValidationStrict,
			objects:   []runtime.Object{ingressClass("nginx", k8s.IngressControllerName)},
			forbidden: true,
			wantErr:   `error when getting IngressClass nginx: missing permission: get ingressclasses.networking.k8s.io "nginx" (cluster-scoped); grant it to the NIC ServiceAccount in a ClusterRole, or set -ingress-class-validation=skip: ingressclasses.networking.k8s.io "nginx" is forbidden`,
			wantCalls: 1,
		},
		{
			name:      "skip with a missing IngressClass",
			mode:      ingressClassValidationSkip,
			wantCalls: 0,
			wantWarn:  true,
		},
		{
			name:      "skip with a forbidden read",
			mode:      ingressClassValidationSkip,
			forbidden: true,
			wantCalls: 0,
			wantWarn:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			clientset := fake.NewClientset(test.objects...)
			if test.forbidden {
				clientset.PrependReactor("get", "ingressclasses", func(action k8stesting.Action) (bool, runtime.Object, error) {
					name := action.(k8stesting.GetAction).GetName()
					return true, nil, k8serrors.NewForbidden(networking.Resource("ingressclasses"), name, errors.New("access denied"))
				})
			}

			var buf bytes.Buffer
			ctx := nl.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)))

			err := validateIngressClass(ctx, clientset, "nginx", test.mode)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateIngressClass() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("validateIngressClass() expected an error containing %q, got none", test.wantErr)
				}
				if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("validateIngressClass() error = %q, want it to contain %q", err.Error(), test.wantErr)
				}
				if test.forbidden && !k8serrors.IsForbidden(err) {
					t.Errorf("validateIngressClass() error = %v, want it to wrap a forbidden error", err)
				}
			}

			if got := len(clientset.Actions()); got != test.wantCalls {
				t.Errorf("validateIngressClass() made %d API calls, want %d: %v", got, test.wantCalls, clientset.Actions())
			}

			gotWarn := strings.Count(buf.String(), "level=WARN")
			wantWarn := 0
			if test.wantWarn {
				wantWarn = 1
			}
			if gotWarn != wantWarn {
				t.Errorf("validateIngressClass() logged %d warnings, want %d; log:\n%s", gotWarn, wantWarn, buf.String())
			}
		})
	}
}

func TestGetControllerZone(t *testing.T) {
	t.Parallel()

	node := func(name string, labels map[string]string) *api_v1.Node {
		return &api_v1.Node{ObjectMeta: meta_v1.ObjectMeta{Name: name, Labels: labels}}
	}

	tests := []struct {
		name     string
		nodeName string
		objects  []runtime.Object
		want     string
	}{
		{
			name:     "zone label on the controller node",
			nodeName: "node-1",
			objects: []runtime.Object{
				node("node-1", map[string]string{api_v1.LabelTopologyZone: "zone-a"}),
				node("node-2", map[string]string{api_v1.LabelTopologyZone: "zone-b"}),
			},
			want: "zone-a",
		},
		{
			name:     "controller node has no zone label",
			nodeName: "node-1",
			objects:  []runtime.Object{node("node-1", nil)},
			want:     "",
		},
		{
			name:     "controller node not found",
			nodeName: "node-1",
			objects:  []runtime.Object{node("node-2", map[string]string{api_v1.LabelTopologyZone: "zone-b"})},
			want:     "",
		},
		{
			name:     "empty node name",
			nodeName: "",
			objects:  []runtime.Object{node("node-1", map[string]string{api_v1.LabelTopologyZone: "zone-a"})},
			want:     "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clientset := fake.NewClientset(test.objects...)
			ctx := nl.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))

			got := getControllerZone(ctx, clientset, test.nodeName)
			if got != test.want {
				t.Errorf("getControllerZone() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGetControllerTopology(t *testing.T) {
	t.Parallel()

	pod := &api_v1.Pod{Spec: api_v1.PodSpec{NodeName: "node-1"}}
	node := &api_v1.Node{ObjectMeta: meta_v1.ObjectMeta{
		Name:   "node-1",
		Labels: map[string]string{api_v1.LabelTopologyZone: "zone-a"},
	}}

	tests := []struct {
		name         string
		enabled      bool
		wantNodeName string
		wantZone     string
		wantActions  int
	}{
		{
			name:         "enabled resolves node and zone",
			enabled:      true,
			wantNodeName: "node-1",
			wantZone:     "zone-a",
			wantActions:  1,
		},
		{
			name:        "disabled does not query the API",
			enabled:     false,
			wantActions: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clientset := fake.NewClientset(node)
			ctx := nl.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))

			gotNodeName, gotZone := getControllerTopology(ctx, clientset, pod, test.enabled)
			if gotNodeName != test.wantNodeName || gotZone != test.wantZone {
				t.Errorf("getControllerTopology() = (%q, %q), want (%q, %q)", gotNodeName, gotZone, test.wantNodeName, test.wantZone)
			}
			if got := len(clientset.Actions()); got != test.wantActions {
				t.Errorf("getControllerTopology() made %d API calls, want %d", got, test.wantActions)
			}
		})
	}
}

// forbidVerb makes every request with verb on resource fail with a Kubernetes "forbidden" error.
func forbidVerb(clientset *fake.Clientset, verb string, gr schema.GroupResource) {
	clientset.PrependReactor(verb, gr.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		name := ""
		if getAction, ok := action.(k8stesting.GetAction); ok {
			name = getAction.GetName()
		}
		return true, nil, k8serrors.NewForbidden(gr, name, errors.New(`User "system:serviceaccount:team-a:nic" cannot `+verb+` resource`))
	})
}

func TestForbiddenError(t *testing.T) {
	t.Parallel()

	forbidden := k8serrors.NewForbidden(api_v1.Resource("secrets"), "tls", errors.New("access denied"))
	notFound := k8serrors.NewNotFound(api_v1.Resource("secrets"), "tls")

	tests := []struct {
		name      string
		err       error
		verb      string
		resource  schema.GroupResource
		namespace string
		objName   string
		hint      string
		want      string
	}{
		{
			name:      "namespaced get with default hint",
			err:       forbidden,
			verb:      "get",
			resource:  api_v1.Resource("secrets"),
			namespace: "team-a",
			objName:   "tls",
			want:      `missing permission: get secrets "tls" in namespace team-a; grant it to the NIC ServiceAccount in a Role or ClusterRole: secrets "tls" is forbidden: access denied`,
		},
		{
			name:     "cluster-scoped list with custom hint",
			err:      k8serrors.NewForbidden(api_v1.Resource("nodes"), "", errors.New("access denied")),
			verb:     "list",
			resource: api_v1.Resource("nodes"),
			hint:     "grant it in a ClusterRole",
			want:     `missing permission: list nodes (cluster-scoped); grant it in a ClusterRole: nodes is forbidden: access denied`,
		},
		{
			name:     "group resource",
			err:      k8serrors.NewForbidden(networking.Resource("ingressclasses"), "nginx", errors.New("access denied")),
			verb:     "get",
			resource: networking.Resource("ingressclasses"),
			objName:  "nginx",
			want:     `missing permission: get ingressclasses.networking.k8s.io "nginx" (cluster-scoped)`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := forbiddenError(test.err, test.verb, test.resource, test.namespace, test.objName, test.hint)
			if got == nil {
				t.Fatal("forbiddenError() returned nil")
			}
			if !strings.Contains(got.Error(), test.want) {
				t.Errorf("forbiddenError() = %q, want it to contain %q", got.Error(), test.want)
			}
			if !k8serrors.IsForbidden(got) {
				t.Errorf("forbiddenError() = %v, want it to still be a forbidden error", got)
			}
			if !errors.Is(got, test.err) {
				t.Errorf("forbiddenError() = %v, want it to wrap %v", got, test.err)
			}
		})
	}

	t.Run("other errors are unchanged", func(t *testing.T) {
		t.Parallel()
		if got := forbiddenError(notFound, "get", api_v1.Resource("secrets"), "team-a", "tls", ""); got != notFound { //nolint:errorlint // identity check
			t.Errorf("forbiddenError(notFound) = %v, want the original error", got)
		}
		if got := forbiddenError(nil, "get", api_v1.Resource("secrets"), "team-a", "tls", ""); got != nil {
			t.Errorf("forbiddenError(nil) = %v, want nil", got)
		}
	})
}

func TestStartupReadsNameMissingPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource schema.GroupResource
		verb     string
		read     func(*fake.Clientset) error
		want     string
	}{
		{
			name:     "controller pod",
			resource: api_v1.Resource("pods"),
			verb:     "get",
			read: func(c *fake.Clientset) error {
				_, err := getControllerPod(context.Background(), c, "team-a", "nic-abc")
				return err
			},
			want: `missing permission: get pods "nic-abc" in namespace team-a;`,
		},
		{
			name:     "startup configmap",
			resource: api_v1.Resource("configmaps"),
			verb:     "get",
			read: func(c *fake.Clientset) error {
				_, err := getStartupConfigMap(context.Background(), c, "team-a", "nic-nginx-ingress")
				return err
			},
			want: `missing permission: get configmaps "nic-nginx-ingress" in namespace team-a;`,
		},
		{
			name:     "startup secret",
			resource: api_v1.Resource("secrets"),
			verb:     "get",
			read: func(c *fake.Clientset) error {
				_, err := getAndValidateSecret(c, "team-a/default-tls", secrets.RoleTLS)
				return err
			},
			want: `could not find team-a/default-tls: missing permission: get secrets "default-tls" in namespace team-a;`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			clientset := fake.NewClientset()
			forbidVerb(clientset, test.verb, test.resource)

			err := test.read(clientset)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), test.want)
			}
			if !k8serrors.IsForbidden(err) {
				t.Errorf("error = %v, want it to wrap a forbidden error", err)
			}
		})
	}
}

func TestStartupReadsSucceed(t *testing.T) {
	t.Parallel()

	clientset := fake.NewClientset(
		&api_v1.Pod{ObjectMeta: meta_v1.ObjectMeta{Name: "nic-abc", Namespace: "team-a"}},
		&api_v1.ConfigMap{ObjectMeta: meta_v1.ObjectMeta{Name: "nic-nginx-ingress", Namespace: "team-a"}},
	)

	pod, err := getControllerPod(context.Background(), clientset, "team-a", "nic-abc")
	if err != nil || pod.Name != "nic-abc" {
		t.Errorf("getControllerPod() = %v, %v; want pod nic-abc", pod, err)
	}
	cfm, err := getStartupConfigMap(context.Background(), clientset, "team-a", "nic-nginx-ingress")
	if err != nil || cfm.Name != "nic-nginx-ingress" {
		t.Errorf("getStartupConfigMap() = %v, %v; want configmap nic-nginx-ingress", cfm, err)
	}

	_, err = getStartupConfigMap(context.Background(), clientset, "team-a", "missing")
	if !k8serrors.IsNotFound(err) || strings.Contains(err.Error(), "missing permission") {
		t.Errorf("getStartupConfigMap(missing) error = %v, want an unchanged not-found error", err)
	}
}

func TestGetControllerZoneForbidden(t *testing.T) {
	t.Parallel()

	clientset := fake.NewClientset()
	forbidVerb(clientset, "list", api_v1.Resource("nodes"))

	var buf bytes.Buffer
	ctx := nl.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)))

	if got := getControllerZone(ctx, clientset, "node-1"); got != "" {
		t.Errorf("getControllerZone() = %q, want empty zone", got)
	}
	want := "missing permission: list nodes (cluster-scoped); grant it to the NIC ServiceAccount in a ClusterRole"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log does not contain %q; log:\n%s", want, buf.String())
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("forbidden node list is not logged as a warning; log:\n%s", buf.String())
	}
}

func crdNames(reqs []requiredCRD) []string {
	names := make([]string, 0, len(reqs))
	for _, req := range reqs {
		names = append(names, req.gvr.Resource+"."+req.gvr.Group+"/"+req.gvr.Version)
	}
	return names
}

func TestRequiredCRDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		features crdFeatures
		want     []string
	}{
		{
			name:     "nothing enabled",
			features: crdFeatures{},
			want:     []string{},
		},
		{
			name:     "custom resources",
			features: crdFeatures{customResources: true},
			want: []string{
				"virtualservers.k8s.nginx.org/v1",
				"virtualserverroutes.k8s.nginx.org/v1",
				"transportservers.k8s.nginx.org/v1",
				"policies.k8s.nginx.org/v1",
			},
		},
		{
			name:     "custom resources with global configuration, cert-manager and external-dns",
			features: crdFeatures{customResources: true, globalConfiguration: true, certManager: true, externalDNS: true},
			want: []string{
				"virtualservers.k8s.nginx.org/v1",
				"virtualserverroutes.k8s.nginx.org/v1",
				"transportservers.k8s.nginx.org/v1",
				"policies.k8s.nginx.org/v1",
				"globalconfigurations.k8s.nginx.org/v1",
				"certificates.cert-manager.io/v1",
				"dnsendpoints.externaldns.nginx.org/v1",
			},
		},
		{
			name:     "custom resource features need custom resources",
			features: crdFeatures{globalConfiguration: true, certManager: true, externalDNS: true},
			want:     []string{},
		},
		{
			name:     "app protect waf",
			features: crdFeatures{appProtect: true},
			want: []string{
				"appolicies.appprotect.f5.com/v1beta1",
				"aplogconfs.appprotect.f5.com/v1beta1",
				"apusersigs.appprotect.f5.com/v1beta1",
			},
		},
		{
			name:     "app protect waf with plm",
			features: crdFeatures{appProtect: true, plm: true},
			want: []string{
				"appolicies.appprotect.f5.com/v1",
				"aplogconfs.appprotect.f5.com/v1",
			},
		},
		{
			name:     "app protect dos",
			features: crdFeatures{appProtectDos: true},
			want: []string{
				"apdospolicies.appprotectdos.f5.com/v1beta1",
				"apdoslogconfs.appprotectdos.f5.com/v1beta1",
				"dosprotectedresources.appprotectdos.f5.com/v1beta1",
			},
		},
		{
			name:     "ingresslink",
			features: crdFeatures{ingressLink: true},
			want:     []string{"ingresslinks.cis.f5.com/v1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := crdNames(requiredCRDs(test.features))
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Errorf("requiredCRDs() =\n  %v\nwant\n  %v", got, test.want)
			}
		})
	}
}

func TestRequiredCRDsSources(t *testing.T) {
	t.Parallel()

	reqs := requiredCRDs(crdFeatures{
		customResources: true, certManager: true, externalDNS: true,
		appProtect: true, appProtectDos: true, ingressLink: true,
	})
	wantSources := map[string]string{
		"k8s.nginx.org":         crdSourceNIC,
		"externaldns.nginx.org": crdSourceNIC,
		"cert-manager.io":       crdSourceCertManager,
		"appprotect.f5.com":     crdSourceNAPWAF,
		"appprotectdos.f5.com":  crdSourceNAPDoS,
		"cis.f5.com":            crdSourceCIS,
	}
	for _, req := range reqs {
		if want := wantSources[req.gvr.Group]; req.source != want {
			t.Errorf("source of %s = %q, want %q", req.gvr.String(), req.source, want)
		}
	}

	for _, req := range requiredCRDs(crdFeatures{appProtect: true, plm: true}) {
		if req.source != crdSourcePLM {
			t.Errorf("source of %s with PLM = %q, want %q", req.gvr.String(), req.source, crdSourcePLM)
		}
	}
}

func newFakeDiscovery(resources ...*meta_v1.APIResourceList) (*fakediscovery.FakeDiscovery, *fake.Clientset) {
	clientset := fake.NewClientset()
	discovery := clientset.Discovery().(*fakediscovery.FakeDiscovery)
	discovery.Resources = resources
	return discovery, clientset
}

func apiResourceList(groupVersion string, resources ...string) *meta_v1.APIResourceList {
	list := &meta_v1.APIResourceList{GroupVersion: groupVersion}
	for _, r := range resources {
		list.APIResources = append(list.APIResources, meta_v1.APIResource{Name: r})
	}
	return list
}

func TestCheckCRDs(t *testing.T) {
	t.Parallel()

	customResources := requiredCRDs(crdFeatures{customResources: true, globalConfiguration: true})
	appProtect := requiredCRDs(crdFeatures{appProtect: true})

	tests := []struct {
		name      string
		resources []*meta_v1.APIResourceList
		reqs      []requiredCRD
		wantErrs  []string
	}{
		{
			name: "all CRDs installed",
			resources: []*meta_v1.APIResourceList{
				apiResourceList("k8s.nginx.org/v1", "virtualservers", "virtualservers/status", "virtualserverroutes", "transportservers", "policies", "globalconfigurations"),
			},
			reqs: customResources,
		},
		{
			name: "one CRD missing from a served group",
			resources: []*meta_v1.APIResourceList{
				apiResourceList("k8s.nginx.org/v1", "virtualservers", "virtualserverroutes", "policies", "globalconfigurations"),
			},
			reqs: customResources,
			wantErrs: []string{
				"CRD transportservers.k8s.nginx.org is not installed (version v1 is required); the platform admin must apply deploy/crds.yaml",
			},
		},
		{
			name: "group not served",
			reqs: appProtect,
			wantErrs: []string{
				"CRD appolicies.appprotect.f5.com is not installed (version v1beta1 is required); the platform admin must apply deploy/crds-nap-waf.yaml",
				"CRD aplogconfs.appprotect.f5.com is not installed (version v1beta1 is required); the platform admin must apply deploy/crds-nap-waf.yaml",
				"CRD apusersigs.appprotect.f5.com is not installed (version v1beta1 is required); the platform admin must apply deploy/crds-nap-waf.yaml",
			},
		},
		{
			name: "CRD installed at another version",
			resources: []*meta_v1.APIResourceList{
				apiResourceList("appprotect.f5.com/v1", "appolicies", "aplogconfs", "apusersigs"),
			},
			reqs: appProtect,
			wantErrs: []string{
				"CRD appolicies.appprotect.f5.com is not installed (version v1beta1 is required)",
				"CRD aplogconfs.appprotect.f5.com is not installed (version v1beta1 is required)",
				"CRD apusersigs.appprotect.f5.com is not installed (version v1beta1 is required)",
			},
		},
		{
			name: "nothing required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			discovery, _ := newFakeDiscovery(test.resources...)
			var buf bytes.Buffer
			ctx := nl.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)))

			checkCRDs(ctx, discovery, test.reqs)

			got := buf.String()
			if n := strings.Count(got, "level=ERROR"); n != len(test.wantErrs) {
				t.Errorf("logged %d errors, want %d; log:\n%s", n, len(test.wantErrs), got)
			}
			for _, want := range test.wantErrs {
				if !strings.Contains(got, want) {
					t.Errorf("log does not contain %q; log:\n%s", want, got)
				}
			}
		})
	}
}

func TestCheckCRDsDiscoveryError(t *testing.T) {
	t.Parallel()

	discovery, clientset := newFakeDiscovery(
		apiResourceList("k8s.nginx.org/v1", "virtualservers", "virtualserverroutes", "policies"),
	)
	// FakeDiscovery runs the clientset's reactors; fail every discovery call.
	clientset.PrependReactor("get", "resource", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(schema.GroupResource{}, "", errors.New("discovery denied"))
	})

	var buf bytes.Buffer
	ctx := nl.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)))

	checkCRDs(ctx, discovery, requiredCRDs(crdFeatures{customResources: true}))

	got := buf.String()
	if strings.Contains(got, "level=ERROR") {
		t.Errorf("logged a missing CRD error after a discovery failure; log:\n%s", got)
	}
	want := "Could not check whether the CRDs in k8s.nginx.org/v1 are installed"
	if n := strings.Count(got, want); n != 1 {
		t.Errorf("logged %q %d times, want 1; log:\n%s", want, n, got)
	}
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("discovery failure is not logged as a warning; log:\n%s", got)
	}
}
