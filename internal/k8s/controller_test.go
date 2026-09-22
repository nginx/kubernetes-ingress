package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/telemetry"

	discovery_v1 "k8s.io/api/discovery/v1"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/cert"
)

type testNginxManager struct {
	*nginx.FakeManager

	CreatedConfigNames []string
	CreatedSecretNames []string
	FailCreateForName  string
	FailCreateOnCall   int
	CreateCalls        int
	KeyValUpdates      []configs.WeightUpdate
}

func newTestNginxManager() *testNginxManager {
	return &testNginxManager{FakeManager: nginx.NewFakeManager("/etc/nginx")}
}

func (m *testNginxManager) CreateConfig(name string, content []byte) (bool, error) {
	m.CreateCalls++
	m.CreatedConfigNames = append(m.CreatedConfigNames, name)

	if m.FailCreateForName == name && m.FailCreateOnCall > 0 && m.FailCreateOnCall == m.CreateCalls {
		return false, fmt.Errorf("injected CreateConfig failure for %s at call %d", name, m.CreateCalls)
	}

	return m.FakeManager.CreateConfig(name, content)
}

func (m *testNginxManager) CreateSecret(name string, content []byte, mode os.FileMode) string {
	m.CreatedSecretNames = append(m.CreatedSecretNames, name)
	return m.FakeManager.CreateSecret(name, content, mode)
}

type secretReconciliationNginxManager struct {
	*testNginxManager
	reloadCalls int
	reloadErr   error
	onReload    func()
}

func newSecretReconciliationNginxManager() *secretReconciliationNginxManager {
	return &secretReconciliationNginxManager{
		testNginxManager: newTestNginxManager(),
	}
}

func (m *secretReconciliationNginxManager) Reload(isEndpointsUpdate bool) error {
	m.reloadCalls++
	if m.onReload != nil {
		m.onReload()
	}
	if m.reloadErr != nil {
		return m.reloadErr
	}
	return m.FakeManager.Reload(isEndpointsUpdate)
}

type fakeSecretFileManager struct{}

func (fakeSecretFileManager) AddOrUpdateSecret(secret *api_v1.Secret, role secrets.SecretRole) secrets.Materialized {
	return secrets.Materialized{Path: fmt.Sprintf("/etc/nginx/secrets/%s_%s_%s", role, secret.Namespace, secret.Name)}
}

func (fakeSecretFileManager) DeleteSecret(string, secrets.SecretRole) {}

func (fakeSecretFileManager) SecretPaths(key string, role secrets.SecretRole) secrets.Materialized {
	return secrets.Materialized{Path: fmt.Sprintf("/etc/nginx/secrets/%s_%s", role, key)}
}

// UpsertSplitClientsKeyVal records the keyval writes the weight-change fast
// lane makes, so tests can assert on them without a real NGINX process.
func (m *testNginxManager) UpsertSplitClientsKeyVal(zoneName, key, value string) {
	m.KeyValUpdates = append(m.KeyValUpdates, configs.WeightUpdate{Zone: zoneName, Key: key, Value: value})
	m.FakeManager.UpsertSplitClientsKeyVal(zoneName, key, value)
}

// fakeStore wraps FakeCustomStore to satisfy the cache.Store interface, which gained
// Bookmark and LastStoreSyncResourceVersion in k8s.io/client-go v0.36.
// FakeCustomStore was not updated upstream to implement these methods.
type fakeStore struct {
	cache.FakeCustomStore
}

// Bookmark tracks the latest resource version seen via bookmark events.
// Not needed in tests — resource version tracking is not exercised here.
func (f *fakeStore) Bookmark(_ string) {}

// LastStoreSyncResourceVersion returns the latest resource version the store has seen.
// Not needed in tests — returns empty string as a safe zero value.
func (f *fakeStore) LastStoreSyncResourceVersion() string {
	return ""
}

func createTestPolicySyncConfigurator(t *testing.T, manager nginx.Manager) *configs.Configurator {
	t.Helper()

	templateExecutor, err := version1.NewTemplateExecutor(
		filepath.Join("..", "configs", "version1", "nginx-plus.tmpl"),
		filepath.Join("..", "configs", "version1", "nginx-plus.ingress.tmpl"),
	)
	if err != nil {
		t.Fatalf("failed to create v1 template executor: %v", err)
	}

	templateExecutorV2, err := version2.NewTemplateExecutor(
		filepath.Join("..", "configs", "version2", "nginx-plus.virtualserver.tmpl"),
		filepath.Join("..", "configs", "version2", "nginx-plus.transportserver.tmpl"),
		filepath.Join("..", "configs", "version2", "oidc.tmpl"),
	)
	if err != nil {
		t.Fatalf("failed to create v2 template executor: %v", err)
	}

	return configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:            manager,
		StaticCfgParams:         &configs.StaticConfigParams{NginxVersion: nginx.NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)")},
		Config:                  configs.NewDefaultConfigParams(context.Background(), false),
		MGMTCfgParams:           configs.NewDefaultMGMTConfigParams(context.Background()),
		TemplateExecutor:        templateExecutor,
		TemplateExecutorV2:      templateExecutorV2,
		IsPlus:                  false,
		IsWildcardEnabled:       false,
		IsPrometheusEnabled:     false,
		IsLatencyMetricsEnabled: false,
	})
}

func createIngressProcessChangesController(t *testing.T, manager nginx.Manager) *LoadBalancerController {
	t.Helper()

	ingressStore := &cache.FakeCustomStore{
		GetByKeyFunc: func(_ string) (item interface{}, exists bool, err error) {
			return nil, false, nil
		},
	}

	return &LoadBalancerController{
		configurator: createTestPolicySyncConfigurator(t, manager),
		recorder:     record.NewFakeRecorder(100),
		secretStore:  secrets.NewEmptyFakeSecretsStore(),
		namespacedInformers: map[string]*namespacedInformer{
			"default": {
				ingressLister: storeToIngressLister{Store: &fakeStore{FakeCustomStore: *ingressStore}},
			},
		},
		Logger: nl.LoggerFromContext(context.Background()),
	}
}

func newHostlessIngressChange(name string) *IngressConfiguration {
	ing := createTestIngress(name, "")
	ingCfg := NewRegularIngressConfiguration(ing)
	ingCfg.ValidHosts[""] = true
	return ingCfg
}

func TestHasCorrectIngressClass(t *testing.T) {
	t.Parallel()
	ingressClass := "ing-ctrl"
	incorrectIngressClass := "gce"
	emptyClass := ""

	tests := []struct {
		lbc      *LoadBalancerController
		ing      *networking.Ingress
		expected bool
	}{
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: emptyClass},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: incorrectIngressClass},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: ingressClass},
				},
			},
			true,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{
					IngressClassName: &incorrectIngressClass,
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{
					IngressClassName: &emptyClass,
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: incorrectIngressClass},
				},
				Spec: networking.IngressSpec{
					IngressClassName: &ingressClass,
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{
					IngressClassName: &ingressClass,
				},
			},
			true,
		},
		{
			&LoadBalancerController{
				ingressClass:     ingressClass,
				metricsCollector: collectors.NewControllerFakeCollector(),
				Logger:           nl.LoggerFromContext(context.Background()),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{},
			},
			false,
		},
	}

	for _, test := range tests {
		if result := test.lbc.HasCorrectIngressClass(test.ing); result != test.expected {
			classAnnotation := "N/A"
			if class, exists := test.ing.Annotations[ingressClassKey]; exists {
				classAnnotation = class
			}
			t.Errorf("lbc.HasCorrectIngressClass(ing), lbc.ingressClass=%v, ing.Annotations['%v']=%v; got %v, expected %v",
				test.lbc.ingressClass, ingressClassKey, classAnnotation, result, test.expected)
		}
	}
}

func deepCopyWithIngressClass(obj interface{}, class string) interface{} {
	switch obj := obj.(type) {
	case *conf_v1.VirtualServer:
		objCopy := obj.DeepCopy()
		objCopy.Spec.IngressClass = class
		return objCopy
	case *conf_v1.VirtualServerRoute:
		objCopy := obj.DeepCopy()
		objCopy.Spec.IngressClass = class
		return objCopy
	case *conf_v1.TransportServer:
		objCopy := obj.DeepCopy()
		objCopy.Spec.IngressClass = class
		return objCopy
	default:
		panic(fmt.Sprintf("unknown type %T", obj))
	}
}

func TestIngressClassForCustomResources(t *testing.T) {
	t.Parallel()
	ctrl := &LoadBalancerController{
		ingressClass: "nginx",
		Logger:       nl.LoggerFromContext(context.Background()),
	}

	tests := []struct {
		lbc             *LoadBalancerController
		objIngressClass string
		expected        bool
		msg             string
	}{
		{
			lbc:             ctrl,
			objIngressClass: "nginx",
			expected:        true,
			msg:             "Ingress Controller handles a resource that matches its IngressClass",
		},
		{
			lbc:             ctrl,
			objIngressClass: "",
			expected:        true,
			msg:             "Ingress Controller handles a resource with an empty IngressClass",
		},
		{
			lbc:             ctrl,
			objIngressClass: "gce",
			expected:        false,
			msg:             "Ingress Controller doesn't handle a resource that doesn't match its IngressClass",
		},
	}

	resources := []interface{}{
		&conf_v1.VirtualServer{},
		&conf_v1.VirtualServerRoute{},
		&conf_v1.TransportServer{},
	}

	for _, r := range resources {
		for _, test := range tests {
			obj := deepCopyWithIngressClass(r, test.objIngressClass)

			result := test.lbc.HasCorrectIngressClass(obj)
			if result != test.expected {
				t.Errorf("HasCorrectIngressClass() returned %v but expected %v for the case of %q for %T", result, test.expected, test.msg, obj)
			}
		}
	}
}

func TestComparePorts(t *testing.T) {
	t.Parallel()
	scenarios := []struct {
		sp       api_v1.ServicePort
		cp       api_v1.ContainerPort
		expected bool
	}{
		{
			// match TargetPort.strval and Protocol
			api_v1.ServicePort{
				TargetPort: intstr.FromString("name"),
				Protocol:   api_v1.ProtocolTCP,
			},
			api_v1.ContainerPort{
				Name:          "name",
				Protocol:      api_v1.ProtocolTCP,
				ContainerPort: 80,
			},
			true,
		},
		{
			// don't match Name and Protocol
			api_v1.ServicePort{
				Name:     "name",
				Protocol: api_v1.ProtocolTCP,
			},
			api_v1.ContainerPort{
				Name:          "name",
				Protocol:      api_v1.ProtocolTCP,
				ContainerPort: 80,
			},
			false,
		},
		{
			// TargetPort intval mismatch, don't match by TargetPort.Name
			api_v1.ServicePort{
				Name:       "name",
				TargetPort: intstr.FromInt(80),
			},
			api_v1.ContainerPort{
				Name:          "name",
				ContainerPort: 81,
			},
			false,
		},
		{
			// match by TargetPort intval
			api_v1.ServicePort{
				TargetPort: intstr.IntOrString{
					IntVal: 80,
				},
			},
			api_v1.ContainerPort{
				ContainerPort: 80,
			},
			true,
		},
		{
			// Fall back on ServicePort.Port if TargetPort is empty
			api_v1.ServicePort{
				Name: "name",
				Port: 80,
			},
			api_v1.ContainerPort{
				Name:          "name",
				ContainerPort: 80,
			},
			true,
		},
		{
			// TargetPort intval mismatch
			api_v1.ServicePort{
				TargetPort: intstr.FromInt(80),
			},
			api_v1.ContainerPort{
				ContainerPort: 81,
			},
			false,
		},
		{
			// don't match empty ports
			api_v1.ServicePort{},
			api_v1.ContainerPort{},
			false,
		},
	}

	for _, scen := range scenarios {
		if scen.expected != compareContainerPortAndServicePort(scen.cp, scen.sp) {
			t.Errorf("Expected: %v, ContainerPort: %v, ServicePort: %v", scen.expected, scen.cp, scen.sp)
		}
	}
}

func TestFindProbeForPods(t *testing.T) {
	t.Parallel()
	pods := []*api_v1.Pod{
		{
			Spec: api_v1.PodSpec{
				Containers: []api_v1.Container{
					{
						ReadinessProbe: &api_v1.Probe{
							ProbeHandler: api_v1.ProbeHandler{
								HTTPGet: &api_v1.HTTPGetAction{
									Path: "/",
									Host: "asdf.com",
									Port: intstr.IntOrString{
										IntVal: 80,
									},
								},
							},
							PeriodSeconds: 42,
						},
						Ports: []api_v1.ContainerPort{
							{
								Name:          "name",
								ContainerPort: 80,
								Protocol:      api_v1.ProtocolTCP,
								HostIP:        "1.2.3.4",
							},
						},
					},
				},
			},
		},
	}
	svcPort := api_v1.ServicePort{
		TargetPort: intstr.FromInt(80),
	}
	probe := findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.TargetPort as int match failed: %+v", probe)
	}

	svcPort = api_v1.ServicePort{
		TargetPort: intstr.FromString("name"),
		Protocol:   api_v1.ProtocolTCP,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.TargetPort as string failed: %+v", probe)
	}

	svcPort = api_v1.ServicePort{
		TargetPort: intstr.FromInt(80),
		Protocol:   api_v1.ProtocolTCP,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.TargetPort as int failed: %+v", probe)
	}

	svcPort = api_v1.ServicePort{
		Port: 80,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.Port should match if TargetPort is not set: %+v", probe)
	}

	svcPort = api_v1.ServicePort{
		TargetPort: intstr.FromString("wrong_name"),
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe != nil {
		t.Errorf("ServicePort.TargetPort should not have matched string: %+v", probe)
	}

	svcPort = api_v1.ServicePort{
		TargetPort: intstr.FromInt(22),
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe != nil {
		t.Errorf("ServicePort.TargetPort should not have matched int: %+v", probe)
	}

	svcPort = api_v1.ServicePort{
		Port: 22,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe != nil {
		t.Errorf("ServicePort.Port mismatch: %+v", probe)
	}
}

func TestGetServicePortForIngressPort(t *testing.T) {
	t.Parallel()
	fakeClient := fake.NewClientset()

	cnf := configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:            &nginx.LocalManager{},
		StaticCfgParams:         &configs.StaticConfigParams{},
		Config:                  &configs.ConfigParams{},
		TemplateExecutor:        &version1.TemplateExecutor{},
		TemplateExecutorV2:      &version2.TemplateExecutor{},
		LatencyCollector:        nil,
		LabelUpdater:            nil,
		IsPlus:                  false,
		IsWildcardEnabled:       false,
		IsPrometheusEnabled:     false,
		IsLatencyMetricsEnabled: false,
	})
	lbc := LoadBalancerController{
		client:           fakeClient,
		ingressClass:     "nginx",
		configurator:     cnf,
		metricsCollector: collectors.NewControllerFakeCollector(),
		Logger:           nl.LoggerFromContext(context.Background()),
	}
	svc := api_v1.Service{
		TypeMeta: meta_v1.TypeMeta{},
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "coffee-svc",
			Namespace: "default",
		},
		Spec: api_v1.ServiceSpec{
			Ports: []api_v1.ServicePort{
				{
					Name:       "foo",
					Port:       80,
					TargetPort: intstr.FromInt(22),
				},
			},
		},
		Status: api_v1.ServiceStatus{},
	}
	backendPort := networking.ServiceBackendPort{
		Name: "foo",
	}
	svcPort := lbc.getServicePortForIngressPort(backendPort, &svc)
	if svcPort == nil || svcPort.Port != 80 {
		t.Errorf("TargetPort string match failed: %+v", svcPort)
	}

	backendPort = networking.ServiceBackendPort{
		Number: 80,
	}
	svcPort = lbc.getServicePortForIngressPort(backendPort, &svc)
	if svcPort == nil || svcPort.Port != 80 {
		t.Errorf("TargetPort int match failed: %+v", svcPort)
	}

	backendPort = networking.ServiceBackendPort{
		Number: 22,
	}
	svcPort = lbc.getServicePortForIngressPort(backendPort, &svc)
	if svcPort != nil {
		t.Errorf("Mismatched ints should not return port: %+v", svcPort)
	}
	backendPort = networking.ServiceBackendPort{
		Name: "bar",
	}
	svcPort = lbc.getServicePortForIngressPort(backendPort, &svc)
	if svcPort != nil {
		t.Errorf("Mismatched strings should not return port: %+v", svcPort)
	}
}

func TestFormatWarningsMessages(t *testing.T) {
	t.Parallel()
	warnings := []string{"Test warning", "Test warning 2"}

	expected := "Test warning; Test warning 2"
	result := formatWarningMessages(warnings)

	if result != expected {
		t.Errorf("formatWarningMessages(%v) returned %v but expected %v", warnings, result, expected)
	}
}

func TestGetEndpointsFromEndpointSlices_DuplicateEndpointsInOneEndpointSlice(t *testing.T) {
	t.Parallel()
	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}

	endpointReady := true

	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
		expectedEndpoints []podEndpoint
	}{
		{
			desc: "duplicate endpoints in an endpointslice",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err != nil {
				t.Fatal(err)
			}
			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("lbc.getEndpointsForPortFromEndpointSlices() got %v, want %v",
					gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointsFromEndpointSlices_TwoDifferentEndpointsInOnEndpointSlice(t *testing.T) {
	t.Parallel()
	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}
	endpointReady := true

	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
		expectedEndpoints []podEndpoint
	}{
		{
			desc: "two different endpoints in one endpoint slice",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
				},
				{
					Address: "5.6.7.8:8080",
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err != nil {
				t.Fatal(err)
			}
			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("lbc.getEndpointsForPortFromEndpointSlices() got %v, want %v",
					gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointsFromEndpointSlices_DuplicateEndpointsAcrossTwoEndpointSlices(t *testing.T) {
	t.Parallel()
	endpointPort := int32(8080)

	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}

	endpointReady := true

	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
		expectedEndpoints []podEndpoint
	}{
		{
			desc: "duplicate endpoints across two endpointslices",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
				},
				{
					Address: "5.6.7.8:8080",
				},
				{
					Address: "10.0.0.1:8080",
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
						{
							Addresses: []string{
								"10.0.0.1",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err != nil {
				t.Fatal(err)
			}
			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("lbc.getEndpointsForPortFromEndpointSlices() got %v, want %v",
					gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointsFromEndpointSlices_TwoDifferentEndpointsInOnEndpointSliceOneEndpointNotReady(t *testing.T) {
	t.Parallel()
	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}
	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
		expectedEndpoints []podEndpoint
	}{
		{
			desc: "two different endpoints in one endpoint slice",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(false),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err != nil {
				t.Fatal(err)
			}
			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("lbc.getEndpointsForPortFromEndpointSlices() got %v, want %v",
					gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointsFromEndpointSlices_TwoDifferentEndpointsAcrossTwoEndpointSlicesOneEndpointNotReady(t *testing.T) {
	t.Parallel()
	endpointPort := int32(8080)

	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}

	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
		expectedEndpoints []podEndpoint
	}{
		{
			desc: "duplicate endpoints across two endpointslices",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
					},
				},
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"10.0.0.1",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(false),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err != nil {
				t.Fatal(err)
			}
			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("lbc.getEndpointsForPortFromEndpointSlices() got %v, want %v",
					gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointsFromEndpointSlices_ErrorsOnInvalidTargetPort(t *testing.T) {
	t.Parallel()
	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}

	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
	}{
		{
			desc: "Target Port should be 0",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       0,
							TargetPort: intstr.FromInt(0),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			_, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err == nil {
				t.Logf("%s but was %+v\n", test.desc, test.svc.Spec.Ports[0].TargetPort.IntVal)
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestGetEndpointsFromEndpointSlices_ErrorsOnNoEndpointSlicesFound(t *testing.T) {
	t.Parallel()
	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}

	tests := []struct {
		desc              string
		svc               api_v1.Service
		svcEndpointSlices []discovery_v1.EndpointSlice
	}{
		{
			desc: "No EndpointSlices should be found",
			svc: api_v1.Service{
				TypeMeta: meta_v1.TypeMeta{},
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee-svc",
					Namespace: "default",
				},
				Spec: api_v1.ServiceSpec{
					Ports: []api_v1.ServicePort{
						{
							Name:       "foo",
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
				Status: api_v1.ServiceStatus{},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{},
		},
	}

	for _, test := range tests {
		test := test // address gosec G601
		t.Run(test.desc, func(t *testing.T) {
			_, err := lbc.getEndpointsForPortFromEndpointSlices(test.svcEndpointSlices, backendServicePort, &test.svc)
			if err == nil {
				t.Logf("%s but got %+v\n", test.desc, test.svcEndpointSlices)
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindOnePodInOneEndpointSlice(t *testing.T) {
	t.Parallel()
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "find one pod in one endpointslice",
			targetPort: 8080,
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_GetsEndpointsOnNilValues(t *testing.T) {
	t.Parallel()
	boolPointer := func(b bool) *bool { return &b }

	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		want              []podEndpoint
	}{
		{
			desc:       "no endpoints selected on nil endpoint port",
			targetPort: 8080,
			want:       nil,
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: nil,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
					},
				},
			},
		},
		{
			desc:       "no endpoints selected on nil endpoint condition",
			targetPort: 8080,
			want:       nil,
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: nil,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)
			if !cmp.Equal(got, test.want) {
				t.Error(cmp.Diff(got, test.want))
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindOnePodInTwoEndpointSlicesWithDuplicateEndpoints(t *testing.T) {
	t.Parallel()
	endpointPort := int32(8080)
	endpointReady := true
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "find one pod in two endpointslices with duplicate endpoints",
			targetPort: 8080,
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindTwoPodsInOneEndpointSlice(t *testing.T) {
	t.Parallel()
	endpointReady := true
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "find two pods in one endpointslice",
			targetPort: 8080,
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
				{
					Address: "5.6.7.8:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "5.6.7.8",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindTwoPodsInTwoEndpointSlices(t *testing.T) {
	t.Parallel()
	endpointPort := int32(8080)
	endpointReady := true
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "find two pods in two endpointslices",
			targetPort: 8080,
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
				{
					Address: "5.6.7.8:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "5.6.7.8",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReady,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindOnePodEndpointInOneEndpointSliceWithOneEndpointNotReady(t *testing.T) {
	t.Parallel()
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "find two pods in one endpointslice",
			targetPort: 8080,
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "5.6.7.8",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(false),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindOnePodEndpointInTwoEndpointSlicesWithOneEndpointNotReady(t *testing.T) {
	t.Parallel()
	endpointPort := int32(8080)
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "find two pods in two endpointslices",
			targetPort: 8080,
			expectedEndpoints: []podEndpoint{
				{
					Address: "1.2.3.4:8080",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "5.6.7.8",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
					},
				},
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(false),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_FindNoPods(t *testing.T) {
	t.Parallel()
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:              "find no pods",
			targetPort:        8080,
			expectedEndpoints: nil,
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
			},
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"5.4.3.2",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: new(true),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func TestGetEndpointSlicesBySubselectedPods_TargetPortMismatch(t *testing.T) {
	t.Parallel()
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc              string
		targetPort        int32
		svcEndpointSlices []discovery_v1.EndpointSlice
		pods              []*api_v1.Pod
		expectedEndpoints []podEndpoint
	}{
		{
			desc:       "targetPort mismatch",
			targetPort: 21,
			svcEndpointSlices: []discovery_v1.EndpointSlice{
				{
					Ports: []discovery_v1.EndpointPort{
						{
							Port: new(int32(8080)),
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
						},
					},
				},
			},
			pods: []*api_v1.Pod{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind:       "Deployment",
								Name:       "deploy-1",
								Controller: boolPointer(true),
							},
						},
					},
					Status: api_v1.PodStatus{
						PodIP: "1.2.3.4",
					},
				},
			},
			expectedEndpoints: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndpoints := getEndpointsFromEndpointSlicesForSubselectedPods(test.targetPort, test.pods, test.svcEndpointSlices)

			if result := unorderedEqual(gotEndpoints, test.expectedEndpoints); !result {
				t.Errorf("getEndpointsFromEndpointSlicesForSubselectedPods() = got %v, want %v", gotEndpoints, test.expectedEndpoints)
			}
		})
	}
}

func unorderedEqual(got, want []podEndpoint) bool {
	if len(got) != len(want) {
		return false
	}
	exists := make(map[string]bool)
	for _, value := range got {
		exists[value.Address] = true
	}
	for _, value := range want {
		if !exists[value.Address] {
			return false
		}
	}
	return true
}

func TestGetStatusFromEventTitle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eventTitle string
		expected   string
	}{
		{
			eventTitle: "",
			expected:   "",
		},
		{
			eventTitle: "AddedOrUpdatedWithError",
			expected:   "Invalid",
		},
		{
			eventTitle: "Rejected",
			expected:   "Invalid",
		},
		{
			eventTitle: "NoVirtualServersFound",
			expected:   "Invalid",
		},
		{
			eventTitle: "Missing Secret",
			expected:   "Invalid",
		},
		{
			eventTitle: "UpdatedWithError",
			expected:   "Invalid",
		},
		{
			eventTitle: "AddedOrUpdatedWithWarning",
			expected:   "Warning",
		},
		{
			eventTitle: "UpdatedWithWarning",
			expected:   "Warning",
		},
		{
			eventTitle: "AddedOrUpdated",
			expected:   "Valid",
		},
		{
			eventTitle: "Updated",
			expected:   "Valid",
		},
		{
			eventTitle: "New State",
			expected:   "",
		},
	}

	for _, test := range tests {
		result := getStatusFromEventTitle(test.eventTitle)
		if result != test.expected {
			t.Errorf("getStatusFromEventTitle(%v) returned %v but expected %v", test.eventTitle, result, test.expected)
		}
	}
}

func TestGetPoliciesGlobalWatch(t *testing.T) {
	t.Parallel()
	validPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			AccessControl: &conf_v1.AccessControl{
				Allow: []string{"127.0.0.1"},
			},
		},
	}

	validPolicyIngressClass := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-policy-ingress-class",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressClass: "test-class",
			AccessControl: &conf_v1.AccessControl{
				Allow: []string{"127.0.0.1"},
			},
		},
	}

	invalidPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{},
	}

	policyLister := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (item interface{}, exists bool, err error) {
			switch key {
			case "default/valid-policy":
				return validPolicy, true, nil
			case "default/valid-policy-ingress-class":
				return validPolicyIngressClass, true, nil
			case "default/invalid-policy":
				return invalidPolicy, true, nil
			case "nginx-ingress/valid-policy":
				return nil, false, nil
			default:
				return nil, false, errors.New("GetByKey error")
			}
		},
	}}

	nsi := make(map[string]*namespacedInformer)
	nsi[""] = &namespacedInformer{policyLister: policyLister}

	lbc := LoadBalancerController{
		isNginxPlus:         true,
		namespacedInformers: nsi,
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	policyRefs := []conf_v1.PolicyReference{
		{
			Name: "valid-policy",
			// Namespace is implicit here
		},
		{
			Name:      "invalid-policy",
			Namespace: "default",
		},
		{
			Name:      "valid-policy", // doesn't exist
			Namespace: "nginx-ingress",
		},
		{
			Name:      "some-policy", // will make lister return error
			Namespace: "nginx-ingress",
		},
		{
			Name:      "valid-policy-ingress-class",
			Namespace: "default",
		},
	}

	expectedPolicies := []*conf_v1.Policy{validPolicy}
	expectedErrors := []error{
		errors.New("policy default/invalid-policy is invalid: spec: Invalid value: \"\": must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`, `basicAuth`, `apiKey`, `cache`, `cors`, `externalAuth`, `hsts`, `jwt`, `oidc`, `oidcNative`, `waf`"),
		errors.New("policy nginx-ingress/valid-policy doesn't exist"),
		errors.New("failed to get policy nginx-ingress/some-policy: GetByKey error"),
		errors.New("referenced policy default/valid-policy-ingress-class has incorrect ingress class: test-class (controller ingress class: )"),
	}

	result, errors := lbc.getPolicies(policyRefs, "default")
	if !reflect.DeepEqual(result, expectedPolicies) {
		t.Errorf("lbc.getPolicies() returned \n%v but \nexpected %v", result, expectedPolicies)
	}
	if diff := cmp.Diff(expectedErrors, errors, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("lbc.getPolicies() mismatch (-want +got):\n%s", diff)
	}
}

func TestGetPoliciesNamespacedWatch(t *testing.T) {
	t.Parallel()
	validPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			AccessControl: &conf_v1.AccessControl{
				Allow: []string{"127.0.0.1"},
			},
		},
	}

	validPolicyIngressClass := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-policy-ingress-class",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressClass: "test-class",
			AccessControl: &conf_v1.AccessControl{
				Allow: []string{"127.0.0.1"},
			},
		},
	}

	invalidPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{},
	}

	policyLister := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (item interface{}, exists bool, err error) {
			switch key {
			case "default/valid-policy":
				return validPolicy, true, nil
			case "default/valid-policy-ingress-class":
				return validPolicyIngressClass, true, nil
			case "default/invalid-policy":
				return invalidPolicy, true, nil
			case "nginx-ingress/valid-policy":
				return nil, false, nil
			default:
				return nil, false, errors.New("GetByKey error")
			}
		},
	}}

	nsi := make(map[string]*namespacedInformer)
	// simulate a watch of the default namespace
	nsi["default"] = &namespacedInformer{policyLister: policyLister}

	lbc := LoadBalancerController{
		isNginxPlus:         true,
		namespacedInformers: nsi,
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	policyRefs := []conf_v1.PolicyReference{
		{
			Name: "valid-policy",
			// Namespace is implicit here
		},
		{
			Name:      "invalid-policy",
			Namespace: "default",
		},
		{
			Name:      "valid-policy",  // doesn't exist
			Namespace: "nginx-ingress", // not watched
		},
		{
			Name:      "valid-policy-ingress-class",
			Namespace: "default",
		},
	}

	expectedPolicies := []*conf_v1.Policy{validPolicy}
	expectedErrors := []error{
		errors.New("policy default/invalid-policy is invalid: spec: Invalid value: \"\": must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`, `basicAuth`, `apiKey`, `cache`, `cors`, `externalAuth`, `hsts`, `jwt`, `oidc`, `oidcNative`, `waf`"),
		errors.New("failed to get namespace nginx-ingress"),
		errors.New("referenced policy default/valid-policy-ingress-class has incorrect ingress class: test-class (controller ingress class: )"),
	}

	result, errors := lbc.getPolicies(policyRefs, "default")
	if !reflect.DeepEqual(result, expectedPolicies) {
		t.Errorf("lbc.getPolicies() returned \n%v but \nexpected %v", result, expectedPolicies)
	}
	if diff := cmp.Diff(expectedErrors, errors, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("lbc.getPolicies() mismatch (-want +got):\n%s", diff)
	}
}

func TestCreatePolicyMap(t *testing.T) {
	t.Parallel()
	policies := []*conf_v1.Policy{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-2",
				Namespace: "default",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "nginx-ingress",
			},
		},
	}

	expected := map[string]*conf_v1.Policy{
		"default/policy-1": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
		},
		"default/policy-2": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-2",
				Namespace: "default",
			},
		},
		"nginx-ingress/policy-1": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "nginx-ingress",
			},
		},
	}

	result := createPolicyMap(policies)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("createPolicyMap() returned \n%s but expected \n%s", policyMapToString(result), policyMapToString(expected))
	}
}

func TestCreateIngressEx_SetsWarningWhenReferencedPolicyMissing(t *testing.T) {
	t.Parallel()

	ing := createTestIngress("ing-with-missing-policy", "example.com")
	ing.Annotations[configs.PoliciesAnnotation] = "missing-policy"

	policyLister := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(_ string) (item interface{}, exists bool, err error) {
			return nil, false, nil
		},
	}}

	lbc := LoadBalancerController{
		namespacedInformers: map[string]*namespacedInformer{
			"default": {policyLister: policyLister},
		},
		areCustomResourcesEnabled: true,
		Logger:                    nl.LoggerFromContext(context.Background()),
	}

	ingEx := lbc.createIngressEx(ing, map[string]bool{"example.com": true}, nil)
	if len(ingEx.PolicyWarnings) == 0 {
		t.Fatalf("expected policy warning when referenced policy is missing")
	}

	if !strings.Contains(ingEx.PolicyWarnings[0], "doesn't exist") {
		t.Fatalf("expected missing policy warning, got: %v", ingEx.PolicyWarnings[0])
	}

	ingConfig := NewRegularIngressConfiguration(ing)
	ingForEvent := mergeIngressPolicyWarnings(ingConfig, ingEx, nil)
	if len(ingForEvent.Warnings) == 0 {
		t.Fatalf("expected ingress warnings to include policy warning for event/status updates")
	}
}

func TestCreateIngressEx_SetsWarningWhenPoliciesAnnotationUsedWithoutCustomResources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
	}{
		{name: "nginx.org annotation", annotation: configs.PoliciesAnnotation},
		{name: "nginx.com annotation", annotation: configs.PoliciesAnnotationPlus},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ing := createTestIngress("ing-with-policy-no-crds", "example.com")
			ing.Annotations[tc.annotation] = "some-policy"

			lbc := LoadBalancerController{
				namespacedInformers: map[string]*namespacedInformer{
					"default": {},
				},
				areCustomResourcesEnabled: false,
				Logger:                    nl.LoggerFromContext(context.Background()),
			}

			ingEx := lbc.createIngressEx(ing, map[string]bool{"example.com": true}, nil)
			if len(ingEx.PolicyWarnings) == 0 {
				t.Fatalf("expected warning when policies annotation is used without custom resources enabled")
			}

			if !strings.Contains(ingEx.PolicyWarnings[0], "custom resources are not enabled") {
				t.Fatalf("expected custom resources warning, got: %v", ingEx.PolicyWarnings[0])
			}

			ingConfig := NewRegularIngressConfiguration(ing)
			ingForEvent := mergeIngressPolicyWarnings(ingConfig, ingEx, nil)
			if len(ingForEvent.Warnings) == 0 {
				t.Fatalf("expected ingress warnings to surface for event/status updates")
			}
		})
	}
}

func TestCreateIngressEx_NoSpuriousWarningWhenTLSSecretNameEmpty(t *testing.T) {
	t.Parallel()

	// Ingress with a tls: block that has no secretName — relies on --wildcard-tls-secret.
	ing := createTestIngress("wildcard-tls-ingress", "example.com")
	ing.Spec.TLS = []networking.IngressTLS{
		{
			Hosts: []string{"example.com"},
			// SecretName intentionally absent — relying on wildcard TLS secret.
		},
	}

	tests := []struct {
		name              string
		wildcardTLSSecret string
	}{
		{
			name:              "wildcard TLS configured",
			wildcardTLSSecret: "default/wildcard-tls-secret",
		},
		{
			name:              "wildcard TLS not configured",
			wildcardTLSSecret: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lbc := LoadBalancerController{
				namespacedInformers: map[string]*namespacedInformer{
					"default": {},
				},
				secretStore: secrets.NewEmptyFakeSecretsStore(),
				specialSecrets: specialSecrets{
					wildcardTLSSecret: tc.wildcardTLSSecret,
				},
				Logger: nl.LoggerFromContext(context.Background()),
			}

			ingEx := lbc.createIngressEx(ing, map[string]bool{"example.com": true}, nil)

			// A tls: block with no secretName produces no SecretRefs entry at all:
			// createIngressEx skips the store lookup to avoid a spurious
			// "secret doesn't exist" warning on every sync. addSSLConfig only
			// looks the key up when tlsSecret != "", and otherwise falls through
			// to the wildcard path, so nothing downstream reads it.
			if len(ingEx.SecretRefs) != 0 {
				t.Errorf("expected no SecretRefs entries for an empty-secretName TLS block, got %d", len(ingEx.SecretRefs))
			}
		})
	}
}

func TestSyncPolicy_UpdatesMergeableIngressesWhenPolicyChanges(t *testing.T) {
	t.Parallel()

	master := createTestIngressMaster("master-ingress", "example.com")
	minion := createTestIngressMinion("minion-ingress", "example.com", "/")
	minion.Spec.Rules[0].IngressRuleValue.HTTP.Paths[0].Backend = networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: "svc",
			Port: networking.ServiceBackendPort{Number: 80},
		},
	}
	minion.Annotations[configs.PoliciesAnnotation] = "test-policy"

	configuration := createTestConfiguration()
	configuration.AddOrUpdateIngress(master)
	configuration.AddOrUpdateIngress(minion)

	pol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressClass: "different-class",
			AccessControl: &conf_v1.AccessControl{
				Allow: []string{"127.0.0.1"},
			},
		},
	}

	policyLister := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(key string) (item interface{}, exists bool, err error) {
			if key == "default/test-policy" {
				return pol, true, nil
			}
			return nil, false, nil
		},
	}}

	svcLister := &fakeStore{cache.FakeCustomStore{
		GetByKeyFunc: func(_ string) (item interface{}, exists bool, err error) {
			return nil, false, nil
		},
	}}

	manager := newTestNginxManager()
	cnf := createTestPolicySyncConfigurator(t, manager)

	lbc := LoadBalancerController{
		namespacedInformers: map[string]*namespacedInformer{
			"default": {
				policyLister: policyLister,
				svcLister:    svcLister,
			},
		},
		configuration:             configuration,
		configurator:              cnf,
		recorder:                  record.NewFakeRecorder(100),
		ingressClass:              "nginx",
		areCustomResourcesEnabled: true,
		Logger:                    nl.LoggerFromContext(context.Background()),
	}

	lbc.syncPolicy(task{Key: "default/test-policy"})

	if len(manager.CreatedConfigNames) == 0 {
		t.Fatalf("expected mergeable ingress config to be created on policy update")
	}

	foundMasterConfig := false
	for _, name := range manager.CreatedConfigNames {
		if name == "default-master-ingress" {
			foundMasterConfig = true
			break
		}
	}

	if !foundMasterConfig {
		t.Fatalf("expected config for mergeable master ingress to be updated, got configs: %v", manager.CreatedConfigNames)
	}
}

func TestProcessChangesHostlessDeleteFailureStillProcessesNextAdd(t *testing.T) {
	t.Parallel()

	manager := newTestNginxManager()
	lbc := createIngressProcessChangesController(t, manager)

	oldCfg := newHostlessIngressChange("hostless-old")
	oldEx := lbc.createIngressEx(oldCfg.Ingress, oldCfg.ValidHosts, nil)
	_, err := lbc.configurator.AddOrUpdateIngress(oldEx)
	if err != nil {
		t.Fatalf("failed to seed old hostless ingress: %v", err)
	}

	manager.CreatedConfigNames = nil
	manager.CreateCalls = 0
	manager.FailCreateForName = "_default-server"
	manager.FailCreateOnCall = 1

	newCfg := newHostlessIngressChange("hostless-new")
	changes := []ResourceChange{
		{Op: Delete, Resource: oldCfg},
		{Op: AddOrUpdate, Resource: newCfg},
	}

	lbc.processChanges(changes)

	if lbc.configurator.HasIngress(oldCfg.Ingress) {
		t.Fatal("expected old hostless ingress to be removed")
	}
	if !lbc.configurator.HasIngress(newCfg.Ingress) {
		t.Fatal("expected new hostless ingress to be added even when delete step failed")
	}
	if manager.CreateCalls < 2 {
		t.Fatalf("expected both delete-sync and add steps to attempt default-server writes, got %d call(s)", manager.CreateCalls)
	}
}

func TestProcessChangesHostlessAddFailureAfterDeleteLeavesIntermediateState(t *testing.T) {
	t.Parallel()

	manager := newTestNginxManager()
	lbc := createIngressProcessChangesController(t, manager)

	oldCfg := newHostlessIngressChange("hostless-old")
	oldEx := lbc.createIngressEx(oldCfg.Ingress, oldCfg.ValidHosts, nil)
	_, err := lbc.configurator.AddOrUpdateIngress(oldEx)
	if err != nil {
		t.Fatalf("failed to seed old hostless ingress: %v", err)
	}

	manager.CreatedConfigNames = nil
	manager.CreateCalls = 0
	manager.FailCreateForName = "_default-server"
	manager.FailCreateOnCall = 2

	newCfg := newHostlessIngressChange("hostless-new")
	changes := []ResourceChange{
		{Op: Delete, Resource: oldCfg},
		{Op: AddOrUpdate, Resource: newCfg},
	}

	lbc.processChanges(changes)

	if lbc.configurator.HasIngress(oldCfg.Ingress) {
		t.Fatal("expected old hostless ingress to be removed")
	}
	if lbc.configurator.HasIngress(newCfg.Ingress) {
		t.Fatal("expected new hostless ingress not to be stored when add step fails")
	}
	if manager.CreateCalls < 2 {
		t.Fatalf("expected add step to be attempted after delete step, got %d call(s)", manager.CreateCalls)
	}
}

func TestProcessChangesDispatchesAddOrUpdate(t *testing.T) {
	t.Parallel()

	manager := nginx.NewFakeManager("/etc/nginx")
	lbc := createIngressProcessChangesController(t, manager)

	ing := createTestIngress("dispatch-test", "example.com")
	ingConfig := NewRegularIngressConfiguration(ing)

	changes := []ResourceChange{
		{
			Op:       AddOrUpdate,
			Resource: ingConfig,
		},
	}

	// Verify processChanges dispatches without error
	lbc.processChanges(changes)
}

func TestProcessChangesDispatchesDelete(t *testing.T) {
	t.Parallel()

	manager := nginx.NewFakeManager("/etc/nginx")
	lbc := createIngressProcessChangesController(t, manager)

	ing := createTestIngress("dispatch-delete-test", "example.com")
	ingConfig := NewRegularIngressConfiguration(ing)

	lbc.processChanges([]ResourceChange{
		{Op: Delete, Resource: ingConfig},
	})
}

func TestGetPodOwnerTypeAndName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		desc    string
		expType string
		expName string
		pod     *api_v1.Pod
	}{
		{
			desc:    "deployment",
			expType: "deployment",
			expName: "deploy-name",
			pod:     &api_v1.Pod{ObjectMeta: createTestObjMeta("Deployment", "deploy-name", true)},
		},
		{
			desc:    "stateful set",
			expType: "statefulset",
			expName: "statefulset-name",
			pod:     &api_v1.Pod{ObjectMeta: createTestObjMeta("StatefulSet", "statefulset-name", true)},
		},
		{
			desc:    "daemon set",
			expType: "daemonset",
			expName: "daemonset-name",
			pod:     &api_v1.Pod{ObjectMeta: createTestObjMeta("DaemonSet", "daemonset-name", true)},
		},
		{
			desc:    "replica set with no pod hash",
			expType: "deployment",
			expName: "replicaset-name",
			pod:     &api_v1.Pod{ObjectMeta: createTestObjMeta("ReplicaSet", "replicaset-name", false)},
		},
		{
			desc:    "replica set with pod hash",
			expType: "deployment",
			expName: "replicaset-name",
			pod: &api_v1.Pod{
				ObjectMeta: createTestObjMeta("ReplicaSet", "replicaset-name-67c6f7c5fd", true),
			},
		},
		{
			desc:    "nil controller should use default values",
			expType: "deployment",
			expName: "deploy-name",
			pod: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					OwnerReferences: []meta_v1.OwnerReference{
						{
							Name:       "deploy-name",
							Controller: nil,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			actualType, actualName := getPodOwnerTypeAndName(test.pod)
			if actualType != test.expType {
				t.Errorf("getPodOwnerTypeAndName() returned %s for owner type but expected %s", actualType, test.expType)
			}
			if actualName != test.expName {
				t.Errorf("getPodOwnerTypeAndName() returned %s for owner name but expected %s", actualName, test.expName)
			}
		})
	}
}

func createTestObjMeta(kind, name string, podHashLabel bool) meta_v1.ObjectMeta {
	meta := meta_v1.ObjectMeta{
		OwnerReferences: []meta_v1.OwnerReference{
			{
				Kind:       kind,
				Name:       name,
				Controller: new(true),
			},
		},
	}
	if podHashLabel {
		meta.Labels = map[string]string{
			"pod-template-hash": "67c6f7c5fd",
		}
	}
	return meta
}

func policyMapToString(policies map[string]*conf_v1.Policy) string {
	var keys []string
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder

	b.WriteString("[ ")
	for _, k := range keys {
		fmt.Fprintf(&b, "%q: '%s/%s', ", k, policies[k].Namespace, policies[k].Name)
	}
	b.WriteString("]")

	return b.String()
}

type testResource struct {
	keyWithKind string
}

func (*testResource) GetObjectMeta() *meta_v1.ObjectMeta {
	return nil
}

func (t *testResource) GetKeyWithKind() string {
	return t.keyWithKind
}

func (*testResource) AcquireHost(string) {
}

func (*testResource) ReleaseHost(string) {
}

func (*testResource) Wins(Resource) bool {
	return false
}

func (*testResource) IsSame(Resource) bool {
	return false
}

func (*testResource) AddWarning(string) {
}

func (*testResource) IsEqual(Resource) bool {
	return false
}

func (t *testResource) String() string {
	return t.keyWithKind
}

func TestUpdateEndpointSliceWarningState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		initialWarnings  map[string]bool
		cfgWarnings      configs.Warnings
		expectStatusCall bool
		expectedWarnings map[string]bool
	}{
		{
			name:             "clean_to_clean_skips_update",
			initialWarnings:  map[string]bool{},
			cfgWarnings:      configs.Warnings{},
			expectStatusCall: false,
			expectedWarnings: map[string]bool{},
		},
		{
			name:             "clean_to_warning_triggers_update",
			initialWarnings:  map[string]bool{},
			cfgWarnings:      configs.Warnings{&networking.Ingress{}: {"no endpoints"}},
			expectStatusCall: true,
			expectedWarnings: map[string]bool{"Ingress/test-ns/test-ingress": true},
		},
		{
			name:             "warning_to_warning_triggers_update",
			initialWarnings:  map[string]bool{"Ingress/test-ns/test-ingress": true},
			cfgWarnings:      configs.Warnings{&networking.Ingress{}: {"no endpoints"}},
			expectStatusCall: true,
			expectedWarnings: map[string]bool{"Ingress/test-ns/test-ingress": true},
		},
		{
			name:             "warning_to_clean_triggers_update",
			initialWarnings:  map[string]bool{"Ingress/test-ns/test-ingress": true},
			cfgWarnings:      configs.Warnings{},
			expectStatusCall: false, // updateResourcesStatusAndEvents is called but testResource has no type match
			expectedWarnings: map[string]bool{},
		},
		{
			name:             "clean_after_recovery_skips_update",
			initialWarnings:  map[string]bool{},
			cfgWarnings:      configs.Warnings{},
			expectStatusCall: false,
			expectedWarnings: map[string]bool{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lbc := &LoadBalancerController{
				endpointSliceWarnings: tc.initialWarnings,
				recorder:              record.NewFakeRecorder(10),
				Logger:                nl.LoggerFromContext(context.Background()),
			}

			resource := &testResource{keyWithKind: "Ingress/test-ns/test-ingress"}
			svcResources := []Resource{resource}
			resourceExes := configs.ExtendedResources{}

			lbc.updateEndpointSliceWarningState(svcResources, resourceExes, tc.cfgWarnings)

			if len(lbc.endpointSliceWarnings) != len(tc.expectedWarnings) {
				t.Errorf("expected %d warning entries, got %d", len(tc.expectedWarnings), len(lbc.endpointSliceWarnings))
			}
			for key, expected := range tc.expectedWarnings {
				if lbc.endpointSliceWarnings[key] != expected {
					t.Errorf("expected endpointSliceWarnings[%q] = %v, got %v", key, expected, lbc.endpointSliceWarnings[key])
				}
			}
		})
	}
}

func TestUpdateEndpointSliceWarningState_WarningToClearTransition(t *testing.T) {
	t.Parallel()

	// Verifies the full lifecycle: clean -> warning -> clean
	lbc := &LoadBalancerController{
		endpointSliceWarnings: make(map[string]bool),
		recorder:              record.NewFakeRecorder(10),
		Logger:                nl.LoggerFromContext(context.Background()),
	}

	resource := &testResource{keyWithKind: "Ingress/default/my-ingress"}
	svcResources := []Resource{resource}
	resourceExes := configs.ExtendedResources{}

	// Step 1: clean -> clean (no-op)
	lbc.updateEndpointSliceWarningState(svcResources, resourceExes, configs.Warnings{})
	if len(lbc.endpointSliceWarnings) != 0 {
		t.Fatalf("step 1: expected empty map, got %v", lbc.endpointSliceWarnings)
	}

	// Step 2: clean -> warning
	warningCfg := configs.Warnings{&networking.Ingress{}: {"no endpoints for auth service"}}
	lbc.updateEndpointSliceWarningState(svcResources, resourceExes, warningCfg)
	if !lbc.endpointSliceWarnings["Ingress/default/my-ingress"] {
		t.Fatalf("step 2: expected warning tracked, got %v", lbc.endpointSliceWarnings)
	}

	// Step 3: warning -> clean (recovery)
	lbc.updateEndpointSliceWarningState(svcResources, resourceExes, configs.Warnings{})
	if len(lbc.endpointSliceWarnings) != 0 {
		t.Fatalf("step 3: expected empty map after recovery, got %v", lbc.endpointSliceWarnings)
	}

	// Step 4: clean -> clean again (should be silent)
	lbc.updateEndpointSliceWarningState(svcResources, resourceExes, configs.Warnings{})
	if len(lbc.endpointSliceWarnings) != 0 {
		t.Fatalf("step 4: expected empty map, got %v", lbc.endpointSliceWarnings)
	}
}

func TestRemoveDuplicateResources(t *testing.T) {
	t.Parallel()
	tests := []struct {
		resources []Resource
		expected  []Resource
	}{
		{
			resources: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-1"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-2"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-2"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
			expected: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-1"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-2"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
		},
		{
			resources: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-2/vs-3"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
			expected: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-2/vs-3"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
		},
	}

	for _, test := range tests {
		result := removeDuplicateResources(test.resources)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("removeDuplicateResources() returned \n%v but expected \n%v", result, test.expected)
		}
	}
}

func TestPolicySecretIndexFunc(t *testing.T) {
	t.Parallel()

	policy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressMTLS: &conf_v1.IngressMTLS{
				ClientCertSecret: "shared-secret",
			},
			JWTAuth: &conf_v1.JWTAuth{
				Secret:            "shared-secret",
				TrustedCertSecret: "jwt-ca",
			},
			BasicAuth: &conf_v1.BasicAuth{
				Secret: "shared-secret",
			},
			EgressMTLS: &conf_v1.EgressMTLS{
				TLSSecret:         "egress-tls",
				TrustedCertSecret: "egress-ca",
			},
			OIDC: &conf_v1.OIDC{
				ClientSecret:      "oidc-client",
				TrustedCertSecret: "oidc-ca",
			},
			OIDCNative: &conf_v1.OIDCNative{
				ClientSecret:      "native-client",
				TrustedCertSecret: "native-ca",
			},
			APIKey: &conf_v1.APIKey{
				ClientSecret: "api-key",
			},
			ExternalAuth: &conf_v1.ExternalAuth{
				TrustedCertSecret: "other-ns/external-ca",
			},
			WAF: &conf_v1.WAF{
				ApBundleSource: &conf_v1.BundleSource{
					Secret:            "waf-client",
					TrustedCertSecret: "waf-ca",
				},
				SecurityLog: &conf_v1.SecurityLog{
					ApLogBundleSource: &conf_v1.BundleSource{
						Secret:            "legacy-log-client",
						TrustedCertSecret: "legacy-log-ca",
					},
				},
				SecurityLogs: []*conf_v1.SecurityLog{
					nil,
					{
						ApLogBundleSource: &conf_v1.BundleSource{
							Secret:            "log-client",
							TrustedCertSecret: "log-ca",
						},
					},
					{
						// Duplicate reference must only produce one index key.
						ApLogBundleSource: &conf_v1.BundleSource{
							Secret: "shared-secret",
						},
					},
				},
			},
		},
	}

	want := []string{
		"default/api-key",
		"default/egress-ca",
		"default/egress-tls",
		"default/jwt-ca",
		"default/legacy-log-ca",
		"default/legacy-log-client",
		"default/log-ca",
		"default/log-client",
		"default/native-ca",
		"default/native-client",
		"default/oidc-ca",
		"default/oidc-client",
		"default/shared-secret",
		"default/waf-ca",
		"default/waf-client",
		"other-ns/external-ca",
	}
	slices.Sort(want)

	got, err := policySecretIndexFunc(policy)
	if err != nil {
		t.Fatalf("policySecretIndexFunc() returned error: %v", err)
	}
	slices.Sort(got)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Policy Secret index keys mismatch (-want +got):\n%s", diff)
	}

	if _, err := policySecretIndexFunc(&api_v1.Secret{}); err == nil {
		t.Error("policySecretIndexFunc() expected an error for a non-Policy object")
	}
}

func TestGetPoliciesForSecret(t *testing.T) {
	t.Parallel()

	newIndexer := func(t *testing.T, policies ...*conf_v1.Policy) cache.Indexer {
		t.Helper()

		indexer := cache.NewIndexer(
			cache.MetaNamespaceKeyFunc,
			cache.Indexers{
				policySecretIndex: policySecretIndexFunc,
			},
		)

		for _, policy := range policies {
			if err := indexer.Add(policy); err != nil {
				t.Fatalf("failed to add Policy %s/%s: %v", policy.Namespace, policy.Name, err)
			}
		}

		return indexer
	}

	validPolicyA := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "external-auth",
			Namespace: "team-a",
		},
		Spec: conf_v1.PolicySpec{
			ExternalAuth: &conf_v1.ExternalAuth{
				AuthURI:           "/auth",
				AuthServiceName:   "auth-service",
				SSLEnabled:        true,
				SSLVerify:         true,
				TrustedCertSecret: "shared-ns/ca-secret",
			},
		},
	}

	validPolicyB := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "external-auth",
			Namespace: "team-b",
		},
		Spec: conf_v1.PolicySpec{
			ExternalAuth: &conf_v1.ExternalAuth{
				AuthURI:           "/auth",
				AuthServiceName:   "auth-service",
				SSLEnabled:        true,
				SSLVerify:         true,
				TrustedCertSecret: "shared-ns/ca-secret",
			},
		},
	}

	invalidPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-external-auth",
			Namespace: "team-a",
		},
		Spec: conf_v1.PolicySpec{
			ExternalAuth: &conf_v1.ExternalAuth{
				// Missing AuthServiceName makes the Policy invalid.
				AuthURI:           "/auth",
				SSLEnabled:        true,
				SSLVerify:         true,
				TrustedCertSecret: "shared-ns/ca-secret",
			},
		},
	}

	unrelatedPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "unrelated",
			Namespace: "team-b",
		},
		Spec: conf_v1.PolicySpec{
			IngressMTLS: &conf_v1.IngressMTLS{
				ClientCertSecret: "another-secret",
			},
		},
	}

	teamAIndexer := newIndexer(t, validPolicyA, invalidPolicy)
	teamBIndexer := newIndexer(t, validPolicyA, validPolicyB, unrelatedPolicy)

	lbc := &LoadBalancerController{
		namespacedInformers: map[string]*namespacedInformer{
			"team-a": {
				policySecretIndexer: teamAIndexer,
			},
			"team-b": {
				policySecretIndexer: teamBIndexer,
			},
			"secrets-only": {
				// A Secret-only informer legitimately has no Policy indexer.
				policySecretIndexer: nil,
			},
		},
		Logger: nl.LoggerFromContext(context.Background()),
	}

	got, err := lbc.getPoliciesForSecret("shared-ns", "ca-secret")
	if err != nil {
		t.Fatalf("getPoliciesForSecret() returned error: %v", err)
	}

	// validPolicy appears in two indexers but must only be returned once.
	want := []*conf_v1.Policy{validPolicyA, validPolicyB}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("getPoliciesForSecret() mismatch (-want +got):\n%s", diff)
	}

	got, err = lbc.getPoliciesForSecret("shared-ns", "unrelated")
	if err != nil {
		t.Fatalf("getPoliciesForSecret() returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("getPoliciesForSecret() returned %v for an unrelated Secret", got)
	}
}

func TestPolicySecretIndexerLifecycle(t *testing.T) {
	t.Parallel()

	indexer := cache.NewIndexer(
		cache.MetaNamespaceKeyFunc,
		cache.Indexers{
			policySecretIndex: policySecretIndexFunc,
		},
	)

	policy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "mtls",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressMTLS: &conf_v1.IngressMTLS{
				ClientCertSecret: "secret-a",
			},
		},
	}

	if err := indexer.Add(policy); err != nil {
		t.Fatalf("failed to add Policy: %v", err)
	}

	got, err := indexer.ByIndex(policySecretIndex, "default/secret-a")
	if err != nil {
		t.Fatalf("failed to query secret-a: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("secret-a matches = %d, want 1", len(got))
	}

	updated := policy.DeepCopy()
	updated.Spec.IngressMTLS.ClientCertSecret = "secret-b"

	if err := indexer.Update(updated); err != nil {
		t.Fatalf("failed to update Policy: %v", err)
	}

	got, err = indexer.ByIndex(policySecretIndex, "default/secret-a")
	if err != nil {
		t.Fatalf("failed to query old Secret: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("secret-a matches after update = %d, want 0", len(got))
	}

	got, err = indexer.ByIndex(policySecretIndex, "default/secret-b")
	if err != nil {
		t.Fatalf("failed to query new Secret: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("secret-b matches after update = %d, want 1", len(got))
	}

	if err := indexer.Delete(updated); err != nil {
		t.Fatalf("failed to delete Policy: %v", err)
	}

	got, err = indexer.ByIndex(policySecretIndex, "default/secret-b")
	if err != nil {
		t.Fatalf("failed to query deleted Policy: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("secret-b matches after deletion = %d, want 0", len(got))
	}
}

func errorComparer(e1, e2 error) bool {
	if e1 == nil || e2 == nil {
		return errors.Is(e1, e2)
	}

	return e1.Error() == e2.Error()
}

func TestAddJWTSecrets(t *testing.T) {
	t.Parallel()
	invalidErr := errors.New("invalid")
	validJWKSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-jwk-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeJWK,
	}
	invalidJWKSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-jwk-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeJWK,
	}

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[secrets.SecretRefKey]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Secret: "valid-jwk-secret",
							Realm:  "My API",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-jwk-secret", secrets.RoleJWK): {
					Secret: validJWKSecret,
					Path:   "/etc/nginx/secrets/default-valid-jwk-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:    "My API",
							JwksURI:  "https://idp.com/token",
							KeyCache: "1h",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid policy using JwksUri",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting invalid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Secret: "invalid-jwk-secret",
							Realm:  "My API",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/invalid-jwk-secret", secrets.RoleJWK): {
					Secret: invalidJWKSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[secrets.SecretRefKey]*secrets.SecretReference{
			secrets.RefKey("default/valid-jwk-secret", secrets.RoleJWK): {
				Secret: validJWKSecret,
				Path:   "/etc/nginx/secrets/default-valid-jwk-secret",
			},
			secrets.RefKey("default/invalid-jwk-secret", secrets.RoleJWK): {
				Secret: invalidJWKSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[secrets.SecretRefKey]*secrets.SecretReference)

		err := lbc.addJWTSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addJWTSecretRefs() returned %v, for the case of %v", err, test.msg)
		}

		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addJWTSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddBasicSecrets(t *testing.T) {
	t.Parallel()
	invalidErr := errors.New("invalid")
	validBasicSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-basic-auth-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeJWK,
	}
	invalidBasicSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-basic-auth-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeJWK,
	}

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[secrets.SecretRefKey]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Secret: "valid-basic-auth-secret",
							Realm:  "My API",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-basic-auth-secret", secrets.RoleHtpasswd): {
					Secret: validBasicSecret,
					Path:   "/etc/nginx/secrets/default-valid-basic-auth-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting invalid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Secret: "invalid-basic-auth-secret",
							Realm:  "My API",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/invalid-basic-auth-secret", secrets.RoleHtpasswd): {
					Secret: invalidBasicSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[secrets.SecretRefKey]*secrets.SecretReference{
			secrets.RefKey("default/valid-basic-auth-secret", secrets.RoleHtpasswd): {
				Secret: validBasicSecret,
				Path:   "/etc/nginx/secrets/default-valid-basic-auth-secret",
			},
			secrets.RefKey("default/invalid-basic-auth-secret", secrets.RoleHtpasswd): {
				Secret: invalidBasicSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[secrets.SecretRefKey]*secrets.SecretReference)

		err := lbc.addBasicSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addBasicSecretRefs() returned %v, for the case of %v", err, test.msg)
		}

		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addBasicSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddIngressMTLSSecret(t *testing.T) {
	t.Parallel()
	invalidErr := errors.New("invalid")
	validSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-ingress-mtls-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeCA,
	}
	invalidSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-ingress-mtls-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeCA,
	}

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[secrets.SecretRefKey]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "valid-ingress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-ingress-mtls-secret", secrets.RoleCA): {
					Secret: validSecret,
					Path:   "/etc/nginx/secrets/default-valid-ingress-mtls-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "invalid-ingress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/invalid-ingress-mtls-secret", secrets.RoleCA): {
					Secret: invalidSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[secrets.SecretRefKey]*secrets.SecretReference{
			secrets.RefKey("default/valid-ingress-mtls-secret", secrets.RoleCA): {
				Secret: validSecret,
				Path:   "/etc/nginx/secrets/default-valid-ingress-mtls-secret",
			},
			secrets.RefKey("default/invalid-ingress-mtls-secret", secrets.RoleCA): {
				Secret: invalidSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[secrets.SecretRefKey]*secrets.SecretReference)

		err := lbc.addIngressMTLSSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addIngressMTLSSecretRefs() returned %v, for the case of %v", err, test.msg)
		}

		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addIngressMTLSSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddEgressMTLSSecrets(t *testing.T) {
	t.Parallel()
	invalidErr := errors.New("invalid")
	validMTLSSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-egress-mtls-secret",
			Namespace: "default",
		},
		Type: api_v1.SecretTypeTLS,
	}
	validTrustedSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-egress-trusted-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeCA,
	}
	invalidMTLSSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-egress-mtls-secret",
			Namespace: "default",
		},
		Type: api_v1.SecretTypeTLS,
	}
	invalidTrustedSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-egress-trusted-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeCA,
	}

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[secrets.SecretRefKey]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "valid-egress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-egress-mtls-secret", secrets.RoleTLS): {
					Secret: validMTLSSecret,
					Path:   "/etc/nginx/secrets/default-valid-egress-mtls-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid TLS secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-egress-trusted-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TrustedCertSecret: "valid-egress-trusted-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-egress-trusted-secret", secrets.RoleCA): {
					Secret: validTrustedSecret,
					Path:   "/etc/nginx/secrets/default-valid-egress-trusted-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid TrustedCA secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret:         "valid-egress-mtls-secret",
							TrustedCertSecret: "valid-egress-trusted-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-egress-mtls-secret", secrets.RoleTLS): {
					Secret: validMTLSSecret,
					Path:   "/etc/nginx/secrets/default-valid-egress-mtls-secret",
				},
				secrets.RefKey("default/valid-egress-trusted-secret", secrets.RoleCA): {
					Secret: validTrustedSecret,
					Path:   "/etc/nginx/secrets/default-valid-egress-trusted-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secrets",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "invalid-egress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/invalid-egress-mtls-secret", secrets.RoleTLS): {
					Secret: invalidMTLSSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid TLS secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TrustedCertSecret: "invalid-egress-trusted-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/invalid-egress-trusted-secret", secrets.RoleCA): {
					Secret: invalidTrustedSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid TrustedCA secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[secrets.SecretRefKey]*secrets.SecretReference{
			secrets.RefKey("default/valid-egress-mtls-secret", secrets.RoleTLS): {
				Secret: validMTLSSecret,
				Path:   "/etc/nginx/secrets/default-valid-egress-mtls-secret",
			},
			secrets.RefKey("default/valid-egress-trusted-secret", secrets.RoleCA): {
				Secret: validTrustedSecret,
				Path:   "/etc/nginx/secrets/default-valid-egress-trusted-secret",
			},
			secrets.RefKey("default/invalid-egress-mtls-secret", secrets.RoleTLS): {
				Secret: invalidMTLSSecret,
				Error:  invalidErr,
			},
			secrets.RefKey("default/invalid-egress-trusted-secret", secrets.RoleCA): {
				Secret: invalidTrustedSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[secrets.SecretRefKey]*secrets.SecretReference)

		err := lbc.addEgressMTLSSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addEgressMTLSSecretRefs() returned %v, for the case of %v", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addEgressMTLSSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddOidcSecret(t *testing.T) {
	t.Parallel()
	invalidErr := errors.New("invalid")
	validSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-oidc-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": nil,
		},
		Type: secrets.SecretTypeOIDC,
	}
	invalidSecret := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-oidc-secret",
			Namespace: "default",
		},
		Type: secrets.SecretTypeOIDC,
	}

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[secrets.SecretRefKey]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret: "valid-oidc-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/valid-oidc-secret", secrets.RoleOIDC): {
					Secret: validSecret,
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret: "invalid-oidc-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[secrets.SecretRefKey]*secrets.SecretReference{
				secrets.RefKey("default/invalid-oidc-secret", secrets.RoleOIDC): {
					Secret: invalidSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[secrets.SecretRefKey]*secrets.SecretReference{
			secrets.RefKey("default/valid-oidc-secret", secrets.RoleOIDC): {
				Secret: validSecret,
			},
			secrets.RefKey("default/invalid-oidc-secret", secrets.RoleOIDC): {
				Secret: invalidSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[secrets.SecretRefKey]*secrets.SecretReference)

		err := lbc.addOIDCSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addOIDCSecretRefs() returned %v, for the case of %v", err, test.msg)
		}

		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addOIDCSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestPreSyncSecrets(t *testing.T) {
	t.Parallel()

	newSecretLister := func(secret *api_v1.Secret) cache.Store {
		return &fakeStore{
			FakeCustomStore: cache.FakeCustomStore{
				ListFunc: func() []interface{} {
					return []interface{}{secret}
				},
			},
		}
	}

	secretA := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwk-a",
			Namespace: "namespace-a",
		},
		Type: api_v1.SecretTypeOpaque,
		Data: map[string][]byte{
			secrets.JWTKeyKey: []byte("{}"),
		},
	}

	secretB := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwk-b",
			Namespace: "namespace-b",
		},
		Type: api_v1.SecretTypeOpaque,
		Data: map[string][]byte{
			secrets.JWTKeyKey: []byte("{}"),
		},
	}

	disabledLister := &fakeStore{
		FakeCustomStore: cache.FakeCustomStore{
			ListFunc: func() []interface{} {
				panic("disabled Secret lister must not be called")
			},
		},
	}

	secretStore := secrets.NewLocalSecretStore(fakeSecretFileManager{})

	lbc := LoadBalancerController{
		secretStore: secretStore,
		namespacedInformers: map[string]*namespacedInformer{
			"namespace-a": {
				secretLister:              newSecretLister(secretA),
				isSecretsEnabledNamespace: true,
			},
			"disabled": {
				secretLister:              disabledLister,
				isSecretsEnabledNamespace: false,
			},
			"namespace-b": {
				secretLister:              newSecretLister(secretB),
				isSecretsEnabledNamespace: true,
			},
		},
		Logger: nl.LoggerFromContext(context.Background()),
	}

	lbc.preSyncSecrets()

	if got := secretStore.SecretCount(); got != 0 {
		t.Errorf("SecretCount() before resolution = %d, want 0", got)
	}

	tests := []struct {
		key string
	}{
		{key: "namespace-a/jwk-a"},
		{key: "namespace-b/jwk-b"},
	}

	for _, test := range tests {
		ref := secretStore.GetSecret(test.key, secrets.RoleJWK)
		if ref.Error != nil {
			t.Errorf("GetSecret(%q, RoleJWK) returned error: %v", test.key, ref.Error)
		}
	}

	if ref := secretStore.GetSecret("disabled/sentinel", secrets.RoleJWK); ref.Error == nil {
		t.Error("disabled namespace Secret unexpectedly existed in the store")
	}

	if got := secretStore.SecretCount(); got != 2 {
		t.Errorf("SecretCount() after resolving enabled Secrets = %d, want 2", got)
	}
}

func TestSyncSecretUnreferencedDoesNotMaterializeOrReload(t *testing.T) {
	t.Parallel()

	manager := newSecretReconciliationNginxManager()
	lbc := newBatchTestLBC(t, manager)

	secretCache := cache.NewStore(cache.MetaNamespaceKeyFunc)
	secretObj := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "unreferenced",
			Namespace: "default",
		},
		Type: api_v1.SecretTypeOpaque,
		Data: map[string][]byte{
			secrets.JWTKeyKey: []byte("{}"),
		},
	}

	if err := secretCache.Add(secretObj); err != nil {
		t.Fatalf("failed to add Secret to cache: %v", err)
	}

	lbc.namespacedInformers["default"].secretLister = secretCache
	lbc.secretStore = secrets.NewLocalSecretStore(lbc.configurator, secrets.WithSecretResolver(lbc.getSecret))
	lbc.areCustomResourcesEnabled = false
	lbc.plmEnabled = false

	key := "default/unreferenced"

	assertInert := func(stage string) {
		t.Helper()

		if got := lbc.secretStore.SecretCount(); got != 0 {
			t.Errorf("%s: SecretCount() = %d, want 0", stage, got)
		}
		if lbc.secretStore.(*secrets.LocalSecretStore).HoldsSecret(key) {
			t.Errorf("%s: unreferenced Secret unexpectedly held in memory", stage)
		}
		if got := len(manager.CreatedSecretNames); got != 0 {
			t.Errorf("%s: created %d Secret files, want 0", stage, got)
		}
		if got := len(manager.CreatedConfigNames); got != 0 {
			t.Errorf("%s: created %d configuration files, want 0", stage, got)
		}
		if manager.reloadCalls != 0 {
			t.Errorf("%s: reload count = %d, want 0", stage, manager.reloadCalls)
		}
	}

	lbc.syncSecret(task{
		Kind: secret,
		Key:  key,
	})
	assertInert("initial sync")

	updatedSecret := secretObj.DeepCopy()
	updatedSecret.Data[secrets.JWTKeyKey] = []byte(`{"keys":[]}`)

	if err := secretCache.Update(updatedSecret); err != nil {
		t.Fatalf("failed to update Secret in cache: %v", err)
	}

	lbc.syncSecret(task{
		Kind: secret,
		Key:  key,
	})
	assertInert("updated sync")

	ref := lbc.secretStore.GetSecret(key, secrets.RoleJWK)
	if ref.Error != nil {
		t.Fatalf("cached Secret could not be resolved: %v", ref.Error)
	}
	if !lbc.secretStore.(*secrets.LocalSecretStore).HoldsSecret(key) {
		t.Errorf("Secret should be held in memory after resolution")
	}
	if got := string(ref.Secret.Data[secrets.JWTKeyKey]); got != `{"keys":[]}` {
		t.Errorf("cached JWK = %q, want updated value", got)
	}
}

func TestSyncSecretReferencedLifecycle(t *testing.T) {
	t.Parallel()

	manager := newSecretReconciliationNginxManager()
	lbc := newBatchTestLBC(t, manager)

	secretCache := cache.NewStore(cache.MetaNamespaceKeyFunc)
	secretObj := &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Type: api_v1.SecretTypeOpaque,
		Data: map[string][]byte{
			secrets.JWTKeyKey: []byte(`{"keys":[]}`),
		},
	}
	if err := secretCache.Add(secretObj); err != nil {
		t.Fatalf("failed to add Secret to cache: %v", err)
	}

	lbc.namespacedInformers["default"].secretLister = secretCache
	localStore := secrets.NewLocalSecretStore(lbc.configurator, secrets.WithSecretResolver(lbc.getSecret))
	lbc.secretStore = localStore
	lbc.areCustomResourcesEnabled = false
	lbc.plmEnabled = false
	lbc.configuration.CompleteStartup()

	key := "default/test-secret"

	// 1. Unreferenced secret sync does NOT retain the secret in LocalSecretStore.
	lbc.syncSecret(task{Kind: secret, Key: key})
	if localStore.HoldsSecret(key) {
		t.Fatalf("HoldsSecret(%q) = true after unreferenced sync, want false", key)
	}

	// 2. An Ingress arrives and references the secret. GetSecret lazily resolves from Informer.
	ref := lbc.secretStore.GetSecret(key, secrets.RoleJWK)
	if ref.Error != nil {
		t.Fatalf("GetSecret(%q, RoleJWK) error = %v, want nil", key, ref.Error)
	}
	if !localStore.HoldsSecret(key) {
		t.Fatalf("HoldsSecret(%q) = false after lazy resolution, want true", key)
	}

	// 3. Simulate Ingress added to configuration so the secret is now referenced.
	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:              "test-ing",
			Namespace:         "default",
			CreationTimestamp: meta_v1.Now(),
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
			},
		},
		Spec: networking.IngressSpec{
			TLS: []networking.IngressTLS{
				{
					Hosts:      []string{"example.com"},
					SecretName: "test-secret",
				},
			},
			Rules: []networking.IngressRule{
				{
					Host: "example.com",
				},
			},
		},
	}
	_, problems := lbc.configuration.AddOrUpdateIngress(ing)
	if len(problems) > 0 {
		t.Fatalf("AddOrUpdateIngress() problems = %v", problems)
	}

	// 4. Update the secret in informer cache.
	updatedSecret := secretObj.DeepCopy()
	updatedSecret.Data[secrets.JWTKeyKey] = []byte(`{"keys":[{"kty":"oct"}]}`)
	if err := secretCache.Update(updatedSecret); err != nil {
		t.Fatalf("failed to update Secret in cache: %v", err)
	}

	// 5. syncSecret now sees the secret is referenced and updates it in LocalSecretStore.
	lbc.syncSecret(task{Kind: secret, Key: key})
	if !localStore.HoldsSecret(key) {
		t.Fatalf("HoldsSecret(%q) = false after referenced sync, want true", key)
	}

	// 6. Remove Ingress from configuration. Now the secret is unreferenced again.
	lbc.configuration.DeleteIngress("default/test-ing")

	// 7. syncSecret now evicts the unreferenced secret from LocalSecretStore.
	lbc.syncSecret(task{Kind: secret, Key: key})
	if localStore.HoldsSecret(key) {
		t.Fatalf("HoldsSecret(%q) = true after dereferencing, want false", key)
	}

	// 8. Delete the secret from cache to simulate secret deletion in K8s.
	if err := secretCache.Delete(secretObj); err != nil {
		t.Fatalf("failed to delete Secret from cache: %v", err)
	}

	// 9. Query the deleted secret: returns error, but does NOT poison refs with negative cache.
	missingRef := lbc.secretStore.GetSecret(key, secrets.RoleJWK)
	if missingRef.Error == nil {
		t.Fatal("expected error on deleted secret, got nil")
	}

	// 10. Re-create the secret in K8s cache BEFORE the referencing Ingress is created.
	if err := secretCache.Add(secretObj); err != nil {
		t.Fatalf("failed to add recreated Secret to cache: %v", err)
	}
	// syncSecret runs while still unreferenced -> evicts, but does NOT leave stale negative refs.
	lbc.syncSecret(task{Kind: secret, Key: key})
	if localStore.HoldsSecret(key) {
		t.Fatalf("HoldsSecret(%q) = true after unreferenced sync, want false", key)
	}

	// 11. Now Ingress arrives and requests the secret. GetSecret lazily resolves from Informer.
	refAfterRecreate := lbc.secretStore.GetSecret(key, secrets.RoleJWK)
	if refAfterRecreate.Error != nil {
		t.Fatalf("GetSecret(%q, RoleJWK) error after recreation = %v, want nil", key, refAfterRecreate.Error)
	}
	if !localStore.HoldsSecret(key) {
		t.Fatalf("HoldsSecret(%q) = false after lazy resolution of recreated secret, want true", key)
	}
}

func TestWriteSpecialSecretsDispatch(t *testing.T) {
	t.Parallel()

	special := specialSecrets{
		defaultServerSecret: "nginx-ingress/default-server-secret",
		wildcardTLSSecret:   "nginx-ingress/wildcard-secret",
		licenseSecret:       "nginx-ingress/license-secret",
		clientAuthSecret:    "nginx-ingress/client-auth-secret",
		trustedCertSecret:   "nginx-ingress/trusted-cert-secret",
	}

	tlsData := map[string][]byte{
		"tls.crt": []byte("cert"),
		"tls.key": []byte("key"),
	}

	tests := []struct {
		name               string
		secretNsName       string
		special            *specialSecrets
		data               map[string][]byte
		specialTLSSecrets  []string
		wantCreatedSecrets []string
		wantOK             bool
	}{
		{
			name:               "license secret",
			secretNsName:       special.licenseSecret,
			data:               map[string][]byte{configs.LicenseSecretFileName: []byte("license-data")},
			wantCreatedSecrets: []string{"license.jwt"},
			wantOK:             true,
		},
		{
			name:         "trusted cert secret writes the fixed mgmt CA paths",
			secretNsName: special.trustedCertSecret,
			data: map[string][]byte{
				configs.CACrtKey: []byte("cert"),
				configs.CACrlKey: []byte("crl"),
			},
			wantCreatedSecrets: []string{"mgmt/ca.crt", "mgmt/ca.crl"},
			wantOK:             true,
		},
		{
			name:               "client auth secret",
			secretNsName:       special.clientAuthSecret,
			data:               tlsData,
			wantCreatedSecrets: []string{"mgmt/client"},
			wantOK:             true,
		},
		{
			name:               "default server secret",
			secretNsName:       special.defaultServerSecret,
			data:               tlsData,
			specialTLSSecrets:  []string{configs.DefaultServerSecretFileName},
			wantCreatedSecrets: []string{"default"},
			wantOK:             true,
		},
		{
			name:               "wildcard TLS secret",
			secretNsName:       special.wildcardTLSSecret,
			data:               tlsData,
			specialTLSSecrets:  []string{configs.WildcardSecretFileName},
			wantCreatedSecrets: []string{"wildcard"},
			wantOK:             true,
		},
		{
			name:         "overlapping default server TLS and management client auth writes both representations",
			secretNsName: "nginx-ingress/shared-secret",
			special: &specialSecrets{
				defaultServerSecret: "nginx-ingress/shared-secret",
				clientAuthSecret:    "nginx-ingress/shared-secret",
			},
			data: tlsData,
			wantCreatedSecrets: []string{
				"default",
				"mgmt/client",
			},
			wantOK: true,
		},
		{
			name:         "overlapping TLS and trusted cert writes all representations",
			secretNsName: "nginx-ingress/shared-secret",
			special: &specialSecrets{
				defaultServerSecret: "nginx-ingress/shared-secret",
				trustedCertSecret:   "nginx-ingress/shared-secret",
			},
			data: map[string][]byte{
				"tls.crt":        []byte("cert"),
				"tls.key":        []byte("key"),
				secrets.CAKey:    []byte("ca-cert"),
				secrets.CACrlKey: []byte("ca-crl"),
			},
			wantCreatedSecrets: []string{
				"default",
				"mgmt/ca.crt",
				"mgmt/ca.crl",
			},
			wantOK: true,
		},
		{
			name:         "overlapping TLS and wildcard TLS writes both representations",
			secretNsName: "nginx-ingress/shared-secret",
			special: &specialSecrets{
				defaultServerSecret: "nginx-ingress/shared-secret",
				wildcardTLSSecret:   "nginx-ingress/shared-secret",
			},
			data: tlsData,
			wantCreatedSecrets: []string{
				"default",
				"wildcard",
			},
			wantOK: true,
		},
		{
			name:               "secret that is not special writes nothing",
			secretNsName:       "default/some-other-secret",
			data:               tlsData,
			wantCreatedSecrets: nil,
			wantOK:             true,
		},
		{
			name:               "license secret missing its key is rejected",
			secretNsName:       special.licenseSecret,
			data:               map[string][]byte{},
			wantCreatedSecrets: nil,
			wantOK:             false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secCfg := special
			if test.special != nil {
				secCfg = *test.special
			}

			ns, name, found := strings.Cut(test.secretNsName, "/")
			if !found {
				t.Fatalf("malformed test fixture %q, want <namespace>/<name>", test.secretNsName)
			}

			manager := newTestNginxManager()
			lbc := LoadBalancerController{
				configurator:   createTestPolicySyncConfigurator(t, manager),
				recorder:       record.NewFakeRecorder(100),
				specialSecrets: secCfg,
				metadata: controllerMetadata{
					pod: &api_v1.Pod{
						ObjectMeta: meta_v1.ObjectMeta{Name: "nginx-ingress", Namespace: "nginx-ingress"},
					},
				},
				Logger: nl.LoggerFromContext(context.Background()),
			}

			secret := &api_v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: name, Namespace: ns},
				Data:       test.data,
			}

			update := lbc.specialSecrets.updateFor(
				test.secretNsName,
				lbc.configurator.DynamicSSLReloadEnabled(),
			)

			got := lbc.writeSpecialSecrets(lbc.Logger, secret, update)

			if got != test.wantOK {
				t.Errorf("writeSpecialSecrets() = %v, want %v", got, test.wantOK)
			}
			if diff := cmp.Diff(test.wantCreatedSecrets, manager.CreatedSecretNames); diff != "" {
				t.Errorf("writeSpecialSecrets() secret files (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateSpecialSecretMultiRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		roles   []specialSecretRole
		data    map[string][]byte
		wantErr bool
	}{
		{
			name:  "valid license with invalid TLS faild",
			roles: []specialSecretRole{specialLicense, specialDefaultTLS},
			data: map[string][]byte{
				configs.LicenseSecretFileName: []byte("jwt-token"),
				"tls.crt":                     []byte("invalid"),
			},
			wantErr: true,
		},
		{
			name:  "trusted CA missing ca.crt fails even if other roles pass",
			roles: []specialSecretRole{specialDefaultTLS, specialMGMTTrustedCA},
			data: map[string][]byte{
				"tls.crt": []byte("cert"),
				"tls.key": []byte("key"),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			secret := &api_v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "shared", Namespace: "nginx-ingress"},
				Data:       tc.data,
			}
			err := validateSpecialSecret(secret, tc.roles)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSpecialSecret() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSpecialSecretAllRoles(t *testing.T) {
	t.Parallel()

	secret := newSharedMGMTSecret(t, true)
	key := secret.Namespace + "/" + secret.Name

	manager := newTestNginxManager()
	lbc := &LoadBalancerController{
		configurator: createTestPolicySyncConfigurator(t, manager),
		recorder:     record.NewFakeRecorder(100),
		specialSecrets: specialSecrets{
			defaultServerSecret: key,
			wildcardTLSSecret:   key,
			licenseSecret:       key,
			clientAuthSecret:    key,
			trustedCertSecret:   key,
		},
		metadata: controllerMetadata{
			pod: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "nginx-ingress",
					Namespace: "nginx-ingress",
				},
			},
		},
		Logger: nl.LoggerFromContext(context.Background()),
	}

	update, ok := lbc.prepareSpecialSecretUpdate(lbc.Logger, secret)
	if !ok {
		t.Fatal("prepareSpecialSecretUpdate() rejected a valid all-role Secret")
	}

	if update.reload != specialReloadAllConfigs {
		t.Errorf("reload action = %v, want specialReloadAllConfigs", update.reload)
	}

	wantRoles := []specialSecretRole{
		specialDefaultTLS,
		specialWildcardTLS,
		specialLicense,
		specialMGMTClientAuth,
		specialMGMTTrustedCA,
	}
	if diff := cmp.Diff(wantRoles, update.roles); diff != "" {
		t.Errorf("special roles mismatch (-want +got):\n%s", diff)
	}

	wantFiles := []string{
		configs.LicenseSecretFileName,
		configs.DefaultServerSecretFileName,
		configs.WildcardSecretFileName,
		fmt.Sprintf("mgmt/%s", configs.ClientAuthCertSecretFileName),
		fmt.Sprintf("mgmt/%s", configs.CACrtKey),
		fmt.Sprintf("mgmt/%s", configs.CACrlKey),
	}
	if diff := cmp.Diff(wantFiles, manager.CreatedSecretNames); diff != "" {
		t.Errorf("created Secret files mismatch (-want +got):\n%s", diff)
	}
}

func TestSyncMGMTSecretsSharedSecret(t *testing.T) {
	t.Parallel()

	secret := newSharedMGMTSecret(t, true)
	client := fake.NewClientset(secret)
	lbc, manager, _ := newMGMTTestController(t, client)

	params := configs.NewDefaultMGMTConfigParams(context.Background())
	params.Secrets.License = secret.Name
	params.Secrets.ClientAuth = secret.Name
	params.Secrets.TrustedCert = secret.Name

	prepared := lbc.syncMGMTSecrets(params)

	if got := countSecretGetActions(client); got != 1 {
		t.Errorf("Secret GET count = %d, want 1", got)
	}

	wantFiles := []string{
		configs.LicenseSecretFileName,
		fmt.Sprintf("mgmt/%s", configs.ClientAuthCertSecretFileName),
		fmt.Sprintf("mgmt/%s", configs.CACrtKey),
		fmt.Sprintf("mgmt/%s", configs.CACrlKey),
	}
	if diff := cmp.Diff(wantFiles, manager.CreatedSecretNames); diff != "" {
		t.Errorf("created Secret files mismatch (-want +got):\n%s", diff)
	}

	if len(prepared) != 1 || prepared[0].Name != secret.Name {
		t.Errorf("prepared Secrets = %v, want one shared Secret", prepared)
	}

	if params.Secrets.TrustedCRL != secret.Name {
		t.Errorf(
			"TrustedCRL = %q, want %q",
			params.Secrets.TrustedCRL,
			secret.Name,
		)
	}

	key := secret.Namespace + "/" + secret.Name
	if lbc.specialSecrets.licenseSecret != key {
		t.Errorf("license Secret key = %q, want %q", lbc.specialSecrets.licenseSecret, key)
	}
	if lbc.specialSecrets.clientAuthSecret != key {
		t.Errorf("client-auth Secret key = %q, want %q", lbc.specialSecrets.clientAuthSecret, key)
	}
	if lbc.specialSecrets.trustedCertSecret != key {
		t.Errorf("trusted-CA Secret key = %q, want %q", lbc.specialSecrets.trustedCertSecret, key)
	}
}

func TestSyncMGMTSecretsClearsStaleCRL(t *testing.T) {
	t.Parallel()

	secret := newSharedMGMTSecret(t, false)
	client := fake.NewClientset(secret)
	lbc, _, _ := newMGMTTestController(t, client)

	params := configs.NewDefaultMGMTConfigParams(context.Background())
	params.Secrets.TrustedCert = secret.Name
	params.Secrets.TrustedCRL = "old-crl"

	prepared := lbc.syncMGMTSecrets(params)

	if params.Secrets.TrustedCRL != "" {
		t.Errorf("TrustedCRL = %q, want empty", params.Secrets.TrustedCRL)
	}
	if len(prepared) != 1 {
		t.Errorf("prepared Secret count = %d, want 1", len(prepared))
	}
}

func TestSyncMGMTSecretsMissingSecret(t *testing.T) {
	t.Parallel()

	client := fake.NewClientset()
	lbc, manager, recorder := newMGMTTestController(t, client)

	params := configs.NewDefaultMGMTConfigParams(context.Background())
	params.Secrets.License = "missing"
	params.Secrets.ClientAuth = "missing"
	params.Secrets.TrustedCert = "missing"

	prepared := lbc.syncMGMTSecrets(params)

	if got := countSecretGetActions(client); got != 1 {
		t.Errorf("Secret GET count = %d, want 1", got)
	}
	if len(prepared) != 0 {
		t.Errorf("prepared Secret count = %d, want 0", len(prepared))
	}
	if len(manager.CreatedSecretNames) != 0 {
		t.Errorf("created Secret files = %v, want none", manager.CreatedSecretNames)
	}
	if events := drainRecorderEvents(recorder); len(events) != 0 {
		t.Errorf("events = %v, want none", events)
	}

	key := "nginx-ingress/missing"
	if lbc.specialSecrets.licenseSecret != key ||
		lbc.specialSecrets.clientAuthSecret != key ||
		lbc.specialSecrets.trustedCertSecret != key {
		t.Error("configured missing Secret names were not retained")
	}
}

func TestSyncMGMTSecretsRejectsInvalidSharedSecret(t *testing.T) {
	t.Parallel()

	secret := newSharedMGMTSecret(t, true)
	delete(secret.Data, secrets.LicenseKey)

	client := fake.NewClientset(secret)
	lbc, manager, recorder := newMGMTTestController(t, client)

	params := configs.NewDefaultMGMTConfigParams(context.Background())
	params.Secrets.License = secret.Name
	params.Secrets.ClientAuth = secret.Name
	params.Secrets.TrustedCert = secret.Name

	prepared := lbc.syncMGMTSecrets(params)

	if got := countSecretGetActions(client); got != 1 {
		t.Errorf("Secret GET count = %d, want 1", got)
	}
	if len(prepared) != 0 {
		t.Errorf("prepared Secret count = %d, want 0", len(prepared))
	}
	if len(manager.CreatedSecretNames) != 0 {
		t.Errorf("created Secret files = %v, want none", manager.CreatedSecretNames)
	}

	events := drainRecorderEvents(recorder)
	rejected := 0
	updated := 0
	for _, event := range events {
		if strings.Contains(event, nl.EventReasonRejected) {
			rejected++
		}
		if strings.Contains(event, nl.EventReasonSecretUpdated) {
			updated++
		}
	}
	if rejected != 1 {
		t.Errorf("Rejected event count = %d, want 1; events=%v", rejected, events)
	}
	if updated != 0 {
		t.Errorf("SecretUpdated event count = %d, want 0; events=%v", updated, events)
	}
}

func TestSyncMGMTSecretsClearsOldNames(t *testing.T) {
	t.Parallel()

	client := fake.NewClientset()
	lbc, _, _ := newMGMTTestController(t, client)

	lbc.specialSecrets.licenseSecret = "nginx-ingress/old-license"
	lbc.specialSecrets.clientAuthSecret = "nginx-ingress/old-client"
	lbc.specialSecrets.trustedCertSecret = "nginx-ingress/old-ca"

	params := configs.NewDefaultMGMTConfigParams(context.Background())
	prepared := lbc.syncMGMTSecrets(params)

	if len(prepared) != 0 {
		t.Errorf("prepared Secret count = %d, want 0", len(prepared))
	}
	if got := countSecretGetActions(client); got != 0 {
		t.Errorf("Secret GET count = %d, want 0", got)
	}
	if lbc.specialSecrets.licenseSecret != "" {
		t.Errorf("license Secret = %q, want empty", lbc.specialSecrets.licenseSecret)
	}
	if lbc.specialSecrets.clientAuthSecret != "" {
		t.Errorf("client-auth Secret = %q, want empty", lbc.specialSecrets.clientAuthSecret)
	}
	if lbc.specialSecrets.trustedCertSecret != "" {
		t.Errorf("trusted-CA Secret = %q, want empty", lbc.specialSecrets.trustedCertSecret)
	}
}

func newMGMTTestController(
	t *testing.T,
	client *fake.Clientset,
) (*LoadBalancerController, *testNginxManager, *record.FakeRecorder) {
	t.Helper()

	manager := newTestNginxManager()
	recorder := record.NewFakeRecorder(100)

	lbc := &LoadBalancerController{
		client:       client,
		configurator: createTestPolicySyncConfigurator(t, manager),
		recorder:     recorder,
		metadata: controllerMetadata{
			namespace: "nginx-ingress",
			pod: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "nginx-ingress",
					Namespace: "nginx-ingress",
				},
			},
		},
		Logger: nl.LoggerFromContext(context.Background()),
	}

	return lbc, manager, recorder
}

func runMGMTSecretReloadTest(t *testing.T, reloadErr error) (eventsAtReload []string, events []string, reloadCalls int, filesAtReload int) {
	t.Helper()

	secret := newSharedMGMTSecret(t, true)
	manager := newSecretReconciliationNginxManager()
	manager.reloadErr = reloadErr

	lbc := newBatchTestLBC(t, manager)
	recorder := record.NewFakeRecorder(100)

	lbc.recorder = recorder
	lbc.isNginxPlus = true
	lbc.client = fake.NewClientset(secret)
	lbc.metadata.namespace = "nginx-ingress"
	lbc.metadata.pod.Name = "nginx-ingress"
	lbc.metadata.pod.Namespace = "nginx-ingress"
	lbc.mgmtConfigMap = &api_v1.ConfigMap{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "mgmt",
			Namespace: "nginx-ingress",
		},
		Data: map[string]string{
			"license-token-secret-name":           secret.Name,
			"ssl-certificate-secret-name":         secret.Name,
			"ssl-trusted-certificate-secret-name": secret.Name,
		},
	}

	manager.onReload = func() {
		eventsAtReload = drainRecorderEvents(recorder)
		filesAtReload = len(manager.CreatedSecretNames)
	}

	lbc.configurator.EnableReloads()
	lbc.updateAllConfigs()

	reloadCalls = manager.reloadCalls
	events = append(
		eventsAtReload,
		drainRecorderEvents(recorder)...,
	)

	return eventsAtReload, events, reloadCalls, filesAtReload
}

func TestUpdateAllConfigsClearsMGMTSecretNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		mgmtConfigMap *api_v1.ConfigMap
	}{
		{
			name:          "deleted MGMT ConfigMap",
			mgmtConfigMap: nil,
		},
		{
			name: "invalid empty MGMT ConfigMap",
			mgmtConfigMap: &api_v1.ConfigMap{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "mgmt",
					Namespace: "nginx-ingress",
				},
				Data: map[string]string{},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manager := newSecretReconciliationNginxManager()
			lbc := newBatchTestLBC(t, manager)

			lbc.isNginxPlus = true
			lbc.client = fake.NewClientset()
			lbc.mgmtConfigMap = test.mgmtConfigMap
			lbc.metadata.namespace = "nginx-ingress"

			lbc.specialSecrets = specialSecrets{
				defaultServerSecret: "nginx-ingress/default",
				wildcardTLSSecret:   "nginx-ingress/wildcard",
				licenseSecret:       "nginx-ingress/old-license",
				clientAuthSecret:    "nginx-ingress/old-client",
				trustedCertSecret:   "nginx-ingress/old-ca",
			}

			lbc.updateAllConfigs()

			if lbc.specialSecrets.licenseSecret != "" {
				t.Errorf("license Secret = %q, want empty", lbc.specialSecrets.licenseSecret)
			}
			if lbc.specialSecrets.clientAuthSecret != "" {
				t.Errorf("client-auth Secret = %q, want empty", lbc.specialSecrets.clientAuthSecret)
			}
			if lbc.specialSecrets.trustedCertSecret != "" {
				t.Errorf("trusted-CA Secret = %q, want empty", lbc.specialSecrets.trustedCertSecret)
			}

			if got := lbc.specialSecrets.defaultServerSecret; got != "nginx-ingress/default" {
				t.Errorf("default-server Secret = %q, want unchanged", got)
			}
			if got := lbc.specialSecrets.wildcardTLSSecret; got != "nginx-ingress/wildcard" {
				t.Errorf("wildcard Secret = %q, want unchanged", got)
			}

			if lbc.configurator.MgmtCfgParams == nil {
				t.Error("Configurator MGMT parameters must not be nil")
			}
		})
	}
}

func TestUpdateAllConfigsMGMTSecretEventsAfterSuccessfulReload(t *testing.T) {
	t.Parallel()

	eventsAtReload, events, reloadCalls, filesAtReload := runMGMTSecretReloadTest(t, nil)

	got := map[string]int{
		"reloads":       reloadCalls,
		"filesAtReload": filesAtReload,
		"earlyEvents": countEventsContaining(
			eventsAtReload,
			"the special Secret",
		),
		"specialNormal": countEventsContaining(
			events,
			"the special Secret",
			api_v1.EventTypeNormal+" "+nl.EventReasonSecretUpdated,
		),
		"specialFailed": countEventsContaining(
			events,
			"the special Secret",
			api_v1.EventTypeWarning+" "+nl.EventReasonUpdatedWithError,
		),
		"mgmtNormal": countEventsContaining(
			events,
			"MGMT ConfigMap",
			api_v1.EventTypeNormal+" "+nl.EventReasonUpdated,
		),
		"mgmtFailed": countEventsContaining(
			events,
			"MGMT ConfigMap",
			api_v1.EventTypeWarning+" "+nl.EventReasonUpdatedWithError,
		),
		"earlyMGMTEvents": countEventsContaining(
			eventsAtReload,
			"MGMT ConfigMap",
		),
	}

	want := map[string]int{
		"reloads":         1,
		"filesAtReload":   4,
		"earlyEvents":     0,
		"specialNormal":   1,
		"specialFailed":   0,
		"mgmtNormal":      1,
		"mgmtFailed":      0,
		"earlyMGMTEvents": 0,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("reload result mismatch (-want +got):\n%s", diff)
	}
}

func TestUpdateAllConfigsMGMTSecretEventsAfterFailedReload(t *testing.T) {
	t.Parallel()

	reloadErr := errors.New("injected reload failure")
	eventsAtReload, events, reloadCalls, filesAtReload := runMGMTSecretReloadTest(t, reloadErr)

	got := map[string]int{
		"reloads":       reloadCalls,
		"filesAtReload": filesAtReload,
		"earlyEvents": countEventsContaining(
			eventsAtReload,
			"the special Secret",
		),
		"specialNormal": countEventsContaining(
			events,
			"the special Secret",
			api_v1.EventTypeNormal+" "+nl.EventReasonSecretUpdated,
		),
		"specialFailed": countEventsContaining(
			events,
			"the special Secret",
			api_v1.EventTypeWarning+" "+nl.EventReasonUpdatedWithError,
		),
		"mgmtNormal": countEventsContaining(
			events,
			"MGMT ConfigMap",
			api_v1.EventTypeNormal+" "+nl.EventReasonUpdated,
		),
		"mgmtFailed": countEventsContaining(
			events,
			"MGMT ConfigMap",
			api_v1.EventTypeWarning+" "+nl.EventReasonUpdatedWithError,
		),
		"errorEvents": countEventsContaining(
			events,
			reloadErr.Error(),
		),
		"earlyMGMTEvents": countEventsContaining(
			eventsAtReload,
			"MGMT ConfigMap",
		),
	}

	want := map[string]int{
		"reloads":         1,
		"filesAtReload":   4,
		"earlyEvents":     0,
		"specialNormal":   0,
		"specialFailed":   1,
		"mgmtNormal":      0,
		"mgmtFailed":      1,
		"errorEvents":     2,
		"earlyMGMTEvents": 0,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("reload result mismatch (-want +got):\n%s", diff)
	}
}

func newSharedMGMTSecret(t *testing.T, withCRL bool) *api_v1.Secret {
	t.Helper()

	certPEM, keyPEM, err := cert.GenerateSelfSignedCertKey(
		"localhost",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	data := map[string][]byte{
		api_v1.TLSCertKey:       certPEM,
		api_v1.TLSPrivateKeyKey: keyPEM,
		secrets.CAKey:           certPEM,
		secrets.LicenseKey:      []byte("license"),
	}
	if withCRL {
		data[secrets.CACrlKey] = []byte("crl")
	}

	return &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "shared",
			Namespace: "nginx-ingress",
		},
		Type: api_v1.SecretTypeOpaque,
		Data: data,
	}
}

func countSecretGetActions(client *fake.Clientset) int {
	count := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "get" &&
			action.GetResource().Resource == "secrets" {
			count++
		}
	}
	return count
}

func drainRecorderEvents(recorder *record.FakeRecorder) []string {
	var events []string

	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			return events
		}
	}
}

func countEventsContaining(events []string, values ...string) int {
	count := 0

	for _, event := range events {
		matches := true
		for _, value := range values {
			if !strings.Contains(event, value) {
				matches = false
				break
			}
		}
		if matches {
			count++
		}
	}

	return count
}

func TestNewTelemetryCollector(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testCase          string
		input             NewLoadBalancerControllerInput
		collectorConfig   telemetry.CollectorConfig
		expectedCollector telemetry.Collector
	}{
		{
			testCase: "New Telemetry Collector with default values",
			input: NewLoadBalancerControllerInput{
				KubeClient:               fake.NewClientset(),
				EnableTelemetryReporting: true,
				LoggerContext:            context.Background(),
			},
			expectedCollector: telemetry.Collector{
				Config: telemetry.CollectorConfig{
					Period: 24 * time.Hour,
				},
				Exporter: &telemetry.StdoutExporter{},
			},
		},
		{
			testCase: "New Telemetry Collector with Telemetry Reporting set to false",
			input: NewLoadBalancerControllerInput{
				KubeClient:               fake.NewClientset(),
				EnableTelemetryReporting: false,
				LoggerContext:            context.Background(),
			},
			expectedCollector: telemetry.Collector{},
		},
	}

	for _, tc := range testCases {
		lbc := NewLoadBalancerController(tc.input)
		if reflect.DeepEqual(tc.expectedCollector, lbc.telemetryCollector) {
			t.Fatalf("Expected %v, but got %v", tc.expectedCollector, lbc.telemetryCollector)
		}
	}
}

func TestGenerateSecretNSName(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		secret   *api_v1.Secret
		expected string
	}{
		{
			name: "Valid secret",
			secret: &api_v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Namespace: "testns",
					Name:      "test-secret",
				},
			},
			expected: "testns/test-secret",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := generateSecretNSName(tc.secret)
			if result != tc.expected {
				t.Fatalf("Expected %v, but got %v", tc.expected, result)
			}
		})
	}
}

func TestShouldForceReloadOnSecretUpdate(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name                    string
		roles                   []secrets.SecretRole
		dynamicSSLReloadEnabled bool
		expected                bool
	}{
		{
			name:                    "TLS server secret with dynamic SSL reload enabled skips forced reload",
			roles:                   []secrets.SecretRole{secrets.RoleTLS},
			dynamicSSLReloadEnabled: true,
			expected:                false,
		},
		{
			name:                    "TLS server secret with dynamic SSL reload disabled forces reload",
			roles:                   []secrets.SecretRole{secrets.RoleTLS},
			dynamicSSLReloadEnabled: false,
			expected:                true,
		},
		{
			name:                    "CA secret forces reload even when dynamic SSL reload is enabled",
			roles:                   []secrets.SecretRole{secrets.RoleCA},
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
		{
			name:                    "JWK secret forces reload even when dynamic SSL reload is enabled",
			roles:                   []secrets.SecretRole{secrets.RoleJWK},
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
		{
			name:                    "Htpasswd secret forces reload even when dynamic SSL reload is enabled",
			roles:                   []secrets.SecretRole{secrets.RoleHtpasswd},
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
		{
			name:                    "OIDC secret forces reload even when dynamic SSL reload is enabled",
			roles:                   []secrets.SecretRole{secrets.RoleOIDC},
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
		{
			name:                    "APIKey secret forces reload even when dynamic SSL reload is enabled",
			roles:                   []secrets.SecretRole{secrets.RoleAPIKey},
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
		{
			name:                    "CA secret forces reload when dynamic SSL reload is disabled",
			roles:                   []secrets.SecretRole{secrets.RoleCA},
			dynamicSSLReloadEnabled: false,
			expected:                true,
		},
		{
			name:                    "JWK secret forces reload when dynamic SSL reload is disabled",
			roles:                   []secrets.SecretRole{secrets.RoleJWK},
			dynamicSSLReloadEnabled: false,
			expected:                true,
		},
		{
			name:                    "Htpasswd secret forces reload when dynamic SSL reload is disabled",
			roles:                   []secrets.SecretRole{secrets.RoleHtpasswd},
			dynamicSSLReloadEnabled: false,
			expected:                true,
		},
		{
			name:                    "OIDC secret forces reload when dynamic SSL reload is disabled",
			roles:                   []secrets.SecretRole{secrets.RoleOIDC},
			dynamicSSLReloadEnabled: false,
			expected:                true,
		},
		{
			name:                    "APIKey secret forces reload when dynamic SSL reload is disabled",
			roles:                   []secrets.SecretRole{secrets.RoleAPIKey},
			dynamicSSLReloadEnabled: false,
			expected:                true,
		},
		{
			name:                    "TLS and CA roles force reload even when dynamic SSL reload is enabled",
			roles:                   []secrets.SecretRole{secrets.RoleTLS, secrets.RoleCA},
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
		{
			name:                    "Multiple TLS-only roles still skip forced reload",
			roles:                   []secrets.SecretRole{secrets.RoleTLS, secrets.RoleTLS},
			dynamicSSLReloadEnabled: true,
			expected:                false,
		},
		{
			name:                    "No resolved roles forces reload",
			roles:                   nil,
			dynamicSSLReloadEnabled: true,
			expected:                true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shouldForceReloadOnSecretUpdate(tc.roles, tc.dynamicSSLReloadEnabled)
			if got != tc.expected {
				t.Fatalf("shouldForceReloadOnSecretUpdate(%q, %v) = %v, want %v",
					tc.roles, tc.dynamicSSLReloadEnabled, got, tc.expected)
			}
		})
	}
}

func TestCreateVirtualServerExWithZoneSync(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testCase string
		input    NewLoadBalancerControllerInput
		vs       conf_v1.VirtualServer
		vsr      []*conf_v1.VirtualServerRoute
		expected configs.VirtualServerEx
	}{
		{
			testCase: "VirtualServerEx without Zone sync",
			input: NewLoadBalancerControllerInput{
				KubeClient:               fake.NewClientset(),
				EnableTelemetryReporting: false,
				LoggerContext:            context.Background(),
			},
			vs:  conf_v1.VirtualServer{},
			vsr: []*conf_v1.VirtualServerRoute{{}},
			expected: configs.VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{},
				},
			},
		},
		{
			testCase: "VirtualServerEx with Zone sync",
			input: NewLoadBalancerControllerInput{
				KubeClient:               fake.NewClientset(),
				EnableTelemetryReporting: false,
				LoggerContext:            context.Background(),
				NginxConfigurator: &configs.Configurator{
					CfgParams: &configs.ConfigParams{
						ZoneSync: configs.ZoneSync{
							Enable: true,
						},
					},
				},
			},
			vs:  conf_v1.VirtualServer{},
			vsr: []*conf_v1.VirtualServerRoute{{}},
			expected: configs.VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{},
				},
			},
		},
	}

	for _, tc := range testCases {
		lbc := NewLoadBalancerController(tc.input)
		vsEx := lbc.createVirtualServerEx(&tc.vs, tc.vsr, nil)
		if reflect.DeepEqual(vsEx, tc.expected) {
			t.Fatalf("Expected %v, but got %v", tc.expected, vsEx)
		}
	}
}

func TestVirtualServerRequiresEndpointsUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		vsEx         *configs.VirtualServerEx
		svcNamespace string
		svcName      string
		expected     bool
	}{
		{
			name: "matches cross-namespace service in VirtualServer upstream",
			vsEx: &configs.VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{Namespace: "default"},
					Spec: conf_v1.VirtualServerSpec{
						Upstreams: []conf_v1.Upstream{{Service: "backend-ns/backend-svc"}},
					},
				},
			},
			svcNamespace: "backend-ns",
			svcName:      "backend-svc",
			expected:     true,
		},
		{
			name: "does not match useClusterIP upstream",
			vsEx: &configs.VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{Namespace: "default"},
					Spec: conf_v1.VirtualServerSpec{
						Upstreams: []conf_v1.Upstream{{Service: "backend-svc", Backup: "backup-svc", UseClusterIP: true}},
					},
				},
			},
			svcNamespace: "default",
			svcName:      "backup-svc",
			expected:     false,
		},
		{
			name: "does not match unrelated service",
			vsEx: &configs.VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{Namespace: "default"},
					Spec: conf_v1.VirtualServerSpec{
						Upstreams: []conf_v1.Upstream{{Service: "backend-svc", Backup: "backup-svc"}},
					},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{Namespace: "default"},
						Spec: conf_v1.VirtualServerRouteSpec{
							Upstreams: []conf_v1.Upstream{{Service: "backend-svc", Backup: "backup-svc"}},
						},
					},
				},
			},
			svcNamespace: "default",
			svcName:      "other-svc",
			expected:     false,
		},
	}

	lbc := &LoadBalancerController{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := lbc.virtualServerRequiresEndpointsUpdate(test.vsEx, test.svcNamespace, test.svcName)
			if result != test.expected {
				t.Fatalf("virtualServerRequiresEndpointsUpdate() returned %v, expected %v", result, test.expected)
			}
		})
	}
}

func TestCreateIngressExWithZoneSync(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testCase string
		input    NewLoadBalancerControllerInput
		ingress  *networking.Ingress
		expected configs.IngressEx
	}{
		{
			testCase: "IngressEx without Zone sync",
			input: NewLoadBalancerControllerInput{
				KubeClient:               fake.NewClientset(),
				EnableTelemetryReporting: false,
				LoggerContext:            context.Background(),
			},
			ingress: &networking.Ingress{},
			expected: configs.IngressEx{
				Ingress: &networking.Ingress{},
			},
		},
		{
			testCase: "IngressEx with Zone sync",
			input: NewLoadBalancerControllerInput{
				KubeClient:               fake.NewClientset(),
				EnableTelemetryReporting: false,
				LoggerContext:            context.Background(),
			},
			ingress: &networking.Ingress{},
			expected: configs.IngressEx{
				Ingress:  &networking.Ingress{},
				ZoneSync: true,
			},
		},
	}

	for _, tc := range testCases {
		lbc := NewLoadBalancerController(tc.input)
		ingressEx := lbc.createIngressEx(tc.ingress, nil, nil)
		if reflect.DeepEqual(ingressEx, tc.expected) {
			t.Fatalf("Expected %v, but got %v", tc.expected, ingressEx)
		}
	}
}

func TestIsPodMarkedForDeletion(t *testing.T) {
	t.Parallel()

	logger := nl.LoggerFromContext(context.Background())

	tests := []struct {
		name            string
		shutdownFlag    bool
		envPodName      string
		envPodNamespace string
		podExists       bool
		podHasTimestamp bool
		expectedResult  bool
	}{
		{
			name:           "controller is shutting down",
			shutdownFlag:   true,
			expectedResult: true,
		},
		{
			name:            "pod exists with deletion timestamp",
			envPodName:      "test-pod",
			envPodNamespace: "test-namespace",
			podExists:       true,
			podHasTimestamp: true,
			expectedResult:  true,
		},
		{
			name:            "pod exists without deletion timestamp",
			envPodName:      "test-pod",
			envPodNamespace: "test-namespace",
			podExists:       true,
			podHasTimestamp: false,
			expectedResult:  false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewClientset()
			if test.podExists {
				pod := &api_v1.Pod{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      test.envPodName,
						Namespace: test.envPodNamespace,
					},
				}

				if test.podHasTimestamp {
					pod.DeletionTimestamp = new(meta_v1.Now())
				}

				_, err := client.CoreV1().Pods(test.envPodNamespace).Create(context.Background(), pod, meta_v1.CreateOptions{})
				if err != nil {
					t.Fatalf("Error creating pod: %v", err)
				}
			}

			lbc := &LoadBalancerController{
				client: client,
				metadata: controllerMetadata{
					pod: &api_v1.Pod{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      test.envPodName,
							Namespace: test.envPodNamespace,
						},
					},
				},
				ShuttingDown: test.shutdownFlag,
				Logger:       logger,
			}

			// Call the function and verify result
			result := lbc.isPodMarkedForDeletion()
			if result != test.expectedResult {
				t.Errorf("Returned %v but expected %v", result, test.expectedResult)
			}
		})
	}
}

func TestGenerateExternalAuthEndpoints(t *testing.T) {
	t.Parallel()

	endpointPort80 := int32(8080)
	endpointPort9000 := int32(9000)
	endpointReady := true

	// buildLBC creates a LoadBalancerController wired with the given services and endpoint slices
	// in the specified namespace. Passing nil slices creates an empty cache.
	buildLBC := func(t *testing.T, namespace string, svcs []*api_v1.Service, endpointSlices []*discovery_v1.EndpointSlice) *LoadBalancerController {
		t.Helper()
		svcStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
		for _, svc := range svcs {
			if err := svcStore.Add(svc); err != nil {
				t.Fatalf("error adding service: %v", err)
			}
		}
		esStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
		for _, es := range endpointSlices {
			if err := esStore.Add(es); err != nil {
				t.Fatalf("error adding endpoint slice: %v", err)
			}
		}
		nsi := &namespacedInformer{
			svcLister:           svcStore,
			endpointSliceLister: storeToEndpointSliceLister{Store: esStore},
			podLister:           indexerToPodLister{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})},
		}
		objs := make([]runtime.Object, 0, len(svcs))
		for _, svc := range svcs {
			objs = append(objs, svc)
		}
		return &LoadBalancerController{
			client:              fake.NewClientset(objs...),
			isNginxPlus:         false,
			Logger:              nl.LoggerFromContext(context.Background()),
			metricsCollector:    collectors.NewControllerFakeCollector(),
			namespacedInformers: map[string]*namespacedInformer{namespace: nsi},
		}
	}

	// Shared fixtures
	authSvc := &api_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{Name: "auth-svc", Namespace: "default"},
		Spec: api_v1.ServiceSpec{
			Ports: []api_v1.ServicePort{
				{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)},
			},
			Selector: map[string]string{"app": "auth"},
		},
	}

	authES80 := &discovery_v1.EndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "auth-svc-abc", Namespace: "default",
			Labels: map[string]string{discovery_v1.LabelServiceName: "auth-svc"},
		},
		Ports: []discovery_v1.EndpointPort{{Port: &endpointPort80}},
		Endpoints: []discovery_v1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
			{Addresses: []string{"10.0.0.2"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
		},
	}

	multiPortSvc := &api_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{Name: "multi-port-svc", Namespace: "default"},
		Spec: api_v1.ServiceSpec{
			Ports: []api_v1.ServicePort{
				{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)},
				{Name: "custom", Port: 9000, TargetPort: intstr.FromInt(9000)},
			},
			Selector: map[string]string{"app": "multi"},
		},
	}

	multiPortES80 := &discovery_v1.EndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "multi-port-svc-http", Namespace: "default",
			Labels: map[string]string{discovery_v1.LabelServiceName: "multi-port-svc"},
		},
		Ports: []discovery_v1.EndpointPort{{Port: &endpointPort80}},
		Endpoints: []discovery_v1.Endpoint{
			{Addresses: []string{"10.0.0.10"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
		},
	}

	multiPortES9000 := &discovery_v1.EndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "multi-port-svc-custom", Namespace: "default",
			Labels: map[string]string{discovery_v1.LabelServiceName: "multi-port-svc"},
		},
		Ports: []discovery_v1.EndpointPort{{Port: &endpointPort9000}},
		Endpoints: []discovery_v1.Endpoint{
			{Addresses: []string{"10.0.0.11"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
		},
	}

	tests := []struct {
		name              string
		setupLBC          func(t *testing.T) *LoadBalancerController
		policies          []*conf_v1.Policy
		initialEndpoints  map[string][]string
		expectedEndpoints map[string][]string
	}{
		{
			name:              "nil policies produces no endpoints",
			setupLBC:          func(t *testing.T) *LoadBalancerController { return buildLBC(t, "default", nil, nil) },
			policies:          nil,
			expectedEndpoints: map[string][]string{},
		},
		{
			name:              "empty policies slice produces no endpoints",
			setupLBC:          func(t *testing.T) *LoadBalancerController { return buildLBC(t, "default", nil, nil) },
			policies:          []*conf_v1.Policy{},
			expectedEndpoints: map[string][]string{},
		},
		{
			name:     "policy with nil ExternalAuth is skipped",
			setupLBC: func(t *testing.T) *LoadBalancerController { return buildLBC(t, "default", nil, nil) },
			policies: []*conf_v1.Policy{
				{ObjectMeta: meta_v1.ObjectMeta{Name: "p1", Namespace: "default"}, Spec: conf_v1.PolicySpec{}},
			},
			expectedEndpoints: map[string][]string{},
		},
		{
			name:     "policy with empty AuthServiceName is skipped",
			setupLBC: func(t *testing.T) *LoadBalancerController { return buildLBC(t, "default", nil, nil) },
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "p1", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: ""}},
				},
			},
			expectedEndpoints: map[string][]string{},
		},
		{
			name: "AuthServiceName resolves service endpoints",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-svc:80": {"10.0.0.1:8080", "10.0.0.2:8080"},
			},
		},
		{
			name: "multi-port service resolves endpoints for all ports",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{multiPortSvc}, []*discovery_v1.EndpointSlice{multiPortES80, multiPortES9000})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "multi-port-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/multi-port-svc:80":   {"10.0.0.10:8080"},
				"default/multi-port-svc:9000": {"10.0.0.11:9000"},
			},
		},
		{
			name:     "service not found is handled gracefully",
			setupLBC: func(t *testing.T) *LoadBalancerController { return buildLBC(t, "default", nil, nil) },
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/auth", AuthServiceName: "nonexistent-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/nonexistent-svc:80": {},
			},
		},
		{
			name: "multiple policies with mixed configurations",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{ObjectMeta: meta_v1.ObjectMeta{Name: "p-nil", Namespace: "default"}, Spec: conf_v1.PolicySpec{}},
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "p-empty", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: ""}},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "p-valid", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-svc:80": {"10.0.0.1:8080", "10.0.0.2:8080"},
			},
		},
		{
			name: "duplicate policies with same AuthServiceName produce single endpoint set",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-1", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-2", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/verify", AuthServiceName: "auth-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-svc:80": {"10.0.0.1:8080", "10.0.0.2:8080"},
			},
		},
		{
			name: "existing endpoints in map are preserved",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
			},
			initialEndpoints: map[string][]string{
				"default/existing-svc:8080": {"192.168.1.1:8080"},
			},
			expectedEndpoints: map[string][]string{
				"default/existing-svc:8080": {"192.168.1.1:8080"},
				"default/auth-svc:80":       {"10.0.0.1:8080", "10.0.0.2:8080"},
			},
		},
		{
			name: "endpoint key uses VirtualServer namespace for ParseServiceReference",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				svc := &api_v1.Service{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-svc", Namespace: "custom-ns"},
					Spec: api_v1.ServiceSpec{
						Ports:    []api_v1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)}},
						Selector: map[string]string{"app": "auth"},
					},
				}
				es := &discovery_v1.EndpointSlice{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "auth-svc-ns", Namespace: "custom-ns",
						Labels: map[string]string{discovery_v1.LabelServiceName: "auth-svc"},
					},
					Ports: []discovery_v1.EndpointPort{{Port: &endpointPort80}},
					Endpoints: []discovery_v1.Endpoint{
						{Addresses: []string{"10.1.0.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
					},
				}
				return buildLBC(t, "custom-ns", []*api_v1.Service{svc}, []*discovery_v1.EndpointSlice{es})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "custom-ns"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"custom-ns/auth-svc:80": {"10.1.0.1:8080"},
			},
		},
		{
			name: "two policies with different services produce separate endpoint keys",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				svcA := &api_v1.Service{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-a", Namespace: "default"},
					Spec: api_v1.ServiceSpec{
						Ports:    []api_v1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)}},
						Selector: map[string]string{"app": "auth-a"},
					},
				}
				svcB := &api_v1.Service{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-b", Namespace: "default"},
					Spec: api_v1.ServiceSpec{
						Ports:    []api_v1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)}},
						Selector: map[string]string{"app": "auth-b"},
					},
				}
				esA := &discovery_v1.EndpointSlice{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "auth-a-es", Namespace: "default",
						Labels: map[string]string{discovery_v1.LabelServiceName: "auth-a"},
					},
					Ports: []discovery_v1.EndpointPort{{Port: &endpointPort80}},
					Endpoints: []discovery_v1.Endpoint{
						{Addresses: []string{"10.0.1.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
					},
				}
				esB := &discovery_v1.EndpointSlice{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "auth-b-es", Namespace: "default",
						Labels: map[string]string{discovery_v1.LabelServiceName: "auth-b"},
					},
					Ports: []discovery_v1.EndpointPort{{Port: &endpointPort80}},
					Endpoints: []discovery_v1.Endpoint{
						{Addresses: []string{"10.0.2.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
					},
				}
				return buildLBC(t, "default", []*api_v1.Service{svcA, svcB}, []*discovery_v1.EndpointSlice{esA, esB})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-a-pol", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-a"}},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-b-pol", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-b"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-a:80": {"10.0.1.1:8080"},
				"default/auth-b:80": {"10.0.2.1:8080"},
			},
		},
		{
			name: "valid policy followed by error policy still adds valid entries",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "good", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "bad", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/auth", AuthServiceName: "nonexistent-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-svc:80":        {"10.0.0.1:8080", "10.0.0.2:8080"},
				"default/nonexistent-svc:80": {},
			},
		},
		{
			name: "AuthServicePorts uses policy-specified port instead of service ports",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{multiPortSvc}, []*discovery_v1.EndpointSlice{multiPortES80, multiPortES9000})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/check",
						AuthServiceName:  "multi-port-svc",
						AuthServicePorts: []int{9000},
					}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/multi-port-svc:9000": {"10.0.0.11:9000"},
			},
		},
		{
			name: "AuthServicePorts with multiple ports resolves each specified port",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{multiPortSvc}, []*discovery_v1.EndpointSlice{multiPortES80, multiPortES9000})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/check",
						AuthServiceName:  "multi-port-svc",
						AuthServicePorts: []int{80, 9000},
					}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/multi-port-svc:80":   {"10.0.0.10:8080"},
				"default/multi-port-svc:9000": {"10.0.0.11:9000"},
			},
		},
		{
			name: "AuthServicePorts with single port on single-port service",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/check",
						AuthServiceName:  "auth-svc",
						AuthServicePorts: []int{80},
					}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-svc:80": {"10.0.0.1:8080", "10.0.0.2:8080"},
			},
		},
		{
			name: "AuthServicePorts with nonexistent port is handled gracefully",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc}, []*discovery_v1.EndpointSlice{authES80})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/check",
						AuthServiceName:  "auth-svc",
						AuthServicePorts: []int{9999},
					}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/auth-svc:9999": {},
			},
		},
		{
			name: "AuthServicePorts mixed with policy without AuthServicePorts",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{authSvc, multiPortSvc}, []*discovery_v1.EndpointSlice{authES80, multiPortES80, multiPortES9000})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "policy-with-ports", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/check",
						AuthServiceName:  "multi-port-svc",
						AuthServicePorts: []int{9000},
					}},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "policy-without-ports", Namespace: "default"},
					Spec:       conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/check", AuthServiceName: "auth-svc"}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/multi-port-svc:9000": {"10.0.0.11:9000"},
				"default/auth-svc:80":         {"10.0.0.1:8080", "10.0.0.2:8080"},
			},
		},
		{
			name: "empty AuthServicePorts slice falls back to service ports",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				return buildLBC(t, "default", []*api_v1.Service{multiPortSvc}, []*discovery_v1.EndpointSlice{multiPortES80, multiPortES9000})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "auth-policy", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/check",
						AuthServiceName:  "multi-port-svc",
						AuthServicePorts: []int{},
					}},
				},
			},
			expectedEndpoints: map[string][]string{
				"default/multi-port-svc:80":   {"10.0.0.10:8080"},
				"default/multi-port-svc:9000": {"10.0.0.11:9000"},
			},
		},
		{
			name: "cross-namespace AuthServiceName with namespace prefix resolves endpoints",
			setupLBC: func(t *testing.T) *LoadBalancerController {
				t.Helper()
				crossNsSvc := &api_v1.Service{
					ObjectMeta: meta_v1.ObjectMeta{Name: "basic-auth-svc", Namespace: "my-namespace"},
					Spec: api_v1.ServiceSpec{
						Ports: []api_v1.ServicePort{
							{Name: "http", Port: 8080, TargetPort: intstr.FromInt(8080)},
							{Name: "https", Port: 8443, TargetPort: intstr.FromInt(8443)},
						},
						Selector: map[string]string{"app": "basic-auth"},
					},
				}
				crossNsES := &discovery_v1.EndpointSlice{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "basic-auth-svc-abc", Namespace: "my-namespace",
						Labels: map[string]string{discovery_v1.LabelServiceName: "basic-auth-svc"},
					},
					Ports: []discovery_v1.EndpointPort{{Port: &endpointPort80}},
					Endpoints: []discovery_v1.Endpoint{
						{Addresses: []string{"10.2.0.1"}, Conditions: discovery_v1.EndpointConditions{Ready: &endpointReady}},
					},
				}
				// Use "" as namespace key to simulate watching all namespaces (global informer)
				return buildLBC(t, "", []*api_v1.Service{crossNsSvc}, []*discovery_v1.EndpointSlice{crossNsES})
			},
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{Name: "ext-auth-policy", Namespace: "default"},
					Spec: conf_v1.PolicySpec{ExternalAuth: &conf_v1.ExternalAuth{
						AuthURI:          "/auth",
						AuthServiceName:  "my-namespace/basic-auth-svc",
						AuthServicePorts: []int{8080},
					}},
				},
			},
			expectedEndpoints: map[string][]string{
				"my-namespace/basic-auth-svc:8080": {"10.2.0.1:8080"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lbc := tc.setupLBC(t)

			endpoints := make(map[string][]string)
			for k, v := range tc.initialEndpoints {
				endpoints[k] = v
			}

			lbc.generateExternalAuthEndpoints(tc.policies, endpoints)

			if len(endpoints) != len(tc.expectedEndpoints) {
				t.Fatalf("expected %d endpoint entries, got %d: %v", len(tc.expectedEndpoints), len(endpoints), endpoints)
			}
			for key, expectedEps := range tc.expectedEndpoints {
				gotEps, exists := endpoints[key]
				if !exists {
					t.Errorf("expected key %q in endpoints map, got: %v", key, endpoints)
					continue
				}
				sort.Strings(gotEps)
				sort.Strings(expectedEps)
				if !reflect.DeepEqual(gotEps, expectedEps) {
					t.Errorf("key %q: expected %v, got %v", key, expectedEps, gotEps)
				}
			}
		})
	}
}
