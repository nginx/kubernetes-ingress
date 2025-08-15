package k8s

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

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
	fakeClient := fake.NewSimpleClientset()

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
	endpointPort := int32(8080)

	lbc := LoadBalancerController{
		isNginxPlus: true,
		Logger:      nl.LoggerFromContext(context.Background()),
	}

	backendServicePort := networking.ServiceBackendPort{
		Number: 8080,
		Name:   "foo",
	}
	endpointReadyTrue := true
	endpointReadyFalse := false

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
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReadyTrue,
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReadyFalse,
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

	endpointReadyTrue := true
	endpointReadyFalse := false

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
								Ready: &endpointReadyTrue,
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
								Ready: &endpointReadyFalse,
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
							Port: &endpointPort,
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

func TestGetEndpointSlicesBySubselectedPods_GetsEndpointsOnNilValues(t *testing.T) {
	t.Parallel()
	endpointPort := int32(8080)
	endpointReady := true
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
								Ready: &endpointReady,
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
							Port: &endpointPort,
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
	endpointPort := int32(8080)
	endpointReadyTrue := true
	endpointReadyFalse := false
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
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"1.2.3.4",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReadyTrue,
							},
						},
						{
							Addresses: []string{
								"5.6.7.8",
							},
							Conditions: discovery_v1.EndpointConditions{
								Ready: &endpointReadyFalse,
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
	endpointReadyTrue := true
	endpointReadyFalse := false
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
								Ready: &endpointReadyTrue,
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
								Ready: &endpointReadyFalse,
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
							Port: &endpointPort,
						},
					},
					Endpoints: []discovery_v1.Endpoint{
						{
							Addresses: []string{
								"5.4.3.2",
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

func TestGetEndpointSlicesBySubselectedPods_TargetPortMismatch(t *testing.T) {
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
			desc:       "targetPort mismatch",
			targetPort: 21,
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

	policyLister := &cache.FakeCustomStore{
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
	}

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
		errors.New("policy default/invalid-policy is invalid: spec: Invalid value: \"\": must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`, `basicAuth`, `apiKey`, `cache`, `jwt`, `oidc`, `waf`"),
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

	policyLister := &cache.FakeCustomStore{
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
	}

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
		errors.New("policy default/invalid-policy is invalid: spec: Invalid value: \"\": must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`, `basicAuth`, `apiKey`, `cache`, `jwt`, `oidc`, `waf`"),
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
	controller := true
	meta := meta_v1.ObjectMeta{
		OwnerReferences: []meta_v1.OwnerReference{
			{
				Kind:       kind,
				Name:       name,
				Controller: &controller,
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

func TestFindPoliciesForSecret(t *testing.T) {
	t.Parallel()
	jwtPol1 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwt-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			JWTAuth: &conf_v1.JWTAuth{
				Secret: "jwk-secret",
			},
		},
	}

	jwtPol2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwt-policy",
			Namespace: "ns-1",
		},
		Spec: conf_v1.PolicySpec{
			JWTAuth: &conf_v1.JWTAuth{
				Secret: "jwk-secret",
			},
		},
	}

	basicPol1 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "basic-auth-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			BasicAuth: &conf_v1.BasicAuth{
				Secret: "basic-auth-secret",
			},
		},
	}

	basicPol2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "basic-auth-policy",
			Namespace: "ns-1",
		},
		Spec: conf_v1.PolicySpec{
			BasicAuth: &conf_v1.BasicAuth{
				Secret: "basic-auth-secret",
			},
		},
	}

	ingTLSPol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "ingress-mtls-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressMTLS: &conf_v1.IngressMTLS{
				ClientCertSecret: "ingress-mtls-secret",
			},
		},
	}
	egTLSPol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "egress-mtls-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			EgressMTLS: &conf_v1.EgressMTLS{
				TLSSecret: "egress-mtls-secret",
			},
		},
	}
	egTLSPol2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "egress-trusted-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			EgressMTLS: &conf_v1.EgressMTLS{
				TrustedCertSecret: "egress-trusted-secret",
			},
		},
	}
	oidcPol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "oidc-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			OIDC: &conf_v1.OIDC{
				ClientSecret: "oidc-secret",
			},
		},
	}

	tests := []struct {
		policies        []*conf_v1.Policy
		secretNamespace string
		secretName      string
		expected        []*conf_v1.Policy
		msg             string
	}{
		{
			policies:        []*conf_v1.Policy{jwtPol1},
			secretNamespace: "default",
			secretName:      "jwk-secret",
			expected:        []*conf_v1.Policy{jwtPol1},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol2},
			secretNamespace: "default",
			secretName:      "jwk-secret",
			expected:        nil,
			msg:             "Ignore policies in other namespaces",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol1, jwtPol2},
			secretNamespace: "default",
			secretName:      "jwk-secret",
			expected:        []*conf_v1.Policy{jwtPol1},
			msg:             "Find policy in default ns, ignore other",
		},
		{
			policies:        []*conf_v1.Policy{basicPol1},
			secretNamespace: "default",
			secretName:      "basic-auth-secret",
			expected:        []*conf_v1.Policy{basicPol1},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{basicPol2},
			secretNamespace: "default",
			secretName:      "basic-auth-secret",
			expected:        nil,
			msg:             "Ignore policies in other namespaces",
		},
		{
			policies:        []*conf_v1.Policy{basicPol1, basicPol2},
			secretNamespace: "default",
			secretName:      "basic-auth-secret",
			expected:        []*conf_v1.Policy{basicPol1},
			msg:             "Find policy in default ns, ignore other",
		},
		{
			policies:        []*conf_v1.Policy{ingTLSPol},
			secretNamespace: "default",
			secretName:      "ingress-mtls-secret",
			expected:        []*conf_v1.Policy{ingTLSPol},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol1, ingTLSPol},
			secretNamespace: "default",
			secretName:      "ingress-mtls-secret",
			expected:        []*conf_v1.Policy{ingTLSPol},
			msg:             "Find policy in default ns, ignore other types",
		},
		{
			policies:        []*conf_v1.Policy{egTLSPol},
			secretNamespace: "default",
			secretName:      "egress-mtls-secret",
			expected:        []*conf_v1.Policy{egTLSPol},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol1, egTLSPol},
			secretNamespace: "default",
			secretName:      "egress-mtls-secret",
			expected:        []*conf_v1.Policy{egTLSPol},
			msg:             "Find policy in default ns, ignore other types",
		},
		{
			policies:        []*conf_v1.Policy{egTLSPol2},
			secretNamespace: "default",
			secretName:      "egress-trusted-secret",
			expected:        []*conf_v1.Policy{egTLSPol2},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{egTLSPol, egTLSPol2},
			secretNamespace: "default",
			secretName:      "egress-trusted-secret",
			expected:        []*conf_v1.Policy{egTLSPol2},
			msg:             "Find policy in default ns, ignore other types",
		},
		{
			policies:        []*conf_v1.Policy{oidcPol},
			secretNamespace: "default",
			secretName:      "oidc-secret",
			expected:        []*conf_v1.Policy{oidcPol},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{ingTLSPol, oidcPol},
			secretNamespace: "default",
			secretName:      "oidc-secret",
			expected:        []*conf_v1.Policy{oidcPol},
			msg:             "Find policy in default ns, ignore other types",
		},
	}
	for _, test := range tests {
		result := findPoliciesForSecret(test.policies, test.secretNamespace, test.secretName)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("findPoliciesForSecret() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
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
		expectedSecretRefs map[string]*secrets.SecretReference
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-jwk-secret": {
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
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid policy using JwksUri",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-jwk-secret": {
					Secret: invalidJWKSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.SecretReference{
			"default/valid-jwk-secret": {
				Secret: validJWKSecret,
				Path:   "/etc/nginx/secrets/default-valid-jwk-secret",
			},
			"default/invalid-jwk-secret": {
				Secret: invalidJWKSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

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
		expectedSecretRefs map[string]*secrets.SecretReference
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-basic-auth-secret": {
					Secret: validBasicSecret,
					Path:   "/etc/nginx/secrets/default-valid-basic-auth-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-basic-auth-secret": {
					Secret: invalidBasicSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.SecretReference{
			"default/valid-basic-auth-secret": {
				Secret: validBasicSecret,
				Path:   "/etc/nginx/secrets/default-valid-basic-auth-secret",
			},
			"default/invalid-basic-auth-secret": {
				Secret: invalidBasicSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

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
		expectedSecretRefs map[string]*secrets.SecretReference
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-ingress-mtls-secret": {
					Secret: validSecret,
					Path:   "/etc/nginx/secrets/default-valid-ingress-mtls-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-ingress-mtls-secret": {
					Secret: invalidSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.SecretReference{
			"default/valid-ingress-mtls-secret": {
				Secret: validSecret,
				Path:   "/etc/nginx/secrets/default-valid-ingress-mtls-secret",
			},
			"default/invalid-ingress-mtls-secret": {
				Secret: invalidSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

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
		expectedSecretRefs map[string]*secrets.SecretReference
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-egress-mtls-secret": {
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-egress-trusted-secret": {
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-egress-mtls-secret": {
					Secret: validMTLSSecret,
					Path:   "/etc/nginx/secrets/default-valid-egress-mtls-secret",
				},
				"default/valid-egress-trusted-secret": {
					Secret: validTrustedSecret,
					Path:   "/etc/nginx/secrets/default-valid-egress-trusted-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secrets",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-egress-mtls-secret": {
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-egress-trusted-secret": {
					Secret: invalidTrustedSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid TrustedCA secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.SecretReference{
			"default/valid-egress-mtls-secret": {
				Secret: validMTLSSecret,
				Path:   "/etc/nginx/secrets/default-valid-egress-mtls-secret",
			},
			"default/valid-egress-trusted-secret": {
				Secret: validTrustedSecret,
				Path:   "/etc/nginx/secrets/default-valid-egress-trusted-secret",
			},
			"default/invalid-egress-mtls-secret": {
				Secret: invalidMTLSSecret,
				Error:  invalidErr,
			},
			"default/invalid-egress-trusted-secret": {
				Secret: invalidTrustedSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

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
		expectedSecretRefs map[string]*secrets.SecretReference
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-oidc-secret": {
					Secret: validSecret,
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{},
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
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-oidc-secret": {
					Secret: invalidSecret,
					Error:  invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.SecretReference{
			"default/valid-oidc-secret": {
				Secret: validSecret,
			},
			"default/invalid-oidc-secret": {
				Secret: invalidSecret,
				Error:  invalidErr,
			},
		}),
		Logger: nl.LoggerFromContext(context.Background()),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

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
	secretLister := &cache.FakeCustomStore{
		ListFunc: func() []interface{} {
			return []interface{}{
				&api_v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "supported-secret",
						Namespace: "default",
					},
					Type: api_v1.SecretTypeTLS,
				},
				&api_v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "unsupported-secret",
						Namespace: "default",
					},
					Type: api_v1.SecretTypeOpaque,
				},
			}
		},
	}
	nsi := make(map[string]*namespacedInformer)
	nsi[""] = &namespacedInformer{secretLister: secretLister, isSecretsEnabledNamespace: true}

	lbc := LoadBalancerController{
		isNginxPlus:         true,
		secretStore:         secrets.NewEmptyFakeSecretsStore(),
		namespacedInformers: nsi,
		Logger:              nl.LoggerFromContext(context.Background()),
	}

	lbc.preSyncSecrets()

	supportedKey := "default/supported-secret"
	ref := lbc.secretStore.GetSecret(supportedKey)
	if ref.Error != nil {
		t.Errorf("GetSecret(%q) returned a reference with an unexpected error %v", supportedKey, ref.Error)
	}

	unsupportedKey := "default/unsupported-secret"
	ref = lbc.secretStore.GetSecret(unsupportedKey)
	if ref.Error == nil {
		t.Errorf("GetSecret(%q) returned a reference without an expected error", unsupportedKey)
	}
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
				KubeClient:               fake.NewSimpleClientset(),
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
				KubeClient:               fake.NewSimpleClientset(),
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
				KubeClient:               fake.NewSimpleClientset(),
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
				KubeClient:               fake.NewSimpleClientset(),
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
		vsEx := lbc.createVirtualServerEx(&tc.vs, tc.vsr)
		if reflect.DeepEqual(vsEx, tc.expected) {
			t.Fatalf("Expected %v, but got %v", tc.expected, vsEx)
		}
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
				KubeClient:               fake.NewSimpleClientset(),
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
				KubeClient:               fake.NewSimpleClientset(),
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
			client := fake.NewSimpleClientset()
			if test.podExists {
				pod := &api_v1.Pod{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      test.envPodName,
						Namespace: test.envPodNamespace,
					},
				}

				if test.podHasTimestamp {
					now := meta_v1.Now()
					pod.DeletionTimestamp = &now
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
