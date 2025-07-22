package k8s

import (
	"context"
	"fmt"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	discovery_v1 "k8s.io/api/discovery/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

type fixture struct {
	t *testing.T

	client     *fake.Clientset
	kubeclient *k8sfake.Clientset
	// Objects from here preloaded into NewSimpleFake.
	kubeobjects []runtime.Object
	objects     []runtime.Object
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{}
	f.t = t
	f.objects = []runtime.Object{}
	f.kubeobjects = []runtime.Object{}
	return f
}

func (f *fixture) runController(lbc *LoadBalancerController) {
	lbc.ctx, lbc.cancel = context.WithCancel(context.Background())

	for _, nif := range lbc.namespacedInformers {
		nif.start()
	}
	lbc.isNginxReady = true
}

func newVS(namespace, name, host string) *conf_v1.VirtualServer {
	vs := &conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: conf_v1.VirtualServerSpec{
			Host: host,
		},
	}
	return vs
}

func newTS(namespace, name, host string) *conf_v1.TransportServer {
	ts := &conf_v1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: conf_v1.TransportServerSpec{
			Host: host,
		},
	}
	return ts
}

func newES(namespace, name, ip string) *discovery_v1.EndpointSlice {
	es := &discovery_v1.EndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		AddressType: discovery_v1.AddressTypeIPv4,
		Endpoints: []discovery_v1.Endpoint{
			{
				Addresses: []string{ip},
			},
		},
	}
	return es
}

func TestLBCBatchUpdate(t *testing.T) {
	f := newFixture(t)
	f.kubeclient = k8sfake.NewSimpleClientset()
	f.client = fake.NewSimpleClientset()
	namespace := "test-namespace"

	input := NewLoadBalancerControllerInput{
		KubeClient:                f.kubeclient,
		EnableTelemetryReporting:  false,
		LoggerContext:             context.Background(),
		Recorder:                  &record.FakeRecorder{},
		NginxConfigurator:         &configs.Configurator{},
		Namespace:                 []string{namespace},
		AreCustomResourcesEnabled: true,
	}
	lbc := NewLoadBalancerController(input)

	vs := newVS(namespace, "test-vs", "test-host")
	ts := newTS(namespace, "test-ts", "test-host")
	es := newES(namespace, "test-endpoint-slice", "10.0.0.1")
	f.objects = append(f.objects, vs)
	f.kubeobjects = append(f.kubeobjects, vs)
	f.objects = append(f.objects, ts)
	f.kubeobjects = append(f.kubeobjects, ts)
	f.objects = append(f.objects, es)
	f.kubeobjects = append(f.kubeobjects, es)
	f.runController(lbc)
	fmt.Println("Running controller")
	task := task{
		Key:  fmt.Sprintf("%s/test-endpoint-slice", namespace),
		Kind: 1, // EndpointSliceKind
	}
	lbc.syncQueue.Enqueue(vs)
	lbc.syncQueue.Enqueue(ts)
	lbc.sync(task)
	if lbc.batchSyncEnabled != true {
		t.Errorf("Expected: lbc.batchSyncEnabled to be: %t, Got: %t", true, lbc.batchSyncEnabled)
	}
	if lbc.nginxReloadForBatchUpdate != false {
		t.Errorf("Expected: lbc.nginxReloadForBatchUpdate to be: %t, Got: %t", false, lbc.nginxReloadForBatchUpdate)
	}
}

func TestLBCNginxReloadForBatchUpdateFalse(t *testing.T) {
	f := newFixture(t)
	f.kubeclient = k8sfake.NewSimpleClientset()
	f.client = fake.NewSimpleClientset()
	namespace := "test-namespace"

	input := NewLoadBalancerControllerInput{
		KubeClient:                f.kubeclient,
		EnableTelemetryReporting:  false,
		LoggerContext:             context.Background(),
		Recorder:                  &record.FakeRecorder{},
		NginxConfigurator:         &configs.Configurator{},
		Namespace:                 []string{namespace},
		AreCustomResourcesEnabled: true,
	}
	lbc := NewLoadBalancerController(input)
	lbc.metricsCollector = collectors.NewControllerFakeCollector()

	vs1 := newVS(namespace, "test-vs1", "test-host1")
	vs2 := newVS(namespace, "test-vs2", "test-host2")
	ts := newTS(namespace, "test-ts", "test-host")
	f.objects = append(f.objects, vs1)
	f.kubeobjects = append(f.kubeobjects, vs1)
	f.objects = append(f.objects, vs2)
	f.kubeobjects = append(f.kubeobjects, vs2)
	f.objects = append(f.objects, ts)
	f.kubeobjects = append(f.kubeobjects, ts)
	f.runController(lbc)
	fmt.Println("Running controller")
	task := task{
		Key:  fmt.Sprintf("%s/test-vs1", namespace),
		Kind: 6, // VirtualServerKind
	}
	lbc.syncQueue.Enqueue(vs1)
	lbc.syncQueue.Enqueue(ts)
	lbc.sync(task)
	if lbc.batchSyncEnabled != true {
		t.Errorf("Expected: lbc.batchSyncEnabled to be: %t, Got: %t", true, lbc.batchSyncEnabled)
	}
	if lbc.nginxReloadForBatchUpdate != true {
		t.Errorf("Expected: lbc.nginxReloadForBatchUpdate to be: %t, Got: %t", true, lbc.nginxReloadForBatchUpdate)
	}
}
