package k8s

import (
	"context"
	"fmt"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	apps "k8s.io/api/apps/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
)

type fixture struct {
	t *testing.T

	client     *fake.Clientset
	kubeclient *k8sfake.Clientset
	// Objects to put in the store.
	deploymentLister []*apps.Deployment
	// Actions expected to happen on the client.
	kubeactions []core.Action
	actions     []core.Action
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

func TestLBCBatch(t *testing.T) {
	f := newFixture(t)
	f.kubeclient = k8sfake.NewSimpleClientset()
	f.client = fake.NewSimpleClientset()

	input := NewLoadBalancerControllerInput{
		KubeClient:               f.kubeclient,
		EnableTelemetryReporting: false,
		LoggerContext:            context.Background(),
		Recorder:                 &record.FakeRecorder{},
		NginxConfigurator:        &configs.Configurator{},
	}
	lbc := NewLoadBalancerController(input)

	vs := &conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-vs",
			Namespace: "test-namespace",
		},
		Spec: conf_v1.VirtualServerSpec{
			Host: "test-host",
		},
	}
	ts := &conf_v1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-vs",
			Namespace: "test-namespace",
		},
		Spec: conf_v1.TransportServerSpec{
			Host: "test-host",
		},
	}
	f.objects = append(f.objects, vs)
	f.kubeobjects = append(f.kubeobjects, vs)
	f.runController(lbc)
	fmt.Println("Running controller")
	task := task{
		Key:  "test-namespace/test-vs",
		Kind: 1,
	}
	lbc.syncQueue.Enqueue(vs)
	lbc.syncQueue.Enqueue(ts)
	lbc.sync(task)
	fmt.Println("Added task to queue")
}
