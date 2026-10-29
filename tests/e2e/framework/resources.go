//go:build e2e

package framework

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck // Gomega DSL
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NIC custom resources, by Kind.
var nicResources = map[string]schema.GroupVersionResource{
	"VirtualServer":       {Group: "k8s.nginx.org", Version: "v1", Resource: "virtualservers"},
	"VirtualServerRoute":  {Group: "k8s.nginx.org", Version: "v1", Resource: "virtualserverroutes"},
	"TransportServer":     {Group: "k8s.nginx.org", Version: "v1", Resource: "transportservers"},
	"Policy":              {Group: "k8s.nginx.org", Version: "v1", Resource: "policies"},
	"GlobalConfiguration": {Group: "k8s.nginx.org", Version: "v1", Resource: "globalconfigurations"},
}

// DataPath returns the absolute path of a file under tests/data (e.g. for ClientCert).
func (f *Framework) DataPath(path string) string {
	p, err := filepath.Abs(filepath.Join(f.DataDir, path))
	if err != nil {
		return filepath.Join(f.DataDir, path)
	}
	return p
}

// VSConf returns the generated NGINX config of a VirtualServer in the sandbox.
func (s *Sandbox) VSConf(ctx context.Context, name string) (string, error) {
	return s.confFile(ctx, fmt.Sprintf("vs_%s_%s.conf", s.Namespace, name))
}

// IngressConf returns the generated NGINX config of an Ingress in the sandbox.
func (s *Sandbox) IngressConf(ctx context.Context, name string) (string, error) {
	return s.confFile(ctx, fmt.Sprintf("%s-%s.conf", s.Namespace, name))
}

func (s *Sandbox) confFile(ctx context.Context, file string) (string, error) {
	pod, err := s.f.ICPod(ctx)
	if err != nil {
		return "", err
	}
	out, err := s.f.Exec(ctx, pod, "cat", "/etc/nginx/conf.d/"+file)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w: %s", file, err, out)
	}
	return out, nil
}

// EventuallyConf polls a generated config (VSConf or IngressConf) until check passes and returns it.
func (s *Sandbox) EventuallyConf(ctx context.Context, read func(context.Context, string) (string, error), name string, check func(Gomega, string)) string {
	GinkgoHelper()
	var conf string
	Eventually(func(g Gomega) {
		c, err := read(ctx, name)
		g.Expect(err).NotTo(HaveOccurred())
		check(g, c)
		conf = c
	}).WithContext(ctx).WithTimeout(WaitTimeout).WithPolling(250 * time.Millisecond).Should(Succeed())
	return conf
}

// Status is the status block NIC writes on its custom resources.
type Status struct {
	State, Reason, Message string
}

// Object reads a NIC custom resource (VirtualServer, VirtualServerRoute, Policy, ...) from the sandbox.
func (s *Sandbox) Object(ctx context.Context, kind, name string) (*unstructured.Unstructured, error) {
	gvr, ok := nicResources[kind]
	if !ok {
		return nil, fmt.Errorf("unknown NIC kind %q", kind)
	}
	return s.f.Dynamic.Resource(gvr).Namespace(s.Namespace).Get(ctx, name, metav1.GetOptions{})
}

// Status reads .status of a NIC custom resource.
func (s *Sandbox) Status(ctx context.Context, kind, name string) (Status, error) {
	o, err := s.Object(ctx, kind, name)
	if err != nil {
		return Status{}, err
	}
	field := func(name string) string {
		v, _, _ := unstructured.NestedString(o.Object, "status", name)
		return v
	}
	return Status{State: field("state"), Reason: field("reason"), Message: field("message")}, nil
}

// EventuallyState waits until a NIC custom resource reports state (Valid, Warning, Invalid) and returns its status.
func (s *Sandbox) EventuallyState(ctx context.Context, kind, name, state string) Status {
	GinkgoHelper()
	var st Status
	Eventually(func(g Gomega) {
		var err error
		st, err = s.Status(ctx, kind, name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(st.State).To(Equal(state), "%s %s status: %+v", kind, name, st)
	}).WithContext(ctx).WithTimeout(WaitTimeout).WithPolling(250 * time.Millisecond).Should(Succeed())
	return st
}

// Events lists events in the sandbox namespace.
func (s *Sandbox) Events(ctx context.Context) ([]corev1.Event, error) {
	l, err := s.f.Kube.CoreV1().Events(s.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

// EventuallyEvent waits until an event whose message contains text is recorded in the sandbox.
func (s *Sandbox) EventuallyEvent(ctx context.Context, text string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		evs, err := s.Events(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		var msgs []string
		for _, e := range evs {
			msgs = append(msgs, e.Message)
		}
		g.Expect(strings.Join(msgs, "\n")).To(ContainSubstring(text))
	}).WithContext(ctx).WithTimeout(WaitTimeout).WithPolling(250 * time.Millisecond).Should(Succeed())
}
