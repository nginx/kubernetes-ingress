//go:build e2e

package framework

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck // Gomega DSL
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
)

// SandboxLabel marks namespaces created by NewSandbox.
const SandboxLabel = "e2e.nginx.org/sandbox"

// Sandbox isolates one spec: a private namespace and hostnames prefixed with a random ID,
// so specs can share one Ingress Controller without colliding.
type Sandbox struct {
	f         *Framework
	ID        string
	Namespace string
	connDrops atomic.Int64
	start     time.Time
}

// NewSandbox creates the spec's namespace and registers cleanup. On failure, cleanup first
// saves NIC logs, `nginx -T` and namespace events to ArtifactsDir.
func (f *Framework) NewSandbox(ctx context.Context) *Sandbox {
	GinkgoHelper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := &Sandbox{f: f, ID: hex.EncodeToString(b), start: time.Now()}
	s.Namespace = "e2e-" + s.ID
	_, err := f.Kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: s.Namespace, Labels: map[string]string{SandboxLabel: "true"},
	}}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(s.cleanup)
	return s
}

func (s *Sandbox) cleanup(ctx SpecContext) {
	AddReportEntry("conn_drops", s.connDrops.Load())
	if CurrentSpecReport().Failed() {
		s.saveArtifacts(ctx)
	}
	// Deletion is asynchronous on purpose: the next spec does not wait for it.
	err := s.f.Kube.CoreV1().Namespaces().Delete(ctx, s.Namespace, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

// Host returns the sandbox-unique form of a hostname used in tests/data manifests.
func (s *Sandbox) Host(orig string) string { return s.ID + "." + orig }

// Load reads a multi-document manifest from tests/data with hostnames rewritten via Host.
func (s *Sandbox) Load(path string) []*unstructured.Unstructured {
	GinkgoHelper()
	data, err := os.ReadFile(filepath.Join(s.f.DataDir, path)) //nolint:gosec // spec-provided path under tests/data
	Expect(err).NotTo(HaveOccurred())
	var objs []*unstructured.Unstructured
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		o := &unstructured.Unstructured{}
		err := dec.Decode(&o.Object)
		if errors.Is(err, io.EOF) {
			break
		}
		Expect(err).NotTo(HaveOccurred(), path)
		if len(o.Object) == 0 {
			continue
		}
		s.rewriteHosts(o)
		objs = append(objs, o)
	}
	return objs
}

// Apply server-side applies every object of a tests/data manifest into the sandbox namespace.
func (s *Sandbox) Apply(ctx context.Context, path string) {
	GinkgoHelper()
	for _, o := range s.Load(path) {
		s.ApplyObject(ctx, o)
	}
}

// ApplyObject server-side applies one object into the sandbox namespace.
func (s *Sandbox) ApplyObject(ctx context.Context, o *unstructured.Unstructured) {
	GinkgoHelper()
	ri, err := s.resource(o)
	Expect(err).NotTo(HaveOccurred())
	_, err = ri.Apply(ctx, o.GetName(), o, metav1.ApplyOptions{FieldManager: "e2e", Force: true})
	Expect(err).NotTo(HaveOccurred(), "applying %s %s", o.GetKind(), o.GetName())
}

// Delete deletes every object of a tests/data manifest from the sandbox namespace.
func (s *Sandbox) Delete(ctx context.Context, path string) {
	GinkgoHelper()
	for _, o := range s.Load(path) {
		ri, err := s.resource(o)
		Expect(err).NotTo(HaveOccurred())
		Expect(ri.Delete(ctx, o.GetName(), metav1.DeleteOptions{})).To(Succeed())
	}
}

func (s *Sandbox) resource(o *unstructured.Unstructured) (dynamic.ResourceInterface, error) {
	gvk := o.GroupVersionKind()
	m, err := s.f.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, err
	}
	if m.Scope.Name() != meta.RESTScopeNameNamespace {
		return nil, fmt.Errorf("cluster-scoped %s %q would be shared between sandboxes", gvk.Kind, o.GetName())
	}
	o.SetNamespace(s.Namespace)
	return s.f.Dynamic.Resource(m.Resource).Namespace(s.Namespace), nil
}

func (s *Sandbox) rewriteHosts(o *unstructured.Unstructured) {
	switch o.GetKind() {
	case "VirtualServer", "VirtualServerRoute", "TransportServer":
		if h, _, _ := unstructured.NestedString(o.Object, "spec", "host"); h != "" {
			_ = unstructured.SetNestedField(o.Object, s.Host(h), "spec", "host")
		}
	case "Ingress":
		rules, _, _ := unstructured.NestedSlice(o.Object, "spec", "rules")
		for _, r := range rules {
			if m, ok := r.(map[string]any); ok && m["host"] != nil {
				m["host"] = s.Host(m["host"].(string))
			}
		}
		_ = unstructured.SetNestedSlice(o.Object, rules, "spec", "rules")
		tls, _, _ := unstructured.NestedSlice(o.Object, "spec", "tls")
		for _, t := range tls {
			m, _ := t.(map[string]any)
			hosts, _ := m["hosts"].([]any)
			for i, h := range hosts {
				hosts[i] = s.Host(h.(string))
			}
		}
		_ = unstructured.SetNestedSlice(o.Object, tls, "spec", "tls")
	}
}

// WaitPodsReady waits until every pod in the sandbox is Ready.
func (s *Sandbox) WaitPodsReady(ctx context.Context) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		pods, err := s.f.Kube.CoreV1().Pods(s.Namespace).List(ctx, metav1.ListOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pods.Items).NotTo(BeEmpty())
		for _, p := range pods.Items {
			g.Expect(podReady(p)).To(BeTrue(), "pod %s not ready", p.Name)
		}
	}).WithContext(ctx).WithTimeout(3 * time.Minute).WithPolling(250 * time.Millisecond).Should(Succeed())
}

// WaitQuiet waits until no other sandbox namespace exists and the reload counter has stopped moving,
// so a Serial spec measures only its own reloads (parallel specs delete their namespaces asynchronously).
func (s *Sandbox) WaitQuiet(ctx context.Context) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		nss, err := s.f.Kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: SandboxLabel})
		g.Expect(err).NotTo(HaveOccurred())
		for _, ns := range nss.Items {
			g.Expect(ns.Name).To(Equal(s.Namespace), "sandbox %s still exists", ns.Name)
		}
	}).WithContext(ctx).WithTimeout(5 * time.Minute).WithPolling(time.Second).Should(Succeed())
	Eventually(func(g Gomega) {
		before, err := s.f.ReloadCount(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Consistently(s.f.ReloadCount).WithContext(ctx).WithTimeout(2 * time.Second).WithPolling(250 * time.Millisecond).Should(Equal(before))
	}).WithContext(ctx).WithTimeout(time.Minute).Should(Succeed())
}

var serverAddr = regexp.MustCompile(`Server address: ([0-9.]+):\d+`)

// ExpectServedHere asserts a backend response came from a pod in this sandbox, proving
// there was no cross-talk with other specs sharing the controller.
func (s *Sandbox) ExpectServedHere(ctx context.Context, body string) {
	GinkgoHelper()
	m := serverAddr.FindStringSubmatch(body)
	Expect(m).To(HaveLen(2), "no server address in response: %q", body)
	pods, err := s.f.Kube.CoreV1().Pods(s.Namespace).List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	var ips []string
	for _, p := range pods.Items {
		ips = append(ips, p.Status.PodIP)
	}
	Expect(ips).To(ContainElement(m[1]), "response served by a pod outside namespace %s", s.Namespace)
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (s *Sandbox) saveArtifacts(ctx context.Context) {
	dir := filepath.Join(s.f.ArtifactsDir, s.Namespace)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		GinkgoWriter.Printf("artifacts: %v\n", err)
		return
	}
	write := func(name string, data []byte, err error) {
		if err != nil {
			data = append(data, []byte("\nerror: "+err.Error())...)
		}
		_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
	}
	write("spec.txt", []byte(CurrentSpecReport().FullText()+"\n\n"+CurrentSpecReport().FailureMessage()), nil)
	if pod, err := s.f.ICPod(ctx); err != nil {
		write("nic.log", nil, err)
	} else {
		since := metav1.NewTime(s.start)
		logs, err := s.f.Kube.CoreV1().Pods(s.f.ICNamespace).GetLogs(pod, &corev1.PodLogOptions{SinceTime: &since}).DoRaw(ctx)
		write("nic.log", logs, err)
		conf, err := s.f.Exec(ctx, pod, "nginx", "-T")
		write("nginx-T.conf", []byte(conf), err)
	}
	var events bytes.Buffer
	evs, err := s.f.Kube.CoreV1().Events(s.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, e := range evs.Items {
			fmt.Fprintf(&events, "%s %s/%s %s: %s\n", e.LastTimestamp.Format(time.RFC3339), e.InvolvedObject.Kind, e.InvolvedObject.Name, e.Reason, e.Message)
		}
	}
	write("events.txt", events.Bytes(), err)
	GinkgoWriter.Printf("artifacts saved to %s\n", dir)
}
