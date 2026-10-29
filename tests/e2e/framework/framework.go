//go:build e2e

// Package framework is a minimal Ginkgo/Gomega harness for running NIC e2e specs in parallel
// against one shared Ingress Controller. Each spec gets its own namespace and hostnames (see Sandbox).
package framework

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

// Framework holds cluster clients and the location of the shared Ingress Controller.
type Framework struct {
	Kube    kubernetes.Interface
	Dynamic dynamic.Interface
	Mapper  meta.RESTMapper
	REST    *rest.Config

	ICNamespace  string
	ICSelector   string
	Address      string // host where the NIC NodePorts are reachable
	HTTPPort     string
	HTTPSPort    string
	DataDir      string // tests/data
	ArtifactsDir string
}

// New builds a Framework from KUBECONFIG and E2E_* environment variables.
func New() (*Framework, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, fmt.Errorf("loading KUBECONFIG: %w", err)
	}
	cfg.QPS, cfg.Burst = 50, 100 // client-go defaults (5/10) throttle parallel specs
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Framework{
		Kube:         kube,
		Dynamic:      dyn,
		Mapper:       restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(kube.Discovery())),
		REST:         cfg,
		ICNamespace:  env("E2E_IC_NAMESPACE", "nginx-ingress"),
		ICSelector:   env("E2E_IC_SELECTOR", "app.kubernetes.io/name=nginx-ingress"),
		Address:      env("E2E_HOST", "127.0.0.1"),
		HTTPPort:     env("E2E_HTTP_PORT", "30080"),
		HTTPSPort:    env("E2E_HTTPS_PORT", "30443"),
		DataDir:      env("E2E_DATA_DIR", "../../data"),
		ArtifactsDir: env("E2E_ARTIFACTS", "artifacts"),
	}, nil
}

// EnvInt reads an integer environment variable, falling back to def.
func EnvInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ICPod returns the name of a running Ingress Controller pod.
func (f *Framework) ICPod(ctx context.Context) (string, error) {
	pods, err := f.Kube.CoreV1().Pods(f.ICNamespace).List(ctx, metav1.ListOptions{LabelSelector: f.ICSelector})
	if err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("no running Ingress Controller pod in %s matching %q", f.ICNamespace, f.ICSelector)
}

// ReloadCount sums nginx_ingress_controller_nginx_reloads_total, scraped through the API server pod proxy
// so the metrics port does not need to be exposed.
func (f *Framework) ReloadCount(ctx context.Context) (int, error) {
	pod, err := f.ICPod(ctx)
	if err != nil {
		return 0, err
	}
	raw, err := f.Kube.CoreV1().RESTClient().Get().Namespace(f.ICNamespace).Resource("pods").
		Name(pod + ":9113").SubResource("proxy").Suffix("metrics").DoRaw(ctx)
	if err != nil {
		return 0, fmt.Errorf("scraping metrics: %w", err)
	}
	total := 0.0
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "nginx_ingress_controller_nginx_reloads_total") {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("parsing %q: %w", line, err)
		}
		total += v
	}
	return int(total), nil
}

// Exec runs a command in an Ingress Controller pod and returns combined stdout and stderr.
func (f *Framework) Exec(ctx context.Context, pod string, cmd ...string) (string, error) {
	req := f.Kube.CoreV1().RESTClient().Post().Namespace(f.ICNamespace).Resource("pods").Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Command: cmd, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(f.REST, "POST", req.URL())
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &out, Stderr: &out})
	return out.String(), err
}
