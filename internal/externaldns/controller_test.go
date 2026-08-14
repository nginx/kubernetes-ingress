package externaldns

import (
	"context"
	"testing"
	"time"

	vsfake "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned/fake"
	"k8s.io/client-go/tools/record"
)

func TestNewController_NoNamespaces(t *testing.T) {
	t.Parallel()
	opts := BuildOpts(context.Background(), nil, &record.FakeRecorder{}, vsfake.NewSimpleClientset(), 0, false)

	c, err := NewController(opts)
	if err != nil {
		t.Errorf("expected nil error with no namespaces, got %v", err)
	}
	if c == nil {
		t.Error("expected non-nil controller")
	}
}

func TestNewController_DynamicNsSkipsEmptyNamespace(t *testing.T) {
	t.Parallel()
	// With isDynamicNs=true and a single empty-string namespace, the loop
	// should break immediately without creating any informers.
	opts := BuildOpts(context.Background(), []string{""}, &record.FakeRecorder{}, vsfake.NewSimpleClientset(), 0, true)

	c, err := NewController(opts)
	if err != nil {
		t.Fatalf("expected nil error when dynamic ns skips empty namespace, got %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil controller")
	}
	if len(c.informerGroup) != 0 {
		t.Errorf("expected empty informerGroup when namespace skipped, got %d entries", len(c.informerGroup))
	}
}

func TestNewController_WithNamespace(t *testing.T) {
	t.Parallel()
	opts := BuildOpts(context.Background(), []string{"default"}, &record.FakeRecorder{}, vsfake.NewSimpleClientset(), time.Duration(0), false)

	c, err := NewController(opts)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil controller")
	}
	if _, ok := c.informerGroup["default"]; !ok {
		t.Error("expected informerGroup to contain entry for 'default' namespace")
	}
}
