package k8s

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func TestAreResourcesDifferent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		oldR, newR *unstructured.Unstructured
		expected   bool
		expectErr  error
		msg        string
	}{
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": true, // wrong type
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expected:  false,
			expectErr: errors.New(`.spec accessor error: true is of the type bool, expected map[string]interface{}`),
			msg:       "invalid old resource",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": true, // wrong type
				},
			},
			expected:  false,
			expectErr: errors.New(`.spec accessor error: true is of the type bool, expected map[string]interface{}`),
			msg:       "invalid new resource",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			expected:  false,
			expectErr: errors.New(`spec has unexpected format`),
			msg:       "new resource with missing spec",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "a",
					},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "a",
					},
				},
			},
			expected:  false,
			expectErr: nil,
			msg:       "equal resources",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "a",
					},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "b",
					},
				},
			},
			expected:  true,
			expectErr: nil,
			msg:       "not equal resources",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "b",
					},
				},
			},
			expected:  true,
			expectErr: nil,
			msg:       "not equal resources with first resource missing spec",
		},
	}

	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	for _, test := range tests {
		result, err := areResourcesDifferent(l, test.oldR, test.newR)
		if result != test.expected {
			t.Errorf("areResourcesDifferent() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
		if test.expectErr != nil {
			if err == nil {
				t.Errorf("areResourcesDifferent() returned no error for the case of %s", test.msg)
			} else if test.expectErr.Error() != err.Error() {
				t.Errorf("areResourcesDifferent() returned an unexpected error '%v' for the case of %s", err, test.msg)
			}
		}
		if test.expectErr == nil && err != nil {
			t.Errorf("areResourcesDifferent() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}

// deleteFuncTestCase describes a single DeleteFunc invocation and the
// enqueue behavior it is expected to produce.
type deleteFuncTestCase struct {
	msg         string
	obj         interface{}
	wantEnqueue bool
}

// runDeleteFuncTests verifies that the DeleteFunc built by newHandlers never
// panics regardless of the shape of obj -- including the object shapes a
// real informer can deliver on delete: the typed object itself, and a
// cache.DeletedFinalStateUnknown wrapper (used by client-go when a delete
// event is missed and reconstructed from the local store during a relist) --
// and that it only enqueues a sync task when it can resolve the expected
// type.
func runDeleteFuncTests(t *testing.T, tests []deleteFuncTestCase, newHandlers func(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs) {
	t.Helper()

	for _, test := range tests {
		test := test
		t.Run(test.msg, func(t *testing.T) {
			t.Parallel()

			l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
			lbc := &LoadBalancerController{
				Logger:    l,
				syncQueue: newTaskQueue(l, func(task) {}),
			}

			handlers := newHandlers(lbc)

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("DeleteFunc panicked for case %q: %v", test.msg, r)
					}
				}()
				handlers.DeleteFunc(test.obj)
			}()

			if got := lbc.syncQueue.Len() > 0; got != test.wantEnqueue {
				t.Errorf("case %q: syncQueue enqueued = %v, want %v", test.msg, got, test.wantEnqueue)
			}
		})
	}
}

func TestCreateIngressHandlersDeleteFunc(t *testing.T) {
	t.Parallel()

	validIngress := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "test-ns",
		},
	}

	tests := []deleteFuncTestCase{
		{
			msg:         "typed Ingress object",
			obj:         validIngress,
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping a valid Ingress",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/test-ingress",
				Obj: validIngress,
			},
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping an unexpected type",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/some-pod",
				Obj: &api_v1.Pod{
					ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
				},
			},
			wantEnqueue: false,
		},
		{
			msg: "completely unexpected object type",
			obj: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
			},
			wantEnqueue: false,
		},
	}

	runDeleteFuncTests(t, tests, createIngressHandlers)
}

func TestCreateVirtualServerHandlersDeleteFunc(t *testing.T) {
	t.Parallel()

	validVS := &conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-vs",
			Namespace: "test-ns",
		},
	}

	tests := []deleteFuncTestCase{
		{
			msg:         "typed VirtualServer object",
			obj:         validVS,
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping a valid VirtualServer",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/test-vs",
				Obj: validVS,
			},
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping an unexpected type",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/some-pod",
				Obj: &api_v1.Pod{
					ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
				},
			},
			wantEnqueue: false,
		},
		{
			msg: "completely unexpected object type",
			obj: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
			},
			wantEnqueue: false,
		},
	}

	runDeleteFuncTests(t, tests, createVirtualServerHandlers)
}

func TestCreateVirtualServerRouteHandlersDeleteFunc(t *testing.T) {
	t.Parallel()

	validVSR := &conf_v1.VirtualServerRoute{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-vsr",
			Namespace: "test-ns",
		},
	}

	tests := []deleteFuncTestCase{
		{
			msg:         "typed VirtualServerRoute object",
			obj:         validVSR,
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping a valid VirtualServerRoute",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/test-vsr",
				Obj: validVSR,
			},
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping an unexpected type",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/some-pod",
				Obj: &api_v1.Pod{
					ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
				},
			},
			wantEnqueue: false,
		},
		{
			msg: "completely unexpected object type",
			obj: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
			},
			wantEnqueue: false,
		},
	}

	runDeleteFuncTests(t, tests, createVirtualServerRouteHandlers)
}

// TestCreateTransportServerHandlersDeleteFunc guards TransportServer's
// DeleteFunc, which -- unlike Ingress/VirtualServer/VirtualServerRoute at the
// time this test was written -- already resolves the object before building
// any log line, so it is not expected to panic. This test locks in that
// property.
func TestCreateTransportServerHandlersDeleteFunc(t *testing.T) {
	t.Parallel()

	validTS := &conf_v1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-ts",
			Namespace: "test-ns",
		},
	}

	tests := []deleteFuncTestCase{
		{
			msg:         "typed TransportServer object",
			obj:         validTS,
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping a valid TransportServer",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/test-ts",
				Obj: validTS,
			},
			wantEnqueue: true,
		},
		{
			msg: "DeletedFinalStateUnknown wrapping an unexpected type",
			obj: cache.DeletedFinalStateUnknown{
				Key: "test-ns/some-pod",
				Obj: &api_v1.Pod{
					ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
				},
			},
			wantEnqueue: false,
		},
		{
			msg: "completely unexpected object type",
			obj: &api_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{Name: "some-pod", Namespace: "test-ns"},
			},
			wantEnqueue: false,
		},
	}

	runDeleteFuncTests(t, tests, createTransportServerHandlers)
}
