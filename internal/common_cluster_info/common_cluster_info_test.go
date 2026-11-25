package commonclusterinfo

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func forbid(clientset *fake.Clientset, verb, resource string) {
	clientset.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource(resource), "", errors.New("access denied"))
	})
}

func fail(clientset *fake.Clientset, verb, resource string) {
	clientset.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(errors.New("etcd unavailable"))
	})
}

func TestGetClusterID(t *testing.T) {
	t.Parallel()

	clientset := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-uid")}})
	got, err := GetClusterID(context.Background(), clientset)
	if err != nil {
		t.Fatalf("GetClusterID() returned error: %v", err)
	}
	if got != "cluster-uid" {
		t.Errorf("GetClusterID() = %q, want %q", got, "cluster-uid")
	}
}

func TestGetNodeCount(t *testing.T) {
	t.Parallel()

	clientset := fake.NewClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}},
	)
	got, err := GetNodeCount(context.Background(), clientset)
	if err != nil {
		t.Fatalf("GetNodeCount() returned error: %v", err)
	}
	if got != 2 {
		t.Errorf("GetNodeCount() = %d, want 2", got)
	}
}

func TestClusterReadsNameMissingPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verb     string
		resource string
		read     func(*fake.Clientset) error
		want     string
	}{
		{
			name:     "cluster ID",
			verb:     "get",
			resource: "namespaces",
			read: func(c *fake.Clientset) error {
				_, err := GetClusterID(context.Background(), c)
				return err
			},
			want: `missing permission: get namespaces "kube-system" (cluster-scoped); grant it to the NIC ServiceAccount in a ClusterRole`,
		},
		{
			name:     "node count",
			verb:     "list",
			resource: "nodes",
			read: func(c *fake.Clientset) error {
				_, err := GetNodeCount(context.Background(), c)
				return err
			},
			want: "missing permission: list nodes (cluster-scoped); grant it to the NIC ServiceAccount in a ClusterRole",
		},
	}

	for _, test := range tests {
		t.Run(test.name+" forbidden", func(t *testing.T) {
			t.Parallel()

			clientset := fake.NewClientset()
			forbid(clientset, test.verb, test.resource)

			err := test.read(clientset)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), test.want)
			}
			if !apierrors.IsForbidden(err) {
				t.Errorf("error = %v, want it to wrap a forbidden error", err)
			}
		})

		t.Run(test.name+" other error unchanged", func(t *testing.T) {
			t.Parallel()

			clientset := fake.NewClientset()
			fail(clientset, test.verb, test.resource)

			err := test.read(clientset)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if strings.Contains(err.Error(), "missing permission") {
				t.Errorf("error = %q, want no missing permission prefix for a non-forbidden error", err.Error())
			}
		})
	}
}
