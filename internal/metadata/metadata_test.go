package metadata

import (
	"context"
	"os"
	"testing"

	api_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewMetadataInfo(t *testing.T) {
	info := newMetadataInfo("nginx-ingress", "e3a5e702-65a7-a55f-753d78cd7ff7", "555-1222-4414test-11223355", "5.0.0", "my-release")
	if info.ProductType != "nic" {
		t.Errorf("ProductName = %q, want %q", info.ProductType, "nic")
	}
	if info.InstallationNamespace != "nginx-ingress" {
		t.Errorf("DeploymentNamespace = %q, want %q", info.InstallationNamespace, "nginx-ingress")
	}
	if info.ClusterID != "e3a5e702-65a7-a55f-753d78cd7ff7" {
		t.Errorf("ClusterID = %q, want %q", info.ClusterID, "e3a5e702-65a7-a55f-753d78cd7ff7")
	}
	if info.InstallationID != "555-1222-4414test-11223355" {
		t.Errorf("DeploymentID = %q, want %q", info.InstallationID, "555-1222-4414test-11223355")
	}
	if info.ProductVersion != "5.0.0" {
		t.Errorf("ProductVersion = %q, want %q", info.ProductVersion, "5.0.0")
	}
	if info.InstallationName != "my-release" {
		t.Errorf("DeploymentName = %q, want %q", info.InstallationName, "my-release")
	}
}

func TestCollectAndWrite(t *testing.T) {
	pod := &api_v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "DaemonSet",
					Name:       "test-pod",
					UID:        types.UID("install-123"),
				},
			},
		},
	}

	if err := os.Setenv("POD_NAMESPACE", pod.Namespace); err != nil {
		t.Errorf("unable to set POD_NAMESPACE: %v", err)
	}
	if err := os.Setenv("POD_NAME", pod.Name); err != nil {
		t.Errorf("unable to set POD_NAME: %v", err)
	}

	client := fake.NewSimpleClientset(
		&api_v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-system",
				UID:  types.UID("123-abc-456-def"),
			},
		},
		pod,
	)

	reporter := NewMetadataReporter(client, pod, "5.0.0")
	if reporter == nil {
		t.Fatal("expected reporter to be non-nil")
	}

	info, err := reporter.CollectAndWrite(context.TODO())
	if err != nil {
		t.Fatalf("CollectAndWrite() error = %v", err)
	}
	if got, want := info.ProductType, "nic"; got != want {
		t.Errorf("ProductType = %q, want %q", got, want)
	}
}

func TestNewMetadataReporter(t *testing.T) {
	reporter := NewMetadataReporter(
		fake.NewSimpleClientset(),
		&api_v1.Pod{},
		"5.0.0",
	)
	if reporter == nil {
		t.Fatal("Expected NewMetadataReporter to return non-nil")
	}
}
