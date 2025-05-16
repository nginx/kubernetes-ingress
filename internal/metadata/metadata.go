package metadata

import (
	"context"
	"fmt"
	"os"

	clusterInfo "github.com/nginx/kubernetes-ingress/internal/common_cluster_info"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Labels contains the metadata information needed for reporting to Agent
type Labels struct {
	ProductName         string `json:"product_name"`
	ProductVersion      string `json:"product_version"`
	ClusterID           string `json:"cluster_id"`
	DeploymentName      string `json:"deployment_name"`
	DeploymentID        string `json:"deployment_id"`
	DeploymentNamespace string `json:"deployment_namespace"`
}

func newMetadataInfo(deploymentNamespace, clusterID, deploymentID, productVersion, deploymentName string) *Labels {
	return &Labels{
		ProductName:         "nic",
		ProductVersion:      productVersion,
		ClusterID:           clusterID,
		DeploymentID:        deploymentID,
		DeploymentName:      deploymentName,
		DeploymentNamespace: deploymentNamespace,
	}
}

// Metadata contains required information for metadata reporting
type Metadata struct {
	K8sClientReader kubernetes.Interface
	PodNSName       types.NamespacedName
	Pod             *api_v1.Pod
	NICVersion      string
}

// NewMetadataReporter creates a new MetadataConfig
func NewMetadataReporter(client kubernetes.Interface, pod *api_v1.Pod, version string) *Metadata {
	return &Metadata{
		K8sClientReader: client,
		PodNSName:       types.NamespacedName{Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("POD_NAME")},
		Pod:             pod,
		NICVersion:      version,
	}
}

// CollectAndWrite collects the metadata information and returns a Labels struct
func (md *Metadata) CollectAndWrite(ctx context.Context) (*Labels, error) {
	deploymentNamespace := md.PodNSName.Namespace
	clusterID, err := clusterInfo.GetClusterID(ctx, md.K8sClientReader)
	if err != nil {
		return nil, fmt.Errorf("error collecting ClusterID: %w", err)
	}
	deploymentID, err := clusterInfo.GetInstallationID(ctx, md.K8sClientReader, md.PodNSName)
	if err != nil {
		return nil, fmt.Errorf("error collecting InstallationID: %w", err)
	}
	deploymentName, err := clusterInfo.GetDeploymentName(ctx, md.K8sClientReader, md.PodNSName)
	if err != nil {
		return nil, fmt.Errorf("error collecting DeploymentName: %w", err)
	}
	info := newMetadataInfo(deploymentNamespace, clusterID, deploymentID, md.NICVersion, deploymentName)
	return info, nil
}
