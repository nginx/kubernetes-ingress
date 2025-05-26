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

// Labels contains the metadata information needed for reporting to Agent v3
type Labels struct {
	ProductType           string `json:"product-type"`
	ProductVersion        string `json:"product-version"`
	ClusterID             string `json:"cluster-id"`
	InstallationName      string `json:"installation-name"`
	InstallationID        string `json:"installation-id"`
	InstallationNamespace string `json:"installation-namespace"`
}

func newMetadataInfo(installationNamespace, clusterID, installationID, productVersion, installationName string) *Labels {
	return &Labels{
		ProductType:           "nic",
		ProductVersion:        productVersion,
		ClusterID:             clusterID,
		InstallationID:        installationID,
		InstallationName:      installationName,
		InstallationNamespace: installationNamespace,
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
	installationNamespace := md.PodNSName.Namespace
	clusterID, err := clusterInfo.GetClusterID(ctx, md.K8sClientReader)
	if err != nil {
		return nil, fmt.Errorf("error collecting ClusterID: %w", err)
	}
	installationID, err := clusterInfo.GetInstallationID(ctx, md.K8sClientReader, md.PodNSName)
	if err != nil {
		return nil, fmt.Errorf("error collecting InstallationID: %w", err)
	}
	installationName, err := clusterInfo.GetInstallationName(ctx, md.K8sClientReader, md.PodNSName)
	if err != nil {
		return nil, fmt.Errorf("error collecting InstallationName: %w", err)
	}
	info := newMetadataInfo(installationNamespace, clusterID, installationID, md.NICVersion, installationName)
	return info, nil
}
