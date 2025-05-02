package licensereporting

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/nginx-plus-go-client/v2/client"

	clusterInfo "github.com/nginx/kubernetes-ingress/internal/common_cluster_info"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

const expiryThreshold = 30 * (time.Hour * 24)

var (
	reportingDir  = "/etc/nginx/reporting"
	reportingFile = "tracking.info"
)

type licenseInfo struct {
	Integration      string `json:"integration"`
	ClusterID        string `json:"cluster_id"`
	ClusterNodeCount int    `json:"cluster_node_count"`
	InstallationID   string `json:"installation_id"`
}

func newLicenseInfo(clusterID, installationID string, clusterNodeCount int) *licenseInfo {
	return &licenseInfo{
		Integration:      "nic",
		ClusterID:        clusterID,
		InstallationID:   installationID,
		ClusterNodeCount: clusterNodeCount,
	}
}

func writeLicenseInfo(l *slog.Logger, info *licenseInfo) {
	jsonData, err := json.Marshal(info)
	if err != nil {
		nl.Errorf(l, "failed to marshal LicenseInfo to JSON: %v", err)
		return
	}
	filePath := filepath.Join(reportingDir, reportingFile)
	if err := os.WriteFile(filePath, jsonData, 0o600); err != nil {
		nl.Errorf(l, "failed to write license reporting info to file: %v", err)
	}
}

// LicenseReporter can start the license reporting process
type LicenseReporter struct {
	Config LicenseReporterConfig
}

// LicenseReporterConfig contains the information needed for license reporting
type LicenseReporterConfig struct {
	Period          time.Duration
	K8sClientReader kubernetes.Interface
	PodNSName       types.NamespacedName
	EventLog        record.EventRecorder
	Pod             *api_v1.Pod
	PlusClient      *client.NginxClient
}

// NewLicenseReporter creates a new LicenseReporter
func NewLicenseReporter(client kubernetes.Interface, eventLog record.EventRecorder, pod *api_v1.Pod) *LicenseReporter {
	return &LicenseReporter{
		Config: LicenseReporterConfig{
			EventLog:        eventLog,
			Period:          time.Hour,
			K8sClientReader: client,
			PodNSName:       types.NamespacedName{Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("POD_NAME")},
			Pod:             pod,
		},
	}
}

// Start begins the license report writer process for NIC
func (lr *LicenseReporter) Start(ctx context.Context) {
	wait.JitterUntilWithContext(ctx, lr.collectAndWrite, lr.Config.Period, 0.1, true)
}

func (lr *LicenseReporter) collectAndWrite(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	clusterID, err := clusterInfo.GetClusterID(ctx, lr.Config.K8sClientReader)
	if err != nil {
		nl.Errorf(l, "Error collecting ClusterIDS: %v", err)
	}
	nodeCount, err := clusterInfo.GetNodeCount(ctx, lr.Config.K8sClientReader)
	if err != nil {
		nl.Errorf(l, "Error collecting ClusterNodeCount: %v", err)
	}
	installationID, err := clusterInfo.GetInstallationID(ctx, lr.Config.K8sClientReader, lr.Config.PodNSName)
	if err != nil {
		nl.Errorf(l, "Error collecting InstallationID: %v", err)
	}
	info := newLicenseInfo(clusterID, installationID, nodeCount)
	writeLicenseInfo(l, info)
	if lr.Config.PlusClient != nil {
		lr.checkLicenseExpiry(ctx)
	}
}

func (lr *LicenseReporter) checkLicenseExpiry(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	licenseData, err := lr.Config.PlusClient.GetNginxLicense(context.Background())
	if err != nil {
		nl.Errorf(l, "could not get license data, %v", err)
		return
	}
	var licenseEventText string
	if expiring, days := licenseExpiring(licenseData); expiring {
		licenseEventText = fmt.Sprintf("License expiring in %d day(s)", days)
		nl.Warn(l, licenseEventText)
		lr.Config.EventLog.Event(lr.Config.Pod, api_v1.EventTypeWarning, nl.EventReasonLicenseExpiry, licenseEventText)
	}
	var usageGraceEventText string
	if ending, days := usageGraceEnding(licenseData); ending {
		usageGraceEventText = fmt.Sprintf("Usage reporting grace period ending in %d day(s)", days)
		nl.Warn(l, usageGraceEventText)
		lr.Config.EventLog.Event(lr.Config.Pod, api_v1.EventTypeWarning, nl.EventReasonUsageGraceEnding, usageGraceEventText)
	}
}

func licenseExpiring(licenseData *client.NginxLicense) (bool, int64) {
	expiry := time.Unix(int64(licenseData.ActiveTill), 0) //nolint:gosec
	now := time.Now()
	timeUntilLicenseExpiry := expiry.Sub(now)
	daysUntilLicenseExpiry := int64(timeUntilLicenseExpiry.Hours() / 24)
	expiryDays := int64(expiryThreshold.Hours() / 24)
	return daysUntilLicenseExpiry < expiryDays, daysUntilLicenseExpiry
}

func usageGraceEnding(licenseData *client.NginxLicense) (bool, int64) {
	grace := time.Second * time.Duration(licenseData.Reporting.Grace) //nolint:gosec
	daysUntilUsageGraceEnds := int64(grace.Hours() / 24)
	expiryDays := int64(expiryThreshold.Hours() / 24)
	return daysUntilUsageGraceEnds < expiryDays, daysUntilUsageGraceEnds
}
