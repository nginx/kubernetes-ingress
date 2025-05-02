package licensereporting

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	"github.com/nginx/nginx-plus-go-client/v2/client"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

func TestNewLicenseInfo(t *testing.T) {
	info := newLicenseInfo("test-cluster", "test-installation", 5)

	if info.Integration != "nic" {
		t.Errorf("newLicenseInfo() Integration = %v, want %v", info.Integration, "nic")
	}
	if info.ClusterID != "test-cluster" {
		t.Errorf("newLicenseInfo() ClusterID = %v, want %v", info.ClusterID, "test-cluster")
	}
	if info.InstallationID != "test-installation" {
		t.Errorf("newLicenseInfo() InstallationID = %v, want %v", info.InstallationID, "test-installation")
	}
	if info.ClusterNodeCount != 5 {
		t.Errorf("newLicenseInfo() ClusterNodeCount = %v, want %v", info.ClusterNodeCount, 5)
	}
}

func TestWriteLicenseInfo(t *testing.T) {
	tempDir := t.TempDir()
	oldReportingDir := reportingDir
	reportingDir = tempDir
	defer func() { reportingDir = oldReportingDir }()

	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	info := newLicenseInfo("test-cluster", "test-installation", 5)
	writeLicenseInfo(l, info)

	filePath := filepath.Join(tempDir, reportingFile)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("Expected file %s to exist, but it doesn't", filePath)
	}

	/* #nosec G304 */
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	var readInfo licenseInfo
	err = json.Unmarshal(content, &readInfo)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if readInfo != *info {
		t.Errorf("Written info does not match original. Got %+v, want %+v", readInfo, *info)
	}
}

func TestNewLicenseReporter(t *testing.T) {
	reporter := NewLicenseReporter(fake.NewSimpleClientset(), record.NewFakeRecorder(2048), &v1.Pod{})
	if reporter == nil {
		t.Fatal("NewLicenseReporter() returned nil")
	}
}

func TestLicenseExpiring(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		licenseData            client.NginxLicense
		belowExpiringThreshold bool
		days                   int64
		name                   string
	}{
		{
			licenseData: client.NginxLicense{
				ActiveTill: uint64(time.Now().Add(time.Hour).Unix()), //nolint:gosec
			},
			belowExpiringThreshold: true,
			days:                   0,
			name:                   "License expires in 1 hour",
		},
		{
			licenseData: client.NginxLicense{
				ActiveTill: uint64(time.Now().Add(-time.Hour).Unix()), //nolint:gosec
			},
			belowExpiringThreshold: true,
			days:                   0,
			name:                   "License expired 1 hour ago",
		},
		{
			licenseData: client.NginxLicense{
				ActiveTill: uint64(time.Now().Add(time.Hour * 24 * 31).Unix()), //nolint:gosec
			},
			belowExpiringThreshold: false,
			days:                   30, // Rounds down
			name:                   "License expires in 31 days",
		},
	}

	for _, tc := range testCases {
		actualExpiring, actualDays := licenseExpiring(&tc.licenseData)
		if actualExpiring != tc.belowExpiringThreshold {
			t.Fatalf("%s: Expected different value for expiring %t", tc.name, tc.belowExpiringThreshold)
		}
		if actualDays != tc.days {
			t.Fatalf("%s: Expected different value for  days %d != %d", tc.name, actualDays, tc.days)
		}
	}
}

func TestUsageGraceEnding(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		licenseData            client.NginxLicense
		belowExpiringThreshold bool
		days                   int64
		name                   string
	}{
		{
			licenseData: client.NginxLicense{
				Reporting: client.LicenseReporting{
					Grace: 3600, // seconds
				},
			},
			belowExpiringThreshold: true,
			days:                   0,
			name:                   "Grace period ends in an hour",
		},
		{
			licenseData: client.NginxLicense{
				Reporting: client.LicenseReporting{
					Grace: 60 * 60 * 24 * 31, // 31 days
				},
			},
			belowExpiringThreshold: false,
			days:                   31,
			name:                   "Grace period ends 31 days",
		},
		{
			licenseData: client.NginxLicense{
				Reporting: client.LicenseReporting{
					Grace: 0,
				},
			},
			belowExpiringThreshold: true,
			days:                   0,
			name:                   "Grace period ended",
		},
	}

	for _, tc := range testCases {
		actualEnding, actualDays := usageGraceEnding(&tc.licenseData)
		if actualEnding != tc.belowExpiringThreshold {
			t.Fatalf("%s: Expected different value for expiring %t", tc.name, tc.belowExpiringThreshold)
		}
		if actualDays != tc.days {
			t.Fatalf("%s: Expected different value for  days %d != %d", tc.name, actualDays, tc.days)
		}
	}
}
