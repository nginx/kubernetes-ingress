// Package telemetry provides functionality for collecting and exporting NIC telemetry data.
package telemetry

import (
	"context"
	"io"
	"runtime"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"

	tel "github.com/nginx/telemetry-exporter/pkg/telemetry"

	"github.com/nginx/kubernetes-ingress/internal/configs"

	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Option is a functional option used for configuring TraceReporter.
type Option func(*Collector) error

// WithExporter configures telemetry collector to use given exporter.
//
// This may change in the future when we use exporter implemented
// in the external module.
func WithExporter(e Exporter) Option {
	return func(c *Collector) error {
		c.Exporter = e
		return nil
	}
}

// Collector is NIC telemetry data collector.
type Collector struct {
	// Exporter is a temp exporter for exporting telemetry data.
	// The concrete implementation will be implemented in a separate module.
	Exporter Exporter

	// Configuration for the collector.
	Config CollectorConfig
}

// CollectorConfig contains configuration options for a Collector
type CollectorConfig struct {
	// Period to collect telemetry
	Period time.Duration

	// K8sClientReader is a kubernetes client.
	K8sClientReader kubernetes.Interface

	// Version represents NIC version.
	Version string

	// GlobalConfiguration represents the use of a GlobalConfiguration resource.
	GlobalConfiguration bool

	// Configurator is a struct for configuring NGINX.
	Configurator *configs.Configurator

	// SecretStore for access to secrets managed by NIC.
	SecretStore secrets.SecretStore

	// PodNSName represents NIC Pod's NamespacedName.
	PodNSName types.NamespacedName

	// Policies gets all policies
	Policies func() []*conf_v1.Policy

	// AppProtectVersion represents the version of App Protect.
	AppProtectVersion string

	// BuildOS represents the base operating system image
	BuildOS string

	// IsPlus represents whether NGINX is Plus or OSS
	IsPlus bool

	// InstallationFlags represents the list of set flags managed by NIC
	InstallationFlags []string

	// MainConfigMap represents the main ConfigMap managed by NIC.
	MainConfigMap *api_v1.ConfigMap
	// MainConfigMapName represents the name of the main ConfigMap.
	MainConfigMapName string

	// MGMTConfigMap represents the mgmt ConfigMap managed by NIC.
	MGMTConfigMap *api_v1.ConfigMap
	// MGMTConfigMapName represents the name of the MGMT ConfigMap.
	MGMTConfigMapName string

	// Indicates if using of Custom Resources is enabled.
	CustomResourcesEnabled bool
}

// NewCollector takes 0 or more options and creates a new TraceReporter.
// If no options are provided, NewReporter returns TraceReporter
// configured to gather data every 24h.
func NewCollector(cfg CollectorConfig, opts ...Option) (*Collector, error) {
	c := Collector{
		Exporter: &StdoutExporter{Endpoint: io.Discard},
		Config:   cfg,
	}
	for _, o := range opts {
		if err := o(&c); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// Start starts running NIC Telemetry Collector.
func (c *Collector) Start(ctx context.Context) {
	wait.JitterUntilWithContext(ctx, c.Collect, c.Config.Period, 0.1, true)
}

// Collect collects and exports telemetry data.
// It exports data using provided exporter.
func (c *Collector) Collect(ctx context.Context) {
	l := nl.LoggerFromContext(c.Config.Configurator.CfgParams.Context)
	nl.Debug(l, "Collecting telemetry data")
	report, err := c.BuildReport(ctx)
	if err != nil {
		nl.Errorf(l, "Error collecting telemetry data: %v", err)
	}

	nicData := Data{
		tel.Data{
			ProjectName:         report.Name,
			ProjectVersion:      c.Config.Version,
			ProjectArchitecture: runtime.GOARCH,
			ClusterID:           report.ClusterID,
			ClusterVersion:      report.ClusterVersion,
			ClusterPlatform:     report.ClusterPlatform,
			InstallationID:      report.InstallationID,
			ClusterNodeCount:    int64(report.ClusterNodeCount),
		},
		NICResourceCounts{
			VirtualServers:             int64(report.VirtualServers),
			VirtualServerRoutes:        int64(report.VirtualServerRoutes),
			TransportServers:           int64(report.TransportServers),
			Replicas:                   int64(report.NICReplicaCount),
			Secrets:                    int64(report.Secrets),
			ClusterIPServices:          int64(report.ClusterIPServices),
			NodePortServices:           int64(report.NodePortServices),
			LoadBalancerServices:       int64(report.LoadBalancerServices),
			ExternalNameServices:       int64(report.ExternalNameServices),
			RegularIngressCount:        int64(report.RegularIngressCount),
			MasterIngressCount:         int64(report.MasterIngressCount),
			MinionIngressCount:         int64(report.MinionIngressCount),
			IngressClasses:             int64(report.IngressClassCount),
			AccessControlPolicies:      int64(report.AccessControlCount),
			RateLimitPolicies:          int64(report.RateLimitCount),
			JWTRateLimitPolicies:       int64(report.RateLimitJWTCount),
			VariablesRateLimitPolicies: int64(report.RateLimitVariablesCount),
			APIKeyPolicies:             int64(report.APIKeyAuthCount),
			JWTAuthPolicies:            int64(report.JWTAuthCount),
			BasicAuthPolicies:          int64(report.BasicAuthCount),
			IngressMTLSPolicies:        int64(report.IngressMTLSCount),
			EgressMTLSPolicies:         int64(report.EgressMTLSCount),
			OIDCPolicies:               int64(report.OIDCCount),
			WAFPolicies:                int64(report.WAFCount),
			CachePolicies:              int64(report.CacheCount),
			GlobalConfiguration:        report.GlobalConfiguration,
			IngressAnnotations:         report.IngressAnnotations,
			AppProtectVersion:          report.AppProtectVersion,
			IsPlus:                     report.IsPlus,
			InstallationFlags:          report.InstallationFlags,
			BuildOS:                    report.BuildOS,
			ConfigMapKeys:              report.MainConfigMapKeys,
			MGMTConfigMapKeys:          report.MGMTConfigMapKeys,
		},
	}

	err = c.Exporter.Export(ctx, &nicData)
	if err != nil {
		nl.Errorf(l, "Error exporting telemetry data: %v", err)
	}
	nl.Debugf(l, "Telemetry data collected: %+v", nicData)
}

// Report holds collected NIC telemetry data. It is the package internal
// data structure used for decoupling types between the NIC `telemetry`
// package and the imported `telemetry` exporter.
type Report struct {
	Name                    string
	Version                 string
	Architecture            string
	ClusterID               string
	ClusterVersion          string
	ClusterPlatform         string
	ClusterNodeCount        int
	InstallationID          string
	NICReplicaCount         int
	VirtualServers          int
	VirtualServerRoutes     int
	ClusterIPServices       int
	NodePortServices        int
	LoadBalancerServices    int
	ExternalNameServices    int
	TransportServers        int
	Secrets                 int
	RegularIngressCount     int
	MasterIngressCount      int
	MinionIngressCount      int
	IngressClassCount       int
	AccessControlCount      int
	RateLimitCount          int
	RateLimitJWTCount       int
	RateLimitVariablesCount int
	JWTAuthCount            int
	APIKeyAuthCount         int
	BasicAuthCount          int
	IngressMTLSCount        int
	EgressMTLSCount         int
	OIDCCount               int
	WAFCount                int
	CacheCount              int
	GlobalConfiguration     bool
	IngressAnnotations      []string
	AppProtectVersion       string
	IsPlus                  bool
	InstallationFlags       []string
	BuildOS                 string
	MainConfigMapKeys       []string
	MGMTConfigMapKeys       []string
}

// BuildReport takes context, collects telemetry data and builds the report.
func (c *Collector) BuildReport(ctx context.Context) (Report, error) {
	l := nl.LoggerFromContext(c.Config.Configurator.CfgParams.Context)
	vsCount := 0
	vsrCount := 0
	tsCount := 0

	// Collect Custom Resources only if CR enabled at startup.
	if c.Config.Configurator != nil && c.Config.CustomResourcesEnabled {
		vsCount, vsrCount = c.Config.Configurator.GetVirtualServerCounts()
		tsCount = c.Config.Configurator.GetTransportServerCounts()
	}

	clusterID, err := c.ClusterID(ctx)
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: ClusterID: %v", err)
	}

	nodes, err := c.NodeCount(ctx)
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: Nodes: %v", err)
	}

	version, err := c.ClusterVersion()
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: K8s Version: %v", err)
	}

	platform, err := c.Platform(ctx)
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: Platform: %v", err)
	}

	replicas, err := c.ReplicaCount(ctx)
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: Replicas: %v", err)
	}

	installationID, err := c.InstallationID(ctx)
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: InstallationID: %v", err)
	}

	secretCount, err := c.Secrets()
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: Secrets: %v", err)
	}

	regularIngressCount := c.RegularIngressCount()
	masterIngressCount := c.MasterIngressCount()
	minionIngressCount := c.MinionIngressCount()
	ingressClassCount, err := c.IngressClassCount(ctx)
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: Ingress Classes: %v", err)
	}

	var (
		accessControlCount      int
		rateLimitCount          int
		rateLimitJWTCount       int
		rateLimitVariablesCount int
		apiKeyCount             int
		jwtAuthCount            int
		basicAuthCount          int
		ingressMTLSCount        int
		egressMTLSCount         int
		oidcCount               int
		wafCount                int
		cacheCount              int
	)
	// Collect Custom Resources (Policies) only if CR enabled at startup.
	if c.Config.CustomResourcesEnabled {
		policies := c.PolicyCount()
		accessControlCount = policies["AccessControl"]
		rateLimitCount = policies["RateLimit"]
		rateLimitJWTCount = policies["RateLimitJWT"]
		rateLimitVariablesCount = policies["RateLimitVariables"]
		apiKeyCount = policies["APIKey"]
		jwtAuthCount = policies["JWTAuth"]
		basicAuthCount = policies["BasicAuth"]
		ingressMTLSCount = policies["IngressMTLS"]
		egressMTLSCount = policies["EgressMTLS"]
		oidcCount = policies["OIDC"]
		wafCount = policies["WAF"]
		cacheCount = policies["Cache"]
	}

	ingressAnnotations := c.IngressAnnotations()
	appProtectVersion := c.AppProtectVersion()
	isPlus := c.IsPlusEnabled()
	installationFlags := c.InstallationFlags()
	serviceCounts, err := c.ServiceCounts()
	if err != nil {
		nl.Debugf(l, "Unable to collect telemetry data: Service Counts: %v", err)
	}
	clusterIPServices := serviceCounts["ClusterIP"]
	nodePortServices := serviceCounts["NodePort"]
	loadBalancerServices := serviceCounts["LoadBalancer"]
	externalNameServices := serviceCounts["ExternalName"]

	configMapKeys, err := c.ConfigMapKeys(ctx)
	if err != nil {
		nl.Debugf(l, "Error fetching main ConfigMap keys: %v", err)
		configMapKeys = []string{}
	}
	var mgmtConfigMapKeys []string
	if isPlus {
		mgmtConfigMapKeys, err = c.MGMTConfigMapKeys(ctx)
		if err != nil {
			nl.Debugf(l, "Error fetching MGMT ConfigMap keys: %v", err)
			mgmtConfigMapKeys = []string{}
		}
	}

	return Report{
		Name:                    "NIC",
		Version:                 c.Config.Version,
		Architecture:            runtime.GOARCH,
		ClusterID:               clusterID,
		ClusterVersion:          version,
		ClusterPlatform:         platform,
		ClusterNodeCount:        nodes,
		InstallationID:          installationID,
		NICReplicaCount:         replicas,
		VirtualServers:          vsCount,
		VirtualServerRoutes:     vsrCount,
		ClusterIPServices:       clusterIPServices,
		NodePortServices:        nodePortServices,
		LoadBalancerServices:    loadBalancerServices,
		ExternalNameServices:    externalNameServices,
		TransportServers:        tsCount,
		Secrets:                 secretCount,
		RegularIngressCount:     regularIngressCount,
		MasterIngressCount:      masterIngressCount,
		MinionIngressCount:      minionIngressCount,
		IngressClassCount:       ingressClassCount,
		AccessControlCount:      accessControlCount,
		RateLimitCount:          rateLimitCount,
		RateLimitJWTCount:       rateLimitJWTCount,
		RateLimitVariablesCount: rateLimitVariablesCount,
		APIKeyAuthCount:         apiKeyCount,
		JWTAuthCount:            jwtAuthCount,
		BasicAuthCount:          basicAuthCount,
		IngressMTLSCount:        ingressMTLSCount,
		EgressMTLSCount:         egressMTLSCount,
		OIDCCount:               oidcCount,
		WAFCount:                wafCount,
		CacheCount:              cacheCount,
		GlobalConfiguration:     c.Config.GlobalConfiguration,
		IngressAnnotations:      ingressAnnotations,
		AppProtectVersion:       appProtectVersion,
		IsPlus:                  isPlus,
		InstallationFlags:       installationFlags,
		BuildOS:                 c.BuildOS(),
		MainConfigMapKeys:       configMapKeys,
		MGMTConfigMapKeys:       mgmtConfigMapKeys,
	}, err
}
