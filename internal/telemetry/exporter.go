package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"

	tel "github.com/nginx/telemetry-exporter/pkg/telemetry"
)

// Exporter interface for exporters.
type Exporter interface {
	Export(ctx context.Context, data tel.Exportable) error
}

// StdoutExporter represents a temporary telemetry data exporter.
type StdoutExporter struct {
	Endpoint io.Writer
}

// Export takes context and trace data and writes to the endpoint.
func (e *StdoutExporter) Export(_ context.Context, data tel.Exportable) error {
	_, err := fmt.Fprintf(e.Endpoint, "%+v", data)
	if err != nil {
		return err
	}
	return nil
}

// JSONExporter represents a temporary telemetry data exporter in JSON format.
type JSONExporter struct {
	Endpoint io.Writer
}

// Export takes context and trace data and marshals it and writes to the endpoint.
func (e *JSONExporter) Export(_ context.Context, data tel.Exportable) error {
	marshaledBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = e.Endpoint.Write(marshaledBytes)
	if err != nil {
		return err
	}
	return nil
}

// ExporterCfg is a configuration struct for an Exporter.
type ExporterCfg struct {
	Endpoint string
}

// NewExporter creates an Exporter with the provided ExporterCfg.
func NewExporter(cfg ExporterCfg) (Exporter, error) {
	providerOptions := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}

	exporter, err := tel.NewExporter(
		tel.ExporterConfig{
			SpanProvider: tel.CreateOTLPSpanProvider(providerOptions...),
		},
	)

	return exporter, err
}

// Data holds collected telemetry data.
//
//go:generate go run -tags=generator github.com/nginx/telemetry-exporter/cmd/generator -type Data -scheme -scheme-protocol=NICProductTelemetry -scheme-df-datatype=nic-product-telemetry -scheme-namespace=ingress.nginx.com
type Data struct {
	tel.Data
	NICResourceCounts
}

// NICResourceCounts holds a count of NIC specific resource.
//
//go:generate go run -tags=generator github.com/nginx/telemetry-exporter/cmd/generator -type NICResourceCounts
type NICResourceCounts struct {
	// VirtualServers is the number of VirtualServer resources managed by the Ingress Controller.
	VirtualServers int64
	// VirtualServerRoutes is the number of VirtualServerRoute resources managed by the Ingress Controller.
	VirtualServerRoutes int64
	// TransportServers is the number of TransportServer resources managed by the Ingress Controller.
	TransportServers int64
	// Replicas is the number of NIC replicas.
	Replicas int64
	// Secrets is the number of Secret resources managed by the Ingress Controller.
	Secrets int64
	// ClusterIPServices is the number of ClusterIP services managed by NGINX Ingress Controller.
	ClusterIPServices int64
	// NodePortServices is the number of NodePort services managed by NGINX Ingress Controller.
	NodePortServices int64
	// LoadBalancerServices is the number of LoadBalancer services managed by NGINX Ingress Controller.
	LoadBalancerServices int64
	// ExternalNameServices is the number of ExternalName services managed by NGINX Ingress Controller.
	ExternalNameServices int64
	// RegularIngressCount is the number of Regular Ingress resources managed by NGINX Ingress Controller.
	RegularIngressCount int64
	// MasterIngressCount is the number of Regular Ingress resources managed by NGINX Ingress Controller.
	MasterIngressCount int64
	// MinionIngressCount is the number of Regular Ingress resources managed by NGINX Ingress Controller.
	MinionIngressCount int64
	// IngressClasses is the number of Ingress Classes.
	IngressClasses int64
	// AccessControlPolicies is the number of AccessControl policies managed by NGINX Ingress Controller
	AccessControlPolicies int64
	// RateLimitPolicies is the number of RateLimit policies managed by NGINX Ingress Controller
	RateLimitPolicies int64
	// APIKeyPolicies is the number of APIKey policies managed by NGINX Ingress Controller
	APIKeyPolicies int64
	// JWTAuthPolicies is the number of JWTAuth policies managed by NGINX Ingress Controller
	JWTAuthPolicies int64
	// BasicAuthPolicies is the number of BasicAuth policies managed by NGINX Ingress Controller
	BasicAuthPolicies int64
	// IngressMTLSPolicies is the number of IngressMTLS policies managed by NGINX Ingress Controller
	IngressMTLSPolicies int64
	// EgressMTLSPolicies is the number of EgressMTLS policies managed by NGINX Ingress Controller
	EgressMTLSPolicies int64
	// OIDCPolicies is the number of OIDC policies managed by NGINX Ingress Controller
	OIDCPolicies int64
	// WAFPolicies is the number of WAF policies managed by NGINX Ingress Controller
	WAFPolicies int64
	// GlobalConfiguration indicates if a GlobalConfiguration resource is used.
	GlobalConfiguration bool
	// IngressAnnotations is the list of annotations resources managed by NGINX Ingress Controller
	IngressAnnotations []string
	// AppProtectVersion represents the version of AppProtect.
	AppProtectVersion string
	// IsPlus represents whether NGINX is Plus or OSS
	IsPlus bool
	// InstallationFlags is the list of command line arguments configured for NGINX Ingress Controller
	InstallationFlags []string
	// BuildOS represents the base operating system image
	BuildOS string
	// ConfigMapKeys is the list of keys for the main ConfigMaps
	ConfigMapKeys []string
	// MGMTConfigMapKeys is the list of keys for the MGMT ConfigMap
	MGMTConfigMapKeys []string
	// JWTRateLimitPolicies is the number of JWT Condition RateLimit policies managed by NGINX Ingress Controller
	JWTRateLimitPolicies int64
	// VariablesRateLimitPolicies is the number of Variables Condition RateLimit policies managed by NGINX Ingress Controller
	VariablesRateLimitPolicies int64
}
