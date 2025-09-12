package telemetry

/*
This is a generated file. DO NOT EDIT.
*/

import (
	"go.opentelemetry.io/otel/attribute"

	ngxTelemetry "github.com/nginx/telemetry-exporter/pkg/telemetry"
)

func (d *NICResourceCounts) Attributes() []attribute.KeyValue {
	var attrs []attribute.KeyValue
	attrs = append(attrs, attribute.Int64("VirtualServers", d.VirtualServers))
	attrs = append(attrs, attribute.Int64("VirtualServerRoutes", d.VirtualServerRoutes))
	attrs = append(attrs, attribute.Int64("TransportServers", d.TransportServers))
	attrs = append(attrs, attribute.Int64("Replicas", d.Replicas))
	attrs = append(attrs, attribute.Int64("Secrets", d.Secrets))
	attrs = append(attrs, attribute.Int64("ClusterIPServices", d.ClusterIPServices))
	attrs = append(attrs, attribute.Int64("NodePortServices", d.NodePortServices))
	attrs = append(attrs, attribute.Int64("LoadBalancerServices", d.LoadBalancerServices))
	attrs = append(attrs, attribute.Int64("ExternalNameServices", d.ExternalNameServices))
	attrs = append(attrs, attribute.Int64("RegularIngressCount", d.RegularIngressCount))
	attrs = append(attrs, attribute.Int64("MasterIngressCount", d.MasterIngressCount))
	attrs = append(attrs, attribute.Int64("MinionIngressCount", d.MinionIngressCount))
	attrs = append(attrs, attribute.Int64("IngressClasses", d.IngressClasses))
	attrs = append(attrs, attribute.Int64("AccessControlPolicies", d.AccessControlPolicies))
	attrs = append(attrs, attribute.Int64("RateLimitPolicies", d.RateLimitPolicies))
	attrs = append(attrs, attribute.Int64("APIKeyPolicies", d.APIKeyPolicies))
	attrs = append(attrs, attribute.Int64("JWTAuthPolicies", d.JWTAuthPolicies))
	attrs = append(attrs, attribute.Int64("BasicAuthPolicies", d.BasicAuthPolicies))
	attrs = append(attrs, attribute.Int64("IngressMTLSPolicies", d.IngressMTLSPolicies))
	attrs = append(attrs, attribute.Int64("EgressMTLSPolicies", d.EgressMTLSPolicies))
	attrs = append(attrs, attribute.Int64("OIDCPolicies", d.OIDCPolicies))
	attrs = append(attrs, attribute.Int64("WAFPolicies", d.WAFPolicies))
	attrs = append(attrs, attribute.Bool("GlobalConfiguration", d.GlobalConfiguration))
	attrs = append(attrs, attribute.StringSlice("IngressAnnotations", d.IngressAnnotations))
	attrs = append(attrs, attribute.String("AppProtectVersion", d.AppProtectVersion))
	attrs = append(attrs, attribute.Bool("IsPlus", d.IsPlus))
	attrs = append(attrs, attribute.StringSlice("InstallationFlags", d.InstallationFlags))
	attrs = append(attrs, attribute.String("BuildOS", d.BuildOS))
	attrs = append(attrs, attribute.StringSlice("ConfigMapKeys", d.ConfigMapKeys))
	attrs = append(attrs, attribute.StringSlice("MGMTConfigMapKeys", d.MGMTConfigMapKeys))
	attrs = append(attrs, attribute.Int64("JWTRateLimitPolicies", d.JWTRateLimitPolicies))
	attrs = append(attrs, attribute.Int64("VariablesRateLimitPolicies", d.VariablesRateLimitPolicies))
	attrs = append(attrs, attribute.Int64("CachePolicies", d.CachePolicies))

	return attrs
}

var _ ngxTelemetry.Exportable = (*NICResourceCounts)(nil)
