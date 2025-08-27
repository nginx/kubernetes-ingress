package configs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"

	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginx/nginx-prometheus-exporter/collector"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"

	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	latCollector "github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
)

const (
	pemFileNameForWildcardTLSSecret = "/etc/nginx/secrets/wildcard" // #nosec G101
	appProtectPolicyFolder          = "/etc/nginx/waf/nac-policies/"
	appProtectLogConfFolder         = "/etc/nginx/waf/nac-logconfs/"
	appProtectUserSigFolder         = "/etc/nginx/waf/nac-usersigs/"
	appProtectUserSigIndex          = "/etc/nginx/waf/nac-usersigs/index.conf"
	appProtectDosPolicyFolder       = "/etc/nginx/dos/policies/"
	appProtectDosLogConfFolder      = "/etc/nginx/dos/logconfs/"
	appProtectDosAllowListFolder    = "/etc/nginx/dos/allowlist/"
)

// DefaultServerSecretPath is the full path to the Secret with a TLS cert and a key for the default server. #nosec G101
const DefaultServerSecretPath = "/etc/nginx/secrets/default" //nolint:gosec // G101: Potential hardcoded credentials - false positive

// DefaultSecretPath is the full default path to where secrets are stored and accessed.
const DefaultSecretPath = "/etc/nginx/secrets" // #nosec G101

// DefaultServerSecretFileName is the filename of the Secret with a TLS cert and a key for the default server.
const DefaultServerSecretFileName = "default"

// WildcardSecretFileName is the filename of the Secret with a TLS cert and a key for the ingress resources with TLS termination enabled but not secret defined.
const WildcardSecretFileName = "wildcard"

// LicenseSecretFileName is the filename of the Secret for the NGINX PLUS License
const LicenseSecretFileName = "license.jwt"

// ClientAuthCertSecretFileName is the filename of the Secret with a TLS cert and a key for the MGMT block for client authentication certificates.
const ClientAuthCertSecretFileName = "client"

// JWTKeyKey is the key of the data field of a Secret where the JWK must be stored.
const JWTKeyKey = "jwk"

// HtpasswdFileKey is the key of the data field of a Secret where the HTTP basic authorization list must be stored
const HtpasswdFileKey = "htpasswd"

// CACrtKey is the key of the data field of a Secret where the cert must be stored.
const CACrtKey = "ca.crt"

// CACrlKey is the key of the data field of a Secret where the cert revocation list must be stored.
const CACrlKey = "ca.crl"

// ClientSecretKey is the key of the data field of a Secret where the OIDC client secret must be stored.
const ClientSecretKey = "client-secret"

// SPIFFE filenames and modes
const (
	spiffeCertFileName   = "spiffe_cert.pem"
	spiffeKeyFileName    = "spiffe_key.pem"
	spiffeBundleFileName = "spiffe_rootca.pem"
	spiffeCertsFileMode  = os.FileMode(0o644)
	spiffeKeyFileMode    = os.FileMode(0o600)
)

// ExtendedResources holds all extended configuration resources, for which Configurator configures NGINX.
type ExtendedResources struct {
	IngressExes         []*IngressEx
	MergeableIngresses  []*MergeableIngresses
	VirtualServerExes   []*VirtualServerEx
	TransportServerExes []*TransportServerEx
}

// WeightUpdate holds the information about the weight updates for weight changes without reloading.
type WeightUpdate struct {
	Zone  string
	Key   string
	Value string
}

type tlsPassthroughPair struct {
	Host       string
	UnixSocket string
}

// metricLabelsIndex keeps the relations between Ingress Controller resources and NGINX configuration.
// Used to be able to add Prometheus Metrics variable labels grouped by resource key.
type metricLabelsIndex struct {
	ingressUpstreams             map[string][]string
	virtualServerUpstreams       map[string][]string
	transportServerUpstreams     map[string][]string
	ingressServerZones           map[string][]string
	virtualServerServerZones     map[string][]string
	transportServerServerZones   map[string][]string
	ingressUpstreamPeers         map[string][]string
	virtualServerUpstreamPeers   map[string][]string
	transportServerUpstreamPeers map[string][]string
}

// Configurator configures NGINX.
// Until reloads are enabled via EnableReloads(), the Configurator will not reload NGINX and update NGINX Plus
// upstream servers via NGINX Plus API for configuration changes.
// This allows the Ingress Controller to incrementally build the NGINX configuration during the IC start and
// then apply it at the end of the start.
type Configurator struct {
	nginxManager              nginx.Manager
	staticCfgParams           *StaticConfigParams
	CfgParams                 *ConfigParams
	MgmtCfgParams             *MGMTConfigParams
	templateExecutor          *version1.TemplateExecutor
	templateExecutorV2        *version2.TemplateExecutor
	ingresses                 map[string]*IngressEx
	minions                   map[string]map[string]bool
	mergeableIngresses        map[string]*MergeableIngresses
	virtualServers            map[string]*VirtualServerEx
	transportServers          map[string]*TransportServerEx
	tlsPassthroughPairs       map[string]tlsPassthroughPair
	isWildcardEnabled         bool
	isPlus                    bool
	labelUpdater              collector.LabelUpdater
	metricLabelsIndex         *metricLabelsIndex
	isPrometheusEnabled       bool
	latencyCollector          latCollector.LatencyCollector
	isLatencyMetricsEnabled   bool
	isReloadsEnabled          bool
	isDynamicSSLReloadEnabled bool
	ingressControllerReplicas int
}

// ConfiguratorParams is a collection of parameters used for the
// NewConfigurator() function
type ConfiguratorParams struct {
	NginxManager                        nginx.Manager
	StaticCfgParams                     *StaticConfigParams
	Config                              *ConfigParams
	MGMTCfgParams                       *MGMTConfigParams
	TemplateExecutor                    *version1.TemplateExecutor
	TemplateExecutorV2                  *version2.TemplateExecutor
	LabelUpdater                        collector.LabelUpdater
	LatencyCollector                    latCollector.LatencyCollector
	IsPlus                              bool
	IsPrometheusEnabled                 bool
	IsWildcardEnabled                   bool
	IsLatencyMetricsEnabled             bool
	IsDynamicSSLReloadEnabled           bool
	IsDynamicWeightChangesReloadEnabled bool
	NginxVersion                        nginx.Version
}

// NewConfigurator creates a new Configurator.
func NewConfigurator(p ConfiguratorParams) *Configurator {
	metricLabelsIndex := &metricLabelsIndex{
		ingressUpstreams:             make(map[string][]string),
		virtualServerUpstreams:       make(map[string][]string),
		transportServerUpstreams:     make(map[string][]string),
		ingressServerZones:           make(map[string][]string),
		virtualServerServerZones:     make(map[string][]string),
		transportServerServerZones:   make(map[string][]string),
		ingressUpstreamPeers:         make(map[string][]string),
		virtualServerUpstreamPeers:   make(map[string][]string),
		transportServerUpstreamPeers: make(map[string][]string),
	}

	cnf := Configurator{
		nginxManager:              p.NginxManager,
		staticCfgParams:           p.StaticCfgParams,
		CfgParams:                 p.Config,
		MgmtCfgParams:             p.MGMTCfgParams,
		ingresses:                 make(map[string]*IngressEx),
		virtualServers:            make(map[string]*VirtualServerEx),
		transportServers:          make(map[string]*TransportServerEx),
		templateExecutor:          p.TemplateExecutor,
		templateExecutorV2:        p.TemplateExecutorV2,
		minions:                   make(map[string]map[string]bool),
		mergeableIngresses:        make(map[string]*MergeableIngresses),
		tlsPassthroughPairs:       make(map[string]tlsPassthroughPair),
		isPlus:                    p.IsPlus,
		isWildcardEnabled:         p.IsWildcardEnabled,
		labelUpdater:              p.LabelUpdater,
		metricLabelsIndex:         metricLabelsIndex,
		isPrometheusEnabled:       p.IsPrometheusEnabled,
		latencyCollector:          p.LatencyCollector,
		isLatencyMetricsEnabled:   p.IsLatencyMetricsEnabled,
		isDynamicSSLReloadEnabled: p.IsDynamicSSLReloadEnabled,
		isReloadsEnabled:          false,
	}
	return &cnf
}

// AddOrUpdateDHParam creates a dhparam file with the content of the string.
func (cnf *Configurator) AddOrUpdateDHParam(content string) (string, error) {
	return cnf.nginxManager.CreateDHParam(content)
}

func findRemovedKeys(currentKeys []string, newKeys map[string]bool) []string {
	var removedKeys []string
	for _, name := range currentKeys {
		if _, exists := newKeys[name]; !exists {
			removedKeys = append(removedKeys, name)
		}
	}
	return removedKeys
}

func (cnf *Configurator) updateIngressMetricsLabels(ingEx *IngressEx, upstreams []version1.Upstream) {
	upstreamServerLabels := make(map[string][]string)
	newUpstreams := make(map[string]bool)
	var newUpstreamsNames []string

	upstreamServerPeerLabels := make(map[string][]string)
	newPeers := make(map[string]bool)
	var newPeersIPs []string

	for _, u := range upstreams {
		upstreamServerLabels[u.Name] = []string{u.UpstreamLabels.Service, u.UpstreamLabels.ResourceType, u.UpstreamLabels.ResourceName, u.UpstreamLabels.ResourceNamespace}
		newUpstreams[u.Name] = true
		newUpstreamsNames = append(newUpstreamsNames, u.Name)
		for _, server := range u.UpstreamServers {
			podInfo := ingEx.PodsByIP[server.Address]
			labelKey := fmt.Sprintf("%v/%v", u.Name, server.Address)
			upstreamServerPeerLabels[labelKey] = []string{podInfo.Name}
			if cnf.staticCfgParams.NginxServiceMesh {
				ownerLabelVal := fmt.Sprintf("%s/%s", podInfo.OwnerType, podInfo.OwnerName)
				upstreamServerPeerLabels[labelKey] = append(upstreamServerPeerLabels[labelKey], ownerLabelVal)
			}
			newPeers[labelKey] = true
			newPeersIPs = append(newPeersIPs, labelKey)
		}
	}

	key := fmt.Sprintf("%v/%v", ingEx.Ingress.Namespace, ingEx.Ingress.Name)
	removedUpstreams := findRemovedKeys(cnf.metricLabelsIndex.ingressUpstreams[key], newUpstreams)
	cnf.metricLabelsIndex.ingressUpstreams[key] = newUpstreamsNames
	cnf.latencyCollector.UpdateUpstreamServerLabels(upstreamServerLabels)
	cnf.latencyCollector.DeleteUpstreamServerLabels(removedUpstreams)

	removedPeers := findRemovedKeys(cnf.metricLabelsIndex.ingressUpstreamPeers[key], newPeers)
	cnf.metricLabelsIndex.ingressUpstreamPeers[key] = newPeersIPs
	cnf.latencyCollector.UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels)
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(removedPeers)
	cnf.latencyCollector.DeleteMetrics(removedPeers)

	if cnf.isPlus {
		cnf.labelUpdater.UpdateUpstreamServerLabels(upstreamServerLabels)
		cnf.labelUpdater.DeleteUpstreamServerLabels(removedUpstreams)
		cnf.labelUpdater.UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels)
		cnf.labelUpdater.DeleteUpstreamServerPeerLabels(removedPeers)
		serverZoneLabels := make(map[string][]string)
		newZones := make(map[string]bool)
		var newZonesNames []string
		for _, rule := range ingEx.Ingress.Spec.Rules {
			serverZoneLabels[rule.Host] = []string{"ingress", ingEx.Ingress.Name, ingEx.Ingress.Namespace}
			newZones[rule.Host] = true
			newZonesNames = append(newZonesNames, rule.Host)
		}

		removedZones := findRemovedKeys(cnf.metricLabelsIndex.ingressServerZones[key], newZones)
		cnf.metricLabelsIndex.ingressServerZones[key] = newZonesNames
		cnf.labelUpdater.UpdateServerZoneLabels(serverZoneLabels)
		cnf.labelUpdater.DeleteServerZoneLabels(removedZones)
	}
}

func (cnf *Configurator) deleteIngressMetricsLabels(key string) {
	cnf.latencyCollector.DeleteUpstreamServerLabels(cnf.metricLabelsIndex.ingressUpstreams[key])
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(cnf.metricLabelsIndex.ingressUpstreamPeers[key])
	cnf.latencyCollector.DeleteMetrics(cnf.metricLabelsIndex.ingressUpstreamPeers[key])

	if cnf.isPlus {
		cnf.labelUpdater.DeleteUpstreamServerLabels(cnf.metricLabelsIndex.ingressUpstreams[key])
		cnf.labelUpdater.DeleteServerZoneLabels(cnf.metricLabelsIndex.ingressServerZones[key])
		cnf.labelUpdater.DeleteUpstreamServerPeerLabels(cnf.metricLabelsIndex.ingressUpstreamPeers[key])
	}

	delete(cnf.metricLabelsIndex.ingressUpstreams, key)
	delete(cnf.metricLabelsIndex.ingressServerZones, key)
	delete(cnf.metricLabelsIndex.ingressUpstreamPeers, key)
}

// AddOrUpdateIngress adds or updates NGINX configuration for the Ingress resource.
func (cnf *Configurator) AddOrUpdateIngress(ingEx *IngressEx) (Warnings, error) {
	_, warnings, err := cnf.addOrUpdateIngress(ingEx)
	if err != nil {
		return warnings, fmt.Errorf("error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("error reloading NGINX for %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
	}

	return warnings, nil
}

// virtualServerExForHost takes a hostname and returns a VirtualServerEx for the given hostname.
func (cnf *Configurator) virtualServerExForHost(hostname string) *VirtualServerEx {
	for _, vsEx := range cnf.virtualServers {
		if vsEx.VirtualServer.Spec.Host == hostname {
			return vsEx
		}
	}
	return nil
}

// upstreamsForVirtualServer takes a VirtualServerEx and returns a list of associated upstreams.
func (cnf *Configurator) upstreamsForVirtualServer(vsEx *VirtualServerEx) []string {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	vs := vsEx.VirtualServer
	var upstreamNames []string

	nl.Debugf(l, "Get upstreamName for vs: %s", vs.Spec.Host)

	virtualServerUpstreamNamer := NewUpstreamNamerForVirtualServer(vs)

	for _, u := range vs.Spec.Upstreams {
		upstreamName := virtualServerUpstreamNamer.GetNameForUpstream(u.Name)
		nl.Debugf(l, "upstream: %s, upstreamName: %s", u.Name, upstreamName)
		upstreamNames = append(upstreamNames, upstreamName)
	}

	for _, vsr := range vsEx.VirtualServerRoutes {
		upstreamNamer := NewUpstreamNamerForVirtualServerRoute(vs, vsr)
		for _, u := range vsr.Spec.Upstreams {
			upstreamName := upstreamNamer.GetNameForUpstream(u.Name)
			nl.Debugf(l, "upstream: %s, upstreamName: %s", u.Name, upstreamName)
			upstreamNames = append(upstreamNames, upstreamName)

		}
	}

	return upstreamNames
}

// UpstreamsForHost takes a hostname and returns upstreams for the given hostname.
func (cnf *Configurator) UpstreamsForHost(hostname string) []string {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	nl.Debugf(l, "Get upstream for host: %s", hostname)
	vsEx := cnf.virtualServerExForHost(hostname)
	if vsEx != nil {
		return cnf.upstreamsForVirtualServer(vsEx)
	}
	return nil
}

// StreamUpstreamsForName takes a name and returns stream upstreams
// associated with this name. The name represents TS's
// (TransportServer) action name.
func (cnf *Configurator) StreamUpstreamsForName(name string) []string {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	nl.Debugf(l, "Get stream upstreams for name: '%s'", name)
	ts := cnf.transportServerForActionName(name)
	if ts != nil {
		return cnf.streamUpstreamsForTransportServer(ts)
	}
	return nil
}

// transportServerForActionName takes an action name and returns
// Transport Server obj associated with that name.
func (cnf *Configurator) transportServerForActionName(name string) *conf_v1.TransportServer {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	for _, tsEx := range cnf.transportServers {
		nl.Debugf(l, "Check ts action '%s' for requested name: '%s'", tsEx.TransportServer.Spec.Action.Pass, name)
		if tsEx.TransportServer.Spec.Action.Pass == name {
			return tsEx.TransportServer
		}
	}
	return nil
}

// streamUpstreamsForTransportServer takes TransportServer obj and returns
// a list of stream upstreams associated with this TransportServer.
func (cnf *Configurator) streamUpstreamsForTransportServer(ts *conf_v1.TransportServer) []string {
	upstreamNames := make([]string, 0, len(ts.Spec.Upstreams))
	n := newUpstreamNamerForTransportServer(ts)
	for _, u := range ts.Spec.Upstreams {
		un := n.GetNameForUpstream(u.Name)
		upstreamNames = append(upstreamNames, un)
	}
	return upstreamNames
}

// addOrUpdateIngress returns a bool that specifies if the underlying config
// file has changed, and any warnings or errors
func (cnf *Configurator) addOrUpdateIngress(ingEx *IngressEx) (bool, Warnings, error) {
	apResources := cnf.updateApResources(ingEx)

	cnf.updateDosResource(ingEx.DosEx)
	dosResource := getAppProtectDosResource(ingEx.DosEx)

	// LocalSecretStore will not set Path if the secret is not on the filesystem.
	// However, NGINX configuration for an Ingress resource, to handle the case of a missing secret,
	// relies on the path to be always configured.
	if jwtKey, exists := ingEx.Ingress.Annotations[JWTKeyAnnotation]; exists {
		ingEx.SecretRefs[jwtKey].Path = cnf.nginxManager.GetFilenameForSecret(ingEx.Ingress.Namespace + "-" + jwtKey)
	}
	if basicAuth, exists := ingEx.Ingress.Annotations[BasicAuthSecretAnnotation]; exists {
		ingEx.SecretRefs[basicAuth].Path = cnf.nginxManager.GetFilenameForSecret(ingEx.Ingress.Namespace + "-" + basicAuth)
	}

	isMinion := false
	nginxCfg, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:              cnf.staticCfgParams,
		ingEx:                     ingEx,
		apResources:               apResources,
		dosResource:               dosResource,
		isMinion:                  isMinion,
		isPlus:                    cnf.isPlus,
		BaseCfgParams:             cnf.CfgParams,
		isResolverConfigured:      cnf.IsResolverConfigured(),
		isWildcardEnabled:         cnf.isWildcardEnabled,
		ingressControllerReplicas: cnf.ingressControllerReplicas,
	})

	name := objectMetaToFileName(&ingEx.Ingress.ObjectMeta)
	content, err := cnf.templateExecutor.ExecuteIngressConfigTemplate(&nginxCfg)
	if err != nil {
		return false, warnings, fmt.Errorf("error generating Ingress Config %v: %w", name, err)
	}
	configChanged := cnf.nginxManager.CreateConfig(name, content)

	cnf.ingresses[name] = ingEx
	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.updateIngressMetricsLabels(ingEx, nginxCfg.Upstreams)
	}
	return configChanged, warnings, nil
}

// AddOrUpdateMergeableIngress adds or updates NGINX configuration for the Ingress resources with Mergeable Types.
func (cnf *Configurator) AddOrUpdateMergeableIngress(mergeableIngs *MergeableIngresses) (Warnings, error) {
	_, warnings, err := cnf.addOrUpdateMergeableIngress(mergeableIngs)
	if err != nil {
		return warnings, fmt.Errorf("error when adding or updating ingress %v/%v: %w", mergeableIngs.Master.Ingress.Namespace, mergeableIngs.Master.Ingress.Name, err)
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("error reloading NGINX for %v/%v: %w", mergeableIngs.Master.Ingress.Namespace, mergeableIngs.Master.Ingress.Name, err)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateMergeableIngress(mergeableIngs *MergeableIngresses) (bool, Warnings, error) {
	apResources := cnf.updateApResources(mergeableIngs.Master)
	cnf.updateDosResource(mergeableIngs.Master.DosEx)
	dosResource := getAppProtectDosResource(mergeableIngs.Master.DosEx)

	// LocalSecretStore will not set Path if the secret is not on the filesystem.
	// However, NGINX configuration for an Ingress resource, to handle the case of a missing secret,
	// relies on the path to be always configured.
	if jwtKey, exists := mergeableIngs.Master.Ingress.Annotations[JWTKeyAnnotation]; exists {
		mergeableIngs.Master.SecretRefs[jwtKey].Path = cnf.nginxManager.GetFilenameForSecret(mergeableIngs.Master.Ingress.Namespace + "-" + jwtKey)
	}
	if basicAuth, exists := mergeableIngs.Master.Ingress.Annotations[BasicAuthSecretAnnotation]; exists {
		mergeableIngs.Master.SecretRefs[basicAuth].Path = cnf.nginxManager.GetFilenameForSecret(mergeableIngs.Master.Ingress.Namespace + "-" + basicAuth)
	}
	for _, minion := range mergeableIngs.Minions {
		if jwtKey, exists := minion.Ingress.Annotations[JWTKeyAnnotation]; exists {
			minion.SecretRefs[jwtKey].Path = cnf.nginxManager.GetFilenameForSecret(minion.Ingress.Namespace + "-" + jwtKey)
		}
		if basicAuth, exists := minion.Ingress.Annotations[BasicAuthSecretAnnotation]; exists {
			minion.SecretRefs[basicAuth].Path = cnf.nginxManager.GetFilenameForSecret(minion.Ingress.Namespace + "-" + basicAuth)
		}
	}

	nginxCfg, warnings := generateNginxCfgForMergeableIngresses(NginxCfgParams{
		mergeableIngs:             mergeableIngs,
		apResources:               apResources,
		dosResource:               dosResource,
		BaseCfgParams:             cnf.CfgParams,
		isPlus:                    cnf.isPlus,
		isResolverConfigured:      cnf.IsResolverConfigured(),
		staticParams:              cnf.staticCfgParams,
		isWildcardEnabled:         cnf.isWildcardEnabled,
		ingressControllerReplicas: cnf.ingressControllerReplicas,
	})

	name := objectMetaToFileName(&mergeableIngs.Master.Ingress.ObjectMeta)
	content, err := cnf.templateExecutor.ExecuteIngressConfigTemplate(&nginxCfg)
	if err != nil {
		return false, warnings, fmt.Errorf("error generating Ingress Config %v: %w", name, err)
	}
	changed := cnf.nginxManager.CreateConfig(name, content)

	cnf.ingresses[name] = mergeableIngs.Master
	cnf.minions[name] = make(map[string]bool)
	for _, minion := range mergeableIngs.Minions {
		minionName := objectMetaToFileName(&minion.Ingress.ObjectMeta)
		cnf.minions[name][minionName] = true
	}

	cnf.mergeableIngresses[name] = mergeableIngs

	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.updateIngressMetricsLabels(mergeableIngs.Master, nginxCfg.Upstreams)
	}

	return changed, warnings, nil
}

func (cnf *Configurator) updateVirtualServerMetricsLabels(virtualServerEx *VirtualServerEx, upstreams []version2.Upstream) {
	labels := make(map[string][]string)
	newUpstreams := make(map[string]bool)
	var newUpstreamsNames []string

	upstreamServerPeerLabels := make(map[string][]string)
	newPeers := make(map[string]bool)
	var newPeersIPs []string

	for _, u := range upstreams {
		labels[u.Name] = []string{u.UpstreamLabels.Service, u.UpstreamLabels.ResourceType, u.UpstreamLabels.ResourceName, u.UpstreamLabels.ResourceNamespace}
		newUpstreams[u.Name] = true
		newUpstreamsNames = append(newUpstreamsNames, u.Name)
		for _, server := range u.Servers {
			podInfo := virtualServerEx.PodsByIP[server.Address]
			labelKey := fmt.Sprintf("%v/%v", u.Name, server.Address)
			upstreamServerPeerLabels[labelKey] = []string{podInfo.Name}
			if cnf.staticCfgParams.NginxServiceMesh {
				ownerLabelVal := fmt.Sprintf("%s/%s", podInfo.OwnerType, podInfo.OwnerName)
				upstreamServerPeerLabels[labelKey] = append(upstreamServerPeerLabels[labelKey], ownerLabelVal)
			}
			newPeers[labelKey] = true
			newPeersIPs = append(newPeersIPs, labelKey)
		}
	}

	key := fmt.Sprintf("%v/%v", virtualServerEx.VirtualServer.Namespace, virtualServerEx.VirtualServer.Name)

	removedPeers := findRemovedKeys(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key], newPeers)
	cnf.metricLabelsIndex.virtualServerUpstreamPeers[key] = newPeersIPs
	cnf.latencyCollector.UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels)
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(removedPeers)

	removedUpstreams := findRemovedKeys(cnf.metricLabelsIndex.virtualServerUpstreams[key], newUpstreams)
	cnf.latencyCollector.UpdateUpstreamServerLabels(labels)
	cnf.metricLabelsIndex.virtualServerUpstreams[key] = newUpstreamsNames

	cnf.latencyCollector.DeleteUpstreamServerLabels(removedUpstreams)
	cnf.latencyCollector.DeleteMetrics(removedPeers)

	if cnf.isPlus {
		cnf.labelUpdater.UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels)
		cnf.labelUpdater.DeleteUpstreamServerPeerLabels(removedPeers)
		cnf.labelUpdater.UpdateUpstreamServerLabels(labels)
		cnf.labelUpdater.DeleteUpstreamServerLabels(removedUpstreams)

		serverZoneLabels := make(map[string][]string)
		newZones := make(map[string]bool)
		newZonesNames := []string{virtualServerEx.VirtualServer.Spec.Host}

		serverZoneLabels[virtualServerEx.VirtualServer.Spec.Host] = []string{
			"virtualserver", virtualServerEx.VirtualServer.Name, virtualServerEx.VirtualServer.Namespace,
		}

		newZones[virtualServerEx.VirtualServer.Spec.Host] = true

		removedZones := findRemovedKeys(cnf.metricLabelsIndex.virtualServerServerZones[key], newZones)
		cnf.metricLabelsIndex.virtualServerServerZones[key] = newZonesNames
		cnf.labelUpdater.UpdateServerZoneLabels(serverZoneLabels)
		cnf.labelUpdater.DeleteServerZoneLabels(removedZones)
	}
}

func (cnf *Configurator) deleteVirtualServerMetricsLabels(key string) {
	cnf.latencyCollector.DeleteUpstreamServerLabels(cnf.metricLabelsIndex.virtualServerUpstreams[key])
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key])
	cnf.latencyCollector.DeleteMetrics(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key])

	if cnf.isPlus {
		cnf.labelUpdater.DeleteUpstreamServerLabels(cnf.metricLabelsIndex.virtualServerUpstreams[key])
		cnf.labelUpdater.DeleteServerZoneLabels(cnf.metricLabelsIndex.virtualServerServerZones[key])
		cnf.labelUpdater.DeleteUpstreamServerPeerLabels(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key])
	}

	delete(cnf.metricLabelsIndex.virtualServerUpstreams, key)
	delete(cnf.metricLabelsIndex.virtualServerServerZones, key)
	delete(cnf.metricLabelsIndex.virtualServerUpstreamPeers, key)
}

// AddOrUpdateVirtualServer adds or updates NGINX configuration for the VirtualServer resource.
func (cnf *Configurator) AddOrUpdateVirtualServer(virtualServerEx *VirtualServerEx) (Warnings, error) {
	_, warnings, weightUpdates, err := cnf.addOrUpdateVirtualServer(virtualServerEx)
	if err != nil {
		return warnings, fmt.Errorf("error adding or updating VirtualServer %v/%v: %w", virtualServerEx.VirtualServer.Namespace, virtualServerEx.VirtualServer.Name, err)
	}

	if len(weightUpdates) > 0 {
		cnf.EnableReloads()
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("error reloading NGINX for VirtualServer %v/%v: %w", virtualServerEx.VirtualServer.Namespace, virtualServerEx.VirtualServer.Name, err)
	}

	for _, weightUpdate := range weightUpdates {
		cnf.nginxManager.UpsertSplitClientsKeyVal(weightUpdate.Zone, weightUpdate.Key, weightUpdate.Value)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateVirtualServer(virtualServerEx *VirtualServerEx) (bool, Warnings, []WeightUpdate, error) {
	var weightUpdates []WeightUpdate
	apResources := cnf.updateApResourcesForVs(virtualServerEx)
	dosResources := map[string]*appProtectDosResource{}
	for k, v := range virtualServerEx.DosProtectedEx {
		cnf.updateDosResource(v)
		dosRes := getAppProtectDosResource(v)
		if dosRes != nil {
			dosResources[k] = dosRes
		}
	}

	name := getFileNameForVirtualServer(virtualServerEx.VirtualServer)

	vsc := newVirtualServerConfigurator(cnf.CfgParams, cnf.isPlus, cnf.IsResolverConfigured(), cnf.staticCfgParams, cnf.isWildcardEnabled, nil)
	vsc.IngressControllerReplicas = cnf.ingressControllerReplicas
	vsCfg, warnings := vsc.GenerateVirtualServerConfig(virtualServerEx, apResources, dosResources)
	content, err := cnf.templateExecutorV2.ExecuteVirtualServerTemplate(&vsCfg)
	if err != nil {
		return false, warnings, weightUpdates, fmt.Errorf("error generating VirtualServer config: %v: %w", name, err)
	}
	changed := cnf.nginxManager.CreateConfig(name, content)

	cnf.virtualServers[name] = virtualServerEx

	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.updateVirtualServerMetricsLabels(virtualServerEx, vsCfg.Upstreams)
	}

	if cnf.staticCfgParams.DynamicWeightChangesReload && len(vsCfg.TwoWaySplitClients) > 0 {
		for _, splitClient := range vsCfg.TwoWaySplitClients {
			if len(splitClient.Weights) != 2 {
				continue
			}
			variableNamer := *NewVSVariableNamer(virtualServerEx.VirtualServer)
			value := variableNamer.GetNameOfKeyOfMapForWeights(splitClient.SplitClientsIndex, splitClient.Weights[0], splitClient.Weights[1])
			weightUpdates = append(weightUpdates, WeightUpdate{Zone: splitClient.ZoneName, Key: splitClient.Key, Value: value})
		}
	}
	return changed, warnings, weightUpdates, nil
}

// AddOrUpdateVirtualServers adds or updates NGINX configuration for multiple VirtualServer resources.
func (cnf *Configurator) AddOrUpdateVirtualServers(virtualServerExes []*VirtualServerEx) (Warnings, error) {
	allWarnings := newWarnings()
	allWeightUpdates := []WeightUpdate{}

	for _, vsEx := range virtualServerExes {
		_, warnings, weightUpdates, err := cnf.addOrUpdateVirtualServer(vsEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
		allWeightUpdates = append(allWeightUpdates, weightUpdates...)
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("error when reloading NGINX when updating Policy: %w", err)
	}

	for _, weightUpdate := range allWeightUpdates {
		cnf.nginxManager.UpsertSplitClientsKeyVal(weightUpdate.Zone, weightUpdate.Key, weightUpdate.Value)
	}

	return allWarnings, nil
}

func (cnf *Configurator) updateTransportServerMetricsLabels(transportServerEx *TransportServerEx, upstreams []version2.StreamUpstream) {
	labels := make(map[string][]string)
	newUpstreams := make(map[string]bool)
	var newUpstreamsNames []string

	upstreamServerPeerLabels := make(map[string][]string)
	newPeers := make(map[string]bool)
	var newPeersIPs []string

	for _, u := range upstreams {
		labels[u.Name] = []string{u.UpstreamLabels.Service, u.UpstreamLabels.ResourceType, u.UpstreamLabels.ResourceName, u.UpstreamLabels.ResourceNamespace}
		newUpstreams[u.Name] = true
		newUpstreamsNames = append(newUpstreamsNames, u.Name)

		for _, server := range u.Servers {
			podName := transportServerEx.PodsByIP[server.Address]
			labelKey := fmt.Sprintf("%v/%v", u.Name, server.Address)
			upstreamServerPeerLabels[labelKey] = []string{podName}

			newPeers[labelKey] = true
			newPeersIPs = append(newPeersIPs, labelKey)
		}
	}

	key := fmt.Sprintf("%v/%v", transportServerEx.TransportServer.Namespace, transportServerEx.TransportServer.Name)

	removedPeers := findRemovedKeys(cnf.metricLabelsIndex.transportServerUpstreamPeers[key], newPeers)
	cnf.metricLabelsIndex.transportServerUpstreamPeers[key] = newPeersIPs

	removedUpstreams := findRemovedKeys(cnf.metricLabelsIndex.transportServerUpstreams[key], newUpstreams)
	cnf.metricLabelsIndex.transportServerUpstreams[key] = newUpstreamsNames
	cnf.labelUpdater.UpdateStreamUpstreamServerPeerLabels(upstreamServerPeerLabels)
	cnf.labelUpdater.DeleteStreamUpstreamServerPeerLabels(removedPeers)
	cnf.labelUpdater.UpdateStreamUpstreamServerLabels(labels)
	cnf.labelUpdater.DeleteStreamUpstreamServerLabels(removedUpstreams)

	streamServerZoneLabels := make(map[string][]string)
	newZones := make(map[string]bool)
	zoneName := transportServerEx.TransportServer.Spec.Listener.Name

	if transportServerEx.TransportServer.Spec.Host != "" {
		zoneName = transportServerEx.TransportServer.Spec.Host
	}

	newZonesNames := []string{zoneName}

	streamServerZoneLabels[zoneName] = []string{
		"transportserver", transportServerEx.TransportServer.Name, transportServerEx.TransportServer.Namespace,
	}

	newZones[zoneName] = true
	removedZones := findRemovedKeys(cnf.metricLabelsIndex.transportServerServerZones[key], newZones)
	cnf.metricLabelsIndex.transportServerServerZones[key] = newZonesNames
	cnf.labelUpdater.UpdateStreamServerZoneLabels(streamServerZoneLabels)
	cnf.labelUpdater.DeleteStreamServerZoneLabels(removedZones)
}

func (cnf *Configurator) deleteTransportServerMetricsLabels(key string) {
	cnf.labelUpdater.DeleteStreamUpstreamServerLabels(cnf.metricLabelsIndex.transportServerUpstreams[key])
	cnf.labelUpdater.DeleteStreamServerZoneLabels(cnf.metricLabelsIndex.transportServerServerZones[key])
	cnf.labelUpdater.DeleteStreamUpstreamServerPeerLabels(cnf.metricLabelsIndex.transportServerUpstreamPeers[key])

	delete(cnf.metricLabelsIndex.transportServerUpstreams, key)
	delete(cnf.metricLabelsIndex.transportServerServerZones, key)
	delete(cnf.metricLabelsIndex.transportServerUpstreamPeers, key)
}

// AddOrUpdateTransportServer adds or updates NGINX configuration for the TransportServer resource.
// It is a responsibility of the caller to check that the TransportServer references an existing listener.
func (cnf *Configurator) AddOrUpdateTransportServer(transportServerEx *TransportServerEx) (Warnings, error) {
	_, warnings, err := cnf.addOrUpdateTransportServer(transportServerEx)
	if err != nil {
		return nil, fmt.Errorf("error adding or updating TransportServer %v/%v: %w", transportServerEx.TransportServer.Namespace, transportServerEx.TransportServer.Name, err)
	}
	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return nil, fmt.Errorf("error reloading NGINX for TransportServer %v/%v: %w", transportServerEx.TransportServer.Namespace, transportServerEx.TransportServer.Name, err)
	}
	return warnings, nil
}

func (cnf *Configurator) addOrUpdateTransportServer(transportServerEx *TransportServerEx) (bool, Warnings, error) {
	name := getFileNameForTransportServer(transportServerEx.TransportServer)
	tsCfg, warnings := generateTransportServerConfig(transportServerConfigParams{
		transportServerEx:      transportServerEx,
		listenerPort:           transportServerEx.ListenerPort,
		isPlus:                 cnf.isPlus,
		isResolverConfigured:   cnf.IsResolverConfigured(),
		isDynamicReloadEnabled: cnf.staticCfgParams.DynamicSSLReload,
		staticSSLPath:          cnf.staticCfgParams.StaticSSLPath,
	})

	content, err := cnf.templateExecutorV2.ExecuteTransportServerTemplate(tsCfg)
	if err != nil {
		return false, nil, fmt.Errorf("error generating TransportServer config %v: %w", name, err)
	}
	if cnf.isPlus && cnf.isPrometheusEnabled {
		cnf.updateTransportServerMetricsLabels(transportServerEx, tsCfg.Upstreams)
	}
	changed := cnf.nginxManager.CreateStreamConfig(name, content)

	cnf.transportServers[name] = transportServerEx

	// update TLS Passthrough Hosts config in case we have a TLS Passthrough TransportServer
	// A non empty Host, may be a TLS Passthrough TransportServer but we have to check for the existence of the TLS Passthrough listener also, as TransportServers that terminate at the NGINX level can have non empty Hosts now too
	isTLSPassthrough := transportServerEx.TransportServer.Spec.Listener.Name == conf_v1.TLSPassthroughListenerName
	if transportServerEx.TransportServer.Spec.Host != "" && isTLSPassthrough {
		key := generateNamespaceNameKey(&transportServerEx.TransportServer.ObjectMeta)
		cnf.tlsPassthroughPairs[key] = tlsPassthroughPair{
			Host:       transportServerEx.TransportServer.Spec.Host,
			UnixSocket: generateUnixSocket(transportServerEx),
		}
		ptChanged, err := cnf.updateTLSPassthroughHostsConfig()
		if err != nil {
			return false, nil, err
		}
		return changed || ptChanged, warnings, nil
	}
	return changed, warnings, nil
}

// GetVirtualServerRoutesForVirtualServer returns the virtualServerRoutes that a virtualServer
// references, if that virtualServer exists
func (cnf *Configurator) GetVirtualServerRoutesForVirtualServer(key string) []*conf_v1.VirtualServerRoute {
	vsFileName := getFileNameForVirtualServerFromKey(key)
	if cnf.virtualServers[vsFileName] != nil {
		return cnf.virtualServers[vsFileName].VirtualServerRoutes
	}
	return nil
}

func (cnf *Configurator) updateTLSPassthroughHostsConfig() (bool, error) {
	cfg := generateTLSPassthroughHostsConfig(cnf.tlsPassthroughPairs)

	content, err := cnf.templateExecutorV2.ExecuteTLSPassthroughHostsTemplate(cfg)
	if err != nil {
		return false, fmt.Errorf("error generating config for TLS Passthrough Unix Sockets map: %w", err)
	}

	return cnf.nginxManager.CreateTLSPassthroughHostsConfig(content), nil
}

func generateTLSPassthroughHostsConfig(tlsPassthroughPairs map[string]tlsPassthroughPair) *version2.TLSPassthroughHostsConfig {
	cfg := version2.TLSPassthroughHostsConfig{}

	for _, pair := range tlsPassthroughPairs {
		cfg[pair.Host] = pair.UnixSocket
	}

	return &cfg
}

// AddOrUpdateCASecret writes the secret content to disk returning the files added/updated
func (cnf *Configurator) AddOrUpdateCASecret(secret *api_v1.Secret, crtFileName, crlFileName string) string {
	crtData, crlData := GenerateCAFileContent(secret)
	crtFilePath := cnf.nginxManager.CreateSecret(crtFileName, crtData, nginx.ReadWriteOnlyFileMode)
	crlFilePath := cnf.nginxManager.CreateSecret(crlFileName, crlData, nginx.ReadWriteOnlyFileMode)
	return fmt.Sprintf("%s %s", crtFilePath, crlFilePath)
}

func (cnf *Configurator) addOrUpdateJWKSecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)
	data := secret.Data[JWTKeyKey]
	return cnf.nginxManager.CreateSecret(name, data, nginx.JWKSecretFileMode)
}

func (cnf *Configurator) addOrUpdateHtpasswdSecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)
	data := secret.Data[HtpasswdFileKey]
	return cnf.nginxManager.CreateSecret(name, data, nginx.HtpasswdSecretFileMode)
}

// AddOrUpdateResources adds or updates configuration for resources.
func (cnf *Configurator) AddOrUpdateResources(resources ExtendedResources, reloadIfUnchanged bool) (Warnings, error) {
	allWarnings := newWarnings()
	allWeightUpdates := []WeightUpdate{}
	configsChanged := false

	updateResource := func(updateFunc func() (bool, Warnings, error), namespace, name string) error {
		changed, warnings, err := updateFunc()
		if err != nil {
			return fmt.Errorf("error adding or updating resource %v/%v: %w", namespace, name, err)
		}
		allWarnings.Add(warnings)
		if changed {
			configsChanged = true
		}
		return nil
	}

	updateVSResource := func(updateFunc func() (bool, Warnings, []WeightUpdate, error), namespace, name string) error {
		changed, warnings, weightUpdates, err := updateFunc()
		if err != nil {
			return fmt.Errorf("error adding or updating resource %v/%v: %w", namespace, name, err)
		}
		allWarnings.Add(warnings)
		allWeightUpdates = append(allWeightUpdates, weightUpdates...)

		if changed {
			configsChanged = true
		}
		return nil
	}

	for _, ingEx := range resources.IngressExes {
		err := updateResource(func() (bool, Warnings, error) {
			return cnf.addOrUpdateIngress(ingEx)
		}, ingEx.Ingress.Namespace, ingEx.Ingress.Name)
		if err != nil {
			return nil, err
		}
	}

	for _, m := range resources.MergeableIngresses {
		err := updateResource(func() (bool, Warnings, error) {
			return cnf.addOrUpdateMergeableIngress(m)
		}, m.Master.Ingress.Namespace, m.Master.Ingress.Name)
		if err != nil {
			return nil, err
		}
	}

	for _, vsEx := range resources.VirtualServerExes {
		err := updateVSResource(func() (bool, Warnings, []WeightUpdate, error) {
			return cnf.addOrUpdateVirtualServer(vsEx)
		}, vsEx.VirtualServer.Namespace, vsEx.VirtualServer.Name)
		if err != nil {
			return nil, err
		}
	}

	for _, tsEx := range resources.TransportServerExes {
		err := updateResource(func() (bool, Warnings, error) {
			return cnf.addOrUpdateTransportServer(tsEx)
		}, tsEx.TransportServer.Namespace, tsEx.TransportServer.Name)
		if err != nil {
			return nil, err
		}
	}

	if configsChanged || reloadIfUnchanged {
		if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
			return nil, fmt.Errorf("error when reloading NGINX when updating resources: %w", err)
		}
	}
	return allWarnings, nil
}

// AddOrUpdateLicenseSecret adds or updates NGINX Plus license secret.
func (cnf *Configurator) AddOrUpdateLicenseSecret(secret *api_v1.Secret) error {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	nl.Debugf(l, "AddOrUpdateLicenseSecret: [%v]", secret.Name)
	data, err := GenerateLicenseSecret(secret)
	if err != nil {
		return err
	}
	cnf.nginxManager.CreateSecret(LicenseSecretFileName, data, nginx.ReadWriteOnlyFileMode)

	return nil
}

func (cnf *Configurator) addOrUpdateTLSSecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)
	data := GenerateCertAndKeyFileContent(secret)
	return cnf.nginxManager.CreateSecret(name, data, nginx.ReadWriteOnlyFileMode)
}

// AddOrUpdateSpecialTLSSecrets adds or updates a file with a TLS cert and a key from a Special TLS Secret (eg. DefaultServerSecret, WildcardTLSSecret).
func (cnf *Configurator) AddOrUpdateSpecialTLSSecrets(secret *api_v1.Secret, secretNames []string) {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	nl.Debugf(l, "AddOrUpdateSpecialTLSSecrets: secrets [%v]", secretNames)
	data := GenerateCertAndKeyFileContent(secret)

	for _, secretName := range secretNames {
		cnf.nginxManager.CreateSecret(secretName, data, nginx.ReadWriteOnlyFileMode)
	}
}

// AddOrUpdateMGMTClientAuthSecret adds or updates the MGMT Client Auth Secret file with a TLS cert and key.
func (cnf *Configurator) AddOrUpdateMGMTClientAuthSecret(secret *api_v1.Secret) {
	data := GenerateCertAndKeyFileContent(secret)
	cnf.nginxManager.CreateSecret("mgmt/client", data, nginx.ReadWriteOnlyFileMode)
}

// GenerateCertAndKeyFileContent generates a pem file content from the TLS secret.
func GenerateCertAndKeyFileContent(secret *api_v1.Secret) []byte {
	var res bytes.Buffer

	res.Write(secret.Data[api_v1.TLSCertKey])
	res.WriteString("\n")
	res.Write(secret.Data[api_v1.TLSPrivateKeyKey])

	return res.Bytes()
}

// GenerateCAFileContent generates a pem file content from the TLS secret.
func GenerateCAFileContent(secret *api_v1.Secret) ([]byte, []byte) {
	var caKey bytes.Buffer
	var caCrl bytes.Buffer

	caKey.Write(secret.Data[CACrtKey])
	caCrl.Write(secret.Data[CACrlKey])

	return caKey.Bytes(), caCrl.Bytes()
}

// GenerateLicenseSecret generates jwt content from the License secret which is required for NGINX Plus.
func GenerateLicenseSecret(secret *api_v1.Secret) ([]byte, error) {
	var licenseKey bytes.Buffer

	data, exists := secret.Data[LicenseSecretFileName]
	if !exists {
		return nil, fmt.Errorf("license secret %s/%s must contain the key %s", secret.Namespace, secret.Name, LicenseSecretFileName)
	}
	licenseKey.Write(data)

	return licenseKey.Bytes(), nil
}

// DeleteIngress deletes NGINX configuration for the Ingress resource.
func (cnf *Configurator) DeleteIngress(key string, skipReload bool) error {
	name := keyToFileName(key)
	cnf.nginxManager.DeleteConfig(name)

	delete(cnf.ingresses, name)
	delete(cnf.minions, name)
	delete(cnf.mergeableIngresses, name)

	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.deleteIngressMetricsLabels(key)
	}

	if !skipReload {
		if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
			return fmt.Errorf("error when removing ingress %v: %w", key, err)
		}
	}

	return nil
}

// DeleteVirtualServer deletes NGINX configuration for the VirtualServer resource.
func (cnf *Configurator) DeleteVirtualServer(key string, skipReload bool) error {
	name := getFileNameForVirtualServerFromKey(key)
	cnf.nginxManager.DeleteConfig(name)

	if cnf.isPlus {
		cnf.nginxManager.DeleteKeyValStateFiles(name)
	}

	delete(cnf.virtualServers, name)
	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.deleteVirtualServerMetricsLabels(key)
	}

	if !skipReload {
		if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
			return fmt.Errorf("error when removing VirtualServer %v: %w", key, err)
		}
	}

	return nil
}

// DeleteTransportServer deletes NGINX configuration for the TransportServer resource.
func (cnf *Configurator) DeleteTransportServer(key string) error {
	if cnf.isPlus && cnf.isPrometheusEnabled {
		cnf.deleteTransportServerMetricsLabels(key)
	}

	err := cnf.deleteTransportServer(key)
	if err != nil {
		return fmt.Errorf("error when removing TransportServer %v: %w", key, err)
	}

	err = cnf.Reload(nginx.ReloadForOtherUpdate)
	if err != nil {
		return fmt.Errorf("error when removing TransportServer %v: %w", key, err)
	}

	return nil
}

func (cnf *Configurator) deleteTransportServer(key string) error {
	name := getFileNameForTransportServerFromKey(key)
	cnf.nginxManager.DeleteStreamConfig(name)

	delete(cnf.transportServers, name)
	// update TLS Passthrough Hosts config in case we have a TLS Passthrough TransportServer
	if _, exists := cnf.tlsPassthroughPairs[key]; exists {
		delete(cnf.tlsPassthroughPairs, key)
		_, err := cnf.updateTLSPassthroughHostsConfig()
		return err
	}

	return nil
}

// UpdateEndpoints updates endpoints in NGINX configuration for the Ingress resources.
func (cnf *Configurator) UpdateEndpoints(ingExes []*IngressEx) error {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	reloadPlus := false

	for _, ingEx := range ingExes {
		// It is safe to ignore warnings here as no new warnings should appear when updating Endpoints for Ingresses
		_, _, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return fmt.Errorf("error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}

		if cnf.isPlus {
			err := cnf.updatePlusEndpoints(ingEx)
			if err != nil {
				nl.Warnf(l, "Couldn't update the endpoints via the API: %v; reloading configuration instead", err)
				reloadPlus = true
			}
		}
	}

	if cnf.isPlus && !reloadPlus {
		nl.Debug(l, "No need to reload nginx")
		return nil
	}

	if err := cnf.Reload(nginx.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("error reloading NGINX when updating endpoints: %w", err)
	}

	return nil
}

// UpdateEndpointsMergeableIngress updates endpoints in NGINX configuration for a mergeable Ingress resource.
func (cnf *Configurator) UpdateEndpointsMergeableIngress(mergeableIngresses []*MergeableIngresses) error {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	reloadPlus := false

	for i := range mergeableIngresses {
		// It is safe to ignore warnings here as no new warnings should appear when updating Endpoints for Ingresses
		_, _, err := cnf.addOrUpdateMergeableIngress(mergeableIngresses[i])
		if err != nil {
			return fmt.Errorf("error adding or updating mergeableIngress %v/%v: %w", mergeableIngresses[i].Master.Ingress.Namespace, mergeableIngresses[i].Master.Ingress.Name, err)
		}

		if cnf.isPlus {
			for _, ing := range mergeableIngresses[i].Minions {
				err = cnf.updatePlusEndpoints(ing)
				if err != nil {
					nl.Warnf(l, "Couldn't update the endpoints via the API: %v; reloading configuration instead", err)
					reloadPlus = true
				}
			}
		}
	}

	if cnf.isPlus && !reloadPlus {
		nl.Debug(l, "No need to reload nginx")
		return nil
	}

	if err := cnf.Reload(nginx.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("error reloading NGINX when updating endpoints for %v: %w", mergeableIngresses, err)
	}

	return nil
}

// UpdateEndpointsForVirtualServers updates endpoints in NGINX configuration for the VirtualServer resources.
func (cnf *Configurator) UpdateEndpointsForVirtualServers(virtualServerExes []*VirtualServerEx) error {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	reloadPlus := false

	for _, vs := range virtualServerExes {
		// It is safe to ignore warnings here as no new warnings should appear when updating Endpoints for VirtualServers
		_, _, _, err := cnf.addOrUpdateVirtualServer(vs)
		if err != nil {
			return fmt.Errorf("error adding or updating VirtualServer %v/%v: %w", vs.VirtualServer.Namespace, vs.VirtualServer.Name, err)
		}

		if cnf.isPlus {
			err := cnf.updatePlusEndpointsForVirtualServer(vs)
			if err != nil {
				nl.Warnf(l, "Couldn't update the endpoints via the API: %v; reloading configuration instead", err)
				reloadPlus = true
			}
		}
	}

	if cnf.isPlus && !reloadPlus {
		nl.Debug(l, "No need to reload nginx")
		return nil
	}

	if err := cnf.Reload(nginx.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("error reloading NGINX when updating endpoints: %w", err)
	}

	return nil
}

func (cnf *Configurator) updatePlusEndpointsForVirtualServer(virtualServerEx *VirtualServerEx) error {
	upstreams := createUpstreamsForPlus(virtualServerEx, cnf.CfgParams, cnf.staticCfgParams)
	for _, upstream := range upstreams {
		serverCfg := createUpstreamServersConfigForPlus(upstream)

		endpoints := createEndpointsFromUpstream(upstream)

		err := cnf.updateServersInPlus(upstream.Name, endpoints, serverCfg)
		if err != nil {
			return fmt.Errorf("couldn't update the endpoints for %v: %w", upstream.Name, err)
		}
	}

	return nil
}

// UpdateEndpointsForTransportServers updates endpoints in NGINX configuration for the TransportServer resources.
func (cnf *Configurator) UpdateEndpointsForTransportServers(transportServerExes []*TransportServerEx) error {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	reloadPlus := false

	for _, tsEx := range transportServerExes {
		// Ignore warnings here as no new warnings should appear when updating Endpoints for TransportServers
		_, _, err := cnf.addOrUpdateTransportServer(tsEx)
		if err != nil {
			return fmt.Errorf("error adding or updating TransportServer %v/%v: %w", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, err)
		}
		if cnf.isPlus {
			err := cnf.updatePlusEndpointsForTransportServer(tsEx)
			if err != nil {
				nl.Warnf(l, "Couldn't update the endpoints via the API: %v; reloading configuration instead", err)
				reloadPlus = true
			}
		}
	}

	if cnf.isPlus && !reloadPlus {
		nl.Debug(l, "No need to reload nginx")
		return nil
	}
	if err := cnf.Reload(nginx.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("error reloading NGINX when updating endpoints: %w", err)
	}
	return nil
}

func (cnf *Configurator) updatePlusEndpointsForTransportServer(transportServerEx *TransportServerEx) error {
	upstreamNamer := newUpstreamNamerForTransportServer(transportServerEx.TransportServer)

	for _, u := range transportServerEx.TransportServer.Spec.Upstreams {
		name := upstreamNamer.GetNameForUpstream(u.Name)

		// subselector is not supported yet in TransportServer upstreams. That's why we pass "nil" here
		endpointsKey := GenerateEndpointsKey(transportServerEx.TransportServer.Namespace, u.Service, nil, uint16(u.Port))
		endpoints := transportServerEx.Endpoints[endpointsKey]

		err := cnf.updateStreamServersInPlus(name, endpoints)
		if err != nil {
			return fmt.Errorf("couldn't update the endpoints for %v: %w", u.Name, err)
		}
	}

	return nil
}

func (cnf *Configurator) updatePlusEndpoints(ingEx *IngressEx) error {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	ingCfg := parseAnnotations(ingEx, cnf.CfgParams, cnf.isPlus, cnf.staticCfgParams.MainAppProtectLoadModule, cnf.staticCfgParams.MainAppProtectDosLoadModule, cnf.staticCfgParams.EnableInternalRoutes, cnf.staticCfgParams.IsDirectiveAutoadjustEnabled)

	cfg := nginx.ServerConfig{
		MaxFails:    ingCfg.MaxFails,
		MaxConns:    ingCfg.MaxConns,
		FailTimeout: ingCfg.FailTimeout,
		SlowStart:   ingCfg.SlowStart,
	}

	if ingEx.Ingress.Spec.DefaultBackend != nil {
		endps, exists := ingEx.Endpoints[ingEx.Ingress.Spec.DefaultBackend.Service.Name+GetBackendPortAsString(ingEx.Ingress.Spec.DefaultBackend.Service.Port)]
		if exists {
			if _, isExternalName := ingEx.ExternalNameSvcs[ingEx.Ingress.Spec.DefaultBackend.Service.Name]; isExternalName {
				nl.Debugf(l, "Service %s is Type ExternalName, skipping NGINX Plus endpoints update via API", ingEx.Ingress.Spec.DefaultBackend.Service.Name)
			} else {
				name := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.DefaultBackend)
				err := cnf.updateServersInPlus(name, endps, cfg)
				if err != nil {
					return fmt.Errorf("couldn't update the endpoints for %v: %w", name, err)
				}
			}
		}
	}

	for _, rule := range ingEx.Ingress.Spec.Rules {
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			path := path // address gosec G601
			endps, exists := ingEx.Endpoints[path.Backend.Service.Name+GetBackendPortAsString(path.Backend.Service.Port)]
			if exists {
				if _, isExternalName := ingEx.ExternalNameSvcs[path.Backend.Service.Name]; isExternalName {
					nl.Debugf(l, "Service %s is Type ExternalName, skipping NGINX Plus endpoints update via API", path.Backend.Service.Name)
					continue
				}

				name := getNameForUpstream(ingEx.Ingress, rule.Host, &path.Backend)
				err := cnf.updateServersInPlus(name, endps, cfg)
				if err != nil {
					return fmt.Errorf("couldn't update the endpoints for %v: %w", name, err)
				}
			}
		}
	}

	return nil
}

// EnableReloads enables NGINX reloads meaning that configuration changes will be followed by a reload.
func (cnf *Configurator) EnableReloads() {
	cnf.isReloadsEnabled = true
}

// DisableReloads disables NGINX reloads meaning that configuration changes will not be followed by a reload.
func (cnf *Configurator) DisableReloads() {
	cnf.isReloadsEnabled = false
}

// Reload reloads nginx if reloads is enabled
func (cnf *Configurator) Reload(isEndpointsUpdate bool) error {
	if !cnf.isReloadsEnabled {
		return nil
	}

	return cnf.nginxManager.Reload(isEndpointsUpdate)
}

func (cnf *Configurator) updateServersInPlus(upstream string, servers []string, config nginx.ServerConfig) error {
	if !cnf.isReloadsEnabled {
		return nil
	}

	return cnf.nginxManager.UpdateServersInPlus(upstream, servers, config)
}

func (cnf *Configurator) updateStreamServersInPlus(upstream string, servers []string) error {
	if !cnf.isReloadsEnabled {
		return nil
	}

	return cnf.nginxManager.UpdateStreamServersInPlus(upstream, servers)
}

// UpdateConfig updates NGINX configuration parameters.
//
//gocyclo:ignore
func (cnf *Configurator) UpdateConfig(resources ExtendedResources) (Warnings, error) {
	allWarnings := newWarnings()
	allWeightUpdates := []WeightUpdate{}

	if cnf.CfgParams.MainServerSSLDHParamFileContent != nil {
		fileName, err := cnf.nginxManager.CreateDHParam(*cnf.CfgParams.MainServerSSLDHParamFileContent)
		if err != nil {
			return allWarnings, fmt.Errorf("error when updating dhparams: %w", err)
		}
		cnf.CfgParams.MainServerSSLDHParam = fileName
	}

	// Apply custom main-template defined in ConfigMap obj
	if cnf.CfgParams.MainTemplate != nil {
		err := cnf.templateExecutor.UpdateMainTemplate(cnf.CfgParams.MainTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("error when parsing the main template: %w", err)
		}
	} else {
		// Reverse to default Main template parsed at NIC startup.
		cnf.templateExecutor.UseOriginalMainTemplate()
	}

	if cnf.CfgParams.IngressTemplate != nil {
		err := cnf.templateExecutor.UpdateIngressTemplate(cnf.CfgParams.IngressTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("error when parsing the ingress template: %w", err)
		}
	} else {
		// Reverse to default Ingress template parsed at NIC startup.
		cnf.templateExecutor.UseOriginalIngressTemplate()
	}

	if cnf.CfgParams.VirtualServerTemplate != nil {
		err := cnf.templateExecutorV2.UpdateVirtualServerTemplate(cnf.CfgParams.VirtualServerTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("error when parsing the VirtualServer template: %w", err)
		}
	} else {
		// Reverse to default TransportServer template parsed at NIC startup.
		cnf.templateExecutorV2.UseOriginalVStemplate()
	}

	if cnf.CfgParams.TransportServerTemplate != nil {
		err := cnf.templateExecutorV2.UpdateTransportServerTemplate(cnf.CfgParams.TransportServerTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("error when parsing the TransportServer template: %w", err)
		}
	} else {
		// Reverse to default TransportServer template parsed at NIC startup.
		cnf.templateExecutorV2.UseOriginalTStemplate()
	}

	mainCfg := GenerateNginxMainConfig(cnf.staticCfgParams, cnf.CfgParams, cnf.MgmtCfgParams)
	mainCfgContent, err := cnf.templateExecutor.ExecuteMainConfigTemplate(mainCfg)
	if err != nil {
		return allWarnings, fmt.Errorf("error when writing main Config")
	}
	cnf.nginxManager.CreateMainConfig(mainCfgContent)

	for _, ingEx := range resources.IngressExes {
		_, warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}
	for _, mergeableIng := range resources.MergeableIngresses {
		_, warnings, err := cnf.addOrUpdateMergeableIngress(mergeableIng)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}
	for _, vsEx := range resources.VirtualServerExes {
		_, warnings, weightUpdates, err := cnf.addOrUpdateVirtualServer(vsEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
		allWeightUpdates = append(allWeightUpdates, weightUpdates...)
	}

	for _, tsEx := range resources.TransportServerExes {
		_, warnings, err := cnf.addOrUpdateTransportServer(tsEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("error when updating config from ConfigMap: %w", err)
	}

	for _, weightUpdate := range allWeightUpdates {
		cnf.nginxManager.UpsertSplitClientsKeyVal(weightUpdate.Zone, weightUpdate.Key, weightUpdate.Value)
	}

	return allWarnings, nil
}

// ReloadForBatchUpdates reloads NGINX after a batch event.
func (cnf *Configurator) ReloadForBatchUpdates(batchReloadsEnabled bool) error {
	if !batchReloadsEnabled {
		return nil
	}
	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("error when reloading NGINX after a batch event: %w", err)
	}
	return nil
}

// UpdateVirtualServers updates VirtualServers.
func (cnf *Configurator) UpdateVirtualServers(updatedVSExes []*VirtualServerEx, deletedKeys []string) []error {
	var errList []error
	var allWeightUpdates []WeightUpdate
	for _, vsEx := range updatedVSExes {
		_, _, weightUpdates, err := cnf.addOrUpdateVirtualServer(vsEx)
		if err != nil {
			errList = append(errList, fmt.Errorf("error adding or updating VirtualServer %v/%v: %w", vsEx.VirtualServer.Namespace, vsEx.VirtualServer.Name, err))
		}
		allWeightUpdates = append(allWeightUpdates, weightUpdates...)
	}

	for _, key := range deletedKeys {
		err := cnf.DeleteVirtualServer(key, true)
		if err != nil {
			errList = append(errList, fmt.Errorf("error when removing VirtualServer %v: %w", key, err))
		}
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		errList = append(errList, fmt.Errorf("error when updating VirtualServer: %w", err))
	}

	for _, weightUpdate := range allWeightUpdates {
		cnf.nginxManager.UpsertSplitClientsKeyVal(weightUpdate.Zone, weightUpdate.Key, weightUpdate.Value)
	}

	return errList
}

// UpdateTransportServers updates TransportServers.
func (cnf *Configurator) UpdateTransportServers(updatedTSExes []*TransportServerEx, deletedKeys []string) []error {
	var errList []error
	for _, tsEx := range updatedTSExes {
		_, _, err := cnf.addOrUpdateTransportServer(tsEx)
		if err != nil {
			errList = append(errList, fmt.Errorf("error adding or updating TransportServer %v/%v: %w", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, err))
		}
	}

	for _, key := range deletedKeys {
		err := cnf.deleteTransportServer(key)
		if err != nil {
			errList = append(errList, fmt.Errorf("error when removing TransportServer %v: %w", key, err))
		}
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		errList = append(errList, fmt.Errorf("error when updating TransportServers: %w", err))
	}

	return errList
}

// BatchDeleteVirtualServers takes a list of VirtualServer resource keys, deletes their configuration, and reloads once
func (cnf *Configurator) BatchDeleteVirtualServers(deletedKeys []string) []error {
	var errList []error
	for _, key := range deletedKeys {
		err := cnf.DeleteVirtualServer(key, true)
		if err != nil {
			errList = append(errList, fmt.Errorf("error when removing VirtualServer %v: %w", key, err))
		}
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		errList = append(errList, fmt.Errorf("error when reloading NGINX for deleted VirtualServers: %w", err))
	}

	return errList
}

// BatchDeleteIngresses takes a list of Ingress resource keys, deletes their configuration, and reloads once
func (cnf *Configurator) BatchDeleteIngresses(deletedKeys []string) []error {
	var errList []error
	for _, key := range deletedKeys {
		err := cnf.DeleteIngress(key, true)
		if err != nil {
			errList = append(errList, fmt.Errorf("error when removing Ingress %v: %w", key, err))
		}
	}

	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		errList = append(errList, fmt.Errorf("error when reloading NGINX for deleted Ingresses: %w", err))
	}

	return errList
}

func keyToFileName(key string) string {
	return strings.Replace(key, "/", "-", -1)
}

func objectMetaToFileName(meta *meta_v1.ObjectMeta) string {
	return meta.Namespace + "-" + meta.Name
}

func generateNamespaceNameKey(objectMeta *meta_v1.ObjectMeta) string {
	return fmt.Sprintf("%s/%s", objectMeta.Namespace, objectMeta.Name)
}

func getFileNameForVirtualServer(virtualServer *conf_v1.VirtualServer) string {
	return fmt.Sprintf("vs_%s_%s", virtualServer.Namespace, virtualServer.Name)
}

func getFileNameForTransportServer(transportServer *conf_v1.TransportServer) string {
	return fmt.Sprintf("ts_%s_%s", transportServer.Namespace, transportServer.Name)
}

func getFileNameForVirtualServerFromKey(key string) string {
	replaced := strings.Replace(key, "/", "_", -1)
	return fmt.Sprintf("vs_%s", replaced)
}

func getFileNameForTransportServerFromKey(key string) string {
	replaced := strings.Replace(key, "/", "_", -1)
	return fmt.Sprintf("ts_%s", replaced)
}

// HasIngress checks if the Ingress resource is present in NGINX configuration.
func (cnf *Configurator) HasIngress(ing *networking.Ingress) bool {
	name := objectMetaToFileName(&ing.ObjectMeta)
	_, exists := cnf.ingresses[name]
	return exists
}

// HasMinion checks if the minion Ingress resource of the master is present in NGINX configuration.
func (cnf *Configurator) HasMinion(master *networking.Ingress, minion *networking.Ingress) bool {
	masterName := objectMetaToFileName(&master.ObjectMeta)

	if _, exists := cnf.minions[masterName]; !exists {
		return false
	}

	return cnf.minions[masterName][objectMetaToFileName(&minion.ObjectMeta)]
}

// IsResolverConfigured checks if a DNS resolver is present in NGINX configuration.
func (cnf *Configurator) IsResolverConfigured() bool {
	return len(cnf.CfgParams.ResolverAddresses) != 0
}

// GetIngressCounts returns the total count of Ingress resources that are handled by the Ingress Controller grouped by their type
func (cnf *Configurator) GetIngressCounts() map[string]int {
	counters := map[string]int{
		"master":  0,
		"regular": 0,
		"minion":  0,
	}

	// cnf.ingresses contains only master and regular Ingress Resources
	for _, ing := range cnf.ingresses {
		if ing.Ingress.Annotations["nginx.org/mergeable-ingress-type"] == "master" {
			counters["master"]++
		} else {
			counters["regular"]++
		}
	}

	for _, minion := range cnf.minions {
		counters["minion"] += len(minion)
	}

	return counters
}

// GetIngressAnnotations returns a list of annotation keys set across all Ingress resources
func (cnf *Configurator) GetIngressAnnotations() []string {
	if cnf == nil || cnf.ingresses == nil {
		return nil
	}

	annotationSet := make(map[string]bool)
	annotationSet = cnf.getMinionIngressAnnotations(annotationSet)
	annotationSet = cnf.getStandardIngressAnnotations(annotationSet)

	var annotations []string
	for key := range annotationSet {
		annotations = append(annotations, key)
	}

	return annotations
}

// getStandardIngressAnnotations returns a map of allowedAnnotations detected in Standard or Master Ingresses
func (cnf *Configurator) getStandardIngressAnnotations(annotationSet map[string]bool) map[string]bool {
	for _, ing := range cnf.ingresses {
		if ing != nil && ing.Ingress != nil && ing.Ingress.Annotations != nil {
			for key := range ing.Ingress.Annotations {
				for _, allowedAnnotationKey := range allowedAnnotationKeys {
					if strings.Contains(key, allowedAnnotationKey) {
						annotationSet[key] = true
					}
				}
			}
		}
	}
	return annotationSet
}

// getMinionIngressAnnotations returns a map of allowedAnnotations detected in Minion Ingresses
func (cnf *Configurator) getMinionIngressAnnotations(annotationSet map[string]bool) map[string]bool {
	for _, ing := range cnf.mergeableIngresses {
		for _, minionIng := range ing.Minions {
			if minionIng != nil && minionIng.Ingress.Annotations != nil {
				for key := range minionIng.Ingress.Annotations {
					for _, allowedAnnotationKey := range allowedAnnotationKeys {
						if strings.Contains(key, allowedAnnotationKey) {
							annotationSet[key] = true
						}
					}
				}
			}
		}
	}
	return annotationSet
}

// GetVirtualServerCounts returns the total count of
// VirtualServer and VirtualServerRoute resources that are handled by the Ingress Controller
func (cnf *Configurator) GetVirtualServerCounts() (int, int) {
	vsCount := len(cnf.virtualServers)
	vsrCount := 0
	for _, vs := range cnf.virtualServers {
		vsrCount += len(vs.VirtualServerRoutes)
	}
	return vsCount, vsrCount
}

// GetTransportServerCounts returns the total count of
// TransportServer resources that are handled by the Ingress Controller
func (cnf *Configurator) GetTransportServerCounts() (tsCount int) {
	return len(cnf.transportServers)
}

// AddOrUpdateSpiffeCerts writes Spiffe certs and keys to disk and reloads NGINX
func (cnf *Configurator) AddOrUpdateSpiffeCerts(svidResponse *workloadapi.X509Context) error {
	svid := svidResponse.DefaultSVID()
	trustDomain := svid.ID.TrustDomain()
	caBundle, err := svidResponse.Bundles.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		return fmt.Errorf("error parsing CA bundle from SPIFFE SVID response: %w", err)
	}

	pemBundle, err := caBundle.Marshal()
	if err != nil {
		return fmt.Errorf("unable to marshal X.509 SVID Bundle: %w", err)
	}

	pemCerts, pemKey, err := svid.Marshal()
	if err != nil {
		return fmt.Errorf("unable to marshal X.509 SVID: %w", err)
	}

	cnf.nginxManager.CreateSecret(spiffeKeyFileName, pemKey, spiffeKeyFileMode)
	cnf.nginxManager.CreateSecret(spiffeCertFileName, pemCerts, spiffeCertsFileMode)
	cnf.nginxManager.CreateSecret(spiffeBundleFileName, pemBundle, spiffeCertsFileMode)

	err = cnf.Reload(nginx.ReloadForOtherUpdate)
	if err != nil {
		return fmt.Errorf("error when reloading NGINX when updating the SPIFFE Certs: %w", err)
	}
	return nil
}

func (cnf *Configurator) updateApResources(ingEx *IngressEx) *AppProtectResources {
	var apResources AppProtectResources

	if ingEx.AppProtectPolicy != nil {
		policyFileName := appProtectPolicyFileNameFromUnstruct(ingEx.AppProtectPolicy)
		policyContent := generateApResourceFileContent(ingEx.AppProtectPolicy)
		cnf.nginxManager.CreateAppProtectResourceFile(policyFileName, policyContent)
		apResources.AppProtectPolicy = policyFileName
	}

	for _, logConf := range ingEx.AppProtectLogs {
		logConfFileName := appProtectLogConfFileNameFromUnstruct(logConf.LogConf)
		logConfContent := generateApResourceFileContent(logConf.LogConf)
		cnf.nginxManager.CreateAppProtectResourceFile(logConfFileName, logConfContent)
		apResources.AppProtectLogconfs = append(apResources.AppProtectLogconfs, logConfFileName+" "+logConf.Dest)
	}

	return &apResources
}

func (cnf *Configurator) updateDosResource(dosEx *DosEx) {
	if dosEx != nil {
		if dosEx.DosProtected != nil {
			allowListFileName := appProtectDosAllowListFileName(dosEx.DosProtected.GetNamespace(), dosEx.DosProtected.GetName())
			allowListContent := generateApDosAllowListFileContent(dosEx.DosProtected.Spec.AllowList)
			cnf.nginxManager.CreateAppProtectResourceFile(allowListFileName, allowListContent)
		}
		if dosEx.DosPolicy != nil {
			policyFileName := appProtectDosPolicyFileName(dosEx.DosPolicy.GetNamespace(), dosEx.DosPolicy.GetName())
			policyContent := generateApResourceFileContent(dosEx.DosPolicy)
			cnf.nginxManager.CreateAppProtectResourceFile(policyFileName, policyContent)
		}
		if dosEx.DosLogConf != nil {
			logConfFileName := appProtectDosLogConfFileName(dosEx.DosLogConf.GetNamespace(), dosEx.DosLogConf.GetName())
			logConfContent := generateApResourceFileContent(dosEx.DosLogConf)
			cnf.nginxManager.CreateAppProtectResourceFile(logConfFileName, logConfContent)
		}
	}
}

func (cnf *Configurator) updateApResourcesForVs(vsEx *VirtualServerEx) *appProtectResourcesForVS {
	resources := newAppProtectVSResourcesForVS()

	for apPolKey, apPol := range vsEx.ApPolRefs {
		policyFileName := appProtectPolicyFileNameFromUnstruct(apPol)
		policyContent := generateApResourceFileContent(apPol)
		cnf.nginxManager.CreateAppProtectResourceFile(policyFileName, policyContent)
		resources.Policies[apPolKey] = policyFileName
	}

	for logConfKey, logConf := range vsEx.LogConfRefs {
		logConfFileName := appProtectLogConfFileNameFromUnstruct(logConf)
		logConfContent := generateApResourceFileContent(logConf)
		cnf.nginxManager.CreateAppProtectResourceFile(logConfFileName, logConfContent)
		resources.LogConfs[logConfKey] = logConfFileName
	}

	return resources
}

func appProtectPolicyFileNameFromUnstruct(unst *unstructured.Unstructured) string {
	return fmt.Sprintf("%s%s_%s", appProtectPolicyFolder, unst.GetNamespace(), unst.GetName())
}

func appProtectLogConfFileNameFromUnstruct(unst *unstructured.Unstructured) string {
	return fmt.Sprintf("%s%s_%s", appProtectLogConfFolder, unst.GetNamespace(), unst.GetName())
}

func appProtectUserSigFileNameFromUnstruct(unst *unstructured.Unstructured) string {
	return fmt.Sprintf("%s%s_%s", appProtectUserSigFolder, unst.GetNamespace(), unst.GetName())
}

func generateDosLogDest(dest string) string {
	if dest == "stderr" {
		return dest
	}
	return "syslog:server=" + dest
}

func generateApResourceFileContent(apResource *unstructured.Unstructured) []byte {
	// Safe to ignore errors since validation already checked those
	spec, _, _ := unstructured.NestedMap(apResource.Object, "spec")
	data, _ := json.Marshal(spec)
	return data
}

func generateApDosAllowListFileContent(allowList []v1beta1.AllowListEntry) []byte {
	type IPAddress struct {
		IPAddress string `json:"ipAddress"`
	}

	type IPAddressList struct {
		IPAddresses   []IPAddress `json:"ipAddresses"`
		BlockRequests string      `json:"blockRequests"`
	}

	type Policy struct {
		IPAddressLists []IPAddressList `json:"ip-address-lists"`
	}

	type AllowListPolicy struct {
		Policy Policy `json:"policy"`
	}

	ipAddresses := make([]IPAddress, len(allowList))
	for i, entry := range allowList {
		ipAddresses[i] = IPAddress{IPAddress: entry.IPWithMask}
	}

	allowListPolicy := AllowListPolicy{
		Policy: Policy{
			IPAddressLists: []IPAddressList{
				{
					IPAddresses:   ipAddresses,
					BlockRequests: "transparent",
				},
			},
		},
	}

	data, err := json.Marshal(allowListPolicy)
	if err != nil {
		return nil
	}

	return data
}

// ResourceOperation represents a function that changes configuration in relation to an unstructured resource.
type ResourceOperation func(resource *v1beta1.DosProtectedResource, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error)

// AddOrUpdateAppProtectResource updates Ingresses and VirtualServers that use App Protect or App Protect DoS resources.
func (cnf *Configurator) AddOrUpdateAppProtectResource(resource *unstructured.Unstructured, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	warnings, err := cnf.addOrUpdateIngressesAndVirtualServers(ingExes, mergeableIngresses, vsExes)
	if err != nil {
		return warnings, fmt.Errorf("error when updating %v %v/%v: %w", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
	}

	err = cnf.Reload(nginx.ReloadForOtherUpdate)
	if err != nil {
		return warnings, fmt.Errorf("error when reloading NGINX when updating %v %v/%v: %w", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
	}

	return warnings, nil
}

// AddOrUpdateResourcesThatUseDosProtected updates Ingresses and VirtualServers that use DoS resources.
func (cnf *Configurator) AddOrUpdateResourcesThatUseDosProtected(ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	warnings, err := cnf.addOrUpdateIngressesAndVirtualServers(ingExes, mergeableIngresses, vsExes)
	if err != nil {
		return warnings, fmt.Errorf("error when updating resources that use Dos: %w", err)
	}

	err = cnf.Reload(nginx.ReloadForOtherUpdate)
	if err != nil {
		return warnings, fmt.Errorf("error when updating resources that use Dos: %w", err)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateIngressesAndVirtualServers(ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	allWarnings := newWarnings()
	allWeightUpdates := []WeightUpdate{}

	for _, ingEx := range ingExes {
		_, warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, fmt.Errorf("error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, m := range mergeableIngresses {
		_, warnings, err := cnf.addOrUpdateMergeableIngress(m)
		if err != nil {
			return allWarnings, fmt.Errorf("error adding or updating mergeableIngress %v/%v: %w", m.Master.Ingress.Namespace, m.Master.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, vs := range vsExes {
		_, warnings, weightUpdates, err := cnf.addOrUpdateVirtualServer(vs)
		if err != nil {
			return allWarnings, fmt.Errorf("error adding or updating VirtualServer %v/%v: %w", vs.VirtualServer.Namespace, vs.VirtualServer.Name, err)
		}
		allWeightUpdates = append(allWeightUpdates, weightUpdates...)
		allWarnings.Add(warnings)
	}

	for _, weightUpdate := range allWeightUpdates {
		cnf.nginxManager.UpsertSplitClientsKeyVal(weightUpdate.Zone, weightUpdate.Key, weightUpdate.Value)
	}

	return allWarnings, nil
}

// DeleteAppProtectPolicy updates Ingresses and VirtualServers that use AP Policy after that policy is deleted
func (cnf *Configurator) DeleteAppProtectPolicy(resource *unstructured.Unstructured, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	warnings := newWarnings()
	var err error
	if len(ingExes)+len(mergeableIngresses)+len(vsExes) > 0 {
		warnings, err = cnf.AddOrUpdateAppProtectResource(resource, ingExes, mergeableIngresses, vsExes)
	}
	cnf.nginxManager.DeleteAppProtectResourceFile(appProtectPolicyFileNameFromUnstruct(resource))
	return warnings, err
}

// DeleteAppProtectLogConf updates Ingresses and VirtualServers that use AP Log Configuration after that policy is deleted
func (cnf *Configurator) DeleteAppProtectLogConf(resource *unstructured.Unstructured, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	warnings := newWarnings()
	var err error
	if len(ingExes)+len(mergeableIngresses)+len(vsExes) > 0 {
		warnings, err = cnf.AddOrUpdateAppProtectResource(resource, ingExes, mergeableIngresses, vsExes)
	}
	cnf.nginxManager.DeleteAppProtectResourceFile(appProtectLogConfFileNameFromUnstruct(resource))
	return warnings, err
}

// RefreshAppProtectUserSigs writes all valid UDS files to fs and reloads NGINX
func (cnf *Configurator) RefreshAppProtectUserSigs(
	userSigs []*unstructured.Unstructured, delPols []string, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx,
) (Warnings, error) {
	allWarnings, err := cnf.addOrUpdateIngressesAndVirtualServers(ingExes, mergeableIngresses, vsExes)
	if err != nil {
		return allWarnings, err
	}

	for _, file := range delPols {
		cnf.nginxManager.DeleteAppProtectResourceFile(file)
	}

	var builder strings.Builder
	cnf.nginxManager.ClearAppProtectFolder(appProtectUserSigFolder)
	for _, sig := range userSigs {
		fName := appProtectUserSigFileNameFromUnstruct(sig)
		data := generateApResourceFileContent(sig)
		cnf.nginxManager.CreateAppProtectResourceFile(fName, data)
		fmt.Fprintf(&builder, "app_protect_user_defined_signatures %s;\n", fName)
	}
	cnf.nginxManager.CreateAppProtectResourceFile(appProtectUserSigIndex, []byte(builder.String()))
	return allWarnings, cnf.Reload(nginx.ReloadForOtherUpdate)
}

func appProtectDosPolicyFileName(namespace string, name string) string {
	return fmt.Sprintf("%s%s_%s.json", appProtectDosPolicyFolder, namespace, name)
}

func appProtectDosLogConfFileName(namespace string, name string) string {
	return fmt.Sprintf("%s%s_%s.json", appProtectDosLogConfFolder, namespace, name)
}

func appProtectDosAllowListFileName(namespace string, name string) string {
	return fmt.Sprintf("%s%s_%s.json", appProtectDosAllowListFolder, namespace, name)
}

// DeleteAppProtectDosPolicy updates Ingresses and VirtualServers that use AP Dos Policy after that policy is deleted
func (cnf *Configurator) DeleteAppProtectDosPolicy(resource *unstructured.Unstructured) {
	cnf.nginxManager.DeleteAppProtectResourceFile(appProtectDosPolicyFileName(resource.GetNamespace(), resource.GetName()))
}

// DeleteAppProtectDosLogConf updates Ingresses and VirtualServers that use AP Log Configuration after that policy is deleted
func (cnf *Configurator) DeleteAppProtectDosLogConf(resource *unstructured.Unstructured) {
	cnf.nginxManager.DeleteAppProtectResourceFile(appProtectDosLogConfFileName(resource.GetNamespace(), resource.GetName()))
}

// DeleteAppProtectDosAllowList updates Ingresses and VirtualServers that use AP Allow List Configuration after that policy is deleted
func (cnf *Configurator) DeleteAppProtectDosAllowList(obj *v1beta1.DosProtectedResource) {
	cnf.nginxManager.DeleteAppProtectResourceFile(appProtectDosAllowListFileName(obj.Namespace, obj.Name))
}

// AddInternalRouteConfig adds internal route server to NGINX Configuration and reloads NGINX
func (cnf *Configurator) AddInternalRouteConfig() error {
	cnf.staticCfgParams.EnableInternalRoutes = true
	cnf.staticCfgParams.InternalRouteServerName = fmt.Sprintf("%s.%s.svc", os.Getenv("POD_SERVICEACCOUNT"), os.Getenv("POD_NAMESPACE"))
	mainCfg := GenerateNginxMainConfig(cnf.staticCfgParams, cnf.CfgParams, cnf.MgmtCfgParams)
	mainCfgContent, err := cnf.templateExecutor.ExecuteMainConfigTemplate(mainCfg)
	if err != nil {
		return fmt.Errorf("error when writing main Config: %w", err)
	}
	cnf.nginxManager.CreateMainConfig(mainCfgContent)
	if err := cnf.Reload(nginx.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("error when reloading nginx: %w", err)
	}
	return nil
}

// AddOrUpdateSecret adds or updates a secret.
func (cnf *Configurator) AddOrUpdateSecret(secret *api_v1.Secret) string {
	switch secret.Type {
	case secrets.SecretTypeCA:
		name := objectMetaToFileName(&secret.ObjectMeta)
		crtSecretName := fmt.Sprintf("%s-%s", name, CACrtKey)
		crlSecretName := fmt.Sprintf("%s-%s", name, CACrlKey)
		return cnf.AddOrUpdateCASecret(secret, crtSecretName, crlSecretName)
	case secrets.SecretTypeJWK:
		return cnf.addOrUpdateJWKSecret(secret)
	case secrets.SecretTypeHtpasswd:
		return cnf.addOrUpdateHtpasswdSecret(secret)
	case secrets.SecretTypeOIDC:
		// OIDC ClientSecret is not required on the filesystem, it is written directly to the config file.
		return ""
	case secrets.SecretTypeAPIKey:
		// APIKey ClientSecret is not required on the filesystem, it is written directly to the config file.
		return ""
	case secrets.SecretTypeLicense:
		return ""
	default:
		return cnf.addOrUpdateTLSSecret(secret)
	}
}

// DeleteSecret deletes a secret.
func (cnf *Configurator) DeleteSecret(key string) {
	cnf.nginxManager.DeleteSecret(keyToFileName(key))
}

// DynamicSSLReloadEnabled is used to check if dynamic reloading of SSL certificates is enabled
func (cnf *Configurator) DynamicSSLReloadEnabled() bool {
	return cnf.isDynamicSSLReloadEnabled
}

// UpsertSplitClientsKeyVal upserts a key-value pair in a keyzal zone for weight changes without reloads.
func (cnf *Configurator) UpsertSplitClientsKeyVal(zoneName, key, value string) {
	cnf.nginxManager.UpsertSplitClientsKeyVal(zoneName, key, value)
}

// GetIngressControllerReplicas returns the number of ingresscontroller-replicas (previously stored via SetIngressControllerReplicas)
func (cnf *Configurator) GetIngressControllerReplicas() int {
	return cnf.ingressControllerReplicas
}

// SetIngressControllerReplicas sets the number of ingresscontroller-replicas
// Is used for calculating ratelimits
func (cnf *Configurator) SetIngressControllerReplicas(replicas int) {
	cnf.ingressControllerReplicas = replicas
}
