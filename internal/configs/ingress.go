package configs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
)

const emptyHost = ""

// AppProtectResources holds namespace names of App Protect resources relevant to an Ingress
type AppProtectResources struct {
	AppProtectPolicy   string
	AppProtectLogconfs []string
}

// AppProtectLog holds a single pair of log config and log destination
type AppProtectLog struct {
	LogConf *unstructured.Unstructured
	Dest    string
}

// IngressEx holds an Ingress along with the resources that are referenced in this Ingress.
type IngressEx struct {
	Ingress          *networking.Ingress
	Endpoints        map[string][]string
	HealthChecks     map[string]*api_v1.Probe
	ExternalNameSvcs map[string]bool
	PodsByIP         map[string]PodInfo
	ValidHosts       map[string]bool
	ValidMinionPaths map[string]bool
	AppProtectPolicy *unstructured.Unstructured
	AppProtectLogs   []AppProtectLog
	DosEx            *DosEx
	SecretRefs       map[string]*secrets.SecretReference
	ZoneSync         bool
}

// DosEx holds a DosProtectedResource and the dos policy and log confs it references.
type DosEx struct {
	DosProtected *v1beta1.DosProtectedResource
	DosPolicy    *unstructured.Unstructured
	DosLogConf   *unstructured.Unstructured
}

// JWTKey represents a secret that holds JSON Web Key.
type JWTKey struct {
	Name   string
	Secret *api_v1.Secret
}

func (ingEx *IngressEx) String() string {
	if ingEx.Ingress == nil {
		return "IngressEx has no Ingress"
	}

	return fmt.Sprintf("%v/%v", ingEx.Ingress.Namespace, ingEx.Ingress.Name)
}

// MergeableIngresses is a mergeable ingress of a master and minions.
type MergeableIngresses struct {
	Master  *IngressEx
	Minions []*IngressEx
}

// NginxCfgParams is a collection of parameters
// used by generateNginxCfg() and generateNginxCfgForMergeableIngresses()
type NginxCfgParams struct {
	staticParams              *StaticConfigParams
	ingEx                     *IngressEx
	mergeableIngs             *MergeableIngresses
	apResources               *AppProtectResources
	dosResource               *appProtectDosResource
	BaseCfgParams             *ConfigParams
	isMinion                  bool
	isPlus                    bool
	isResolverConfigured      bool
	isWildcardEnabled         bool
	ingressControllerReplicas int
}

//nolint:gocyclo
func generateNginxCfg(p NginxCfgParams) (version1.IngressNginxConfig, Warnings) {
	l := nl.LoggerFromContext(p.BaseCfgParams.Context)
	hasAppProtect := p.staticParams.MainAppProtectLoadModule
	hasAppProtectDos := p.staticParams.MainAppProtectDosLoadModule

	cfgParams := parseAnnotations(p.ingEx, p.BaseCfgParams, p.isPlus, hasAppProtect, hasAppProtectDos, p.staticParams.EnableInternalRoutes, p.staticParams.IsDirectiveAutoadjustEnabled)

	wsServices := getWebsocketServices(p.ingEx)
	spServices := getSessionPersistenceServices(p.BaseCfgParams.Context, p.ingEx)
	rewrites := getRewrites(p.BaseCfgParams.Context, p.ingEx)
	sslServices := getSSLServices(p.ingEx)
	grpcServices := getGrpcServices(p.ingEx)

	upstreams := make(map[string]version1.Upstream)
	healthChecks := make(map[string]version1.HealthCheck)

	// HTTP2 is required for gRPC to function
	if len(grpcServices) > 0 && !cfgParams.HTTP2 {
		nl.Errorf(l, "Ingress %s/%s: annotation nginx.org/grpc-services requires HTTP2, ignoring", p.ingEx.Ingress.Namespace, p.ingEx.Ingress.Name)
		grpcServices = make(map[string]bool)
	}

	if p.ingEx.Ingress.Spec.DefaultBackend != nil {
		name := getNameForUpstream(p.ingEx.Ingress, emptyHost, p.ingEx.Ingress.Spec.DefaultBackend)
		upstream := createUpstream(p.ingEx, name, p.ingEx.Ingress.Spec.DefaultBackend, spServices[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name], &cfgParams,
			p.isPlus, p.isResolverConfigured, p.staticParams.EnableLatencyMetrics)
		upstreams[name] = upstream

		if cfgParams.HealthCheckEnabled {
			if hc, exists := p.ingEx.HealthChecks[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name+GetBackendPortAsString(p.ingEx.Ingress.Spec.DefaultBackend.Service.Port)]; exists {
				healthChecks[name] = createHealthCheck(hc, name, &cfgParams)
			}
		}
	}

	allWarnings := newWarnings()

	var servers []version1.Server
	var limitReqZones []version1.LimitReqZone

	for _, rule := range p.ingEx.Ingress.Spec.Rules {
		// skipping invalid hosts
		if !p.ingEx.ValidHosts[rule.Host] {
			continue
		}

		httpIngressRuleValue := rule.HTTP

		if httpIngressRuleValue == nil {
			// the code in this loop expects non-nil
			httpIngressRuleValue = &networking.HTTPIngressRuleValue{}
		}

		serverName := rule.Host

		statusZone := rule.Host

		server := version1.Server{
			Name:                  serverName,
			ServerTokens:          cfgParams.ServerTokens,
			HTTP2:                 cfgParams.HTTP2,
			RedirectToHTTPS:       cfgParams.RedirectToHTTPS,
			SSLRedirect:           cfgParams.SSLRedirect,
			ProxyProtocol:         cfgParams.ProxyProtocol,
			HSTS:                  cfgParams.HSTS,
			HSTSMaxAge:            cfgParams.HSTSMaxAge,
			HSTSIncludeSubdomains: cfgParams.HSTSIncludeSubdomains,
			HSTSBehindProxy:       cfgParams.HSTSBehindProxy,
			StatusZone:            statusZone,
			RealIPHeader:          cfgParams.RealIPHeader,
			SetRealIPFrom:         cfgParams.SetRealIPFrom,
			RealIPRecursive:       cfgParams.RealIPRecursive,
			ProxyHideHeaders:      cfgParams.ProxyHideHeaders,
			ProxyPassHeaders:      cfgParams.ProxyPassHeaders,
			ServerSnippets:        cfgParams.ServerSnippets,
			Ports:                 cfgParams.Ports,
			SSLPorts:              cfgParams.SSLPorts,
			TLSPassthrough:        p.staticParams.TLSPassthrough,
			AppProtectEnable:      cfgParams.AppProtectEnable,
			AppProtectLogEnable:   cfgParams.AppProtectLogEnable,
			SpiffeCerts:           cfgParams.SpiffeServerCerts,
			DisableIPV6:           p.staticParams.DisableIPV6,
		}

		warnings := addSSLConfig(&server, p.ingEx.Ingress, rule.Host, p.ingEx.Ingress.Spec.TLS, p.ingEx.SecretRefs, p.isWildcardEnabled)
		allWarnings.Add(warnings)

		if hasAppProtect {
			server.AppProtectPolicy = p.apResources.AppProtectPolicy
			server.AppProtectLogConfs = p.apResources.AppProtectLogconfs
		}

		if hasAppProtectDos && p.dosResource != nil {
			server.AppProtectDosEnable = p.dosResource.AppProtectDosEnable
			server.AppProtectDosLogEnable = p.dosResource.AppProtectDosLogEnable
			server.AppProtectDosMonitorURI = p.dosResource.AppProtectDosMonitorURI
			server.AppProtectDosMonitorProtocol = p.dosResource.AppProtectDosMonitorProtocol
			server.AppProtectDosMonitorTimeout = p.dosResource.AppProtectDosMonitorTimeout
			server.AppProtectDosName = p.dosResource.AppProtectDosName
			server.AppProtectDosAllowListPath = p.dosResource.AppProtectDosAllowListPath
			server.AppProtectDosAccessLogDst = p.dosResource.AppProtectDosAccessLogDst
			server.AppProtectDosPolicyFile = p.dosResource.AppProtectDosPolicyFile
			server.AppProtectDosLogConfFile = p.dosResource.AppProtectDosLogConfFile
		}

		if !p.isMinion && cfgParams.JWTKey != "" {
			jwtAuth, redirectLoc, warnings := generateJWTConfig(p.ingEx.Ingress, p.ingEx.SecretRefs, &cfgParams, getNameForRedirectLocation(p.ingEx.Ingress))
			server.JWTAuth = jwtAuth
			if redirectLoc != nil {
				server.JWTRedirectLocations = append(server.JWTRedirectLocations, *redirectLoc)
			}
			allWarnings.Add(warnings)
		}

		if !p.isMinion && cfgParams.BasicAuthSecret != "" {
			basicAuth, warnings := generateBasicAuthConfig(p.ingEx.Ingress, p.ingEx.SecretRefs, &cfgParams)
			server.BasicAuth = basicAuth
			allWarnings.Add(warnings)
		}

		var locations []version1.Location
		healthChecks := make(map[string]version1.HealthCheck)

		rootLocation := false

		grpcOnly := true
		if len(grpcServices) > 0 {
			for _, path := range httpIngressRuleValue.Paths {
				if _, exists := grpcServices[path.Backend.Service.Name]; !exists {
					grpcOnly = false
					break
				}
			}
		} else {
			grpcOnly = false
		}

		for i := range httpIngressRuleValue.Paths {
			path := httpIngressRuleValue.Paths[i]
			// skip invalid paths for minions
			if p.isMinion && !p.ingEx.ValidMinionPaths[path.Path] {
				continue
			}

			upsName := getNameForUpstream(p.ingEx.Ingress, rule.Host, &path.Backend)

			if cfgParams.HealthCheckEnabled {
				if hc, exists := p.ingEx.HealthChecks[path.Backend.Service.Name+GetBackendPortAsString(path.Backend.Service.Port)]; exists {
					healthChecks[upsName] = createHealthCheck(hc, upsName, &cfgParams)
				}
			}

			if _, exists := upstreams[upsName]; !exists {
				upstream := createUpstream(p.ingEx, upsName, &path.Backend, spServices[path.Backend.Service.Name], &cfgParams, p.isPlus, p.isResolverConfigured, p.staticParams.EnableLatencyMetrics)
				upstreams[upsName] = upstream
			}

			ssl := isSSLEnabled(sslServices[path.Backend.Service.Name], cfgParams, p.staticParams)
			proxySSLName := generateProxySSLName(path.Backend.Service.Name, p.ingEx.Ingress.Namespace)
			loc := createLocation(pathOrDefault(path.Path), upstreams[upsName], &cfgParams, wsServices[path.Backend.Service.Name], rewrites[path.Backend.Service.Name],
				ssl, grpcServices[path.Backend.Service.Name], proxySSLName, path.PathType, path.Backend.Service.Name)

			if p.isMinion && cfgParams.JWTKey != "" {
				jwtAuth, redirectLoc, warnings := generateJWTConfig(p.ingEx.Ingress, p.ingEx.SecretRefs, &cfgParams, getNameForRedirectLocation(p.ingEx.Ingress))
				loc.JWTAuth = jwtAuth
				if redirectLoc != nil {
					server.JWTRedirectLocations = append(server.JWTRedirectLocations, *redirectLoc)
				}
				allWarnings.Add(warnings)
			}

			if p.isMinion && cfgParams.BasicAuthSecret != "" {
				basicAuth, warnings := generateBasicAuthConfig(p.ingEx.Ingress, p.ingEx.SecretRefs, &cfgParams)
				loc.BasicAuth = basicAuth
				allWarnings.Add(warnings)
			}

			if cfgParams.LimitReqRate != "" {
				zoneName := p.ingEx.Ingress.Namespace + "/" + p.ingEx.Ingress.Name
				if p.ingEx.ZoneSync {
					zoneName = fmt.Sprintf("%v_sync", zoneName)
				}
				loc.LimitReq = &version1.LimitReq{
					Zone:       zoneName,
					Burst:      cfgParams.LimitReqBurst,
					Delay:      cfgParams.LimitReqDelay,
					NoDelay:    cfgParams.LimitReqNoDelay,
					DryRun:     cfgParams.LimitReqDryRun,
					LogLevel:   cfgParams.LimitReqLogLevel,
					RejectCode: cfgParams.LimitReqRejectCode,
				}
				if !limitReqZoneExists(limitReqZones, zoneName) {
					rate := cfgParams.LimitReqRate
					if cfgParams.LimitReqScale && p.ingressControllerReplicas > 0 {
						if p.ingEx.ZoneSync {
							warningText := fmt.Sprintf("Ingress %s/%s: both zone sync and rate limit scale are enabled, the rate limit scale value will not be used.", p.ingEx.Ingress.Namespace, p.ingEx.Ingress.Name)
							nl.Warn(l, warningText)
						} else {
							rate = scaleRatelimit(rate, p.ingressControllerReplicas)
						}
					}
					limitReqZones = append(limitReqZones, version1.LimitReqZone{
						Name: zoneName,
						Key:  cfgParams.LimitReqKey,
						Size: cfgParams.LimitReqZoneSize,
						Rate: rate,
						Sync: p.ingEx.ZoneSync,
					})
				}
			}

			locations = append(locations, loc)

			if loc.Path == "/" {
				rootLocation = true
			}
		}

		if !rootLocation && p.ingEx.Ingress.Spec.DefaultBackend != nil {
			upsName := getNameForUpstream(p.ingEx.Ingress, emptyHost, p.ingEx.Ingress.Spec.DefaultBackend)
			ssl := isSSLEnabled(sslServices[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name], cfgParams, p.staticParams)
			proxySSLName := generateProxySSLName(p.ingEx.Ingress.Spec.DefaultBackend.Service.Name, p.ingEx.Ingress.Namespace)
			pathtype := networking.PathTypePrefix

			loc := createLocation(pathOrDefault("/"), upstreams[upsName], &cfgParams, wsServices[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name], rewrites[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name],
				ssl, grpcServices[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name], proxySSLName, &pathtype, p.ingEx.Ingress.Spec.DefaultBackend.Service.Name)
			locations = append(locations, loc)

			if cfgParams.HealthCheckEnabled {
				if hc, exists := p.ingEx.HealthChecks[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name+GetBackendPortAsString(p.ingEx.Ingress.Spec.DefaultBackend.Service.Port)]; exists {
					healthChecks[upsName] = createHealthCheck(hc, upsName, &cfgParams)
				}
			}

			if _, exists := grpcServices[p.ingEx.Ingress.Spec.DefaultBackend.Service.Name]; !exists {
				grpcOnly = false
			}
		}

		server.Locations = locations
		server.HealthChecks = healthChecks
		server.GRPCOnly = grpcOnly

		servers = append(servers, server)
	}

	var keepalive string
	if cfgParams.Keepalive > 0 {
		keepalive = fmt.Sprint(cfgParams.Keepalive)
	}

	return version1.IngressNginxConfig{
		Upstreams: upstreamMapToSlice(upstreams),
		Servers:   servers,
		Keepalive: keepalive,
		Ingress: version1.Ingress{
			Name:        p.ingEx.Ingress.Name,
			Namespace:   p.ingEx.Ingress.Namespace,
			Annotations: p.ingEx.Ingress.Annotations,
		},
		SpiffeClientCerts:       p.staticParams.NginxServiceMesh && !cfgParams.SpiffeServerCerts,
		DynamicSSLReloadEnabled: p.staticParams.DynamicSSLReload,
		StaticSSLPath:           p.staticParams.StaticSSLPath,
		LimitReqZones:           limitReqZones,
	}, allWarnings
}

func generateJWTConfig(owner runtime.Object, secretRefs map[string]*secrets.SecretReference, cfgParams *ConfigParams,
	redirectLocationName string,
) (*version1.JWTAuth, *version1.JWTRedirectLocation, Warnings) {
	warnings := newWarnings()

	secretRef := secretRefs[cfgParams.JWTKey]
	var secretType api_v1.SecretType
	if secretRef.Secret != nil {
		secretType = secretRef.Secret.Type
	}
	if secretType != "" && secretType != secrets.SecretTypeJWK {
		warnings.AddWarningf(owner, "JWK secret %s is of a wrong type '%s', must be '%s'", cfgParams.JWTKey, secretType, secrets.SecretTypeJWK)
	} else if secretRef.Error != nil {
		warnings.AddWarningf(owner, "JWK secret %s is invalid: %v", cfgParams.JWTKey, secretRef.Error)
	}

	// Key is configured for all cases, including when the secret is (1) invalid or (2) of a wrong type.
	// For (1) and (2), NGINX Plus will reject such a key at runtime and return 500 to clients.
	jwtAuth := &version1.JWTAuth{
		Key:   secretRef.Path,
		Realm: cfgParams.JWTRealm,
		Token: cfgParams.JWTToken,
	}

	var redirectLocation *version1.JWTRedirectLocation

	if cfgParams.JWTLoginURL != "" {
		jwtAuth.RedirectLocationName = redirectLocationName
		redirectLocation = &version1.JWTRedirectLocation{
			Name:     redirectLocationName,
			LoginURL: cfgParams.JWTLoginURL,
		}
	}

	return jwtAuth, redirectLocation, warnings
}

func generateBasicAuthConfig(owner runtime.Object, secretRefs map[string]*secrets.SecretReference, cfgParams *ConfigParams) (*version1.BasicAuth, Warnings) {
	warnings := newWarnings()

	secretRef := secretRefs[cfgParams.BasicAuthSecret]
	var secretType api_v1.SecretType
	if secretRef.Secret != nil {
		secretType = secretRef.Secret.Type
	}
	if secretType != "" && secretType != secrets.SecretTypeHtpasswd {
		warnings.AddWarningf(owner, "Basic auth secret %s is of a wrong type '%s', must be '%s'", cfgParams.BasicAuthSecret, secretType, secrets.SecretTypeHtpasswd)
	} else if secretRef.Error != nil {
		warnings.AddWarningf(owner, "Basic auth secret %s is invalid: %v", cfgParams.BasicAuthSecret, secretRef.Error)
	}

	basicAuth := &version1.BasicAuth{
		Secret: secretRef.Path,
		Realm:  cfgParams.BasicAuthRealm,
	}

	return basicAuth, warnings
}

func addSSLConfig(server *version1.Server, owner runtime.Object, host string, ingressTLS []networking.IngressTLS,
	secretRefs map[string]*secrets.SecretReference, isWildcardEnabled bool,
) Warnings {
	warnings := newWarnings()

	var tlsEnabled bool
	var tlsSecret string

	for _, tls := range ingressTLS {
		for _, h := range tls.Hosts {
			if h == host {
				tlsEnabled = true
				tlsSecret = tls.SecretName
				break
			}
		}
	}

	if !tlsEnabled {
		return warnings
	}

	var pemFile string
	var rejectHandshake bool

	if tlsSecret != "" {
		secretRef := secretRefs[tlsSecret]
		var secretType api_v1.SecretType
		if secretRef.Secret != nil {
			secretType = secretRef.Secret.Type
		}
		if secretType != "" && secretType != api_v1.SecretTypeTLS {
			rejectHandshake = true
			warnings.AddWarningf(owner, "TLS secret %s is of a wrong type '%s', must be '%s'", tlsSecret, secretType, api_v1.SecretTypeTLS)
		} else if secretRef.Error != nil {
			rejectHandshake = true
			warnings.AddWarningf(owner, "TLS secret %s is invalid: %v", tlsSecret, secretRef.Error)
		} else {
			pemFile = secretRef.Path
		}
	} else if isWildcardEnabled {
		pemFile = pemFileNameForWildcardTLSSecret
	} else {
		rejectHandshake = true
		warnings.AddWarningf(owner, "TLS termination for host '%s' requires specifying a TLS secret or configuring a global wildcard TLS secret", host)
	}

	server.SSL = true
	server.SSLCertificate = pemFile
	server.SSLCertificateKey = pemFile
	server.SSLRejectHandshake = rejectHandshake

	return warnings
}

func generateIngressPath(path string, pathType *networking.PathType) string {
	if pathType == nil {
		return path
	}
	if *pathType == networking.PathTypeExact {
		path = "= " + path
	}

	return path
}

func createLocation(path string, upstream version1.Upstream, cfg *ConfigParams, websocket bool, rewrite string, ssl bool, grpc bool, proxySSLName string, pathType *networking.PathType, serviceName string) version1.Location {
	loc := version1.Location{
		Path:                 generateIngressPath(path, pathType),
		Upstream:             upstream,
		ProxyConnectTimeout:  cfg.ProxyConnectTimeout,
		ProxyReadTimeout:     cfg.ProxyReadTimeout,
		ProxySendTimeout:     cfg.ProxySendTimeout,
		ProxySetHeaders:      cfg.ProxySetHeaders,
		ClientMaxBodySize:    cfg.ClientMaxBodySize,
		Websocket:            websocket,
		Rewrite:              rewrite,
		SSL:                  ssl,
		GRPC:                 grpc,
		ProxyBuffering:       cfg.ProxyBuffering,
		ProxyBuffers:         cfg.ProxyBuffers,
		ProxyBufferSize:      cfg.ProxyBufferSize,
		ProxyBusyBuffersSize: cfg.ProxyBusyBuffersSize,
		ProxyMaxTempFileSize: cfg.ProxyMaxTempFileSize,
		ProxySSLName:         proxySSLName,
		LocationSnippets:     cfg.LocationSnippets,
		ServiceName:          serviceName,
	}

	return loc
}

// upstreamRequiresQueue checks if the upstream requires a queue.
// Mandatory Health Checks can cause nginx to return errors on reload, since all Upstreams start
// Unhealthy. By adding a queue to the Upstream we can avoid returning errors, at the cost of a short delay.
func upstreamRequiresQueue(name string, ingEx *IngressEx, cfg *ConfigParams) (n int64, timeout int64) {
	if cfg.HealthCheckEnabled && cfg.HealthCheckMandatory && cfg.HealthCheckMandatoryQueue > 0 {
		if hc, exists := ingEx.HealthChecks[name]; exists {
			return cfg.HealthCheckMandatoryQueue, int64(hc.TimeoutSeconds)
		}
	}
	return 0, 0
}

func createUpstream(ingEx *IngressEx, name string, backend *networking.IngressBackend, stickyCookie string, cfg *ConfigParams,
	isPlus bool, isResolverConfigured bool, isLatencyMetricsEnabled bool,
) version1.Upstream {
	var ups version1.Upstream
	labels := version1.UpstreamLabels{
		Service:           backend.Service.Name,
		ResourceType:      "ingress",
		ResourceName:      ingEx.Ingress.Name,
		ResourceNamespace: ingEx.Ingress.Namespace,
	}
	l := nl.LoggerFromContext(cfg.Context)
	if isPlus {
		queue, timeout := upstreamRequiresQueue(backend.Service.Name+GetBackendPortAsString(backend.Service.Port), ingEx, cfg)
		ups = version1.Upstream{Name: name, StickyCookie: stickyCookie, Queue: queue, QueueTimeout: timeout, UpstreamLabels: labels}
	} else {
		ups = version1.NewUpstreamWithDefaultServer(name)
		if isLatencyMetricsEnabled {
			ups.UpstreamLabels = labels
		}
	}

	endps, exists := ingEx.Endpoints[backend.Service.Name+GetBackendPortAsString(backend.Service.Port)]
	if exists {
		var upsServers []version1.UpstreamServer
		// Always false for NGINX OSS
		_, isExternalNameSvc := ingEx.ExternalNameSvcs[backend.Service.Name]
		if isExternalNameSvc && !isResolverConfigured {
			nl.Warnf(l, "A resolver must be configured for Type ExternalName service %s, no upstream servers will be created", backend.Service.Name)
			endps = []string{}
		}

		for _, endp := range endps {
			upsServers = append(upsServers, version1.UpstreamServer{
				Address:     endp,
				MaxFails:    cfg.MaxFails,
				MaxConns:    cfg.MaxConns,
				FailTimeout: cfg.FailTimeout,
				SlowStart:   cfg.SlowStart,
				Resolve:     isExternalNameSvc,
			})
		}
		if len(upsServers) > 0 {
			sort.Slice(upsServers, func(i, j int) bool {
				return upsServers[i].Address < upsServers[j].Address
			})
			ups.UpstreamServers = upsServers
		}
	}

	ups.LBMethod = cfg.LBMethod
	ups.UpstreamZoneSize = cfg.UpstreamZoneSize
	return ups
}

func createHealthCheck(hc *api_v1.Probe, upstreamName string, cfg *ConfigParams) version1.HealthCheck {
	return version1.HealthCheck{
		UpstreamName:   upstreamName,
		Fails:          hc.FailureThreshold,
		Interval:       hc.PeriodSeconds,
		Passes:         hc.SuccessThreshold,
		URI:            hc.HTTPGet.Path,
		Scheme:         strings.ToLower(string(hc.HTTPGet.Scheme)),
		Mandatory:      cfg.HealthCheckMandatory,
		Headers:        headersToString(hc.HTTPGet.HTTPHeaders),
		TimeoutSeconds: int64(hc.TimeoutSeconds),
	}
}

func headersToString(headers []api_v1.HTTPHeader) map[string]string {
	m := make(map[string]string)
	for _, header := range headers {
		m[header.Name] = header.Value
	}
	return m
}

func pathOrDefault(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func getNameForUpstream(ing *networking.Ingress, host string, backend *networking.IngressBackend) string {
	return fmt.Sprintf("%v-%v-%v-%v-%v", ing.Namespace, ing.Name, host, backend.Service.Name, GetBackendPortAsString(backend.Service.Port))
}

func getNameForRedirectLocation(ing *networking.Ingress) string {
	return fmt.Sprintf("@login_url_%v-%v", ing.Namespace, ing.Name)
}

func upstreamMapToSlice(upstreams map[string]version1.Upstream) []version1.Upstream {
	keys := make([]string, 0, len(upstreams))
	for k := range upstreams {
		keys = append(keys, k)
	}

	// this ensures that the slice 'result' is sorted, which preserves the order of upstream servers
	// in the generated configuration file from one version to another and is also required for repeatable
	// Unit test results
	sort.Strings(keys)

	result := make([]version1.Upstream, 0, len(upstreams))

	for _, k := range keys {
		result = append(result, upstreams[k])
	}

	return result
}

func generateNginxCfgForMergeableIngresses(p NginxCfgParams) (version1.IngressNginxConfig, Warnings) {
	l := nl.LoggerFromContext(p.BaseCfgParams.Context)
	var masterServer version1.Server
	var locations []version1.Location
	var upstreams []version1.Upstream
	healthChecks := make(map[string]version1.HealthCheck)
	var limitReqZones []version1.LimitReqZone
	var keepalive string

	// replace master with a deepcopy because we will modify it
	originalMaster := p.mergeableIngs.Master.Ingress
	p.mergeableIngs.Master.Ingress = p.mergeableIngs.Master.Ingress.DeepCopy()

	removedAnnotations := filterMasterAnnotations(p.mergeableIngs.Master.Ingress.Annotations)
	if len(removedAnnotations) != 0 {
		nl.Errorf(l, "Ingress Resource %v/%v with the annotation 'nginx.org/mergeable-ingress-type' set to 'master' cannot contain the '%v' annotation(s). They will be ignored",
			p.mergeableIngs.Master.Ingress.Namespace, p.mergeableIngs.Master.Ingress.Name, strings.Join(removedAnnotations, ","))
	}
	isMinion := false

	masterNginxCfg, warnings := generateNginxCfg(NginxCfgParams{
		staticParams:              p.staticParams,
		ingEx:                     p.mergeableIngs.Master,
		apResources:               p.apResources,
		dosResource:               p.dosResource,
		isMinion:                  isMinion,
		isPlus:                    p.isPlus,
		BaseCfgParams:             p.BaseCfgParams,
		isResolverConfigured:      p.isResolverConfigured,
		isWildcardEnabled:         p.isWildcardEnabled,
		ingressControllerReplicas: p.ingressControllerReplicas,
	})

	// because p.mergeableIngs.Master.Ingress is a deepcopy of the original master
	// we need to change the key in the warnings to the original master
	if _, exists := warnings[p.mergeableIngs.Master.Ingress]; exists {
		warnings[originalMaster] = warnings[p.mergeableIngs.Master.Ingress]
		delete(warnings, p.mergeableIngs.Master.Ingress)
	}

	masterServer = masterNginxCfg.Servers[0]
	masterServer.Locations = []version1.Location{}

	upstreams = append(upstreams, masterNginxCfg.Upstreams...)

	if masterNginxCfg.Keepalive != "" {
		keepalive = masterNginxCfg.Keepalive
	}

	minions := p.mergeableIngs.Minions
	for _, minion := range minions {
		// replace minion with a deepcopy because we will modify it
		originalMinion := minion.Ingress
		minion.Ingress = minion.Ingress.DeepCopy()

		// Remove the default backend so that "/" will not be generated
		minion.Ingress.Spec.DefaultBackend = nil

		// Add acceptable master annotations to minion
		mergeMasterAnnotationsIntoMinion(minion.Ingress.Annotations, p.mergeableIngs.Master.Ingress.Annotations)

		removedAnnotations = filterMinionAnnotations(minion.Ingress.Annotations)
		if len(removedAnnotations) != 0 {
			nl.Errorf(l, "Ingress Resource %v/%v with the annotation 'nginx.org/mergeable-ingress-type' set to 'minion' cannot contain the %v annotation(s). They will be ignored",
				minion.Ingress.Namespace, minion.Ingress.Name, strings.Join(removedAnnotations, ","))
		}

		isMinion := true
		// App Protect Resources not allowed in minions - pass empty struct
		dummyApResources := &AppProtectResources{}
		dummyDosResource := &appProtectDosResource{}
		nginxCfg, minionWarnings := generateNginxCfg(NginxCfgParams{
			staticParams:              p.staticParams,
			ingEx:                     minion,
			apResources:               dummyApResources,
			dosResource:               dummyDosResource,
			isMinion:                  isMinion,
			isPlus:                    p.isPlus,
			BaseCfgParams:             p.BaseCfgParams,
			isResolverConfigured:      p.isResolverConfigured,
			isWildcardEnabled:         p.isWildcardEnabled,
			ingressControllerReplicas: p.ingressControllerReplicas,
		})
		warnings.Add(minionWarnings)

		// because minion.Ingress is a deepcopy of the original minion
		// we need to change the key in the warnings to the original minion
		if _, exists := warnings[minion.Ingress]; exists {
			warnings[originalMinion] = warnings[minion.Ingress]
			delete(warnings, minion.Ingress)
		}

		for _, server := range nginxCfg.Servers {
			for _, loc := range server.Locations {
				loc.MinionIngress = &nginxCfg.Ingress
				locations = append(locations, loc)
			}
			for hcName, healthCheck := range server.HealthChecks {
				healthChecks[hcName] = healthCheck
			}
			masterServer.JWTRedirectLocations = append(masterServer.JWTRedirectLocations, server.JWTRedirectLocations...)
		}

		upstreams = append(upstreams, nginxCfg.Upstreams...)
		limitReqZones = append(limitReqZones, nginxCfg.LimitReqZones...)
	}

	masterServer.HealthChecks = healthChecks
	masterServer.Locations = locations

	return version1.IngressNginxConfig{
		Servers:                 []version1.Server{masterServer},
		Upstreams:               upstreams,
		Keepalive:               keepalive,
		Ingress:                 masterNginxCfg.Ingress,
		SpiffeClientCerts:       p.staticParams.NginxServiceMesh && !p.BaseCfgParams.SpiffeServerCerts,
		DynamicSSLReloadEnabled: p.staticParams.DynamicSSLReload,
		StaticSSLPath:           p.staticParams.StaticSSLPath,
		LimitReqZones:           limitReqZones,
	}, warnings
}

func limitReqZoneExists(zones []version1.LimitReqZone, zoneName string) bool {
	for _, zone := range zones {
		if zone.Name == zoneName {
			return true
		}
	}
	return false
}

func isSSLEnabled(isSSLService bool, cfgParams ConfigParams, staticCfgParams *StaticConfigParams) bool {
	return isSSLService || staticCfgParams.NginxServiceMesh && !cfgParams.SpiffeServerCerts
}

// GetBackendPortAsString returns the port of a ServiceBackend of an Ingress resource as a string.
func GetBackendPortAsString(port networking.ServiceBackendPort) string {
	if port.Name != "" {
		return port.Name
	}
	return strconv.Itoa(int(port.Number))
}

// scaleRatelimit divides a given ratelimit by the given number of replicas, adjusting the unit and flooring the result as needed
func scaleRatelimit(ratelimit string, replicas int) string {
	if replicas < 1 {
		return ratelimit
	}

	match := rateRegexp.FindStringSubmatch(ratelimit)
	if match == nil {
		return ratelimit
	}

	number, err := strconv.Atoi(match[1])
	if err != nil {
		return ratelimit
	}

	numberf := float64(number) / float64(replicas)

	unit := match[2]
	if unit == "r/s" && numberf < 1 {
		numberf = numberf * 60
		unit = "r/m"
	}

	return strconv.Itoa(int(numberf)) + unit
}
