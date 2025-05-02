package configs

import (
	"fmt"
	"sort"
	"strings"

	api_v1 "k8s.io/api/core/v1"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

const nginxNonExistingUnixSocket = "unix:/var/lib/nginx/non-existing-unix-socket.sock"

// TransportServerEx holds a TransportServer along with the resources referenced by it.
type TransportServerEx struct {
	ListenerPort     int
	TransportServer  *conf_v1.TransportServer
	Endpoints        map[string][]string
	PodsByIP         map[string]string
	ExternalNameSvcs map[string]bool
	DisableIPV6      bool
	SecretRefs       map[string]*secrets.SecretReference
	IPv4             string
	IPv6             string
}

func (tsEx *TransportServerEx) String() string {
	if tsEx == nil {
		return "<nil>"
	}
	if tsEx.TransportServer == nil {
		return "TransportServerEx has no TransportServer"
	}
	return fmt.Sprintf("%s/%s", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name)
}

func newUpstreamNamerForTransportServer(transportServer *conf_v1.TransportServer) *upstreamNamer {
	return &upstreamNamer{
		prefix: fmt.Sprintf("ts_%s_%s", transportServer.Namespace, transportServer.Name),
	}
}

type transportServerConfigParams struct {
	transportServerEx      *TransportServerEx
	listenerPort           int
	isPlus                 bool
	isResolverConfigured   bool
	isDynamicReloadEnabled bool
	staticSSLPath          string
}

// generateTransportServerConfig generates a full configuration for a TransportServer.
func generateTransportServerConfig(p transportServerConfigParams) (*version2.TransportServerConfig, Warnings) {
	warnings := newWarnings()

	upstreamNamer := newUpstreamNamerForTransportServer(p.transportServerEx.TransportServer)

	upstreams, w := generateStreamUpstreams(p.transportServerEx, upstreamNamer, p.isPlus, p.isResolverConfigured)
	warnings.Add(w)

	healthCheck, match := generateTransportServerHealthCheck(p.transportServerEx.TransportServer.Spec.Action.Pass,
		upstreamNamer.GetNameForUpstream(p.transportServerEx.TransportServer.Spec.Action.Pass),
		p.transportServerEx.TransportServer.Spec.Upstreams)

	sslConfig, w := generateSSLConfig(p.transportServerEx.TransportServer, p.transportServerEx.TransportServer.Spec.TLS, p.transportServerEx.TransportServer.Namespace, p.transportServerEx.SecretRefs)
	warnings.Add(w)

	var proxyRequests, proxyResponses *int
	var connectTimeout, nextUpstreamTimeout string
	var nextUpstream bool
	var nextUpstreamTries int
	if p.transportServerEx.TransportServer.Spec.UpstreamParameters != nil {
		proxyRequests = p.transportServerEx.TransportServer.Spec.UpstreamParameters.UDPRequests
		proxyResponses = p.transportServerEx.TransportServer.Spec.UpstreamParameters.UDPResponses

		nextUpstream = p.transportServerEx.TransportServer.Spec.UpstreamParameters.NextUpstream
		if nextUpstream {
			nextUpstreamTries = p.transportServerEx.TransportServer.Spec.UpstreamParameters.NextUpstreamTries
			nextUpstreamTimeout = p.transportServerEx.TransportServer.Spec.UpstreamParameters.NextUpstreamTimeout
		}

		connectTimeout = p.transportServerEx.TransportServer.Spec.UpstreamParameters.ConnectTimeout
	}

	var proxyTimeout string
	if p.transportServerEx.TransportServer.Spec.SessionParameters != nil {
		proxyTimeout = p.transportServerEx.TransportServer.Spec.SessionParameters.Timeout
	}

	serverSnippets := generateSnippets(true, p.transportServerEx.TransportServer.Spec.ServerSnippets, []string{})

	streamSnippets := generateSnippets(true, p.transportServerEx.TransportServer.Spec.StreamSnippets, []string{})

	statusZone := p.transportServerEx.TransportServer.Spec.Listener.Name
	if p.transportServerEx.TransportServer.Spec.Listener.Name == conf_v1.TLSPassthroughListenerName {
		statusZone = p.transportServerEx.TransportServer.Spec.Host
	}
	host := p.transportServerEx.TransportServer.Spec.Host
	isTLSPassthrough := p.transportServerEx.TransportServer.Spec.Listener.Name == conf_v1.TLSPassthroughListenerName
	serverName := generateServerName(host, isTLSPassthrough)
	isUDP := p.transportServerEx.TransportServer.Spec.Listener.Protocol == "UDP"

	tsConfig := &version2.TransportServerConfig{
		Server: version2.StreamServer{
			ServerName:               serverName,
			TLSPassthrough:           isTLSPassthrough,
			UnixSocket:               generateUnixSocket(p.transportServerEx),
			Port:                     p.listenerPort,
			UDP:                      isUDP,
			StatusZone:               statusZone,
			ProxyRequests:            proxyRequests,
			ProxyResponses:           proxyResponses,
			ProxyPass:                upstreamNamer.GetNameForUpstream(p.transportServerEx.TransportServer.Spec.Action.Pass),
			Name:                     p.transportServerEx.TransportServer.Name,
			Namespace:                p.transportServerEx.TransportServer.Namespace,
			ProxyConnectTimeout:      generateTimeWithDefault(connectTimeout, "60s"),
			ProxyTimeout:             generateTimeWithDefault(proxyTimeout, "10m"),
			ProxyNextUpstream:        nextUpstream,
			ProxyNextUpstreamTimeout: generateTimeWithDefault(nextUpstreamTimeout, "0s"),
			ProxyNextUpstreamTries:   nextUpstreamTries,
			HealthCheck:              healthCheck,
			ServerSnippets:           serverSnippets,
			DisableIPV6:              p.transportServerEx.DisableIPV6,
			SSL:                      sslConfig,
			IPv4:                     p.transportServerEx.IPv4,
			IPv6:                     p.transportServerEx.IPv6,
		},
		Match:                   match,
		Upstreams:               upstreams,
		StreamSnippets:          streamSnippets,
		DynamicSSLReloadEnabled: p.isDynamicReloadEnabled,
		StaticSSLPath:           p.staticSSLPath,
	}
	return tsConfig, warnings
}

func generateUnixSocket(transportServerEx *TransportServerEx) string {
	if transportServerEx.TransportServer.Spec.Listener.Name == conf_v1.TLSPassthroughListenerName {
		return fmt.Sprintf("unix:/var/lib/nginx/passthrough-%s_%s.sock", transportServerEx.TransportServer.Namespace, transportServerEx.TransportServer.Name)
	}
	return ""
}

func generateSSLConfig(ts *conf_v1.TransportServer, tls *conf_v1.TransportServerTLS, namespace string, secretRefs map[string]*secrets.SecretReference) (*version2.StreamSSL, Warnings) {
	if tls == nil {
		return &version2.StreamSSL{Enabled: false}, nil
	}

	warnings := newWarnings()
	sslEnabled := true

	secretRef := secretRefs[fmt.Sprintf("%s/%s", namespace, tls.Secret)]
	var secretType api_v1.SecretType
	if secretRef.Secret != nil {
		secretType = secretRef.Secret.Type
	}
	name := secretRef.Path
	if secretType != "" && secretType != api_v1.SecretTypeTLS {
		errMsg := fmt.Sprintf("TLS secret %s is of a wrong type '%s', must be '%s'. SSL termination will not be enabled for this server.", tls.Secret, secretType, api_v1.SecretTypeTLS)
		warnings.AddWarning(ts, errMsg)
		sslEnabled = false
	} else if secretRef.Error != nil {
		errMsg := fmt.Sprintf("TLS secret %s is invalid: %v. SSL termination will not be enabled for this server.", tls.Secret, secretRef.Error)
		warnings.AddWarning(ts, errMsg)
		sslEnabled = false
	}

	ssl := version2.StreamSSL{
		Enabled:        sslEnabled,
		Certificate:    name,
		CertificateKey: name,
	}

	return &ssl, warnings
}

func generateStreamUpstreams(transportServerEx *TransportServerEx, upstreamNamer *upstreamNamer, isPlus bool, isResolverConfigured bool) ([]version2.StreamUpstream, Warnings) {
	warnings := newWarnings()
	var upstreams []version2.StreamUpstream

	for _, u := range transportServerEx.TransportServer.Spec.Upstreams {
		// subselector is not supported yet in TransportServer upstreams. That's why we pass "nil" here
		endpointsKey := GenerateEndpointsKey(transportServerEx.TransportServer.Namespace, u.Service, nil, uint16(u.Port))
		externalNameSvcKey := GenerateExternalNameSvcKey(transportServerEx.TransportServer.Namespace, u.Service)
		endpoints := transportServerEx.Endpoints[endpointsKey]

		_, isExternalNameSvc := transportServerEx.ExternalNameSvcs[externalNameSvcKey]
		if isExternalNameSvc && !isResolverConfigured {
			msgFmt := "Type ExternalName service %v in upstream %v will be ignored. To use ExternalName services, a resolver must be configured in the ConfigMap"
			warnings.AddWarningf(transportServerEx.TransportServer, msgFmt, u.Service, u.Name)
			endpoints = []string{}
		}

		var backupEndpoints []string
		if u.Backup != "" && u.BackupPort != nil {
			backupEnpointsKey := GenerateEndpointsKey(transportServerEx.TransportServer.Namespace, u.Backup, nil, *u.BackupPort)
			externalNameSvcKey = GenerateExternalNameSvcKey(transportServerEx.TransportServer.Namespace, u.Backup)

			backupEndpoints = transportServerEx.Endpoints[backupEnpointsKey]
			_, isExternalNameSvc = transportServerEx.ExternalNameSvcs[externalNameSvcKey]
			if isExternalNameSvc && !isResolverConfigured {
				msgFmt := "Type ExternalName service %v in upstream %v will be ignored. To use ExternalName services, a resolver must be configured in the ConfigMap"
				warnings.AddWarningf(transportServerEx.TransportServer, msgFmt, u.Backup, u.Name)
				backupEndpoints = []string{}
			}
		}

		ups := generateStreamUpstream(u, upstreamNamer, endpoints, backupEndpoints, isPlus)
		ups.Resolve = isExternalNameSvc
		ups.UpstreamLabels.Service = u.Service
		ups.UpstreamLabels.ResourceType = "transportserver"
		ups.UpstreamLabels.ResourceName = transportServerEx.TransportServer.Name
		ups.UpstreamLabels.ResourceNamespace = transportServerEx.TransportServer.Namespace

		upstreams = append(upstreams, ups)
	}
	sort.Slice(upstreams, func(i, j int) bool {
		return upstreams[i].Name < upstreams[j].Name
	})
	return upstreams, warnings
}

func generateTransportServerHealthCheck(upstreamName string, generatedUpstreamName string, upstreams []conf_v1.TransportServerUpstream) (*version2.StreamHealthCheck, *version2.Match) {
	var hc *version2.StreamHealthCheck
	var match *version2.Match

	for _, u := range upstreams {
		if u.Name == upstreamName {
			if u.HealthCheck == nil || !u.HealthCheck.Enabled {
				return nil, nil
			}
			hc = generateTransportServerHealthCheckWithDefaults()

			hc.Enabled = u.HealthCheck.Enabled
			hc.Interval = generateTimeWithDefault(u.HealthCheck.Interval, hc.Interval)
			hc.Jitter = generateTimeWithDefault(u.HealthCheck.Jitter, hc.Jitter)
			hc.Timeout = generateTimeWithDefault(u.HealthCheck.Timeout, hc.Timeout)
			hc.Port = u.HealthCheck.Port

			if u.HealthCheck.Fails > 0 {
				hc.Fails = u.HealthCheck.Fails
			}

			if u.HealthCheck.Passes > 0 {
				hc.Passes = u.HealthCheck.Passes
			}

			if u.HealthCheck.Match != nil {
				name := "match_" + generatedUpstreamName
				match = generateHealthCheckMatch(u.HealthCheck.Match, name)
				hc.Match = name
			}

			break
		}
	}
	return hc, match
}

func generateTransportServerHealthCheckWithDefaults() *version2.StreamHealthCheck {
	return &version2.StreamHealthCheck{
		Enabled:  false,
		Timeout:  "5s",
		Jitter:   "0s",
		Interval: "5s",
		Passes:   1,
		Fails:    1,
		Match:    "",
	}
}

func generateHealthCheckMatch(match *conf_v1.TransportServerMatch, name string) *version2.Match {
	var modifier string
	var expect string

	if strings.HasPrefix(match.Expect, "~*") {
		modifier = "~*"
		expect = strings.TrimPrefix(match.Expect, "~*")
	} else if strings.HasPrefix(match.Expect, "~") {
		modifier = "~"
		expect = strings.TrimPrefix(match.Expect, "~")
	} else {
		expect = match.Expect
	}

	return &version2.Match{
		Name:                name,
		Send:                match.Send,
		ExpectRegexModifier: modifier,
		Expect:              expect,
	}
}

func generateStreamUpstream(upstream conf_v1.TransportServerUpstream, upstreamNamer *upstreamNamer, endpoints, backupEndpoints []string, isPlus bool) version2.StreamUpstream {
	var upsServers []version2.StreamUpstreamServer

	name := upstreamNamer.GetNameForUpstream(upstream.Name)
	maxFails := generateIntFromPointer(upstream.MaxFails, 1)
	maxConns := generateIntFromPointer(upstream.MaxConns, 0)
	failTimeout := generateTimeWithDefault(upstream.FailTimeout, "10s")

	for _, e := range endpoints {
		s := version2.StreamUpstreamServer{
			Address:        e,
			MaxFails:       maxFails,
			FailTimeout:    failTimeout,
			MaxConnections: maxConns,
		}

		upsServers = append(upsServers, s)
	}

	var upsBackups []version2.StreamUpstreamBackupServer
	for _, e := range backupEndpoints {
		s := version2.StreamUpstreamBackupServer{
			Address: e,
		}
		upsBackups = append(upsBackups, s)
	}

	if !isPlus && len(endpoints) == 0 {
		upsServers = append(upsServers, version2.StreamUpstreamServer{
			Address:     nginxNonExistingUnixSocket,
			MaxFails:    maxFails,
			FailTimeout: failTimeout,
		})
	}

	sort.Slice(upsServers, func(i, j int) bool {
		return upsServers[i].Address < upsServers[j].Address
	})
	sort.Slice(upsBackups, func(i, j int) bool {
		return upsBackups[i].Address < upsBackups[j].Address
	})

	return version2.StreamUpstream{
		Name:                name,
		Servers:             upsServers,
		LoadBalancingMethod: generateLoadBalancingMethod(upstream.LoadBalancingMethod),
		BackupServers:       upsBackups,
	}
}

func generateLoadBalancingMethod(method string) string {
	if method == "" {
		// By default, if unspecified, Nginx uses the 'round_robin' load balancing method.
		// We override this default which suits the Ingress Controller better.
		return "random two least_conn"
	}
	if method == "round_robin" {
		// By default, Nginx uses round robin. We select this method by not specifying any method.
		return ""
	}
	return method
}

func generateServerName(host string, isTLSPassthrough bool) string {
	if isTLSPassthrough {
		return ""
	}
	return host
}
