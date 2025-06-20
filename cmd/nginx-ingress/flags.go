package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	internalValidation "github.com/nginx/kubernetes-ingress/internal/validation"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

const (
	dynamicSSLReloadParam         = "ssl-dynamic-reload"
	dynamicWeightChangesParam     = "weight-changes-dynamic-reload"
	appProtectLogLevelDefault     = "fatal"
	appProtectEnforcerAddrDefault = "127.0.0.1:50000"
	logLevelDefault               = "info"
	logFormatDefault              = "glog"
)

var (
	healthStatus = flag.Bool("health-status", false,
		`Add a location based on the value of health-status-uri to the default server. The location responds with the 200 status code for any request.
	Useful for external health-checking of the Ingress Controller`)

	healthStatusURI = flag.String("health-status-uri", "/nginx-health",
		`Sets the URI of health status location in the default server. Requires -health-status`)

	proxyURL = flag.String("proxy", "",
		`Use a proxy server to connect to Kubernetes API started by "kubectl proxy" command. For testing purposes only.
	The Ingress Controller does not start NGINX and does not write any generated NGINX configuration files to disk`)

	watchNamespace = flag.String("watch-namespace", api_v1.NamespaceAll,
		`Comma separated list of namespaces the Ingress Controller should watch for resources. By default the Ingress Controller watches all namespaces. Mutually exclusive with "watch-namespace-label".`)

	watchNamespaces []string

	watchSecretNamespace = flag.String("watch-secret-namespace", "",
		`Comma separated list of namespaces the Ingress Controller should watch for secrets. If this arg is not configured, the Ingress Controller watches the same namespaces for all resources. See "watch-namespace" and "watch-namespace-label". `)

	watchSecretNamespaces []string

	watchNamespaceLabel = flag.String("watch-namespace-label", "",
		`Configures the Ingress Controller to watch only those namespaces with label foo=bar. By default the Ingress Controller watches all namespaces. Mutually exclusive with "watch-namespace". `)

	nginxConfigMaps = flag.String("nginx-configmaps", "",
		`A ConfigMap resource for customizing NGINX configuration. If a ConfigMap is set,
	but the Ingress Controller is not able to fetch it from Kubernetes API, the Ingress Controller will fail to start.
	Format: <namespace>/<name>`)

	mgmtConfigMap = flag.String("mgmt-configmap", "",
		`A ConfigMap resource for customizing NGINX configuration. If a ConfigMap is set,
	but the Ingress Controller is not able to fetch it from Kubernetes API, the Ingress Controller will fail to start.
	Format: <namespace>/<name>`)

	nginxPlus = flag.Bool("nginx-plus", false, "Enable support for NGINX Plus")

	appProtect = flag.Bool("enable-app-protect", false, "Enable support for NGINX App Protect. Requires -nginx-plus.")

	appProtectLogLevel = flag.String("app-protect-log-level", appProtectLogLevelDefault,
		`Sets log level for App Protect. Allowed values: fatal, error, warn, info, debug, trace. Requires -nginx-plus and -enable-app-protect.`)

	appProtectDos = flag.Bool("enable-app-protect-dos", false, "Enable support for NGINX App Protect dos. Requires -nginx-plus.")

	appProtectDosDebug = flag.Bool("app-protect-dos-debug", false, "Enable debugging for App Protect Dos. Requires -nginx-plus and -enable-app-protect-dos.")

	appProtectDosMaxDaemons = flag.Int("app-protect-dos-max-daemons", 0, "Max number of ADMD instances. Requires -nginx-plus and -enable-app-protect-dos.")
	appProtectDosMaxWorkers = flag.Int("app-protect-dos-max-workers", 0, "Max number of nginx processes to support. Requires -nginx-plus and -enable-app-protect-dos.")
	appProtectDosMemory     = flag.Int("app-protect-dos-memory", 0, "RAM memory size to consume in MB. Requires -nginx-plus and -enable-app-protect-dos.")

	appProtectEnforcerAddress = flag.String("app-protect-enforcer-address", appProtectEnforcerAddrDefault,
		`Sets address for App Protect v5 Enforcer. Requires -nginx-plus and -enable-app-protect.`)

	agent              = flag.Bool("agent", false, "Enable NGINX Agent")
	agentInstanceGroup = flag.String("agent-instance-group", "nginx-ingress-controller", "Grouping used to associate NGINX Ingress Controller instances")

	ingressClass = flag.String("ingress-class", "nginx",
		`A class of the Ingress Controller.

	An IngressClass resource with the name equal to the class must be deployed. Otherwise, the Ingress Controller will fail to start.
	The Ingress Controller only processes resources that belong to its class - i.e. have the "ingressClassName" field resource equal to the class.

	The Ingress Controller processes all the VirtualServer/VirtualServerRoute/TransportServer resources that do not have the "ingressClassName" field for all versions of kubernetes.`)

	defaultServerSecret = flag.String("default-server-tls-secret", "",
		`A Secret with a TLS certificate and key for TLS termination of the default server. Format: <namespace>/<name>.
	If not set, than the certificate and key in the file "/etc/nginx/secrets/default" are used.
	If "/etc/nginx/secrets/default" doesn't exist, the Ingress Controller will configure NGINX to reject TLS connections to the default server.
	If a secret is set, but the Ingress Controller is not able to fetch it from Kubernetes API or it is not set and the Ingress Controller
	fails to read the file "/etc/nginx/secrets/default", the Ingress Controller will fail to start.`)

	versionFlag = flag.Bool("version", false, "Print the version, git-commit hash and build date and exit")

	mainTemplatePath = flag.String("main-template-path", "",
		`Path to the main NGINX configuration template. (default for NGINX "nginx.tmpl"; default for NGINX Plus "nginx-plus.tmpl")`)

	ingressTemplatePath = flag.String("ingress-template-path", "",
		`Path to the ingress NGINX configuration template for an ingress resource.
	(default for NGINX "nginx.ingress.tmpl"; default for NGINX Plus "nginx-plus.ingress.tmpl")`)

	virtualServerTemplatePath = flag.String("virtualserver-template-path", "",
		`Path to the VirtualServer NGINX configuration template for a VirtualServer resource.
	(default for NGINX "nginx.virtualserver.tmpl"; default for NGINX Plus "nginx-plus.virtualserver.tmpl")`)

	transportServerTemplatePath = flag.String("transportserver-template-path", "",
		`Path to the TransportServer NGINX configuration template for a TransportServer resource.
	(default for NGINX "nginx.transportserver.tmpl"; default for NGINX Plus "nginx-plus.transportserver.tmpl")`)

	externalService = flag.String("external-service", "",
		`Specifies the name of the service with the type LoadBalancer through which the Ingress Controller pods are exposed externally.
	The external address of the service is used when reporting the status of Ingress, VirtualServer and VirtualServerRoute resources. For Ingress resources only: Requires -report-ingress-status.`)

	ingressLink = flag.String("ingresslink", "",
		`Specifies the name of the IngressLink resource, which exposes the Ingress Controller pods via a BIG-IP system.
	The IP of the BIG-IP system is used when reporting the status of Ingress, VirtualServer and VirtualServerRoute resources. For Ingress resources only: Requires -report-ingress-status.`)

	reportIngressStatus = flag.Bool("report-ingress-status", false,
		"Updates the address field in the status of Ingress resources. Requires the -external-service or -ingresslink flag, or the 'external-status-address' key in the ConfigMap.")

	leaderElectionEnabled = flag.Bool("enable-leader-election", true,
		"Enable Leader election to avoid multiple replicas of the controller reporting the status of Ingress, VirtualServer and VirtualServerRoute resources -- only one replica will report status (default true). See -report-ingress-status flag.")

	leaderElectionLockName = flag.String("leader-election-lock-name", "nginx-ingress-leader-election",
		`Specifies the name of the ConfigMap, within the same namespace as the controller, used as the lock for leader election. Requires -enable-leader-election.`)

	nginxStatusAllowCIDRs = flag.String("nginx-status-allow-cidrs", "127.0.0.1,::1", `Add IP/CIDR blocks to the allow list for NGINX stub_status or the NGINX Plus API. Separate multiple IP/CIDR by commas.`)

	allowedCIDRs []string

	nginxStatusPort = flag.Int("nginx-status-port", 8080,
		"Set the port where the NGINX stub_status or the NGINX Plus API is exposed. [1024 - 65535]")

	nginxStatus = flag.Bool("nginx-status", true,
		"Enable the NGINX stub_status, or the NGINX Plus API.")

	nginxDebug = flag.Bool("nginx-debug", false,
		"Enable debugging for NGINX. Uses the nginx-debug binary. Requires 'error-log-level: debug' in the ConfigMap.")

	nginxReloadTimeout = flag.Int("nginx-reload-timeout", 60000,
		`The timeout in milliseconds which the Ingress Controller will wait for a successful NGINX reload after a change or at the initial start. (default 60000)`)

	wildcardTLSSecret = flag.String("wildcard-tls-secret", "",
		`A Secret with a TLS certificate and key for TLS termination of every Ingress/VirtualServer host for which TLS termination is enabled but the Secret is not specified.
		Format: <namespace>/<name>. If the argument is not set, for such Ingress/VirtualServer hosts NGINX will break any attempt to establish a TLS connection.
		If the argument is set, but the Ingress Controller is not able to fetch the Secret from Kubernetes API, the Ingress Controller will fail to start.`)

	enablePrometheusMetrics = flag.Bool("enable-prometheus-metrics", false,
		"Enable exposing NGINX or NGINX Plus metrics in the Prometheus format")

	prometheusTLSSecretName = flag.String("prometheus-tls-secret", "",
		`A Secret with a TLS certificate and key for TLS termination of the prometheus endpoint.`)

	prometheusMetricsListenPort = flag.Int("prometheus-metrics-listen-port", 9113,
		"Set the port where the Prometheus metrics are exposed. [1024 - 65535]")

	enableServiceInsight = flag.Bool("enable-service-insight", false,
		`Enable service insight for external load balancers. Requires -nginx-plus`)

	serviceInsightTLSSecretName = flag.String("service-insight-tls-secret", "",
		`A Secret with a TLS certificate and key for TLS termination of the service insight.`)

	serviceInsightListenPort = flag.Int("service-insight-listen-port", 9114,
		"Set the port where the Service Insight stats are exposed. Requires -nginx-plus. [1024 - 65535]")

	enableCustomResources = flag.Bool("enable-custom-resources", true,
		"Enable custom resources")

	enableOIDC = flag.Bool("enable-oidc", false,
		"Enable OIDC Policies.")

	enableSnippets = flag.Bool("enable-snippets", false,
		"Enable custom NGINX configuration snippets in Ingress, VirtualServer, VirtualServerRoute and TransportServer resources.")

	globalConfiguration = flag.String("global-configuration", "",
		`The namespace/name of the GlobalConfiguration resource for global configuration of the Ingress Controller. Requires -enable-custom-resources. Format: <namespace>/<name>`)

	enableTLSPassthrough = flag.Bool("enable-tls-passthrough", false,
		"Enable TLS Passthrough on default port 443. Requires -enable-custom-resources")

	tlsPassthroughPort = flag.Int("tls-passthrough-port", 443, "Set custom port for TLS Passthrough. [1024 - 65535]")

	spireAgentAddress = flag.String("spire-agent-address", "",
		`Specifies the address of the running Spire agent. Requires -nginx-plus and is for use with NGINX Service Mesh only. If the flag is set,
			but the Ingress Controller is not able to connect with the Spire Agent, the Ingress Controller will fail to start.`)

	enableInternalRoutes = flag.Bool("enable-internal-routes", false,
		`Enable support for internal routes with NGINX Service Mesh. Requires -spire-agent-address and -nginx-plus. Is for use with NGINX Service Mesh only.`)

	readyStatus = flag.Bool("ready-status", true, "Enables the readiness endpoint '/nginx-ready'. The endpoint returns a success code when NGINX has loaded all the config after the startup")

	readyStatusPort = flag.Int("ready-status-port", 8081, "Set the port where the readiness endpoint is exposed. [1024 - 65535]")

	enableLatencyMetrics = flag.Bool("enable-latency-metrics", false,
		"Enable collection of latency metrics for upstreams. Requires -enable-prometheus-metrics")

	enableCertManager = flag.Bool("enable-cert-manager", false,
		"Enable cert-manager controller for VirtualServer resources. Requires -enable-custom-resources")

	enableExternalDNS = flag.Bool("enable-external-dns", false,
		"Enable external-dns controller for VirtualServer resources. Requires -enable-custom-resources")

	disableIPV6 = flag.Bool("disable-ipv6", false,
		`Disable IPV6 listeners explicitly for nodes that do not support the IPV6 stack`)

	defaultHTTPListenerPort = flag.Int("default-http-listener-port", 80, "Sets a custom port for the HTTP NGINX `default_server`. [1024 - 65535]")

	defaultHTTPSListenerPort = flag.Int("default-https-listener-port", 443, "Sets a custom port for the HTTPS `default_server`. [1024 - 65535]")

	enableDynamicSSLReload = flag.Bool(dynamicSSLReloadParam, true, "Enable reloading of SSL Certificates without restarting the NGINX process.")

	enableTelemetryReporting = flag.Bool("enable-telemetry-reporting", true, "Enable gathering and reporting of product related telemetry.")

	logFormat = flag.String("log-format", logFormatDefault, "Set log format to either glog, text, or json.")

	logLevel = flag.String("log-level", logLevelDefault,
		`Sets log level for Ingress Controller. Allowed values: fatal, error, warning, info, debug, trace.`)

	enableDynamicWeightChangesReload = flag.Bool(dynamicWeightChangesParam, false, "Enable changing weights of split clients without reloading NGINX. Requires -nginx-plus")

	startupCheckFn func() error
)

//gocyclo:ignore
func parseFlags() {
	flag.Parse()

	if *versionFlag { // printed in main
		os.Exit(0)
	}
}

func initValidate(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	logFormatValidationError := validateLogFormat(*logFormat)
	if logFormatValidationError != nil {
		nl.Warnf(l, "Invalid log format: %s. Valid options are: glog, text, json. Falling back to default: %s", *logFormat, logFormatDefault)
	}

	logLevelValidationError := validateLogLevel(*logLevel)
	if logLevelValidationError != nil {
		nl.Warnf(l, "Invalid log level: %s. Valid options are: trace, debug, info, warning, error, fatal. Falling back to default: %s", *logLevel, logLevelDefault)
	}

	if *enableLatencyMetrics && !*enablePrometheusMetrics {
		nl.Warn(l, "enable-latency-metrics flag requires enable-prometheus-metrics, latency metrics will not be collected")
		*enableLatencyMetrics = false
	}

	if *enableServiceInsight && !*nginxPlus {
		nl.Warn(l, "enable-service-insight flag support is for NGINX Plus, service insight endpoint will not be exposed")
		*enableServiceInsight = false
	}

	if *enableDynamicWeightChangesReload && !*nginxPlus {
		nl.Warn(l, "weight-changes-dynamic-reload flag support is for NGINX Plus, Dynamic Weight Changes will not be enabled")
		*enableDynamicWeightChangesReload = false
	}

	if *mgmtConfigMap != "" && !*nginxPlus {
		nl.Warn(l, "mgmt-configmap flag requires -nginx-plus, mgmt configmap will not be used")
		*mgmtConfigMap = ""
	}

	mustValidateInitialChecks(ctx)
	mustValidateWatchedNamespaces(ctx)
	mustValidateFlags(ctx)
}

func mustValidateInitialChecks(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)

	if startupCheckFn != nil {
		err := startupCheckFn()
		if err != nil {
			nl.Fatalf(l, "Failed startup check: %v", err)
		}
		l.Info("AWS startup check passed")
	}

	l.Info(fmt.Sprintf("Starting with flags: %+q", os.Args[1:]))

	unparsed := flag.Args()
	if len(unparsed) > 0 {
		nl.Warnf(l, "Ignoring unhandled arguments: %+q", unparsed)
	}
}

// mustValidateWatchedNamespaces calls internally os.Exit if it can't validate namespaces.
func mustValidateWatchedNamespaces(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	if *watchNamespace != "" && *watchNamespaceLabel != "" {
		nl.Fatal(l, "watch-namespace and -watch-namespace-label are mutually exclusive")
	}

	watchNamespaces = strings.Split(*watchNamespace, ",")

	if *watchNamespace != "" {
		l.Info(fmt.Sprintf("Namespaces watched: %v", watchNamespaces))
		namespacesNameValidationError := validateNamespaceNames(watchNamespaces)
		if namespacesNameValidationError != nil {
			nl.Fatalf(l, "Invalid values for namespaces: %v", namespacesNameValidationError)
		}
	}

	if len(*watchSecretNamespace) > 0 {
		watchSecretNamespaces = strings.Split(*watchSecretNamespace, ",")
		l.Debug(fmt.Sprintf("Namespaces watched for secrets: %v", watchSecretNamespaces))
		namespacesNameValidationError := validateNamespaceNames(watchSecretNamespaces)
		if namespacesNameValidationError != nil {
			nl.Fatalf(l, "Invalid values for secret namespaces: %v", namespacesNameValidationError)
		}
	} else {
		// empty => default to watched namespaces
		watchSecretNamespaces = watchNamespaces
	}

	if *watchNamespaceLabel != "" {
		var err error
		_, err = labels.Parse(*watchNamespaceLabel)
		if err != nil {
			nl.Fatalf(l, "Unable to parse label %v for watch namespace label: %v", *watchNamespaceLabel, err)
		}
	}
}

// mustValidateFlags checks the values for various flags
// and calls os.Exit if any of the flags is invalid.
// nolint:gocyclo
func mustValidateFlags(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	healthStatusURIValidationError := validateLocation(*healthStatusURI)
	if healthStatusURIValidationError != nil {
		nl.Fatalf(l, "Invalid value for health-status-uri: %v", healthStatusURIValidationError)
	}

	statusLockNameValidationError := validateResourceName(*leaderElectionLockName)
	if statusLockNameValidationError != nil {
		nl.Fatalf(l, "Invalid value for leader-election-lock-name: %v", statusLockNameValidationError)
	}

	statusPortValidationError := internalValidation.ValidateUnprivilegedPort(*nginxStatusPort)
	if statusPortValidationError != nil {
		nl.Fatalf(l, "Invalid value for nginx-status-port: %v", statusPortValidationError)
	}

	metricsPortValidationError := internalValidation.ValidateUnprivilegedPort(*prometheusMetricsListenPort)
	if metricsPortValidationError != nil {
		nl.Fatalf(l, "Invalid value for prometheus-metrics-listen-port: %v", metricsPortValidationError)
	}

	readyStatusPortValidationError := internalValidation.ValidateUnprivilegedPort(*readyStatusPort)
	if readyStatusPortValidationError != nil {
		nl.Fatalf(l, "Invalid value for ready-status-port: %v", readyStatusPortValidationError)
	}

	healthProbePortValidationError := internalValidation.ValidateUnprivilegedPort(*serviceInsightListenPort)
	if healthProbePortValidationError != nil {
		nl.Fatalf(l, "Invalid value for service-insight-listen-port: %v", metricsPortValidationError)
	}

	var err error
	allowedCIDRs, err = parseNginxStatusAllowCIDRs(*nginxStatusAllowCIDRs)
	if err != nil {
		nl.Fatalf(l, "Invalid value for nginx-status-allow-cidrs: %v", err)
	}

	if *appProtectLogLevel != appProtectLogLevelDefault && *appProtect && *nginxPlus {
		appProtectlogLevelValidationError := validateLogLevel(*appProtectLogLevel)
		if appProtectlogLevelValidationError != nil {
			nl.Fatalf(l, "Invalid value for app-protect-log-level: %v", *appProtectLogLevel)
		}
	}

	if *enableTLSPassthrough && !*enableCustomResources {
		nl.Fatal(l, "enable-tls-passthrough flag requires -enable-custom-resources")
	}

	if *appProtect && !*nginxPlus {
		nl.Fatal(l, "NGINX App Protect support is for NGINX Plus only")
	}

	if *appProtectLogLevel != appProtectLogLevelDefault && !*appProtect && !*nginxPlus {
		nl.Fatal(l, "app-protect-log-level support is for NGINX Plus only and App Protect is enable")
	}

	if *appProtectDos && !*nginxPlus {
		nl.Fatal(l, "NGINX App Protect Dos support is for NGINX Plus only")
	}

	if *appProtectDosDebug && !*appProtectDos && !*nginxPlus {
		nl.Fatal(l, "NGINX App Protect Dos debug support is for NGINX Plus only and App Protect Dos is enable")
	}

	if *appProtectDosMaxDaemons != 0 && !*appProtectDos && !*nginxPlus {
		nl.Fatal(l, "NGINX App Protect Dos max daemons support is for NGINX Plus only and App Protect Dos is enable")
	}

	if *appProtectDosMaxWorkers != 0 && !*appProtectDos && !*nginxPlus {
		nl.Fatal(l, "NGINX App Protect Dos max workers support is for NGINX Plus and App Protect Dos is enable")
	}

	if *appProtectDosMemory != 0 && !*appProtectDos && !*nginxPlus {
		nl.Fatal(l, "NGINX App Protect Dos memory support is for NGINX Plus and App Protect Dos is enable")
	}

	if *enableInternalRoutes && *spireAgentAddress == "" {
		nl.Fatal(l, "enable-internal-routes flag requires spire-agent-address")
	}

	if *enableCertManager && !*enableCustomResources {
		nl.Fatal(l, "enable-cert-manager flag requires -enable-custom-resources")
	}

	if *enableExternalDNS && !*enableCustomResources {
		nl.Fatal(l, "enable-external-dns flag requires -enable-custom-resources")
	}

	if *ingressLink != "" && *externalService != "" {
		nl.Fatal(l, "ingresslink and external-service cannot both be set")
	}

	if *nginxPlus && *mgmtConfigMap == "" {
		nl.Fatal(l, "NGINX Plus requires a mgmt ConfigMap to be set")
	}
}

// validateNamespaceNames validates the namespaces are in the correct format
func validateNamespaceNames(namespaces []string) error {
	var allErrs []error

	for _, ns := range namespaces {
		if ns != "" {
			ns = strings.TrimSpace(ns)
			err := validateResourceName(ns)
			if err != nil {
				allErrs = append(allErrs, err)
				fmt.Printf("error %v ", err)
			}
		}
	}
	if len(allErrs) > 0 {
		return fmt.Errorf("errors validating namespaces: %v", allErrs)
	}
	return nil
}

// validateResourceName validates the name of a resource
func validateResourceName(name string) error {
	allErrs := validation.IsDNS1123Subdomain(name)
	if len(allErrs) > 0 {
		return fmt.Errorf("invalid resource name %v: %v", name, allErrs)
	}
	return nil
}

// validateLogLevel makes sure a given logLevel is one of the allowed values
func validateLogLevel(logLevel string) error {
	switch strings.ToLower(logLevel) {
	case
		"fatal",
		"error",
		"warn",
		"info",
		"debug",
		"trace":
		return nil
	}
	return fmt.Errorf("invalid log level: %v", logLevel)
}

// validateLogFormat makes sure a given logFormat is one of the allowed values
func validateLogFormat(logFormat string) error {
	switch strings.ToLower(logFormat) {
	case "glog", "json", "text":
		return nil
	}
	return fmt.Errorf("invalid log format: %v", logFormat)
}

// parseNginxStatusAllowCIDRs converts a comma separated CIDR/IP address string into an array of CIDR/IP addresses.
// It returns an array of the valid CIDR/IP addresses or an error if given an invalid address.
func parseNginxStatusAllowCIDRs(input string) (cidrs []string, err error) {
	cidrsArray := strings.Split(input, ",")
	for _, cidr := range cidrsArray {
		trimmedCidr := strings.TrimSpace(cidr)
		err := validateCIDRorIP(trimmedCidr)
		if err != nil {
			return cidrs, err
		}
		cidrs = append(cidrs, trimmedCidr)
	}
	return cidrs, nil
}

// validateCIDRorIP makes sure a given string is either a valid CIDR block or IP address.
// It an error if it is not valid.
func validateCIDRorIP(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("invalid CIDR address: an empty string is an invalid CIDR block or IP address")
	}
	_, _, err := net.ParseCIDR(cidr)
	if err == nil {
		return nil
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %v", cidr)
	}
	return nil
}

const (
	locationFmt    = `/[^\s{};]*`
	locationErrMsg = "must start with / and must not include any whitespace character, `{`, `}` or `;`"
)

var locationRegexp = regexp.MustCompile("^" + locationFmt + "$")

func validateLocation(location string) error {
	if location == "" || location == "/" {
		return fmt.Errorf("invalid location format: '%v' is an invalid location", location)
	}
	if !locationRegexp.MatchString(location) {
		msg := validation.RegexError(locationErrMsg, locationFmt, "/path", "/path/subpath-123")
		return fmt.Errorf("invalid location format: %v", msg)
	}
	return nil
}
