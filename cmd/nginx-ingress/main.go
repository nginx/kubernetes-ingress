package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nginxinc/kubernetes-ingress/internal/configs"
	"github.com/nginxinc/kubernetes-ingress/internal/configs/version1"
	"github.com/nginxinc/kubernetes-ingress/internal/configs/version2"
	"github.com/nginxinc/kubernetes-ingress/internal/healthcheck"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginxinc/kubernetes-ingress/internal/metrics"
	"github.com/nginxinc/kubernetes-ingress/internal/metrics/collectors"
	"github.com/nginxinc/kubernetes-ingress/internal/nginx"
	cr_validation "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/validation"
	k8s_nginx "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned"
	conf_scheme "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned/scheme"
	"github.com/nginxinc/nginx-plus-go-client/client"
	nginxCollector "github.com/nginxinc/nginx-prometheus-exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	util_version "k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"

	nl "github.com/nginxinc/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginxinc/kubernetes-ingress/internal/logger/glog"
	"github.com/nginxinc/kubernetes-ingress/internal/logger/levels"
)

// Injected during build
var (
	version           string
	telemetryEndpoint string
	logLevels         = map[string]slog.Level{
		"trace":   levels.LevelTrace,
		"debug":   levels.LevelDebug,
		"info":    levels.LevelInfo,
		"warning": levels.LevelWarning,
		"error":   levels.LevelError,
		"fatal":   levels.LevelFatal,
	}
)

const (
	nginxVersionLabel        = "app.nginx.org/version"
	versionLabel             = "app.kubernetes.io/version"
	appProtectVersionLabel   = "appprotect.f5.com/version"
	agentVersionLabel        = "app.nginx.org/agent-version"
	appProtectVersionPath    = "/opt/app_protect/RELEASE"
	appProtectv4BundleFolder = "/etc/nginx/waf/bundles/"
	appProtectv5BundleFolder = "/etc/app_protect/bundles/"
)

func main() {
	commitHash, commitTime, dirtyBuild := getBuildInfo()
	fmt.Printf("NGINX Ingress Controller Version=%v Commit=%v Date=%v DirtyState=%v Arch=%v/%v Go=%v\n", version, commitHash, commitTime, dirtyBuild, runtime.GOOS, runtime.GOARCH, runtime.Version())
	parseFlags()
	ctx := initLogger(*logFormat, logLevels[*logLevel], os.Stdout)
	l := nl.LoggerFromContext(ctx)

	initValidate(ctx)
	parsedFlags := os.Args[1:]

	buildOS := os.Getenv("BUILD_OS")

	config, kubeClient := mustCreateConfigAndKubeClient(ctx)
	mustValidateKubernetesVersionInfo(ctx, kubeClient)
	mustValidateIngressClass(ctx, kubeClient)

	checkNamespaces(ctx, kubeClient)

	dynClient, confClient := createCustomClients(ctx, config)

	constLabels := map[string]string{"class": *ingressClass}

	managerCollector, controllerCollector, registry := createManagerAndControllerCollectors(ctx, constLabels)

	nginxManager, useFakeNginxManager := createNginxManager(ctx, managerCollector)

	nginxVersion := getNginxVersionInfo(ctx, nginxManager)

	var appProtectVersion string
	var appProtectV5 bool
	appProtectBundlePath := appProtectv4BundleFolder
	if *appProtect {
		appProtectVersion = getAppProtectVersionInfo(ctx)

		r := regexp.MustCompile("^5.*")
		if r.MatchString(appProtectVersion) {
			appProtectV5 = true
			appProtectBundlePath = appProtectv5BundleFolder
		}
	}

	var agentVersion string
	if *agent {
		agentVersion = getAgentVersionInfo(nginxManager)
	}

	go updateSelfWithVersionInfo(ctx, kubeClient, version, appProtectVersion, agentVersion, nginxVersion, 10, time.Second*5)

	templateExecutor, templateExecutorV2 := createTemplateExecutors(ctx)

	sslRejectHandshake := processDefaultServerSecret(ctx, kubeClient, nginxManager)

	isWildcardEnabled := processWildcardSecret(ctx, kubeClient, nginxManager)

	globalConfigurationValidator := createGlobalConfigurationValidator()

	mustProcessGlobalConfiguration(ctx)

	cfgParams := configs.NewDefaultConfigParams(ctx, *nginxPlus)
	cfgParams = processConfigMaps(kubeClient, cfgParams, nginxManager, templateExecutor)

	staticCfgParams := &configs.StaticConfigParams{
		DisableIPV6:                    *disableIPV6,
		DefaultHTTPListenerPort:        *defaultHTTPListenerPort,
		DefaultHTTPSListenerPort:       *defaultHTTPSListenerPort,
		HealthStatus:                   *healthStatus,
		HealthStatusURI:                *healthStatusURI,
		NginxStatus:                    *nginxStatus,
		NginxStatusAllowCIDRs:          allowedCIDRs,
		NginxStatusPort:                *nginxStatusPort,
		StubStatusOverUnixSocketForOSS: *enablePrometheusMetrics,
		TLSPassthrough:                 *enableTLSPassthrough,
		TLSPassthroughPort:             *tlsPassthroughPort,
		EnableSnippets:                 *enableSnippets,
		NginxServiceMesh:               *spireAgentAddress != "",
		MainAppProtectLoadModule:       *appProtect,
		MainAppProtectV5LoadModule:     appProtectV5,
		MainAppProtectDosLoadModule:    *appProtectDos,
		MainAppProtectV5EnforcerAddr:   *appProtectEnforcerAddress,
		EnableLatencyMetrics:           *enableLatencyMetrics,
		EnableOIDC:                     *enableOIDC,
		SSLRejectHandshake:             sslRejectHandshake,
		EnableCertManager:              *enableCertManager,
		DynamicSSLReload:               *enableDynamicSSLReload,
		DynamicWeightChangesReload:     *enableDynamicWeightChangesReload,
		StaticSSLPath:                  nginxManager.GetSecretsDir(),
		NginxVersion:                   nginxVersion,
		AppProtectBundlePath:           appProtectBundlePath,
	}

	mustProcessNginxConfig(staticCfgParams, cfgParams, templateExecutor, nginxManager)

	if *enableTLSPassthrough {
		var emptyFile []byte
		nginxManager.CreateTLSPassthroughHostsConfig(emptyFile)
	}

	process := startChildProcesses(nginxManager, appProtectV5)

	plusClient := createPlusClient(ctx, *nginxPlus, useFakeNginxManager, nginxManager)

	plusCollector, syslogListener, latencyCollector := createPlusAndLatencyCollectors(ctx, registry, constLabels, kubeClient, plusClient, staticCfgParams.NginxServiceMesh)
	cnf := configs.NewConfigurator(configs.ConfiguratorParams{
		NginxManager:                        nginxManager,
		StaticCfgParams:                     staticCfgParams,
		Config:                              cfgParams,
		TemplateExecutor:                    templateExecutor,
		TemplateExecutorV2:                  templateExecutorV2,
		LatencyCollector:                    latencyCollector,
		LabelUpdater:                        plusCollector,
		IsPlus:                              *nginxPlus,
		IsWildcardEnabled:                   isWildcardEnabled,
		IsPrometheusEnabled:                 *enablePrometheusMetrics,
		IsLatencyMetricsEnabled:             *enableLatencyMetrics,
		IsDynamicSSLReloadEnabled:           *enableDynamicSSLReload,
		IsDynamicWeightChangesReloadEnabled: *enableDynamicWeightChangesReload,
		NginxVersion:                        nginxVersion,
	})

	controllerNamespace := os.Getenv("POD_NAMESPACE")

	transportServerValidator := cr_validation.NewTransportServerValidator(*enableTLSPassthrough, *enableSnippets, *nginxPlus)
	virtualServerValidator := cr_validation.NewVirtualServerValidator(
		cr_validation.IsPlus(*nginxPlus),
		cr_validation.IsDosEnabled(*appProtectDos),
		cr_validation.IsCertManagerEnabled(*enableCertManager),
		cr_validation.IsExternalDNSEnabled(*enableExternalDNS),
	)

	if *enableServiceInsight {
		createHealthProbeEndpoint(kubeClient, plusClient, cnf)
	}

	lbcInput := k8s.NewLoadBalancerControllerInput{
		KubeClient:                   kubeClient,
		ConfClient:                   confClient,
		DynClient:                    dynClient,
		RestConfig:                   config,
		ResyncPeriod:                 30 * time.Second,
		LoggerContext:                ctx,
		Namespace:                    watchNamespaces,
		SecretNamespace:              watchSecretNamespaces,
		NginxConfigurator:            cnf,
		DefaultServerSecret:          *defaultServerSecret,
		AppProtectEnabled:            *appProtect,
		AppProtectDosEnabled:         *appProtectDos,
		AppProtectVersion:            appProtectVersion,
		IsNginxPlus:                  *nginxPlus,
		IngressClass:                 *ingressClass,
		ExternalServiceName:          *externalService,
		IngressLink:                  *ingressLink,
		ControllerNamespace:          controllerNamespace,
		ReportIngressStatus:          *reportIngressStatus,
		IsLeaderElectionEnabled:      *leaderElectionEnabled,
		LeaderElectionLockName:       *leaderElectionLockName,
		WildcardTLSSecret:            *wildcardTLSSecret,
		ConfigMaps:                   *nginxConfigMaps,
		GlobalConfiguration:          *globalConfiguration,
		AreCustomResourcesEnabled:    *enableCustomResources,
		EnableOIDC:                   *enableOIDC,
		MetricsCollector:             controllerCollector,
		GlobalConfigurationValidator: globalConfigurationValidator,
		TransportServerValidator:     transportServerValidator,
		VirtualServerValidator:       virtualServerValidator,
		SpireAgentAddress:            *spireAgentAddress,
		InternalRoutesEnabled:        *enableInternalRoutes,
		IsPrometheusEnabled:          *enablePrometheusMetrics,
		IsLatencyMetricsEnabled:      *enableLatencyMetrics,
		IsTLSPassthroughEnabled:      *enableTLSPassthrough,
		TLSPassthroughPort:           *tlsPassthroughPort,
		SnippetsEnabled:              *enableSnippets,
		CertManagerEnabled:           *enableCertManager,
		ExternalDNSEnabled:           *enableExternalDNS,
		IsIPV6Disabled:               *disableIPV6,
		WatchNamespaceLabel:          *watchNamespaceLabel,
		EnableTelemetryReporting:     *enableTelemetryReporting,
		TelemetryReportingEndpoint:   telemetryEndpoint,
		BuildOS:                      buildOS,
		NICVersion:                   version,
		DynamicWeightChangesReload:   *enableDynamicWeightChangesReload,
		InstallationFlags:            parsedFlags,
	}

	lbc := k8s.NewLoadBalancerController(lbcInput)

	if *readyStatus {
		go func() {
			port := fmt.Sprintf(":%v", *readyStatusPort)
			s := http.NewServeMux()
			s.HandleFunc("/nginx-ready", ready(lbc))
			nl.Fatal(l, http.ListenAndServe(port, s)) // nolint:gosec
		}()
	}

	go handleTermination(lbc, nginxManager, syslogListener, process)

	lbc.Run()

	for {
		nl.Info(l, "Waiting for the controller to exit...")
		time.Sleep(30 * time.Second)
	}
}

func mustCreateConfigAndKubeClient(ctx context.Context) (*rest.Config, *kubernetes.Clientset) {
	l := nl.LoggerFromContext(ctx)
	var config *rest.Config
	var err error
	if *proxyURL != "" {
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{},
			&clientcmd.ConfigOverrides{
				ClusterInfo: clientcmdapi.Cluster{
					Server: *proxyURL,
				},
			}).ClientConfig()
		if err != nil {
			nl.Fatalf(l, "error creating client configuration: %v", err)
		}
	} else {
		if config, err = rest.InClusterConfig(); err != nil {
			nl.Fatalf(l, "error creating client configuration: %v", err)
		}
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		nl.Fatalf(l, "Failed to create client: %v.", err)
	}

	return config, kubeClient
}

// mustValidateKubernetesVersionInfo calls internally os.Exit if
// the k8s version can not be retrieved or the version is not supported.
func mustValidateKubernetesVersionInfo(ctx context.Context, kubeClient kubernetes.Interface) {
	l := nl.LoggerFromContext(ctx)
	k8sVersion, err := k8s.GetK8sVersion(kubeClient)
	if err != nil {
		nl.Fatalf(l, "error retrieving k8s version: %v", err)
	}
	nl.Infof(l, "Kubernetes version: %v", k8sVersion)

	minK8sVersion, err := util_version.ParseGeneric("1.22.0")
	if err != nil {
		nl.Fatalf(l, "unexpected error parsing minimum supported version: %v", err)
	}

	if !k8sVersion.AtLeast(minK8sVersion) {
		nl.Fatalf(l, "Versions of Kubernetes < %v are not supported, please refer to the documentation for details on supported versions and legacy controller support.", minK8sVersion)
	}
}

// mustValidateIngressClass calls internally os.Exit
// and terminates the program if the ingress class is not valid.
func mustValidateIngressClass(ctx context.Context, kubeClient kubernetes.Interface) {
	l := nl.LoggerFromContext(ctx)
	ingressClassRes, err := kubeClient.NetworkingV1().IngressClasses().Get(context.TODO(), *ingressClass, meta_v1.GetOptions{})
	if err != nil {
		nl.Fatalf(l, "Error when getting IngressClass %v: %v", *ingressClass, err)
	}

	if ingressClassRes.Spec.Controller != k8s.IngressControllerName {
		nl.Fatalf(l, "IngressClass with name %v has an invalid Spec.Controller %v; expected %v", ingressClassRes.Name, ingressClassRes.Spec.Controller, k8s.IngressControllerName)
	}
}

func checkNamespaces(ctx context.Context, kubeClient kubernetes.Interface) {
	l := nl.LoggerFromContext(ctx)
	if *watchNamespaceLabel != "" {
		// bootstrap the watched namespace list
		var newWatchNamespaces []string
		nsList, err := kubeClient.CoreV1().Namespaces().List(context.TODO(), meta_v1.ListOptions{LabelSelector: *watchNamespaceLabel})
		if err != nil {
			nl.Errorf(l, "error when getting Namespaces with the label selector %v: %v", watchNamespaceLabel, err)
		}
		for _, ns := range nsList.Items {
			newWatchNamespaces = append(newWatchNamespaces, ns.Name)
		}
		watchNamespaces = newWatchNamespaces
		nl.Infof(l, "Namespaces watched using label %v: %v", *watchNamespaceLabel, watchNamespaces)
	} else {
		checkNamespaceExists(ctx, kubeClient, watchNamespaces)
	}
	checkNamespaceExists(ctx, kubeClient, watchSecretNamespaces)
}

func checkNamespaceExists(ctx context.Context, kubeClient kubernetes.Interface, namespaces []string) {
	l := nl.LoggerFromContext(ctx)
	for _, ns := range namespaces {
		if ns != "" {
			_, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), ns, meta_v1.GetOptions{})
			if err != nil {
				nl.Warnf(l, "Error when getting Namespace %v: %v", ns, err)
			}
		}
	}
}

func createCustomClients(ctx context.Context, config *rest.Config) (dynamic.Interface, k8s_nginx.Interface) {
	l := nl.LoggerFromContext(ctx)
	var dynClient dynamic.Interface
	var err error
	if *appProtectDos || *appProtect || *ingressLink != "" {
		dynClient, err = dynamic.NewForConfig(config)
		if err != nil {
			nl.Fatalf(l, "Failed to create dynamic client: %v.", err)
		}
	}
	var confClient k8s_nginx.Interface
	if *enableCustomResources {
		confClient, err = k8s_nginx.NewForConfig(config)
		if err != nil {
			nl.Fatalf(l, "Failed to create a conf client: %v", err)
		}

		// required for emitting Events for VirtualServer
		err = conf_scheme.AddToScheme(scheme.Scheme)
		if err != nil {
			nl.Fatalf(l, "Failed to add configuration types to the scheme: %v", err)
		}
	}
	return dynClient, confClient
}

func createPlusClient(ctx context.Context, nginxPlus bool, useFakeNginxManager bool, nginxManager nginx.Manager) *client.NginxClient {
	l := nl.LoggerFromContext(ctx)
	var plusClient *client.NginxClient
	var err error

	if nginxPlus && !useFakeNginxManager {
		httpClient := getSocketClient("/var/lib/nginx/nginx-plus-api.sock")
		plusClient, err = client.NewNginxClient("http://nginx-plus-api/api", client.WithHTTPClient(httpClient))
		if err != nil {
			nl.Fatalf(l, "Failed to create NginxClient for Plus: %v", err)
		}
		nginxManager.SetPlusClients(plusClient, httpClient)
	}
	return plusClient
}

func createTemplateExecutors(ctx context.Context) (*version1.TemplateExecutor, *version2.TemplateExecutor) {
	l := nl.LoggerFromContext(ctx)
	nginxConfTemplatePath := "nginx.tmpl"
	nginxIngressTemplatePath := "nginx.ingress.tmpl"
	nginxVirtualServerTemplatePath := "nginx.virtualserver.tmpl"
	nginxTransportServerTemplatePath := "nginx.transportserver.tmpl"
	if *nginxPlus {
		nginxConfTemplatePath = "nginx-plus.tmpl"
		nginxIngressTemplatePath = "nginx-plus.ingress.tmpl"
		nginxVirtualServerTemplatePath = "nginx-plus.virtualserver.tmpl"
		nginxTransportServerTemplatePath = "nginx-plus.transportserver.tmpl"
	}

	if *mainTemplatePath != "" {
		nginxConfTemplatePath = *mainTemplatePath
	}
	if *ingressTemplatePath != "" {
		nginxIngressTemplatePath = *ingressTemplatePath
	}
	if *virtualServerTemplatePath != "" {
		nginxVirtualServerTemplatePath = *virtualServerTemplatePath
	}
	if *transportServerTemplatePath != "" {
		nginxTransportServerTemplatePath = *transportServerTemplatePath
	}

	templateExecutor, err := version1.NewTemplateExecutor(nginxConfTemplatePath, nginxIngressTemplatePath)
	if err != nil {
		nl.Fatalf(l, "Error creating TemplateExecutor: %v", err)
	}

	templateExecutorV2, err := version2.NewTemplateExecutor(nginxVirtualServerTemplatePath, nginxTransportServerTemplatePath)
	if err != nil {
		nl.Fatalf(l, "Error creating TemplateExecutorV2: %v", err)
	}

	return templateExecutor, templateExecutorV2
}

func createNginxManager(ctx context.Context, managerCollector collectors.ManagerCollector) (nginx.Manager, bool) {
	useFakeNginxManager := *proxyURL != ""
	var nginxManager nginx.Manager
	if useFakeNginxManager {
		nginxManager = nginx.NewFakeManager("/etc/nginx")
	} else {
		timeout := time.Duration(*nginxReloadTimeout) * time.Millisecond
		nginxManager = nginx.NewLocalManager(ctx, "/etc/nginx/", *nginxDebug, managerCollector, timeout)
	}
	return nginxManager, useFakeNginxManager
}

func getNginxVersionInfo(ctx context.Context, nginxManager nginx.Manager) nginx.Version {
	l := nl.LoggerFromContext(ctx)
	nginxInfo := nginxManager.Version()
	nl.Infof(l, "Using %s", nginxInfo.String())

	if *nginxPlus && !nginxInfo.IsPlus {
		nl.Fatalf(l, "NGINX Plus flag enabled (-nginx-plus) without NGINX Plus binary")
	} else if !*nginxPlus && nginxInfo.IsPlus {
		nl.Fatalf(l, "NGINX Plus binary found without NGINX Plus flag (-nginx-plus)")
	}
	return nginxInfo
}

func getAppProtectVersionInfo(ctx context.Context) string {
	l := nl.LoggerFromContext(ctx)
	v, err := os.ReadFile(appProtectVersionPath)
	if err != nil {
		nl.Fatalf(l, "Cannot detect the AppProtect version, %s", err.Error())
	}
	version := strings.TrimSpace(string(v))
	nl.Infof(l, "Using AppProtect Version %s", version)
	return version
}

func getAgentVersionInfo(nginxManager nginx.Manager) string {
	return nginxManager.AgentVersion()
}

type childProcesses struct {
	nginxDone      chan error
	aPPluginEnable bool
	aPPluginDone   chan error
	aPDosEnable    bool
	aPDosDone      chan error
	agentEnable    bool
	agentDone      chan error
}

// newChildProcesses starts the several child processes based on flags set.
// AppProtect. AppProtectDos, Agent.
func startChildProcesses(nginxManager nginx.Manager, appProtectV5 bool) childProcesses {
	var aPPluginDone chan error

	// Do not start AppProtect Plugins when using v5.
	if *appProtect && !appProtectV5 {
		aPPluginDone = make(chan error, 1)
		nginxManager.AppProtectPluginStart(aPPluginDone, *appProtectLogLevel)
	}

	var aPPDosAgentDone chan error

	if *appProtectDos {
		aPPDosAgentDone = make(chan error, 1)
		nginxManager.AppProtectDosAgentStart(aPPDosAgentDone, *appProtectDosDebug, *appProtectDosMaxDaemons, *appProtectDosMaxWorkers, *appProtectDosMemory)
	}

	nginxDone := make(chan error, 1)
	nginxManager.Start(nginxDone)

	var agentDone chan error
	if *agent {
		agentDone = make(chan error, 1)
		nginxManager.AgentStart(agentDone, *agentInstanceGroup)
	}

	return childProcesses{
		nginxDone:      nginxDone,
		aPPluginEnable: *appProtect,
		aPPluginDone:   aPPluginDone,
		aPDosEnable:    *appProtectDos,
		aPDosDone:      aPPDosAgentDone,
		agentEnable:    *agent,
		agentDone:      agentDone,
	}
}

func processDefaultServerSecret(ctx context.Context, kubeClient *kubernetes.Clientset, nginxManager nginx.Manager) bool {
	l := nl.LoggerFromContext(ctx)
	var sslRejectHandshake bool

	if *defaultServerSecret != "" {
		secret, err := getAndValidateSecret(kubeClient, *defaultServerSecret)
		if err != nil {
			nl.Fatalf(l, "Error trying to get the default server TLS secret %v: %v", *defaultServerSecret, err)
		}

		bytes := configs.GenerateCertAndKeyFileContent(secret)
		nginxManager.CreateSecret(configs.DefaultServerSecretName, bytes, nginx.TLSSecretFileMode)
	} else {
		_, err := os.Stat(configs.DefaultServerSecretPath)
		if err != nil {
			if os.IsNotExist(err) {
				// file doesn't exist - it is OK! we will reject TLS connections in the default server
				sslRejectHandshake = true
			} else {
				nl.Fatalf(l, "Error checking the default server TLS cert and key in %s: %v", configs.DefaultServerSecretPath, err)
			}
		}
	}
	return sslRejectHandshake
}

func processWildcardSecret(ctx context.Context, kubeClient *kubernetes.Clientset, nginxManager nginx.Manager) bool {
	l := nl.LoggerFromContext(ctx)
	if *wildcardTLSSecret != "" {
		secret, err := getAndValidateSecret(kubeClient, *wildcardTLSSecret)
		if err != nil {
			nl.Fatalf(l, "Error trying to get the wildcard TLS secret %v: %v", *wildcardTLSSecret, err)
		}

		bytes := configs.GenerateCertAndKeyFileContent(secret)
		nginxManager.CreateSecret(configs.WildcardSecretName, bytes, nginx.TLSSecretFileMode)
	}
	return *wildcardTLSSecret != ""
}

func createGlobalConfigurationValidator() *cr_validation.GlobalConfigurationValidator {
	forbiddenListenerPorts := map[int]bool{
		80:  true,
		443: true,
	}

	if *nginxStatus {
		forbiddenListenerPorts[*nginxStatusPort] = true
	}
	if *enablePrometheusMetrics {
		forbiddenListenerPorts[*prometheusMetricsListenPort] = true
	}

	if *enableServiceInsight {
		forbiddenListenerPorts[*serviceInsightListenPort] = true
	}

	if *enableTLSPassthrough {
		forbiddenListenerPorts[*tlsPassthroughPort] = true
	}

	return cr_validation.NewGlobalConfigurationValidator(forbiddenListenerPorts)
}

// mustProcessNginxConfig calls internally os.Exit
// if can't generate a valid NGINX config.
func mustProcessNginxConfig(staticCfgParams *configs.StaticConfigParams, cfgParams *configs.ConfigParams, templateExecutor *version1.TemplateExecutor, nginxManager nginx.Manager) {
	l := nl.LoggerFromContext(cfgParams.Context)
	ngxConfig := configs.GenerateNginxMainConfig(staticCfgParams, cfgParams)
	content, err := templateExecutor.ExecuteMainConfigTemplate(ngxConfig)
	if err != nil {
		nl.Fatalf(l, "Error generating NGINX main config: %v", err)
	}
	nginxManager.CreateMainConfig(content)

	nginxManager.UpdateConfigVersionFile(ngxConfig.OpenTracingLoadModule)

	nginxManager.SetOpenTracing(ngxConfig.OpenTracingLoadModule)

	if ngxConfig.OpenTracingLoadModule {
		err := nginxManager.CreateOpenTracingTracerConfig(cfgParams.MainOpenTracingTracerConfig)
		if err != nil {
			nl.Fatalf(l, "Error creating OpenTracing tracer config file: %v", err)
		}
	}
}

// getSocketClient gets a http.Client with a unix socket transport.
func getSocketClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}
}

// getAndValidateSecret gets and validates a secret.
func getAndValidateSecret(kubeClient *kubernetes.Clientset, secretNsName string) (secret *api_v1.Secret, err error) {
	ns, name, err := k8s.ParseNamespaceName(secretNsName)
	if err != nil {
		return nil, fmt.Errorf("could not parse the %v argument: %w", secretNsName, err)
	}
	secret, err = kubeClient.CoreV1().Secrets(ns).Get(context.TODO(), name, meta_v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get %v: %w", secretNsName, err)
	}
	err = secrets.ValidateTLSSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("%v is invalid: %w", secretNsName, err)
	}
	return secret, nil
}

func handleTermination(lbc *k8s.LoadBalancerController, nginxManager nginx.Manager, listener metrics.SyslogListener, cpcfg childProcesses) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)

	select {
	case err := <-cpcfg.nginxDone:
		if err != nil {
			nl.Fatalf(lbc.Logger, "nginx command exited unexpectedly with status: %v", err)
		} else {
			nl.Info(lbc.Logger, "nginx command exited successfully")
		}
	case err := <-cpcfg.aPPluginDone:
		nl.Fatalf(lbc.Logger, "AppProtectPlugin command exited unexpectedly with status: %v", err)
	case err := <-cpcfg.aPDosDone:
		nl.Fatalf(lbc.Logger, "AppProtectDosAgent command exited unexpectedly with status: %v", err)
	case <-signalChan:
		nl.Info(lbc.Logger, "Received SIGTERM, shutting down")
		lbc.Stop()
		nginxManager.Quit()
		<-cpcfg.nginxDone
		if cpcfg.aPPluginEnable {
			nginxManager.AppProtectPluginQuit()
			<-cpcfg.aPPluginDone
		}
		if cpcfg.aPDosEnable {
			nginxManager.AppProtectDosAgentQuit()
			<-cpcfg.aPDosDone
		}
		listener.Stop()
	}
	nl.Info(lbc.Logger, "Exiting successfully")
	os.Exit(0)
}

func ready(lbc *k8s.LoadBalancerController) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !lbc.IsNginxReady() {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Ready")
	}
}

func createManagerAndControllerCollectors(ctx context.Context, constLabels map[string]string) (collectors.ManagerCollector, collectors.ControllerCollector, *prometheus.Registry) {
	l := nl.LoggerFromContext(ctx)
	var err error

	var registry *prometheus.Registry
	var mc collectors.ManagerCollector
	var cc collectors.ControllerCollector
	mc = collectors.NewManagerFakeCollector()
	cc = collectors.NewControllerFakeCollector()

	if *enablePrometheusMetrics {
		registry = prometheus.NewRegistry()
		mc = collectors.NewLocalManagerMetricsCollector(constLabels)
		cc = collectors.NewControllerMetricsCollector(*enableCustomResources, constLabels)
		processCollector := collectors.NewNginxProcessesMetricsCollector(ctx, constLabels)
		workQueueCollector := collectors.NewWorkQueueMetricsCollector(constLabels)

		err = mc.Register(registry)
		if err != nil {
			nl.Errorf(l, "Error registering Manager Prometheus metrics: %v", err)
		}

		err = cc.Register(registry)
		if err != nil {
			nl.Errorf(l, "Error registering Controller Prometheus metrics: %v", err)
		}

		err = processCollector.Register(registry)
		if err != nil {
			nl.Errorf(l, "Error registering NginxProcess Prometheus metrics: %v", err)
		}

		err = workQueueCollector.Register(registry)
		if err != nil {
			nl.Errorf(l, "Error registering WorkQueue Prometheus metrics: %v", err)
		}
	}
	return mc, cc, registry
}

func createPlusAndLatencyCollectors(
	ctx context.Context,
	registry *prometheus.Registry,
	constLabels map[string]string,
	kubeClient *kubernetes.Clientset,
	plusClient *client.NginxClient,
	isMesh bool,
) (*nginxCollector.NginxPlusCollector, metrics.SyslogListener, collectors.LatencyCollector) {
	l := nl.LoggerFromContext(ctx)
	var prometheusSecret *api_v1.Secret
	var err error
	var lc collectors.LatencyCollector
	lc = collectors.NewLatencyFakeCollector()
	var syslogListener metrics.SyslogListener
	syslogListener = metrics.NewSyslogFakeServer()

	if *prometheusTLSSecretName != "" {
		prometheusSecret, err = getAndValidateSecret(kubeClient, *prometheusTLSSecretName)
		if err != nil {
			nl.Fatalf(l, "Error trying to get the prometheus TLS secret %v: %v", *prometheusTLSSecretName, err)
		}
	}

	var plusCollector *nginxCollector.NginxPlusCollector
	if *enablePrometheusMetrics {
		upstreamServerVariableLabels := []string{"service", "resource_type", "resource_name", "resource_namespace"}
		upstreamServerPeerVariableLabelNames := []string{"pod_name"}
		if isMesh {
			upstreamServerPeerVariableLabelNames = append(upstreamServerPeerVariableLabelNames, "pod_owner")
		}
		if *nginxPlus {
			streamUpstreamServerVariableLabels := []string{"service", "resource_type", "resource_name", "resource_namespace"}
			streamUpstreamServerPeerVariableLabelNames := []string{"pod_name"}

			serverZoneVariableLabels := []string{"resource_type", "resource_name", "resource_namespace"}
			streamServerZoneVariableLabels := []string{"resource_type", "resource_name", "resource_namespace"}
			variableLabelNames := nginxCollector.NewVariableLabelNames(upstreamServerVariableLabels, serverZoneVariableLabels, upstreamServerPeerVariableLabelNames,
				streamUpstreamServerVariableLabels, streamServerZoneVariableLabels, streamUpstreamServerPeerVariableLabelNames, nil)
			logger := kitlog.NewLogfmtLogger(os.Stdout)
			logger = level.NewFilter(logger, level.AllowError())
			plusCollector = nginxCollector.NewNginxPlusCollector(plusClient, "nginx_ingress_nginxplus", variableLabelNames, constLabels, logger)
			go metrics.RunPrometheusListenerForNginxPlus(ctx, *prometheusMetricsListenPort, plusCollector, registry, prometheusSecret)
		} else {
			httpClient := getSocketClient("/var/lib/nginx/nginx-status.sock")
			client := metrics.NewNginxMetricsClient(httpClient)
			go metrics.RunPrometheusListenerForNginx(ctx, *prometheusMetricsListenPort, client, registry, constLabels, prometheusSecret)
		}
		if *enableLatencyMetrics {
			lc = collectors.NewLatencyMetricsCollector(ctx, constLabels, upstreamServerVariableLabels, upstreamServerPeerVariableLabelNames)
			if err := lc.Register(registry); err != nil {
				nl.Errorf(l, "Error registering Latency Prometheus metrics: %v", err)
			}
			syslogListener = metrics.NewLatencyMetricsListener(ctx, "/var/lib/nginx/nginx-syslog.sock", lc)
			go syslogListener.Run()
		}
	}

	return plusCollector, syslogListener, lc
}

func createHealthProbeEndpoint(kubeClient *kubernetes.Clientset, plusClient *client.NginxClient, cnf *configs.Configurator) {
	l := nl.LoggerFromContext(cnf.CfgParams.Context)
	if !*enableServiceInsight {
		return
	}
	var serviceInsightSecret *api_v1.Secret
	var err error

	if *serviceInsightTLSSecretName != "" {
		serviceInsightSecret, err = getAndValidateSecret(kubeClient, *serviceInsightTLSSecretName)
		if err != nil {
			nl.Fatalf(l, "Error trying to get the service insight TLS secret %v: %v", *serviceInsightTLSSecretName, err)
		}
	}
	go healthcheck.RunHealthCheck(*serviceInsightListenPort, plusClient, cnf, serviceInsightSecret)
}

// mustProcessGlobalConfiguration calls internally os.Exit
// if unable to parse provided global configuration.
func mustProcessGlobalConfiguration(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	if *globalConfiguration != "" {
		_, _, err := k8s.ParseNamespaceName(*globalConfiguration)
		if err != nil {
			nl.Fatalf(l, "Error parsing the global-configuration argument: %v", err)
		}

		if !*enableCustomResources {
			nl.Fatalf(l, "global-configuration flag requires -enable-custom-resources")
		}
	}
}

func processConfigMaps(kubeClient *kubernetes.Clientset, cfgParams *configs.ConfigParams, nginxManager nginx.Manager, templateExecutor *version1.TemplateExecutor) *configs.ConfigParams {
	l := nl.LoggerFromContext(cfgParams.Context)
	if *nginxConfigMaps != "" {
		ns, name, err := k8s.ParseNamespaceName(*nginxConfigMaps)
		if err != nil {
			nl.Fatalf(l, "Error parsing the nginx-configmaps argument: %v", err)
		}
		cfm, err := kubeClient.CoreV1().ConfigMaps(ns).Get(context.TODO(), name, meta_v1.GetOptions{})
		if err != nil {
			nl.Fatalf(l, "Error when getting %v: %v", *nginxConfigMaps, err)
		}
		cfgParams = configs.ParseConfigMap(cfgParams.Context, cfm, *nginxPlus, *appProtect, *appProtectDos, *enableTLSPassthrough)
		if cfgParams.MainServerSSLDHParamFileContent != nil {
			fileName, err := nginxManager.CreateDHParam(*cfgParams.MainServerSSLDHParamFileContent)
			if err != nil {
				nl.Fatalf(l, "Configmap %s/%s: Could not update dhparams: %v", ns, name, err)
			} else {
				cfgParams.MainServerSSLDHParam = fileName
			}
		}
		if cfgParams.MainTemplate != nil {
			err = templateExecutor.UpdateMainTemplate(cfgParams.MainTemplate)
			if err != nil {
				nl.Fatalf(l, "Error updating NGINX main template: %v", err)
			}
		}
		if cfgParams.IngressTemplate != nil {
			err = templateExecutor.UpdateIngressTemplate(cfgParams.IngressTemplate)
			if err != nil {
				nl.Fatalf(l, "Error updating ingress template: %v", err)
			}
		}
	}
	return cfgParams
}

func updateSelfWithVersionInfo(ctx context.Context, kubeClient *kubernetes.Clientset, version, appProtectVersion, agentVersion string, nginxVersion nginx.Version, maxRetries int, waitTime time.Duration) {
	l := nl.LoggerFromContext(ctx)
	podUpdated := false

	for i := 0; (i < maxRetries || maxRetries == 0) && !podUpdated; i++ {
		if i > 0 {
			time.Sleep(waitTime)
		}
		pod, err := kubeClient.CoreV1().Pods(os.Getenv("POD_NAMESPACE")).Get(context.TODO(), os.Getenv("POD_NAME"), meta_v1.GetOptions{})
		if err != nil {
			nl.Errorf(l, "Error getting pod on attempt %d of %d: %v", i+1, maxRetries, err)
			continue
		}

		// Copy pod and update the labels.
		newPod := pod.DeepCopy()
		labels := newPod.ObjectMeta.Labels
		if labels == nil {
			labels = make(map[string]string)
		}

		labels[nginxVersionLabel] = nginxVersion.Format()
		labels[versionLabel] = strings.TrimPrefix(version, "v")
		if appProtectVersion != "" {
			labels[appProtectVersionLabel] = appProtectVersion
		}
		if agentVersion != "" {
			labels[agentVersionLabel] = agentVersion
		}
		newPod.ObjectMeta.Labels = labels

		_, err = kubeClient.CoreV1().Pods(newPod.ObjectMeta.Namespace).Update(context.TODO(), newPod, meta_v1.UpdateOptions{})
		if err != nil {
			nl.Errorf(l, "Error updating pod with labels on attempt %d of %d: %v", i+1, maxRetries, err)
			continue
		}

		nl.Infof(l, "Pod label updated: %s", pod.ObjectMeta.Name)
		podUpdated = true
	}

	if !podUpdated {
		nl.Errorf(l, "Failed to update pod labels after %d attempts", maxRetries)
	}
}

func initLogger(logFormat string, level slog.Level, out io.Writer) context.Context {
	programLevel := new(slog.LevelVar) // Info by default
	var h slog.Handler
	switch {
	case logFormat == "glog":
		h = nic_glog.New(out, &nic_glog.Options{Level: programLevel})
	case logFormat == "json":
		h = slog.NewJSONHandler(out, &slog.HandlerOptions{Level: programLevel})
	case logFormat == "text":
		h = slog.NewTextHandler(out, &slog.HandlerOptions{Level: programLevel})
	default:
		h = nic_glog.New(out, &nic_glog.Options{Level: programLevel})
	}
	l := slog.New(h)
	slog.SetDefault(l)
	c := context.Background()

	programLevel.Set(level)

	return nl.ContextWithLogger(c, l)
}
