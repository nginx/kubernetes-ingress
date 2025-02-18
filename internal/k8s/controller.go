/*
Copyright 2015 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotect"
	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotectdos"
	"github.com/nginx/kubernetes-ingress/internal/telemetry"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/rest"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginxinc/nginx-service-mesh/pkg/spiffe"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/record"

	cm_controller "github.com/nginx/kubernetes-ingress/internal/certmanager"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	ed_controller "github.com/nginx/kubernetes-ingress/internal/externaldns"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"

	api_v1 "k8s.io/api/core/v1"
	discovery_v1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	k8s_nginx "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
	k8s_nginx_informers "github.com/nginx/kubernetes-ingress/pkg/client/informers/externalversions"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

const (
	ingressClassKey = "kubernetes.io/ingress.class"
	// IngressControllerName holds Ingress Controller name
	IngressControllerName = "nginx.org/ingress-controller"

	typeKeyword                                     = "type"
	helmReleaseType                                 = "helm.sh/release.v1"
	splitClientAmountWhenWeightChangesDynamicReload = 101
)

var (
	ingressLinkGVR = schema.GroupVersionResource{
		Group:    "cis.f5.com",
		Version:  "v1",
		Resource: "ingresslinks",
	}
	ingressLinkGVK = schema.GroupVersionKind{
		Group:   "cis.f5.com",
		Version: "v1",
		Kind:    "IngressLink",
	}
)

type podEndpoint struct {
	Address string
	PodName string
	// MeshPodOwner is used for NGINX Service Mesh metrics
	configs.MeshPodOwner
}

type specialSecrets struct {
	defaultServerSecret string
	wildcardTLSSecret   string
	licenseSecret       string
	clientAuthSecret    string
	trustedCertSecret   string
}

type controllerMetadata struct {
	namespace string
	pod       *api_v1.Pod
}

// LoadBalancerController watches Kubernetes API and
// reconfigures NGINX via NginxController when needed
type LoadBalancerController struct {
	client                        kubernetes.Interface
	confClient                    k8s_nginx.Interface
	dynClient                     dynamic.Interface
	restConfig                    *rest.Config
	cacheSyncs                    []cache.InformerSynced
	namespacedInformers           map[string]*namespacedInformer
	configMapController           cache.Controller
	mgmtConfigMapController       cache.Controller
	globalConfigurationController cache.Controller
	ingressLinkInformer           cache.SharedIndexInformer
	configMapLister               storeToConfigMapLister
	mgmtConfigMapLister           storeToConfigMapLister
	globalConfigurationLister     cache.Store
	ingressLinkLister             cache.Store
	namespaceLabeledLister        cache.Store
	syncQueue                     *taskQueue
	ctx                           context.Context
	Logger                        *slog.Logger
	cancel                        context.CancelFunc
	configurator                  *configs.Configurator
	controllerNamespace           string
	watchNginxConfigMaps          bool
	watchMGMTConfigMap            bool
	watchGlobalConfiguration      bool
	watchIngressLink              bool
	isNginxPlus                   bool
	appProtectEnabled             bool
	appProtectDosEnabled          bool
	recorder                      record.EventRecorder
	specialSecrets                specialSecrets
	ingressClass                  string
	statusUpdater                 *statusUpdater
	leaderElector                 *leaderelection.LeaderElector
	reportIngressStatus           bool
	isLeaderElectionEnabled       bool
	leaderElectionLockName        string
	resync                        time.Duration
	namespaceList                 []string
	secretNamespaceList           []string
	metadata                      controllerMetadata
	areCustomResourcesEnabled     bool
	enableOIDC                    bool
	metricsCollector              collectors.ControllerCollector
	globalConfigurationValidator  *validation.GlobalConfigurationValidator
	transportServerValidator      *validation.TransportServerValidator
	spiffeCertFetcher             *spiffe.X509CertFetcher
	internalRoutesEnabled         bool
	syncLock                      sync.Mutex
	isNginxReady                  bool
	isPrometheusEnabled           bool
	isLatencyMetricsEnabled       bool
	configuration                 *Configuration
	secretStore                   secrets.SecretStore
	appProtectConfiguration       appprotect.Configuration
	dosConfiguration              *appprotectdos.Configuration
	configMap                     *api_v1.ConfigMap
	mgmtConfigMap                 *api_v1.ConfigMap
	certManagerController         *cm_controller.CmController
	externalDNSController         *ed_controller.ExtDNSController
	batchSyncEnabled              bool
	updateAllConfigsOnBatch       bool
	enableBatchReload             bool
	isIPV6Disabled                bool
	namespaceWatcherController    cache.Controller
	telemetryCollector            *telemetry.Collector
	telemetryChan                 chan struct{}
	weightChangesDynamicReload    bool
	nginxConfigMapName            string
	mgmtConfigMapName             string
}

var keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

// NewLoadBalancerControllerInput holds the input needed to call NewLoadBalancerController.
type NewLoadBalancerControllerInput struct {
	KubeClient                   kubernetes.Interface
	ConfClient                   k8s_nginx.Interface
	DynClient                    dynamic.Interface
	RestConfig                   *rest.Config
	Recorder                     record.EventRecorder
	ResyncPeriod                 time.Duration
	LoggerContext                context.Context
	Namespace                    []string
	SecretNamespace              []string
	NginxConfigurator            *configs.Configurator
	DefaultServerSecret          string
	AppProtectEnabled            bool
	AppProtectDosEnabled         bool
	AppProtectVersion            string
	IsNginxPlus                  bool
	IngressClass                 string
	ExternalServiceName          string
	IngressLink                  string
	ControllerNamespace          string
	Pod                          *api_v1.Pod
	ReportIngressStatus          bool
	IsLeaderElectionEnabled      bool
	LeaderElectionLockName       string
	WildcardTLSSecret            string
	ConfigMaps                   string
	MGMTConfigMap                string
	GlobalConfiguration          string
	AreCustomResourcesEnabled    bool
	EnableOIDC                   bool
	MetricsCollector             collectors.ControllerCollector
	GlobalConfigurationValidator *validation.GlobalConfigurationValidator
	TransportServerValidator     *validation.TransportServerValidator
	VirtualServerValidator       *validation.VirtualServerValidator
	SpireAgentAddress            string
	InternalRoutesEnabled        bool
	IsPrometheusEnabled          bool
	IsLatencyMetricsEnabled      bool
	IsTLSPassthroughEnabled      bool
	TLSPassthroughPort           int
	SnippetsEnabled              bool
	CertManagerEnabled           bool
	ExternalDNSEnabled           bool
	IsIPV6Disabled               bool
	WatchNamespaceLabel          string
	EnableTelemetryReporting     bool
	TelemetryReportingEndpoint   string
	BuildOS                      string
	NICVersion                   string
	DynamicWeightChangesReload   bool
	InstallationFlags            []string
}

// NewLoadBalancerController creates a controller
func NewLoadBalancerController(input NewLoadBalancerControllerInput) *LoadBalancerController {
	specialSecrets := specialSecrets{
		defaultServerSecret: input.DefaultServerSecret,
		wildcardTLSSecret:   input.WildcardTLSSecret,
	}
	if input.IsNginxPlus {
		specialSecrets.licenseSecret = fmt.Sprintf("%s/%s", input.ControllerNamespace, input.NginxConfigurator.MgmtCfgParams.Secrets.License)
		specialSecrets.clientAuthSecret = fmt.Sprintf("%s/%s", input.ControllerNamespace, input.NginxConfigurator.MgmtCfgParams.Secrets.ClientAuth)
		specialSecrets.trustedCertSecret = fmt.Sprintf("%s/%s", input.ControllerNamespace, input.NginxConfigurator.MgmtCfgParams.Secrets.TrustedCert)
	}
	lbc := &LoadBalancerController{
		client:                       input.KubeClient,
		confClient:                   input.ConfClient,
		dynClient:                    input.DynClient,
		restConfig:                   input.RestConfig,
		recorder:                     input.Recorder,
		Logger:                       nl.LoggerFromContext(input.LoggerContext),
		configurator:                 input.NginxConfigurator,
		controllerNamespace:          input.ControllerNamespace,
		specialSecrets:               specialSecrets,
		appProtectEnabled:            input.AppProtectEnabled,
		appProtectDosEnabled:         input.AppProtectDosEnabled,
		isNginxPlus:                  input.IsNginxPlus,
		ingressClass:                 input.IngressClass,
		reportIngressStatus:          input.ReportIngressStatus,
		isLeaderElectionEnabled:      input.IsLeaderElectionEnabled,
		leaderElectionLockName:       input.LeaderElectionLockName,
		resync:                       input.ResyncPeriod,
		namespaceList:                input.Namespace,
		secretNamespaceList:          input.SecretNamespace,
		metadata:                     controllerMetadata{namespace: input.ControllerNamespace, pod: input.Pod},
		areCustomResourcesEnabled:    input.AreCustomResourcesEnabled,
		enableOIDC:                   input.EnableOIDC,
		metricsCollector:             input.MetricsCollector,
		globalConfigurationValidator: input.GlobalConfigurationValidator,
		transportServerValidator:     input.TransportServerValidator,
		internalRoutesEnabled:        input.InternalRoutesEnabled,
		isPrometheusEnabled:          input.IsPrometheusEnabled,
		isLatencyMetricsEnabled:      input.IsLatencyMetricsEnabled,
		isIPV6Disabled:               input.IsIPV6Disabled,
		weightChangesDynamicReload:   input.DynamicWeightChangesReload,
		nginxConfigMapName:           input.ConfigMaps,
		mgmtConfigMapName:            input.MGMTConfigMap,
	}

	lbc.syncQueue = newTaskQueue(lbc.Logger, lbc.sync)
	var err error
	if input.SpireAgentAddress != "" {
		lbc.spiffeCertFetcher, err = spiffe.NewX509CertFetcher(input.SpireAgentAddress, nil)
		if err != nil {
			nl.Fatalf(lbc.Logger, "failed to initialize spiffe certfetcher: %v", err)
		}
	}

	isDynamicNs := input.WatchNamespaceLabel != ""

	if isDynamicNs {
		lbc.addNamespaceHandler(createNamespaceHandlers(lbc), input.WatchNamespaceLabel)
	}

	if input.CertManagerEnabled {
		lbc.certManagerController = cm_controller.NewCmController(cm_controller.BuildOpts(input.LoggerContext, lbc.restConfig, lbc.client, lbc.namespaceList, lbc.recorder, lbc.confClient, isDynamicNs))
	}

	if input.ExternalDNSEnabled {
		lbc.externalDNSController = ed_controller.NewController(ed_controller.BuildOpts(input.LoggerContext, lbc.namespaceList, lbc.recorder, lbc.confClient, input.ResyncPeriod, isDynamicNs))
	}

	nl.Debugf(lbc.Logger, "Nginx Ingress Controller has class: %v", input.IngressClass)

	lbc.namespacedInformers = make(map[string]*namespacedInformer)
	for _, ns := range lbc.namespaceList {
		if isDynamicNs && ns == "" {
			// no initial namespaces with watched label - skip creating informers for now
			break
		}
		lbc.newNamespacedInformer(ns)
	}

	if lbc.areCustomResourcesEnabled {
		if input.GlobalConfiguration != "" {
			lbc.watchGlobalConfiguration = true
			ns, name, _ := ParseNamespaceName(input.GlobalConfiguration)
			lbc.addGlobalConfigurationHandler(createGlobalConfigurationHandlers(lbc), ns, name)
		}
	}

	if input.ConfigMaps != "" {
		nginxConfigMapsNS, nginxConfigMapsName, err := ParseNamespaceName(input.ConfigMaps)
		if err != nil {
			nl.Warn(lbc.Logger, err)
		} else {
			lbc.watchNginxConfigMaps = true
			lbc.addConfigMapHandler(createConfigMapHandlers(lbc, nginxConfigMapsName), nginxConfigMapsNS)
		}
	}

	if input.MGMTConfigMap != "" {
		mgmtConfigMapNS, mgmtConfigMapName, err := ParseNamespaceName(input.MGMTConfigMap)
		if err != nil {
			nl.Warn(lbc.Logger, err)
		} else {
			lbc.watchMGMTConfigMap = true
			lbc.addMGMTConfigMapHandler(createConfigMapHandlers(lbc, mgmtConfigMapName), mgmtConfigMapNS)
		}
	}

	if input.IngressLink != "" {
		lbc.watchIngressLink = true
		lbc.addIngressLinkHandler(createIngressLinkHandlers(lbc), input.IngressLink)
	}

	if input.IsLeaderElectionEnabled {
		lbc.addLeaderHandler(createLeaderHandler(lbc))
	}

	lbc.statusUpdater = &statusUpdater{
		client:                 input.KubeClient,
		namespace:              input.ControllerNamespace,
		externalServiceName:    input.ExternalServiceName,
		namespacedInformers:    lbc.namespacedInformers,
		keyFunc:                keyFunc,
		confClient:             input.ConfClient,
		hasCorrectIngressClass: lbc.HasCorrectIngressClass,
		logger:                 lbc.Logger,
	}

	lbc.configuration = NewConfiguration(
		lbc.HasCorrectIngressClass,
		input.IsNginxPlus,
		input.AppProtectEnabled,
		input.AppProtectDosEnabled,
		input.InternalRoutesEnabled,
		input.VirtualServerValidator,
		input.GlobalConfigurationValidator,
		input.TransportServerValidator,
		input.IsTLSPassthroughEnabled,
		input.SnippetsEnabled,
		input.CertManagerEnabled,
		input.IsIPV6Disabled,
	)

	lbc.appProtectConfiguration = appprotect.NewConfiguration(lbc.Logger)
	lbc.dosConfiguration = appprotectdos.NewConfiguration(input.AppProtectDosEnabled)

	lbc.secretStore = secrets.NewLocalSecretStore(lbc.configurator)

	// NIC Telemetry Reporting
	if input.EnableTelemetryReporting {
		// Default endpoint
		exporterCfg := telemetry.ExporterCfg{
			Endpoint: "oss.edge.df.f5.com:443",
		}
		if input.TelemetryReportingEndpoint != "" {
			exporterCfg.Endpoint = input.TelemetryReportingEndpoint
		}

		exporter, err := telemetry.NewExporter(exporterCfg)
		if err != nil {
			nl.Fatalf(lbc.Logger, "failed to initialize telemetry exporter: %v", err)
		}
		collectorConfig := telemetry.CollectorConfig{
			Period:              24 * time.Hour,
			K8sClientReader:     input.KubeClient,
			Version:             input.NICVersion,
			AppProtectVersion:   input.AppProtectVersion,
			BuildOS:             input.BuildOS,
			InstallationFlags:   input.InstallationFlags,
			GlobalConfiguration: lbc.watchGlobalConfiguration,
			Configurator:        lbc.configurator,
			SecretStore:         lbc.secretStore,
			PodNSName: types.NamespacedName{
				Namespace: os.Getenv("POD_NAMESPACE"),
				Name:      os.Getenv("POD_NAME"),
			},
			Policies:               lbc.getAllPolicies,
			IsPlus:                 lbc.isNginxPlus,
			CustomResourcesEnabled: lbc.areCustomResourcesEnabled,
		}
		collector, err := telemetry.NewCollector(
			collectorConfig,
			telemetry.WithExporter(exporter),
		)
		if err != nil {
			nl.Fatalf(lbc.Logger, "failed to initialize telemetry collector: %v", err)
		}
		lbc.telemetryCollector = collector
		lbc.telemetryChan = make(chan struct{})
	}

	return lbc
}

type namespacedInformer struct {
	namespace                    string
	sharedInformerFactory        informers.SharedInformerFactory
	confSharedInformerFactory    k8s_nginx_informers.SharedInformerFactory
	secretInformerFactory        informers.SharedInformerFactory
	dynInformerFactory           dynamicinformer.DynamicSharedInformerFactory
	ingressLister                storeToIngressLister
	svcLister                    cache.Store
	endpointSliceLister          storeToEndpointSliceLister
	podLister                    indexerToPodLister
	secretLister                 cache.Store
	virtualServerLister          cache.Store
	virtualServerRouteLister     cache.Store
	appProtectPolicyLister       cache.Store
	appProtectLogConfLister      cache.Store
	appProtectDosPolicyLister    cache.Store
	appProtectDosLogConfLister   cache.Store
	appProtectDosProtectedLister cache.Store
	appProtectUserSigLister      cache.Store
	transportServerLister        cache.Store
	policyLister                 cache.Store
	isSecretsEnabledNamespace    bool
	areCustomResourcesEnabled    bool
	appProtectEnabled            bool
	appProtectDosEnabled         bool
	stopCh                       chan struct{}
	lock                         sync.RWMutex
	cacheSyncs                   []cache.InformerSynced
}

func (lbc *LoadBalancerController) newNamespacedInformer(ns string) *namespacedInformer {
	nsi := &namespacedInformer{}
	nsi.stopCh = make(chan struct{})
	nsi.namespace = ns
	nsi.sharedInformerFactory = informers.NewSharedInformerFactoryWithOptions(lbc.client, lbc.resync, informers.WithNamespace(ns))

	// create handlers for resources we care about
	nsi.addIngressHandler(createIngressHandlers(lbc))
	nsi.addServiceHandler(createServiceHandlers(lbc))
	nsi.addEndpointSliceHandler(createEndpointSliceHandlers(lbc))
	nsi.addPodHandler()

	secretsTweakListOptionsFunc := func(options *meta_v1.ListOptions) {
		// Filter for helm release secrets.
		helmSecretSelector := fields.OneTermNotEqualSelector(typeKeyword, helmReleaseType)
		baseSelector, err := fields.ParseSelector(options.FieldSelector)

		if err != nil {
			options.FieldSelector = helmSecretSelector.String()
		} else {
			options.FieldSelector = fields.AndSelectors(baseSelector, helmSecretSelector).String()
		}
	}

	// Check if secrets informer should be created for this namespace
	for _, v := range lbc.secretNamespaceList {
		if v == "" || v == ns {
			nsi.isSecretsEnabledNamespace = true
			nsi.secretInformerFactory = informers.NewSharedInformerFactoryWithOptions(lbc.client, lbc.resync, informers.WithNamespace(ns), informers.WithTweakListOptions(secretsTweakListOptionsFunc))
			nsi.addSecretHandler(createSecretHandlers(lbc))
			break
		}
	}

	if lbc.areCustomResourcesEnabled {
		nsi.areCustomResourcesEnabled = true
		nsi.confSharedInformerFactory = k8s_nginx_informers.NewSharedInformerFactoryWithOptions(lbc.confClient, lbc.resync, k8s_nginx_informers.WithNamespace(ns))

		nsi.addVirtualServerHandler(createVirtualServerHandlers(lbc))
		nsi.addVirtualServerRouteHandler(createVirtualServerRouteHandlers(lbc))
		nsi.addTransportServerHandler(createTransportServerHandlers(lbc))
		nsi.addPolicyHandler(createPolicyHandlers(lbc))

	}

	if lbc.appProtectEnabled || lbc.appProtectDosEnabled {
		nsi.dynInformerFactory = dynamicinformer.NewFilteredDynamicSharedInformerFactory(lbc.dynClient, 0, ns, nil)
		if lbc.appProtectEnabled {
			nsi.appProtectEnabled = true
			nsi.addAppProtectPolicyHandler(createAppProtectPolicyHandlers(lbc))
			nsi.addAppProtectLogConfHandler(createAppProtectLogConfHandlers(lbc))
			nsi.addAppProtectUserSigHandler(createAppProtectUserSigHandlers(lbc))
		}

		if lbc.appProtectDosEnabled {
			nsi.appProtectDosEnabled = true
			nsi.addAppProtectDosPolicyHandler(createAppProtectDosPolicyHandlers(lbc))
			nsi.addAppProtectDosLogConfHandler(createAppProtectDosLogConfHandlers(lbc))
			nsi.addAppProtectDosProtectedResourceHandler(createAppProtectDosProtectedResourceHandlers(lbc))
		}
	}

	lbc.namespacedInformers[ns] = nsi
	return nsi
}

// AddSyncQueue enqueues the provided item on the sync queue
func (lbc *LoadBalancerController) AddSyncQueue(item interface{}) {
	lbc.syncQueue.Enqueue(item)
}

// addSecretHandler adds the handler for secrets to the controller
func (nsi *namespacedInformer) addSecretHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.secretInformerFactory.Core().V1().Secrets().Informer()
	informer.AddEventHandler(handlers)
	nsi.secretLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// addIngressHandler adds the handler for ingresses to the controller
func (nsi *namespacedInformer) addIngressHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.sharedInformerFactory.Networking().V1().Ingresses().Informer()
	informer.AddEventHandler(handlers)
	nsi.ingressLister = storeToIngressLister{Store: informer.GetStore()}

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addPodHandler() {
	informer := nsi.sharedInformerFactory.Core().V1().Pods().Informer()
	nsi.podLister = indexerToPodLister{Indexer: informer.GetIndexer()}

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addVirtualServerHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().VirtualServers().Informer()
	informer.AddEventHandler(handlers)
	nsi.virtualServerLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

func (nsi *namespacedInformer) addVirtualServerRouteHandler(handlers cache.ResourceEventHandlerFuncs) {
	informer := nsi.confSharedInformerFactory.K8s().V1().VirtualServerRoutes().Informer()
	informer.AddEventHandler(handlers)
	nsi.virtualServerRouteLister = informer.GetStore()

	nsi.cacheSyncs = append(nsi.cacheSyncs, informer.HasSynced)
}

// Run starts the loadbalancer controller
func (lbc *LoadBalancerController) Run() {
	lbc.ctx, lbc.cancel = context.WithCancel(context.Background())

	if lbc.namespaceWatcherController != nil {
		go lbc.namespaceWatcherController.Run(lbc.ctx.Done())
	}

	if lbc.spiffeCertFetcher != nil {
		_, _, err := lbc.spiffeCertFetcher.Start(lbc.ctx)
		lbc.addInternalRouteServer()
		if err != nil {
			nl.Fatal(lbc.Logger, err)
		}

		// wait for initial bundle
		timeoutch := make(chan bool, 1)
		go func() { time.Sleep(time.Second * 30); timeoutch <- true }()
		select {
		case cert := <-lbc.spiffeCertFetcher.CertCh:
			lbc.syncSVIDRotation(cert)
		case <-timeoutch:
			nl.Fatal(lbc.Logger, "Failed to download initial spiffe trust bundle")
		}

		go func() {
			for {
				select {
				case err := <-lbc.spiffeCertFetcher.WatchErrCh:
					nl.Errorf(lbc.Logger, "error watching for SVID rotations: %v", err)
					return
				case cert := <-lbc.spiffeCertFetcher.CertCh:
					lbc.syncSVIDRotation(cert)
				}
			}
		}()
	}
	if lbc.certManagerController != nil {
		go lbc.certManagerController.Run(lbc.ctx.Done())
	}
	if lbc.externalDNSController != nil {
		go lbc.externalDNSController.Run(lbc.ctx.Done())
	}

	if lbc.leaderElector != nil {
		go lbc.leaderElector.Run(lbc.ctx)
	}

	if lbc.telemetryCollector != nil {
		go func(ctx context.Context) {
			select {
			case <-lbc.telemetryChan:
				lbc.telemetryCollector.Start(lbc.ctx)
			case <-ctx.Done():
				return
			}
		}(lbc.ctx)
	}

	for _, nif := range lbc.namespacedInformers {
		nif.start()
	}

	if lbc.watchNginxConfigMaps {
		go lbc.configMapController.Run(lbc.ctx.Done())
	}

	if lbc.watchMGMTConfigMap {
		go lbc.mgmtConfigMapController.Run(lbc.ctx.Done())
	}

	if lbc.watchGlobalConfiguration {
		go lbc.globalConfigurationController.Run(lbc.ctx.Done())
	}
	if lbc.watchIngressLink {
		go lbc.ingressLinkInformer.Run(lbc.ctx.Done())
	}

	totalCacheSyncs := lbc.cacheSyncs

	for _, nif := range lbc.namespacedInformers {
		totalCacheSyncs = append(totalCacheSyncs, nif.cacheSyncs...)
	}

	nl.Debugf(lbc.Logger, "Waiting for %d caches to sync", len(totalCacheSyncs))

	if !cache.WaitForCacheSync(lbc.ctx.Done(), totalCacheSyncs...) {
		return
	}

	lbc.preSyncSecrets()

	nl.Debugf(lbc.Logger, "Starting the queue with %d initial elements", lbc.syncQueue.Len())

	go lbc.syncQueue.Run(time.Second, lbc.ctx.Done())
	<-lbc.ctx.Done()
}

// Stop shutsdown the load balancer controller
func (lbc *LoadBalancerController) Stop() {
	lbc.cancel()
	for _, nif := range lbc.namespacedInformers {
		nif.stop()
	}
	lbc.syncQueue.Shutdown()
}

func (nsi *namespacedInformer) start() {
	go nsi.sharedInformerFactory.Start(nsi.stopCh)

	if nsi.isSecretsEnabledNamespace {
		go nsi.secretInformerFactory.Start(nsi.stopCh)
	}

	if nsi.areCustomResourcesEnabled {
		go nsi.confSharedInformerFactory.Start(nsi.stopCh)
	}

	if nsi.appProtectEnabled || nsi.appProtectDosEnabled {
		go nsi.dynInformerFactory.Start(nsi.stopCh)
	}
}

func (nsi *namespacedInformer) stop() {
	close(nsi.stopCh)
}

func (lbc *LoadBalancerController) getNamespacedInformer(ns string) *namespacedInformer {
	var nsi *namespacedInformer
	var isGlobalNs bool
	var exists bool

	nsi, isGlobalNs = lbc.namespacedInformers[""]

	if !isGlobalNs {
		// get the correct namespaced informers
		nsi, exists = lbc.namespacedInformers[ns]
		if !exists {
			// we are not watching this namespace
			return nil
		}
	}
	return nsi
}

// finds the number of currently active endpoints for the service pointing at the ingresscontroller and updates all configs that depend on that number
func (lbc *LoadBalancerController) updateNumberOfIngressControllerReplicas(controllerEndpointSlice discovery_v1.EndpointSlice) bool {
	previous := lbc.configurator.GetIngressControllerReplicas()
	current := countReadyEndpoints(controllerEndpointSlice)
	found := false

	if current != previous {
		// number of active endpoints changed. Update configuration of all ingresses that depend on it
		lbc.configurator.SetIngressControllerReplicas(len(controllerEndpointSlice.Endpoints))

		// handle ingresses
		resources := lbc.configuration.FindIngressesWithRatelimitScaling(controllerEndpointSlice.Namespace)
		resourceExes := lbc.createExtendedResources(resources)
		for _, ingress := range resourceExes.IngressExes {
			found = true
			_, err := lbc.configurator.AddOrUpdateIngress(ingress)
			if err != nil {
				nl.Errorf(lbc.Logger, "Error updating ratelimit for Ingress %s/%s: %s", ingress.Ingress.Namespace, ingress.Ingress.Name, err)
			}
		}
		for _, ingress := range resourceExes.MergeableIngresses {
			found = true
			_, err := lbc.configurator.AddOrUpdateMergeableIngress(ingress)
			if err != nil {
				nl.Errorf(lbc.Logger, "Error updating ratelimit for Ingress %s/%s: %s", ingress.Master.Ingress.Namespace, ingress.Master.Ingress.Name, err)
			}
		}

		// handle virtualservers
		if lbc.areCustomResourcesEnabled {
			resources = lbc.findVirtualServersUsingRatelimitScaling()
			resourceExes = lbc.createExtendedResources(resources)
			for _, vserver := range resourceExes.VirtualServerExes {
				found = true
				_, err := lbc.configurator.AddOrUpdateVirtualServer(vserver)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error updating ratelimit for VirtualServer %s/%s: %s", vserver.VirtualServer.Namespace, vserver.VirtualServer.Name, err)
				}
			}
		}

	}
	return found
}

func (lbc *LoadBalancerController) findVirtualServersUsingRatelimitScaling() []Resource {
	policies := lbc.getAllPolicies()
	resources := make([]Resource, 0, len(policies))
	for _, policy := range policies {
		if policy.Spec.RateLimit != nil && policy.Spec.RateLimit.Scale {
			newresources := lbc.configuration.FindResourcesForPolicy(policy.Namespace, policy.Name)
			resources = append(resources, newresources...)
		}
	}
	return resources
}

func (lbc *LoadBalancerController) virtualServerRequiresEndpointsUpdate(vsEx *configs.VirtualServerEx, serviceName string) bool {
	for _, upstream := range vsEx.VirtualServer.Spec.Upstreams {
		if upstream.Service == serviceName && !upstream.UseClusterIP {
			return true
		}
	}

	for _, vsr := range vsEx.VirtualServerRoutes {
		for _, upstream := range vsr.Spec.Upstreams {
			if upstream.Service == serviceName && !upstream.UseClusterIP {
				return true
			}
		}
	}

	return false
}

func (lbc *LoadBalancerController) ingressRequiresEndpointsUpdate(ingressEx *configs.IngressEx, serviceName string) bool {
	hasUseClusterIPAnnotation := ingressEx.Ingress.Annotations[useClusterIPAnnotation] == "true"

	for _, rule := range ingressEx.Ingress.Spec.Rules {
		if http := rule.HTTP; http != nil {
			for _, path := range http.Paths {
				if path.Backend.Service != nil && path.Backend.Service.Name == serviceName {
					if !hasUseClusterIPAnnotation {
						return true
					}
				}
			}
		}
	}

	if http := ingressEx.Ingress.Spec.DefaultBackend; http != nil {
		if http.Service != nil && http.Service.Name == serviceName {
			if !hasUseClusterIPAnnotation {
				return true
			}
		}
	}

	return false
}

func (lbc *LoadBalancerController) mergeableIngressRequiresEndpointsUpdate(mergeableIngresses *configs.MergeableIngresses, serviceName string) bool {
	masterIngress := mergeableIngresses.Master
	minions := mergeableIngresses.Minions

	for _, minion := range minions {
		if lbc.ingressRequiresEndpointsUpdate(minion, serviceName) {
			return true
		}
	}

	return lbc.ingressRequiresEndpointsUpdate(masterIngress, serviceName)
}

// countReadyEndpoints returns the number of ready endpoints in this endpointslice
func countReadyEndpoints(slice discovery_v1.EndpointSlice) int {
	count := 0
	for _, endpoint := range slice.Endpoints {
		if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
			count = count + 1
		}
	}
	return count
}

func (lbc *LoadBalancerController) createExtendedResources(resources []Resource) configs.ExtendedResources {
	var result configs.ExtendedResources

	for _, r := range resources {
		switch impl := r.(type) {
		case *VirtualServerConfiguration:
			vs := impl.VirtualServer
			vsEx := lbc.createVirtualServerEx(vs, impl.VirtualServerRoutes)
			result.VirtualServerExes = append(result.VirtualServerExes, vsEx)
		case *IngressConfiguration:

			if impl.IsMaster {
				mergeableIng := lbc.createMergeableIngresses(impl)
				result.MergeableIngresses = append(result.MergeableIngresses, mergeableIng)
			} else {
				ingEx := lbc.createIngressEx(impl.Ingress, impl.ValidHosts, nil)
				result.IngressExes = append(result.IngressExes, ingEx)
			}
		case *TransportServerConfiguration:
			tsEx := lbc.createTransportServerEx(impl.TransportServer, impl.ListenerPort, impl.IPv4, impl.IPv6)
			result.TransportServerExes = append(result.TransportServerExes, tsEx)
		}
	}

	return result
}

func (lbc *LoadBalancerController) updateAllConfigs() {
	ctx := nl.ContextWithLogger(context.Background(), lbc.Logger)
	cfgParams := configs.NewDefaultConfigParams(ctx, lbc.isNginxPlus)
	mgmtCfgParams := configs.NewDefaultMGMTConfigParams(ctx)
	var isNGINXConfigValid bool
	var mgmtConfigHasWarnings bool
	var mgmtErr error
	var reloadNginx bool

	if lbc.configMap != nil {
		cfgParams, isNGINXConfigValid = configs.ParseConfigMap(ctx, lbc.configMap, lbc.isNginxPlus, lbc.appProtectEnabled, lbc.appProtectDosEnabled, lbc.configuration.isTLSPassthroughEnabled, lbc.recorder)
	}
	if lbc.mgmtConfigMap != nil && lbc.isNginxPlus {
		mgmtCfgParams, mgmtConfigHasWarnings, mgmtErr = configs.ParseMGMTConfigMap(ctx, lbc.mgmtConfigMap, lbc.recorder)
		if mgmtErr != nil {
			nl.Errorf(lbc.Logger, "configmap %s/%s: %v", lbc.mgmtConfigMap.GetNamespace(), lbc.mgmtConfigMap.GetName(), mgmtErr)
		}
	}

	lbc.configurator.CfgParams = cfgParams
	lbc.configurator.MgmtCfgParams = mgmtCfgParams
	cfgParams.ZoneSync.Domain = lbc.ingressClass

	// update special license secret in mgmtConfigParams
	if lbc.mgmtConfigMap != nil && lbc.isNginxPlus {
		if mgmtCfgParams.Secrets.License != "" {
			secret, err := lbc.client.CoreV1().Secrets(lbc.mgmtConfigMap.GetNamespace()).Get(context.TODO(), mgmtCfgParams.Secrets.License, meta_v1.GetOptions{})
			if err != nil {
				nl.Errorf(lbc.Logger, "secret %s/%s: %v", lbc.mgmtConfigMap.GetNamespace(), mgmtCfgParams.Secrets.License, err)
			}
			lbc.specialSecrets.licenseSecret = fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
			lbc.handleSpecialSecretUpdate(secret, reloadNginx)
		}
		// update special CA secret in mgmtConfigParams
		if mgmtCfgParams.Secrets.TrustedCert != "" {
			secret, err := lbc.client.CoreV1().Secrets(lbc.mgmtConfigMap.GetNamespace()).Get(context.TODO(), mgmtCfgParams.Secrets.TrustedCert, meta_v1.GetOptions{})
			if err != nil {
				nl.Errorf(lbc.Logger, "secret %s/%s: %v", lbc.mgmtConfigMap.GetNamespace(), mgmtCfgParams.Secrets.TrustedCert, err)
			}
			if _, hasCRL := secret.Data[configs.CACrlKey]; hasCRL {
				lbc.configurator.MgmtCfgParams.Secrets.TrustedCRL = secret.Name
			}
			lbc.specialSecrets.trustedCertSecret = fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
			lbc.handleSpecialSecretUpdate(secret, reloadNginx)
		}
		// update special ClientAuth secret in mgmtConfigParams
		if mgmtCfgParams.Secrets.ClientAuth != "" {
			secret, err := lbc.client.CoreV1().Secrets(lbc.mgmtConfigMap.GetNamespace()).Get(context.TODO(), mgmtCfgParams.Secrets.ClientAuth, meta_v1.GetOptions{})
			if err != nil {
				nl.Errorf(lbc.Logger, "secret %s/%s: %v", lbc.mgmtConfigMap.GetNamespace(), mgmtCfgParams.Secrets.ClientAuth, err)
			}
			lbc.specialSecrets.clientAuthSecret = fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
			lbc.handleSpecialSecretUpdate(secret, reloadNginx)
		}
	}
	resources := lbc.configuration.GetResources()
	nl.Debugf(lbc.Logger, "Updating %v resources", len(resources))
	resourceExes := lbc.createExtendedResources(resources)
	warnings, updateErr := lbc.configurator.UpdateConfig(resourceExes)

	eventTitle := nl.EventReasonUpdated
	eventType := api_v1.EventTypeNormal
	eventWarningMessage := ""

	if updateErr != nil {
		eventTitle = nl.EventReasonUpdatedWithError
		eventType = api_v1.EventTypeWarning
		eventWarningMessage = fmt.Sprintf("but was not applied: %v", updateErr)
	}

	if len(warnings) > 0 && updateErr == nil {
		eventWarningMessage = "with warnings. Please check the logs"
	}

	if lbc.configMap != nil {
		if isNGINXConfigValid {
			lbc.recorder.Event(lbc.configMap, api_v1.EventTypeNormal, nl.EventReasonUpdated, fmt.Sprintf("ConfigMap %s/%s updated without error", lbc.configMap.GetNamespace(), lbc.configMap.GetName()))
		} else {
			lbc.recorder.Event(lbc.configMap, api_v1.EventTypeWarning, nl.EventReasonUpdatedWithError, fmt.Sprintf("ConfigMap %s/%s updated with errors. Ignoring invalid values", lbc.configMap.GetNamespace(), lbc.configMap.GetName()))
		}
	}

	if lbc.mgmtConfigMap != nil {
		if !mgmtConfigHasWarnings {
			lbc.recorder.Event(lbc.mgmtConfigMap, api_v1.EventTypeNormal, nl.EventReasonUpdated, fmt.Sprintf("MGMT ConfigMap %s/%s updated without error", lbc.mgmtConfigMap.GetNamespace(), lbc.mgmtConfigMap.GetName()))
		} else {
			lbc.recorder.Event(lbc.mgmtConfigMap, api_v1.EventTypeWarning, nl.EventReasonUpdatedWithError, fmt.Sprintf("MGMT ConfigMap %s/%s updated with errors. Ignoring invalid values", lbc.mgmtConfigMap.GetNamespace(), lbc.mgmtConfigMap.GetName()))
		}
	}

	gc := lbc.configuration.GetGlobalConfiguration()
	if gc != nil && lbc.configMap != nil {
		key := getResourceKey(&lbc.configMap.ObjectMeta)
		lbc.recorder.Eventf(gc, eventType, eventTitle, fmt.Sprintf("GlobalConfiguration %s was updated %s", key, eventWarningMessage))
	}

	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
}

// preSyncSecrets adds Secret resources to the SecretStore.
// It must be called after the caches are synced but before the queue starts processing elements.
// If we don't add Secrets, there is a chance that during the IC start
// syncing an Ingress or other resource that references a Secret will happen before that Secret was synced.
// As a result, the IC will generate configuration for that resource assuming that the Secret is missing and
// it will report warnings. (See https://github.com/nginx/kubernetes-ingress/issues/1448 )
func (lbc *LoadBalancerController) preSyncSecrets() {
	for _, ni := range lbc.namespacedInformers {
		if !ni.isSecretsEnabledNamespace {
			break
		}
		objects := ni.secretLister.List()
		nl.Debugf(lbc.Logger, "PreSync %d Secrets", len(objects))

		for _, obj := range objects {
			secret := obj.(*api_v1.Secret)

			if !secrets.IsSupportedSecretType(secret.Type) {
				nl.Debugf(lbc.Logger, "Ignoring Secret %s/%s of unsupported type %s", secret.Namespace, secret.Name, secret.Type)
				continue
			}

			nl.Debugf(lbc.Logger, "Adding Secret: %s/%s", secret.Namespace, secret.Name)
			lbc.secretStore.AddOrUpdateSecret(secret)
		}
	}
}

func (lbc *LoadBalancerController) sync(task task) {
	if lbc.isNginxReady && lbc.syncQueue.Len() > 1 && !lbc.batchSyncEnabled {
		lbc.configurator.DisableReloads()
		lbc.batchSyncEnabled = true

		nl.Debugf(lbc.Logger, "Batch processing %v items", lbc.syncQueue.Len())
	}
	nl.Debugf(lbc.Logger, "Syncing %v", task.Key)
	if lbc.spiffeCertFetcher != nil {
		lbc.syncLock.Lock()
		defer lbc.syncLock.Unlock()
	}
	if lbc.batchSyncEnabled && task.Kind != endpointslice {
		nl.Debug(lbc.Logger, "Task is not endpointslice - enabling batch reload")
		lbc.enableBatchReload = true
	}
	switch task.Kind {
	case ingress:
		lbc.syncIngress(task)
		lbc.updateIngressMetrics()
		lbc.updateTransportServerMetrics()
	case configMap:
		if lbc.batchSyncEnabled {
			lbc.updateAllConfigsOnBatch = true
		}
		lbc.syncConfigMap(task)
	case endpointslice:
		resourcesFound := lbc.syncEndpointSlices(task)
		if lbc.batchSyncEnabled && resourcesFound {
			nl.Debugf(lbc.Logger, "Endpointslice %v is referenced - enabling batch reload", task.Key)
			lbc.enableBatchReload = true
		}
	case secret:
		lbc.syncSecret(task)
	case service:
		lbc.syncService(task)
	case namespace:
		lbc.syncNamespace(task)
	case virtualserver:
		lbc.syncVirtualServer(task)
		lbc.updateVirtualServerMetrics()
		lbc.updateTransportServerMetrics()
	case virtualServerRoute:
		lbc.syncVirtualServerRoute(task)
		lbc.updateVirtualServerMetrics()
	case globalConfiguration:
		lbc.syncGlobalConfiguration(task)
		lbc.updateTransportServerMetrics()
		lbc.updateVirtualServerMetrics()
	case transportserver:
		lbc.syncTransportServer(task)
		lbc.updateTransportServerMetrics()
	case policy:
		lbc.syncPolicy(task)
	case appProtectPolicy:
		lbc.syncAppProtectPolicy(task)
	case appProtectLogConf:
		lbc.syncAppProtectLogConf(task)
	case appProtectUserSig:
		lbc.syncAppProtectUserSig(task)
	case appProtectDosPolicy:
		lbc.syncAppProtectDosPolicy(task)
	case appProtectDosLogConf:
		lbc.syncAppProtectDosLogConf(task)
	case appProtectDosProtectedResource:
		lbc.syncDosProtectedResource(task)
	case ingressLink:
		lbc.syncIngressLink(task)
	}

	err := lbc.syncZoneSyncHeadlessService(fmt.Sprintf("%s-headless", lbc.ingressClass))
	if err != nil {
		nl.Errorf(lbc.Logger, "error syncing zone sync headless service: %v", err)
	}

	if !lbc.isNginxReady && lbc.syncQueue.Len() == 0 {
		lbc.configurator.EnableReloads()
		lbc.updateAllConfigs()

		lbc.isNginxReady = true
		nl.Debug(lbc.Logger, "NGINX is ready")
	}

	if lbc.batchSyncEnabled && lbc.syncQueue.Len() == 0 {
		lbc.batchSyncEnabled = false
		lbc.configurator.EnableReloads()
		if lbc.updateAllConfigsOnBatch {
			lbc.updateAllConfigs()
		} else {
			if err := lbc.configurator.ReloadForBatchUpdates(lbc.enableBatchReload); err != nil {
				nl.Errorf(lbc.Logger, "error reloading for batch updates: %v", err)
			}
		}

		lbc.enableBatchReload = false
		nl.Debug(lbc.Logger, "Batch sync completed - disabling batch reload")
	}
}

func (lbc *LoadBalancerController) removeNamespacedInformer(nsi *namespacedInformer, key string) {
	nsi.lock.Lock()
	defer nsi.lock.Unlock()
	nsi.stop()
	delete(lbc.namespacedInformers, key)
	nsi = nil
}

func (lbc *LoadBalancerController) cleanupUnwatchedNamespacedResources(nsi *namespacedInformer) {
	// if a namespace is not deleted but the label is removed: we see an update event, so we will stop watching that namespace,
	// BUT we need to remove any configuration for resources deployed in that namespace and still maintained by us
	nsi.lock.Lock()
	defer nsi.lock.Unlock()

	var delIngressList []string

	il, err := nsi.ingressLister.List()
	if err != nil {
		nl.Warnf(lbc.Logger, "unable to list Ingress resources for recently unwatched namespace %s", nsi.namespace)
	} else {
		for _, ing := range il.Items {
			ing := ing // address gosec G601
			key := getResourceKey(&ing.ObjectMeta)
			delIngressList = append(delIngressList, key)
			lbc.configuration.DeleteIngress(key)
		}
		delIngErrs := lbc.configurator.BatchDeleteIngresses(delIngressList)
		if len(delIngErrs) > 0 {
			nl.Warnf(lbc.Logger, "Received error(s) deleting Ingress configurations from unwatched namespace: %v", delIngErrs)
		}
	}

	if nsi.areCustomResourcesEnabled {
		var delVsList []string
		for _, obj := range nsi.virtualServerLister.List() {
			vs := obj.(*conf_v1.VirtualServer)
			key := getResourceKey(&vs.ObjectMeta)
			delVsList = append(delVsList, key)
			lbc.configuration.DeleteVirtualServer(key)
		}
		delVsErrs := lbc.configurator.BatchDeleteVirtualServers(delVsList)
		if len(delVsErrs) > 0 {
			nl.Warnf(lbc.Logger, "Received error(s) deleting VirtualServer configurations from unwatched namespace: %v", delVsErrs)
		}

		var delTsList []string
		for _, obj := range nsi.transportServerLister.List() {
			ts := obj.(*conf_v1.TransportServer)
			key := getResourceKey(&ts.ObjectMeta)
			delTsList = append(delTsList, key)
			lbc.configuration.DeleteTransportServer(key)
		}
		var updatedTSExes []*configs.TransportServerEx
		delTsErrs := lbc.configurator.UpdateTransportServers(updatedTSExes, delTsList)
		if len(delTsErrs) > 0 {
			nl.Warnf(lbc.Logger, "Received error(s) deleting TransportServer configurations from unwatched namespace: %v", delVsErrs)
		}

		for _, obj := range nsi.virtualServerRouteLister.List() {
			vsr := obj.(*conf_v1.VirtualServerRoute)
			key := getResourceKey(&vsr.ObjectMeta)
			lbc.configuration.DeleteVirtualServerRoute(key)
		}
	}
	if nsi.appProtectEnabled {
		lbc.cleanupUnwatchedAppWafResources(nsi)
	}
	if nsi.appProtectDosEnabled {
		lbc.cleanupUnwatchedAppDosResources(nsi)
	}
	for _, obj := range nsi.secretLister.List() {
		sec := obj.(*api_v1.Secret)
		key := getResourceKey(&sec.ObjectMeta)
		resources := lbc.configuration.FindResourcesForSecret(sec.Namespace, sec.Name)
		lbc.secretStore.DeleteSecret(key)

		nl.Debugf(lbc.Logger, "Deleting Secret: %v\n", key)

		if len(resources) > 0 {
			lbc.handleRegularSecretDeletion(resources)
		}
		if lbc.isSpecialSecret(key) {
			nl.Warnf(lbc.Logger, "A special TLS Secret %v was removed. Retaining the Secret.", key)
		}
	}
	nl.Debugf(lbc.Logger, "Finished cleaning up configuration for unwatched resources in namespace: %v", nsi.namespace)
	nsi.stop()
}

func (lbc *LoadBalancerController) syncVirtualServer(task task) {
	key := task.Key
	var obj interface{}
	var vsExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, vsExists, err = lbc.getNamespacedInformer(ns).virtualServerLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !vsExists {
		nl.Debugf(lbc.Logger, "Deleting VirtualServer: %v\n", key)

		changes, problems = lbc.configuration.DeleteVirtualServer(key)
	} else {
		nl.Debugf(lbc.Logger, "Adding or Updating VirtualServer: %v\n", key)

		vs := obj.(*conf_v1.VirtualServer)
		changes, problems = lbc.configuration.AddOrUpdateVirtualServer(vs)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) processProblems(problems []ConfigurationProblem) {
	nl.Debugf(lbc.Logger, "Processing %v problems", len(problems))

	for _, p := range problems {
		eventType := api_v1.EventTypeWarning
		lbc.recorder.Event(p.Object, eventType, p.Reason, p.Message)

		if lbc.reportCustomResourceStatusEnabled() {
			state := conf_v1.StateWarning
			if p.IsError {
				state = conf_v1.StateInvalid
			}

			switch obj := p.Object.(type) {
			case *networking.Ingress:
				err := lbc.statusUpdater.ClearIngressStatus(*obj)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when updating the status for Ingress %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			case *conf_v1.VirtualServer:
				err := lbc.statusUpdater.UpdateVirtualServerStatus(obj, state, p.Reason, p.Message)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when updating the status for VirtualServer %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			case *conf_v1.TransportServer:
				err := lbc.statusUpdater.UpdateTransportServerStatus(obj, state, p.Reason, p.Message)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when updating the status for TransportServer %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			case *conf_v1.VirtualServerRoute:
				var emptyVSes []*conf_v1.VirtualServer
				err := lbc.statusUpdater.UpdateVirtualServerRouteStatusWithReferencedBy(obj, state, p.Reason, p.Message, emptyVSes)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when updating the status for VirtualServerRoute %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			}
		}
	}
}

func (lbc *LoadBalancerController) processChanges(changes []ResourceChange) {
	nl.Debugf(lbc.Logger, "Processing %v changes", len(changes))

	for _, c := range changes {
		if c.Op == AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				vsEx := lbc.createVirtualServerEx(impl.VirtualServer, impl.VirtualServerRoutes)

				warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateVirtualServer(vsEx)
				lbc.updateVirtualServerStatusAndEvents(impl, warnings, addOrUpdateErr)
			case *IngressConfiguration:
				if impl.IsMaster {
					mergeableIng := lbc.createMergeableIngresses(impl)

					warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateMergeableIngress(mergeableIng)
					lbc.updateMergeableIngressStatusAndEvents(impl, warnings, addOrUpdateErr)
				} else {
					// for regular Ingress, validMinionPaths is nil
					ingEx := lbc.createIngressEx(impl.Ingress, impl.ValidHosts, nil)

					warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateIngress(ingEx)
					lbc.updateRegularIngressStatusAndEvents(impl, warnings, addOrUpdateErr)
				}
			case *TransportServerConfiguration:
				tsEx := lbc.createTransportServerEx(impl.TransportServer, impl.ListenerPort, impl.IPv4, impl.IPv6)
				warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateTransportServer(tsEx)
				lbc.updateTransportServerStatusAndEvents(impl, warnings, addOrUpdateErr)
			}
		} else if c.Op == Delete {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				key := getResourceKey(&impl.VirtualServer.ObjectMeta)

				deleteErr := lbc.configurator.DeleteVirtualServer(key, false)
				if deleteErr != nil {
					nl.Errorf(lbc.Logger, "Error when deleting configuration for VirtualServer %v: %v", key, deleteErr)
				}

				var vsExists bool
				var err error

				ns, _, _ := cache.SplitMetaNamespaceKey(key)
				_, vsExists, err = lbc.getNamespacedInformer(ns).virtualServerLister.GetByKey(key)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when getting VirtualServer for %v: %v", key, err)
				}

				if vsExists {
					lbc.UpdateVirtualServerStatusAndEventsOnDelete(impl, c.Error, deleteErr)
				}
			case *IngressConfiguration:
				key := getResourceKey(&impl.Ingress.ObjectMeta)

				nl.Debugf(lbc.Logger, "Deleting Ingress: %v\n", key)

				deleteErr := lbc.configurator.DeleteIngress(key, false)
				if deleteErr != nil {
					nl.Errorf(lbc.Logger, "Error when deleting configuration for Ingress %v: %v", key, deleteErr)
				}

				var ingExists bool
				var err error

				ns, _, _ := cache.SplitMetaNamespaceKey(key)
				_, ingExists, err = lbc.getNamespacedInformer(ns).ingressLister.GetByKeySafe(key)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when getting Ingress for %v: %v", key, err)
				}

				if ingExists {
					lbc.UpdateIngressStatusAndEventsOnDelete(impl, c.Error, deleteErr)
				}
			case *TransportServerConfiguration:
				key := getResourceKey(&impl.TransportServer.ObjectMeta)

				deleteErr := lbc.configurator.DeleteTransportServer(key)

				if deleteErr != nil {
					nl.Errorf(lbc.Logger, "Error when deleting configuration for TransportServer %v: %v", key, deleteErr)
				}

				var tsExists bool
				var err error

				ns, _, _ := cache.SplitMetaNamespaceKey(key)
				_, tsExists, err = lbc.getNamespacedInformer(ns).transportServerLister.GetByKey(key)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when getting TransportServer for %v: %v", key, err)
				}
				if tsExists {
					lbc.updateTransportServerStatusAndEventsOnDelete(impl, c.Error, deleteErr)
				}
			}
		}
	}
}

// UpdateVirtualServerStatusAndEventsOnDelete updates the virtual server status and events
func (lbc *LoadBalancerController) UpdateVirtualServerStatusAndEventsOnDelete(vsConfig *VirtualServerConfiguration, changeError string, deleteErr error) {
	eventType := api_v1.EventTypeWarning
	eventTitle := nl.EventReasonRejected
	eventWarningMessage := ""
	state := ""

	// VirtualServer either became invalid or lost its host
	if changeError != "" {
		eventWarningMessage = fmt.Sprintf("with error: %s", changeError)
		state = conf_v1.StateInvalid
	} else if len(vsConfig.Warnings) > 0 {
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(vsConfig.Warnings))
		state = conf_v1.StateWarning
	}

	// we don't need to report anything if eventWarningMessage is empty
	// in that case, the resource was deleted because its class became incorrect
	// (some other Ingress Controller will handle it)
	if eventWarningMessage != "" {
		if deleteErr != nil {
			eventType = api_v1.EventTypeWarning
			eventTitle = nl.EventReasonRejectedWithError
			eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, deleteErr)
			state = conf_v1.StateInvalid
		}

		msg := fmt.Sprintf("VirtualServer %s was rejected %s", getResourceKey(&vsConfig.VirtualServer.ObjectMeta), eventWarningMessage)
		lbc.recorder.Eventf(vsConfig.VirtualServer, eventType, eventTitle, msg)

		if lbc.reportCustomResourceStatusEnabled() {
			err := lbc.statusUpdater.UpdateVirtualServerStatus(vsConfig.VirtualServer, state, eventTitle, msg)
			if err != nil {
				nl.Errorf(lbc.Logger, "Error when updating the status for VirtualServer %v/%v: %v", vsConfig.VirtualServer.Namespace, vsConfig.VirtualServer.Name, err)
			}
		}
	}

	// for delete, no need to report VirtualServerRoutes
	// for each VSR, a dedicated problem exists
}

// UpdateIngressStatusAndEventsOnDelete updates the ingress status and events.
func (lbc *LoadBalancerController) UpdateIngressStatusAndEventsOnDelete(ingConfig *IngressConfiguration, changeError string, deleteErr error) {
	eventTitle := nl.EventReasonRejected
	eventWarningMessage := ""

	// Ingress either became invalid or lost all its hosts
	if changeError != "" {
		eventWarningMessage = fmt.Sprintf("with error: %s", changeError)
	} else if len(ingConfig.Warnings) > 0 {
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(ingConfig.Warnings))
	}

	// we don't need to report anything if eventWarningMessage is empty
	// in that case, the resource was deleted because its class became incorrect
	// (some other Ingress Controller will handle it)
	if eventWarningMessage != "" {
		if deleteErr != nil {
			eventTitle = nl.EventReasonRejectedWithError
			eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, deleteErr)
		}

		lbc.recorder.Eventf(ingConfig.Ingress, api_v1.EventTypeWarning, eventTitle, "%v was rejected: %v", getResourceKey(&ingConfig.Ingress.ObjectMeta), eventWarningMessage)
		if lbc.reportStatusEnabled() {
			err := lbc.statusUpdater.ClearIngressStatus(*ingConfig.Ingress)
			if err != nil {
				nl.Debugf(lbc.Logger, "Error clearing Ingress status: %v", err)
			}
		}
	}

	// for delete, no need to report minions
	// for each minion, a dedicated problem exists
}

func (lbc *LoadBalancerController) updateResourcesStatusAndEvents(resources []Resource, warnings configs.Warnings, operationErr error) {
	for _, r := range resources {
		switch impl := r.(type) {
		case *VirtualServerConfiguration:
			lbc.updateVirtualServerStatusAndEvents(impl, warnings, operationErr)
		case *IngressConfiguration:
			if impl.IsMaster {
				lbc.updateMergeableIngressStatusAndEvents(impl, warnings, operationErr)
			} else {
				lbc.updateRegularIngressStatusAndEvents(impl, warnings, operationErr)
			}
		case *TransportServerConfiguration:
			lbc.updateTransportServerStatusAndEvents(impl, warnings, operationErr)
		}
	}
}

func (lbc *LoadBalancerController) updateMergeableIngressStatusAndEvents(ingConfig *IngressConfiguration, warnings configs.Warnings, operationErr error) {
	eventType := api_v1.EventTypeNormal
	eventTitle := nl.EventReasonAddedOrUpdated
	eventWarningMessage := ""
	eventWarningSuffix := ""

	if len(ingConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(ingConfig.Warnings))
		eventWarningSuffix = "; "
	}

	if messages, ok := warnings[ingConfig.Ingress]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("%s%swith warning(s): %v", eventWarningMessage, eventWarningSuffix, formatWarningMessages(messages))
		eventWarningSuffix = "; "
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithError
		eventWarningMessage = fmt.Sprintf("%s%sbut was not applied: %v", eventWarningMessage, eventWarningSuffix, operationErr)
	}

	eventWarningPrefixed := ""
	if eventWarningMessage != "" {
		eventWarningPrefixed = fmt.Sprintf(" %s", eventWarningMessage)
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated%s", getResourceKey(&ingConfig.Ingress.ObjectMeta), eventWarningPrefixed)
	lbc.recorder.Eventf(ingConfig.Ingress, eventType, eventTitle, msg)

	for _, fm := range ingConfig.Minions {
		minionEventType := api_v1.EventTypeNormal
		minionEventTitle := nl.EventReasonAddedOrUpdated
		minionEventWarningMessage := ""
		minionEventWarningSuffix := ""

		minionChangeWarnings := ingConfig.ChildWarnings[getResourceKey(&fm.Ingress.ObjectMeta)]

		if len(minionChangeWarnings) > 0 {
			minionEventType = api_v1.EventTypeWarning
			minionEventTitle = nl.EventReasonAddedOrUpdatedWithWarning
			minionEventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(minionChangeWarnings))
			minionEventWarningSuffix = "; "
		}

		if messages, ok := warnings[fm.Ingress]; ok {
			minionEventType = api_v1.EventTypeWarning
			minionEventTitle = nl.EventReasonAddedOrUpdatedWithWarning
			minionEventWarningMessage = fmt.Sprintf("%s%swith warning(s): %v", minionEventWarningMessage, minionEventWarningSuffix, formatWarningMessages(messages))
			minionEventWarningSuffix = "; "
		}

		if operationErr != nil {
			minionEventType = api_v1.EventTypeWarning
			minionEventTitle = nl.EventReasonAddedOrUpdatedWithError
			minionEventWarningMessage = fmt.Sprintf("%s%s; but was not applied: %v", minionEventWarningMessage, minionEventWarningSuffix, operationErr)
			minionEventWarningSuffix = "; "
		}

		minionEventWarningPrefixed := ""
		if minionEventWarningMessage != "" {
			minionEventWarningPrefixed = fmt.Sprintf(" %s", minionEventWarningMessage)
		}
		minionMsg := fmt.Sprintf("Configuration for %v/%v was added or updated%s", fm.Ingress.Namespace, fm.Ingress.Name, minionEventWarningPrefixed)
		lbc.recorder.Eventf(fm.Ingress, minionEventType, minionEventTitle, minionMsg)
	}

	if lbc.reportStatusEnabled() {
		ings := []networking.Ingress{*ingConfig.Ingress}

		for _, fm := range ingConfig.Minions {
			ings = append(ings, *fm.Ingress)
		}

		err := lbc.statusUpdater.BulkUpdateIngressStatus(ings)
		if err != nil {
			nl.Errorf(lbc.Logger, "error updating ing status: %v", err)
		}
	}
}

func (lbc *LoadBalancerController) updateRegularIngressStatusAndEvents(ingConfig *IngressConfiguration, warnings configs.Warnings, operationErr error) {
	eventType := api_v1.EventTypeNormal
	eventTitle := nl.EventReasonAddedOrUpdated
	eventWarningMessage := ""

	if len(ingConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(ingConfig.Warnings))
	}

	if messages, ok := warnings[ingConfig.Ingress]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("%s; with warning(s): %v", eventWarningMessage, formatWarningMessages(messages))
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithError
		eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, operationErr)
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated %s", getResourceKey(&ingConfig.Ingress.ObjectMeta), eventWarningMessage)
	lbc.recorder.Eventf(ingConfig.Ingress, eventType, eventTitle, msg)

	if lbc.reportStatusEnabled() {
		err := lbc.statusUpdater.UpdateIngressStatus(*ingConfig.Ingress)
		if err != nil {
			nl.Errorf(lbc.Logger, "error updating ingress status: %v", err)
		}
	}
}

func (lbc *LoadBalancerController) updateVirtualServerStatusAndEvents(vsConfig *VirtualServerConfiguration, warnings configs.Warnings, operationErr error) {
	eventType := api_v1.EventTypeNormal
	eventTitle := nl.EventReasonAddedOrUpdated
	eventWarningMessage := ""
	state := conf_v1.StateValid

	if len(vsConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(vsConfig.Warnings))
		state = conf_v1.StateWarning
	}

	if messages, ok := warnings[vsConfig.VirtualServer]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
		eventWarningMessage = fmt.Sprintf("%s; with warning(s): %v", eventWarningMessage, formatWarningMessages(messages))
		state = conf_v1.StateWarning
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = nl.EventReasonAddedOrUpdatedWithError
		eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, operationErr)
		state = conf_v1.StateInvalid
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated %s", getResourceKey(&vsConfig.VirtualServer.ObjectMeta), eventWarningMessage)
	lbc.recorder.Eventf(vsConfig.VirtualServer, eventType, eventTitle, msg)

	if lbc.reportCustomResourceStatusEnabled() {
		err := lbc.statusUpdater.UpdateVirtualServerStatus(vsConfig.VirtualServer, state, eventTitle, msg)
		if err != nil {
			nl.Errorf(lbc.Logger, "Error when updating the status for VirtualServer %v/%v: %v", vsConfig.VirtualServer.Namespace, vsConfig.VirtualServer.Name, err)
		}
	}

	for _, vsr := range vsConfig.VirtualServerRoutes {
		vsrEventType := api_v1.EventTypeNormal
		vsrEventTitle := nl.EventReasonAddedOrUpdated
		vsrEventWarningMessage := ""
		vsrState := conf_v1.StateValid

		if messages, ok := warnings[vsr]; ok {
			vsrEventType = api_v1.EventTypeWarning
			vsrEventTitle = nl.EventReasonAddedOrUpdatedWithWarning
			vsrEventWarningMessage = fmt.Sprintf(" with warning(s): %v", formatWarningMessages(messages))
			vsrState = conf_v1.StateWarning
		}

		if operationErr != nil {
			vsrEventType = api_v1.EventTypeWarning
			vsrEventTitle = nl.EventReasonAddedOrUpdatedWithError
			vsrEventWarningMessage = fmt.Sprintf(" %s; but was not applied:%v", vsrEventWarningMessage, operationErr)
			vsrState = conf_v1.StateInvalid
		}

		msg := fmt.Sprintf("Configuration for %v/%v was added or updated%s", vsr.Namespace, vsr.Name, vsrEventWarningMessage)
		lbc.recorder.Eventf(vsr, vsrEventType, vsrEventTitle, msg)

		if lbc.reportCustomResourceStatusEnabled() {
			vss := []*conf_v1.VirtualServer{vsConfig.VirtualServer}
			err := lbc.statusUpdater.UpdateVirtualServerRouteStatusWithReferencedBy(vsr, vsrState, vsrEventTitle, msg, vss)
			if err != nil {
				nl.Errorf(lbc.Logger, "Error when updating the status for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}
		}
	}
}

func (lbc *LoadBalancerController) syncVirtualServerRoute(task task) {
	key := task.Key
	var obj interface{}
	var exists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	obj, exists, err = lbc.getNamespacedInformer(ns).virtualServerRouteLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !exists {
		nl.Debugf(lbc.Logger, "Deleting VirtualServerRoute: %v", key)

		changes, problems = lbc.configuration.DeleteVirtualServerRoute(key)
	} else {
		nl.Debugf(lbc.Logger, "Adding or Updating VirtualServerRoute: %v", key)

		vsr := obj.(*conf_v1.VirtualServerRoute)
		changes, problems = lbc.configuration.AddOrUpdateVirtualServerRoute(vsr)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) syncIngress(task task) {
	key := task.Key
	var ing *networking.Ingress
	var ingExists bool
	var err error

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	ing, ingExists, err = lbc.getNamespacedInformer(ns).ingressLister.GetByKeySafe(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !ingExists {
		nl.Debugf(lbc.Logger, "Deleting Ingress: %v", key)

		changes, problems = lbc.configuration.DeleteIngress(key)
	} else {
		nl.Debugf(lbc.Logger, "Adding or Updating Ingress: %v", key)

		changes, problems = lbc.configuration.AddOrUpdateIngress(ing)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) updateIngressMetrics() {
	counters := lbc.configurator.GetIngressCounts()
	for nType, count := range counters {
		lbc.metricsCollector.SetIngresses(nType, count)
	}
}

func (lbc *LoadBalancerController) updateVirtualServerMetrics() {
	vsCount, vsrCount := lbc.configurator.GetVirtualServerCounts()
	lbc.metricsCollector.SetVirtualServers(vsCount)
	lbc.metricsCollector.SetVirtualServerRoutes(vsrCount)
}

// IsExternalServiceForStatus matches the service specified by the external-service cli arg
func (lbc *LoadBalancerController) IsExternalServiceForStatus(svc *api_v1.Service) bool {
	return lbc.statusUpdater.namespace == svc.Namespace && lbc.statusUpdater.externalServiceName == svc.Name
}

// IsExternalServiceKeyForStatus matches the service key specified by the external-service cli arg
func (lbc *LoadBalancerController) IsExternalServiceKeyForStatus(key string) bool {
	externalSvcKey := fmt.Sprintf("%s/%s", lbc.statusUpdater.namespace, lbc.statusUpdater.externalServiceName)
	return key == externalSvcKey
}

// reportStatusEnabled determines if we should attempt to report status for Ingress resources.
func (lbc *LoadBalancerController) reportStatusEnabled() bool {
	if lbc.reportIngressStatus {
		if lbc.isLeaderElectionEnabled {
			return lbc.leaderElector != nil && lbc.leaderElector.IsLeader()
		}
		return true
	}
	return false
}

// reportCustomResourceStatusEnabled determines if we should attempt to report status for Custom Resources.
func (lbc *LoadBalancerController) reportCustomResourceStatusEnabled() bool {
	if lbc.isLeaderElectionEnabled {
		return lbc.leaderElector != nil && lbc.leaderElector.IsLeader()
	}

	return true
}

func (lbc *LoadBalancerController) syncSecret(task task) {
	key := task.Key
	var obj interface{}
	var secretWatched bool
	var err error

	namespace, name, err := ParseNamespaceName(key)
	if err != nil {
		nl.Warnf(lbc.Logger, "Secret key %v is invalid: %v", key, err)
		return
	}
	obj, secretWatched, err = lbc.getNamespacedInformer(namespace).secretLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	resources := lbc.configuration.FindResourcesForSecret(namespace, name)

	if lbc.areCustomResourcesEnabled {
		secretPols := lbc.getPoliciesForSecret(namespace, name)
		for _, pol := range secretPols {
			resources = append(resources, lbc.configuration.FindResourcesForPolicy(pol.Namespace, pol.Name)...)
		}

		resources = removeDuplicateResources(resources)
	}

	nl.Debugf(lbc.Logger, "Found %v Resources with Secret %v", len(resources), key)

	if !secretWatched {
		lbc.secretStore.DeleteSecret(key)

		nl.Debugf(lbc.Logger, "Deleting Secret: %v", key)

		if len(resources) > 0 {
			lbc.handleRegularSecretDeletion(resources)
		}
		if lbc.isSpecialSecret(key) {
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonSecretDeleted, "A special secret [%s] was deleted.  Retaining the secret on this pod but this will affect new pods.", key)
			nl.Warnf(lbc.Logger, "A special Secret %v was removed. Retaining the Secret.", key)
		}
		return
	}

	nl.Debugf(lbc.Logger, "Adding / Updating Secret: %v", key)

	secret := obj.(*api_v1.Secret)

	lbc.secretStore.AddOrUpdateSecret(secret)

	if lbc.isSpecialSecret(key) {
		reloadNginx := true
		lbc.handleSpecialSecretUpdate(secret, reloadNginx)
		// we don't return here in case the special secret is also used in resources.
	}

	if len(resources) > 0 {
		lbc.handleSecretUpdate(secret, resources)
	}
}

func removeDuplicateResources(resources []Resource) []Resource {
	encountered := make(map[string]bool)
	var uniqueResources []Resource
	for _, r := range resources {
		key := r.GetKeyWithKind()
		if !encountered[key] {
			encountered[key] = true
			uniqueResources = append(uniqueResources, r)
		}
	}

	return uniqueResources
}

func (lbc *LoadBalancerController) isSpecialSecret(secretName string) bool {
	switch secretName {
	case lbc.specialSecrets.defaultServerSecret:
		return true
	case lbc.specialSecrets.wildcardTLSSecret:
		return true
	case lbc.specialSecrets.licenseSecret:
		return true
	case lbc.specialSecrets.clientAuthSecret:
		return true
	case lbc.specialSecrets.trustedCertSecret:
		return true
	default:
		return false
	}
}

func (lbc *LoadBalancerController) handleRegularSecretDeletion(resources []Resource) {
	resourceExes := lbc.createExtendedResources(resources)

	warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateResources(resourceExes, true)

	lbc.updateResourcesStatusAndEvents(resources, warnings, addOrUpdateErr)
}

func (lbc *LoadBalancerController) handleSecretUpdate(secret *api_v1.Secret, resources []Resource) {
	secretNsName := generateSecretNSName(secret)

	var warnings configs.Warnings
	var addOrUpdateErr error

	resourceExes := lbc.createExtendedResources(resources)

	warnings, addOrUpdateErr = lbc.configurator.AddOrUpdateResources(resourceExes, !lbc.configurator.DynamicSSLReloadEnabled())
	if addOrUpdateErr != nil {
		nl.Errorf(lbc.Logger, "Error when updating Secret %v: %v", secretNsName, addOrUpdateErr)
		lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonUpdatedWithError, "%v was updated, but not applied: %v", secretNsName, addOrUpdateErr)
	}

	lbc.updateResourcesStatusAndEvents(resources, warnings, addOrUpdateErr)
}

func (lbc *LoadBalancerController) validationTLSSpecialSecret(secret *api_v1.Secret, secretName string, secretList *[]string) error {
	err := secrets.ValidateTLSSecret(secret)
	if err != nil {
		return err
	}
	*secretList = append(*secretList, secretName)
	return nil
}

func (lbc *LoadBalancerController) handleSpecialSecretUpdate(secret *api_v1.Secret, reload bool) {
	var specialTLSSecretsToUpdate []string
	secretNsName := generateSecretNSName(secret)

	if ok := lbc.specialSecretValidation(secretNsName, secret, &specialTLSSecretsToUpdate); !ok {
		// if not ok bail early
		return
	}

	if ok := lbc.writeSpecialSecrets(secret, specialTLSSecretsToUpdate); !ok {
		// if not ok bail early
		return
	}

	// When the MGMT Configmap updates, we don't need to reload here, we are reloading in updateAllConfigs().
	if !reload {
		lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeNormal, nl.EventReasonSecretUpdated, "the special Secret %v was updated", secretNsName)
		return
	}

	// reload nginx when the TLS special secrets are updated
	switch secretNsName {
	case lbc.specialSecrets.licenseSecret:
		if ok := lbc.performNGINXReload(secret); !ok {
			return
		}
	case lbc.specialSecrets.defaultServerSecret, lbc.specialSecrets.wildcardTLSSecret:
		if ok := lbc.performDynamicSSLReload(secret); !ok {
			return
		}
	case lbc.specialSecrets.clientAuthSecret:
		if ok := lbc.performNGINXReload(secret); !ok {
			return
		}
	case lbc.specialSecrets.trustedCertSecret:
		lbc.updateAllConfigs()
		if ok := lbc.performNGINXReload(secret); !ok {
			return
		}
	}

	lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeNormal, nl.EventReasonSecretUpdated, "the special Secret %v was updated", secretNsName)
}

// writeSpecialSecrets generates content and writes the secret to disk
func (lbc *LoadBalancerController) writeSpecialSecrets(secret *api_v1.Secret, specialTLSSecretsToUpdate []string) bool {
	secretNsName := generateSecretNSName(secret)
	var mgmtClientAuthNamespaceName string
	if lbc.configurator.MgmtCfgParams != nil {
		mgmtClientAuthNamespaceName = fmt.Sprintf("%s/%s", lbc.metadata.pod.Namespace, lbc.configurator.MgmtCfgParams.Secrets.ClientAuth)
	}
	switch secret.Type {
	case secrets.SecretTypeLicense:
		err := lbc.configurator.AddOrUpdateLicenseSecret(secret)
		if err != nil {
			nl.Error(lbc.Logger, err)
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonUpdatedWithError, "the license Secret %v was updated, but not applied: %v", secretNsName, err)
			return false
		}
	case secrets.SecretTypeCA:
		lbc.configurator.AddOrUpdateCASecret(secret, fmt.Sprintf("mgmt/%s", configs.CACrtKey), fmt.Sprintf("mgmt/%s", configs.CACrlKey))
	case api_v1.SecretTypeTLS:
		// if the secret name matches the specified
		if secretNsName == mgmtClientAuthNamespaceName {
			lbc.configurator.AddOrUpdateMGMTClientAuthSecret(secret)
		} else {
			lbc.configurator.AddOrUpdateSpecialTLSSecrets(secret, specialTLSSecretsToUpdate)
		}
	}
	return true
}

func (lbc *LoadBalancerController) specialSecretValidation(secretNsName string, secret *api_v1.Secret, specialTLSSecretsToUpdate *[]string) bool {
	if secretNsName == lbc.specialSecrets.defaultServerSecret {
		err := lbc.validationTLSSpecialSecret(secret, configs.DefaultServerSecretFileName, specialTLSSecretsToUpdate)
		if err != nil {
			nl.Errorf(lbc.Logger, "Couldn't validate the special Secret %v: %v", secretNsName, err)
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonRejected, "the special Secret %v was rejected, using the previous version: %v", secretNsName, err)
			return false
		}
	}
	if secretNsName == lbc.specialSecrets.wildcardTLSSecret {
		err := lbc.validationTLSSpecialSecret(secret, configs.WildcardSecretFileName, specialTLSSecretsToUpdate)
		if err != nil {
			nl.Errorf(lbc.Logger, "Couldn't validate the special Secret %v: %v", secretNsName, err)
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonRejected, "the special Secret %v was rejected, using the previous version: %v", secretNsName, err)
			return false
		}
	}
	if secretNsName == lbc.specialSecrets.licenseSecret {
		err := secrets.ValidateLicenseSecret(secret)
		if err != nil {
			nl.Errorf(lbc.Logger, "Couldn't validate the special Secret %v: %v", secretNsName, err)
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonRejected, "the special Secret %v was rejected, using the previous version: %v", secretNsName, err)
			return false
		}
	}
	if secretNsName == lbc.specialSecrets.trustedCertSecret {
		err := secrets.ValidateCASecret(secret)
		if err != nil {
			nl.Errorf(lbc.Logger, "Couldn't validate the special Secret %v: %v", secretNsName, err)
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonRejected, "the special Secret %v was rejected, using the previous version: %v", secretNsName, err)
			return false
		}
	}
	if secretNsName == lbc.specialSecrets.clientAuthSecret {
		err := secrets.ValidateTLSSecret(secret)
		if err != nil {
			nl.Errorf(lbc.Logger, "Couldn't validate the special Secret %v: %v", secretNsName, err)
			lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonRejected, "the special Secret %v was rejected, using the previous version: %v", secretNsName, err)
			return false
		}
	}
	return true
}

func (lbc *LoadBalancerController) performDynamicSSLReload(secret *api_v1.Secret) bool {
	if !lbc.configurator.DynamicSSLReloadEnabled() {
		return lbc.performNGINXReload(secret)
	}
	return true
}

func (lbc *LoadBalancerController) performNGINXReload(secret *api_v1.Secret) bool {
	secretNsName := generateSecretNSName(secret)
	if err := lbc.configurator.Reload(false); err != nil {
		nl.Errorf(lbc.Logger, "error when reloading NGINX when updating the special Secrets: %v", err)
		lbc.recorder.Eventf(lbc.metadata.pod, api_v1.EventTypeWarning, nl.EventReasonUpdatedWithError, "the special Secret %v was updated, but not applied: %v", secretNsName, err)
		return false
	}
	return true
}

func generateSecretNSName(secret *api_v1.Secret) string {
	return secret.Namespace + "/" + secret.Name
}

func getStatusFromEventTitle(eventTitle string) string {
	switch eventTitle {
	case "AddedOrUpdatedWithError", "Rejected", "NoVirtualServersFound", "Missing Secret", "UpdatedWithError":
		return conf_v1.StateInvalid
	case "AddedOrUpdatedWithWarning", "UpdatedWithWarning":
		return conf_v1.StateWarning
	case "AddedOrUpdated", "Updated":
		return conf_v1.StateValid
	}

	return ""
}

func (lbc *LoadBalancerController) updateVirtualServersStatusFromEvents() error {
	var allErrs []error
	for _, nsi := range lbc.namespacedInformers {
		for _, obj := range nsi.virtualServerLister.List() {
			vs := obj.(*conf_v1.VirtualServer)

			if !lbc.HasCorrectIngressClass(vs) {
				nl.Debugf(lbc.Logger, "Ignoring VirtualServer %v based on class %v", vs.Name, vs.Spec.IngressClass)
				continue
			}

			events, err := lbc.client.CoreV1().Events(vs.Namespace).List(context.TODO(),
				meta_v1.ListOptions{FieldSelector: fmt.Sprintf("involvedObject.name=%v,involvedObject.uid=%v", vs.Name, vs.UID)})
			if err != nil {
				allErrs = append(allErrs, fmt.Errorf("error trying to get events for VirtualServer %v/%v: %w", vs.Namespace, vs.Name, err))
				break
			}

			if len(events.Items) == 0 {
				continue
			}

			var timestamp time.Time
			var latestEvent api_v1.Event
			for _, event := range events.Items {
				if event.CreationTimestamp.After(timestamp) {
					latestEvent = event
				}
			}

			err = lbc.statusUpdater.UpdateVirtualServerStatus(vs, getStatusFromEventTitle(latestEvent.Reason), latestEvent.Reason, latestEvent.Message)
			if err != nil {
				allErrs = append(allErrs, err)
			}
		}
	}

	if len(allErrs) > 0 {
		return fmt.Errorf("not all VirtualServers statuses were updated: %v", allErrs)
	}

	return nil
}

func (lbc *LoadBalancerController) updateVirtualServerRoutesStatusFromEvents() error {
	var allErrs []error
	for _, nsi := range lbc.namespacedInformers {
		for _, obj := range nsi.virtualServerRouteLister.List() {
			vsr := obj.(*conf_v1.VirtualServerRoute)

			if !lbc.HasCorrectIngressClass(vsr) {
				nl.Debugf(lbc.Logger, "Ignoring VirtualServerRoute %v based on class %v", vsr.Name, vsr.Spec.IngressClass)
				continue
			}

			events, err := lbc.client.CoreV1().Events(vsr.Namespace).List(context.TODO(),
				meta_v1.ListOptions{FieldSelector: fmt.Sprintf("involvedObject.name=%v,involvedObject.uid=%v", vsr.Name, vsr.UID)})
			if err != nil {
				allErrs = append(allErrs, fmt.Errorf("error trying to get events for VirtualServerRoute %v/%v: %w", vsr.Namespace, vsr.Name, err))
				break
			}

			if len(events.Items) == 0 {
				continue
			}

			var timestamp time.Time
			var latestEvent api_v1.Event
			for _, event := range events.Items {
				if event.CreationTimestamp.After(timestamp) {
					latestEvent = event
				}
			}

			err = lbc.statusUpdater.UpdateVirtualServerRouteStatus(vsr, getStatusFromEventTitle(latestEvent.Reason), latestEvent.Reason, latestEvent.Message)
			if err != nil {
				allErrs = append(allErrs, err)
			}
		}
	}

	if len(allErrs) > 0 {
		return fmt.Errorf("not all VirtualServerRoutes statuses were updated: %v", allErrs)
	}

	return nil
}

func getIPAddressesFromEndpoints(endpoints []podEndpoint) []string {
	var endps []string
	for _, ep := range endpoints {
		endps = append(endps, ep.Address)
	}
	return endps
}

func (lbc *LoadBalancerController) createMergeableIngresses(ingConfig *IngressConfiguration) *configs.MergeableIngresses {
	// for master Ingress, validMinionPaths are nil
	masterIngressEx := lbc.createIngressEx(ingConfig.Ingress, ingConfig.ValidHosts, nil)

	var minions []*configs.IngressEx

	for _, m := range ingConfig.Minions {
		minions = append(minions, lbc.createIngressEx(m.Ingress, ingConfig.ValidHosts, m.ValidPaths))
	}

	return &configs.MergeableIngresses{
		Master:  masterIngressEx,
		Minions: minions,
	}
}

func (lbc *LoadBalancerController) createIngressEx(ing *networking.Ingress, validHosts map[string]bool, validMinionPaths map[string]bool) *configs.IngressEx {
	var endps []string
	ingEx := &configs.IngressEx{
		Ingress:          ing,
		ValidHosts:       validHosts,
		ValidMinionPaths: validMinionPaths,
	}

	ingEx.SecretRefs = make(map[string]*secrets.SecretReference)

	for _, tls := range ing.Spec.TLS {
		secretName := tls.SecretName
		secretKey := ing.Namespace + "/" + secretName

		secretRef := lbc.secretStore.GetSecret(secretKey)
		if secretRef.Error != nil {
			nl.Warnf(lbc.Logger, "Error trying to get the secret %v for Ingress %v: %v", secretName, ing.Name, secretRef.Error)
		}

		ingEx.SecretRefs[secretName] = secretRef
	}

	if basicAuth, exists := ingEx.Ingress.Annotations[configs.BasicAuthSecretAnnotation]; exists {
		secretName := basicAuth
		secretKey := ing.Namespace + "/" + secretName

		secretRef := lbc.secretStore.GetSecret(secretKey)
		if secretRef.Error != nil {
			nl.Warnf(lbc.Logger, "Error trying to get the secret %v for Ingress %v/%v: %v", secretName, ing.Namespace, ing.Name, secretRef.Error)
		}

		ingEx.SecretRefs[secretName] = secretRef
	}

	if lbc.isNginxPlus {
		if jwtKey, exists := ingEx.Ingress.Annotations[configs.JWTKeyAnnotation]; exists {
			secretName := jwtKey
			secretKey := ing.Namespace + "/" + secretName

			secretRef := lbc.secretStore.GetSecret(secretKey)
			if secretRef.Error != nil {
				nl.Warnf(lbc.Logger, "Error trying to get the secret %v for Ingress %v/%v: %v", secretName, ing.Namespace, ing.Name, secretRef.Error)
			}

			ingEx.SecretRefs[secretName] = secretRef
		}
		if lbc.appProtectEnabled {
			if apPolicyAntn, exists := ingEx.Ingress.Annotations[configs.AppProtectPolicyAnnotation]; exists {
				policy, err := lbc.getAppProtectPolicy(ing)
				if err != nil {
					nl.Warnf(lbc.Logger, "Error Getting App Protect policy %v for Ingress %v/%v: %v", apPolicyAntn, ing.Namespace, ing.Name, err)
				} else {
					ingEx.AppProtectPolicy = policy
				}
			}

			if apLogConfAntn, exists := ingEx.Ingress.Annotations[configs.AppProtectLogConfAnnotation]; exists {
				logConf, err := lbc.getAppProtectLogConfAndDst(ing)
				if err != nil {
					nl.Warnf(lbc.Logger, "Error Getting App Protect Log Config %v for Ingress %v/%v: %v", apLogConfAntn, ing.Namespace, ing.Name, err)
				} else {
					ingEx.AppProtectLogs = logConf
				}
			}
		}

		if lbc.appProtectDosEnabled {
			if dosProtectedAnnotationValue, exists := ingEx.Ingress.Annotations[configs.AppProtectDosProtectedAnnotation]; exists {
				dosResEx, err := lbc.dosConfiguration.GetValidDosEx(ing.Namespace, dosProtectedAnnotationValue)
				if err != nil {
					nl.Warnf(lbc.Logger, "Error Getting Dos Protected Resource %v for Ingress %v/%v: %v", dosProtectedAnnotationValue, ing.Namespace, ing.Name, err)
				}
				if dosResEx != nil {
					ingEx.DosEx = dosResEx
				}
			}
		}
	}

	ingEx.Endpoints = make(map[string][]string)
	ingEx.HealthChecks = make(map[string]*api_v1.Probe)
	ingEx.ExternalNameSvcs = make(map[string]bool)
	ingEx.PodsByIP = make(map[string]configs.PodInfo)
	hasUseClusterIP := ingEx.Ingress.Annotations[configs.UseClusterIPAnnotation] == "true"

	if ing.Spec.DefaultBackend != nil {
		podEndps := []podEndpoint{}
		var external bool
		svc, err := lbc.getServiceForIngressBackend(ing.Spec.DefaultBackend, ing.Namespace)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting service %v: %v", ing.Spec.DefaultBackend.Service.Name, err)
		} else {
			podEndps, external, err = lbc.getEndpointsForIngressBackend(ing.Spec.DefaultBackend, svc)
			if err == nil && external && lbc.isNginxPlus {
				ingEx.ExternalNameSvcs[svc.Name] = true
			}
		}

		if err != nil {
			nl.Warnf(lbc.Logger, "Error retrieving endpoints for the service %v: %v", ing.Spec.DefaultBackend.Service.Name, err)
		}

		if svc != nil && !external && hasUseClusterIP {
			if ing.Spec.DefaultBackend.Service.Port.Number == 0 {
				for _, port := range svc.Spec.Ports {
					if port.Name == ing.Spec.DefaultBackend.Service.Port.Name {
						ing.Spec.DefaultBackend.Service.Port.Number = port.Port
						break
					}
				}
			}
			endps = []string{ipv6SafeAddrPort(svc.Spec.ClusterIP, ing.Spec.DefaultBackend.Service.Port.Number)}
		} else {
			endps = getIPAddressesFromEndpoints(podEndps)
		}

		// endps is empty if there was any error before this point
		ingEx.Endpoints[ing.Spec.DefaultBackend.Service.Name+configs.GetBackendPortAsString(ing.Spec.DefaultBackend.Service.Port)] = endps

		if lbc.isNginxPlus && lbc.isHealthCheckEnabled(ing) {
			healthCheck := lbc.getHealthChecksForIngressBackend(ing.Spec.DefaultBackend, ing.Namespace)
			if healthCheck != nil {
				ingEx.HealthChecks[ing.Spec.DefaultBackend.Service.Name+configs.GetBackendPortAsString(ing.Spec.DefaultBackend.Service.Port)] = healthCheck
			}
		}

		if (lbc.isNginxPlus && lbc.isPrometheusEnabled) || lbc.isLatencyMetricsEnabled {
			for _, endpoint := range podEndps {
				ingEx.PodsByIP[endpoint.Address] = configs.PodInfo{
					Name:         endpoint.PodName,
					MeshPodOwner: endpoint.MeshPodOwner,
				}
			}
		}
	}

	for _, rule := range ing.Spec.Rules {
		if !validHosts[rule.Host] {
			nl.Debugf(lbc.Logger, "Skipping host %s for Ingress %s", rule.Host, ing.Name)
			continue
		}

		// check if rule has any paths
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			path := path // address gosec G601
			podEndps := []podEndpoint{}
			if validMinionPaths != nil && !validMinionPaths[path.Path] {
				nl.Debugf(lbc.Logger, "Skipping path %s for minion Ingress %s", path.Path, ing.Name)
				continue
			}

			var external bool
			svc, err := lbc.getServiceForIngressBackend(&path.Backend, ing.Namespace)
			if err != nil {
				nl.Debugf(lbc.Logger, "Error getting service %v: %v", &path.Backend.Service.Name, err)
			} else {
				podEndps, external, err = lbc.getEndpointsForIngressBackend(&path.Backend, svc)
				if err == nil && external && lbc.isNginxPlus {
					ingEx.ExternalNameSvcs[svc.Name] = true
				}
			}

			if err != nil {
				nl.Warnf(lbc.Logger, "Error retrieving endpoints for the service %v: %v", path.Backend.Service.Name, err)
			}

			if svc != nil && !external && hasUseClusterIP {
				if path.Backend.Service.Port.Number == 0 {
					for _, port := range svc.Spec.Ports {
						if port.Name == path.Backend.Service.Port.Name {
							path.Backend.Service.Port.Number = port.Port
							break
						}
					}
				}
				endps = []string{ipv6SafeAddrPort(svc.Spec.ClusterIP, path.Backend.Service.Port.Number)}
			} else {
				endps = getIPAddressesFromEndpoints(podEndps)
			}

			// endps is empty if there was any error before this point
			ingEx.Endpoints[path.Backend.Service.Name+configs.GetBackendPortAsString(path.Backend.Service.Port)] = endps

			// Pull active health checks from k8 api
			if lbc.isNginxPlus && lbc.isHealthCheckEnabled(ing) {
				healthCheck := lbc.getHealthChecksForIngressBackend(&path.Backend, ing.Namespace)
				if healthCheck != nil {
					ingEx.HealthChecks[path.Backend.Service.Name+configs.GetBackendPortAsString(path.Backend.Service.Port)] = healthCheck
				}
			}

			if lbc.isNginxPlus || lbc.isLatencyMetricsEnabled {
				for _, endpoint := range podEndps {
					ingEx.PodsByIP[endpoint.Address] = configs.PodInfo{
						Name:         endpoint.PodName,
						MeshPodOwner: endpoint.MeshPodOwner,
					}
				}
			}
		}
	}

	return ingEx
}

func (lbc *LoadBalancerController) createVirtualServerEx(virtualServer *conf_v1.VirtualServer, virtualServerRoutes []*conf_v1.VirtualServerRoute) *configs.VirtualServerEx {
	virtualServerEx := configs.VirtualServerEx{
		VirtualServer:  virtualServer,
		SecretRefs:     make(map[string]*secrets.SecretReference),
		ApPolRefs:      make(map[string]*unstructured.Unstructured),
		LogConfRefs:    make(map[string]*unstructured.Unstructured),
		DosProtectedEx: make(map[string]*configs.DosEx),
	}

	resource := lbc.configuration.hosts[virtualServer.Spec.Host]
	if vsc, ok := resource.(*VirtualServerConfiguration); ok {
		virtualServerEx.HTTPPort = vsc.HTTPPort
		virtualServerEx.HTTPSPort = vsc.HTTPSPort
		virtualServerEx.HTTPIPv4 = vsc.HTTPIPv4
		virtualServerEx.HTTPIPv6 = vsc.HTTPIPv6
		virtualServerEx.HTTPSIPv4 = vsc.HTTPSIPv4
		virtualServerEx.HTTPSIPv6 = vsc.HTTPSIPv6
	}

	if virtualServer.Spec.TLS != nil && virtualServer.Spec.TLS.Secret != "" {
		scrtKey := virtualServer.Namespace + "/" + virtualServer.Spec.TLS.Secret

		scrtRef := lbc.secretStore.GetSecret(scrtKey)
		if scrtRef.Error != nil {
			nl.Warnf(lbc.Logger, "Error trying to get the secret %v for VirtualServer %v: %v", scrtKey, virtualServer.Name, scrtRef.Error)
		}

		virtualServerEx.SecretRefs[scrtKey] = scrtRef
	}

	policies, policyErrors := lbc.getPolicies(virtualServer.Spec.Policies, virtualServer.Namespace)
	for _, err := range policyErrors {
		nl.Warnf(lbc.Logger, "Error getting policy for VirtualServer %s/%s: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	err := lbc.addJWTSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting JWT secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}
	err = lbc.addBasicSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting Basic Auth secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}
	err = lbc.addIngressMTLSSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting IngressMTLS secret for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}
	err = lbc.addEgressMTLSSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting EgressMTLS secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}
	err = lbc.addOIDCSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting OIDC secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}
	err = lbc.addAPIKeySecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting APIKey secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	err = lbc.addWAFPolicyRefs(virtualServerEx.ApPolRefs, virtualServerEx.LogConfRefs, policies)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting App Protect resource for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	if virtualServer.Spec.Dos != "" {
		dosEx, err := lbc.dosConfiguration.GetValidDosEx(virtualServer.Namespace, virtualServer.Spec.Dos)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting App Protect Dos resource for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
		if dosEx != nil {
			virtualServerEx.DosProtectedEx[""] = dosEx
		}
	}

	endpoints := make(map[string][]string)
	externalNameSvcs := make(map[string]bool)
	podsByIP := make(map[string]configs.PodInfo)

	// generateBackupEndpoints takes the Upstream, determines if backup and backup port are defined.
	// If backup and backup port are defined it generates a backup server entry for the upstream.
	// Backup Service is of type ExternalName.
	generateBackupEndpoints := func(endpoints map[string][]string, u conf_v1.Upstream) {
		if u.Backup == "" || u.BackupPort == nil {
			return
		}
		backupEndpointsKey := configs.GenerateEndpointsKey(virtualServer.Namespace, u.Backup, u.Subselector, *u.BackupPort)
		backupEndps, external, err := lbc.getEndpointsForUpstream(virtualServer.Namespace, u.Backup, *u.BackupPort)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting Endpoints for Upstream %v: %v", u.Name, err)
		}
		if err == nil && external {
			externalNameSvcs[configs.GenerateExternalNameSvcKey(virtualServer.Namespace, u.Backup)] = true
		}
		bendps := getIPAddressesFromEndpoints(backupEndps)
		endpoints[backupEndpointsKey] = bendps
	}

	for _, u := range virtualServer.Spec.Upstreams {
		endpointsKey := configs.GenerateEndpointsKey(virtualServer.Namespace, u.Service, u.Subselector, u.Port)

		var endps []string
		if u.UseClusterIP {
			s, err := lbc.getServiceForUpstream(virtualServer.Namespace, u.Service, u.Port)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting Service for Upstream %v: %v", u.Service, err)
			} else {
				endps = append(endps, ipv6SafeAddrPort(s.Spec.ClusterIP, int32(u.Port)))
			}

		} else {
			var podEndps []podEndpoint
			var err error

			if len(u.Subselector) > 0 {
				podEndps, err = lbc.getEndpointsForSubselector(virtualServer.Namespace, u)
			} else {
				var external bool
				podEndps, external, err = lbc.getEndpointsForUpstream(virtualServer.Namespace, u.Service, u.Port)

				if err == nil && external && lbc.isNginxPlus {
					externalNameSvcs[configs.GenerateExternalNameSvcKey(virtualServer.Namespace, u.Service)] = true
				}
			}

			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting Endpoints for Upstream %v: %v", u.Name, err)
			}

			endps = getIPAddressesFromEndpoints(podEndps)

			if (lbc.isNginxPlus && lbc.isPrometheusEnabled) || lbc.isLatencyMetricsEnabled {
				for _, endpoint := range podEndps {
					podsByIP[endpoint.Address] = configs.PodInfo{
						Name:         endpoint.PodName,
						MeshPodOwner: endpoint.MeshPodOwner,
					}
				}
			}
		}

		generateBackupEndpoints(endpoints, u)
		endpoints[endpointsKey] = endps
	}

	for _, r := range virtualServer.Spec.Routes {
		vsRoutePolicies, policyErrors := lbc.getPolicies(r.Policies, virtualServer.Namespace)
		for _, err := range policyErrors {
			nl.Warnf(lbc.Logger, "Error getting policy for VirtualServer %s/%s: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
		policies = append(policies, vsRoutePolicies...)

		err = lbc.addJWTSecretRefs(virtualServerEx.SecretRefs, vsRoutePolicies)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting JWT secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
		err = lbc.addBasicSecretRefs(virtualServerEx.SecretRefs, vsRoutePolicies)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting Basic Auth secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
		err = lbc.addEgressMTLSSecretRefs(virtualServerEx.SecretRefs, vsRoutePolicies)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting EgressMTLS secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}

		err = lbc.addWAFPolicyRefs(virtualServerEx.ApPolRefs, virtualServerEx.LogConfRefs, vsRoutePolicies)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting WAF policies for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}

		if r.Dos != "" {
			routeDosEx, err := lbc.dosConfiguration.GetValidDosEx(virtualServer.Namespace, r.Dos)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting App Protect Dos resource for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
			}
			virtualServerEx.DosProtectedEx[r.Path] = routeDosEx
		}

		err = lbc.addOIDCSecretRefs(virtualServerEx.SecretRefs, vsRoutePolicies)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting OIDC secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}

		err = lbc.addAPIKeySecretRefs(virtualServerEx.SecretRefs, vsRoutePolicies)
		if err != nil {
			nl.Warnf(lbc.Logger, "Error getting APIKey secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}

	}

	for _, vsr := range virtualServerRoutes {
		for _, sr := range vsr.Spec.Subroutes {
			vsrSubroutePolicies, policyErrors := lbc.getPolicies(sr.Policies, vsr.Namespace)
			for _, err := range policyErrors {
				nl.Warnf(lbc.Logger, "Error getting policy for VirtualServerRoute %s/%s: %v", vsr.Namespace, vsr.Name, err)
			}
			policies = append(policies, vsrSubroutePolicies...)

			err = lbc.addJWTSecretRefs(virtualServerEx.SecretRefs, vsrSubroutePolicies)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting JWT secrets for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			err = lbc.addBasicSecretRefs(virtualServerEx.SecretRefs, vsrSubroutePolicies)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting Basic Auth secrets for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			err = lbc.addEgressMTLSSecretRefs(virtualServerEx.SecretRefs, vsrSubroutePolicies)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting EgressMTLS secrets for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			err = lbc.addOIDCSecretRefs(virtualServerEx.SecretRefs, vsrSubroutePolicies)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting OIDC secrets for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			err = lbc.addAPIKeySecretRefs(virtualServerEx.SecretRefs, vsrSubroutePolicies)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting APIKey secrets for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			err = lbc.addWAFPolicyRefs(virtualServerEx.ApPolRefs, virtualServerEx.LogConfRefs, vsrSubroutePolicies)
			if err != nil {
				nl.Warnf(lbc.Logger, "Error getting WAF policies for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			if sr.Dos != "" {
				routeDosEx, err := lbc.dosConfiguration.GetValidDosEx(vsr.Namespace, sr.Dos)
				if err != nil {
					nl.Warnf(lbc.Logger, "Error getting App Protect Dos resource for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
				}
				virtualServerEx.DosProtectedEx[sr.Path] = routeDosEx
			}
		}

		for _, u := range vsr.Spec.Upstreams {
			endpointsKey := configs.GenerateEndpointsKey(vsr.Namespace, u.Service, u.Subselector, u.Port)

			var endps []string
			if u.UseClusterIP {
				s, err := lbc.getServiceForUpstream(vsr.Namespace, u.Service, u.Port)
				if err != nil {
					nl.Warnf(lbc.Logger, "Error getting Service for Upstream %v: %v", u.Service, err)
				} else {
					endps = append(endps, fmt.Sprintf("%s:%d", s.Spec.ClusterIP, u.Port))
				}

			} else {
				var podEndps []podEndpoint
				var err error
				if len(u.Subselector) > 0 {
					podEndps, err = lbc.getEndpointsForSubselector(vsr.Namespace, u)
				} else {
					var external bool
					podEndps, external, err = lbc.getEndpointsForUpstream(vsr.Namespace, u.Service, u.Port)

					if err == nil && external && lbc.isNginxPlus {
						externalNameSvcs[configs.GenerateExternalNameSvcKey(vsr.Namespace, u.Service)] = true
					}
				}
				if err != nil {
					nl.Warnf(lbc.Logger, "Error getting Endpoints for Upstream %v: %v", u.Name, err)
				}

				endps = getIPAddressesFromEndpoints(podEndps)

				if lbc.isNginxPlus || lbc.isLatencyMetricsEnabled {
					for _, endpoint := range podEndps {
						podsByIP[endpoint.Address] = configs.PodInfo{
							Name:         endpoint.PodName,
							MeshPodOwner: endpoint.MeshPodOwner,
						}
					}
				}
			}

			generateBackupEndpoints(endpoints, u)
			endpoints[endpointsKey] = endps
		}
	}

	virtualServerEx.Endpoints = endpoints
	virtualServerEx.VirtualServerRoutes = virtualServerRoutes
	virtualServerEx.ExternalNameSvcs = externalNameSvcs
	virtualServerEx.Policies = createPolicyMap(policies)
	virtualServerEx.PodsByIP = podsByIP

	return &virtualServerEx
}

func createPolicyMap(policies []*conf_v1.Policy) map[string]*conf_v1.Policy {
	result := make(map[string]*conf_v1.Policy)

	for _, p := range policies {
		key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
		result[key] = p
	}

	return result
}

func (lbc *LoadBalancerController) getAllPolicies() []*conf_v1.Policy {
	var policies []*conf_v1.Policy

	for _, nsi := range lbc.namespacedInformers {
		for _, obj := range nsi.policyLister.List() {
			pol := obj.(*conf_v1.Policy)

			err := validation.ValidatePolicy(pol, lbc.isNginxPlus, lbc.enableOIDC, lbc.appProtectEnabled)
			if err != nil {
				nl.Debugf(lbc.Logger, "Skipping invalid Policy %s/%s: %v", pol.Namespace, pol.Name, err)
				continue
			}

			policies = append(policies, pol)
		}
	}

	return policies
}

func (lbc *LoadBalancerController) getPolicies(policies []conf_v1.PolicyReference, ownerNamespace string) ([]*conf_v1.Policy, []error) {
	var result []*conf_v1.Policy
	var errors []error

	for _, p := range policies {
		polNamespace := p.Namespace
		if polNamespace == "" {
			polNamespace = ownerNamespace
		}

		policyKey := fmt.Sprintf("%s/%s", polNamespace, p.Name)

		var policyObj interface{}
		var exists bool
		var err error

		nsi := lbc.getNamespacedInformer(polNamespace)
		if nsi == nil {
			errors = append(errors, fmt.Errorf("failed to get namespace %s", polNamespace))
			continue
		}

		policyObj, exists, err = nsi.policyLister.GetByKey(policyKey)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to get policy %s: %w", policyKey, err))
			continue
		}

		if !exists {
			errors = append(errors, fmt.Errorf("policy %s doesn't exist", policyKey))
			continue
		}

		policy := policyObj.(*conf_v1.Policy)

		if !lbc.HasCorrectIngressClass(policy) {
			errors = append(errors, fmt.Errorf("referenced policy %s has incorrect ingress class: %s (controller ingress class: %s)", policyKey, policy.Spec.IngressClass, lbc.ingressClass))
			continue
		}

		err = validation.ValidatePolicy(policy, lbc.isNginxPlus, lbc.enableOIDC, lbc.appProtectEnabled)
		if err != nil {
			errors = append(errors, fmt.Errorf("policy %s is invalid: %w", policyKey, err))
			continue
		}

		result = append(result, policy)
	}

	return result, errors
}

func (lbc *LoadBalancerController) addJWTSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.JWTAuth == nil {
			continue
		}

		if pol.Spec.JWTAuth.JwksURI != "" {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.JWTAuth.Secret)
		secretRef := lbc.secretStore.GetSecret(secretKey)

		secretRefs[secretKey] = secretRef

		if secretRef.Error != nil {
			return secretRef.Error
		}
	}

	return nil
}

func (lbc *LoadBalancerController) addBasicSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.BasicAuth == nil {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.BasicAuth.Secret)
		secretRef := lbc.secretStore.GetSecret(secretKey)

		secretRefs[secretKey] = secretRef

		if secretRef.Error != nil {
			return secretRef.Error
		}
	}

	return nil
}

func (lbc *LoadBalancerController) addIngressMTLSSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.IngressMTLS == nil {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.IngressMTLS.ClientCertSecret)
		secretRef := lbc.secretStore.GetSecret(secretKey)

		secretRefs[secretKey] = secretRef

		return secretRef.Error
	}

	return nil
}

func (lbc *LoadBalancerController) addEgressMTLSSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.EgressMTLS == nil {
			continue
		}
		if pol.Spec.EgressMTLS.TLSSecret != "" {
			secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.EgressMTLS.TLSSecret)
			secretRef := lbc.secretStore.GetSecret(secretKey)

			secretRefs[secretKey] = secretRef

			if secretRef.Error != nil {
				return secretRef.Error
			}
		}
		if pol.Spec.EgressMTLS.TrustedCertSecret != "" {
			secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.EgressMTLS.TrustedCertSecret)
			secretRef := lbc.secretStore.GetSecret(secretKey)

			secretRefs[secretKey] = secretRef

			if secretRef.Error != nil {
				return secretRef.Error
			}
		}
	}

	return nil
}

func (lbc *LoadBalancerController) addOIDCSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.OIDC == nil {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.OIDC.ClientSecret)
		secretRef := lbc.secretStore.GetSecret(secretKey)

		secretRefs[secretKey] = secretRef

		if secretRef.Error != nil {
			return secretRef.Error
		}
	}
	return nil
}

func (lbc *LoadBalancerController) addAPIKeySecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.APIKey == nil {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.APIKey.ClientSecret)
		secretRef := lbc.secretStore.GetSecret(secretKey)

		secretRefs[secretKey] = secretRef

		if secretRef.Error != nil {
			return secretRef.Error
		}

	}
	return nil
}

func (lbc *LoadBalancerController) getPoliciesForSecret(secretNamespace string, secretName string) []*conf_v1.Policy {
	return findPoliciesForSecret(lbc.getAllPolicies(), secretNamespace, secretName)
}

func findPoliciesForSecret(policies []*conf_v1.Policy, secretNamespace string, secretName string) []*conf_v1.Policy {
	var res []*conf_v1.Policy

	for _, pol := range policies {
		if pol.Spec.IngressMTLS != nil && pol.Spec.IngressMTLS.ClientCertSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.JWTAuth != nil && pol.Spec.JWTAuth.Secret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.BasicAuth != nil && pol.Spec.BasicAuth.Secret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.EgressMTLS != nil && pol.Spec.EgressMTLS.TLSSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.EgressMTLS != nil && pol.Spec.EgressMTLS.TrustedCertSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.OIDC != nil && pol.Spec.OIDC.ClientSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.APIKey != nil && pol.Spec.APIKey.ClientSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		}
	}

	return res
}

func (lbc *LoadBalancerController) getTransportServerBackupEndpointsAndKey(transportServer *conf_v1.TransportServer, u conf_v1.TransportServerUpstream, externalNameSvcs map[string]bool) ([]string, string) {
	backupEndpointsKey := configs.GenerateEndpointsKey(transportServer.Namespace, u.Backup, nil, *u.BackupPort)
	backupEndps, external, err := lbc.getEndpointsForUpstream(transportServer.Namespace, u.Backup, *u.BackupPort)
	if err != nil {
		nl.Warnf(lbc.Logger, "Error getting Endpoints for Upstream %v: %v", u.Name, err)
	}
	if err == nil && external {
		externalNameSvcs[configs.GenerateExternalNameSvcKey(transportServer.Namespace, u.Backup)] = true
	}
	bendps := getIPAddressesFromEndpoints(backupEndps)
	return bendps, backupEndpointsKey
}

func (lbc *LoadBalancerController) getEndpointsForUpstream(namespace string, upstreamService string, upstreamPort uint16) (endps []podEndpoint, isExternal bool, err error) {
	svc, err := lbc.getServiceForUpstream(namespace, upstreamService, upstreamPort)
	if err != nil {
		return nil, false, fmt.Errorf("error getting service %v: %w", upstreamService, err)
	}

	backend := &networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: upstreamService,
			Port: networking.ServiceBackendPort{
				Number: int32(upstreamPort),
			},
		},
	}

	endps, isExternal, err = lbc.getEndpointsForIngressBackend(backend, svc)
	if err != nil {
		return nil, false, fmt.Errorf("error retrieving endpoints for the service %v: %w", upstreamService, err)
	}

	return endps, isExternal, err
}

func (lbc *LoadBalancerController) getEndpointsForSubselector(namespace string, upstream conf_v1.Upstream) (endps []podEndpoint, err error) {
	svc, err := lbc.getServiceForUpstream(namespace, upstream.Service, upstream.Port)
	if err != nil {
		return nil, fmt.Errorf("error getting service %v: %w", upstream.Service, err)
	}

	var targetPort int32

	for _, port := range svc.Spec.Ports {
		if port.Port == int32(upstream.Port) {
			targetPort, err = lbc.getTargetPort(port, svc)
			if err != nil {
				return nil, fmt.Errorf("error determining target port for port %v in service %v: %w", upstream.Port, svc.Name, err)
			}
			break
		}
	}

	if targetPort == 0 {
		return nil, fmt.Errorf("no port %v in service %s", upstream.Port, svc.Name)
	}

	endps, err = lbc.getEndpointsForServiceWithSubselector(targetPort, upstream.Subselector, svc)
	if err != nil {
		return nil, fmt.Errorf("error retrieving endpoints for the service %v: %w", upstream.Service, err)
	}

	return endps, err
}

func (lbc *LoadBalancerController) getEndpointsForServiceWithSubselector(targetPort int32, subselector map[string]string, svc *api_v1.Service) (endps []podEndpoint, err error) {
	var pods []*api_v1.Pod
	nsi := lbc.getNamespacedInformer(svc.Namespace)
	pods, err = nsi.podLister.ListByNamespace(svc.Namespace, labels.Merge(svc.Spec.Selector, subselector).AsSelector())
	if err != nil {
		return nil, fmt.Errorf("error getting pods in namespace %v that match the selector %v: %w", svc.Namespace, labels.Merge(svc.Spec.Selector, subselector), err)
	}

	var svcEndpointSlices []discovery_v1.EndpointSlice
	svcEndpointSlices, err = nsi.endpointSliceLister.GetServiceEndpointSlices(svc)
	if err != nil {
		nl.Debugf(lbc.Logger, "Error getting endpointslices for service %s from the cache: %v", svc.Name, err)
		return nil, err
	}

	endps = getEndpointsFromEndpointSlicesForSubselectedPods(targetPort, pods, svcEndpointSlices)
	return endps, nil
}

// selectEndpointSlicesForPort returns EndpointSlices that match given targetPort.
func selectEndpointSlicesForPort(targetPort int32, esx []discovery_v1.EndpointSlice) []discovery_v1.EndpointSlice {
	eps := make([]discovery_v1.EndpointSlice, 0, len(esx))
	for _, es := range esx {
		for _, p := range es.Ports {
			if p.Port == nil {
				continue
			}
			if *p.Port == targetPort {
				eps = append(eps, es)
			}
		}
	}
	return eps
}

// filterReadyEndpoinsFrom returns ready Endpoints from given EndpointSlices.
func filterReadyEndpointsFrom(esx []discovery_v1.EndpointSlice) []discovery_v1.Endpoint {
	epx := make([]discovery_v1.Endpoint, 0, len(esx))
	for _, es := range esx {
		for _, e := range es.Endpoints {
			if e.Conditions.Ready == nil {
				continue
			}
			if *e.Conditions.Ready {
				epx = append(epx, e)
			}
		}
	}
	return epx
}

func getEndpointsFromEndpointSlicesForSubselectedPods(targetPort int32, pods []*api_v1.Pod, svcEndpointSlices []discovery_v1.EndpointSlice) (podEndpoints []podEndpoint) {
	// Match ready endpoints IP ddresses with Pod's IP. If they match create a new podEnpoint.
	makePodEndpoints := func(pods []*api_v1.Pod, endpoints []discovery_v1.Endpoint) []podEndpoint {
		endpointSet := make(map[podEndpoint]struct{})

		for _, pod := range pods {
			for _, endpoint := range endpoints {
				for _, address := range endpoint.Addresses {
					if pod.Status.PodIP == address {
						addr := ipv6SafeAddrPort(pod.Status.PodIP, targetPort)
						ownerType, ownerName := getPodOwnerTypeAndName(pod)
						podEndpoint := podEndpoint{
							Address: addr,
							PodName: getPodName(endpoint.TargetRef),
							MeshPodOwner: configs.MeshPodOwner{
								OwnerType: ownerType,
								OwnerName: ownerName,
							},
						}
						endpointSet[podEndpoint] = struct{}{}
					}
				}
			}
		}
		return slices.Collect(maps.Keys(endpointSet))
	}

	return makePodEndpoints(pods, filterReadyEndpointsFrom(selectEndpointSlicesForPort(targetPort, svcEndpointSlices)))
}

func ipv6SafeAddrPort(addr string, port int32) string {
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}

func getPodName(pod *api_v1.ObjectReference) string {
	if pod != nil {
		return pod.Name
	}
	return ""
}

func (lbc *LoadBalancerController) getHealthChecksForIngressBackend(backend *networking.IngressBackend, namespace string) *api_v1.Probe {
	svc, err := lbc.getServiceForIngressBackend(backend, namespace)
	if err != nil {
		nl.Debugf(lbc.Logger, "Error getting service %v: %v", backend.Service.Name, err)
		return nil
	}
	svcPort := lbc.getServicePortForIngressPort(backend.Service.Port, svc)
	if svcPort == nil {
		return nil
	}
	var pods []*api_v1.Pod
	nsi := lbc.getNamespacedInformer(svc.Namespace)
	pods, err = nsi.podLister.ListByNamespace(svc.Namespace, labels.Set(svc.Spec.Selector).AsSelector())
	if err != nil {
		nl.Debugf(lbc.Logger, "Error fetching pods for namespace %v: %v", svc.Namespace, err)
		return nil
	}
	return findProbeForPods(pods, svcPort)
}

func findProbeForPods(pods []*api_v1.Pod, svcPort *api_v1.ServicePort) *api_v1.Probe {
	if len(pods) > 0 {
		pod := pods[0]
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if compareContainerPortAndServicePort(port, *svcPort) {
					// only http ReadinessProbes are useful for us
					if container.ReadinessProbe != nil && container.ReadinessProbe.ProbeHandler.HTTPGet != nil && container.ReadinessProbe.PeriodSeconds > 0 {
						return container.ReadinessProbe
					}
				}
			}
		}
	}
	return nil
}

func compareContainerPortAndServicePort(containerPort api_v1.ContainerPort, svcPort api_v1.ServicePort) bool {
	targetPort := svcPort.TargetPort
	if (targetPort == intstr.IntOrString{}) {
		return svcPort.Port > 0 && svcPort.Port == containerPort.ContainerPort
	}
	switch targetPort.Type {
	case intstr.String:
		return targetPort.StrVal == containerPort.Name && svcPort.Protocol == containerPort.Protocol
	case intstr.Int:
		return targetPort.IntVal > 0 && targetPort.IntVal == containerPort.ContainerPort
	}
	return false
}

func (lbc *LoadBalancerController) getExternalEndpointsForIngressBackend(backend *networking.IngressBackend, svc *api_v1.Service) []podEndpoint {
	address := fmt.Sprintf("%s:%d", svc.Spec.ExternalName, backend.Service.Port.Number)
	endpoints := []podEndpoint{
		{
			Address: address,
			PodName: "",
		},
	}
	return endpoints
}

func (lbc *LoadBalancerController) getEndpointsForIngressBackend(backend *networking.IngressBackend, svc *api_v1.Service) (result []podEndpoint, isExternal bool, err error) {
	var endpointSlices []discovery_v1.EndpointSlice
	endpointSlices, err = lbc.getNamespacedInformer(svc.Namespace).endpointSliceLister.GetServiceEndpointSlices(svc)
	if err != nil {
		if svc.Spec.Type == api_v1.ServiceTypeExternalName {
			if !lbc.isNginxPlus {
				return nil, false, fmt.Errorf("type ExternalName Services feature is only available in NGINX Plus")
			}
			result = lbc.getExternalEndpointsForIngressBackend(backend, svc)
			return result, true, nil
		}
		nl.Debugf(lbc.Logger, "Error getting endpoints for service %s from the cache: %v", svc.Name, err)
		return nil, false, err
	}

	result, err = lbc.getEndpointsForPortFromEndpointSlices(endpointSlices, backend.Service.Port, svc)
	if err != nil {
		nl.Debugf(lbc.Logger, "Error getting endpointslices for service %s port %v: %v", svc.Name, configs.GetBackendPortAsString(backend.Service.Port), err)
		return nil, false, err
	}
	return result, false, nil
}

func (lbc *LoadBalancerController) getEndpointsForPortFromEndpointSlices(endpointSlices []discovery_v1.EndpointSlice, backendPort networking.ServiceBackendPort, svc *api_v1.Service) ([]podEndpoint, error) {
	var targetPort int32
	var err error

	for _, port := range svc.Spec.Ports {
		if (backendPort.Name == "" && port.Port == backendPort.Number) || port.Name == backendPort.Name {
			targetPort, err = lbc.getTargetPort(port, svc)
			if err != nil {
				return nil, fmt.Errorf("error determining target port for port %v in Ingress: %w", backendPort, err)
			}
			break
		}
	}

	if targetPort == 0 {
		return nil, fmt.Errorf("no port %v in service %s", backendPort, svc.Name)
	}

	makePodEndpoints := func(port int32, epx []discovery_v1.Endpoint) []podEndpoint {
		endpointSet := make(map[podEndpoint]struct{})

		for _, ep := range epx {
			for _, addr := range ep.Addresses {
				address := ipv6SafeAddrPort(addr, port)
				podEndpoint := podEndpoint{
					Address: address,
				}
				if ep.TargetRef != nil {
					parentType, parentName := lbc.getPodOwnerTypeAndNameFromAddress(ep.TargetRef.Namespace, ep.TargetRef.Name)
					podEndpoint.OwnerType = parentType
					podEndpoint.OwnerName = parentName
					podEndpoint.PodName = ep.TargetRef.Name
				}
				endpointSet[podEndpoint] = struct{}{}
			}
		}
		return slices.Collect(maps.Keys(endpointSet))
	}

	endpoints := makePodEndpoints(targetPort, filterReadyEndpointsFrom(selectEndpointSlicesForPort(targetPort, endpointSlices)))
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpointslices for target port %v in service %s", targetPort, svc.Name)
	}
	return endpoints, nil
}

func (lbc *LoadBalancerController) getPodOwnerTypeAndNameFromAddress(ns, name string) (parentType, parentName string) {
	var obj interface{}
	var exists bool
	var err error

	obj, exists, err = lbc.getNamespacedInformer(ns).podLister.GetByKey(fmt.Sprintf("%s/%s", ns, name))
	if err != nil {
		nl.Warnf(lbc.Logger, "could not get pod by key %s/%s: %v", ns, name, err)
		return "", ""
	}
	if exists {
		pod := obj.(*api_v1.Pod)
		return getPodOwnerTypeAndName(pod)
	}
	return "", ""
}

func getPodOwnerTypeAndName(pod *api_v1.Pod) (parentType, parentName string) {
	parentType = "deployment"
	for _, owner := range pod.GetOwnerReferences() {
		parentName = owner.Name
		if owner.Controller != nil && *owner.Controller {
			if owner.Kind == "StatefulSet" || owner.Kind == "DaemonSet" {
				parentType = strings.ToLower(owner.Kind)
			}
			if owner.Kind == "ReplicaSet" && strings.HasSuffix(owner.Name, pod.Labels["pod-template-hash"]) {
				parentName = strings.TrimSuffix(owner.Name, "-"+pod.Labels["pod-template-hash"])
			}
		}
	}
	return parentType, parentName
}

func (lbc *LoadBalancerController) getServicePortForIngressPort(backendPort networking.ServiceBackendPort, svc *api_v1.Service) *api_v1.ServicePort {
	for _, port := range svc.Spec.Ports {
		if (backendPort.Name == "" && port.Port == backendPort.Number) || port.Name == backendPort.Name {
			return &port
		}
	}
	return nil
}

func (lbc *LoadBalancerController) getTargetPort(svcPort api_v1.ServicePort, svc *api_v1.Service) (int32, error) {
	if (svcPort.TargetPort == intstr.IntOrString{}) {
		return svcPort.Port, nil
	}

	if svcPort.TargetPort.Type == intstr.Int {
		return int32(svcPort.TargetPort.IntValue()), nil
	}

	var pods []*api_v1.Pod
	var err error
	pods, err = lbc.getNamespacedInformer(svc.Namespace).podLister.ListByNamespace(svc.Namespace, labels.Set(svc.Spec.Selector).AsSelector())
	if err != nil {
		return 0, fmt.Errorf("error getting pod information: %w", err)
	}

	if len(pods) == 0 {
		return 0, fmt.Errorf("no pods of service %s", svc.Name)
	}

	pod := pods[0]

	portNum, err := findPort(pod, svcPort)
	if err != nil {
		return 0, fmt.Errorf("error finding named port %v in pod %s: %w", svcPort, pod.Name, err)
	}

	return portNum, nil
}

func (lbc *LoadBalancerController) getServiceForUpstream(namespace string, upstreamService string, upstreamPort uint16) (*api_v1.Service, error) {
	backend := &networking.IngressBackend{
		Service: &networking.IngressServiceBackend{
			Name: upstreamService,
			Port: networking.ServiceBackendPort{
				Number: int32(upstreamPort),
			},
		},
	}
	return lbc.getServiceForIngressBackend(backend, namespace)
}

func (lbc *LoadBalancerController) getServiceForIngressBackend(backend *networking.IngressBackend, namespace string) (*api_v1.Service, error) {
	svcKey := namespace + "/" + backend.Service.Name
	var svcObj interface{}
	var svcExists bool
	var err error

	svcObj, svcExists, err = lbc.getNamespacedInformer(namespace).svcLister.GetByKey(svcKey)
	if err != nil {
		return nil, err
	}

	if svcExists {
		return svcObj.(*api_v1.Service), nil
	}

	return nil, fmt.Errorf("service %s doesn't exist", svcKey)
}

// HasCorrectIngressClass checks if resource ingress class annotation (if exists) or ingressClass string for VS/VSR is matching with Ingress Controller class
func (lbc *LoadBalancerController) HasCorrectIngressClass(obj interface{}) bool {
	var class string
	switch obj := obj.(type) {
	case *conf_v1.VirtualServer:
		class = obj.Spec.IngressClass
	case *conf_v1.VirtualServerRoute:
		class = obj.Spec.IngressClass
	case *conf_v1.TransportServer:
		class = obj.Spec.IngressClass
	case *conf_v1.Policy:
		class = obj.Spec.IngressClass
	case *networking.Ingress:
		class = obj.Annotations[ingressClassKey]
		if class == "" && obj.Spec.IngressClassName != nil {
			class = *obj.Spec.IngressClassName
		} else if class != "" {
			// the annotation takes precedence over the field
			nl.Warnf(lbc.Logger, "Using the DEPRECATED annotation 'kubernetes.io/ingress.class'. The 'ingressClassName' field will be ignored.")
		}
		return class == lbc.ingressClass

	default:
		return false
	}

	return class == lbc.ingressClass || class == ""
}

// isHealthCheckEnabled checks if health checks are enabled so we can only query pods if enabled.
func (lbc *LoadBalancerController) isHealthCheckEnabled(ing *networking.Ingress) bool {
	if healthCheckEnabled, exists, err := configs.GetMapKeyAsBool(ing.Annotations, "nginx.com/health-checks", ing); exists {
		if err != nil {
			nl.Error(lbc.Logger, err)
		}
		return healthCheckEnabled
	}
	return false
}

func formatWarningMessages(w []string) string {
	return strings.Join(w, "; ")
}

func (lbc *LoadBalancerController) syncSVIDRotation(svidResponse *workloadapi.X509Context) {
	lbc.syncLock.Lock()
	defer lbc.syncLock.Unlock()
	nl.Debug(lbc.Logger, "Rotating SPIFFE Certificates")
	err := lbc.configurator.AddOrUpdateSpiffeCerts(svidResponse)
	if err != nil {
		nl.Errorf(lbc.Logger, "failed to rotate SPIFFE certificates: %v", err)
	}
}

// IsNginxReady returns ready status of NGINX
func (lbc *LoadBalancerController) IsNginxReady() bool {
	return lbc.isNginxReady
}

func (lbc *LoadBalancerController) addInternalRouteServer() {
	if lbc.internalRoutesEnabled {
		if err := lbc.configurator.AddInternalRouteConfig(); err != nil {
			nl.Warnf(lbc.Logger, "failed to configure internal route server: %v", err)
		}
	}
}

func (lbc *LoadBalancerController) processVSWeightChangesDynamicReload(vsOld *conf_v1.VirtualServer, vsNew *conf_v1.VirtualServer) {
	var weightUpdates []configs.WeightUpdate
	var splitClientsIndex int
	variableNamer := configs.NewVSVariableNamer(vsNew)

	for i, routeNew := range vsNew.Spec.Routes {
		routeOld := vsOld.Spec.Routes[i]
		for j, matchNew := range routeNew.Matches {
			matchOld := routeOld.Matches[j]
			if len(matchNew.Splits) == 2 {
				if matchNew.Splits[0].Weight != matchOld.Splits[0].Weight || matchNew.Splits[1].Weight != matchOld.Splits[1].Weight {
					weightUpdates = append(weightUpdates, configs.WeightUpdate{
						Zone:  variableNamer.GetNameOfKeyvalZoneForSplitClientIndex(splitClientsIndex),
						Key:   variableNamer.GetNameOfKeyvalKeyForSplitClientIndex(splitClientsIndex),
						Value: variableNamer.GetNameOfKeyOfMapForWeights(splitClientsIndex, matchNew.Splits[0].Weight, matchNew.Splits[1].Weight),
					})
				}
				splitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
			} else if len(matchNew.Splits) > 0 {
				splitClientsIndex++
			}
		}
		if len(routeNew.Splits) == 2 {
			if routeNew.Splits[0].Weight != routeOld.Splits[0].Weight || routeNew.Splits[1].Weight != routeOld.Splits[1].Weight {
				weightUpdates = append(weightUpdates, configs.WeightUpdate{
					Zone:  variableNamer.GetNameOfKeyvalZoneForSplitClientIndex(splitClientsIndex),
					Key:   variableNamer.GetNameOfKeyvalKeyForSplitClientIndex(splitClientsIndex),
					Value: variableNamer.GetNameOfKeyOfMapForWeights(splitClientsIndex, routeNew.Splits[0].Weight, routeNew.Splits[1].Weight),
				})
				splitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
			}
			splitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
		} else if len(routeNew.Splits) > 0 {
			splitClientsIndex++
		}
	}

	if len(weightUpdates) == 0 {
		return
	}

	if vsOld.Status.State == conf_v1.StateInvalid {
		lbc.AddSyncQueue(vsNew)
		return
	}

	if lbc.haltIfVSConfigInvalid(vsNew) {
		return
	}

	for _, weight := range weightUpdates {
		lbc.configurator.UpsertSplitClientsKeyVal(weight.Zone, weight.Key, weight.Value)
	}
}

func (lbc *LoadBalancerController) processVSRWeightChangesDynamicReload(vsrOld *conf_v1.VirtualServerRoute, vsrNew *conf_v1.VirtualServerRoute) {
	if !lbc.vsrHasWeightChanges(vsrOld, vsrNew) {
		return
	}

	if vsrOld.Status.State == conf_v1.StateInvalid {
		changes, problems := lbc.configuration.AddOrUpdateVirtualServerRoute(vsrNew)
		lbc.processProblems(problems)
		lbc.processChanges(changes)
		return
	}

	halt, vsEx := lbc.haltIfVSRConfigInvalid(vsrNew)
	if vsEx == nil {
		return
	}

	var weightUpdates []configs.WeightUpdate

	splitClientsIndex := lbc.getStartingSplitClientsIndex(vsrNew, vsEx)

	variableNamer := configs.NewVSVariableNamer(vsEx.VirtualServer)

	for i, routeNew := range vsrNew.Spec.Subroutes {
		routeOld := vsrOld.Spec.Subroutes[i]
		for j, matchNew := range routeNew.Matches {
			matchOld := routeOld.Matches[j]
			if len(matchNew.Splits) == 2 {
				if matchNew.Splits[0].Weight != matchOld.Splits[0].Weight || matchNew.Splits[1].Weight != matchOld.Splits[1].Weight {
					weightUpdates = append(weightUpdates, configs.WeightUpdate{
						Zone:  variableNamer.GetNameOfKeyvalZoneForSplitClientIndex(splitClientsIndex),
						Key:   variableNamer.GetNameOfKeyvalKeyForSplitClientIndex(splitClientsIndex),
						Value: variableNamer.GetNameOfKeyOfMapForWeights(splitClientsIndex, matchNew.Splits[0].Weight, matchNew.Splits[1].Weight),
					})
				}
				splitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
			} else if len(matchNew.Splits) > 0 {
				splitClientsIndex++
			}
		}
		if len(routeNew.Splits) == 2 {
			if routeNew.Splits[0].Weight != routeOld.Splits[0].Weight || routeNew.Splits[1].Weight != routeOld.Splits[1].Weight {
				weightUpdates = append(weightUpdates, configs.WeightUpdate{
					Zone:  variableNamer.GetNameOfKeyvalZoneForSplitClientIndex(splitClientsIndex),
					Key:   variableNamer.GetNameOfKeyvalKeyForSplitClientIndex(splitClientsIndex),
					Value: variableNamer.GetNameOfKeyOfMapForWeights(splitClientsIndex, routeNew.Splits[0].Weight, routeNew.Splits[1].Weight),
				})
			}
			splitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
		} else if len(routeNew.Splits) > 0 {
			splitClientsIndex++
		}
	}

	if halt {
		return
	}

	for _, weight := range weightUpdates {
		lbc.configurator.UpsertSplitClientsKeyVal(weight.Zone, weight.Key, weight.Value)
	}
}

func (lbc *LoadBalancerController) getStartingSplitClientsIndex(vsr *conf_v1.VirtualServerRoute, vsEx *configs.VirtualServerEx) int {
	var startingSplitClientsIndex int

	for _, r := range vsEx.VirtualServer.Spec.Routes {
		for _, match := range r.Matches {
			if len(match.Splits) == 2 {
				startingSplitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
			} else if len(match.Splits) > 0 {
				startingSplitClientsIndex++
			}
		}
		if len(r.Splits) == 2 {
			startingSplitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
		} else if len(r.Splits) > 0 {
			startingSplitClientsIndex++
		}

	}

	for _, vsRoute := range vsEx.VirtualServerRoutes {
		if vsRoute.Name == vsr.Name {
			return startingSplitClientsIndex
		}
		for _, r := range vsRoute.Spec.Subroutes {
			for _, match := range r.Matches {
				if len(match.Splits) == 2 {
					startingSplitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
				} else if len(match.Splits) > 0 {
					startingSplitClientsIndex++
				}
			}
			if len(r.Splits) == 2 {
				startingSplitClientsIndex += splitClientAmountWhenWeightChangesDynamicReload
			} else if len(r.Splits) > 0 {
				startingSplitClientsIndex++
			}
		}
	}

	return startingSplitClientsIndex
}

func (lbc *LoadBalancerController) haltIfVSConfigInvalid(vsNew *conf_v1.VirtualServer) bool {
	lbc.configuration.lock.Lock()
	defer lbc.configuration.lock.Unlock()
	key := getResourceKey(&vsNew.ObjectMeta)

	validationError := lbc.configuration.virtualServerValidator.ValidateVirtualServer(vsNew)
	if validationError != nil {
		delete(lbc.configuration.virtualServers, key)
	} else {
		lbc.configuration.virtualServers[key] = vsNew
	}

	changes, problems := lbc.configuration.rebuildHosts()

	if validationError != nil {

		kind := getResourceKeyWithKind(virtualServerKind, &vsNew.ObjectMeta)
		for i := range changes {
			k := changes[i].Resource.GetKeyWithKind()

			if k == kind {
				changes[i].Error = validationError.Error()
			}
		}
		p := ConfigurationProblem{
			Object:  vsNew,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: fmt.Sprintf("VirtualServer %s was rejected with error: %s", getResourceKey(&vsNew.ObjectMeta), validationError.Error()),
		}
		problems = append(problems, p)
	}

	if len(problems) > 0 {
		lbc.processProblems(problems)
	}

	if len(changes) == 0 {
		return true
	}

	for _, c := range changes {
		if c.Op == AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				lbc.updateVirtualServerStatusAndEvents(impl, configs.Warnings{}, nil)
			}
		} else if c.Op == Delete {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				key := getResourceKey(&impl.VirtualServer.ObjectMeta)

				deleteErr := lbc.configurator.DeleteVirtualServer(key, false)
				if deleteErr != nil {
					nl.Errorf(lbc.Logger, "Error when deleting configuration for VirtualServer %v: %v", key, deleteErr)
				}

				var vsExists bool
				var err error

				ns, _, _ := cache.SplitMetaNamespaceKey(key)
				_, vsExists, err = lbc.getNamespacedInformer(ns).virtualServerLister.GetByKey(key)
				if err != nil {
					nl.Errorf(lbc.Logger, "Error when getting VirtualServer for %v: %v", key, err)
				}

				if vsExists {
					lbc.UpdateVirtualServerStatusAndEventsOnDelete(impl, c.Error, deleteErr)
				}
			}
		}
	}

	lbc.configuration.virtualServers[key] = vsNew
	return len(problems) > 0
}

func (lbc *LoadBalancerController) haltIfVSRConfigInvalid(vsrNew *conf_v1.VirtualServerRoute) (bool, *configs.VirtualServerEx) {
	lbc.configuration.lock.Lock()
	defer lbc.configuration.lock.Unlock()
	key := getResourceKey(&vsrNew.ObjectMeta)
	var vsEx *configs.VirtualServerEx

	validationError := lbc.configuration.virtualServerValidator.ValidateVirtualServerRoute(vsrNew)
	if validationError != nil {
		lbc.AddSyncQueue(vsrNew)
		return true, nil
	} else {
		lbc.configuration.virtualServerRoutes[key] = vsrNew
	}

	changes, _ := lbc.configuration.rebuildHosts()

	if len(changes) == 0 {
		return true, nil
	}

	for _, c := range changes {
		if c.Op == AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				vsEx = lbc.createVirtualServerEx(impl.VirtualServer, impl.VirtualServerRoutes)
				lbc.updateVirtualServerStatusAndEvents(impl, configs.Warnings{}, nil)
			}
		}
	}

	if vsEx == nil {
		nl.Debugf(lbc.Logger, "VirtualServerRoute %s does not have a corresponding VirtualServer", vsrNew.Name)
		return true, nil
	}

	lbc.configuration.virtualServerRoutes[key] = vsrNew
	return false, vsEx
}

func (lbc *LoadBalancerController) vsrHasWeightChanges(vsrOld *conf_v1.VirtualServerRoute, vsrNew *conf_v1.VirtualServerRoute) bool {
	for i, routeNew := range vsrNew.Spec.Subroutes {
		routeOld := vsrOld.Spec.Subroutes[i]
		for j, matchNew := range routeNew.Matches {
			matchOld := routeOld.Matches[j]
			if len(matchNew.Splits) == 2 && (matchNew.Splits[0].Weight != matchOld.Splits[0].Weight || matchNew.Splits[1].Weight != matchOld.Splits[1].Weight) {
				return true
			}
		}
		if len(routeNew.Splits) == 2 && (routeNew.Splits[0].Weight != routeOld.Splits[0].Weight || routeNew.Splits[1].Weight != routeOld.Splits[1].Weight) {
			return true
		}
	}
	return false
}
