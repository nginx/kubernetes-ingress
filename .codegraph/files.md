# Files

Per-package file index with top-level exported symbols. For wider context (architecture, layers, pipeline) load the `nic-structure` skill.

## github.com/nginx/kubernetes-ingress/internal/certmanager

_Package certmanager provides a controller for creating and managing certificates for VS resources._

- [internal/certmanager/cm_controller.go](../internal/certmanager/cm_controller.go) — (CmController).AddNewNamespacedInformer, (CmController).RemoveNamespacedInformer, (CmController).Run, BuildOpts, CmController, CmOpts, ControllerName, NewCmController
- [internal/certmanager/helper.go](../internal/certmanager/helper.go)
- [internal/certmanager/sync.go](../internal/certmanager/sync.go) — SyncFn, SyncFnFor

## github.com/nginx/kubernetes-ingress/internal/certmanager/test_files


## github.com/nginx/kubernetes-ingress/internal/common_cluster_info

- [internal/common_cluster_info/common_cluster_info.go](../internal/common_cluster_info/common_cluster_info.go) — GetClusterID, GetInstallationID, GetInstallationName, GetNodeCount

## github.com/nginx/kubernetes-ingress/internal/configs

- [internal/configs/annotations.go](../internal/configs/annotations.go) — AddHeaderAnnotation, AddHeaderInheritAnnotation, AppProtectDosProtectedAnnotation, AppProtectLogConfAnnotation, AppProtectLogConfDstAnnotation, AppProtectPolicyAnnotation, BasicAuthSecretAnnotation, HTTPRedirectCodeAnnotation, JWTKeyAnnotation, JWTLoginURLAnnotation, JWTRealmAnnotation, JWTTokenAnnotation, …
- [internal/configs/bundle_validator.go](../internal/configs/bundle_validator.go)
- [internal/configs/common.go](../internal/configs/common.go)
- [internal/configs/config_params.go](../internal/configs/config_params.go) — ConfigParams, GlobalConfigParams, Listener, MGMTConfigParams, MGMTSecrets, NewDefaultConfigParams, NewDefaultMGMTConfigParams, OIDC, StaticConfigParams, ZoneSync
- [internal/configs/configmaps.go](../internal/configs/configmaps.go) — GenerateNginxMainConfig, ParseConfigMap, ParseHTTPRedirectCode, ParseMGMTConfigMap
- [internal/configs/configurator.go](../internal/configs/configurator.go) — (Configurator).AddInternalRouteConfig, (Configurator).AddOrUpdateAppProtectResource, (Configurator).AddOrUpdateCASecret, (Configurator).AddOrUpdateDHParam, (Configurator).AddOrUpdateIngress, (Configurator).AddOrUpdateIngresses, (Configurator).AddOrUpdateLicenseSecret, (Configurator).AddOrUpdateMGMTClientAuthSecret, (Configurator).AddOrUpdateMergeableIngress, (Configurator).AddOrUpdateResources, (Configurator).AddOrUpdateResourcesThatUseDosProtected, (Configurator).AddOrUpdateSecret, …
- [internal/configs/dos.go](../internal/configs/dos.go)
- [internal/configs/ingress.go](../internal/configs/ingress.go) — (IngressEx).String, AppProtectLog, AppProtectResources, DosEx, GetBackendPortAsString, IngressEx, JWTKey, MergeableIngresses, NginxCfgParams
- [internal/configs/parsing_helpers.go](../internal/configs/parsing_helpers.go) — GetMapKeyAsBool, GetMapKeyAsInt, GetMapKeyAsInt64, GetMapKeyAsStringSlice, GetMapKeyAsUint64, OffsetFmt, ParseAddHeaderInherit, ParseBool, ParseFloat64, ParseInt, ParseInt64, ParseLBMethod, …
- [internal/configs/policy.go](../internal/configs/policy.go) — DefaultSigninRedirectBasePath, IsPolicySupportedOnIngress
- [internal/configs/transportserver.go](../internal/configs/transportserver.go) — (TransportServerEx).String, TransportServerEx
- [internal/configs/validation_results.go](../internal/configs/validation_results.go)
- [internal/configs/virtualserver.go](../internal/configs/virtualserver.go) — (VariableNamer).GetNameForSplitClientVariable, (VariableNamer).GetNameForVariableForMatchesRouteMainMap, (VariableNamer).GetNameForVariableForMatchesRouteMap, (VariableNamer).GetNameOfKeyOfMapForWeights, (VariableNamer).GetNameOfKeyvalForSplitClientIndex, (VariableNamer).GetNameOfKeyvalKeyForSplitClientIndex, (VariableNamer).GetNameOfKeyvalZoneForSplitClientIndex, (VariableNamer).GetNameOfMapForSplitClientIndex, (VariableNamer).GetNameOfSplitClientsForWeights, (VirtualServerEx).String, (upstreamNamer).GetNameForUpstream, (upstreamNamer).GetNameForUpstreamFromAction, …
- [internal/configs/warnings.go](../internal/configs/warnings.go) — (Warnings).Add, (Warnings).AddWarning, (Warnings).AddWarningf, MakeResourceErrorKey, ResourceErrors, Warnings

## github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers

_Package commonhelpers contains template helpers used in v1 and v2_

- [internal/configs/commonhelpers/common_template_helpers.go](../internal/configs/commonhelpers/common_template_helpers.go) — BoolToPointerBool, MakeOnOffFromBool, MakeSecretPath

## github.com/nginx/kubernetes-ingress/internal/configs/version1

- [internal/configs/version1/config.go](../internal/configs/version1/config.go) — BasicAuth, HealthCheck, Ingress, IngressNginxConfig, JWTAuth, JWTRedirectLocation, LimitReq, LimitReqZone, Location, MGMTConfig, MainConfig, NewUpstreamWithDefaultServer, …
- [internal/configs/version1/header_parsing_helper.go](../internal/configs/version1/header_parsing_helper.go) — MergeProxySetHeaders, ParseAddHeaders, ParseProxySetHeaders, ValidateAddHeaderName, ValidateAddHeaderValue
- [internal/configs/version1/template_executor.go](../internal/configs/version1/template_executor.go) — (TemplateExecutor).ExecuteIngressConfigTemplate, (TemplateExecutor).ExecuteMainConfigTemplate, (TemplateExecutor).UpdateIngressTemplate, (TemplateExecutor).UpdateMainTemplate, (TemplateExecutor).UseOriginalIngressTemplate, (TemplateExecutor).UseOriginalMainTemplate, NewTemplateExecutor, TemplateExecutor
- [internal/configs/version1/template_helper.go](../internal/configs/version1/template_helper.go)

## github.com/nginx/kubernetes-ingress/internal/configs/version2

- [internal/configs/version2/http.go](../internal/configs/version2/http.go) — (LimitReq).String, (LimitReqOptions).String, (LimitReqZone).String, (Map).String, APIKey, AddHeader, AuthJWTClaimSet, AuthURI, BasicAuth, Cache, CacheZone, Distribution, …
- [internal/configs/version2/stream.go](../internal/configs/version2/stream.go) — Match, StreamHealthCheck, StreamSSL, StreamServer, StreamUpstream, StreamUpstreamBackupServer, StreamUpstreamServer, TLSPassthroughHostsConfig, TransportServerConfig
- [internal/configs/version2/template_executor.go](../internal/configs/version2/template_executor.go) — (TemplateExecutor).ExecuteOIDCTemplate, (TemplateExecutor).ExecuteTLSPassthroughHostsTemplate, (TemplateExecutor).ExecuteTransportServerTemplate, (TemplateExecutor).ExecuteVirtualServerTemplate, (TemplateExecutor).UpdateTransportServerTemplate, (TemplateExecutor).UpdateVirtualServerTemplate, (TemplateExecutor).UseOriginalTStemplate, (TemplateExecutor).UseOriginalVStemplate, NewTemplateExecutor, TemplateExecutor
- [internal/configs/version2/template_helper.go](../internal/configs/version2/template_helper.go)

## github.com/nginx/kubernetes-ingress/internal/externaldns

_Package externaldns implements External DNS controller for Virtual Server._

- [internal/externaldns/controller.go](../internal/externaldns/controller.go) — (ExtDNSController).AddNewNamespacedInformer, (ExtDNSController).RemoveNamespacedInformer, (ExtDNSController).Run, BuildOpts, ControllerName, ExtDNSController, ExtDNSOpts, NewController
- [internal/externaldns/doc.go](../internal/externaldns/doc.go)
- [internal/externaldns/handlers.go](../internal/externaldns/handlers.go) — (BlockingEventHandler).Enqueue, (BlockingEventHandler).OnAdd, (BlockingEventHandler).OnDelete, (BlockingEventHandler).OnUpdate, (QueuingEventHandler).Enqueue, (QueuingEventHandler).OnAdd, (QueuingEventHandler).OnDelete, (QueuingEventHandler).OnUpdate, BlockingEventHandler, DefaultItemBasedRateLimiter, KeyFunc, QueuingEventHandler
- [internal/externaldns/sync.go](../internal/externaldns/sync.go) — DNSTarget, SyncFn, SyncFnFor

## github.com/nginx/kubernetes-ingress/internal/healthcheck

_Package healthcheck provides primitives for running deep healtcheck service._

- [internal/healthcheck/healthcheck.go](../internal/healthcheck/healthcheck.go) — (HealthServer).ListenAndServe, (HealthServer).Shutdown, (HealthServer).StreamStats, (HealthServer).UpstreamStats, HealthServer, HostStats, NewHealthServer, RunHealthCheck

## github.com/nginx/kubernetes-ingress/internal/k8s

- [internal/k8s/appprotect_dos.go](../internal/k8s/appprotect_dos.go)
- [internal/k8s/appprotect_waf.go](../internal/k8s/appprotect_waf.go)
- [internal/k8s/configmap.go](../internal/k8s/configmap.go)
- [internal/k8s/configuration.go](../internal/k8s/configuration.go) — (Configuration).AddOrUpdateGlobalConfiguration, (Configuration).AddOrUpdateIngress, (Configuration).AddOrUpdateTransportServer, (Configuration).AddOrUpdateVirtualServer, (Configuration).AddOrUpdateVirtualServerRoute, (Configuration).CompleteStartup, (Configuration).DeleteGlobalConfiguration, (Configuration).DeleteIngress, (Configuration).DeletePolicyServiceRef, (Configuration).DeleteTransportServer, (Configuration).DeleteVirtualServer, (Configuration).DeleteVirtualServerRoute, …
- [internal/k8s/controller.go](../internal/k8s/controller.go) — (LoadBalancerController).AddSyncQueue, (LoadBalancerController).HasCorrectIngressClass, (LoadBalancerController).IsExternalServiceForStatus, (LoadBalancerController).IsExternalServiceKeyForStatus, (LoadBalancerController).IsNginxReady, (LoadBalancerController).Run, (LoadBalancerController).Stop, (LoadBalancerController).UpdateIngressStatusAndEventsOnDelete, (LoadBalancerController).UpdateVirtualServerStatusAndEventsOnDelete, IngressControllerName, LoadBalancerController, NewLoadBalancerController, …
- [internal/k8s/endpoint_slice.go](../internal/k8s/endpoint_slice.go)
- [internal/k8s/global_configuration.go](../internal/k8s/global_configuration.go)
- [internal/k8s/handlers.go](../internal/k8s/handlers.go)
- [internal/k8s/ingress_link.go](../internal/k8s/ingress_link.go)
- [internal/k8s/leader.go](../internal/k8s/leader.go)
- [internal/k8s/namespace.go](../internal/k8s/namespace.go)
- [internal/k8s/policy.go](../internal/k8s/policy.go)
- [internal/k8s/reference_checkers.go](../internal/k8s/reference_checkers.go) — (appProtectResourceReferenceChecker).IsReferencedByIngress, (appProtectResourceReferenceChecker).IsReferencedByMinion, (appProtectResourceReferenceChecker).IsReferencedByTransportServer, (appProtectResourceReferenceChecker).IsReferencedByVirtualServer, (appProtectResourceReferenceChecker).IsReferencedByVirtualServerRoute, (dosResourceReferenceChecker).IsReferencedByIngress, (dosResourceReferenceChecker).IsReferencedByMinion, (dosResourceReferenceChecker).IsReferencedByTransportServer, (dosResourceReferenceChecker).IsReferencedByVirtualServer, (dosResourceReferenceChecker).IsReferencedByVirtualServerRoute, (policyReferenceChecker).IsReferencedByIngress, (policyReferenceChecker).IsReferencedByMinion, …
- [internal/k8s/service.go](../internal/k8s/service.go) — (portSort).Len, (portSort).Less, (portSort).Swap
- [internal/k8s/status.go](../internal/k8s/status.go) — (statusUpdater).BulkUpdateIngressStatus, (statusUpdater).ClearIngressStatus, (statusUpdater).ClearStatusFromExternalService, (statusUpdater).ClearStatusFromIngressLink, (statusUpdater).SaveStatusFromExternalService, (statusUpdater).SaveStatusFromExternalStatus, (statusUpdater).SaveStatusFromIngressLink, (statusUpdater).UpdateExternalEndpointsForResource, (statusUpdater).UpdateExternalEndpointsForResources, (statusUpdater).UpdateIngressStatus, (statusUpdater).UpdatePolicyStatus, (statusUpdater).UpdateTransportServerStatus, …
- [internal/k8s/task_queue.go](../internal/k8s/task_queue.go) — (taskQueue).Enqueue, (taskQueue).Len, (taskQueue).Requeue, (taskQueue).RequeueAfter, (taskQueue).Run, (taskQueue).Shutdown
- [internal/k8s/transport_server.go](../internal/k8s/transport_server.go)
- [internal/k8s/utils.go](../internal/k8s/utils.go) — (indexerToPodLister).ListByNamespace, (storeToConfigMapLister).List, (storeToEndpointSliceLister).GetServiceEndpointSlices, (storeToIngressLister).GetByKeySafe, (storeToIngressLister).List, CreateUniformSelectorsFromController, GetK8sVersion, ParseNamespaceName
- [internal/k8s/validation.go](../internal/k8s/validation.go) — IngressOpts, ValidateEscapedString

## github.com/nginx/kubernetes-ingress/internal/k8s/appprotect

- [internal/k8s/appprotect/app_protect_configuration.go](../internal/k8s/appprotect/app_protect_configuration.go) — (ConfigurationImpl).AddOrUpdateLogConf, (ConfigurationImpl).AddOrUpdatePolicy, (ConfigurationImpl).AddOrUpdateUserSig, (ConfigurationImpl).DeleteLogConf, (ConfigurationImpl).DeletePolicy, (ConfigurationImpl).DeleteUserSig, (ConfigurationImpl).GetAppResource, (FakeConfiguration).AddOrUpdateLogConf, (FakeConfiguration).AddOrUpdatePolicy, (FakeConfiguration).AddOrUpdateUserSig, (FakeConfiguration).DeleteLogConf, (FakeConfiguration).DeletePolicy, …

## github.com/nginx/kubernetes-ingress/internal/k8s/appprotectcommon

- [internal/k8s/appprotectcommon/app_protect_common_resources.go](../internal/k8s/appprotectcommon/app_protect_common_resources.go) — GetNsName, ParseResourceReferenceAnnotation, ParseResourceReferenceAnnotationList

## github.com/nginx/kubernetes-ingress/internal/k8s/appprotectdos

- [internal/k8s/appprotectdos/app_protect_dos_configuration.go](../internal/k8s/appprotectdos/app_protect_dos_configuration.go) — (Configuration).AddOrUpdateDosProtectedResource, (Configuration).AddOrUpdateLogConf, (Configuration).AddOrUpdatePolicy, (Configuration).DeleteLogConf, (Configuration).DeletePolicy, (Configuration).DeleteProtectedResource, (Configuration).GetDosProtectedThatReferencedDosLogConf, (Configuration).GetDosProtectedThatReferencedDosPolicy, (Configuration).GetValidDosEx, AddOrUpdate, Change, Configuration, …

## github.com/nginx/kubernetes-ingress/internal/k8s/policies

- [internal/k8s/policies/policy_refs.go](../internal/k8s/policies/policy_refs.go) — GetPolicyRefsFromAnnotation

## github.com/nginx/kubernetes-ingress/internal/k8s/secrets

- [internal/k8s/secrets/store.go](../internal/k8s/secrets/store.go) — (FakeSecretStore).AddOrUpdateSecret, (FakeSecretStore).DeleteSecret, (FakeSecretStore).GetSecret, (FakeSecretStore).GetSecretReferenceMap, (LocalSecretStore).AddOrUpdateSecret, (LocalSecretStore).DeleteSecret, (LocalSecretStore).GetSecret, (LocalSecretStore).GetSecretReferenceMap, FakeSecretStore, LocalSecretStore, NewEmptyFakeSecretsStore, NewFakeSecretsStore, …
- [internal/k8s/secrets/validation.go](../internal/k8s/secrets/validation.go) — CAKey, ClientSecretKey, HtpasswdFileKey, IsSupportedSecretType, JWTKeyKey, SecretTypeAPIKey, SecretTypeCA, SecretTypeHtpasswd, SecretTypeJWK, SecretTypeLicense, SecretTypeOIDC, ValidateAPIKeySecret, …

## github.com/nginx/kubernetes-ingress/internal/license_reporting

- [internal/license_reporting/license_reporting.go](../internal/license_reporting/license_reporting.go) — (LicenseReporter).Start, LicenseReporter, LicenseReporterConfig, NewLicenseReporter

## github.com/nginx/kubernetes-ingress/internal/logger

- [internal/logger/events.go](../internal/logger/events.go) — EventReasonAddedOrUpdated, EventReasonAddedOrUpdatedWithError, EventReasonAddedOrUpdatedWithWarning, EventReasonBadConfig, EventReasonCreateCertificate, EventReasonCreateDNSEndpoint, EventReasonDeleteCertificate, EventReasonIgnored, EventReasonInvalidValue, EventReasonLicenseExpiry, EventReasonNoIngressMasterFound, EventReasonNoVirtualServerFound, …
- [internal/logger/logger.go](../internal/logger/logger.go) — ContextWithLogger, Debug, Debugf, Error, Errorf, Fatal, Fatalf, Info, Infof, LoggerFromContext, Trace, Tracef, …

## github.com/nginx/kubernetes-ingress/internal/logger/glog

- [internal/logger/glog/handler.go](../internal/logger/glog/handler.go) — (Handler).Enabled, (Handler).Handle, (Handler).WithAttrs, (Handler).WithGroup, Handler, New, Options

## github.com/nginx/kubernetes-ingress/internal/logger/levels

- [internal/logger/levels/levels.go](../internal/logger/levels/levels.go) — LevelDebug, LevelError, LevelFatal, LevelInfo, LevelTrace, LevelWarning

## github.com/nginx/kubernetes-ingress/internal/metadata

- [internal/metadata/metadata.go](../internal/metadata/metadata.go) — (Metadata).CollectAndWrite, Labels, Metadata, NewMetadataReporter

## github.com/nginx/kubernetes-ingress/internal/metrics

- [internal/metrics/listener.go](../internal/metrics/listener.go) — (Server).Home, (Server).ListenAndServe, (Server).Shutdown, NewNginxMetricsClient, RunPrometheusListenerForNginx, RunPrometheusListenerForNginxPlus, Server
- [internal/metrics/syslog_listener.go](../internal/metrics/syslog_listener.go) — (LatencyMetricsListener).Run, (LatencyMetricsListener).Stop, (SyslogFakeListener).Run, (SyslogFakeListener).Stop, LatencyMetricsListener, NewLatencyMetricsListener, NewSyslogFakeServer, SyslogFakeListener, SyslogListener

## github.com/nginx/kubernetes-ingress/internal/metrics/collectors

- [internal/metrics/collectors/collectors.go](../internal/metrics/collectors/collectors.go)
- [internal/metrics/collectors/controller.go](../internal/metrics/collectors/controller.go) — (ControllerFakeCollector).Register, (ControllerFakeCollector).SetIngresses, (ControllerFakeCollector).SetTransportServers, (ControllerFakeCollector).SetVirtualServerRoutes, (ControllerFakeCollector).SetVirtualServers, (ControllerMetricsCollector).Collect, (ControllerMetricsCollector).Describe, (ControllerMetricsCollector).Register, (ControllerMetricsCollector).SetIngresses, (ControllerMetricsCollector).SetTransportServers, (ControllerMetricsCollector).SetVirtualServerRoutes, (ControllerMetricsCollector).SetVirtualServers, …
- [internal/metrics/collectors/latency.go](../internal/metrics/collectors/latency.go) — (LatencyFakeCollector).DeleteMetrics, (LatencyFakeCollector).DeleteUpstreamServerLabels, (LatencyFakeCollector).DeleteUpstreamServerPeerLabels, (LatencyFakeCollector).RecordLatency, (LatencyFakeCollector).Register, (LatencyFakeCollector).UpdateUpstreamServerLabels, (LatencyFakeCollector).UpdateUpstreamServerPeerLabels, (LatencyMetricsCollector).Collect, (LatencyMetricsCollector).DeleteMetrics, (LatencyMetricsCollector).DeleteUpstreamServerLabels, (LatencyMetricsCollector).DeleteUpstreamServerPeerLabels, (LatencyMetricsCollector).Describe, …
- [internal/metrics/collectors/manager.go](../internal/metrics/collectors/manager.go) — (LocalManagerMetricsCollector).Collect, (LocalManagerMetricsCollector).Describe, (LocalManagerMetricsCollector).IncNginxReloadCount, (LocalManagerMetricsCollector).IncNginxReloadErrors, (LocalManagerMetricsCollector).Register, (LocalManagerMetricsCollector).UpdateLastReloadTime, (ManagerFakeCollector).IncNginxReloadCount, (ManagerFakeCollector).IncNginxReloadErrors, (ManagerFakeCollector).Register, (ManagerFakeCollector).UpdateLastReloadTime, LocalManagerMetricsCollector, ManagerCollector, …
- [internal/metrics/collectors/processes.go](../internal/metrics/collectors/processes.go) — (NginxProcessesMetricsCollector).Collect, (NginxProcessesMetricsCollector).Describe, (NginxProcessesMetricsCollector).Register, NewNginxProcessesMetricsCollector, NginxProcessesMetricsCollector
- [internal/metrics/collectors/workqueue.go](../internal/metrics/collectors/workqueue.go) — (WorkQueueMetricsCollector).Collect, (WorkQueueMetricsCollector).Describe, (WorkQueueMetricsCollector).NewAddsMetric, (WorkQueueMetricsCollector).NewDepthMetric, (WorkQueueMetricsCollector).NewLatencyMetric, (WorkQueueMetricsCollector).NewLongestRunningProcessorSecondsMetric, (WorkQueueMetricsCollector).NewRetriesMetric, (WorkQueueMetricsCollector).NewUnfinishedWorkSecondsMetric, (WorkQueueMetricsCollector).NewWorkDurationMetric, (WorkQueueMetricsCollector).Register, (noopMetric).Dec, (noopMetric).Inc, …

## github.com/nginx/kubernetes-ingress/internal/nginx

- [internal/nginx/fake_manager.go](../internal/nginx/fake_manager.go) — (FakeManager).AgentQuit, (FakeManager).AgentStart, (FakeManager).AgentVersion, (FakeManager).AppProtectDosAgentQuit, (FakeManager).AppProtectDosAgentStart, (FakeManager).AppProtectPluginQuit, (FakeManager).AppProtectPluginStart, (FakeManager).ClearAppProtectFolder, (FakeManager).CreateAppProtectResourceFile, (FakeManager).CreateConfig, (FakeManager).CreateDHParam, (FakeManager).CreateMainConfig, …
- [internal/nginx/manager.go](../internal/nginx/manager.go) — (LocalManager).AgentQuit, (LocalManager).AgentStart, (LocalManager).AgentVersion, (LocalManager).AppProtectDosAgentQuit, (LocalManager).AppProtectDosAgentStart, (LocalManager).AppProtectPluginQuit, (LocalManager).AppProtectPluginStart, (LocalManager).ClearAppProtectFolder, (LocalManager).CreateAppProtectResourceFile, (LocalManager).CreateConfig, (LocalManager).CreateDHParam, (LocalManager).CreateMainConfig, …
- [internal/nginx/rollback_manager.go](../internal/nginx/rollback_manager.go) — (ConfigRollbackManager).CreateConfig, (ConfigRollbackManager).CreateMainConfig, (ConfigRollbackManager).CreateStreamConfig, ConfigRollbackManager, NewConfigRollbackManager
- [internal/nginx/utils.go](../internal/nginx/utils.go)
- [internal/nginx/verify.go](../internal/nginx/verify.go) — (verifyClient).GetConfigVersion, (verifyClient).WaitForCorrectVersion, (verifyConfigGenerator).GenerateVersionConfig
- [internal/nginx/version.go](../internal/nginx/version.go) — (Version).Format, (Version).PlusGreaterThanOrEqualTo, (Version).String, ExtractAgentVersionValues, NewVersion, Version

## github.com/nginx/kubernetes-ingress/internal/nsutils

- [internal/nsutils/utils.go](../internal/nsutils/utils.go) — FormatResourceReference, HasNamespace

## github.com/nginx/kubernetes-ingress/internal/telemetry

_Package telemetry provides functionality for collecting and exporting NIC telemetry data._

- [internal/telemetry/cluster.go](../internal/telemetry/cluster.go) — (Collector).AppProtectVersion, (Collector).BuildOS, (Collector).ClusterID, (Collector).ClusterVersion, (Collector).ConfigMapKeys, (Collector).IngressAnnotations, (Collector).IngressClassCount, (Collector).InstallationFlags, (Collector).InstallationID, (Collector).IsPlusEnabled, (Collector).MGMTConfigMapKeys, (Collector).MasterIngressCount, …
- [internal/telemetry/collector.go](../internal/telemetry/collector.go) — (Collector).BuildReport, (Collector).Collect, (Collector).Start, Collector, CollectorConfig, NewCollector, Option, Report, WithExporter
- [internal/telemetry/exporter.go](../internal/telemetry/exporter.go) — (JSONExporter).Export, (StdoutExporter).Export, Data, Exporter, ExporterCfg, JSONExporter, NICResourceCounts, NewExporter, StdoutExporter

## github.com/nginx/kubernetes-ingress/internal/validation

- [internal/validation/data_types.go](../internal/validation/data_types.go) — (SizeUnit).String, BadUnit, BalanceProxiesForUpstreams, BalanceProxyValues, NewSizeWithUnit, SizeGB, SizeKB, SizeMB, SizeUnit
- [internal/validation/validation.go](../internal/validation/validation.go) — URIValidationOption, ValidateHost, ValidatePort, ValidateURI, ValidateUnprivilegedPort, WithAllowedSchemes, WithDefaultScheme, WithUserAllowed

## github.com/nginx/kubernetes-ingress/pkg/apis/configuration

- [pkg/apis/configuration/register.go](../pkg/apis/configuration/register.go) — GroupName

## github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1

_Package v1 is the v1 version of the API._

- [pkg/apis/configuration/v1/doc.go](../pkg/apis/configuration/v1/doc.go)
- [pkg/apis/configuration/v1/register.go](../pkg/apis/configuration/v1/register.go) — AddToScheme, Kind, Resource, SchemeBuilder, SchemeGroupVersion
- [pkg/apis/configuration/v1/types.go](../pkg/apis/configuration/v1/types.go) — APIKey, AccessControl, Action, ActionProxy, ActionRedirect, ActionReturn, AddHeader, BasicAuth, CORS, Cache, CacheConditions, CacheLock, …

## github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation

- [pkg/apis/configuration/validation/appprotect.go](../pkg/apis/configuration/validation/appprotect.go) — ValidateAppProtectLogConf, ValidateAppProtectPolicy, ValidateAppProtectUserSig
- [pkg/apis/configuration/validation/appprotect_common.go](../pkg/apis/configuration/validation/appprotect_common.go) — ValidateAppProtectLogDestination, ValidateRequiredFields, ValidateRequiredSlices
- [pkg/apis/configuration/validation/common.go](../pkg/apis/configuration/validation/common.go) — ValidateEscapedString, ValidateParameter, ValidatePath, ValidateSize
- [pkg/apis/configuration/validation/globalconfiguration.go](../pkg/apis/configuration/validation/globalconfiguration.go) — (GlobalConfigurationValidator).ValidateGlobalConfiguration, GlobalConfigurationValidator, NewGlobalConfigurationValidator
- [pkg/apis/configuration/validation/policy.go](../pkg/apis/configuration/validation/policy.go) — ContainsDangerousChars, PolicyValidationConfig, ValidatePolicy
- [pkg/apis/configuration/validation/transportserver.go](../pkg/apis/configuration/validation/transportserver.go) — (TransportServerValidator).ValidateTransportServer, NewTransportServerValidator, TransportServerValidator
- [pkg/apis/configuration/validation/virtualserver.go](../pkg/apis/configuration/validation/virtualserver.go) — (VirtualServerValidator).BalanceUpstreamProxies, (VirtualServerValidator).BalanceUpstreamProxiesForRoute, (VirtualServerValidator).ValidateVirtualServer, (VirtualServerValidator).ValidateVirtualServerRoute, (VirtualServerValidator).ValidateVirtualServerRouteForVirtualServer, IsCertManagerEnabled, IsDirectiveAutoadjustEnabled, IsDosEnabled, IsExternalDNSEnabled, IsPlus, NewVirtualServerValidator, NormalizePath, …

## github.com/nginx/kubernetes-ingress/pkg/apis/dos

- [pkg/apis/dos/register.go](../pkg/apis/dos/register.go) — GroupName

## github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1

_Package v1beta1 is the v1beta1 version of the API._

- [pkg/apis/dos/v1beta1/doc.go](../pkg/apis/dos/v1beta1/doc.go)
- [pkg/apis/dos/v1beta1/register.go](../pkg/apis/dos/v1beta1/register.go) — AddToScheme, Kind, Resource, SchemeBuilder, SchemeGroupVersion
- [pkg/apis/dos/v1beta1/types.go](../pkg/apis/dos/v1beta1/types.go) — AllowListEntry, ApDosMonitor, DosProtectedResource, DosProtectedResourceList, DosProtectedResourceSpec, DosSecurityLog

## github.com/nginx/kubernetes-ingress/pkg/apis/dos/validation

- [pkg/apis/dos/validation/dos.go](../pkg/apis/dos/validation/dos.go) — ValidateAppProtectDosAllowList, ValidateAppProtectDosLogConf, ValidateAppProtectDosPolicy, ValidateDosProtectedResource

## github.com/nginx/kubernetes-ingress/pkg/apis/externaldns

- [pkg/apis/externaldns/register.go](../pkg/apis/externaldns/register.go) — GroupName

## github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1

_Package v1 is the v1 version of the API._

- [pkg/apis/externaldns/v1/doc.go](../pkg/apis/externaldns/v1/doc.go)
- [pkg/apis/externaldns/v1/register.go](../pkg/apis/externaldns/v1/register.go) — AddToScheme, Kind, Resource, SchemeBuilder, SchemeGroupVersion
- [pkg/apis/externaldns/v1/types.go](../pkg/apis/externaldns/v1/types.go) — DNSEndpoint, DNSEndpointList, DNSEndpointSpec, DNSEndpointStatus, Endpoint, Labels, ProviderSpecific, ProviderSpecificProperty, TTL, Targets

## github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/validation

_Package validation provides validation rules for the ExternalDNS CRD._

- [pkg/apis/externaldns/validation/doc.go](../pkg/apis/externaldns/validation/doc.go)
- [pkg/apis/externaldns/validation/externaldns.go](../pkg/apis/externaldns/validation/externaldns.go) — ErrTypeDuplicated, ErrTypeInvalid, ErrTypeNotInRange, ErrTypeNotSupported, ErrTypeRequired, ValidateDNSEndpoint

