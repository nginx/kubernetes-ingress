package configs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/validation"
)

const (
	minimumInterval     = 60
	zoneSyncDefaultPort = 12345
	kubeDNSDefault      = "kube-dns.kube-system.svc.cluster.local"
)

// ParseConfigMap parses ConfigMap into ConfigParams.
//
//nolint:gocyclo
func ParseConfigMap(ctx context.Context, cfgm *v1.ConfigMap, nginxPlus bool, hasAppProtect bool, hasAppProtectDos bool, hasTLSPassthrough bool, eventLog record.EventRecorder) (*ConfigParams, bool) {
	l := nl.LoggerFromContext(ctx)
	cfgParams := NewDefaultConfigParams(ctx, nginxPlus)
	configOk := true

	// valid values for server token are on | off | build | string;
	// oss can only use on | off
	if serverTokens, exists, err := GetMapKeyAsBool(cfgm.Data, "server-tokens", cfgm); exists {
		// this may be a build | string
		if err != nil {
			if nginxPlus {
				cfgParams.ServerTokens = cfgm.Data["server-tokens"]
			} else {
				errorText := fmt.Sprintf("ConfigMap %s/%s: 'server-tokens' must be a bool for OSS, ignoring", cfgm.GetNamespace(), cfgm.GetName())
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		} else {
			cfgParams.ServerTokens = "off"
			if serverTokens {
				cfgParams.ServerTokens = "on"
			}
		}
	}

	if lbMethod, exists := cfgm.Data["lb-method"]; exists {
		if nginxPlus {
			if parsedMethod, err := ParseLBMethodForPlus(lbMethod); err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'lb-method': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), lbMethod, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.LBMethod = parsedMethod
			}
		} else {
			if parsedMethod, err := ParseLBMethod(lbMethod); err != nil {
				errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the lb-method key: got %q: %v", cfgm.GetNamespace(), cfgm.GetName(), lbMethod, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.LBMethod = parsedMethod
			}
		}
	}

	if proxyConnectTimeout, exists := cfgm.Data["proxy-connect-timeout"]; exists {
		cfgParams.ProxyConnectTimeout = proxyConnectTimeout
	}

	if proxyReadTimeout, exists := cfgm.Data["proxy-read-timeout"]; exists {
		cfgParams.ProxyReadTimeout = proxyReadTimeout
	}

	if proxySendTimeout, exists := cfgm.Data["proxy-send-timeout"]; exists {
		cfgParams.ProxySendTimeout = proxySendTimeout
	}

	if proxyHideHeaders, exists := GetMapKeyAsStringSlice(cfgm.Data, "proxy-hide-headers", cfgm, ","); exists {
		cfgParams.ProxyHideHeaders = proxyHideHeaders
	}

	if proxyPassHeaders, exists := GetMapKeyAsStringSlice(cfgm.Data, "proxy-pass-headers", cfgm, ","); exists {
		cfgParams.ProxyPassHeaders = proxyPassHeaders
	}

	if clientMaxBodySize, exists := cfgm.Data["client-max-body-size"]; exists {
		cfgParams.ClientMaxBodySize = clientMaxBodySize
	}

	if serverNamesHashBucketSize, exists := cfgm.Data["server-names-hash-bucket-size"]; exists {
		cfgParams.MainServerNamesHashBucketSize = serverNamesHashBucketSize
	}

	if serverNamesHashMaxSize, exists := cfgm.Data["server-names-hash-max-size"]; exists {
		cfgParams.MainServerNamesHashMaxSize = serverNamesHashMaxSize
	}

	if mapHashBucketSize, exists := cfgm.Data["map-hash-bucket-size"]; exists {
		cfgParams.MainMapHashBucketSize = mapHashBucketSize
	}

	if mapHashMaxSize, exists := cfgm.Data["map-hash-max-size"]; exists {
		cfgParams.MainMapHashMaxSize = mapHashMaxSize
	}

	if HTTP2, exists, err := GetMapKeyAsBool(cfgm.Data, "http2", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.HTTP2 = HTTP2
		}
	}

	if redirectToHTTPS, exists, err := GetMapKeyAsBool(cfgm.Data, "redirect-to-https", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.RedirectToHTTPS = redirectToHTTPS
		}
	}

	if sslRedirect, exists, err := GetMapKeyAsBool(cfgm.Data, "ssl-redirect", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.SSLRedirect = sslRedirect
		}
	}

	if hsts, exists, err := GetMapKeyAsBool(cfgm.Data, "hsts", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			parsingErrors := false

			hstsMaxAge, existsMA, err := GetMapKeyAsInt64(cfgm.Data, "hsts-max-age", cfgm)
			if existsMA && err != nil {
				nl.Error(l, err)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
				parsingErrors = true
				configOk = false
			}
			hstsIncludeSubdomains, existsIS, err := GetMapKeyAsBool(cfgm.Data, "hsts-include-subdomains", cfgm)
			if existsIS && err != nil {
				nl.Error(l, err)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
				parsingErrors = true
				configOk = false
			}
			hstsBehindProxy, existsBP, err := GetMapKeyAsBool(cfgm.Data, "hsts-behind-proxy", cfgm)
			if existsBP && err != nil {
				nl.Error(l, err)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
				parsingErrors = true
				configOk = false
			}

			if parsingErrors {
				errorText := fmt.Sprintf("ConfigMap %s/%s: there are configuration issues with HSTS settings, ignoring all HSTS options", cfgm.GetNamespace(), cfgm.GetName())
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.HSTS = hsts
				if existsMA {
					cfgParams.HSTSMaxAge = hstsMaxAge
				}
				if existsIS {
					cfgParams.HSTSIncludeSubdomains = hstsIncludeSubdomains
				}
				if existsBP {
					cfgParams.HSTSBehindProxy = hstsBehindProxy
				}
			}
		}
	}

	if proxyProtocol, exists, err := GetMapKeyAsBool(cfgm.Data, "proxy-protocol", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.ProxyProtocol = proxyProtocol
		}
	}

	if realIPHeader, exists := cfgm.Data["real-ip-header"]; exists {
		if hasTLSPassthrough {
			errorText := fmt.Sprintf("ConfigMap %s/%s: 'real-ip-header' is ignored because 'real_ip_header' is automatically set to 'proxy_protocol' when TLS passthrough is enabled, ignoring", cfgm.GetNamespace(), cfgm.GetName())
			if realIPHeader == "proxy_protocol" {
				nl.Info(l, errorText)
			} else {
				nl.Error(l, errorText)
				configOk = false
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			}
		} else {
			cfgParams.RealIPHeader = realIPHeader
		}
	}

	if setRealIPFrom, exists := GetMapKeyAsStringSlice(cfgm.Data, "set-real-ip-from", cfgm, ","); exists {
		cfgParams.SetRealIPFrom = setRealIPFrom
	}

	if realIPRecursive, exists, err := GetMapKeyAsBool(cfgm.Data, "real-ip-recursive", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.RealIPRecursive = realIPRecursive
		}
	}

	if sslProtocols, exists := cfgm.Data["ssl-protocols"]; exists {
		cfgParams.MainServerSSLProtocols = sslProtocols
	}

	if sslPreferServerCiphers, exists, err := GetMapKeyAsBool(cfgm.Data, "ssl-prefer-server-ciphers", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.MainServerSSLPreferServerCiphers = sslPreferServerCiphers
		}
	}

	if sslCiphers, exists := cfgm.Data["ssl-ciphers"]; exists {
		cfgParams.MainServerSSLCiphers = strings.Trim(sslCiphers, "\n")
	}

	if sslDHParamFile, exists := cfgm.Data["ssl-dhparam-file"]; exists {
		sslDHParamFile = strings.Trim(sslDHParamFile, "\n")
		cfgParams.MainServerSSLDHParamFileContent = &sslDHParamFile
	}

	if errorLogLevel, exists := cfgm.Data["error-log-level"]; exists {
		cfgParams.MainErrorLogLevel = errorLogLevel
	}

	if accessLog, exists := cfgm.Data["access-log"]; exists {
		if !strings.HasPrefix(accessLog, "syslog:") {
			errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'access-log': %q, ignoring", cfgm.GetNamespace(), cfgm.GetName(), accessLog)
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		} else {
			cfgParams.MainAccessLog = accessLog
		}
	}

	if accessLogOff, exists, err := GetMapKeyAsBool(cfgm.Data, "access-log-off", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			if accessLogOff {
				cfgParams.MainAccessLog = "off"
			}
		}
	}

	if logFormat, exists := GetMapKeyAsStringSlice(cfgm.Data, "log-format", cfgm, "\n"); exists {
		cfgParams.MainLogFormat = logFormat
	}

	if logFormatEscaping, exists := cfgm.Data["log-format-escaping"]; exists {
		logFormatEscaping = strings.TrimSpace(logFormatEscaping)
		if logFormatEscaping != "" {
			cfgParams.MainLogFormatEscaping = logFormatEscaping
		}
	}

	if streamLogFormat, exists := GetMapKeyAsStringSlice(cfgm.Data, "stream-log-format", cfgm, "\n"); exists {
		cfgParams.MainStreamLogFormat = streamLogFormat
	}

	if streamLogFormatEscaping, exists := cfgm.Data["stream-log-format-escaping"]; exists {
		streamLogFormatEscaping = strings.TrimSpace(streamLogFormatEscaping)
		if streamLogFormatEscaping != "" {
			cfgParams.MainStreamLogFormatEscaping = streamLogFormatEscaping
		}
	}

	if defaultServerAccessLogOff, exists, err := GetMapKeyAsBool(cfgm.Data, "default-server-access-log-off", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.DefaultServerAccessLogOff = defaultServerAccessLogOff
		}
	}

	if defaultServerReturn, exists := cfgm.Data["default-server-return"]; exists {
		cfgParams.DefaultServerReturn = defaultServerReturn
	}

	if proxyBuffering, exists, err := GetMapKeyAsBool(cfgm.Data, "proxy-buffering", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.ProxyBuffering = proxyBuffering
		}
	}

	if proxyBuffers, exists := cfgm.Data["proxy-buffers"]; exists {
		cfgParams.ProxyBuffers = proxyBuffers
	}

	if proxyBufferSize, exists := cfgm.Data["proxy-buffer-size"]; exists {
		cfgParams.ProxyBufferSize = proxyBufferSize
	}

	if proxyMaxTempFileSize, exists := cfgm.Data["proxy-max-temp-file-size"]; exists {
		cfgParams.ProxyMaxTempFileSize = proxyMaxTempFileSize
	}

	if mainMainSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "main-snippets", cfgm, "\n"); exists {
		cfgParams.MainMainSnippets = mainMainSnippets
	}

	if mainHTTPSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "http-snippets", cfgm, "\n"); exists {
		cfgParams.MainHTTPSnippets = mainHTTPSnippets
	}

	if locationSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "location-snippets", cfgm, "\n"); exists {
		cfgParams.LocationSnippets = locationSnippets
	}

	if serverSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "server-snippets", cfgm, "\n"); exists {
		cfgParams.ServerSnippets = serverSnippets
	}

	if _, exists, err := GetMapKeyAsInt(cfgm.Data, "worker-processes", cfgm); exists {
		if err != nil && cfgm.Data["worker-processes"] != "auto" {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.MainWorkerProcesses = cfgm.Data["worker-processes"]
		}
	}

	if workerCPUAffinity, exists := cfgm.Data["worker-cpu-affinity"]; exists {
		cfgParams.MainWorkerCPUAffinity = workerCPUAffinity
	}

	if workerShutdownTimeout, exists := cfgm.Data["worker-shutdown-timeout"]; exists {
		cfgParams.MainWorkerShutdownTimeout = workerShutdownTimeout
	}

	if workerConnections, exists := cfgm.Data["worker-connections"]; exists {
		cfgParams.MainWorkerConnections = workerConnections
	}

	if workerRlimitNofile, exists := cfgm.Data["worker-rlimit-nofile"]; exists {
		cfgParams.MainWorkerRlimitNofile = workerRlimitNofile
	}

	if keepalive, exists, err := GetMapKeyAsInt(cfgm.Data, "keepalive", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.Keepalive = keepalive
		}
	}

	if maxFails, exists, err := GetMapKeyAsInt(cfgm.Data, "max-fails", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.MaxFails = maxFails
		}
	}

	_, err := parseConfigMapZoneSync(l, cfgm, cfgParams, eventLog, nginxPlus)
	if err != nil {
		configOk = false
	}

	if upstreamZoneSize, exists := cfgm.Data["upstream-zone-size"]; exists {
		cfgParams.UpstreamZoneSize = upstreamZoneSize
	}

	if failTimeout, exists := cfgm.Data["fail-timeout"]; exists {
		cfgParams.FailTimeout = failTimeout
	}

	if mainTemplate, exists := cfgm.Data["main-template"]; exists {
		cfgParams.MainTemplate = &mainTemplate
	} else {
		cfgParams.MainTemplate = nil
	}

	if ingressTemplate, exists := cfgm.Data["ingress-template"]; exists {
		cfgParams.IngressTemplate = &ingressTemplate
	} else {
		cfgParams.IngressTemplate = nil
	}

	if virtualServerTemplate, exists := cfgm.Data["virtualserver-template"]; exists {
		cfgParams.VirtualServerTemplate = &virtualServerTemplate
	} else {
		cfgParams.VirtualServerTemplate = nil
	}

	if transportServerTemplate, exists := cfgm.Data["transportserver-template"]; exists {
		cfgParams.TransportServerTemplate = &transportServerTemplate
	} else {
		cfgParams.TransportServerTemplate = nil
	}

	if mainStreamSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "stream-snippets", cfgm, "\n"); exists {
		cfgParams.MainStreamSnippets = mainStreamSnippets
	}

	if resolverAddresses, exists := GetMapKeyAsStringSlice(cfgm.Data, "resolver-addresses", cfgm, ","); exists {
		if nginxPlus {
			cfgParams.ResolverAddresses = resolverAddresses
		} else {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "resolver-addresses")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		}
	}

	if resolverIpv6, exists, err := GetMapKeyAsBool(cfgm.Data, "resolver-ipv6", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			if nginxPlus {
				cfgParams.ResolverIPV6 = resolverIpv6
			} else {
				errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "resolver-ipv6")
				nl.Warn(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		}
	}

	if resolverValid, exists := cfgm.Data["resolver-valid"]; exists {
		if nginxPlus {
			cfgParams.ResolverValid = resolverValid
		} else {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "resolver-valid")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		}
	}

	if resolverTimeout, exists := cfgm.Data["resolver-timeout"]; exists {
		if nginxPlus {
			cfgParams.ResolverTimeout = resolverTimeout
		} else {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "resolver-timeout")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		}
	}

	if keepaliveTimeout, exists := cfgm.Data["keepalive-timeout"]; exists {
		cfgParams.MainKeepaliveTimeout = keepaliveTimeout
	}

	if keepaliveRequests, exists, err := GetMapKeyAsInt64(cfgm.Data, "keepalive-requests", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.MainKeepaliveRequests = keepaliveRequests
		}
	}

	if varHashBucketSize, exists, err := GetMapKeyAsUint64(cfgm.Data, "variables-hash-bucket-size", cfgm, true); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.VariablesHashBucketSize = varHashBucketSize
		}
	}

	if varHashMaxSize, exists, err := GetMapKeyAsUint64(cfgm.Data, "variables-hash-max-size", cfgm, false); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.VariablesHashMaxSize = varHashMaxSize
		}
	}

	if otelExporterEndpoint, exists := cfgm.Data["otel-exporter-endpoint"]; exists {
		otelExporterEndpoint = strings.TrimSpace(otelExporterEndpoint)
		if otelExporterEndpoint != "" {
			cfgParams.MainOtelExporterEndpoint = otelExporterEndpoint
		}
	}

	if otelExporterTrustedCA, exists := cfgm.Data["otel-exporter-trusted-ca"]; exists {
		otelExporterTrustedCA = strings.TrimSpace(otelExporterTrustedCA)
		if otelExporterTrustedCA != "" {
			cfgParams.MainOtelExporterTrustedCA = otelExporterTrustedCA
		}
	}

	if otelExporterHeaderName, exists := cfgm.Data["otel-exporter-header-name"]; exists {
		otelExporterHeaderName = strings.TrimSpace(otelExporterHeaderName)
		if otelExporterHeaderName != "" {
			cfgParams.MainOtelExporterHeaderName = otelExporterHeaderName
		}
	}

	if otelExporterHeaderValue, exists := cfgm.Data["otel-exporter-header-value"]; exists {
		otelExporterHeaderValue = strings.TrimSpace(otelExporterHeaderValue)
		if otelExporterHeaderValue != "" {
			cfgParams.MainOtelExporterHeaderValue = otelExporterHeaderValue
		}
	}

	if otelServiceName, exists := cfgm.Data["otel-service-name"]; exists {
		otelServiceName = strings.TrimSpace(otelServiceName)
		if otelServiceName != "" {
			cfgParams.MainOtelServiceName = otelServiceName
		}
	}

	if otelGlobalTraceEnabled, exists, err := GetMapKeyAsBool(cfgm.Data, "otel-global-trace-enabled", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		}
		cfgParams.MainOtelGlobalTraceEnabled = otelGlobalTraceEnabled
	}

	if cfgParams.MainOtelExporterEndpoint != "" {
		cfgParams.MainOtelLoadModule = true
	}

	if hasAppProtect {
		if appProtectFailureModeAction, exists := cfgm.Data["app-protect-failure-mode-action"]; exists {
			if appProtectFailureModeAction == "pass" || appProtectFailureModeAction == "drop" {
				cfgParams.MainAppProtectFailureModeAction = appProtectFailureModeAction
			} else {
				errorText := fmt.Sprintf(
					"ConfigMap %s/%s: invalid value for 'app-protect-failure-mode-action': %q, must be 'pass' or 'drop', ignoring",
					cfgm.GetNamespace(),
					cfgm.GetName(),
					appProtectFailureModeAction,
				)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		}

		if appProtectCompressedRequestsAction, exists := cfgm.Data["app-protect-compressed-requests-action"]; exists {
			if appProtectCompressedRequestsAction == "pass" || appProtectCompressedRequestsAction == "drop" {
				cfgParams.MainAppProtectCompressedRequestsAction = appProtectCompressedRequestsAction
			} else {
				errorText := fmt.Sprintf(
					"ConfigMap %s/%s: invalid value for 'app-protect-compressed-requests-action': %q, must be 'pass' or 'drop', ignoring",
					cfgm.GetNamespace(),
					cfgm.GetName(),
					appProtectCompressedRequestsAction,
				)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		}

		if appProtectCookieSeed, exists := cfgm.Data["app-protect-cookie-seed"]; exists {
			cfgParams.MainAppProtectCookieSeed = appProtectCookieSeed
		}

		if appProtectCPUThresholds, exists := cfgm.Data["app-protect-cpu-thresholds"]; exists {
			if VerifyAppProtectThresholds(appProtectCPUThresholds) {
				cfgParams.MainAppProtectCPUThresholds = appProtectCPUThresholds
			} else {
				errorText := fmt.Sprintf(
					"ConfigMap %s/%s: invalid value for 'app-protect-cpu-thresholds': %q, must follow pattern 'high=<0 - 100> low=<0 - 100>', ignoring",
					cfgm.GetNamespace(),
					cfgm.GetName(),
					appProtectCPUThresholds,
				)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		}

		if appProtectPhysicalMemoryThresholds, exists := cfgm.Data["app-protect-physical-memory-util-thresholds"]; exists {
			if VerifyAppProtectThresholds(appProtectPhysicalMemoryThresholds) {
				cfgParams.MainAppProtectPhysicalMemoryThresholds = appProtectPhysicalMemoryThresholds
			} else {
				errorText := fmt.Sprintf(
					"ConfigMap %s/%s: invalid value for 'app-protect-physical-memory-util-thresholds': %q, must follow pattern 'high=<0 - 100> low=<0 - 100>', ignoring",
					cfgm.GetNamespace(),
					cfgm.GetName(),
					appProtectPhysicalMemoryThresholds,
				)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		}

		if appProtectReconnectPeriod, exists := cfgm.Data["app-protect-reconnect-period-seconds"]; exists {
			period, err := ParseFloat64(appProtectReconnectPeriod)
			if err == nil && period > 0 && period <= 60 {
				cfgParams.MainAppProtectReconnectPeriod = appProtectReconnectPeriod
			} else {
				errorText := fmt.Sprintf(
					"ConfigMap %s/%s: invalid value for 'app-protect-reconnect-period-seconds': %q, must be between '0' and '60' (exclusive), '0' is illegal, ignoring",
					cfgm.GetNamespace(),
					cfgm.GetName(),
					appProtectReconnectPeriod,
				)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			}
		}
	}

	if hasAppProtectDos {
		if appProtectDosLogFormat, exists := GetMapKeyAsStringSlice(cfgm.Data, "app-protect-dos-log-format", cfgm, "\n"); exists {
			cfgParams.MainAppProtectDosLogFormat = appProtectDosLogFormat
		}

		if appProtectDosLogFormatEscaping, exists := cfgm.Data["app-protect-dos-log-format-escaping"]; exists {
			appProtectDosLogFormatEscaping = strings.TrimSpace(appProtectDosLogFormatEscaping)
			if appProtectDosLogFormatEscaping != "" {
				cfgParams.MainAppProtectDosLogFormatEscaping = appProtectDosLogFormatEscaping
			}
		}

		if appProtectDosArbFqdn, exists := cfgm.Data["app-protect-dos-arb-fqdn"]; exists {
			appProtectDosArbFqdn = strings.TrimSpace(appProtectDosArbFqdn)
			if appProtectDosArbFqdn != "" {
				cfgParams.MainAppProtectDosArbFqdn = appProtectDosArbFqdn
			}
		}
	}

	return cfgParams, configOk
}

//nolint:gocyclo
func parseConfigMapZoneSync(l *slog.Logger, cfgm *v1.ConfigMap, cfgParams *ConfigParams, eventLog record.EventRecorder, nginxPlus bool) (*ZoneSync, error) {
	if zoneSync, exists, err := GetMapKeyAsBool(cfgm.Data, "zone-sync", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			return nil, err
		}
		if nginxPlus {
			cfgParams.ZoneSync.Enable = zoneSync
		} else {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "zone-sync")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
	}

	if zoneSyncPort, exists, err := GetMapKeyAsInt(cfgm.Data, "zone-sync-port", cfgm); exists {
		if !cfgParams.ZoneSync.Enable {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires 'zone-sync' to be enabled", cfgm.Namespace, cfgm.Name, "zone-sync-port")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		if err != nil {
			cfgParams.ZoneSync.Port = zoneSyncDefaultPort
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s has an errored port %d set, defaulting to 12345 -  %v", cfgm.Namespace, cfgm.Name, "zone-sync-port", zoneSyncPort, err)
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		if portValidationError := validation.ValidatePort(zoneSyncPort); portValidationError != nil {
			cfgParams.ZoneSync.Port = zoneSyncDefaultPort
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s has invalid port %d set, defaulting to 12345 -  %v", cfgm.Namespace, cfgm.Name, "zone-sync-port", zoneSyncPort, portValidationError)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		cfgParams.ZoneSync.Port = zoneSyncPort
	} else {
		cfgParams.ZoneSync.Port = zoneSyncDefaultPort
	}

	if zoneSyncResolverAddresses, exists := GetMapKeyAsStringSlice(cfgm.Data, "zone-sync-resolver-addresses", cfgm, ","); exists {
		if !cfgParams.ZoneSync.Enable {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires 'zone-sync' to be enabled", cfgm.Namespace, cfgm.Name, "zone-sync-resolver-addresses")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		for _, addr := range zoneSyncResolverAddresses {
			if err := validation.ValidateHost(addr); err != nil {
				nl.Warn(l, err)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
				return nil, err
			}
		}
		cfgParams.ZoneSync.ResolverAddresses = zoneSyncResolverAddresses
	} else {
		cfgParams.ZoneSync.ResolverAddresses = []string{kubeDNSDefault}
	}

	if zoneSyncResolverValid, exists := cfgm.Data["zone-sync-resolver-valid"]; exists {
		if !cfgParams.ZoneSync.Enable {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires 'zone-sync' to be enabled", cfgm.Namespace, cfgm.Name, "zone-sync-resolver-valid")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		zoneSyncResolverValidTime, err := ParseTime(zoneSyncResolverValid)
		if err != nil {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s contains invalid nginx time: %s, eg. 10s\",", cfgm.Namespace, cfgm.Name, "zone-sync-resolver-valid", zoneSyncResolverValid)
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		cfgParams.ZoneSync.ResolverValid = zoneSyncResolverValidTime
	} else {
		cfgParams.ZoneSync.ResolverValid = "5s"
	}

	if zoneSyncResolverIpv6, exists, err := GetMapKeyAsBool(cfgm.Data, "zone-sync-resolver-ipv6", cfgm); exists {
		if err != nil {
			nl.Warn(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			return nil, err
		}
		if !cfgParams.ZoneSync.Enable {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires 'zone-sync' to be enabled", cfgm.Namespace, cfgm.Name, "zone-sync-resolver-ipv6")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return nil, errors.New(errorText)
		}
		cfgParams.ZoneSync.ResolverIPV6 = commonhelpers.BoolToPointerBool(zoneSyncResolverIpv6)
	}

	return &cfgParams.ZoneSync, nil
}

// ParseMGMTConfigMap parses the mgmt block ConfigMap into MGMTConfigParams.
//
//nolint:gocyclo
func ParseMGMTConfigMap(ctx context.Context, cfgm *v1.ConfigMap, eventLog record.EventRecorder) (*MGMTConfigParams, bool, error) {
	l := nl.LoggerFromContext(ctx)
	configWarnings := false

	mgmtCfgParams := NewDefaultMGMTConfigParams(ctx)

	license, licenseExists := cfgm.Data["license-token-secret-name"]
	trimmedLicense := strings.TrimSpace(license)
	if !licenseExists || trimmedLicense == "" {
		errorText := fmt.Sprintf("Configmap %s/%s: Missing or empty value for the license-token-secret-name key. Failing.", cfgm.GetNamespace(), cfgm.GetName())
		return nil, true, errors.New(errorText)
	}
	mgmtCfgParams.Secrets.License = trimmedLicense

	if sslVerify, exists, err := GetMapKeyAsBool(cfgm.Data, "ssl-verify", cfgm); exists {
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the ssl-verify key: got %t: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), sslVerify, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.SSLVerify = commonhelpers.BoolToPointerBool(sslVerify)
		}
	}

	if resolverAddresses, exists := GetMapKeyAsStringSlice(cfgm.Data, "resolver-addresses", cfgm, ","); exists {
		mgmtCfgParams.ResolverAddresses = resolverAddresses
	}

	if resolverIpv6, exists, err := GetMapKeyAsBool(cfgm.Data, "resolver-ipv6", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configWarnings = true
		} else {
			mgmtCfgParams.ResolverIPV6 = commonhelpers.BoolToPointerBool(resolverIpv6)
		}
	}

	if resolverValid, exists := cfgm.Data["resolver-valid"]; exists {
		mgmtCfgParams.ResolverValid = resolverValid
	}

	if enforceInitialReport, exists, err := GetMapKeyAsBool(cfgm.Data, "enforce-initial-report", cfgm); exists {
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the enforce-initial-report key: got %t: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), enforceInitialReport, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.EnforceInitialReport = commonhelpers.BoolToPointerBool(enforceInitialReport)
		}
	}

	if endpoint, exists := cfgm.Data["usage-report-endpoint"]; exists {
		endpoint := strings.TrimSpace(endpoint)
		err := validation.ValidateHost(endpoint)
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the usage-report-endpoint key: got %q: %v. Using default endpoint.", cfgm.GetNamespace(), cfgm.GetName(), endpoint, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.Endpoint = strings.TrimSpace(endpoint)
		}
	}

	if interval, exists := cfgm.Data["usage-report-interval"]; exists {
		i := strings.TrimSpace(interval)
		t, err := time.ParseDuration(i)
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the interval key: got %q: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), i, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		}
		if t.Seconds() < minimumInterval {
			errorText := fmt.Sprintf("Configmap %s/%s: Value too low for the interval key, got: %v, need higher than %ds. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), i, minimumInterval)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
			mgmtCfgParams.Interval = ""
		} else {
			mgmtCfgParams.Interval = i
		}

	}
	if trustedCertSecretName, exists := cfgm.Data["ssl-trusted-certificate-secret-name"]; exists {
		mgmtCfgParams.Secrets.TrustedCert = strings.TrimSpace(trustedCertSecretName)
	}

	if clientAuthSecretName, exists := cfgm.Data["ssl-certificate-secret-name"]; exists {
		mgmtCfgParams.Secrets.ClientAuth = strings.TrimSpace(clientAuthSecretName)
	}

	if proxyHost, exists := cfgm.Data["usage-report-proxy-host"]; exists {
		proxyHost := strings.TrimSpace(proxyHost)
		err := validation.ValidateHost(proxyHost)
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the usage-report-proxy-host key: got %q: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), proxyHost, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonIgnored, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.ProxyHost = strings.TrimSpace(proxyHost)
		}

		if proxyUser := os.Getenv("PROXY_USER"); proxyUser != "" {
			mgmtCfgParams.ProxyUser = strings.TrimSpace(proxyUser)
		}

		if proxyPass := os.Getenv("PROXY_PASS"); proxyPass != "" {
			mgmtCfgParams.ProxyPass = strings.TrimSpace(proxyPass)
		}
	}

	return mgmtCfgParams, configWarnings, nil
}

// GenerateNginxMainConfig generates MainConfig.
func GenerateNginxMainConfig(staticCfgParams *StaticConfigParams, config *ConfigParams, mgmtCfgParams *MGMTConfigParams) *version1.MainConfig {
	var mgmtConfig version1.MGMTConfig
	if mgmtCfgParams != nil {
		mgmtConfig = version1.MGMTConfig{
			SSLVerify:            mgmtCfgParams.SSLVerify,
			ResolverAddresses:    mgmtCfgParams.ResolverAddresses,
			ResolverIPV6:         mgmtCfgParams.ResolverIPV6,
			ResolverValid:        mgmtCfgParams.ResolverValid,
			EnforceInitialReport: mgmtCfgParams.EnforceInitialReport,
			Endpoint:             mgmtCfgParams.Endpoint,
			Interval:             mgmtCfgParams.Interval,
			TrustedCert:          mgmtCfgParams.Secrets.TrustedCert != "",
			TrustedCRL:           mgmtCfgParams.Secrets.TrustedCRL != "",
			ClientAuth:           mgmtCfgParams.Secrets.ClientAuth != "",
			ProxyHost:            mgmtCfgParams.ProxyHost,
			ProxyUser:            mgmtCfgParams.ProxyUser,
			ProxyPass:            mgmtCfgParams.ProxyPass,
		}
	}

	zoneSyncConfig := version1.ZoneSyncConfig{
		Enable:            config.ZoneSync.Enable,
		Port:              config.ZoneSync.Port,
		Domain:            fmt.Sprintf("%s-hl.%s.svc.cluster.local", config.ZoneSync.Domain, os.Getenv("POD_NAMESPACE")),
		ResolverAddresses: config.ZoneSync.ResolverAddresses,
		ResolverIPV6:      config.ZoneSync.ResolverIPV6,
		ResolverValid:     config.ZoneSync.ResolverValid,
	}

	nginxCfg := &version1.MainConfig{
		AccessLog:                          config.MainAccessLog,
		DefaultServerAccessLogOff:          config.DefaultServerAccessLogOff,
		DefaultServerReturn:                config.DefaultServerReturn,
		DisableIPV6:                        staticCfgParams.DisableIPV6,
		DefaultHTTPListenerPort:            staticCfgParams.DefaultHTTPListenerPort,
		DefaultHTTPSListenerPort:           staticCfgParams.DefaultHTTPSListenerPort,
		ErrorLogLevel:                      config.MainErrorLogLevel,
		HealthStatus:                       staticCfgParams.HealthStatus,
		HealthStatusURI:                    staticCfgParams.HealthStatusURI,
		HTTP2:                              config.HTTP2,
		HTTPSnippets:                       config.MainHTTPSnippets,
		KeepaliveRequests:                  config.MainKeepaliveRequests,
		KeepaliveTimeout:                   config.MainKeepaliveTimeout,
		LogFormat:                          config.MainLogFormat,
		LogFormatEscaping:                  config.MainLogFormatEscaping,
		MainSnippets:                       config.MainMainSnippets,
		MGMTConfig:                         mgmtConfig,
		NginxStatus:                        staticCfgParams.NginxStatus,
		NginxStatusAllowCIDRs:              staticCfgParams.NginxStatusAllowCIDRs,
		NginxStatusPort:                    staticCfgParams.NginxStatusPort,
		MainOtelEnabled:                    config.MainOtelEnabled,
		MainOtelLoadModule:                 config.MainOtelLoadModule,
		MainOtelGlobalTraceEnabled:         config.MainOtelGlobalTraceEnabled,
		MainOtelExporterEndpoint:           config.MainOtelExporterEndpoint,
		MainOtelExporterTrustedCA:          config.MainOtelExporterTrustedCA,
		MainOtelExporterHeaderName:         config.MainOtelExporterHeaderName,
		MainOtelExporterHeaderValue:        config.MainOtelExporterHeaderValue,
		MainOtelServiceName:                config.MainOtelServiceName,
		ProxyProtocol:                      config.ProxyProtocol,
		ResolverAddresses:                  config.ResolverAddresses,
		ResolverIPV6:                       config.ResolverIPV6,
		ResolverTimeout:                    config.ResolverTimeout,
		ResolverValid:                      config.ResolverValid,
		RealIPHeader:                       config.RealIPHeader,
		RealIPRecursive:                    config.RealIPRecursive,
		SetRealIPFrom:                      config.SetRealIPFrom,
		ServerNamesHashBucketSize:          config.MainServerNamesHashBucketSize,
		ServerNamesHashMaxSize:             config.MainServerNamesHashMaxSize,
		MapHashBucketSize:                  config.MainMapHashBucketSize,
		MapHashMaxSize:                     config.MainMapHashMaxSize,
		ServerTokens:                       config.ServerTokens,
		SSLCiphers:                         config.MainServerSSLCiphers,
		SSLDHParam:                         config.MainServerSSLDHParam,
		SSLPreferServerCiphers:             config.MainServerSSLPreferServerCiphers,
		SSLProtocols:                       config.MainServerSSLProtocols,
		SSLRejectHandshake:                 staticCfgParams.SSLRejectHandshake,
		TLSPassthrough:                     staticCfgParams.TLSPassthrough,
		TLSPassthroughPort:                 staticCfgParams.TLSPassthroughPort,
		StreamLogFormat:                    config.MainStreamLogFormat,
		StreamLogFormatEscaping:            config.MainStreamLogFormatEscaping,
		StreamSnippets:                     config.MainStreamSnippets,
		StubStatusOverUnixSocketForOSS:     staticCfgParams.StubStatusOverUnixSocketForOSS,
		WorkerCPUAffinity:                  config.MainWorkerCPUAffinity,
		WorkerProcesses:                    config.MainWorkerProcesses,
		WorkerShutdownTimeout:              config.MainWorkerShutdownTimeout,
		WorkerConnections:                  config.MainWorkerConnections,
		WorkerRlimitNofile:                 config.MainWorkerRlimitNofile,
		VariablesHashBucketSize:            config.VariablesHashBucketSize,
		VariablesHashMaxSize:               config.VariablesHashMaxSize,
		AppProtectLoadModule:               staticCfgParams.MainAppProtectLoadModule,
		AppProtectV5LoadModule:             staticCfgParams.MainAppProtectV5LoadModule,
		AppProtectDosLoadModule:            staticCfgParams.MainAppProtectDosLoadModule,
		AppProtectV5EnforcerAddr:           staticCfgParams.MainAppProtectV5EnforcerAddr,
		AppProtectFailureModeAction:        config.MainAppProtectFailureModeAction,
		AppProtectCompressedRequestsAction: config.MainAppProtectCompressedRequestsAction,
		AppProtectCookieSeed:               config.MainAppProtectCookieSeed,
		AppProtectCPUThresholds:            config.MainAppProtectCPUThresholds,
		AppProtectPhysicalMemoryThresholds: config.MainAppProtectPhysicalMemoryThresholds,
		AppProtectReconnectPeriod:          config.MainAppProtectReconnectPeriod,
		AppProtectDosLogFormat:             config.MainAppProtectDosLogFormat,
		AppProtectDosLogFormatEscaping:     config.MainAppProtectDosLogFormatEscaping,
		AppProtectDosArbFqdn:               config.MainAppProtectDosArbFqdn,
		InternalRouteServer:                staticCfgParams.EnableInternalRoutes,
		InternalRouteServerName:            staticCfgParams.InternalRouteServerName,
		LatencyMetrics:                     staticCfgParams.EnableLatencyMetrics,
		OIDC:                               staticCfgParams.EnableOIDC,
		ZoneSyncConfig:                     zoneSyncConfig,
		DynamicSSLReloadEnabled:            staticCfgParams.DynamicSSLReload,
		StaticSSLPath:                      staticCfgParams.StaticSSLPath,
		NginxVersion:                       staticCfgParams.NginxVersion,
	}
	return nginxCfg
}
