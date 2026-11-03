package configs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/validation"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/nginx/kubernetes-ingress/internal/configs/version1"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

const (
	minimumInterval     = 60
	maximumInterval     = 24 * 60 * 60 // interval cannot be greater than 24h
	zoneSyncDefaultPort = 12345
	kubeDNSDefault      = "kube-dns.kube-system.svc.cluster.local"
)

// ParseConfigMap parses ConfigMap into ConfigParams.
//
//nolint:gocyclo
func ParseConfigMap(ctx context.Context, cfgm *v1.ConfigMap, nginxPlus bool, hasAppProtect bool, hasAppProtectDos bool, hasTLSPassthrough bool, enableDirectiveAutoadjust bool, enableSnippets bool, eventLog record.EventRecorder) (*ConfigParams, bool) {
	l := nl.LoggerFromContext(ctx)
	cfgParams := NewDefaultConfigParams(ctx, nginxPlus)
	configOk := true
	parseString := func(key string, parseFunc func(string) (string, error), assignFunc func(string)) {
		if err := parseStringField(cfgm, key, parseFunc, assignFunc, "", l, eventLog); err != nil {
			configOk = false
		}
	}
	parseStrings := func(key string, parseFunc func(string) ([]string, error), assignFunc func([]string)) {
		if err := parseStringSliceField(cfgm, key, parseFunc, assignFunc, l, eventLog); err != nil {
			configOk = false
		}
	}

	// valid values for server token are on | off | build | string;
	// oss can only use on | off
	if serverTokens, exists, err := GetMapKeyAsBool(cfgm.Data, "server-tokens", cfgm); exists {
		// this may be a build | string
		if err != nil {
			if nginxPlus {
				serverTokensValue := cfgm.Data["server-tokens"]
				// The ingress template quotes this value plainly, so it is
				// already escaped for NGINX and must be validated as such.
				// Escaping it again here would change the Server header NGINX
				// sends.
				if err := validation.ValidateQuotedDirectiveValue(serverTokensValue); err != nil {
					errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'server-tokens': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), serverTokensValue, err)
					nl.Error(l, errorText)
					eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
					configOk = false
				} else {
					cfgParams.ServerTokens = serverTokensValue
				}
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

	parseString("proxy-connect-timeout", ParseTime, func(value string) { cfgParams.ProxyConnectTimeout = value })
	parseString("proxy-read-timeout", ParseTime, func(value string) { cfgParams.ProxyReadTimeout = value })
	parseString("proxy-send-timeout", ParseTime, func(value string) { cfgParams.ProxySendTimeout = value })
	parseStrings("proxy-hide-headers", ParseHeaderList, func(value []string) { cfgParams.ProxyHideHeaders = value })
	parseStrings("proxy-pass-headers", ParseHeaderList, func(value []string) { cfgParams.ProxyPassHeaders = value })

	if addHeader, exists := cfgm.Data["add-header"]; exists {
		// ConfigMap "add-header" is a global default → http {} context.
		// Stored in MainAddHeaders so GenerateNginxMainConfig wires it into
		// MainConfig and the main template renders it at http level.
		if headers, err := parseAndValidateAddHeaders(addHeader); err != nil {
			nl.Error(l, fmt.Sprintf("ConfigMap %s/%s: %s, ignoring all add-header entries", cfgm.GetNamespace(), cfgm.GetName(), err))
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue,
				fmt.Sprintf("ConfigMap %s/%s: %s, ignoring all add-header entries", cfgm.GetNamespace(), cfgm.GetName(), err))
			configOk = false
		} else {
			cfgParams.MainAddHeaders = headers
		}
	}

	if disableForwardedHeaders, exists, err := GetMapKeyAsBool(cfgm.Data, "disable-forwarded-headers", cfgm); exists {
		if !enableSnippets {
			errorText := fmt.Sprintf("ConfigMap %s/%s: 'disable-forwarded-headers' requires -enable-snippets, ignoring", cfgm.GetNamespace(), cfgm.GetName())
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		} else if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.DisableForwardedHeaders = disableForwardedHeaders
		}
	}

	if useForwardedHeaders, exists, err := GetMapKeyAsBool(cfgm.Data, "use-forwarded-headers", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.UseForwardedHeaders = useForwardedHeaders
		}
	}

	if cfgParams.UseForwardedHeaders && cfgParams.DisableForwardedHeaders {
		errorText := fmt.Sprintf("ConfigMap %s/%s: 'use-forwarded-headers' and 'disable-forwarded-headers' are mutually exclusive, ignoring 'use-forwarded-headers'", cfgm.GetNamespace(), cfgm.GetName())
		nl.Error(l, errorText)
		eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
		cfgParams.UseForwardedHeaders = false
		configOk = false
	}

	parseString("client-max-body-size", ParseOffset, func(value string) { cfgParams.ClientMaxBodySize = value })

	if clientBodyBufferSize, exists := cfgm.Data["client-body-buffer-size"]; exists {
		if parsedClientBodyBufferSize, err := ParseSize(clientBodyBufferSize); err != nil {
			wrappedError := fmt.Errorf("ConfigMap %s/%s: invalid value for 'client-body-buffer-size': %w", cfgm.GetNamespace(), cfgm.GetName(), err)
			nl.Errorf(l, "%s", wrappedError.Error())
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, wrappedError.Error())
			configOk = false
		} else {
			cfgParams.MainClientBodyBufferSize = parsedClientBodyBufferSize
		}
	}

	parseString("server-names-hash-bucket-size", ParseUnsignedInteger, func(value string) { cfgParams.MainServerNamesHashBucketSize = value })
	parseString("server-names-hash-max-size", ParseUnsignedInteger, func(value string) { cfgParams.MainServerNamesHashMaxSize = value })
	parseString("map-hash-bucket-size", ParseUnsignedInteger, func(value string) { cfgParams.MainMapHashBucketSize = value })
	parseString("map-hash-max-size", ParseUnsignedInteger, func(value string) { cfgParams.MainMapHashMaxSize = value })

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

	if httpRedirectCode, exists := cfgm.Data["http-redirect-code"]; exists {
		if code, err := ParseHTTPRedirectCode(httpRedirectCode); err != nil {
			errorText := fmt.Sprintf("ConfigMap %s/%s: Invalid value for 'http-redirect-code': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), httpRedirectCode, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		} else {
			cfgParams.HTTPRedirectCode = code
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
		// A YAML block scalar adds a trailing newline, which NGINX reads as a
		// token separator, so surrounding whitespace was always accepted.
		realIPHeader = strings.TrimSpace(realIPHeader)
		if msgs := validation.ValidateRealIPHeader(realIPHeader); len(msgs) != 0 {
			errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'real-ip-header': %q, %s, ignoring", cfgm.GetNamespace(), cfgm.GetName(), realIPHeader, strings.Join(msgs, "; "))
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		} else if hasTLSPassthrough {
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

	parseStrings("set-real-ip-from", ParseSetRealIPFrom, func(value []string) { cfgParams.SetRealIPFrom = value })

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
		if err := validation.ValidateTLSProtocols(sslProtocols); err != nil {
			errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'ssl-protocols': %q, ignoring", cfgm.GetNamespace(), cfgm.GetName(), sslProtocols)
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		} else {
			cfgParams.MainServerSSLProtocols = sslProtocols
		}
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
		sslCiphers = strings.Trim(sslCiphers, "\n")
		if !validation.SSLCiphersRegex.MatchString(sslCiphers) {
			errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'ssl-ciphers': %q, ignoring", cfgm.GetNamespace(), cfgm.GetName(), sslCiphers)
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		} else {
			cfgParams.MainServerSSLCiphers = sslCiphers
		}
	}

	if sslDHParamFile, exists := cfgm.Data["ssl-dhparam-file"]; exists {
		sslDHParamFile = strings.Trim(sslDHParamFile, "\n")
		cfgParams.MainServerSSLDHParamFileContent = &sslDHParamFile
	}

	parseString("error-log-level", ParseErrorLogLevel, func(value string) { cfgParams.MainErrorLogLevel = value })

	if accessLog, exists := cfgm.Data["access-log"]; exists {
		accessLog = strings.TrimSpace(accessLog)
		if !strings.HasPrefix(accessLog, "syslog:") || validation.ValidateDirectiveValue(accessLog) != nil {
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

	parseStrings("log-format", parseLogFormat, func(value []string) { cfgParams.MainLogFormat = value })

	parseString("log-format-escaping", ParseLogFormatEscaping, func(value string) { cfgParams.MainLogFormatEscaping = value })

	parseStrings("stream-log-format", parseLogFormat, func(value []string) { cfgParams.MainStreamLogFormat = value })

	parseString("stream-log-format-escaping", ParseLogFormatEscaping, func(value string) { cfgParams.MainStreamLogFormatEscaping = value })

	if defaultServerAccessLogOff, exists, err := GetMapKeyAsBool(cfgm.Data, "default-server-access-log-off", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configOk = false
		} else {
			cfgParams.DefaultServerAccessLogOff = defaultServerAccessLogOff
		}
	}

	parseString("default-server-return", func(value string) (string, error) {
		value = strings.TrimSpace(value)
		if err := validation.ValidateDirectiveValue(value); err != nil {
			return "", err
		}
		return value, nil
	}, func(value string) { cfgParams.DefaultServerReturn = value })

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
		if parsedProxyBuffers, err := ParseProxyBuffersSpec(proxyBuffers); err != nil {
			wrappedError := fmt.Errorf("ConfigMap %s/%s: invalid value for 'proxy-buffers': %w", cfgm.GetNamespace(), cfgm.GetName(), err)

			nl.Errorf(l, "%s", wrappedError.Error())
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, wrappedError.Error())
			configOk = false
		} else {
			cfgParams.ProxyBuffers = parsedProxyBuffers
		}
	}

	if proxyBufferSize, exists := cfgm.Data["proxy-buffer-size"]; exists {
		if parsedProxyBufferSize, err := ParseSize(proxyBufferSize); err != nil {
			wrappedError := fmt.Errorf("ConfigMap %s/%s: invalid value for 'proxy-buffer-size': %w", cfgm.GetNamespace(), cfgm.GetName(), err)

			nl.Errorf(l, "%s", wrappedError.Error())
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, wrappedError.Error())
			configOk = false
		} else {
			cfgParams.ProxyBufferSize = parsedProxyBufferSize
		}
	}

	if proxyBusyBuffersSize, exists := cfgm.Data["proxy-busy-buffers-size"]; exists {
		if parsedProxyBusyBuffersSize, err := ParseSize(proxyBusyBuffersSize); err != nil {
			wrappedError := fmt.Errorf("ConfigMap %s/%s: invalid value for 'proxy-busy-buffers-size': %w", cfgm.GetNamespace(), cfgm.GetName(), err)

			nl.Errorf(l, "%s", wrappedError.Error())
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, wrappedError.Error())
			configOk = false
		} else {
			cfgParams.ProxyBusyBuffersSize = parsedProxyBusyBuffersSize
		}
	}

	// Only run balance validation if auto-adjust is enabled
	if enableDirectiveAutoadjust {
		balancedProxyBuffers, balancedProxyBufferSize, balancedProxyBusyBufferSize, modifications := validation.BalanceProxyValues(cfgParams.ProxyBuffers, cfgParams.ProxyBufferSize, cfgParams.ProxyBusyBuffersSize, enableDirectiveAutoadjust)

		cfgParams.ProxyBuffers = balancedProxyBuffers
		cfgParams.ProxyBufferSize = balancedProxyBufferSize
		cfgParams.ProxyBusyBuffersSize = balancedProxyBusyBufferSize

		if len(modifications) > 0 {
			for _, modification := range modifications {
				nl.Infof(l, "Changes made to proxy values: %s", modification)
			}
		}
	}

	parseString("proxy-max-temp-file-size", ParseSize, func(value string) { cfgParams.ProxyMaxTempFileSize = value })

	if mainMainSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "main-snippets", cfgm, "\n"); exists {
		cfgParams.MainMainSnippets = mainMainSnippets
	}

	if mainHTTPSnippets, exists := GetMapKeyAsStringSlice(cfgm.Data, "http-snippets", cfgm, "\n"); exists {
		cfgParams.MainHTTPSnippets = mainHTTPSnippets
	}

	if addHeaderInherit, exists := cfgm.Data["add-header-inherit"]; exists {
		if parsed, err := ParseAddHeaderInherit(addHeaderInherit); err != nil {
			wrappedError := fmt.Errorf("ConfigMap %s/%s: invalid value for 'add-header-inherit': %w", cfgm.GetNamespace(), cfgm.GetName(), err)
			nl.Errorf(l, "%s", wrappedError.Error())
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, wrappedError.Error())
			configOk = false
		} else {
			cfgParams.AddHeaderInherit = parsed
		}
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

	parseString("worker-cpu-affinity", ParseWorkerCPUAffinity, func(value string) { cfgParams.MainWorkerCPUAffinity = value })
	parseString("worker-shutdown-timeout", ParseTime, func(value string) { cfgParams.MainWorkerShutdownTimeout = value })
	parseString("worker-connections", ParseUnsignedInteger, func(value string) { cfgParams.MainWorkerConnections = value })
	parseString("worker-rlimit-nofile", ParseUnsignedInteger, func(value string) { cfgParams.MainWorkerRlimitNofile = value })

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

	err = parseConfigMapOIDC(l, cfgm, cfgParams, eventLog)
	if err != nil {
		configOk = false
	}

	parseString("upstream-zone-size", ParseSize, func(value string) { cfgParams.UpstreamZoneSize = value })
	parseString("fail-timeout", ParseTime, func(value string) { cfgParams.FailTimeout = value })

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

	if resolverAddresses, exists := cfgm.Data["resolver-addresses"]; exists {
		if nginxPlus {
			parsedResolverAddresses, err := ParseResolverAddresses(resolverAddresses)
			if err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'resolver-addresses': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), resolverAddresses, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.ResolverAddresses = parsedResolverAddresses
			}
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
			parsedResolverValid, err := ParseTime(resolverValid)
			if err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'resolver-valid': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), resolverValid, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.ResolverValid = parsedResolverValid
			}
		} else {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "resolver-valid")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		}
	}

	if resolverTimeout, exists := cfgm.Data["resolver-timeout"]; exists {
		if nginxPlus {
			parsedResolverTimeout, err := ParseTime(resolverTimeout)
			if err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'resolver-timeout': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), resolverTimeout, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.ResolverTimeout = parsedResolverTimeout
			}
		} else {
			errorText := fmt.Sprintf("ConfigMap %s/%s key %s requires NGINX Plus", cfgm.Namespace, cfgm.Name, "resolver-timeout")
			nl.Warn(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configOk = false
		}
	}

	parseString("keepalive-timeout", ParseKeepaliveTimeout, func(value string) { cfgParams.MainKeepaliveTimeout = value })

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

	_, otelErr := parseConfigMapOpenTelemetry(l, cfgm, cfgParams, eventLog)
	if otelErr != nil {
		configOk = false
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
			// The seed is secret, so a rejected value is never logged or put in
			// an Event: a near miss usually is most of the real seed.
			if parsed, err := ParseAppProtectCookieSeed(appProtectCookieSeed); err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'app-protect-cookie-seed': %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.MainAppProtectCookieSeed = parsed
			}
		}

		if appProtectCPUThresholds, exists := cfgm.Data["app-protect-cpu-thresholds"]; exists {
			appProtectCPUThresholds = strings.TrimSpace(appProtectCPUThresholds)
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
			appProtectPhysicalMemoryThresholds = strings.TrimSpace(appProtectPhysicalMemoryThresholds)
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
		parseStrings("app-protect-dos-log-format", parseLogFormat, func(value []string) {
			cfgParams.MainAppProtectDosLogFormat = value
		})

		parseString("app-protect-dos-log-format-escaping", ParseLogFormatEscaping, func(value string) {
			cfgParams.MainAppProtectDosLogFormatEscaping = value
		})

		if appProtectDosArbFqdn, exists := cfgm.Data["app-protect-dos-arb-fqdn"]; exists {
			parsedAppProtectDosArbFqdn, err := ParseFQDN(appProtectDosArbFqdn)
			if err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'app-protect-dos-arb-fqdn': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), appProtectDosArbFqdn, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configOk = false
			} else {
				cfgParams.MainAppProtectDosArbFqdn = parsedAppProtectDosArbFqdn
			}
		}
	}

	return cfgParams, configOk
}

// parseConfigMapOIDC parses OIDC timeout configuration from ConfigMap.
func parseConfigMapOIDC(l *slog.Logger, cfgm *v1.ConfigMap, cfgParams *ConfigParams, eventLog record.EventRecorder) error {
	timeSuggestion := "must be a valid nginx time (e.g. '90s', '5m', '1h')"
	sizeSuggestion := "must be a valid nginx size (e.g. '16k', '1m')"

	var err error

	// TimeOut config map variables
	err = parseStringField(cfgm, "oidc-pkce-timeout", ParseTime, func(value string) {
		cfgParams.OIDC.PKCETimeout = value
	}, timeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-pkce-timeout: %w", err)
	}

	err = parseStringField(cfgm, "oidc-id-tokens-timeout", ParseTime, func(value string) {
		cfgParams.OIDC.IDTokenTimeout = value
	}, timeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-id-tokens-timeout: %w", err)
	}

	err = parseStringField(cfgm, "oidc-access-tokens-timeout", ParseTime, func(value string) {
		cfgParams.OIDC.AccessTimeout = value
	}, timeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-access-tokens-timeout: %w", err)
	}

	err = parseStringField(cfgm, "oidc-refresh-tokens-timeout", ParseTime, func(value string) {
		cfgParams.OIDC.RefreshTimeout = value
	}, timeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-refresh-tokens-timeout: %w", err)
	}

	err = parseStringField(cfgm, "oidc-sids-timeout", ParseTime, func(value string) {
		cfgParams.OIDC.SIDSTimeout = value
	}, timeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-sids-timeout: %w", err)
	}

	// ZoneSize config map variables
	err = parseStringField(cfgm, "oidc-pkce-zone-size", ParseSize, func(value string) {
		cfgParams.OIDC.PKCEZoneSize = value
	}, sizeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-pkce-zone-size: %w", err)
	}

	err = parseStringField(cfgm, "oidc-id-tokens-zone-size", ParseSize, func(value string) {
		cfgParams.OIDC.IDTokenZoneSize = value
	}, sizeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-id-tokens-zone-size: %w", err)
	}

	err = parseStringField(cfgm, "oidc-access-tokens-zone-size", ParseSize, func(value string) {
		cfgParams.OIDC.AccessZoneSize = value
	}, sizeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-access-tokens-zone-size: %w", err)
	}

	err = parseStringField(cfgm, "oidc-refresh-tokens-zone-size", ParseSize, func(value string) {
		cfgParams.OIDC.RefreshZoneSize = value
	}, sizeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-refresh-tokens-zone-size: %w", err)
	}

	err = parseStringField(cfgm, "oidc-sids-zone-size", ParseSize, func(value string) {
		cfgParams.OIDC.SIDSZoneSize = value
	}, sizeSuggestion, l, eventLog)
	if err != nil {
		return fmt.Errorf("error parsing oidc-sids-zone-size: %w", err)
	}

	return nil
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
		cfgParams.ZoneSync.ResolverIPV6 = new(zoneSyncResolverIpv6)
	}

	return &cfgParams.ZoneSync, nil
}

//nolint:gocyclo
func parseConfigMapOpenTelemetry(l *slog.Logger, cfgm *v1.ConfigMap, cfgParams *ConfigParams, eventLog record.EventRecorder) (*ConfigParams, error) {
	otelValid := true

	if otelExporterEndpoint, exists := cfgm.Data["otel-exporter-endpoint"]; exists {
		otelExporterEndpoint = strings.TrimSpace(otelExporterEndpoint)
		if otelExporterEndpoint != "" {
			if err := validation.ValidateURI(otelExporterEndpoint); err != nil {
				nl.Warn(l, err)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
				return nil, err
			}
			if err := validation.ValidateDirectiveToken(otelExporterEndpoint); err != nil {
				nl.Warn(l, err)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
				return nil, err
			}
			cfgParams.MainOtelExporterEndpoint = otelExporterEndpoint
		}
	}

	if otelExporterHeaderName, exists := cfgm.Data["otel-exporter-header-name"]; exists {
		otelExporterHeaderName = strings.TrimSpace(otelExporterHeaderName)
		if otelExporterHeaderName != "" {
			errorMessages := validation.ValidateHeaderName(otelExporterHeaderName)
			if len(errorMessages) > 0 {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'otel-exporter-header-name': %q, %s", cfgm.GetNamespace(), cfgm.GetName(), otelExporterHeaderName, strings.Join(errorMessages, "; "))
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				otelValid = false
			} else {
				cfgParams.MainOtelExporterHeaderName = otelExporterHeaderName
			}
		}
	}

	if otelExporterHeaderValue, exists := cfgm.Data["otel-exporter-header-value"]; exists {
		otelExporterHeaderValue = strings.TrimSpace(otelExporterHeaderValue)
		if otelExporterHeaderValue != "" {
			// The template quotes this value plainly, so it is already escaped
			// for NGINX and must be validated as such. Escaping it again here or
			// with printf "%q" would change the header NGINX sends.
			if err := validation.ValidateQuotedDirectiveValue(otelExporterHeaderValue); err != nil {
				// The header usually carries a credential, so the value is not echoed.
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'otel-exporter-header-value': %v", cfgm.GetNamespace(), cfgm.GetName(), err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				otelValid = false
			} else {
				cfgParams.MainOtelExporterHeaderValue = otelExporterHeaderValue
			}
		}
	}

	if otelServiceName, exists := cfgm.Data["otel-service-name"]; exists {
		otelServiceName = strings.TrimSpace(otelServiceName)
		if otelServiceName != "" {
			if err := validation.ValidateRawQuotedDirectiveValue(otelServiceName); err != nil {
				errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for 'otel-service-name': %q: %v, ignoring", cfgm.GetNamespace(), cfgm.GetName(), otelServiceName, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				otelValid = false
			} else {
				cfgParams.MainOtelServiceName = otelServiceName
			}
		}
	}

	if otelTraceInHTTP, exists, err := GetMapKeyAsBool(cfgm.Data, "otel-trace-in-http", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			otelValid = false
		}
		cfgParams.MainOtelTraceInHTTP = otelTraceInHTTP
	}

	if otelTraceContext, exists := cfgm.Data["otel-trace-context"]; exists {
		otelTraceContext = strings.TrimSpace(otelTraceContext)
		switch otelTraceContext {
		case "extract", "inject", "propagate", "ignore":
			cfgParams.MainOtelTraceContext = otelTraceContext
		case "":
		default:
			errorText := fmt.Sprintf(
				"ConfigMap %s/%s: invalid value for 'otel-trace-context': %q, must be one of 'extract', 'inject', 'propagate', 'ignore'",
				cfgm.GetNamespace(), cfgm.GetName(), otelTraceContext,
			)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			otelValid = false
		}
	}

	if (cfgParams.MainOtelExporterHeaderName != "" && cfgParams.MainOtelExporterHeaderValue == "") ||
		(cfgParams.MainOtelExporterHeaderName == "" && cfgParams.MainOtelExporterHeaderValue != "") {
		cfgParams.MainOtelExporterHeaderName = ""
		cfgParams.MainOtelExporterHeaderValue = ""
		errorText := "Both 'otel-exporter-header-name' and 'otel-exporter-header-value' must be set or neither"
		nl.Error(l, errorText)
		eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
		otelValid = false
	}

	if cfgParams.MainOtelExporterEndpoint != "" {
		cfgParams.MainOtelLoadModule = true
	}

	if cfgParams.MainOtelExporterEndpoint == "" &&
		(cfgParams.MainOtelExporterHeaderName != "" ||
			cfgParams.MainOtelExporterHeaderValue != "" ||
			cfgParams.MainOtelServiceName != "" ||
			cfgParams.MainOtelTraceContext != "" ||
			cfgParams.MainOtelTraceInHTTP) {
		errorText := "ConfigMap key 'otel-exporter-endpoint' is required when other otel fields are set"
		nl.Error(l, errorText)
		eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
		otelValid = false
		cfgParams.MainOtelTraceInHTTP = false
		cfgParams.MainOtelExporterHeaderName = ""
		cfgParams.MainOtelTraceContext = ""
		cfgParams.MainOtelExporterHeaderValue = ""
		cfgParams.MainOtelServiceName = ""
	}

	if !otelValid {
		return nil, errors.New("invalid OpenTelemetry configuration")
	}

	return cfgParams, nil
}

// ParseHTTPRedirectCode parses and validates an HTTP redirect code.
func ParseHTTPRedirectCode(code string) (int, error) {
	redirectCode, err := strconv.Atoi(code)
	if err != nil {
		return 0, fmt.Errorf("invalid redirect code: %w", err)
	}

	// Validate that the code is one of the allowed redirect codes: 301, 302, 307, 308
	validCodes := map[int]bool{
		301: true,
		302: true,
		307: true,
		308: true,
	}

	if _, valid := validCodes[redirectCode]; !valid {
		return 0, fmt.Errorf("status code out of accepted range. accepted values are '301', '302', '307', '308'")
	}

	return redirectCode, nil
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
			mgmtCfgParams.SSLVerify = new(sslVerify)
		}
	}

	if resolverAddresses, exists := cfgm.Data["resolver-addresses"]; exists {
		parsedResolverAddresses, err := ParseResolverAddresses(resolverAddresses)
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the resolver-addresses key: got %q: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), resolverAddresses, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.ResolverAddresses = parsedResolverAddresses
		}
	}

	if resolverIpv6, exists, err := GetMapKeyAsBool(cfgm.Data, "resolver-ipv6", cfgm); exists {
		if err != nil {
			nl.Error(l, err)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, err.Error())
			configWarnings = true
		} else {
			mgmtCfgParams.ResolverIPV6 = new(resolverIpv6)
		}
	}

	if resolverValid, exists := cfgm.Data["resolver-valid"]; exists {
		parsedResolverValid, err := ParseTime(resolverValid)
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the resolver-valid key: got %q: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), resolverValid, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.ResolverValid = parsedResolverValid
		}
	}

	if enforceInitialReport, exists, err := GetMapKeyAsBool(cfgm.Data, "enforce-initial-report", cfgm); exists {
		if err != nil {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the enforce-initial-report key: got %t: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), enforceInitialReport, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			mgmtCfgParams.EnforceInitialReport = new(enforceInitialReport)
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

		// Validate interval: check for unsupported units and parse duration in case json schema validation is not used.
		if strings.Contains(i, "ms") || strings.Contains(i, "d") {
			errorText := fmt.Sprintf("Configmap %s/%s: Invalid unit for the interval key: got %q. Only seconds (s), minutes (m), and hours (h) are allowed. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), i)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			configWarnings = true
		} else {
			t, err := time.ParseDuration(i)
			if err != nil {
				errorText := fmt.Sprintf("Configmap %s/%s: Invalid value for the interval key: got %q: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), i, err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configWarnings = true
			} else if t.Seconds() < minimumInterval {
				errorText := fmt.Sprintf("Configmap %s/%s: Value too low for the interval key, got: %v, need higher than %ds. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), i, minimumInterval)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configWarnings = true
			} else if t.Seconds() > maximumInterval {
				errorText := fmt.Sprintf("Configmap %s/%s: Value too high for the interval key, got: %v, maximum allowed is %ds (24h). Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), i, maximumInterval)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configWarnings = true
			} else {
				mgmtCfgParams.Interval = i
			}
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
			proxyUser = strings.TrimSpace(proxyUser)
			if err := validation.ValidateRawQuotedDirectiveValue(proxyUser); err != nil {
				errorText := fmt.Sprintf("Configmap %s/%s: invalid PROXY_USER value: %v. Ignoring.", cfgm.GetNamespace(), cfgm.GetName(), err)
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configWarnings = true
			} else {
				mgmtCfgParams.ProxyUser = proxyUser
			}
		}

		if proxyPass := os.Getenv("PROXY_PASS"); proxyPass != "" {
			proxyPass = strings.TrimSpace(proxyPass)
			if err := validation.ValidateRawQuotedDirectiveValue(proxyPass); err != nil {
				errorText := fmt.Sprintf("Configmap %s/%s: invalid PROXY_PASS value. Ignoring.", cfgm.GetNamespace(), cfgm.GetName())
				nl.Error(l, errorText)
				eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
				configWarnings = true
			} else {
				mgmtCfgParams.ProxyPass = proxyPass
			}
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
		AddHeaders:                         config.MainAddHeaders,
		AddHeaderInherit:                   config.AddHeaderInherit,
		DisableIPV6:                        staticCfgParams.DisableIPV6,
		ErrorLogLevel:                      config.MainErrorLogLevel,
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
		MainOtelLoadModule:                 config.MainOtelLoadModule,
		MainOtelGlobalTraceEnabled:         config.MainOtelTraceInHTTP,
		MainOtelExporterEndpoint:           config.MainOtelExporterEndpoint,
		MainOtelExporterHeaderName:         config.MainOtelExporterHeaderName,
		MainOtelExporterHeaderValue:        config.MainOtelExporterHeaderValue,
		MainOtelServiceName:                config.MainOtelServiceName,
		MainOtelTraceContext:               config.MainOtelTraceContext,
		ProxyProtocol:                      config.ProxyProtocol,
		ResolverAddresses:                  config.ResolverAddresses,
		ResolverIPV6:                       config.ResolverIPV6,
		ResolverTimeout:                    config.ResolverTimeout,
		ResolverValid:                      config.ResolverValid,
		SetRealIPFrom:                      config.SetRealIPFrom,
		ServerNamesHashBucketSize:          config.MainServerNamesHashBucketSize,
		ServerNamesHashMaxSize:             config.MainServerNamesHashMaxSize,
		MapHashBucketSize:                  config.MainMapHashBucketSize,
		MapHashMaxSize:                     config.MainMapHashMaxSize,
		ClientBodyBufferSize:               config.MainClientBodyBufferSize,
		SSLCiphers:                         config.MainServerSSLCiphers,
		SSLDHParam:                         config.MainServerSSLDHParam,
		SSLPreferServerCiphers:             config.MainServerSSLPreferServerCiphers,
		SSLProtocols:                       config.MainServerSSLProtocols,
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
		UseForwardedHeaders:                config.UseForwardedHeaders,
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
		LatencyMetrics:                     staticCfgParams.EnableLatencyMetrics,
		OIDC: version1.OIDCConfig{
			Enable:          staticCfgParams.EnableOIDC,
			PKCETimeout:     config.OIDC.PKCETimeout,
			PKCEZoneSize:    config.OIDC.PKCEZoneSize,
			IDTokenTimeout:  config.OIDC.IDTokenTimeout,
			IDTokenZoneSize: config.OIDC.IDTokenZoneSize,
			AccessTimeout:   config.OIDC.AccessTimeout,
			AccessZoneSize:  config.OIDC.AccessZoneSize,
			RefreshTimeout:  config.OIDC.RefreshTimeout,
			RefreshZoneSize: config.OIDC.RefreshZoneSize,
			SIDSTimeout:     config.OIDC.SIDSTimeout,
			SIDSZoneSize:    config.OIDC.SIDSZoneSize,
		},
		ZoneSyncConfig:          zoneSyncConfig,
		DynamicSSLReloadEnabled: staticCfgParams.DynamicSSLReload,
		StaticSSLPath:           staticCfgParams.StaticSSLPath,
		NginxVersion:            staticCfgParams.NginxVersion,
	}
	return nginxCfg
}

// parseAndValidateAddHeaders parses and validates a comma-separated add-header
// ConfigMap value. Header names are validated with HTTP header name rules
// (rendered unquoted in the NGINX template, so an invalid name would corrupt
// the generated config). Header values are checked for '$', newline, and
// carriage-return characters ('$' is expanded by NGINX as a variable reference;
// newlines/carriage-returns break config line structure).
//
// On the first invalid entry the function returns an error describing the
// problem and no headers are returned (all-or-nothing semantics, consistent
// with how other multi-part ConfigMap keys are handled).
func parseAndValidateAddHeaders(raw string) ([]version2.AddHeader, error) {
	parsed := version1.ParseAddHeaders(raw)
	for _, h := range parsed {
		if msgs := validation.ValidateHeaderName(h.Name); len(msgs) != 0 {
			return nil, fmt.Errorf("invalid 'add-header' header name %q: %s", h.Name, strings.Join(msgs, "; "))
		}
		if msgs := version1.ValidateAddHeaderValue(h.Value); len(msgs) != 0 {
			return nil, fmt.Errorf("invalid 'add-header' value for header %q: %s", h.Name, strings.Join(msgs, "; "))
		}
	}
	return parsed, nil
}

func parseLogFormat(raw string) ([]string, error) {
	values := strings.Split(raw, "\n")
	hasValue := false
	for _, value := range values {
		if err := validation.ValidateSingleQuotedDirectiveValue(value); err != nil {
			return nil, err
		}
		if value != "" {
			hasValue = true
		}
	}
	if !hasValue {
		return nil, errors.New("log format must not be empty")
	}
	return values, nil
}

// parseStringField parses and reports errors for string ConfigMap values.
func parseStringField(cfgm *v1.ConfigMap, key string, parseFunc func(string) (string, error), assignFunc func(string), suggestion string, l *slog.Logger, eventLog record.EventRecorder) error {
	if value, exists := cfgm.Data[key]; exists {
		parsedValue, err := parseFunc(value)
		if err != nil {
			errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for '%s': %q, %v", cfgm.GetNamespace(), cfgm.GetName(), key, value, err)
			if suggestion != "" {
				errorText += ", " + suggestion
			}
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return err
		}
		assignFunc(parsedValue)
	}
	return nil
}

func parseStringSliceField(cfgm *v1.ConfigMap, key string, parseFunc func(string) ([]string, error), assignFunc func([]string), l *slog.Logger, eventLog record.EventRecorder) error {
	if value, exists := cfgm.Data[key]; exists {
		parsedValue, err := parseFunc(value)
		if err != nil {
			errorText := fmt.Sprintf("ConfigMap %s/%s: invalid value for '%s': %q, %v", cfgm.GetNamespace(), cfgm.GetName(), key, value, err)
			nl.Error(l, errorText)
			eventLog.Event(cfgm, v1.EventTypeWarning, nl.EventReasonInvalidValue, errorText)
			return err
		}
		assignFunc(parsedValue)
	}
	return nil
}
