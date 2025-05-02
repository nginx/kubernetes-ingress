package configs

import (
	"context"
	"fmt"
	"slices"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
)

// JWTKeyAnnotation is the annotation where the Secret with a JWK is specified.
const JWTKeyAnnotation = "nginx.com/jwt-key"

// BasicAuthSecretAnnotation is the annotation where the Secret with the HTTP basic user list
const BasicAuthSecretAnnotation = "nginx.org/basic-auth-secret" // #nosec G101

// PathRegexAnnotation is the annotation where the regex location (path) modifier is specified.
const PathRegexAnnotation = "nginx.org/path-regex"

// UseClusterIPAnnotation is the annotation where the use-cluster-ip boolean is specified.
const UseClusterIPAnnotation = "nginx.org/use-cluster-ip"

// AppProtectPolicyAnnotation is where the NGINX App Protect policy is specified
const AppProtectPolicyAnnotation = "appprotect.f5.com/app-protect-policy"

// AppProtectLogConfAnnotation is where the NGINX AppProtect Log Configuration is specified
const AppProtectLogConfAnnotation = "appprotect.f5.com/app-protect-security-log"

// AppProtectLogConfDstAnnotation is where the NGINX AppProtect Log Configuration destination is specified
const AppProtectLogConfDstAnnotation = "appprotect.f5.com/app-protect-security-log-destination"

// AppProtectDosProtectedAnnotation is the namespace/name reference of a DosProtectedResource
const AppProtectDosProtectedAnnotation = "appprotectdos.f5.com/app-protect-dos-resource"

// nginxMeshInternalRoute specifies if the ingress resource is an internal route.
const nginxMeshInternalRouteAnnotation = "nsm.nginx.com/internal-route"

var masterDenylist = map[string]bool{
	"nginx.org/rewrites":                      true,
	"nginx.org/ssl-services":                  true,
	"nginx.org/grpc-services":                 true,
	"nginx.org/websocket-services":            true,
	"nginx.com/sticky-cookie-services":        true,
	"nginx.com/health-checks":                 true,
	"nginx.com/health-checks-mandatory":       true,
	"nginx.com/health-checks-mandatory-queue": true,
	UseClusterIPAnnotation:                    true,
}

var minionDenylist = map[string]bool{
	"nginx.org/proxy-hide-headers":                      true,
	"nginx.org/proxy-pass-headers":                      true,
	"nginx.org/redirect-to-https":                       true,
	"ingress.kubernetes.io/ssl-redirect":                true,
	"nginx.org/hsts":                                    true,
	"nginx.org/hsts-max-age":                            true,
	"nginx.org/hsts-include-subdomains":                 true,
	"nginx.org/server-tokens":                           true,
	"nginx.org/listen-ports":                            true,
	"nginx.org/listen-ports-ssl":                        true,
	"nginx.org/server-snippets":                         true,
	"appprotect.f5.com/app_protect_enable":              true,
	"appprotect.f5.com/app_protect_policy":              true,
	"appprotect.f5.com/app_protect_security_log_enable": true,
	"appprotect.f5.com/app_protect_security_log":        true,
	"appprotectdos.f5.com/app-protect-dos-resource":     true,
}

var minionInheritanceList = map[string]bool{
	"nginx.org/proxy-connect-timeout":    true,
	"nginx.org/proxy-read-timeout":       true,
	"nginx.org/proxy-send-timeout":       true,
	"nginx.org/client-max-body-size":     true,
	"nginx.org/proxy-buffering":          true,
	"nginx.org/proxy-buffers":            true,
	"nginx.org/proxy-buffer-size":        true,
	"nginx.org/proxy-max-temp-file-size": true,
	"nginx.org/upstream-zone-size":       true,
	"nginx.org/location-snippets":        true,
	"nginx.org/lb-method":                true,
	"nginx.org/keepalive":                true,
	"nginx.org/max-fails":                true,
	"nginx.org/max-conns":                true,
	"nginx.org/fail-timeout":             true,
	"nginx.org/limit-req-rate":           true,
	"nginx.org/limit-req-key":            true,
	"nginx.org/limit-req-zone-size":      true,
	"nginx.org/limit-req-delay":          true,
	"nginx.org/limit-req-no-delay":       true,
	"nginx.org/limit-req-burst":          true,
	"nginx.org/limit-req-dry-run":        true,
	"nginx.org/limit-req-log-level":      true,
	"nginx.org/limit-req-reject-code":    true,
	"nginx.org/limit-req-scale":          true,
}

var validPathRegex = map[string]bool{
	"case_sensitive":   true,
	"case_insensitive": true,
	"exact":            true,
}

// List of Ingress Annotation Keys used by the Ingress Controller
var allowedAnnotationKeys = []string{
	"nginx.org",
	"nginx.com",
	"f5.com",
	"ingress.kubernetes.io/ssl-redirect",
}

func parseAnnotations(ingEx *IngressEx, baseCfgParams *ConfigParams, isPlus bool, hasAppProtect bool, hasAppProtectDos bool, enableInternalRoutes bool) ConfigParams {
	l := nl.LoggerFromContext(baseCfgParams.Context)
	cfgParams := *baseCfgParams

	if lbMethod, exists := ingEx.Ingress.Annotations["nginx.org/lb-method"]; exists {
		if isPlus {
			if parsedMethod, err := ParseLBMethodForPlus(lbMethod); err != nil {
				nl.Errorf(l, "Ingress %s/%s: Invalid value for the nginx.org/lb-method: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), lbMethod, err)
			} else {
				cfgParams.LBMethod = parsedMethod
			}
		} else {
			if parsedMethod, err := ParseLBMethod(lbMethod); err != nil {
				nl.Errorf(l, "Ingress %s/%s: Invalid value for the nginx.org/lb-method: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), lbMethod, err)
			} else {
				cfgParams.LBMethod = parsedMethod
			}
		}
	}

	if healthCheckEnabled, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.com/health-checks", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		}
		if isPlus {
			cfgParams.HealthCheckEnabled = healthCheckEnabled
		} else {
			nl.Warn(l, "Annotation 'nginx.com/health-checks' requires NGINX Plus")
		}
	}

	if cfgParams.HealthCheckEnabled {
		if healthCheckMandatory, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.com/health-checks-mandatory", ingEx.Ingress); exists {
			if err != nil {
				nl.Error(l, err)
			}
			cfgParams.HealthCheckMandatory = healthCheckMandatory
		}
	}

	if cfgParams.HealthCheckMandatory {
		if healthCheckQueue, exists, err := GetMapKeyAsInt64(ingEx.Ingress.Annotations, "nginx.com/health-checks-mandatory-queue", ingEx.Ingress); exists {
			if err != nil {
				nl.Error(l, err)
			}
			cfgParams.HealthCheckMandatoryQueue = healthCheckQueue
		}
	}

	if slowStart, exists := ingEx.Ingress.Annotations["nginx.com/slow-start"]; exists {
		if parsedSlowStart, err := ParseTime(slowStart); err != nil {
			nl.Errorf(l, "Ingress %s/%s: Invalid value nginx.org/slow-start: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), slowStart, err)
		} else {
			if isPlus {
				cfgParams.SlowStart = parsedSlowStart
			} else {
				nl.Warn(l, "Annotation 'nginx.com/slow-start' requires NGINX Plus")
			}
		}
	}

	if serverTokens, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/server-tokens", ingEx.Ingress); exists {
		if err != nil {
			if isPlus {
				cfgParams.ServerTokens = ingEx.Ingress.Annotations["nginx.org/server-tokens"]
			} else {
				nl.Error(l, err)
			}
		} else {
			cfgParams.ServerTokens = "off"
			if serverTokens {
				cfgParams.ServerTokens = "on"
			}
		}
	}

	if serverSnippets, exists := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/server-snippets", ingEx.Ingress, "\n"); exists {
		cfgParams.ServerSnippets = serverSnippets
	}

	if locationSnippets, exists := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/location-snippets", ingEx.Ingress, "\n"); exists {
		cfgParams.LocationSnippets = locationSnippets
	}

	if proxyConnectTimeout, exists := ingEx.Ingress.Annotations["nginx.org/proxy-connect-timeout"]; exists {
		if parsedProxyConnectTimeout, err := ParseTime(proxyConnectTimeout); err != nil {
			nl.Errorf(l, "Ingress %s/%s: Invalid value nginx.org/proxy-connect-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), proxyConnectTimeout, err)
		} else {
			cfgParams.ProxyConnectTimeout = parsedProxyConnectTimeout
		}
	}

	if proxyReadTimeout, exists := ingEx.Ingress.Annotations["nginx.org/proxy-read-timeout"]; exists {
		if parsedProxyReadTimeout, err := ParseTime(proxyReadTimeout); err != nil {
			nl.Errorf(l, "Ingress %s/%s: Invalid value nginx.org/proxy-read-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), proxyReadTimeout, err)
		} else {
			cfgParams.ProxyReadTimeout = parsedProxyReadTimeout
		}
	}

	if proxySendTimeout, exists := ingEx.Ingress.Annotations["nginx.org/proxy-send-timeout"]; exists {
		if parsedProxySendTimeout, err := ParseTime(proxySendTimeout); err != nil {
			nl.Errorf(l, "Ingress %s/%s: Invalid value nginx.org/proxy-send-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), proxySendTimeout, err)
		} else {
			cfgParams.ProxySendTimeout = parsedProxySendTimeout
		}
	}

	if proxyHideHeaders, exists := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/proxy-hide-headers", ingEx.Ingress, ","); exists {
		cfgParams.ProxyHideHeaders = proxyHideHeaders
	}

	if proxyPassHeaders, exists := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/proxy-pass-headers", ingEx.Ingress, ","); exists {
		cfgParams.ProxyPassHeaders = proxyPassHeaders
	}

	if proxySetHeaders, exists := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/proxy-set-headers", ingEx.Ingress, ","); exists {
		parsedHeaders := parseProxySetHeaders(proxySetHeaders)
		cfgParams.ProxySetHeaders = parsedHeaders
	}

	if clientMaxBodySize, exists := ingEx.Ingress.Annotations["nginx.org/client-max-body-size"]; exists {
		cfgParams.ClientMaxBodySize = clientMaxBodySize
	}

	if redirectToHTTPS, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/redirect-to-https", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.RedirectToHTTPS = redirectToHTTPS
		}
	}

	if sslRedirect, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "ingress.kubernetes.io/ssl-redirect", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.SSLRedirect = sslRedirect
		}
	}

	if proxyBuffering, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/proxy-buffering", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.ProxyBuffering = proxyBuffering
		}
	}

	if hsts, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/hsts", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			parsingErrors := false

			hstsMaxAge, existsMA, err := GetMapKeyAsInt64(ingEx.Ingress.Annotations, "nginx.org/hsts-max-age", ingEx.Ingress)
			if existsMA && err != nil {
				nl.Error(l, err)
				parsingErrors = true
			}
			hstsIncludeSubdomains, existsIS, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/hsts-include-subdomains", ingEx.Ingress)
			if existsIS && err != nil {
				nl.Error(l, err)
				parsingErrors = true
			}
			hstsBehindProxy, existsBP, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/hsts-behind-proxy", ingEx.Ingress)
			if existsBP && err != nil {
				nl.Error(l, err)
				parsingErrors = true
			}

			if parsingErrors {
				nl.Errorf(l, "Ingress %s/%s: There are configuration issues with hsts annotations, skipping annotations for all hsts settings", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName())
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

	if proxyBuffers, exists := ingEx.Ingress.Annotations["nginx.org/proxy-buffers"]; exists {
		cfgParams.ProxyBuffers = proxyBuffers
	}

	if proxyBufferSize, exists := ingEx.Ingress.Annotations["nginx.org/proxy-buffer-size"]; exists {
		cfgParams.ProxyBufferSize = proxyBufferSize
	}

	if upstreamZoneSize, exists := ingEx.Ingress.Annotations["nginx.org/upstream-zone-size"]; exists {
		cfgParams.UpstreamZoneSize = upstreamZoneSize
	}

	if proxyMaxTempFileSize, exists := ingEx.Ingress.Annotations["nginx.org/proxy-max-temp-file-size"]; exists {
		cfgParams.ProxyMaxTempFileSize = proxyMaxTempFileSize
	}

	if isPlus {
		if jwtRealm, exists := ingEx.Ingress.Annotations["nginx.com/jwt-realm"]; exists {
			cfgParams.JWTRealm = jwtRealm
		}
		if jwtKey, exists := ingEx.Ingress.Annotations[JWTKeyAnnotation]; exists {
			cfgParams.JWTKey = jwtKey
		}
		if jwtToken, exists := ingEx.Ingress.Annotations["nginx.com/jwt-token"]; exists {
			cfgParams.JWTToken = jwtToken
		}
		if jwtLoginURL, exists := ingEx.Ingress.Annotations["nginx.com/jwt-login-url"]; exists {
			cfgParams.JWTLoginURL = jwtLoginURL
		}
	}

	if basicSecret, exists := ingEx.Ingress.Annotations[BasicAuthSecretAnnotation]; exists {
		cfgParams.BasicAuthSecret = basicSecret
	}
	if basicRealm, exists := ingEx.Ingress.Annotations["nginx.org/basic-auth-realm"]; exists {
		cfgParams.BasicAuthRealm = basicRealm
	}

	if values, exists := ingEx.Ingress.Annotations["nginx.org/listen-ports"]; exists {
		ports, err := ParsePortList(values)
		if err != nil {
			nl.Errorf(l, "In %v nginx.org/listen-ports contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
		}
		if len(ports) > 0 {
			cfgParams.Ports = ports
		}
	}

	if values, exists := ingEx.Ingress.Annotations["nginx.org/listen-ports-ssl"]; exists {
		sslPorts, err := ParsePortList(values)
		if err != nil {
			nl.Errorf(l, "In %v nginx.org/listen-ports-ssl contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
		}
		if len(sslPorts) > 0 {
			cfgParams.SSLPorts = sslPorts
		}
	}

	if keepalive, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "nginx.org/keepalive", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.Keepalive = keepalive
		}
	}

	if maxFails, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "nginx.org/max-fails", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.MaxFails = maxFails
		}
	}

	if maxConns, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "nginx.org/max-conns", ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.MaxConns = maxConns
		}
	}

	if failTimeout, exists := ingEx.Ingress.Annotations["nginx.org/fail-timeout"]; exists {
		if parsedFailTimeout, err := ParseTime(failTimeout); err != nil {
			nl.Errorf(l, "Ingress %s/%s: Invalid value nginx.org/fail-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), failTimeout, err)
		} else {
			cfgParams.FailTimeout = parsedFailTimeout
		}
	}

	if hasAppProtect {
		if appProtectEnable, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "appprotect.f5.com/app-protect-enable", ingEx.Ingress); exists {
			if err != nil {
				nl.Error(l, err)
			} else {
				if appProtectEnable {
					cfgParams.AppProtectEnable = "on"
				} else {
					cfgParams.AppProtectEnable = "off"
				}
			}
		}

		if appProtectLogEnable, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "appprotect.f5.com/app-protect-security-log-enable", ingEx.Ingress); exists {
			if err != nil {
				nl.Error(l, err)
			} else {
				if appProtectLogEnable {
					cfgParams.AppProtectLogEnable = "on"
				} else {
					cfgParams.AppProtectLogEnable = "off"
				}
			}
		}

	}
	if hasAppProtectDos {
		if appProtectDosResource, exists := ingEx.Ingress.Annotations["appprotectdos.f5.com/app-protect-dos-resource"]; exists {
			cfgParams.AppProtectDosResource = appProtectDosResource
		}
	}
	if enableInternalRoutes {
		if spiffeServerCerts, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, nginxMeshInternalRouteAnnotation, ingEx.Ingress); exists {
			if err != nil {
				nl.Error(l, err)
			} else {
				cfgParams.SpiffeServerCerts = spiffeServerCerts
			}
		}
	}

	if pathRegex, exists := ingEx.Ingress.Annotations[PathRegexAnnotation]; exists {
		_, ok := validPathRegex[pathRegex]
		if !ok {
			nl.Errorf(l, "Ingress %s/%s: Invalid value nginx.org/path-regex: got %q. Allowed values: 'case_sensitive', 'case_insensitive', 'exact'", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), pathRegex)
		}
	}

	if useClusterIP, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, UseClusterIPAnnotation, ingEx.Ingress); exists {
		if err != nil {
			nl.Error(l, err)
		} else {
			cfgParams.UseClusterIP = useClusterIP
		}
	}

	for _, err := range parseRateLimitAnnotations(ingEx.Ingress.Annotations, &cfgParams, ingEx.Ingress) {
		nl.Error(l, err)
	}

	return cfgParams
}

// parseRateLimitAnnotations parses rate-limiting-related annotations and places them into CfgParams. Occurring errors are collected and returned, but do not abort parsing.
//
//gocyclo:ignore
func parseRateLimitAnnotations(annotations map[string]string, cfgParams *ConfigParams, context apiObject) []error {
	errors := make([]error, 0)
	if requestRateLimit, exists := annotations["nginx.org/limit-req-rate"]; exists {
		if rate, err := ParseRequestRate(requestRateLimit); err != nil {
			errors = append(errors, fmt.Errorf("ingress %s/%s: invalid value for nginx.org/limit-req-rate: got %s: %w", context.GetNamespace(), context.GetName(), requestRateLimit, err))
		} else {
			cfgParams.LimitReqRate = rate
		}
	}
	if requestRateKey, exists := annotations["nginx.org/limit-req-key"]; exists {
		cfgParams.LimitReqKey = requestRateKey
	}
	if requestRateZoneSize, exists := annotations["nginx.org/limit-req-zone-size"]; exists {
		if size, err := ParseSize(requestRateZoneSize); err != nil {
			errors = append(errors, fmt.Errorf("ingress %s/%s: invalid value for nginx.org/limit-req-zone-size: got %s: %w", context.GetNamespace(), context.GetName(), requestRateZoneSize, err))
		} else {
			cfgParams.LimitReqZoneSize = size
		}
	}
	if requestRateDelay, exists, err := GetMapKeyAsInt(annotations, "nginx.org/limit-req-delay", context); exists {
		if err != nil {
			errors = append(errors, err)
		} else {
			cfgParams.LimitReqDelay = requestRateDelay
		}
	}
	if requestRateNoDelay, exists, err := GetMapKeyAsBool(annotations, "nginx.org/limit-req-no-delay", context); exists {
		if err != nil {
			errors = append(errors, err)
		} else {
			cfgParams.LimitReqNoDelay = requestRateNoDelay
		}
	}
	if requestRateBurst, exists, err := GetMapKeyAsInt(annotations, "nginx.org/limit-req-burst", context); exists {
		if err != nil {
			errors = append(errors, err)
		} else {
			cfgParams.LimitReqBurst = requestRateBurst
		}
	}
	if requestRateDryRun, exists, err := GetMapKeyAsBool(annotations, "nginx.org/limit-req-dry-run", context); exists {
		if err != nil {
			errors = append(errors, err)
		} else {
			cfgParams.LimitReqDryRun = requestRateDryRun
		}
	}
	if requestRateLogLevel, exists := annotations["nginx.org/limit-req-log-level"]; exists {
		if !slices.Contains([]string{"info", "notice", "warn", "error"}, requestRateLogLevel) {
			errors = append(errors, fmt.Errorf("ingress %s/%s: invalid value for nginx.org/limit-req-log-level: got %s", context.GetNamespace(), context.GetName(), requestRateLogLevel))
		} else {
			cfgParams.LimitReqLogLevel = requestRateLogLevel
		}
	}
	if requestRateRejectCode, exists, err := GetMapKeyAsInt(annotations, "nginx.org/limit-req-reject-code", context); exists {
		if err != nil {
			errors = append(errors, err)
		} else {
			cfgParams.LimitReqRejectCode = requestRateRejectCode
		}
	}
	if requestRateScale, exists, err := GetMapKeyAsBool(annotations, "nginx.org/limit-req-scale", context); exists {
		if err != nil {
			errors = append(errors, err)
		} else {
			cfgParams.LimitReqScale = requestRateScale
		}
	}
	return errors
}

func getWebsocketServices(ingEx *IngressEx) map[string]bool {
	if value, exists := ingEx.Ingress.Annotations["nginx.org/websocket-services"]; exists {
		return ParseServiceList(value)
	}
	return nil
}

func getRewrites(ctx context.Context, ingEx *IngressEx) map[string]string {
	l := nl.LoggerFromContext(ctx)
	if value, exists := ingEx.Ingress.Annotations["nginx.org/rewrites"]; exists {
		rewrites, err := ParseRewriteList(value)
		if err != nil {
			nl.Error(l, err)
		}
		return rewrites
	}
	return nil
}

func getSSLServices(ingEx *IngressEx) map[string]bool {
	if value, exists := ingEx.Ingress.Annotations["nginx.org/ssl-services"]; exists {
		return ParseServiceList(value)
	}
	return nil
}

func getGrpcServices(ingEx *IngressEx) map[string]bool {
	if value, exists := ingEx.Ingress.Annotations["nginx.org/grpc-services"]; exists {
		return ParseServiceList(value)
	}
	return nil
}

func getSessionPersistenceServices(ctx context.Context, ingEx *IngressEx) map[string]string {
	l := nl.LoggerFromContext(ctx)
	if value, exists := ingEx.Ingress.Annotations["nginx.com/sticky-cookie-services"]; exists {
		services, err := ParseStickyServiceList(value)
		if err != nil {
			nl.Error(l, err)
		}
		return services
	}
	return nil
}

func filterMasterAnnotations(annotations map[string]string) []string {
	var removedAnnotations []string

	for key := range annotations {
		if _, notAllowed := masterDenylist[key]; notAllowed {
			removedAnnotations = append(removedAnnotations, key)
			delete(annotations, key)
		}
	}

	return removedAnnotations
}

func filterMinionAnnotations(annotations map[string]string) []string {
	var removedAnnotations []string

	for key := range annotations {
		if _, notAllowed := minionDenylist[key]; notAllowed {
			removedAnnotations = append(removedAnnotations, key)
			delete(annotations, key)
		}
	}

	return removedAnnotations
}

func mergeMasterAnnotationsIntoMinion(minionAnnotations map[string]string, masterAnnotations map[string]string) {
	for key, val := range masterAnnotations {
		if _, exists := minionAnnotations[key]; !exists {
			if _, allowed := minionInheritanceList[key]; allowed {
				minionAnnotations[key] = val
			}
		}
	}
}
