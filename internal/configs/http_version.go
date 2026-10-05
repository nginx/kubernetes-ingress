package configs

const (
	// proxyHTTPVersion10 selects HTTP/1.0 for upstream connections. HTTP/1.0 has no persistent
	// connections or Upgrade mechanism, so the templates send "Connection: close" for it.
	// Ref.: https://blog.nginx.org/blog/keep-alive-to-upstreams-is-now-default-in-nginx-1-29-7
	proxyHTTPVersion10 = "1.0"

	// proxyHTTPVersion2 selects HTTP/2 for upstream connections. The proxy_http_version
	// directive accepts this value from NGINX 1.29.4 onwards.
	// Ref.: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version
	proxyHTTPVersion2 = "2"

	// appProtocolH2C is the standard Kubernetes appProtocol value for cleartext HTTP/2.
	// Ref.: https://kubernetes.io/docs/concepts/services-networking/service/#application-protocol
	appProtocolH2C = "kubernetes.io/h2c"
)

// resolveProxyHTTPVersion returns the HTTP version to use for upstream connections of a single
// location, applying the documented precedence:
//
//	explicit configuration (Ingress annotation / VirtualServer upstream field)
//	> Service appProtocol ("kubernetes.io/h2c" implies HTTP/2)
//	> unset
//
// An empty return value means "do not render proxy_http_version" and lets NGINX apply its own
// default, which is 1.1 as of NGINX 1.29.7. The templates must therefore only render the
// directive when this value is non-empty: a bare `proxy_http_version ;` is not valid config.
func resolveProxyHTTPVersion(configured string, appProtocol string) string {
	if configured != "" {
		return configured
	}
	if appProtocol == appProtocolH2C {
		return proxyHTTPVersion2
	}
	return ""
}
