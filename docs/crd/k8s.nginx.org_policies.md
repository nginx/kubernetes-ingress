# Policy

**Group:** `k8s.nginx.org`  
**Version:** `v1`  
**Kind:** `Policy`  
**Scope:** `Namespaced`

## Description

The `Policy` resource defines a security policy for `VirtualServer` and `VirtualServerRoute` resources. It allows you to apply various policies such as access control, authentication, rate limiting, and WAF protection.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `accessControl` | `object` | The access control policy based on the client IP address. |
| `accessControl.allow` | `array[string]` | Configuration field. |
| `accessControl.deny` | `array[string]` | Configuration field. |
| `apiKey` | `object` | The API Key policy configures NGINX to authorize requests which provide a valid API Key in a specified header or query param. |
| `apiKey.clientSecret` | `string` | The key to which the API key is applied. Can contain text, variables, or a combination of them. Accepted variables are $http_, $arg_, $cookie_. |
| `apiKey.suppliedIn` | `object` | The location of the API Key. For example, $http_auth, $arg_apikey, $cookie_auth. Accepted variables are $http_, $arg_, $cookie_. |
| `apiKey.suppliedIn.header` | `array[string]` | The location of the API Key as a request header. For example, $http_auth. Accepted variables are $http_. |
| `apiKey.suppliedIn.query` | `array[string]` | The location of the API Key as a query param. For example, $arg_apikey. Accepted variables are $arg_. |
| `basicAuth` | `object` | The basic auth policy configures NGINX to authenticate client requests using HTTP Basic authentication credentials. |
| `basicAuth.realm` | `string` | The realm for the basic authentication. |
| `basicAuth.secret` | `string` | The name of the Kubernetes secret that stores the Htpasswd configuration. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/htpasswd, and the config must be stored in the secret under the key htpasswd, otherwise the secret will be rejected as invalid. |
| `cache` | `object` | The Cache Key defines a cache policy for proxy caching |
| `cache.allowedCodes` | `array` | AllowedCodes defines which HTTP response codes should be cached. Accepts either: - The string "any" to cache all response codes (must be the only element) - A list of HTTP status codes as integers (100-599) Examples: ["any"], [200, 301, 404], [200]. Invalid: ["any", 200] (cannot mix "any" with specific codes). |
| `cache.allowedMethods` | `array[string]` | AllowedMethods defines which HTTP methods should be cached. Only "GET", "HEAD", and "POST" are supported by NGINX proxy_cache_methods directive. GET and HEAD are always cached by default even if not specified. Maximum of 3 items allowed. Examples: ["GET"], ["GET", "HEAD", "POST"]. Invalid methods: PUT, DELETE, PATCH, etc. |
| `cache.cachePurgeAllow` | `array[string]` | CachePurgeAllow defines IP addresses or CIDR blocks allowed to purge cache. This feature is only available in NGINX Plus. Examples: ["192.168.1.100", "10.0.0.0/8", "::1"]. Invalid in NGINX OSS (will be ignored). |
| `cache.cacheZoneName` | `string` | CacheZoneName defines the name of the cache zone. Must start with a lowercase letter, followed by alphanumeric characters or underscores, and end with an alphanumeric character. Single lowercase letters are also allowed. Examples: "cache", "my_cache", "cache1". |
| `cache.cacheZoneSize` | `string` | CacheZoneSize defines the size of the cache zone. Must be a number followed by a size unit: 'k' for kilobytes, 'm' for megabytes, or 'g' for gigabytes. Examples: "10m", "1g", "512k". |
| `cache.levels` | `string` | Levels defines the cache directory hierarchy levels for storing cached files. Must be in format "X:Y" or "X:Y:Z" where X, Y, Z are either 1 or 2. This controls the number of subdirectory levels and their name lengths. Examples: "1:2", "2:2", "1:2:2". Invalid: "3:1", "1:3", "1:2:3". |
| `cache.overrideUpstreamCache` | `boolean` | OverrideUpstreamCache controls whether to override upstream cache headers (using proxy_ignore_headers directive). When true, NGINX will ignore cache-related headers from upstream servers like Cache-Control, Expires, etc. Default: false. |
| `cache.time` | `string` | Time defines the default cache time. Required when allowedCodes is specified. Must be a number followed by a time unit: 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days. Examples: "30s", "5m", "1h", "2d". |
| `egressMTLS` | `object` | The EgressMTLS policy configures upstreams authentication and certificate verification. |
| `egressMTLS.ciphers` | `string` | Specifies the enabled ciphers for requests to an upstream HTTPS server. The default is DEFAULT. |
| `egressMTLS.protocols` | `string` | Specifies the protocols for requests to an upstream HTTPS server. The default is TLSv1 TLSv1.1 TLSv1.2. |
| `egressMTLS.serverName` | `boolean` | Enables passing of the server name through Server Name Indication extension. |
| `egressMTLS.sessionReuse` | `boolean` | Enables reuse of SSL sessions to the upstreams. The default is true. |
| `egressMTLS.sslName` | `string` | Allows overriding the server name used to verify the certificate of the upstream HTTPS server. |
| `egressMTLS.tlsSecret` | `string` | The name of the Kubernetes secret that stores the TLS certificate and key. It must be in the same namespace as the Policy resource. The secret must be of the type kubernetes.io/tls, the certificate must be stored in the secret under the key tls.crt, and the key must be stored under the key tls.key, otherwise the secret will be rejected as invalid. |
| `egressMTLS.trustedCertSecret` | `string` | The name of the Kubernetes secret that stores the CA certificate. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/ca, and the certificate must be stored in the secret under the key ca.crt, otherwise the secret will be rejected as invalid. |
| `egressMTLS.verifyDepth` | `integer` | Sets the verification depth in the proxied HTTPS server certificates chain. The default is 1. |
| `egressMTLS.verifyServer` | `boolean` | Enables verification of the upstream HTTPS server certificate. |
| `ingressClassName` | `string` | Specifies which instance of NGINX Ingress Controller must handle the Policy resource. |
| `ingressMTLS` | `object` | The IngressMTLS policy configures client certificate verification. |
| `ingressMTLS.clientCertSecret` | `string` | The name of the Kubernetes secret that stores the CA certificate. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/ca, and the certificate must be stored in the secret under the key ca.crt, otherwise the secret will be rejected as invalid. |
| `ingressMTLS.crlFileName` | `string` | The file name of the Certificate Revocation List. NGINX Ingress Controller will look for this file in /etc/nginx/secrets |
| `ingressMTLS.verifyClient` | `string` | Verification for the client. Possible values are "on", "off", "optional", "optional_no_ca". The default is "on". |
| `ingressMTLS.verifyDepth` | `integer` | Sets the verification depth in the client certificates chain. The default is 1. |
| `jwt` | `object` | The JWT policy configures NGINX Plus to authenticate client requests using JSON Web Tokens. |
| `jwt.jwksURI` | `string` | The remote URI where the request will be sent to retrieve JSON Web Key set |
| `jwt.keyCache` | `string` | Enables in-memory caching of JWKS (JSON Web Key Sets) that are obtained from the jwksURI and sets a valid time for expiration. |
| `jwt.realm` | `string` | The realm of the JWT. |
| `jwt.secret` | `string` | The name of the Kubernetes secret that stores the Htpasswd configuration. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/htpasswd, and the config must be stored in the secret under the key htpasswd, otherwise the secret will be rejected as invalid. |
| `jwt.sniEnabled` | `boolean` | Enables SNI (Server Name Indication) for the JWT policy. This is useful when the remote server requires SNI to serve the correct certificate. |
| `jwt.sniName` | `string` | The SNI name to use when connecting to the remote server. If not set, the hostname from the ``jwksURI`` will be used. |
| `jwt.token` | `string` | The token specifies a variable that contains the JSON Web Token. By default the JWT is passed in the Authorization header as a Bearer Token. JWT may be also passed as a cookie or a part of a query string, for example: $cookie_auth_token. Accepted variables are $http_, $arg_, $cookie_. |
| `oidc` | `object` | The OpenID Connect policy configures NGINX to authenticate client requests by validating a JWT token against an OAuth2/OIDC token provider, such as Auth0 or Keycloak. |
| `oidc.accessTokenEnable` | `boolean` | Option of whether Bearer token is used to authorize NGINX to access protected backend. |
| `oidc.authEndpoint` | `string` | URL for the authorization endpoint provided by your OpenID Connect provider. |
| `oidc.authExtraArgs` | `array[string]` | A list of extra URL arguments to pass to the authorization endpoint provided by your OpenID Connect provider. Arguments must be URL encoded, multiple arguments may be included in the list, for example [ arg1=value1, arg2=value2 ] |
| `oidc.clientID` | `string` | The client ID provided by your OpenID Connect provider. |
| `oidc.clientSecret` | `string` | The name of the Kubernetes secret that stores the client secret provided by your OpenID Connect provider. It must be in the same namespace as the Policy resource. The secret must be of the type nginx.org/oidc, and the secret under the key client-secret, otherwise the secret will be rejected as invalid. If PKCE is enabled, this should be not configured. |
| `oidc.endSessionEndpoint` | `string` | URL provided by your OpenID Connect provider to request the end user be logged out. |
| `oidc.jwksURI` | `string` | URL for the JSON Web Key Set (JWK) document provided by your OpenID Connect provider. |
| `oidc.pkceEnable` | `boolean` | Switches Proof Key for Code Exchange on. The OpenID client needs to be in public mode. clientSecret is not used in this mode. |
| `oidc.postLogoutRedirectURI` | `string` | URI to redirect to after the logout has been performed. Requires endSessionEndpoint. The default is /_logout. |
| `oidc.redirectURI` | `string` | Allows overriding the default redirect URI. The default is /_codexch. |
| `oidc.scope` | `string` | List of OpenID Connect scopes. The scope openid always needs to be present and others can be added concatenating them with a + sign, for example openid+profile+email, openid+email+userDefinedScope. The default is openid. |
| `oidc.tokenEndpoint` | `string` | URL for the token endpoint provided by your OpenID Connect provider. |
| `oidc.zoneSyncLeeway` | `integer` | Specifies the maximum timeout in milliseconds for synchronizing ID/access tokens and shared values between Ingress Controller pods. The default is 200. |
| `rateLimit` | `object` | The rate limit policy controls the rate of processing requests per a defined key. |
| `rateLimit.burst` | `integer` | Excessive requests are delayed until their number exceeds the burst size, in which case the request is terminated with an error. |
| `rateLimit.condition` | `object` | Add a condition to a rate-limit policy. |
| `rateLimit.condition.default` | `boolean` | Sets the rate limit in this policy to be the default if no conditions are met. In a group of policies with the same condition, only one policy can be the default. |
| `rateLimit.condition.jwt` | `object` | Defines a JWT condition to rate limit against. |
| `rateLimit.condition.jwt.claim` | `string` | The JWT claim to be rate limit by. Nested claims should be separated by "." |
| `rateLimit.condition.jwt.match` | `string` | The value of the claim to match against. |
| `rateLimit.condition.variables` | `array` | Defines a Variables condition to rate limit against. |
| `rateLimit.condition.variables[].match` | `string` | The value of the variable to match against. |
| `rateLimit.condition.variables[].name` | `string` | The name of the variable to match against. |
| `rateLimit.delay` | `integer` | The delay parameter specifies a limit at which excessive requests become delayed. If not set all excessive requests are delayed. |
| `rateLimit.dryRun` | `boolean` | Enables the dry run mode. In this mode, the rate limit is not actually applied, but the number of excessive requests is accounted as usual in the shared memory zone. |
| `rateLimit.key` | `string` | The key to which the rate limit is applied. Can contain text, variables, or a combination of them. Variables must be surrounded by ${}. For example: ${binary_remote_addr}. Accepted variables are $binary_remote_addr, $request_uri, $request_method, $url, $http_, $args, $arg_, $cookie_,$jwt_claim_ . |
| `rateLimit.logLevel` | `string` | Sets the desired logging level for cases when the server refuses to process requests due to rate exceeding, or delays request processing. Allowed values are info, notice, warn or error. Default is error. |
| `rateLimit.noDelay` | `boolean` | Disables the delaying of excessive requests while requests are being limited. Overrides delay if both are set. |
| `rateLimit.rate` | `string` | The rate of requests permitted. The rate is specified in requests per second (r/s) or requests per minute (r/m). |
| `rateLimit.rejectCode` | `integer` | Sets the status code to return in response to rejected requests. Must fall into the range 400..599. Default is 503. |
| `rateLimit.scale` | `boolean` | Enables a constant rate-limit by dividing the configured rate by the number of nginx-ingress pods currently serving traffic. This adjustment ensures that the rate-limit remains consistent, even as the number of nginx-pods fluctuates due to autoscaling. This will not work properly if requests from a client are not evenly distributed across all ingress pods (Such as with sticky sessions, long lived TCP Connections with many requests, and so forth). In such cases using zone-sync instead would give better results. Enabling zone-sync will suppress this setting. |
| `rateLimit.zoneSize` | `string` | Size of the shared memory zone. Only positive values are allowed. Allowed suffixes are k or m, if none are present k is assumed. |
| `waf` | `object` | The WAF policy configures WAF and log configuration policies for NGINX AppProtect |
| `waf.apBundle` | `string` | The App Protect WAF policy bundle. Mutually exclusive with apPolicy. |
| `waf.apPolicy` | `string` | The App Protect WAF policy of the WAF. Accepts an optional namespace. Mutually exclusive with apBundle. |
| `waf.enable` | `boolean` | Enables NGINX App Protect WAF. |
| `waf.securityLog` | `object` | SecurityLog defines the security log of a WAF policy. |
| `waf.securityLog.apLogBundle` | `string` | The App Protect WAF log bundle resource. Only works with apBundle. |
| `waf.securityLog.apLogConf` | `string` | The App Protect WAF log conf resource. Accepts an optional namespace. Only works with apPolicy. |
| `waf.securityLog.enable` | `boolean` | Enables security log. |
| `waf.securityLog.logDest` | `string` | The log destination for the security log. Only accepted variables are syslog:server=<ip-address>; localhost; fqdn>:<port>, stderr, <absolute path to file>. |
| `waf.securityLogs` | `array` | List of configuration values. |
| `waf.securityLogs[].apLogBundle` | `string` | The App Protect WAF log bundle resource. Only works with apBundle. |
| `waf.securityLogs[].apLogConf` | `string` | The App Protect WAF log conf resource. Accepts an optional namespace. Only works with apPolicy. |
| `waf.securityLogs[].enable` | `boolean` | Enables security log. |
| `waf.securityLogs[].logDest` | `string` | The log destination for the security log. Only accepted variables are syslog:server=<ip-address>; localhost; fqdn>:<port>, stderr, <absolute path to file>. |
