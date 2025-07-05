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
| `accessControl` | `object` | AccessControl defines an access policy based on the source IP of a request. |
| `accessControl.allow` | `array[string]` | Configuration field. |
| `accessControl.deny` | `array[string]` | Configuration field. |
| `apiKey` | `object` | APIKey defines an API Key policy. |
| `apiKey.clientSecret` | `string` | String configuration value. |
| `apiKey.suppliedIn` | `object` | SuppliedIn defines the locations API Key should be supplied in. |
| `apiKey.suppliedIn.header` | `array[string]` | Configuration field. |
| `apiKey.suppliedIn.query` | `array[string]` | Configuration field. |
| `basicAuth` | `object` | BasicAuth holds HTTP Basic authentication configuration |
| `basicAuth.realm` | `string` | String configuration value. |
| `basicAuth.secret` | `string` | String configuration value. |
| `egressMTLS` | `object` | EgressMTLS defines an Egress MTLS policy. |
| `egressMTLS.ciphers` | `string` | String configuration value. |
| `egressMTLS.protocols` | `string` | String configuration value. |
| `egressMTLS.serverName` | `boolean` | Enable or disable this feature. |
| `egressMTLS.sessionReuse` | `boolean` | Enable or disable this feature. |
| `egressMTLS.sslName` | `string` | String configuration value. |
| `egressMTLS.tlsSecret` | `string` | String configuration value. |
| `egressMTLS.trustedCertSecret` | `string` | String configuration value. |
| `egressMTLS.verifyDepth` | `integer` | Numeric configuration value. |
| `egressMTLS.verifyServer` | `boolean` | Enable or disable this feature. |
| `ingressClassName` | `string` | String configuration value. |
| `ingressMTLS` | `object` | IngressMTLS defines an Ingress MTLS policy. |
| `ingressMTLS.clientCertSecret` | `string` | String configuration value. |
| `ingressMTLS.crlFileName` | `string` | String configuration value. |
| `ingressMTLS.verifyClient` | `string` | String configuration value. |
| `ingressMTLS.verifyDepth` | `integer` | Numeric configuration value. |
| `jwt` | `object` | JWTAuth holds JWT authentication configuration. |
| `jwt.jwksURI` | `string` | String configuration value. |
| `jwt.keyCache` | `string` | String configuration value. |
| `jwt.realm` | `string` | String configuration value. |
| `jwt.secret` | `string` | String configuration value. |
| `jwt.token` | `string` | String configuration value. |
| `oidc` | `object` | OIDC defines an Open ID Connect policy. |
| `oidc.accessTokenEnable` | `boolean` | Enable or disable this feature. |
| `oidc.authEndpoint` | `string` | String configuration value. |
| `oidc.authExtraArgs` | `array[string]` | Configuration field. |
| `oidc.clientID` | `string` | String configuration value. |
| `oidc.clientSecret` | `string` | String configuration value. |
| `oidc.endSessionEndpoint` | `string` | String configuration value. |
| `oidc.jwksURI` | `string` | String configuration value. |
| `oidc.pkceEnable` | `boolean` | Enable or disable this feature. |
| `oidc.postLogoutRedirectURI` | `string` | String configuration value. |
| `oidc.redirectURI` | `string` | String configuration value. |
| `oidc.scope` | `string` | String configuration value. |
| `oidc.tokenEndpoint` | `string` | String configuration value. |
| `oidc.zoneSyncLeeway` | `integer` | Numeric configuration value. |
| `rateLimit` | `object` | RateLimit defines a rate limit policy. |
| `rateLimit.burst` | `integer` | Numeric configuration value. |
| `rateLimit.condition` | `object` | RateLimitCondition defines a condition for a rate limit policy. |
| `rateLimit.condition.default` | `boolean` | Sets the rate limit in this policy to be the default if no conditions are met. In a group of policies with the same condition, only one policy can be the default. |
| `rateLimit.condition.jwt` | `object` | Defines a JWT condition to rate limit against. |
| `rateLimit.condition.jwt.claim` | `string` | The JWT claim to be rate limit by. Nested claims should be separated by "." |
| `rateLimit.condition.jwt.match` | `string` | The value of the claim to match against. |
| `rateLimit.condition.variables` | `array` | Defines a Variables condition to rate limit against. |
| `rateLimit.condition.variables[].match` | `string` | The value of the variable to match against. |
| `rateLimit.condition.variables[].name` | `string` | The name of the variable to match against. |
| `rateLimit.delay` | `integer` | Numeric configuration value. |
| `rateLimit.dryRun` | `boolean` | Enable or disable this feature. |
| `rateLimit.key` | `string` | String configuration value. |
| `rateLimit.logLevel` | `string` | String configuration value. |
| `rateLimit.noDelay` | `boolean` | Enable or disable this feature. |
| `rateLimit.rate` | `string` | String configuration value. |
| `rateLimit.rejectCode` | `integer` | Numeric configuration value. |
| `rateLimit.scale` | `boolean` | Enable or disable this feature. |
| `rateLimit.zoneSize` | `string` | String configuration value. |
| `waf` | `object` | WAF defines an WAF policy. |
| `waf.apBundle` | `string` | String configuration value. |
| `waf.apPolicy` | `string` | String configuration value. |
| `waf.enable` | `boolean` | Enable or disable this feature. |
| `waf.securityLog` | `object` | SecurityLog defines the security log of a WAF policy. |
| `waf.securityLog.apLogBundle` | `string` | String configuration value. |
| `waf.securityLog.apLogConf` | `string` | String configuration value. |
| `waf.securityLog.enable` | `boolean` | Enable or disable this feature. |
| `waf.securityLog.logDest` | `string` | String configuration value. |
| `waf.securityLogs` | `array` | List of configuration values. |
| `waf.securityLogs[].apLogBundle` | `string` | String configuration value. |
| `waf.securityLogs[].apLogConf` | `string` | String configuration value. |
| `waf.securityLogs[].enable` | `boolean` | Enable or disable this feature. |
| `waf.securityLogs[].logDest` | `string` | String configuration value. |
