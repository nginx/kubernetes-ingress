package configs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nsutils"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// rateLimit hold the configuration for the ratelimiting Policy
type rateLimit struct {
	Reqs             []version2.LimitReq
	Zones            []version2.LimitReqZone
	GroupMaps        []version2.Map
	PolicyGroupMaps  []version2.Map
	Options          version2.LimitReqOptions
	AuthJWTClaimSets []version2.AuthJWTClaimSet
}

// jwtAuth hold the configuration for the JWTAuth & JWKSAuth Policies
type jwtAuth struct {
	Auth        *version2.JWTAuth
	List        map[string]*version2.JWTAuth
	JWKSEnabled bool
}

type apiKeyClient struct {
	ClientID  string
	HashedKey string
}

// apiKeyAuth hold the configuration for the APIKey Policy
type apiKeyAuth struct {
	Enabled   bool
	Key       *version2.APIKey
	Clients   []apiKeyClient
	ClientMap map[string][]apiKeyClient
}

type policiesCfg struct {
	Allow           []string
	Context         context.Context
	Deny            []string
	RateLimit       rateLimit
	JWTAuth         jwtAuth
	BasicAuth       *version2.BasicAuth
	IngressMTLS     *version2.IngressMTLS
	EgressMTLS      *version2.EgressMTLS
	OIDC            *version2.OIDC
	APIKey          apiKeyAuth
	WAF             *version2.WAF
	Cache           *version2.Cache
	CORSHeaders     []version2.AddHeader
	CORSMap         *version2.Map
	ErrorReturn     *version2.Return
	BundleValidator bundleValidator
}

func newPoliciesConfig(bv bundleValidator) *policiesCfg {
	return &policiesCfg{
		BundleValidator: bv,
	}
}

func (p *policiesCfg) addAccessControlConfig(accessControl *conf_v1.AccessControl) *validationResults {
	res := newValidationResults()
	p.Allow = append(p.Allow, accessControl.Allow...)
	p.Deny = append(p.Deny, accessControl.Deny...)
	if len(p.Allow) > 0 && len(p.Deny) > 0 {
		res.addWarningf(
			"AccessControl policy (or policies) with deny rules is overridden by policy (or policies) with allow rules",
		)
	}
	return res
}

func (p *policiesCfg) addRateLimitConfig(
	policy *conf_v1.Policy,
	ownerDetails policyOwnerDetails,
	podReplicas int,
	zoneSync bool,
	context string,
	path string,
) *validationResults {
	res := newValidationResults()
	rateLimit := policy.Spec.RateLimit
	polKey := fmt.Sprintf("%v/%v", policy.Namespace, policy.Name)
	l := nl.LoggerFromContext(p.Context)

	rlZoneName := rfc1123ToSnake(fmt.Sprintf("pol_rl_%v_%v_%v_%v", policy.Namespace, policy.Name, ownerDetails.vsNamespace, ownerDetails.vsName))
	if zoneSync {
		rlZoneName = fmt.Sprintf("%v_sync", rlZoneName)
	}
	if rateLimit.Condition != nil {
		lrz, warningText := generateGroupedLimitReqZone(rlZoneName, policy, podReplicas, ownerDetails, zoneSync, context, path)
		if warningText != "" {
			nl.Warn(l, warningText)
		}
		p.RateLimit.PolicyGroupMaps = append(p.RateLimit.PolicyGroupMaps, *generateLRZPolicyGroupMap(lrz))
		if rateLimit.Condition.JWT != nil && rateLimit.Condition.JWT.Claim != "" && rateLimit.Condition.JWT.Match != "" {
			p.RateLimit.AuthJWTClaimSets = append(p.RateLimit.AuthJWTClaimSets, generateAuthJwtClaimSet(*rateLimit.Condition.JWT, ownerDetails))
		}
		p.RateLimit.Zones = append(p.RateLimit.Zones, lrz)
	} else {
		lrz, warningText := generateLimitReqZone(rlZoneName, policy, podReplicas, zoneSync)
		if warningText != "" {
			nl.Warn(l, warningText)
		}
		p.RateLimit.Zones = append(p.RateLimit.Zones, lrz)
	}

	p.RateLimit.Reqs = append(p.RateLimit.Reqs, generateLimitReq(rlZoneName, rateLimit))
	if len(p.RateLimit.Reqs) == 1 {
		p.RateLimit.Options = generateLimitReqOptions(rateLimit)
	} else {
		curOptions := generateLimitReqOptions(rateLimit)
		if curOptions.DryRun != p.RateLimit.Options.DryRun {
			res.addWarningf("RateLimit policy %s with limit request option dryRun='%v' is overridden to dryRun='%v' by the first policy reference in this context", polKey, curOptions.DryRun, p.RateLimit.Options.DryRun)
		}
		if curOptions.LogLevel != p.RateLimit.Options.LogLevel {
			res.addWarningf("RateLimit policy %s with limit request option logLevel='%v' is overridden to logLevel='%v' by the first policy reference in this context", polKey, curOptions.LogLevel, p.RateLimit.Options.LogLevel)
		}
		if curOptions.RejectCode != p.RateLimit.Options.RejectCode {
			res.addWarningf("RateLimit policy %s with limit request option rejectCode='%v' is overridden to rejectCode='%v' by the first policy reference in this context", polKey, curOptions.RejectCode, p.RateLimit.Options.RejectCode)
		}
	}
	return res
}

// nolint:gocyclo
func (p *policiesCfg) addJWTAuthConfig(
	jwtAuth *conf_v1.JWTAuth,
	polKey string,
	polNamespace string,
	secretRefs map[string]*secrets.SecretReference,
) *validationResults {
	res := newValidationResults()
	if p.JWTAuth.Auth != nil {
		res.addWarningf("Multiple jwt policies in the same context is not valid. JWT policy %s will be ignored", polKey)
		return res
	}
	if jwtAuth.Secret != "" {
		jwtSecretKey := fmt.Sprintf("%v/%v", polNamespace, jwtAuth.Secret)
		secretRef := secretRefs[jwtSecretKey]
		var secretType api_v1.SecretType
		if secretRef.Secret != nil {
			secretType = secretRef.Secret.Type
		}
		if secretType != "" && secretType != secrets.SecretTypeJWK {
			res.addWarningf("JWT policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, jwtSecretKey, secretType, secrets.SecretTypeJWK)
			res.isError = true
			return res
		} else if secretRef.Error != nil {
			res.addWarningf("JWT policy %s references an invalid secret %s: %v", polKey, jwtSecretKey, secretRef.Error)
			res.isError = true
			return res
		}

		p.JWTAuth.Auth = &version2.JWTAuth{
			Secret: secretRef.Path,
			Realm:  jwtAuth.Realm,
			Token:  jwtAuth.Token,
		}
		return res
	} else if jwtAuth.JwksURI != "" {
		uri, _ := url.Parse(jwtAuth.JwksURI)

		// Handle SSL verification for JWKS
		var trustedCertPath string
		if jwtAuth.SSLVerify && jwtAuth.TrustedCertSecret != "" {
			trustedCertSecretKey := fmt.Sprintf("%s/%s", polNamespace, jwtAuth.TrustedCertSecret)
			trustedCertSecretRef := secretRefs[trustedCertSecretKey]

			// Check if secret reference exists
			if trustedCertSecretRef == nil {
				res.addWarningf("JWT policy %s references a non-existent trusted cert secret %s", polKey, trustedCertSecretKey)
				res.isError = true
				return res
			}

			var secretType api_v1.SecretType
			if trustedCertSecretRef.Secret != nil {
				secretType = trustedCertSecretRef.Secret.Type
			}
			if secretType != "" && secretType != secrets.SecretTypeCA {
				res.addWarningf("JWT policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, trustedCertSecretKey, secretType, secrets.SecretTypeCA)
				res.isError = true
				return res
			} else if trustedCertSecretRef.Error != nil {
				res.addWarningf("JWT policy %s references an invalid trusted cert secret %s: %v", polKey, trustedCertSecretKey, trustedCertSecretRef.Error)
				res.isError = true
				return res
			}

			caFields := strings.Fields(trustedCertSecretRef.Path)
			if len(caFields) > 0 {
				trustedCertPath = caFields[0]
			}
		}

		sslVerifyDepth := 1
		if jwtAuth.SSLVerifyDepth != nil {
			sslVerifyDepth = *jwtAuth.SSLVerifyDepth
		}

		JwksURI := &version2.JwksURI{
			JwksScheme:     uri.Scheme,
			JwksHost:       uri.Hostname(),
			JwksPort:       uri.Port(),
			JwksPath:       uri.Path,
			JwksSNIName:    jwtAuth.SNIName,
			JwksSNIEnabled: jwtAuth.SNIEnabled,
			SSLVerify:      jwtAuth.SSLVerify,
			TrustedCert:    trustedCertPath,
			SSLVerifyDepth: sslVerifyDepth,
		}

		p.JWTAuth.Auth = &version2.JWTAuth{
			Key:      polKey,
			JwksURI:  *JwksURI,
			Realm:    jwtAuth.Realm,
			Token:    jwtAuth.Token,
			KeyCache: jwtAuth.KeyCache,
		}
		p.JWTAuth.JWKSEnabled = true
		return res
	}
	return res
}

func (p *policiesCfg) addBasicAuthConfig(
	basicAuth *conf_v1.BasicAuth,
	polKey string,
	polNamespace string,
	secretRefs map[string]*secrets.SecretReference,
) *validationResults {
	res := newValidationResults()
	if p.BasicAuth != nil {
		res.addWarningf("Multiple basic auth policies in the same context is not valid. Basic auth policy %s will be ignored", polKey)
		return res
	}

	basicSecretKey := fmt.Sprintf("%v/%v", polNamespace, basicAuth.Secret)
	secretRef := secretRefs[basicSecretKey]
	var secretType api_v1.SecretType
	if secretRef.Secret != nil {
		secretType = secretRef.Secret.Type
	}
	if secretType != "" && secretType != secrets.SecretTypeHtpasswd {
		res.addWarningf("Basic Auth policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, basicSecretKey, secretType, secrets.SecretTypeHtpasswd)
		res.isError = true
		return res
	} else if secretRef.Error != nil {
		res.addWarningf("Basic Auth policy %s references an invalid secret %s: %v", polKey, basicSecretKey, secretRef.Error)
		res.isError = true
		return res
	}

	p.BasicAuth = &version2.BasicAuth{
		Secret: secretRef.Path,
		Realm:  basicAuth.Realm,
	}
	return res
}

func (p *policiesCfg) addIngressMTLSConfig(
	ingressMTLS *conf_v1.IngressMTLS,
	polKey string,
	polNamespace string,
	context string,
	tls bool,
	secretRefs map[string]*secrets.SecretReference,
) *validationResults {
	res := newValidationResults()
	if !tls {
		res.addWarningf("TLS must be enabled in VirtualServer for IngressMTLS policy %s", polKey)
		res.isError = true
		return res
	}
	if context != specContext {
		res.addWarningf("IngressMTLS policy %s is not allowed in the %v context", polKey, context)
		res.isError = true
		return res
	}
	if p.IngressMTLS != nil {
		res.addWarningf("Multiple ingressMTLS policies are not allowed. IngressMTLS policy %s will be ignored", polKey)
		return res
	}

	secretKey := fmt.Sprintf("%v/%v", polNamespace, ingressMTLS.ClientCertSecret)
	secretRef := secretRefs[secretKey]
	var secretType api_v1.SecretType
	if secretRef.Secret != nil {
		secretType = secretRef.Secret.Type
	}
	if secretType != "" && secretType != secrets.SecretTypeCA {
		res.addWarningf("IngressMTLS policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, secretKey, secretType, secrets.SecretTypeCA)
		res.isError = true
		return res
	} else if secretRef.Error != nil {
		res.addWarningf("IngressMTLS policy %q references an invalid secret %s: %v", polKey, secretKey, secretRef.Error)
		res.isError = true
		return res
	}

	verifyDepth := 1
	verifyClient := "on"
	if ingressMTLS.VerifyDepth != nil {
		verifyDepth = *ingressMTLS.VerifyDepth
	}
	if ingressMTLS.VerifyClient != "" {
		verifyClient = ingressMTLS.VerifyClient
	}

	caFields := strings.Fields(secretRef.Path)

	if _, hasCrlKey := secretRef.Secret.Data[CACrlKey]; hasCrlKey && ingressMTLS.CrlFileName != "" {
		res.addWarningf("Both ca.crl in the Secret and ingressMTLS.crlFileName fields cannot be used. ca.crl in %s will be ignored and %s will be applied", secretKey, polKey)
	}

	if ingressMTLS.CrlFileName != "" {
		p.IngressMTLS = &version2.IngressMTLS{
			ClientCert:   caFields[0],
			ClientCrl:    fmt.Sprintf("%s/%s", DefaultSecretPath, ingressMTLS.CrlFileName),
			VerifyClient: verifyClient,
			VerifyDepth:  verifyDepth,
		}
	} else if _, hasCrlKey := secretRef.Secret.Data[CACrlKey]; hasCrlKey {
		p.IngressMTLS = &version2.IngressMTLS{
			ClientCert:   caFields[0],
			ClientCrl:    caFields[1],
			VerifyClient: verifyClient,
			VerifyDepth:  verifyDepth,
		}
	} else {
		p.IngressMTLS = &version2.IngressMTLS{
			ClientCert:   caFields[0],
			VerifyClient: verifyClient,
			VerifyDepth:  verifyDepth,
		}
	}
	return res
}

func (p *policiesCfg) addEgressMTLSConfig(
	egressMTLS *conf_v1.EgressMTLS,
	polKey string,
	polNamespace string,
	secretRefs map[string]*secrets.SecretReference,
) *validationResults {
	res := newValidationResults()
	if p.EgressMTLS != nil {
		res.addWarningf(
			"Multiple egressMTLS policies in the same context is not valid. EgressMTLS policy %s will be ignored",
			polKey,
		)
		return res
	}

	var tlsSecretPath string

	if egressMTLS.TLSSecret != "" {
		egressTLSSecret := fmt.Sprintf("%v/%v", polNamespace, egressMTLS.TLSSecret)

		secretRef := secretRefs[egressTLSSecret]
		var secretType api_v1.SecretType
		if secretRef.Secret != nil {
			secretType = secretRef.Secret.Type
		}
		if secretType != "" && secretType != api_v1.SecretTypeTLS {
			res.addWarningf("EgressMTLS policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, egressTLSSecret, secretType, api_v1.SecretTypeTLS)
			res.isError = true
			return res
		} else if secretRef.Error != nil {
			res.addWarningf("EgressMTLS policy %s references an invalid secret %s: %v", polKey, egressTLSSecret, secretRef.Error)
			res.isError = true
			return res
		}

		tlsSecretPath = secretRef.Path
	}

	var trustedSecretPath string

	if egressMTLS.TrustedCertSecret != "" {
		trustedCertSecret := fmt.Sprintf("%v/%v", polNamespace, egressMTLS.TrustedCertSecret)

		secretRef := secretRefs[trustedCertSecret]
		var secretType api_v1.SecretType
		if secretRef.Secret != nil {
			secretType = secretRef.Secret.Type
		}
		if secretType != "" && secretType != secrets.SecretTypeCA {
			res.addWarningf("EgressMTLS policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, trustedCertSecret, secretType, secrets.SecretTypeCA)
			res.isError = true
			return res
		} else if secretRef.Error != nil {
			res.addWarningf("EgressMTLS policy %s references an invalid secret %s: %v", polKey, trustedCertSecret, secretRef.Error)
			res.isError = true
			return res
		}

		trustedSecretPath = secretRef.Path
	}

	if len(trustedSecretPath) != 0 {
		caFields := strings.Fields(trustedSecretPath)
		trustedSecretPath = caFields[0]
	}

	p.EgressMTLS = &version2.EgressMTLS{
		Certificate:    tlsSecretPath,
		CertificateKey: tlsSecretPath,
		Ciphers:        generateString(egressMTLS.Ciphers, "DEFAULT"),
		Protocols:      generateString(egressMTLS.Protocols, "TLSv1 TLSv1.1 TLSv1.2"),
		VerifyServer:   egressMTLS.VerifyServer,
		VerifyDepth:    generateIntFromPointer(egressMTLS.VerifyDepth, 1),
		SessionReuse:   generateBool(egressMTLS.SessionReuse, true),
		ServerName:     egressMTLS.ServerName,
		TrustedCert:    trustedSecretPath,
		SSLName:        generateString(egressMTLS.SSLName, "$proxy_host"),
	}
	return res
}

// nolint:gocyclo
func (p *policiesCfg) addOIDCConfig(
	oidc *conf_v1.OIDC,
	polKey string,
	polNamespace string,
	policyOpts policyOptions,
) *validationResults {
	secretRefs := policyOpts.secretRefs
	res := newValidationResults()
	if p.OIDC != nil {
		res.addWarningf(
			"Multiple oidc policies in the same context is not valid. OIDC policy %s will be ignored",
			polKey,
		)
		return res
	}

	var policy *version2.OIDC
	if policyOpts.oidcPolicyName != "" {
		if policyOpts.oidcPolicyName != polKey {
			res.addWarningf(
				"Only one oidc policy is allowed in a VirtualServer and its VirtualServerRoutes. Can't use %s. Use %s",
				polKey,
				policyOpts.oidcPolicyName,
			)
			res.isError = true
			return res
		}
	} else {
		secretKey := fmt.Sprintf("%v/%v", polNamespace, oidc.ClientSecret)
		secretRef, ok := secretRefs[secretKey]
		clientSecret := []byte("")

		if ok {
			var secretType api_v1.SecretType
			if secretRef.Secret != nil {
				secretType = secretRef.Secret.Type
			}
			if secretType != "" && secretType != secrets.SecretTypeOIDC {
				res.addWarningf("OIDC policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, secretKey, secretType, secrets.SecretTypeOIDC)
				res.isError = true
				return res
			} else if secretRef.Error != nil && !oidc.PKCEEnable {
				res.addWarningf("OIDC policy %s references an invalid secret %s: %v", polKey, secretKey, secretRef.Error)
				res.isError = true
				return res
			} else if oidc.PKCEEnable {
				res.addWarningf("OIDC policy %s has a secret and PKCE enabled. Secrets can't be used with PKCE", polKey)
				res.isError = true
				return res
			}

			clientSecret = secretRef.Secret.Data[ClientSecretKey]
		} else if !oidc.PKCEEnable {
			res.addWarningf("Client secret is required for OIDC policy %s when not using PKCE", polKey)
			res.isError = true
			return res
		}

		redirectURI := oidc.RedirectURI
		if redirectURI == "" {
			redirectURI = "/_codexch"
		}
		postLogoutRedirectURI := oidc.PostLogoutRedirectURI
		if postLogoutRedirectURI == "" {
			postLogoutRedirectURI = "/_logout"
		}
		scope := oidc.Scope
		if scope == "" {
			scope = "openid"
		}
		authExtraArgs := ""
		if oidc.AuthExtraArgs != nil {
			authExtraArgs = strings.Join(oidc.AuthExtraArgs, "&")
		}

		trustedCertPath := policyOpts.defaultCABundle
		if oidc.SSLVerify && oidc.TrustedCertSecret != "" {
			// Override default CA bundle if trusted cert secret is provided
			trustedCertSecretKey := fmt.Sprintf("%s/%s", polNamespace, oidc.TrustedCertSecret)
			trustedCertSecretRef := secretRefs[trustedCertSecretKey]

			// Check if secret reference exists
			if trustedCertSecretRef == nil {
				res.addWarningf("OIDC policy %s references a non-existent trusted cert secret %s", polKey, trustedCertSecretKey)
				res.isError = true
				return res
			}

			var secretType api_v1.SecretType
			if trustedCertSecretRef.Secret != nil {
				secretType = trustedCertSecretRef.Secret.Type
			}
			if secretType != "" && secretType != secrets.SecretTypeCA {
				res.addWarningf("OIDC policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, trustedCertSecretKey, secretType, secrets.SecretTypeCA)
				res.isError = true
				return res
			} else if trustedCertSecretRef.Error != nil {
				res.addWarningf("OIDC policy %s references an invalid trusted cert secret %s: %v", polKey, trustedCertSecretKey, trustedCertSecretRef.Error)
				res.isError = true
				return res
			}

			caFields := strings.Fields(trustedCertSecretRef.Path)
			if len(caFields) > 0 {
				trustedCertPath = caFields[0]
			}
		}

		sslVerifyDepth := 1
		if oidc.SSLVerifyDepth != nil {
			sslVerifyDepth = *oidc.SSLVerifyDepth
		}

		policy = &version2.OIDC{
			AuthEndpoint:          oidc.AuthEndpoint,
			AuthExtraArgs:         authExtraArgs,
			TokenEndpoint:         oidc.TokenEndpoint,
			JwksURI:               oidc.JWKSURI,
			EndSessionEndpoint:    oidc.EndSessionEndpoint,
			ClientID:              oidc.ClientID,
			ClientSecret:          string(clientSecret),
			Scope:                 scope,
			RedirectURI:           redirectURI,
			PostLogoutRedirectURI: postLogoutRedirectURI,
			ZoneSyncLeeway:        generateIntFromPointer(oidc.ZoneSyncLeeway, 200),
			AccessTokenEnable:     oidc.AccessTokenEnable,
			PKCEEnable:            oidc.PKCEEnable,
			TLSVerify:             oidc.SSLVerify,
			VerifyDepth:           sslVerifyDepth,
			CAFile:                trustedCertPath,
			PolicyName:            polKey,
		}
	}

	p.OIDC = policy

	return res
}

func (p *policiesCfg) addAPIKeyConfig(
	apiKey *conf_v1.APIKey,
	polKey string,
	polNamespace string,
	vsNamespace string,
	vsName string,
	ownerType string,
	secretRefs map[string]*secrets.SecretReference,
) *validationResults {
	res := newValidationResults()
	if p.APIKey.Key != nil {
		res.addWarningf(
			"Multiple API Key policies in the same context is not valid. API Key policy %s will be ignored",
			polKey,
		)
		res.isError = true
		return res
	}

	secretKey := fmt.Sprintf("%v/%v", polNamespace, apiKey.ClientSecret)
	secretRef := secretRefs[secretKey]
	var secretType api_v1.SecretType
	if secretRef.Secret != nil {
		secretType = secretRef.Secret.Type
	}
	if secretType != "" && secretType != secrets.SecretTypeAPIKey {
		res.addWarningf("API Key policy %s references a secret %s of a wrong type '%s', must be '%s'", polKey, secretKey, secretType, secrets.SecretTypeAPIKey)
		res.isError = true
		return res
	} else if secretRef.Error != nil {
		res.addWarningf("API Key %s references an invalid secret %s: %v", polKey, secretKey, secretRef.Error)
		res.isError = true
		return res
	}

	p.APIKey.Clients = generateAPIKeyClients(secretRef.Secret.Data)

	ownerTypeName := formatOwnerType(ownerType)
	mapName := fmt.Sprintf(
		"apikey_auth_client_name_%s_%s_%s_%s",
		rfc1123ToSnake(vsNamespace),
		rfc1123ToSnake(vsName),
		ownerTypeName,
		strings.Split(rfc1123ToSnake(polKey), "/")[1],
	)
	p.APIKey.Key = &version2.APIKey{
		Header:  apiKey.SuppliedIn.Header,
		Query:   apiKey.SuppliedIn.Query,
		MapName: mapName,
	}
	p.APIKey.Enabled = true
	return res
}

// nolint:gocyclo
func (p *policiesCfg) addWAFConfig(
	ctx context.Context,
	waf *conf_v1.WAF,
	polKey string,
	polNamespace string,
	apResources *appProtectResourcesForVS,
) *validationResults {
	l := nl.LoggerFromContext(ctx)
	res := newValidationResults()
	if p.WAF != nil {
		res.addWarningf("Multiple WAF policies in the same context is not valid. WAF policy %s will be ignored", polKey)
		return res
	}

	if waf.Enable {
		p.WAF = &version2.WAF{Enable: "on"}
	} else {
		p.WAF = &version2.WAF{Enable: "off"}
	}

	if waf.ApPolicy != "" {
		apPolKey := waf.ApPolicy
		if !nsutils.HasNamespace(apPolKey) {
			apPolKey = fmt.Sprintf("%v/%v", polNamespace, apPolKey)
		}

		if apPolPath, exists := apResources.Policies[apPolKey]; exists {
			p.WAF.ApPolicy = apPolPath
		} else {
			res.addWarningf("WAF policy %s references an invalid or non-existing App Protect policy %s", polKey, apPolKey)
			res.isError = true
			return res
		}
	}

	if waf.ApBundle != "" {
		bundlePath, err := p.BundleValidator.validate(waf.ApBundle)
		if err != nil {
			res.addWarningf("WAF policy %s references an invalid or non-existing App Protect bundle %s", polKey, bundlePath)
			res.isError = true
		}
		p.WAF.ApBundle = bundlePath
	}

	if waf.SecurityLog != nil && waf.SecurityLogs == nil {
		nl.Debug(l, "the field securityLog is deprecated and will be removed in future releases. Use field securityLogs instead")
		waf.SecurityLogs = append(waf.SecurityLogs, waf.SecurityLog)
	}

	if waf.SecurityLogs != nil {
		p.WAF.ApSecurityLogEnable = true
		p.WAF.ApLogConf = []string{}
		for _, loco := range waf.SecurityLogs {
			logDest := generateString(loco.LogDest, defaultLogOutput)

			if loco.ApLogConf != "" {
				logConfKey := loco.ApLogConf
				if !nsutils.HasNamespace(logConfKey) {
					logConfKey = fmt.Sprintf("%v/%v", polNamespace, logConfKey)
				}
				if logConfPath, ok := apResources.LogConfs[logConfKey]; ok {
					p.WAF.ApLogConf = append(p.WAF.ApLogConf, fmt.Sprintf("%s %s", logConfPath, logDest))
				} else {
					res.addWarningf("WAF policy %s references an invalid or non-existing log config %s", polKey, logConfKey)
					res.isError = true
				}
			}

			if loco.ApLogBundle != "" {
				logBundle, err := p.BundleValidator.validate(loco.ApLogBundle)
				if err != nil {
					res.addWarningf("WAF policy %s references an invalid or non-existing log config bundle %s", polKey, logBundle)
					res.isError = true
				} else {
					p.WAF.ApLogConf = append(p.WAF.ApLogConf, fmt.Sprintf("%s %s", logBundle, logDest))
				}
			}
		}
	}
	return res
}

func (p *policiesCfg) addCacheConfig(
	cache *conf_v1.Cache,
	polKey string,
	vsNamespace, vsName, ownerNamespace, ownerName, ownerType string,
) *validationResults {
	res := newValidationResults()
	if p.Cache != nil {
		res.addWarningf("Multiple cache policies in the same context is not valid. Cache policy %s will be ignored", polKey)
		return res
	}

	p.Cache = generateCacheConfig(cache, vsNamespace, vsName, ownerNamespace, ownerName, ownerType)
	return res
}

// generateCORSVariableName creates a unique variable name for CORS map based on VS/VSR owner details.
func generateCORSVariableName(polKey, vsNamespace, vsName, ownerNamespace, ownerName, ownerType string) string {
	polNamespace, polName, ok := strings.Cut(polKey, "/")
	ownerTypeName := formatOwnerType(ownerType)
	if !ok || polNamespace == "" || polName == "" {
		if vsNamespace == ownerNamespace && vsName == ownerName {
			return fmt.Sprintf("cors_origin_%s_%s_%s", rfc1123ToSnake(vsNamespace), rfc1123ToSnake(vsName), ownerTypeName)
		}
		return fmt.Sprintf("cors_origin_%s_%s_%s_%s_%s",
			rfc1123ToSnake(vsNamespace),
			rfc1123ToSnake(vsName),
			rfc1123ToSnake(ownerNamespace),
			rfc1123ToSnake(ownerName),
			ownerTypeName,
		)
	}

	if vsNamespace == ownerNamespace && vsName == ownerName {
		return fmt.Sprintf("cors_origin_%s_%s_%s_%s_%s",
			rfc1123ToSnake(vsNamespace),
			rfc1123ToSnake(vsName),
			ownerTypeName,
			rfc1123ToSnake(polNamespace),
			rfc1123ToSnake(polName),
		)
	}

	return fmt.Sprintf("cors_origin_%s_%s_%s_%s_%s_%s_%s",
		rfc1123ToSnake(vsNamespace),
		rfc1123ToSnake(vsName),
		rfc1123ToSnake(ownerNamespace),
		rfc1123ToSnake(ownerName),
		ownerTypeName,
		rfc1123ToSnake(polNamespace),
		rfc1123ToSnake(polName),
	)
}

// buildOriginRegex converts a wildcard origin pattern to nginx-compatible regex
// Supports single-level wildcard subdomains: https://*.example.com -> ~^https://[^.]+\.example\.com$
func buildOriginRegex(origin string) string {
	// Global wildcard - return as-is
	if origin == "*" {
		return origin
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		// Not a valid origin format, return as-is (validation should catch this)
		return origin
	}

	if parsedOrigin.Scheme != "http" && parsedOrigin.Scheme != "https" {
		// Not a valid origin format, return as-is (validation should catch this)
		return origin
	}

	if parsedOrigin.Host == "" {
		// Not a valid origin format, return as-is (validation should catch this)
		return origin
	}

	scheme := parsedOrigin.Scheme + "://"
	host := parsedOrigin.Host

	// Check for wildcard subdomain pattern
	if !strings.HasPrefix(host, "*.") {
		// For exact origins, return as-is (no regex needed)
		return origin
	}

	// Convert wildcard subdomain to regex
	domain := host[2:] // Remove "*."

	// Build regex pattern: ^https://[^.]+\.example\.com$
	// [^.]+  matches one or more characters except dots (single-level subdomain)
	// \.     escaped literal dot
	// ^...$  anchored to match full string
	return fmt.Sprintf("~^%s[^.]+\\.%s$", regexp.QuoteMeta(scheme), regexp.QuoteMeta(domain))
}

// isWildcardOrigin checks if an origin contains a wildcard subdomain pattern
func isWildcardOrigin(origin string) bool {
	if origin == "*" {
		return false // Global wildcard is handled differently
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if parsedOrigin.Scheme != "http" && parsedOrigin.Scheme != "https" {
		return false
	}

	if parsedOrigin.Host == "" {
		return false
	}

	return strings.HasPrefix(parsedOrigin.Host, "*.")
}

func generateCORSOriginMap(origins []string, variableName string) *version2.Map {
	params := []version2.Parameter{{
		Value:  "default",
		Result: `""`,
	}}

	for _, origin := range origins {
		if origin == "" {
			continue
		}

		if isWildcardOrigin(origin) {
			params = append(params, version2.Parameter{
				Value:  buildOriginRegex(origin),
				Result: "$http_origin",
			})
			continue
		}

		escapedOrigin := escapeNginxString(origin)
		quotedOrigin := fmt.Sprintf(`"%s"`, escapedOrigin)
		params = append(params, version2.Parameter{
			Value:  quotedOrigin,
			Result: escapedOrigin,
		})
	}

	return &version2.Map{
		Source:     "$http_origin",
		Variable:   fmt.Sprintf("$%s", variableName),
		Parameters: params,
	}
}

func generateCORSHeaders(cors *conf_v1.CORS, originValue string) []version2.AddHeader {
	var corsHeaders []version2.AddHeader

	hasOriginValidation := len(cors.AllowOrigin) > 0 && (len(cors.AllowOrigin) != 1 || cors.AllowOrigin[0] != "*")
	if hasOriginValidation {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Vary", Value: "Origin"},
			Always: true,
		})
	}

	if originValue != "" {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Access-Control-Allow-Origin", Value: originValue},
			Always: true,
		})
	}

	if len(cors.AllowMethods) > 0 {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Access-Control-Allow-Methods", Value: escapeNginxString(strings.Join(cors.AllowMethods, ", "))},
			Always: true,
		})
	}

	if len(cors.AllowHeaders) > 0 {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Access-Control-Allow-Headers", Value: escapeNginxString(strings.Join(cors.AllowHeaders, ", "))},
			Always: true,
		})
	}

	if cors.AllowCredentials != nil {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Access-Control-Allow-Credentials", Value: fmt.Sprintf("%t", *cors.AllowCredentials)},
			Always: true,
		})
	}

	if len(cors.ExposeHeaders) > 0 {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Access-Control-Expose-Headers", Value: escapeNginxString(strings.Join(cors.ExposeHeaders, ", "))},
			Always: true,
		})
	}

	if cors.MaxAge != nil {
		corsHeaders = append(corsHeaders, version2.AddHeader{
			Header: version2.Header{Name: "Access-Control-Max-Age", Value: fmt.Sprintf("%d", *cors.MaxAge)},
			Always: true,
		})
	}

	return corsHeaders
}

func (p *policiesCfg) addCORSConfig(
	cors *conf_v1.CORS,
	polKey string,
	vsNamespace,
	vsName,
	ownerNamespace,
	ownerName,
	ownerType string,
) *validationResults {
	res := newValidationResults()

	var originValue string
	if len(cors.AllowOrigin) > 0 {
		if len(cors.AllowOrigin) == 1 && cors.AllowOrigin[0] == "*" {
			originValue = "*"
		} else if len(cors.AllowOrigin) == 1 && !isWildcardOrigin(cors.AllowOrigin[0]) {
			originValue = escapeNginxString(cors.AllowOrigin[0])
		} else {
			policyVarName := generateCORSVariableName(polKey, vsNamespace, vsName, ownerNamespace, ownerName, ownerType)
			originValue = fmt.Sprintf("$%s", policyVarName)
			p.CORSMap = generateCORSOriginMap(cors.AllowOrigin, policyVarName)
		}
	}

	p.CORSHeaders = generateCORSHeaders(cors, originValue)

	return res
}

// nolint:gocyclo
func generatePolicies(
	ctx context.Context,
	ownerDetails policyOwnerDetails,
	policyRefs []conf_v1.PolicyReference,
	policies map[string]*conf_v1.Policy,
	pathContext string,
	path string,
	policyOpts policyOptions,
	bundleValidator bundleValidator,
) (policiesCfg, Warnings) {
	warnings := make(Warnings)
	config := newPoliciesConfig(bundleValidator)
	config.Context = ctx

	for _, p := range policyRefs {
		polNamespace := p.Namespace
		if polNamespace == "" {
			polNamespace = ownerDetails.ownerNamespace
		}

		key := fmt.Sprintf("%s/%s", polNamespace, p.Name)

		if pol, exists := policies[key]; exists {
			var res *validationResults
			switch {
			case pol.Spec.AccessControl != nil:
				res = config.addAccessControlConfig(pol.Spec.AccessControl)
			case pol.Spec.RateLimit != nil:
				res = config.addRateLimitConfig(
					pol,
					ownerDetails,
					policyOpts.replicas,
					policyOpts.zoneSync,
					pathContext,
					path,
				)
			case pol.Spec.JWTAuth != nil:
				res = config.addJWTAuthConfig(pol.Spec.JWTAuth, key, polNamespace, policyOpts.secretRefs)
			case pol.Spec.BasicAuth != nil:
				res = config.addBasicAuthConfig(pol.Spec.BasicAuth, key, polNamespace, policyOpts.secretRefs)
			case pol.Spec.IngressMTLS != nil:
				res = config.addIngressMTLSConfig(
					pol.Spec.IngressMTLS,
					key,
					polNamespace,
					pathContext,
					policyOpts.tls,
					policyOpts.secretRefs,
				)
			case pol.Spec.EgressMTLS != nil:
				res = config.addEgressMTLSConfig(pol.Spec.EgressMTLS, key, polNamespace, policyOpts.secretRefs)
			case pol.Spec.OIDC != nil:
				res = config.addOIDCConfig(pol.Spec.OIDC, key, polNamespace, policyOpts)
			case pol.Spec.APIKey != nil:
				res = config.addAPIKeyConfig(pol.Spec.APIKey, key, polNamespace, ownerDetails.vsNamespace,
					ownerDetails.vsName, ownerDetails.ownerType, policyOpts.secretRefs)
			case pol.Spec.WAF != nil:
				res = config.addWAFConfig(ctx, pol.Spec.WAF, key, polNamespace, policyOpts.apResources)
			case pol.Spec.Cache != nil:
				res = config.addCacheConfig(pol.Spec.Cache, key, ownerDetails.vsNamespace, ownerDetails.vsName, ownerDetails.ownerNamespace, ownerDetails.ownerName, ownerDetails.ownerType)
			case pol.Spec.CORS != nil:
				res = config.addCORSConfig(pol.Spec.CORS, key, ownerDetails.vsNamespace, ownerDetails.vsName, ownerDetails.ownerNamespace, ownerDetails.ownerName, ownerDetails.ownerType)
			default:
				res = newValidationResults()
			}
			for _, msg := range res.warnings {
				warnings.AddWarning(ownerDetails.owner, msg)
			}
			if res.isError {
				return policiesCfg{
					ErrorReturn: &version2.Return{Code: 500},
				}, warnings
			}
		} else {
			warnings.AddWarningf(ownerDetails.owner, "Policy %s is missing or invalid", key)
			return policiesCfg{
				ErrorReturn: &version2.Return{Code: 500},
			}, warnings
		}
	}

	if len(config.RateLimit.PolicyGroupMaps) > 0 {
		for _, v := range generateLRZGroupMaps(config.RateLimit.Zones) {
			if hasDuplicateMapDefaults(v) {
				warnings.AddWarningf(ownerDetails.owner, "Tiered rate-limit Policies on [%v/%v] contain conflicting default values", ownerDetails.ownerNamespace, ownerDetails.ownerName)
				return policiesCfg{
					ErrorReturn: &version2.Return{Code: 500},
				}, warnings
			}
			config.RateLimit.GroupMaps = append(config.RateLimit.GroupMaps, *v)
		}
	}

	return *config, warnings
}

func generateAPIKeyClients(secretData map[string][]byte) []apiKeyClient {
	var clients []apiKeyClient
	for clientID, apiKey := range secretData {

		h := sha256.New()
		h.Write(apiKey)
		sha256Hash := hex.EncodeToString(h.Sum(nil))
		clients = append(clients, apiKeyClient{ClientID: clientID, HashedKey: sha256Hash}) //
	}
	return clients
}

func generateLimitReq(zoneName string, rateLimitPol *conf_v1.RateLimit) version2.LimitReq {
	var limitReq version2.LimitReq

	limitReq.ZoneName = zoneName

	if rateLimitPol.Burst != nil {
		limitReq.Burst = *rateLimitPol.Burst
	}
	if rateLimitPol.Delay != nil {
		limitReq.Delay = *rateLimitPol.Delay
	}

	limitReq.NoDelay = generateBool(rateLimitPol.NoDelay, false)
	if limitReq.NoDelay {
		limitReq.Delay = 0
	}

	return limitReq
}

func generateLimitReqZone(zoneName string, policy *conf_v1.Policy, podReplicas int, zoneSync bool) (version2.LimitReqZone, string) {
	rateLimitPol := policy.Spec.RateLimit
	rate := rateLimitPol.Rate
	warningText := ""

	if rateLimitPol.Scale {
		if zoneSync {
			warningText = fmt.Sprintf("Policy %s/%s: both zone sync and rate limit scale are enabled, the rate limit scale value will not be used.", policy.Namespace, policy.Name)
		} else {
			rate = scaleRatelimit(rateLimitPol.Rate, podReplicas)
		}
	}
	return version2.LimitReqZone{
		ZoneName: zoneName,
		Key:      rateLimitPol.Key,
		ZoneSize: rateLimitPol.ZoneSize,
		Rate:     rate,
		Sync:     zoneSync,
	}, warningText
}

func generateGroupedLimitReqZone(
	zoneName string,
	policy *conf_v1.Policy,
	podReplicas int,
	ownerDetails policyOwnerDetails,
	zoneSync bool,
	context string,
	path string,
) (version2.LimitReqZone, string) {
	rateLimitPol := policy.Spec.RateLimit
	rate := rateLimitPol.Rate
	warningText := ""

	if rateLimitPol.Scale {
		if zoneSync {
			warningText = fmt.Sprintf("Policy %s/%s: both zone sync and rate limit scale are enabled, the rate limit scale value will not be used.", policy.Namespace, policy.Name)
		} else {
			rate = scaleRatelimit(rateLimitPol.Rate, podReplicas)
		}
	}
	lrz := version2.LimitReqZone{
		ZoneName: zoneName,
		Key:      rateLimitPol.Key,
		ZoneSize: rateLimitPol.ZoneSize,
		Rate:     rate,
		Sync:     zoneSync,
	}

	encoder := base64.URLEncoding.WithPadding(base64.NoPadding)
	encPath := encoder.EncodeToString([]byte(path))
	if rateLimitPol.Condition != nil && rateLimitPol.Condition.JWT != nil {
		lrz.GroupValue = rateLimitPol.Condition.JWT.Match
		lrz.PolicyValue = fmt.Sprintf("rl_%s_%s_match_%s",
			ownerDetails.vsNamespace,
			ownerDetails.vsName,
			strings.ToLower(rateLimitPol.Condition.JWT.Match),
		)

		lrz.GroupVariable = rfc1123ToSnake(fmt.Sprintf("$rl_%s_%s_group_%s_%s_%s",
			ownerDetails.vsNamespace,
			ownerDetails.vsName,
			strings.ToLower(
				strings.Join(
					strings.Split(rateLimitPol.Condition.JWT.Claim, "."), "_",
				),
			),
			context,
			encPath,
		))
		lrz.Key = rfc1123ToSnake(fmt.Sprintf("$%s", zoneName))
		lrz.PolicyResult = rateLimitPol.Key
		lrz.GroupDefault = rateLimitPol.Condition.Default
		lrz.GroupSource = generateAuthJwtClaimSetVariable(rateLimitPol.Condition.JWT.Claim, ownerDetails.vsNamespace, ownerDetails.vsName)
	}
	if rateLimitPol.Condition != nil && rateLimitPol.Condition.Variables != nil && len(*rateLimitPol.Condition.Variables) > 0 {
		variable := (*rateLimitPol.Condition.Variables)[0]
		lrz.GroupValue = fmt.Sprintf("\"%s\"", variable.Match)
		lrz.PolicyValue = rfc1123ToSnake(fmt.Sprintf("rl_%s_%s_match_%s",
			ownerDetails.vsNamespace,
			ownerDetails.vsName,
			strings.ToLower(policy.Name),
		))

		lrz.GroupVariable = rfc1123ToSnake(fmt.Sprintf("$rl_%s_%s_variable_%s_%s_%s",
			ownerDetails.vsNamespace,
			ownerDetails.vsName,
			strings.ReplaceAll(variable.Name, "$", ""),
			context,
			encPath,
		))
		lrz.Key = rfc1123ToSnake(fmt.Sprintf("$%s", zoneName))
		lrz.PolicyResult = rateLimitPol.Key
		lrz.GroupDefault = rateLimitPol.Condition.Default
		lrz.GroupSource = variable.Name
	}

	return lrz, warningText
}

func generateLRZGroupMaps(rlzs []version2.LimitReqZone) map[string]*version2.Map {
	m := make(map[string]*version2.Map)

	for _, lrz := range rlzs {
		if lrz.GroupVariable != "" {
			s := &version2.Map{
				Source:   lrz.GroupSource,
				Variable: lrz.GroupVariable,
				Parameters: []version2.Parameter{
					{
						Value:  lrz.GroupValue,
						Result: lrz.PolicyValue,
					},
				},
			}
			if lrz.GroupDefault {
				s.Parameters = append(s.Parameters, version2.Parameter{
					Value:  "default",
					Result: lrz.PolicyValue,
				})
			}
			if _, ok := m[lrz.GroupVariable]; ok {
				s.Parameters = append(s.Parameters, m[lrz.GroupVariable].Parameters...)
			}
			m[lrz.GroupVariable] = s
		}
	}

	return m
}

func generateLRZPolicyGroupMap(lrz version2.LimitReqZone) *version2.Map {
	defaultParam := version2.Parameter{
		Value:  "default",
		Result: "''",
	}

	params := []version2.Parameter{defaultParam}
	params = append(params, version2.Parameter{
		Value: lrz.PolicyValue,
		// Result needs prefixing with a value here, otherwise the zone key may end up being an empty value
		//   and the default rate limit would not be applied
		Result: fmt.Sprintf("Val%s", lrz.PolicyResult),
	})
	return &version2.Map{
		Source:     lrz.GroupVariable,
		Variable:   fmt.Sprintf("$%s", rfc1123ToSnake(lrz.ZoneName)),
		Parameters: params,
	}
}

func generateLimitReqOptions(rateLimitPol *conf_v1.RateLimit) version2.LimitReqOptions {
	return version2.LimitReqOptions{
		DryRun:     generateBool(rateLimitPol.DryRun, false),
		LogLevel:   generateString(rateLimitPol.LogLevel, "error"),
		RejectCode: generateIntFromPointer(rateLimitPol.RejectCode, 503),
	}
}

func generateAuthJwtClaimSet(jwtCondition conf_v1.JWTCondition, owner policyOwnerDetails) version2.AuthJWTClaimSet {
	return version2.AuthJWTClaimSet{
		Variable: generateAuthJwtClaimSetVariable(jwtCondition.Claim, owner.vsNamespace, owner.vsName),
		Claim:    generateAuthJwtClaimSetClaim(jwtCondition.Claim),
	}
}

func generateAuthJwtClaimSetVariable(claim string, vsNamespace string, vsName string) string {
	return strings.ReplaceAll(fmt.Sprintf("$jwt_%v_%v_%v", vsNamespace, vsName, strings.Join(strings.Split(claim, "."), "_")), "-", "_")
}

func generateAuthJwtClaimSetClaim(claim string) string {
	return strings.Join(strings.Split(claim, "."), " ")
}

func generateCacheConfig(cache *conf_v1.Cache, vsNamespace, vsName, ownerNamespace, ownerName, ownerType string) *version2.Cache {
	// Create unique zone name including VS namespace/name and owner namespace/name for policy reuse
	// This ensures that the same cache policy can be safely reused across different VS/VSR
	ownerTypeName := formatOwnerType(ownerType)
	var uniqueZoneName string
	if vsNamespace == ownerNamespace && vsName == ownerName {
		// Policy is applied directly to VirtualServer, use VS namespace/name only
		uniqueZoneName = fmt.Sprintf("%s_%s_%s_%s", vsNamespace, vsName, ownerTypeName, cache.CacheZoneName)
	} else {
		// Policy is applied to VirtualServerRoute, include both VS and owner info
		uniqueZoneName = fmt.Sprintf("%s_%s_%s_%s_%s_%s", vsNamespace, vsName, ownerNamespace, ownerName, ownerTypeName, cache.CacheZoneName)
	}

	// Set cache key with default if not provided
	cacheKey := "$scheme$proxy_host$request_uri"
	if cache.CacheKey != "" {
		cacheKey = cache.CacheKey
	}

	cacheConfig := &version2.Cache{
		ZoneName:              uniqueZoneName,
		Time:                  cache.Time,
		Valid:                 make(map[string]string),
		AllowedMethods:        cache.AllowedMethods,
		CachePurgeAllow:       cache.CachePurgeAllow,
		ZoneSize:              cache.CacheZoneSize,
		OverrideUpstreamCache: cache.OverrideUpstreamCache,
		Levels:                cache.Levels, // Pass Levels from Cache to CacheZone
		Inactive:              cache.Inactive,
		UseTempPath:           cache.UseTempPath,
		MaxSize:               cache.MaxSize,
		MinFree:               cache.MinFree,
		CacheKey:              cacheKey,
		CacheUseStale:         cache.CacheUseStale,
		CacheRevalidate:       cache.CacheRevalidate,
		CacheBackgroundUpdate: cache.CacheBackgroundUpdate,
		CacheMinUses:          cache.CacheMinUses,
	}

	// Map lock fields
	if cache.Lock != nil {
		cacheConfig.CacheLock = cache.Lock.Enable
		cacheConfig.CacheLockTimeout = cache.Lock.Timeout
		cacheConfig.CacheLockAge = cache.Lock.Age
	}

	// Map manager fields
	if cache.Manager != nil {
		cacheConfig.ManagerFiles = cache.Manager.Files
		cacheConfig.ManagerSleep = cache.Manager.Sleep
		cacheConfig.ManagerThreshold = cache.Manager.Threshold
	}

	// Map conditions
	if cache.Conditions != nil {
		cacheConfig.NoCacheConditions = cache.Conditions.NoCache
		cacheConfig.CacheBypassConditions = cache.Conditions.Bypass
	}

	// Convert allowed codes to proxy_cache_valid entries
	for _, code := range cache.AllowedCodes {
		if cache.Time != "" {
			if code.Type == intstr.String {
				// Handle the "any" string case
				cacheConfig.Valid[code.StrVal] = cache.Time
			} else {
				// Handle integer status codes
				cacheConfig.Valid[fmt.Sprintf("%d", code.IntVal)] = cache.Time
			}
		}
	}

	return cacheConfig
}

func rfc1123ToSnake(rfc1123String string) string {
	return strings.ReplaceAll(rfc1123String, "-", "_")
}

func formatOwnerType(ownerType string) string {
	if ownerType == "" {
		return "owner"
	}

	return rfc1123ToSnake(strings.ToLower(ownerType))
}
