package configs

import (
	"context"
	"fmt"

	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

// nolint:gocyclo
func generatePolicies(
	ctx context.Context,
	ownerDetails policyOwnerDetails,
	policyRefs []conf_v1.PolicyReference,
	policies map[string]*conf_v1.Policy,
	pathContext string,
	path string,
	policyOpts policyOptions,
	replicas int,
	bundleValidator bundleValidator,
	oidcPolCfg *oidcPolicyCfg,
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
					replicas,
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
				res = config.addOIDCConfig(pol.Spec.OIDC, key, polNamespace, policyOpts, oidcPolCfg)
			case pol.Spec.APIKey != nil:
				res = config.addAPIKeyConfig(pol.Spec.APIKey, key, polNamespace, ownerDetails.vsNamespace,
					ownerDetails.vsName, policyOpts.secretRefs)
			case pol.Spec.WAF != nil:
				res = config.addWAFConfig(ctx, pol.Spec.WAF, key, polNamespace, policyOpts.apResources)
			case pol.Spec.Cache != nil:
				res = config.addCacheConfig(pol.Spec.Cache, key, ownerDetails.vsNamespace, ownerDetails.vsName, ownerDetails.ownerNamespace, ownerDetails.ownerName)
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
