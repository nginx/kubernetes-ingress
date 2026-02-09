package configs

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestGeneratePolicies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerDetails := policyOwnerDetails{
		owner:          nil, // nil is OK for the unit test
		ownerNamespace: "default",
		vsNamespace:    "default",
		vsName:         "test",
		ownerName:      "test",
	}
	mTLSCertPath := "/etc/nginx/secrets/default-ingress-mtls-secret-ca.crt"
	mTLSCrlPath := "/etc/nginx/secrets/default-ingress-mtls-secret-ca.crl"
	mTLSCertAndCrlPath := fmt.Sprintf("%s %s", mTLSCertPath, mTLSCrlPath)
	policyOpts := policyOptions{
		tls:      true,
		zoneSync: false,
		secretRefs: map[string]*secrets.SecretReference{
			"default/ingress-mtls-secret": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeCA,
				},
				Path: mTLSCertPath,
			},
			"default/ingress-mtls-secret-crl": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeCA,
					Data: map[string][]byte{
						"ca.crl": []byte("base64crl"),
					},
				},
				Path: mTLSCertAndCrlPath,
			},
			"default/egress-mtls-secret": {
				Secret: &api_v1.Secret{
					Type: api_v1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-egress-mtls-secret",
			},
			"default/egress-trusted-ca-secret": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeCA,
				},
				Path: "/etc/nginx/secrets/default-egress-trusted-ca-secret",
			},
			"default/egress-trusted-ca-secret-crl": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeCA,
				},
				Path: mTLSCertAndCrlPath,
			},
			"default/jwt-secret": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeJWK,
				},
				Path: "/etc/nginx/secrets/default-jwt-secret",
			},
			"default/htpasswd-secret": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeHtpasswd,
				},
				Path: "/etc/nginx/secrets/default-htpasswd-secret",
			},
			"default/oidc-secret": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeOIDC,
					Data: map[string][]byte{
						"client-secret": []byte("super_secret_123"),
					},
				},
			},
			"default/api-key-secret": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"client1": []byte("password"),
					},
				},
			},
			"default/api-key-secret-2": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"client2": []byte("password2"),
					},
				},
			},
		},
		defaultCABundle: "/etc/ssl/certs/ca-certificate.crt",
		apResources: &appProtectResourcesForVS{
			Policies: map[string]string{
				"default/dataguard-alarm": "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
			},
			LogConfs: map[string]string{
				"default/logconf": "/etc/nginx/waf/nac-logconfs/default-logconf",
			},
		},
	}

	tests := []struct {
		policyRefs []conf_v1.PolicyReference
		policies   map[string]*conf_v1.Policy
		context    string
		path       string
		expected   policiesCfg
		msg        string
	}{
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "allow-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/allow-policy": {
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expected: policiesCfg{
				Allow:   []string{"127.0.0.1"},
				Context: ctx,
			},
			msg: "explicit reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name: "allow-policy",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/allow-policy": {
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expected: policiesCfg{
				Allow:   []string{"127.0.0.1"},
				Context: ctx,
			},
			msg: "implicit reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name: "allow-policy-1",
				},
				{
					Name: "allow-policy-2",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/allow-policy-1": {
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
				"default/allow-policy-2": {
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.2"},
						},
					},
				},
			},
			expected: policiesCfg{
				Allow:   []string{"127.0.0.1", "127.0.0.2"},
				Context: ctx,
			},
			msg: "merging",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "rateLimit-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/rateLimit-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							LogLevel: "notice",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				RateLimit: rateLimit{
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit_policy_default_test",
						},
					},
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							ZoneName: "pol_rl_default_rateLimit_policy_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "notice",
						RejectCode: 503,
					},
				},
			},
			msg: "rate limit reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "rateLimit-policy",
					Namespace: "default",
				},
				{
					Name:      "rateLimit-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/rateLimit-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
						},
					},
				},
				"default/rateLimit-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test2",
							ZoneSize: "20M",
							Rate:     "20r/s",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							ZoneName: "pol_rl_default_rateLimit_policy_default_test",
						},
						{
							Key:      "test2",
							ZoneSize: "20M",
							Rate:     "20r/s",
							ZoneName: "pol_rl_default_rateLimit_policy2_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "error",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit_policy_default_test",
						},
						{
							ZoneName: "pol_rl_default_rateLimit_policy2_default_test",
						},
					},
				},
			},
			msg: "multi rate limit reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "rateLimitScale-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/rateLimitScale-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimitScale-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							LogLevel: "notice",
							Scale:    true,
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "5r/s",
							ZoneName: "pol_rl_default_rateLimitScale_policy_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "notice",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimitScale_policy_default_test",
						},
					},
				},
			},
			msg: "rate limit reference with scale",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "rateLimit-basic-policy",
					Namespace: "default",
				},
				{
					Name:      "rateLimit-premium-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/rateLimit-basic-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-basic-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "$apikey_client_name",
							ZoneSize: "10M",
							Rate:     "10r/s",
							LogLevel: "notice",
							Condition: &conf_v1.RateLimitCondition{
								Variables: &[]conf_v1.VariableCondition{
									{
										Name:  "$apikey_client_name",
										Match: "basic",
									},
								},
								Default: true,
							},
						},
					},
				},
				"default/rateLimit-premium-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-premium-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "$apikey_client_name",
							ZoneSize: "10M",
							Rate:     "100r/s",
							LogLevel: "notice",
							Condition: &conf_v1.RateLimitCondition{
								Variables: &[]conf_v1.VariableCondition{
									{
										Name:  "$apikey_client_name",
										Match: "premium",
									},
								},
							},
						},
					},
				},
			},
			context: "route",
			path:    "/coffee",
			expected: policiesCfg{
				Context: ctx,
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:           "$pol_rl_default_rateLimit_basic_policy_default_test",
							ZoneSize:      "10M",
							Rate:          "10r/s",
							ZoneName:      "pol_rl_default_rateLimit_basic_policy_default_test",
							GroupValue:    `"basic"`,
							GroupVariable: "$rl_default_test_variable_apikey_client_name_route_L2NvZmZlZQ",
							PolicyValue:   "rl_default_test_match_ratelimit_basic_policy",
							PolicyResult:  "$apikey_client_name",
							GroupSource:   "$apikey_client_name",
							GroupDefault:  true,
						},
						{
							Key:           "$pol_rl_default_rateLimit_premium_policy_default_test",
							ZoneSize:      "10M",
							Rate:          "100r/s",
							ZoneName:      "pol_rl_default_rateLimit_premium_policy_default_test",
							GroupValue:    `"premium"`,
							GroupVariable: "$rl_default_test_variable_apikey_client_name_route_L2NvZmZlZQ",
							PolicyValue:   "rl_default_test_match_ratelimit_premium_policy",
							PolicyResult:  "$apikey_client_name",
							GroupSource:   "$apikey_client_name",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "notice",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit_basic_policy_default_test",
						},
						{
							ZoneName: "pol_rl_default_rateLimit_premium_policy_default_test",
						},
					},
					GroupMaps: []version2.Map{
						{
							Source:   "$apikey_client_name",
							Variable: "$rl_default_test_variable_apikey_client_name_route_L2NvZmZlZQ",
							Parameters: []version2.Parameter{
								{Value: `"premium"`, Result: "rl_default_test_match_ratelimit_premium_policy"},
								{Value: `"basic"`, Result: "rl_default_test_match_ratelimit_basic_policy"},
								{Value: "default", Result: "rl_default_test_match_ratelimit_basic_policy"},
							},
						},
					},
					PolicyGroupMaps: []version2.Map{
						{
							Source:   "$rl_default_test_variable_apikey_client_name_route_L2NvZmZlZQ",
							Variable: "$pol_rl_default_rateLimit_basic_policy_default_test",
							Parameters: []version2.Parameter{
								{Value: "default", Result: "''"},
								{Value: "rl_default_test_match_ratelimit_basic_policy", Result: "Val$apikey_client_name"},
							},
						},
						{
							Source:   "$rl_default_test_variable_apikey_client_name_route_L2NvZmZlZQ",
							Variable: "$pol_rl_default_rateLimit_premium_policy_default_test",
							Parameters: []version2.Parameter{
								{Value: "default", Result: "''"},
								{Value: "rl_default_test_match_ratelimit_premium_policy", Result: "Val$apikey_client_name"},
							},
						},
					},
				},
			},
			msg: "tiered rate limits",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "jwt-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/jwt-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:  "My Test API",
							Secret: "jwt-secret",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				JWTAuth: jwtAuth{
					Auth: &version2.JWTAuth{
						Secret: "/etc/nginx/secrets/default-jwt-secret",
						Realm:  "My Test API",
					},
					JWKSEnabled: false,
				},
			},
			msg: "jwt reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "jwt-policy-2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/jwt-policy-2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy-2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:    "My Test API",
							JwksURI:  "https://idp.example.com:443/keys",
							KeyCache: "1h",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				JWTAuth: jwtAuth{
					Auth: &version2.JWTAuth{
						Key:   "default/jwt-policy-2",
						Realm: "My Test API",
						JwksURI: version2.JwksURI{
							JwksScheme:     "https",
							JwksHost:       "idp.example.com",
							JwksPort:       "443",
							JwksPath:       "/keys",
							JwksSNIName:    "",
							JwksSNIEnabled: false,
							SSLVerify:      false,
							TrustedCert:    "",
							SSLVerifyDepth: 1,
						},
						KeyCache: "1h",
					},
					JWKSEnabled: true,
				},
			},
			msg: "Basic jwks example",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "jwt-policy-2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/jwt-policy-2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy-2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:    "My Test API",
							JwksURI:  "https://idp.example.com/keys",
							KeyCache: "1h",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				JWTAuth: jwtAuth{
					Auth: &version2.JWTAuth{
						Key:   "default/jwt-policy-2",
						Realm: "My Test API",
						JwksURI: version2.JwksURI{
							JwksScheme:     "https",
							JwksHost:       "idp.example.com",
							JwksPort:       "",
							JwksPath:       "/keys",
							JwksSNIName:    "",
							JwksSNIEnabled: false,
							SSLVerify:      false,
							TrustedCert:    "",
							SSLVerifyDepth: 1,
						},
						KeyCache: "1h",
					},
					JWKSEnabled: true,
				},
			},
			msg: "Basic jwks example, no port in JwksURI",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "basic-auth-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/basic-auth-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Realm:  "My Test API",
							Secret: "htpasswd-secret",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				BasicAuth: &version2.BasicAuth{
					Secret: "/etc/nginx/secrets/default-htpasswd-secret",
					Realm:  "My Test API",
				},
			},
			msg: "basic auth reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
							VerifyClient:     "off",
						},
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				Context: ctx,
				IngressMTLS: &version2.IngressMTLS{
					ClientCert:   mTLSCertPath,
					VerifyClient: "off",
					VerifyDepth:  1,
				},
			},
			msg: "ingressMTLS reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy-crl",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy-crl": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy-crl",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret-crl",
							VerifyClient:     "off",
						},
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				Context: ctx,
				IngressMTLS: &version2.IngressMTLS{
					ClientCert:   mTLSCertPath,
					ClientCrl:    mTLSCrlPath,
					VerifyClient: "off",
					VerifyDepth:  1,
				},
			},
			msg: "ingressMTLS reference with ca.crl field in secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy-crl",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy-crl": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy-crl",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
							CrlFileName:      "default-ingress-mtls-secret-ca.crl",
							VerifyClient:     "off",
						},
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				Context: ctx,
				IngressMTLS: &version2.IngressMTLS{
					ClientCert:   mTLSCertPath,
					ClientCrl:    mTLSCrlPath,
					VerifyClient: "off",
					VerifyDepth:  1,
				},
			},
			msg: "ingressMTLS reference with crl field in policy",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret:         "egress-mtls-secret",
							ServerName:        true,
							SessionReuse:      createPointerFromBool(false),
							TrustedCertSecret: "egress-trusted-ca-secret",
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				Context: ctx,
				EgressMTLS: &version2.EgressMTLS{
					Certificate:    "/etc/nginx/secrets/default-egress-mtls-secret",
					CertificateKey: "/etc/nginx/secrets/default-egress-mtls-secret",
					Ciphers:        "DEFAULT",
					Protocols:      "TLSv1 TLSv1.1 TLSv1.2",
					ServerName:     true,
					SessionReuse:   false,
					VerifyDepth:    1,
					VerifyServer:   false,
					TrustedCert:    "/etc/nginx/secrets/default-egress-trusted-ca-secret",
					SSLName:        "$proxy_host",
				},
			},
			msg: "egressMTLS reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret:         "egress-mtls-secret",
							ServerName:        true,
							SessionReuse:      createPointerFromBool(false),
							TrustedCertSecret: "egress-trusted-ca-secret-crl",
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				Context: ctx,
				EgressMTLS: &version2.EgressMTLS{
					Certificate:    "/etc/nginx/secrets/default-egress-mtls-secret",
					CertificateKey: "/etc/nginx/secrets/default-egress-mtls-secret",
					Ciphers:        "DEFAULT",
					Protocols:      "TLSv1 TLSv1.1 TLSv1.2",
					ServerName:     true,
					SessionReuse:   false,
					VerifyDepth:    1,
					VerifyServer:   false,
					TrustedCert:    mTLSCertPath,
					SSLName:        "$proxy_host",
				},
			},
			msg: "egressMTLS with crt and crl",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							AuthEndpoint:          "http://example.com/auth",
							TokenEndpoint:         "http://example.com/token",
							JWKSURI:               "http://example.com/jwks",
							ClientID:              "client-id",
							ClientSecret:          "oidc-secret",
							Scope:                 "scope",
							RedirectURI:           "/redirect",
							ZoneSyncLeeway:        createPointerFromInt(20),
							AccessTokenEnable:     true,
							EndSessionEndpoint:    "http://example.com/logout",
							PostLogoutRedirectURI: "/_logout",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				OIDC:    true,
			},
			msg: "oidc reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "api-key-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/api-key-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				APIKey: apiKeyAuth{
					Key: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_test_api_key_policy",
					},
					Enabled:   true,
					ClientMap: nil,
					Clients: []apiKeyClient{
						{
							ClientID:  "client1",
							HashedKey: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
						},
					},
				},
			},
			msg: "api key reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "api-key-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/api-key-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				APIKey: apiKeyAuth{
					Key: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_test_api_key_policy",
					},
					Enabled:   true,
					ClientMap: nil,
					Clients: []apiKeyClient{
						{
							ClientID:  "client1",
							HashedKey: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
						},
					},
				},
			},
			msg: "api key same secrets for different policies",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "waf-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/waf-policy": {
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "default/dataguard-alarm",
							SecurityLog: &conf_v1.SecurityLog{
								Enable:    true,
								ApLogConf: "default/logconf",
								LogDest:   "syslog:server=127.0.0.1:514",
							},
						},
					},
				},
			},
			context: "route",
			path:    "/coffee",
			expected: policiesCfg{
				Context: ctx,
				WAF: &version2.WAF{
					Enable:              "on",
					ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
					ApSecurityLogEnable: true,
					ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf syslog:server=127.0.0.1:514"},
				},
			},
			msg: "WAF reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "cache-policy-basic",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/cache-policy-basic": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cache-policy-basic",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						Cache: &conf_v1.Cache{
							CacheZoneName: "basic-cache",
							CacheZoneSize: "10m",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				Cache: &version2.Cache{
					ZoneName: "default_test_basic-cache",
					ZoneSize: "10m",
					Valid:    map[string]string{},
					CacheKey: "$scheme$proxy_host$request_uri",
				},
			},
			msg: "basic cache policy reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "cache-policy-full",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/cache-policy-full": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cache-policy-full",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						Cache: &conf_v1.Cache{
							CacheZoneName:         "full-cache",
							CacheZoneSize:         "100m",
							AllowedCodes:          []intstr.IntOrString{intstr.FromString("any")},
							AllowedMethods:        []string{"GET", "HEAD", "POST"},
							Time:                  "1h",
							OverrideUpstreamCache: true,
							Levels:                "1:2",
							Inactive:              "2d",
							UseTempPath:           false,
							MaxSize:               "5g",
							MinFree:               "500m",
							Manager: &conf_v1.CacheManager{
								Files:     &[]int{1000}[0],
								Sleep:     "50ms",
								Threshold: "150ms",
							},
							CacheKey:              "$scheme$proxy_host$request_uri$is_args$args",
							CacheUseStale:         []string{"error", "timeout", "invalid_header", "updating", "http_500", "http_502", "http_503"},
							CacheRevalidate:       true,
							CacheBackgroundUpdate: true,
							CacheMinUses:          &[]int{3}[0],
							Lock: &conf_v1.CacheLock{
								Enable:  true,
								Timeout: "10s",
								Age:     "30s",
							},
							CachePurgeAllow: []string{"127.0.0.1", "10.0.0.0/8"},
							Conditions: &conf_v1.CacheConditions{
								NoCache: []string{"$http_pragma", "$http_authorization"},
								Bypass:  []string{"$cookie_nocache", "$arg_nocache", "$arg_comment"},
							},
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				Cache: &version2.Cache{
					ZoneName:              "default_test_full-cache",
					ZoneSize:              "100m",
					Time:                  "1h",
					Valid:                 map[string]string{"any": "1h"},
					AllowedMethods:        []string{"GET", "HEAD", "POST"},
					OverrideUpstreamCache: true,
					Levels:                "1:2",
					Inactive:              "2d",
					UseTempPath:           false,
					MaxSize:               "5g",
					MinFree:               "500m",
					ManagerFiles:          &[]int{1000}[0],
					ManagerSleep:          "50ms",
					ManagerThreshold:      "150ms",
					CacheKey:              "$scheme$proxy_host$request_uri$is_args$args",
					CacheUseStale:         []string{"error", "timeout", "invalid_header", "updating", "http_500", "http_502", "http_503"},
					CacheRevalidate:       true,
					CacheBackgroundUpdate: true,
					CacheMinUses:          &[]int{3}[0],
					CacheLock:             true,
					CacheLockTimeout:      "10s",
					CacheLockAge:          "30s",
					CachePurgeAllow:       []string{"127.0.0.1", "10.0.0.0/8"},
					NoCacheConditions:     []string{"$http_pragma", "$http_authorization"},
					CacheBypassConditions: []string{"$cookie_nocache", "$arg_nocache", "$arg_comment"},
				},
			},
			msg: "full cache policy with all options",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "cache-policy-status-codes",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/cache-policy-status-codes": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cache-policy-status-codes",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						Cache: &conf_v1.Cache{
							CacheZoneName: "status-cache",
							CacheZoneSize: "50m",
							AllowedCodes: []intstr.IntOrString{
								intstr.FromInt(200),
								intstr.FromInt(301),
								intstr.FromInt(404),
							},
							Time: "30m",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				Cache: &version2.Cache{
					ZoneName: "default_test_status-cache",
					ZoneSize: "50m",
					Time:     "30m",
					Valid: map[string]string{
						"200": "30m",
						"301": "30m",
						"404": "30m",
					},
					CacheKey: "$scheme$proxy_host$request_uri",
				},
			},
			msg: "cache policy with specific status codes",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "cache-policy-methods",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/cache-policy-methods": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cache-policy-methods",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						Cache: &conf_v1.Cache{
							CacheZoneName:  "methods-cache",
							CacheZoneSize:  "25m",
							AllowedMethods: []string{"GET", "HEAD"},
							Levels:         "2:2",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				Cache: &version2.Cache{
					ZoneName:       "default_test_methods-cache",
					ZoneSize:       "25m",
					Valid:          map[string]string{},
					AllowedMethods: []string{"GET", "HEAD"},
					Levels:         "2:2",
					CacheKey:       "$scheme$proxy_host$request_uri",
				},
			},
			msg: "cache policy with allowed methods and levels",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "cache-policy-purge",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/cache-policy-purge": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cache-policy-purge",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						Cache: &conf_v1.Cache{
							CacheZoneName:   "purge-cache",
							CacheZoneSize:   "75m",
							CachePurgeAllow: []string{"192.168.1.0/24", "10.0.0.1"},
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				Cache: &version2.Cache{
					ZoneName:        "default_test_purge-cache",
					ZoneSize:        "75m",
					Valid:           map[string]string{},
					CachePurgeAllow: []string{"192.168.1.0/24", "10.0.0.1"},
					CacheKey:        "$scheme$proxy_host$request_uri",
				},
			},
			msg: "cache policy with purge allow IPs",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name: "cache-policy-implicit",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/cache-policy-implicit": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cache-policy-implicit",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						Cache: &conf_v1.Cache{
							CacheZoneName: "implicit-cache",
							CacheZoneSize: "15m",
							Time:          "45m",
						},
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				Cache: &version2.Cache{
					ZoneName: "default_test_implicit-cache",
					ZoneSize: "15m",
					Time:     "45m",
					Valid:    map[string]string{},
					CacheKey: "$scheme$proxy_host$request_uri",
				},
			},
			msg: "implicit cache policy reference",
		},
	}

	vsc := newVirtualServerConfigurator(&ConfigParams{Context: ctx}, false, false, &StaticConfigParams{}, false, &fakeBV)
	// required to test the scaling of the ratelimit
	vsc.IngressControllerReplicas = 2

	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			result, warnings := generatePolicies(ctx, ownerDetails, tc.policyRefs, tc.policies, tc.context, tc.path, policyOpts, vsc.IngressControllerReplicas, vsc.bundleValidator, &oidcPolicyCfg{})

			result.BundleValidator = nil

			if !reflect.DeepEqual(tc.expected, result) {
				t.Error(cmp.Diff(tc.expected, result, cmpopts.IgnoreFields(policiesCfg{}, "Context")))
			}
			if len(warnings) > 0 {
				t.Errorf("generatePolicies() returned unexpected warnings %v for the case of %s", warnings, tc.msg)
			}
		})
	}
}

func TestGeneratePolicies_GeneratesWAFPolicyOnValidApBundle(t *testing.T) {
	t.Parallel()

	ownerDetails := policyOwnerDetails{
		owner:          nil, // nil is OK for the unit test
		ownerNamespace: "default",
		vsNamespace:    "default",
		vsName:         "test",
	}

	tests := []struct {
		name       string
		policyRefs []conf_v1.PolicyReference
		policies   map[string]*conf_v1.Policy
		policyOpts policyOptions
		context    string
		path       string
		want       policiesCfg
	}{
		{
			name: "valid bundle",
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "waf-bundle",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/waf-bundle": {
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApBundle: "testWAFPolicyBundle.tgz",
						},
					},
				},
			},
			context: "route",
			want: policiesCfg{
				Context: ctx,
				WAF: &version2.WAF{
					Enable:   "on",
					ApBundle: "/fake/bundle/path/testWAFPolicyBundle.tgz",
				},
			},
		},
		{
			name: "valid bundle with logConf",
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "waf-bundle",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/waf-bundle": {
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApBundle: "testWAFPolicyBundle.tgz",
							SecurityLogs: []*conf_v1.SecurityLog{
								{
									Enable:      true,
									ApLogBundle: "secops_dashboard.tgz",
								},
							},
						},
					},
				},
			},
			context: "route",
			want: policiesCfg{
				Context: ctx,
				WAF: &version2.WAF{
					Enable:              "on",
					ApBundle:            "/fake/bundle/path/testWAFPolicyBundle.tgz",
					ApSecurityLogEnable: true,
					ApLogConf:           []string{"/fake/bundle/path/secops_dashboard.tgz syslog:server=localhost:514"},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, warnings := generatePolicies(ctx, ownerDetails, tc.policyRefs, tc.policies, tc.context, tc.path, policyOptions{apResources: &appProtectResourcesForVS{}}, 1, &fakeBV, nil)
			res.BundleValidator = nil
			if !reflect.DeepEqual(tc.want, res) {
				t.Error(cmp.Diff(tc.want, res))
			}
			if len(warnings) > 0 {
				t.Errorf("generatePolicies() returned unexpected warnings %v for the case of %s", warnings, tc.name)
			}
		})
	}
}

func TestGeneratePoliciesFails(t *testing.T) {
	t.Parallel()
	ownerDetails := policyOwnerDetails{
		owner:          nil, // nil is OK for the unit test
		ownerName:      "test",
		ownerNamespace: "default",
		vsNamespace:    "default",
		vsName:         "test",
	}

	dryRunOverride := true
	rejectCodeOverride := 505

	ingressMTLSCertPath := "/etc/nginx/secrets/default-ingress-mtls-secret-ca.crt"
	ingressMTLSCrlPath := "/etc/nginx/secrets/default-ingress-mtls-secret-ca.crl"

	tests := []struct {
		policyRefs        []conf_v1.PolicyReference
		policies          map[string]*conf_v1.Policy
		policyOpts        policyOptions
		trustedCAFileName string
		context           string
		path              string
		oidcPolCfg        *oidcPolicyCfg
		expected          policiesCfg
		expectedWarnings  Warnings
		expectedOidc      *oidcPolicyCfg
		msg               string
	}{
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "allow-policy",
					Namespace: "default",
				},
			},
			policies:   map[string]*conf_v1.Policy{},
			policyOpts: policyOptions{},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					"Policy default/allow-policy is missing or invalid",
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "missing policy",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name: "allow-policy",
				},
				{
					Name: "deny-policy",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/allow-policy": {
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
				"default/deny-policy": {
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Deny: []string{"127.0.0.2"},
						},
					},
				},
			},
			policyOpts: policyOptions{},
			expected: policiesCfg{
				Context: ctx,
				Allow:   []string{"127.0.0.1"},
				Deny:    []string{"127.0.0.2"},
			},
			expectedWarnings: Warnings{
				nil: {
					"AccessControl policy (or policies) with deny rules is overridden by policy (or policies) with allow rules",
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "conflicting policies",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "rateLimit-policy",
					Namespace: "default",
				},
				{
					Name:      "rateLimit-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/rateLimit-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
						},
					},
				},
				"default/rateLimit-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:        "test2",
							ZoneSize:   "20M",
							Rate:       "20r/s",
							DryRun:     &dryRunOverride,
							LogLevel:   "info",
							RejectCode: &rejectCodeOverride,
						},
					},
				},
			},
			policyOpts: policyOptions{},
			expected: policiesCfg{
				Context: ctx,
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							ZoneName: "pol_rl_default_rateLimit_policy_default_test",
						},
						{
							Key:      "test2",
							ZoneSize: "20M",
							Rate:     "20r/s",
							ZoneName: "pol_rl_default_rateLimit_policy2_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "error",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit_policy_default_test",
						},
						{
							ZoneName: "pol_rl_default_rateLimit_policy2_default_test",
						},
					},
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`RateLimit policy default/rateLimit-policy2 with limit request option dryRun='true' is overridden to dryRun='false' by the first policy reference in this context`,
					`RateLimit policy default/rateLimit-policy2 with limit request option logLevel='info' is overridden to logLevel='error' by the first policy reference in this context`,
					`RateLimit policy default/rateLimit-policy2 with limit request option rejectCode='505' is overridden to rejectCode='503' by the first policy reference in this context`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "rate limit policy limit request option override",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "rateLimit-policy",
					Namespace: "default",
				},
				{
					Name:      "rateLimit-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/rateLimit-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							Condition: &conf_v1.RateLimitCondition{
								JWT: &conf_v1.JWTCondition{
									Match: "Basic",
									Claim: "user_details.level",
								},
								Default: true,
							},
						},
					},
				},
				"default/rateLimit-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "rateLimit-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test2",
							ZoneSize: "20M",
							Rate:     "20r/s",
							Condition: &conf_v1.RateLimitCondition{
								JWT: &conf_v1.JWTCondition{
									Match: "Premium",
									Claim: "user_details.level",
								},
								Default: true,
							},
						},
					},
				},
			},
			policyOpts: policyOptions{},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Tiered rate-limit Policies on [default/test] contain conflicting default values`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "tiered rate limit policy with duplicate defaults",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "jwt-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/jwt-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:  "test",
							Secret: "jwt-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/jwt-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeJWK,
						},
						Error: errors.New("secret is invalid"),
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`JWT policy default/jwt-policy references an invalid secret default/jwt-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "jwt reference missing secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "jwt-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/jwt-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:  "test",
							Secret: "jwt-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/jwt-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`JWT policy default/jwt-policy references a secret default/jwt-secret of a wrong type 'nginx.org/ca', must be 'nginx.org/jwk'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "jwt references wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "jwt-policy",
					Namespace: "default",
				},
				{
					Name:      "jwt-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/jwt-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:  "test",
							Secret: "jwt-secret",
						},
					},
				},
				"default/jwt-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Realm:  "test",
							Secret: "jwt-secret2",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/jwt-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeJWK,
						},
						Path: "/etc/nginx/secrets/default-jwt-secret",
					},
					"default/jwt-secret2": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeJWK,
						},
						Path: "/etc/nginx/secrets/default-jwt-secret2",
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				JWTAuth: jwtAuth{
					Auth: &version2.JWTAuth{
						Secret: "/etc/nginx/secrets/default-jwt-secret",
						Realm:  "test",
					},
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple jwt policies in the same context is not valid. JWT policy default/jwt-policy2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "multi jwt reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "basic-auth-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/basic-auth-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Realm:  "test",
							Secret: "htpasswd-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/htpasswd-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeHtpasswd,
						},
						Error: errors.New("secret is invalid"),
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Basic Auth policy default/basic-auth-policy references an invalid secret default/htpasswd-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "basic auth reference missing secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "basic-auth-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/basic-auth-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Realm:  "test",
							Secret: "htpasswd-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/htpasswd-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Basic Auth policy default/basic-auth-policy references a secret default/htpasswd-secret of a wrong type 'nginx.org/ca', must be 'nginx.org/htpasswd'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "basic auth references wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "basic-auth-policy",
					Namespace: "default",
				},
				{
					Name:      "basic-auth-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/basic-auth-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Realm:  "test",
							Secret: "htpasswd-secret",
						},
					},
				},
				"default/basic-auth-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "basic-auth-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						BasicAuth: &conf_v1.BasicAuth{
							Realm:  "test",
							Secret: "htpasswd-secret2",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/htpasswd-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeHtpasswd,
						},
						Path: "/etc/nginx/secrets/default-htpasswd-secret",
					},
					"default/htpasswd-secret2": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeHtpasswd,
						},
						Path: "/etc/nginx/secrets/default-htpasswd-secret2",
					},
				},
			},
			expected: policiesCfg{
				Context: ctx,
				BasicAuth: &version2.BasicAuth{
					Secret: "/etc/nginx/secrets/default-htpasswd-secret",
					Realm:  "test",
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple basic auth policies in the same context is not valid. Basic auth policy default/basic-auth-policy2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "multi basic auth reference",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				tls: true,
				secretRefs: map[string]*secrets.SecretReference{
					"default/ingress-mtls-secret": {
						Error: errors.New("secret is invalid"),
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`IngressMTLS policy "default/ingress-mtls-policy" references an invalid secret default/ingress-mtls-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "ingress mtls reference an invalid secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				tls: true,
				secretRefs: map[string]*secrets.SecretReference{
					"default/ingress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: api_v1.SecretTypeTLS,
						},
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`IngressMTLS policy default/ingress-mtls-policy references a secret default/ingress-mtls-secret of a wrong type 'kubernetes.io/tls', must be 'nginx.org/ca'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "ingress mtls references wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
				{
					Name:      "ingress-mtls-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
						},
					},
				},
				"default/ingress-mtls-policy2": {
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret2",
						},
					},
				},
			},
			policyOpts: policyOptions{
				tls: true,
				secretRefs: map[string]*secrets.SecretReference{
					"default/ingress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
						Path: ingressMTLSCertPath,
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				Context: ctx,
				IngressMTLS: &version2.IngressMTLS{
					ClientCert:   ingressMTLSCertPath,
					VerifyClient: "on",
					VerifyDepth:  1,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple ingressMTLS policies are not allowed. IngressMTLS policy default/ingress-mtls-policy2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "multi ingress mtls",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				tls: true,
				secretRefs: map[string]*secrets.SecretReference{
					"default/ingress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
						Path: ingressMTLSCertPath,
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`IngressMTLS policy default/ingress-mtls-policy is not allowed in the route context`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "ingress mtls in the wrong context",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				tls: false,
				secretRefs: map[string]*secrets.SecretReference{
					"default/ingress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
						Path: ingressMTLSCertPath,
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`TLS must be enabled in VirtualServer for IngressMTLS policy default/ingress-mtls-policy`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "ingress mtls missing TLS config",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "ingress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/ingress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "ingress-mtls-secret",
							CrlFileName:      "default-ingress-mtls-secret-ca.crl",
						},
					},
				},
			},
			policyOpts: policyOptions{
				tls: true,
				secretRefs: map[string]*secrets.SecretReference{
					"default/ingress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
							Data: map[string][]byte{
								"ca.crl": []byte("base64crl"),
							},
						},
						Path: ingressMTLSCertPath,
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				Context: ctx,
				IngressMTLS: &version2.IngressMTLS{
					ClientCert:   ingressMTLSCertPath,
					ClientCrl:    ingressMTLSCrlPath,
					VerifyClient: "on",
					VerifyDepth:  1,
				},
				ErrorReturn: nil,
			},
			expectedWarnings: Warnings{
				nil: {
					`Both ca.crl in the Secret and ingressMTLS.crlFileName fields cannot be used. ca.crl in default/ingress-mtls-secret will be ignored and default/ingress-mtls-policy will be applied`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "ingress mtls ca.crl and ingressMTLS.Crl set",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
				{
					Name:      "egress-mtls-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "egress-mtls-secret",
						},
					},
				},
				"default/egress-mtls-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "egress-mtls-secret2",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/egress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: api_v1.SecretTypeTLS,
						},
						Path: "/etc/nginx/secrets/default-egress-mtls-secret",
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				Context: ctx,
				EgressMTLS: &version2.EgressMTLS{
					Certificate:    "/etc/nginx/secrets/default-egress-mtls-secret",
					CertificateKey: "/etc/nginx/secrets/default-egress-mtls-secret",
					VerifyServer:   false,
					VerifyDepth:    1,
					Ciphers:        "DEFAULT",
					Protocols:      "TLSv1 TLSv1.1 TLSv1.2",
					SessionReuse:   true,
					SSLName:        "$proxy_host",
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple egressMTLS policies in the same context is not valid. EgressMTLS policy default/egress-mtls-policy2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "multi egress mtls",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TrustedCertSecret: "egress-trusted-secret",
							SSLName:           "foo.com",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/egress-trusted-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
						Error: errors.New("secret is invalid"),
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`EgressMTLS policy default/egress-mtls-policy references an invalid secret default/egress-trusted-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "egress mtls referencing an invalid CA secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "egress-mtls-secret",
							SSLName:   "foo.com",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/egress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeCA,
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`EgressMTLS policy default/egress-mtls-policy references a secret default/egress-mtls-secret of a wrong type 'nginx.org/ca', must be 'kubernetes.io/tls'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "egress mtls referencing wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TrustedCertSecret: "egress-trusted-secret",
							SSLName:           "foo.com",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/egress-trusted-secret": {
						Secret: &api_v1.Secret{
							Type: api_v1.SecretTypeTLS,
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`EgressMTLS policy default/egress-mtls-policy references a secret default/egress-trusted-secret of a wrong type 'kubernetes.io/tls', must be 'nginx.org/ca'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "egress trusted secret referencing wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "egress-mtls-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/egress-mtls-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "egress-mtls-secret",
							SSLName:   "foo.com",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/egress-mtls-secret": {
						Secret: &api_v1.Secret{
							Type: api_v1.SecretTypeTLS,
						},
						Error: errors.New("secret is invalid"),
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`EgressMTLS policy default/egress-mtls-policy references an invalid secret default/egress-mtls-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "egress mtls referencing missing tls secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret: "oidc-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/oidc-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeOIDC,
						},
						Error: errors.New("secret is invalid"),
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`OIDC policy default/oidc-policy references an invalid secret default/oidc-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "oidc referencing missing oidc secret",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret:          "oidc-secret",
							AuthEndpoint:          "http://foo.com/bar",
							TokenEndpoint:         "http://foo.com/bar",
							JWKSURI:               "http://foo.com/bar",
							EndSessionEndpoint:    "http://foo.com/bar",
							PostLogoutRedirectURI: "/_logout",
							AccessTokenEnable:     true,
							PKCEEnable:            true,
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/oidc-secret": {
						Secret: &api_v1.Secret{
							Type: api_v1.SecretTypeTLS,
						},
					},
				},
			},
			context: "spec",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`OIDC policy default/oidc-policy references a secret default/oidc-secret of a wrong type 'kubernetes.io/tls', must be 'nginx.org/oidc'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "oidc secret referencing wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy-2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy-1": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy-1",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientID:              "foo",
							ClientSecret:          "oidc-secret",
							AuthEndpoint:          "https://foo.com/auth",
							TokenEndpoint:         "https://foo.com/token",
							JWKSURI:               "https://foo.com/certs",
							EndSessionEndpoint:    "https://foo.com/logout",
							PostLogoutRedirectURI: "/_logout",
							AccessTokenEnable:     true,
						},
					},
				},
				"default/oidc-policy-2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy-2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientID:              "foo",
							ClientSecret:          "oidc-secret",
							AuthEndpoint:          "https://bar.com/auth",
							TokenEndpoint:         "https://bar.com/token",
							JWKSURI:               "https://bar.com/certs",
							EndSessionEndpoint:    "https://bar.com/logout",
							PostLogoutRedirectURI: "/_logout",
							AccessTokenEnable:     true,
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/oidc-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeOIDC,
							Data: map[string][]byte{
								"client-secret": []byte("super_secret_123"),
							},
						},
					},
				},
			},
			context: "route",
			oidcPolCfg: &oidcPolicyCfg{
				oidc: &version2.OIDC{
					AuthEndpoint:          "https://foo.com/auth",
					TokenEndpoint:         "https://foo.com/token",
					JwksURI:               "https://foo.com/certs",
					ClientID:              "foo",
					ClientSecret:          "super_secret_123",
					RedirectURI:           "/_codexch",
					Scope:                 "openid",
					ZoneSyncLeeway:        0,
					EndSessionEndpoint:    "https://foo.com/logout",
					PostLogoutRedirectURI: "/_logout",
					AccessTokenEnable:     true,
				},
				key: "default/oidc-policy-1",
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Only one oidc policy is allowed in a VirtualServer and its VirtualServerRoutes. Can't use default/oidc-policy-2. Use default/oidc-policy-1`,
				},
			},
			expectedOidc: &oidcPolicyCfg{
				oidc: &version2.OIDC{
					AuthEndpoint:          "https://foo.com/auth",
					TokenEndpoint:         "https://foo.com/token",
					JwksURI:               "https://foo.com/certs",
					ClientID:              "foo",
					ClientSecret:          "super_secret_123",
					RedirectURI:           "/_codexch",
					Scope:                 "openid",
					EndSessionEndpoint:    "https://foo.com/logout",
					PostLogoutRedirectURI: "/_logout",
					AccessTokenEnable:     true,
				},
				key: "default/oidc-policy-1",
			},
			msg: "multiple oidc policies",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy",
					Namespace: "default",
				},
				{
					Name:      "oidc-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret:          "oidc-secret",
							AuthEndpoint:          "https://foo.com/auth",
							TokenEndpoint:         "https://foo.com/token",
							JWKSURI:               "https://foo.com/certs",
							EndSessionEndpoint:    "https://foo.com/logout",
							PostLogoutRedirectURI: "/_logout",
							ClientID:              "foo",
							AccessTokenEnable:     true,
						},
					},
				},
				"default/oidc-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret:          "oidc-secret",
							AuthEndpoint:          "https://bar.com/auth",
							TokenEndpoint:         "https://bar.com/token",
							JWKSURI:               "https://bar.com/certs",
							EndSessionEndpoint:    "https://bar.com/logout",
							PostLogoutRedirectURI: "/_logout",
							ClientID:              "bar",
							AccessTokenEnable:     true,
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/oidc-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeOIDC,
							Data: map[string][]byte{
								"client-secret": []byte("super_secret_123"),
							},
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				Context: ctx,
				OIDC:    true,
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple oidc policies in the same context is not valid. OIDC policy default/oidc-policy2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{
				&version2.OIDC{
					AuthEndpoint:          "https://foo.com/auth",
					TokenEndpoint:         "https://foo.com/token",
					JwksURI:               "https://foo.com/certs",
					ClientID:              "foo",
					ClientSecret:          "super_secret_123",
					RedirectURI:           "/_codexch",
					Scope:                 "openid",
					EndSessionEndpoint:    "https://foo.com/logout",
					PostLogoutRedirectURI: "/_logout",
					ZoneSyncLeeway:        200,
					AccessTokenEnable:     true,
					VerifyDepth:           1,
				},
				"default/oidc-policy",
			},
			msg: "multi oidc",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "api-key-policy",
					Namespace: "default",
				},
				{
					Name:      "api-key-policy-2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/api-key-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
				"default/api-key-policy-2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy-2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"client1": []byte("password"),
							},
						},
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple API Key policies in the same context is not valid. API Key policy default/api-key-policy-2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "api key multi api key policies",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "api-key-policy",
					Namespace: "default",
				},
				{
					Name:      "api-key-policy-2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/api-key-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
				"default/api-key-policy-2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy-2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeJWK,
							Data: map[string][]byte{
								"client1": []byte("password"),
							},
						},
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`API Key policy default/api-key-policy references a secret default/api-key-secret of a wrong type 'nginx.org/jwk', must be 'nginx.org/apikey'`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "api key referencing wrong secret type",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "api-key-policy",
					Namespace: "default",
				},
				{
					Name:      "api-key-policy-2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/api-key-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
				"default/api-key-policy-2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "api-key-policy-2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						APIKey: &conf_v1.APIKey{
							SuppliedIn: &conf_v1.SuppliedIn{
								Header: []string{"X-API-Key"},
								Query:  []string{"api-key"},
							},
							ClientSecret: "api-key-secret",
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"client1": []byte("password"),
								"client2": []byte("password"),
							},
						},
						Error: errors.New("secret is invalid"),
					},
				},
			},
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`API Key default/api-key-policy references an invalid secret default/api-key-secret: secret is invalid`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "api key referencing invalid api key secrets",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "waf-policy",
					Namespace: "default",
				},
				{
					Name:      "waf-policy2",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/waf-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "default/dataguard-alarm",
						},
					},
				},
				"default/waf-policy2": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-policy2",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "default/dataguard-alarm",
						},
					},
				},
			},
			policyOpts: policyOptions{
				apResources: &appProtectResourcesForVS{
					Policies: map[string]string{
						"default/dataguard-alarm": "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
					},
					LogConfs: map[string]string{
						"default/logconf": "/etc/nginx/waf/nac-logconfs/default-logconf",
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				Context: ctx,
				WAF: &version2.WAF{
					Enable:   "on",
					ApPolicy: "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Multiple WAF policies in the same context is not valid. WAF policy default/waf-policy2 will be ignored`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "multi waf",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							ClientSecret:          "oidc-secret",
							AuthEndpoint:          "https://foo.com/auth",
							TokenEndpoint:         "https://foo.com/token",
							JWKSURI:               "https://foo.com/certs",
							EndSessionEndpoint:    "https://foo.com/logout",
							PostLogoutRedirectURI: "/_logout",
							ClientID:              "foo",
							AccessTokenEnable:     true,
							PKCEEnable:            true,
						},
					},
				},
			},
			policyOpts: policyOptions{
				secretRefs: map[string]*secrets.SecretReference{
					"default/oidc-secret": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeOIDC,
							Data: map[string][]byte{
								"client-secret": []byte("super_secret_123"),
							},
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`OIDC policy default/oidc-policy has a secret and PKCE enabled. Secrets can't be used with PKCE`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "oidc pkce yes secret yes",
		},
		{
			policyRefs: []conf_v1.PolicyReference{
				{
					Name:      "oidc-policy",
					Namespace: "default",
				},
			},
			policies: map[string]*conf_v1.Policy{
				"default/oidc-policy": {
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "oidc-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						OIDC: &conf_v1.OIDC{
							AuthEndpoint:          "https://foo.com/auth",
							TokenEndpoint:         "https://foo.com/token",
							JWKSURI:               "https://foo.com/certs",
							EndSessionEndpoint:    "https://foo.com/logout",
							PostLogoutRedirectURI: "/_logout",
							ClientID:              "foo",
							AccessTokenEnable:     true,
							PKCEEnable:            false,
						},
					},
				},
			},
			context: "route",
			expected: policiesCfg{
				ErrorReturn: &version2.Return{
					Code: 500,
				},
			},
			expectedWarnings: Warnings{
				nil: {
					`Client secret is required for OIDC policy default/oidc-policy when not using PKCE`,
				},
			},
			expectedOidc: &oidcPolicyCfg{},
			msg:          "oidc pkce no secret no",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			vsc := newVirtualServerConfigurator(&ConfigParams{Context: ctx}, false, false, &StaticConfigParams{}, false, &fakeBV)

			if test.oidcPolCfg != nil {
				vsc.oidcPolCfg = test.oidcPolCfg
			}

			result, warnings := generatePolicies(ctx, ownerDetails, test.policyRefs, test.policies, test.context, test.path, test.policyOpts, 1, &fakeBV, vsc.oidcPolCfg)
			result.BundleValidator = nil

			if !reflect.DeepEqual(test.expected, result) {
				t.Errorf("generatePolicies() '%v' mismatch (-want +got):\n%s", test.msg, cmp.Diff(test.expected, result))
			}
			if !reflect.DeepEqual(warnings, test.expectedWarnings) {
				t.Errorf(
					"generatePolicies() returned warnings of \n%v but expected \n%v for the case of %s",
					warnings,
					test.expectedWarnings,
					test.msg,
				)
			}
			if !reflect.DeepEqual(test.expectedOidc.oidc, vsc.oidcPolCfg.oidc) {
				t.Errorf("generatePolicies() '%v' mismatch (-want +got):\n%s", test.msg, cmp.Diff(test.expectedOidc.oidc, vsc.oidcPolCfg.oidc))
			}
			if !reflect.DeepEqual(test.expectedOidc.key, vsc.oidcPolCfg.key) {
				t.Errorf("generatePolicies() '%v' mismatch (-want +got):\n%s", test.msg, cmp.Diff(test.expectedOidc.key, vsc.oidcPolCfg.key))
			}
		})
	}
}
