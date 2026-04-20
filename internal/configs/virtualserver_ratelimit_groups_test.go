package configs

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateVirtualServerConfigRateLimitGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg             string
		virtualServerEx VirtualServerEx
		expected        version2.VirtualServerConfig
	}{
		{
			msg: "jwt claim rate limits at vs spec level, no default with zonesync enabled",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				ZoneSync: true,
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
						Sync:          true,
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
						Sync:          true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "jwt claim rate limits at vs spec level, no default",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "jwt claim rate limits at vs spec level, with default",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
									Default: true,
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupDefault:  true,
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "jwt claim rate limits at vs route level, with default",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
									Default: true,
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupDefault:  true,
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
				},
			},
		},
		{
			msg: "jwt claim rate limits at two different vs route levels, with defaults",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
									Default: true,
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_route_L2NvZmZlZQ",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_route_L2NvZmZlZQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_route_L2NvZmZlZQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupDefault:  true,
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
					},
				},
			},
		},
		{
			msg: "jwt claim rate limits at vsr /tea level, with default",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path:  "/tea",
								Route: "default/tea",
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
									Default: true,
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea",
							Namespace: "default",
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea",
									Service: "tea-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea",
									Action: &conf_v1.Action{
										Pass: "tea",
									},
									Policies: []conf_v1.PolicyReference{
										{
											Name: "premium-rate-limit-policy",
										},
										{
											Name: "basic-rate-limit-policy",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_tea_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupDefault:  true,
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_vsr_default_tea_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							IsVSR:                    true,
							VSRName:                  "tea",
							VSRNamespace:             "default",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
					},
				},
			},
		},
		{
			msg: "jwt claim rate limits at vsr /tea level & at vs spec level, with default",
			virtualServerEx: VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path:  "/tea",
								Route: "default/tea",
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "premium",
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "basic",
									},
									Default: true,
								},
							},
						},
					},
					"default/gold-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "gold-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "100r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "gold",
									},
								},
							},
						},
					},
					"default/silver-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "silver-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "50r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "silver",
									},
								},
							},
						},
					},
					"default/bronze-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "bronze-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$jwt_claim_sub",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									JWT: &conf_v1.JWTCondition{
										Claim: "user_type.tier",
										Match: "bronze",
									},
									Default: true,
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea",
							Namespace: "default",
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea",
									Service: "tea-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea",
									Action: &conf_v1.Action{
										Pass: "tea",
									},
									Policies: []conf_v1.PolicyReference{
										{
											Name: "gold-rate-limit-policy",
										},
										{
											Name: "silver-rate-limit-policy",
										},
										{
											Name: "bronze-rate-limit-policy",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  "basic",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic",
							},
							{
								Value:  "premium",
								Result: "rl_default_cafe_vs_match_premium",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$jwt_default_cafe_vs_user_type_tier",
						Variable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  "bronze",
								Result: "rl_default_cafe_vs_match_bronze",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_bronze",
							},
							{
								Value:  "silver",
								Result: "rl_default_cafe_vs_match_silver",
							},
							{
								Value:  "gold",
								Result: "rl_default_cafe_vs_match_gold",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Variable: "$pol_rl_default_gold_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_gold",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Variable: "$pol_rl_default_silver_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_silver",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						Variable: "$pol_rl_default_bronze_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_bronze",
								Result: "Val$jwt_claim_sub",
							},
						},
					},
				},
				AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_tea_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium",
						GroupValue:    "premium",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic",
						GroupValue:    "basic",
						GroupDefault:  true,
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_gold_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_gold_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "100r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_gold",
						GroupValue:    "gold",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_silver_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_silver_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "50r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_silver",
						GroupValue:    "silver",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
					},
					{
						Key:           "$pol_rl_default_bronze_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_bronze_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$jwt_claim_sub",
						GroupVariable: "$rl_default_cafe_vs_group_user_type_tier_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_bronze",
						GroupValue:    "bronze",
						GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
						GroupDefault:  true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_vsr_default_tea_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							IsVSR:                    true,
							VSRName:                  "tea",
							VSRNamespace:             "default",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_gold_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_silver_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_bronze_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
					},
				},
			},
		},
		{
			msg: "apikey claim rate limits at vs spec level, no default with zonesync enabled",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				ZoneSync: true,
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
						Sync:          true,
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
						Sync:          true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs_sync", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs_sync", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
		{
			msg: "apikey claim rate limits at vs spec level, no default",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
		{
			msg: "apikey claim rate limits at vs spec level, with default",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "premium-rate-limit-policy",
							},
							{
								Name: "basic-rate-limit-policy",
							},
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
									Default: true,
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_spec_Lw",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
						GroupDefault:  true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",
					LimitReqs: []version2.LimitReq{
						{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
						{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
					},
					LimitReqOptions: version2.LimitReqOptions{
						DryRun:     false,
						LogLevel:   "error",
						RejectCode: 503,
					},
					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
		{
			msg: "apikey claim rate limits at vs route level, with default",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
									Default: true,
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
						GroupDefault:  true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",

					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
		{
			msg: "apikey claim rate limits at two different vs route levels, with default",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "tea",
								Service: "tea-svc",
								Port:    80,
							},
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path: "/tea",
								Action: &conf_v1.Action{
									Pass: "tea",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
									Default: true,
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
						},
					},
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
						GroupDefault:  true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",

					Locations: []version2.Location{
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
		{
			msg: "apikey rate limits at vsr /tea level, with default",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path:  "/tea",
								Route: "default/tea",
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
									Default: true,
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea",
							Namespace: "default",
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea",
									Service: "tea-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea",
									Action: &conf_v1.Action{
										Pass: "tea",
									},
									Policies: []conf_v1.PolicyReference{
										{
											Name: "premium-rate-limit-policy",
										},
										{
											Name: "basic-rate-limit-policy",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
						},
					},
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_tea_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
						GroupDefault:  true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",

					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
						},
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_vsr_default_tea_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
							IsVSR:        true,
							VSRName:      "tea",
							VSRNamespace: "default",
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
		{
			msg: "apikey rate limits at vsr /tea level & at vs spec level, with default",
			virtualServerEx: VirtualServerEx{
				SecretRefs: map[string]*secrets.SecretReference{
					"default/api-key-secret-spec": {
						Secret: &api_v1.Secret{
							Type: secrets.SecretTypeAPIKey,
							Data: map[string][]byte{
								"premium": []byte("premiumpassword"),
								"basic":   []byte("basicpassword"),
							},
						},
					},
				},
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
					Spec: conf_v1.VirtualServerSpec{
						Host: "cafe.example.com",
						Policies: []conf_v1.PolicyReference{
							{
								Name: "api-key-policy",
							},
						},
						Upstreams: []conf_v1.Upstream{
							{
								Name:    "coffee",
								Service: "coffee-svc",
								Port:    80,
							},
						},
						Routes: []conf_v1.Route{
							{
								Path:  "/tea",
								Route: "default/tea",
							},
							{
								Path: "/coffee",
								Action: &conf_v1.Action{
									Pass: "coffee",
								},
								Policies: []conf_v1.PolicyReference{
									{
										Name: "premium-rate-limit-policy",
									},
									{
										Name: "basic-rate-limit-policy",
									},
								},
							},
						},
					},
				},
				Policies: map[string]*conf_v1.Policy{
					"default/premium-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "premium-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "10M",
								Rate:     "10r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "premium",
											Name:  "$apikey_client_name",
										},
									},
								},
							},
						},
					},
					"default/basic-rate-limit-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "basic-rate-limit-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							RateLimit: &conf_v1.RateLimit{
								Key:      "$apikey_client_name",
								ZoneSize: "20M",
								Rate:     "20r/s",
								Condition: &conf_v1.RateLimitCondition{
									Variables: &[]conf_v1.VariableCondition{
										{
											Match: "basic",
											Name:  "$apikey_client_name",
										},
									},
									Default: true,
								},
							},
						},
					},
					"default/api-key-policy": {
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "api-key-policy",
							Namespace: "default",
						},
						Spec: conf_v1.PolicySpec{
							APIKey: &conf_v1.APIKey{
								ClientSecret: "api-key-secret-spec",
								SuppliedIn: &conf_v1.SuppliedIn{
									Header: []string{"X-API-Key"},
									Query:  []string{"api-key"},
								},
							},
						},
					},
				},
				Endpoints: map[string][]string{
					"default/tea-svc:80": {
						"10.0.0.20:80",
					},
					"default/coffee-svc:80": {
						"10.0.0.30:80",
					},
				},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
					{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "tea",
							Namespace: "default",
						},
						Spec: conf_v1.VirtualServerRouteSpec{
							Host: "cafe.example.com",
							Upstreams: []conf_v1.Upstream{
								{
									Name:    "tea",
									Service: "tea-svc",
									Port:    80,
								},
							},
							Subroutes: []conf_v1.Route{
								{
									Path: "/tea",
									Action: &conf_v1.Action{
										Pass: "tea",
									},
									Policies: []conf_v1.PolicyReference{
										{
											Name: "premium-rate-limit-policy",
										},
										{
											Name: "basic-rate-limit-policy",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: version2.VirtualServerConfig{
				Maps: []version2.Map{
					{
						Source:   "$apikey_auth_token",
						Variable: "$apikey_auth_client_name_default_cafe_vs_api_key_policy",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: `""`,
							},
							{
								Value:  `"e96ac3dd8ef94a6c4bb88f216231c1968e1700add139d722fe406cd0cae73074"`,
								Result: `"premium"`,
							},
							{
								Value:  `"e1e1a4f93c814d938254e6fd7da12f096c9948eae7bc4137656202a413a0f3f4"`,
								Result: `"basic"`,
							},
						},
					},
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$apikey_client_name",
						Variable: "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						Parameters: []version2.Parameter{
							{
								Value:  `"basic"`,
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  "default",
								Result: "rl_default_cafe_vs_match_basic_rate_limit_policy",
							},
							{
								Value:  `"premium"`,
								Result: "rl_default_cafe_vs_match_premium_rate_limit_policy",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_premium_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
					{
						Source:   "$rl_default_cafe_vs_variable_apikey_client_name_subroute_L3RlYQ",
						Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						Parameters: []version2.Parameter{
							{
								Value:  "default",
								Result: "''",
							},
							{
								Value:  "rl_default_cafe_vs_match_basic_rate_limit_policy",
								Result: "Val$apikey_client_name",
							},
						},
					},
				},
				Upstreams: []version2.Upstream{
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "coffee-svc",
							ResourceType:      "virtualserver",
							ResourceName:      "cafe",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_coffee",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.30:80",
							},
						},
					},
					{
						UpstreamLabels: version2.UpstreamLabels{
							Service:           "tea-svc",
							ResourceType:      "virtualserverroute",
							ResourceName:      "tea",
							ResourceNamespace: "default",
						},
						Name: "vs_default_cafe_vsr_default_tea_tea",
						Servers: []version2.UpstreamServer{
							{
								Address: "10.0.0.20:80",
							},
						},
					},
				},
				HTTPSnippets: []string{},
				LimitReqZones: []version2.LimitReqZone{
					{
						Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "10M",
						Rate:          "10r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						PolicyValue:   "rl_default_cafe_vs_match_premium_rate_limit_policy",
						GroupValue:    `"premium"`,
						GroupSource:   "$apikey_client_name",
					},
					{
						Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
						ZoneSize:      "20M",
						Rate:          "20r/s",
						PolicyResult:  "$apikey_client_name",
						GroupVariable: "$rl_default_cafe_vs_variable_apikey_client_name_route_L2NvZmZlZQ",
						PolicyValue:   "rl_default_cafe_vs_match_basic_rate_limit_policy",
						GroupValue:    `"basic"`,
						GroupSource:   "$apikey_client_name",
						GroupDefault:  true,
					},
				},
				Server: version2.Server{
					ServerName:   "cafe.example.com",
					StatusZone:   "cafe.example.com",
					ServerTokens: "off",
					VSNamespace:  "default",
					VSName:       "cafe",

					Locations: []version2.Location{
						{
							Path:                     "/coffee",
							ProxyPass:                "http://vs_default_cafe_coffee",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "coffee-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "coffee-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
						},
						{
							Path:                     "/tea",
							ProxyPass:                "http://vs_default_cafe_vsr_default_tea_tea",
							ProxyNextUpstream:        "error timeout",
							ProxyNextUpstreamTimeout: "0s",
							ProxyNextUpstreamTries:   0,
							ProxySSLName:             "tea-svc.default.svc",
							ProxyPassRequestHeaders:  true,
							ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
							ServiceName:              "tea-svc",
							LimitReqs: []version2.LimitReq{
								{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
								{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
							},
							LimitReqOptions: version2.LimitReqOptions{
								DryRun:     false,
								LogLevel:   "error",
								RejectCode: 503,
							},
							IsVSR:        true,
							VSRName:      "tea",
							VSRNamespace: "default",
						},
					},
					APIKeyEnabled: true,
					APIKey: &version2.APIKey{
						Header:  []string{"X-API-Key"},
						Query:   []string{"api-key"},
						MapName: "apikey_auth_client_name_default_cafe_vs_api_key_policy",
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:      context.Background(),
		ServerTokens: "off",
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{},
		false,
		&fakeBV,
	)

	for _, test := range tests {
		result, warnings := vsc.GenerateVirtualServerConfig(&test.virtualServerEx, nil, nil)

		for i, m := range result.Maps {
			sort.Slice(m.Parameters, func(i, j int) bool {
				return m.Parameters[i].Value < m.Parameters[j].Value
			})
			result.Maps[i] = m
		}

		sort.Slice(result.Maps, func(i, j int) bool {
			return result.Maps[i].Variable < result.Maps[j].Variable && result.Maps[i].Source < result.Maps[j].Source
		})

		for i, m := range test.expected.Maps {
			sort.Slice(m.Parameters, func(i, j int) bool {
				return m.Parameters[i].Value < m.Parameters[j].Value
			})
			test.expected.Maps[i] = m
		}

		sort.Slice(test.expected.Maps, func(i, j int) bool {
			return test.expected.Maps[i].Variable < test.expected.Maps[j].Variable && test.expected.Maps[i].Source < test.expected.Maps[j].Source
		})

		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
			t.Error(test.msg)
		}

		if len(warnings) != 0 {
			t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
		}
	}
}

func TestGenerateVirtualServerConfigWithRateLimitGroupsWarning(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Policies: []conf_v1.PolicyReference{
					{
						Name: "premium-rate-limit-policy",
					},
					{
						Name: "basic-rate-limit-policy",
					},
				},
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:    "coffee",
						Service: "coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
					},
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/premium-rate-limit-policy": {
				Spec: conf_v1.PolicySpec{
					RateLimit: &conf_v1.RateLimit{
						Key:      "$jwt_claim_sub",
						ZoneSize: "10M",
						Rate:     "10r/s",
						Condition: &conf_v1.RateLimitCondition{
							JWT: &conf_v1.JWTCondition{
								Claim: "user_type.tier",
								Match: "premium",
							},
							Default: true,
						},
					},
				},
			},
			"default/basic-rate-limit-policy": {
				Spec: conf_v1.PolicySpec{
					RateLimit: &conf_v1.RateLimit{
						Key:      "$jwt_claim_sub",
						ZoneSize: "20M",
						Rate:     "20r/s",
						Condition: &conf_v1.RateLimitCondition{
							JWT: &conf_v1.JWTCondition{
								Claim: "user_type.tier",
								Match: "basic",
							},
							Default: true,
						},
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.30:80",
			},
		},
	}
	expected := version2.VirtualServerConfig{
		Maps: []version2.Map{
			{
				Source:   "$rl_default_cafe_vs_group_user_type_tier",
				Variable: "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "rl_default_cafe_vs_match_basic",
						Result: "Val$jwt_claim_sub",
					},
				},
			},
			{
				Source:   "$rl_default_cafe_vs_group_user_type_tier",
				Variable: "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: "''",
					},
					{
						Value:  "rl_default_cafe_vs_match_premium",
						Result: "Val$jwt_claim_sub",
					},
				},
			},
			{
				Source:   "$jwt_default_cafe_vs_user_type_tier",
				Variable: "$rl_default_cafe_vs_group_user_type_tier",
				Parameters: []version2.Parameter{
					{
						Value:  "basic",
						Result: "rl_default_cafe_vs_match_basic",
					},
					{
						Value:  "premium",
						Result: "rl_default_cafe_vs_match_premium",
					},
				},
			},
		},
		AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_vs_user_type_tier", Claim: "user_type tier"}},
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
			},
		},
		HTTPSnippets: []string{},
		LimitReqZones: []version2.LimitReqZone{
			{
				Key:           "$pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
				ZoneName:      "pol_rl_default_premium_rate_limit_policy_default_cafe_vs",
				ZoneSize:      "10M",
				Rate:          "10r/s",
				PolicyResult:  "$jwt_claim_sub",
				GroupVariable: "$rl_default_cafe_vs_group_user_type_tier",
				PolicyValue:   "rl_default_cafe_vs_match_premium",
				GroupValue:    "premium",
				GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
			},
			{
				Key:           "$pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
				ZoneName:      "pol_rl_default_basic_rate_limit_policy_default_cafe_vs",
				ZoneSize:      "20M",
				Rate:          "20r/s",
				PolicyResult:  "$jwt_claim_sub",
				GroupVariable: "$rl_default_cafe_vs_group_user_type_tier",
				PolicyValue:   "rl_default_cafe_vs_match_basic",
				GroupValue:    "basic",
				GroupSource:   "$jwt_default_cafe_vs_user_type_tier",
			},
		},
		Server: version2.Server{
			ServerName:   "cafe.example.com",
			StatusZone:   "cafe.example.com",
			ServerTokens: "off",
			VSNamespace:  "default",
			VSName:       "cafe",
			LimitReqs: []version2.LimitReq{
				{ZoneName: "pol_rl_default_premium_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
				{ZoneName: "pol_rl_default_basic_rate_limit_policy_default_cafe_vs", Burst: 0, NoDelay: false, Delay: 0},
			},
			LimitReqOptions: version2.LimitReqOptions{
				DryRun:     false,
				LogLevel:   "error",
				RejectCode: 503,
			},
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
				},
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context:         context.Background(),
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	isPlus := true
	isResolverConfigured := false
	staticConfigParams := &StaticConfigParams{TLSPassthrough: true, NginxServiceMesh: true, EnableInternalRoutes: false}
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, staticConfigParams, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff == "" {
		t.Errorf("GenerateVirtualServerConfig() should not configure internal route")
	}

	if len(warnings) != 1 {
		t.Errorf("GenerateVirtualServerConfig should return warning about tiered rate limits with duplicate defaults")
	}
}
