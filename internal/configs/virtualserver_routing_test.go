package configs

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateVirtualServerConfigForVirtualServerWithSplits(t *testing.T) {
	t.Parallel()
	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea-v1",
						Service: "tea-svc-v1",
						Port:    80,
					},
					{
						Name:    "tea-v2",
						Service: "tea-svc-v2",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Splits: []conf_v1.Split{
							{
								Weight: 90,
								Action: &conf_v1.Action{
									Pass: "tea-v1",
								},
							},
							{
								Weight: 10,
								Action: &conf_v1.Action{
									Pass: "tea-v2",
								},
							},
						},
					},
					{
						Path:  "/coffee",
						Route: "default/coffee",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc-v1:80": {
				"10.0.0.20:80",
			},
			"default/tea-svc-v2:80": {
				"10.0.0.21:80",
			},
			"default/coffee-svc-v1:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc-v2:80": {
				"10.0.0.31:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "coffee-v1",
							Service: "coffee-svc-v1",
							Port:    80,
						},
						{
							Name:    "coffee-v2",
							Service: "coffee-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Splits: []conf_v1.Split{
								{
									Weight: 40,
									Action: &conf_v1.Action{
										Pass: "coffee-v1",
									},
								},
								{
									Weight: 60,
									Action: &conf_v1.Action{
										Pass: "coffee-v2",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{Context: context.Background()}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				Name: "vs_default_cafe_tea-v1",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc-v1",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_tea-v2",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc-v2",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.21:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_vsr_default_coffee_coffee-v1",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc-v1",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_vsr_default_coffee_coffee-v2",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc-v2",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.31:80",
					},
				},
			},
		},
		SplitClients: []version2.SplitClient{
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_0",
				Distributions: []version2.Distribution{
					{
						Weight: "90%",
						Value:  "/internal_location_splits_0_split_0",
					},
					{
						Weight: "10%",
						Value:  "/internal_location_splits_0_split_1",
					},
				},
			},
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_1",
				Distributions: []version2.Distribution{
					{
						Weight: "40%",
						Value:  "/internal_location_splits_1_split_0",
					},
					{
						Weight: "60%",
						Value:  "/internal_location_splits_1_split_1",
					},
				},
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:  "cafe.example.com",
			StatusZone:  "cafe.example.com",
			VSNamespace: "default",
			VSName:      "cafe",
			InternalRedirectLocations: []version2.InternalRedirectLocation{
				{
					Path:        "/tea",
					Destination: "$vs_default_cafe_splits_0",
				},
				{
					Path:        "/coffee",
					Destination: "$vs_default_cafe_splits_1",
				},
			},
			Locations: []version2.Location{
				{
					Path:                     "/internal_location_splits_0_split_0",
					ProxyPass:                "http://vs_default_cafe_tea-v1$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "tea-svc-v1.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc-v1",
				},
				{
					Path:                     "/internal_location_splits_0_split_1",
					ProxyPass:                "http://vs_default_cafe_tea-v2$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "tea-svc-v2.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc-v2",
				},
				{
					Path:                     "/internal_location_splits_1_split_0",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee-v1$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "coffee-svc-v1.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc-v1",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/internal_location_splits_1_split_1",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee-v2$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "coffee-svc-v2.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc-v2",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
			},
		},
	}

	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{}, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigForVirtualServerWithMatches(t *testing.T) {
	t.Parallel()
	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "tea-v1",
						Service: "tea-svc-v1",
						Port:    80,
					},
					{
						Name:    "tea-v2",
						Service: "tea-svc-v2",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/tea",
						Matches: []conf_v1.Match{
							{
								Conditions: []conf_v1.Condition{
									{
										Header: "x-version",
										Value:  "v2",
									},
								},
								Action: &conf_v1.Action{
									Pass: "tea-v2",
								},
							},
						},
						Action: &conf_v1.Action{
							Pass: "tea-v1",
						},
					},
					{
						Path:  "/coffee",
						Route: "default/coffee",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc-v1:80": {
				"10.0.0.20:80",
			},
			"default/tea-svc-v2:80": {
				"10.0.0.21:80",
			},
			"default/coffee-svc-v1:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc-v2:80": {
				"10.0.0.31:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "coffee-v1",
							Service: "coffee-svc-v1",
							Port:    80,
						},
						{
							Name:    "coffee-v2",
							Service: "coffee-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Matches: []conf_v1.Match{
								{
									Conditions: []conf_v1.Condition{
										{
											Argument: "version",
											Value:    "v2",
										},
									},
									Action: &conf_v1.Action{
										Pass: "coffee-v2",
									},
								},
							},
							Action: &conf_v1.Action{
								Pass: "coffee-v1",
							},
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{Context: context.Background()}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc-v1",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-v1",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_tea-v2",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc-v2",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.21:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_vsr_default_coffee_coffee-v1",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc-v1",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_vsr_default_coffee_coffee-v2",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc-v2",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.31:80",
					},
				},
			},
		},
		Maps: []version2.Map{
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_cafe_matches_0_match_0_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v2"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$vs_default_cafe_matches_0_match_0_cond_0",
				Variable: "$vs_default_cafe_matches_0",
				Parameters: []version2.Parameter{
					{
						Value:  "~^1",
						Result: "/internal_location_matches_0_match_0",
					},
					{
						Value:  "default",
						Result: "/internal_location_matches_0_default",
					},
				},
			},
			{
				Source:   "$arg_version",
				Variable: "$vs_default_cafe_matches_1_match_0_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v2"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$vs_default_cafe_matches_1_match_0_cond_0",
				Variable: "$vs_default_cafe_matches_1",
				Parameters: []version2.Parameter{
					{
						Value:  "~^1",
						Result: "/internal_location_matches_1_match_0",
					},
					{
						Value:  "default",
						Result: "/internal_location_matches_1_default",
					},
				},
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:  "cafe.example.com",
			StatusZone:  "cafe.example.com",
			VSNamespace: "default",
			VSName:      "cafe",
			InternalRedirectLocations: []version2.InternalRedirectLocation{
				{
					Path:        "/tea",
					Destination: "$vs_default_cafe_matches_0",
				},
				{
					Path:        "/coffee",
					Destination: "$vs_default_cafe_matches_1",
				},
			},
			Locations: []version2.Location{
				{
					Path:                     "/internal_location_matches_0_match_0",
					ProxyPass:                "http://vs_default_cafe_tea-v2$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "tea-svc-v2.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc-v2",
				},
				{
					Path:                     "/internal_location_matches_0_default",
					ProxyPass:                "http://vs_default_cafe_tea-v1$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "tea-svc-v1.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc-v1",
				},
				{
					Path:                     "/internal_location_matches_1_match_0",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee-v2$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "coffee-svc-v2.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc-v2",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/internal_location_matches_1_default",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee-v1$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Internal:                 true,
					ProxySSLName:             "coffee-svc-v1.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc-v1",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
			},
		},
	}

	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{}, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigForVirtualServerRoutesWithDos(t *testing.T) {
	t.Parallel()
	dosResources := map[string]*appProtectDosResource{
		"/coffee": {
			AppProtectDosEnable:          "on",
			AppProtectDosLogEnable:       false,
			AppProtectDosMonitorURI:      "test.example.com",
			AppProtectDosMonitorProtocol: "http",
			AppProtectDosMonitorTimeout:  0,
			AppProtectDosName:            "my-dos-coffee",
			AppProtectDosAccessLogDst:    "svc.dns.com:123",
			AppProtectDosPolicyFile:      "",
			AppProtectDosLogConfFile:     "",
			AppProtectDosAllowListPath:   "/etc/nginx/dos/allowlist/default_coffee",
		},
		"/tea": {
			AppProtectDosEnable:          "on",
			AppProtectDosLogEnable:       false,
			AppProtectDosMonitorURI:      "test.example.com",
			AppProtectDosMonitorProtocol: "http",
			AppProtectDosMonitorTimeout:  0,
			AppProtectDosName:            "my-dos-tea",
			AppProtectDosAccessLogDst:    "svc.dns.com:123",
			AppProtectDosPolicyFile:      "",
			AppProtectDosLogConfFile:     "",
			AppProtectDosAllowListPath:   "/etc/nginx/dos/allowlist/default_tea",
		},
		"/juice": {
			AppProtectDosEnable:          "on",
			AppProtectDosLogEnable:       false,
			AppProtectDosMonitorURI:      "test.example.com",
			AppProtectDosMonitorProtocol: "http",
			AppProtectDosMonitorTimeout:  0,
			AppProtectDosName:            "my-dos-juice",
			AppProtectDosAccessLogDst:    "svc.dns.com:123",
			AppProtectDosPolicyFile:      "",
			AppProtectDosLogConfFile:     "",
			AppProtectDosAllowListPath:   "/etc/nginx/dos/allowlist/default_juice",
		},
	}

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Routes: []conf_v1.Route{
					{
						Path:  "/coffee",
						Route: "default/coffee",
					},
					{
						Path:  "/tea",
						Route: "default/tea",
					},
					{
						Path:  "/juice",
						Route: "default/juice",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc-v1:80": {
				"10.0.0.20:80",
			},
			"default/tea-svc-v2:80": {
				"10.0.0.21:80",
			},
			"default/coffee-svc-v1:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc-v2:80": {
				"10.0.0.31:80",
			},
			"default/juice-svc-v1:80": {
				"10.0.0.33:80",
			},
			"default/juice-svc-v2:80": {
				"10.0.0.34:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "coffee",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "coffee-v1",
							Service: "coffee-svc-v1",
							Port:    80,
						},
						{
							Name:    "coffee-v2",
							Service: "coffee-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Matches: []conf_v1.Match{
								{
									Conditions: []conf_v1.Condition{
										{
											Argument: "version",
											Value:    "v2",
										},
									},
									Action: &conf_v1.Action{
										Pass: "coffee-v2",
									},
								},
							},
							Dos: "test_ns/dos_protected",
							Action: &conf_v1.Action{
								Pass: "coffee-v1",
							},
						},
					},
				},
			},
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tea",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "tea-v1",
							Service: "tea-svc-v1",
							Port:    80,
						},
						{
							Name:    "tea-v2",
							Service: "tea-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/tea",
							Dos:  "test_ns/dos_protected",
							Action: &conf_v1.Action{
								Pass: "tea-v1",
							},
						},
					},
				},
			},
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "juice",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "juice-v1",
							Service: "juice-svc-v1",
							Port:    80,
						},
						{
							Name:    "juice-v2",
							Service: "juice-svc-v2",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/juice",
							Dos:  "test_ns/dos_protected",
							Splits: []conf_v1.Split{
								{
									Weight: 80,
									Action: &conf_v1.Action{
										Pass: "juice-v1",
									},
								},
								{
									Weight: 20,
									Action: &conf_v1.Action{
										Pass: "juice-v2",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{Context: context.Background()}

	expected := []version2.Location{
		{
			Path:                     "/internal_location_matches_0_match_0",
			ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee-v2$request_uri",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 true,
			ProxySSLName:             "coffee-svc-v2.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "coffee-svc-v2",
			IsVSR:                    true,
			VSRName:                  "coffee",
			VSRNamespace:             "default",
			Dos: &version2.Dos{
				Enable:               "on",
				Name:                 "my-dos-coffee",
				ApDosMonitorURI:      "test.example.com",
				ApDosMonitorProtocol: "http",
				ApDosAccessLogDest:   "svc.dns.com:123",
				AllowListPath:        "/etc/nginx/dos/allowlist/default_coffee",
			},
		},
		{
			Path:                     "/internal_location_matches_0_default",
			ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee-v1$request_uri",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 true,
			ProxySSLName:             "coffee-svc-v1.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "coffee-svc-v1",
			IsVSR:                    true,
			VSRName:                  "coffee",
			VSRNamespace:             "default",
			Dos: &version2.Dos{
				Enable:               "on",
				Name:                 "my-dos-coffee",
				ApDosMonitorURI:      "test.example.com",
				ApDosMonitorProtocol: "http",
				ApDosAccessLogDest:   "svc.dns.com:123",
				AllowListPath:        "/etc/nginx/dos/allowlist/default_coffee",
			},
		},
		{
			Path:                     "/tea",
			ProxyPass:                "http://vs_default_cafe_vsr_default_tea_tea-v1",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 false,
			ProxySSLName:             "tea-svc-v1.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "tea-svc-v1",
			IsVSR:                    true,
			VSRName:                  "tea",
			VSRNamespace:             "default",
			Dos: &version2.Dos{
				Enable:               "on",
				Name:                 "my-dos-tea",
				ApDosMonitorURI:      "test.example.com",
				ApDosMonitorProtocol: "http",
				ApDosAccessLogDest:   "svc.dns.com:123",
				AllowListPath:        "/etc/nginx/dos/allowlist/default_tea",
			},
		},
		{
			Path:                     "/internal_location_splits_0_split_0",
			Internal:                 true,
			ProxyPass:                "http://vs_default_cafe_vsr_default_juice_juice-v1$request_uri",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ProxySSLName:             "juice-svc-v1.default.svc",
			Dos: &version2.Dos{
				Enable:               "on",
				Name:                 "my-dos-juice",
				ApDosMonitorURI:      "test.example.com",
				ApDosMonitorProtocol: "http",
				ApDosAccessLogDest:   "svc.dns.com:123",
				AllowListPath:        "/etc/nginx/dos/allowlist/default_juice",
			},
			ServiceName:  "juice-svc-v1",
			IsVSR:        true,
			VSRName:      "juice",
			VSRNamespace: "default",
		},
		{
			Path:                     "/internal_location_splits_0_split_1",
			Internal:                 true,
			ProxyPass:                "http://vs_default_cafe_vsr_default_juice_juice-v2$request_uri",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ProxySSLName:             "juice-svc-v2.default.svc",
			Dos: &version2.Dos{
				Enable:               "on",
				Name:                 "my-dos-juice",
				ApDosMonitorURI:      "test.example.com",
				ApDosMonitorProtocol: "http",
				ApDosAccessLogDest:   "svc.dns.com:123",
				AllowListPath:        "/etc/nginx/dos/allowlist/default_juice",
			},
			ServiceName:  "juice-svc-v2",
			IsVSR:        true,
			VSRName:      "juice",
			VSRNamespace: "default",
		},
	}

	isPlus := false
	isResolverConfigured := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{MainAppProtectDosLoadModule: true}, false, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, dosResources)
	if diff := cmp.Diff(expected, result.Server.Locations); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigForVirtualServerWithReturns(t *testing.T) {
	t.Parallel()
	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "returns",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "example.com",
				Routes: []conf_v1.Route{
					{
						Path: "/return",
						Action: &conf_v1.Action{
							Return: &conf_v1.ActionReturn{
								Body: "hello 0",
							},
						},
					},
					{
						Path: "/splits-with-return",
						Splits: []conf_v1.Split{
							{
								Weight: 90,
								Action: &conf_v1.Action{
									Return: &conf_v1.ActionReturn{
										Body: "hello 1",
									},
								},
							},
							{
								Weight: 10,
								Action: &conf_v1.Action{
									Return: &conf_v1.ActionReturn{
										Body: "hello 2",
									},
								},
							},
						},
					},
					{
						Path: "/matches-with-return",
						Matches: []conf_v1.Match{
							{
								Conditions: []conf_v1.Condition{
									{
										Header: "x-version",
										Value:  "v2",
									},
								},
								Action: &conf_v1.Action{
									Return: &conf_v1.ActionReturn{
										Body: "hello 3",
									},
								},
							},
						},
						Action: &conf_v1.Action{
							Return: &conf_v1.ActionReturn{
								Body: "hello 4",
							},
						},
					},
					{
						Path:  "/more",
						Route: "default/more-returns",
					},
				},
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "more-returns",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "example.com",
					Subroutes: []conf_v1.Route{
						{
							Path: "/more/return",
							Action: &conf_v1.Action{
								Return: &conf_v1.ActionReturn{
									Body: "hello 5",
								},
							},
						},
						{
							Path: "/more/splits-with-return",
							Splits: []conf_v1.Split{
								{
									Weight: 90,
									Action: &conf_v1.Action{
										Return: &conf_v1.ActionReturn{
											Body: "hello 6",
										},
									},
								},
								{
									Weight: 10,
									Action: &conf_v1.Action{
										Return: &conf_v1.ActionReturn{
											Body: "hello 7",
										},
									},
								},
							},
						},
						{
							Path: "/more/matches-with-return",
							Matches: []conf_v1.Match{
								{
									Conditions: []conf_v1.Condition{
										{
											Header: "x-version",
											Value:  "v2",
										},
									},
									Action: &conf_v1.Action{
										Return: &conf_v1.ActionReturn{
											Body: "hello 8",
										},
									},
								},
							},
							Action: &conf_v1.Action{
								Return: &conf_v1.ActionReturn{
									Body: "hello 9",
								},
							},
						},
					},
				},
			},
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "header-returns",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "example.com",
					Subroutes: []conf_v1.Route{
						{
							Path: "/header/return",
							Action: &conf_v1.Action{
								Return: &conf_v1.ActionReturn{
									Headers: []conf_v1.Header{{Name: "return-header", Value: "value 1"}},
									Body:    "hello 10",
								},
							},
						},
						{
							Path: "/header/return-multiple",
							Action: &conf_v1.Action{
								Return: &conf_v1.ActionReturn{
									Headers: []conf_v1.Header{
										{Name: "return-header", Value: "value 1"},
										{Name: "return-header-2", Value: "value 2"},
									},
									Body: "hello 11",
								},
							},
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{Context: context.Background()}

	expected := version2.VirtualServerConfig{
		Maps: []version2.Map{
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_returns_matches_0_match_0_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v2"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$vs_default_returns_matches_0_match_0_cond_0",
				Variable: "$vs_default_returns_matches_0",
				Parameters: []version2.Parameter{
					{
						Value:  "~^1",
						Result: "/internal_location_matches_0_match_0",
					},
					{
						Value:  "default",
						Result: "/internal_location_matches_0_default",
					},
				},
			},
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_returns_matches_1_match_0_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v2"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$vs_default_returns_matches_1_match_0_cond_0",
				Variable: "$vs_default_returns_matches_1",
				Parameters: []version2.Parameter{
					{
						Value:  "~^1",
						Result: "/internal_location_matches_1_match_0",
					},
					{
						Value:  "default",
						Result: "/internal_location_matches_1_default",
					},
				},
			},
		},
		SplitClients: []version2.SplitClient{
			{
				Source:   "$request_id",
				Variable: "$vs_default_returns_splits_0",
				Distributions: []version2.Distribution{
					{
						Weight: "90%",
						Value:  "/internal_location_splits_0_split_0",
					},
					{
						Weight: "10%",
						Value:  "/internal_location_splits_0_split_1",
					},
				},
			},
			{
				Source:   "$request_id",
				Variable: "$vs_default_returns_splits_1",
				Distributions: []version2.Distribution{
					{
						Weight: "90%",
						Value:  "/internal_location_splits_1_split_0",
					},
					{
						Weight: "10%",
						Value:  "/internal_location_splits_1_split_1",
					},
				},
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:  "example.com",
			StatusZone:  "example.com",
			VSNamespace: "default",
			VSName:      "returns",
			InternalRedirectLocations: []version2.InternalRedirectLocation{
				{
					Path:        "/splits-with-return",
					Destination: "$vs_default_returns_splits_0",
				},
				{
					Path:        "/matches-with-return",
					Destination: "$vs_default_returns_matches_0",
				},
				{
					Path:        "/more/splits-with-return",
					Destination: "$vs_default_returns_splits_1",
				},
				{
					Path:        "/more/matches-with-return",
					Destination: "$vs_default_returns_matches_1",
				},
			},
			ReturnLocations: []version2.ReturnLocation{
				{
					Name:        "@return_0",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 0",
					},
				},
				{
					Name:        "@return_1",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 1",
					},
				},
				{
					Name:        "@return_2",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 2",
					},
				},
				{
					Name:        "@return_3",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 3",
					},
				},
				{
					Name:        "@return_4",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 4",
					},
				},
				{
					Name:        "@return_5",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 5",
					},
				},
				{
					Name:        "@return_6",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 6",
					},
				},
				{
					Name:        "@return_7",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 7",
					},
				},
				{
					Name:        "@return_8",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 8",
					},
				},
				{
					Name:        "@return_9",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 9",
					},
				},
				{
					Name:        "@return_10",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 10",
					},
					Headers: []version2.Header{{Name: "return-header", Value: "value 1"}},
				},
				{
					Name:        "@return_11",
					DefaultType: "text/plain",
					Return: version2.Return{
						Code: 0,
						Text: "hello 11",
					},
					Headers: []version2.Header{
						{Name: "return-header", Value: "value 1"},
						{Name: "return-header-2", Value: "value 2"},
					},
				},
			},
			Locations: []version2.Location{
				{
					Path:                 "/return",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_0",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_splits_0_split_0",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_1",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_splits_0_split_1",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_2",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_matches_0_match_0",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_3",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_matches_0_default",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_4",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/more/return",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_5",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_splits_1_split_0",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_6",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_splits_1_split_1",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_7",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_matches_1_match_0",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_8",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/internal_location_matches_1_default",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_9",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/header/return",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_10",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
				{
					Path:                 "/header/return-multiple",
					ProxyInterceptErrors: true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@return_11",
							Codes:        "418",
							ResponseCode: 200,
						},
					},
					InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
				},
			},
		},
	}

	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{}, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("GenerateVirtualServerConfig returned \n%+v but expected \n%+v", result, expected)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateSplits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		splits               []conf_v1.Split
		expectedSplitClients []version2.SplitClient
		msg                  string
	}{
		{
			splits: []conf_v1.Split{
				{
					Weight: 90,
					Action: &conf_v1.Action{
						Proxy: &conf_v1.ActionProxy{
							Upstream:    "coffee-v1",
							RewritePath: "/rewrite",
						},
					},
				},
				{
					Weight: 9,
					Action: &conf_v1.Action{
						Pass: "coffee-v2",
					},
				},
				{
					Weight: 1,
					Action: &conf_v1.Action{
						Return: &conf_v1.ActionReturn{
							Body: "hello",
						},
					},
				},
			},
			expectedSplitClients: []version2.SplitClient{
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_splits_1",
					Distributions: []version2.Distribution{
						{
							Weight: "90%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "9%",
							Value:  "/internal_location_splits_1_split_1",
						},
						{
							Weight: "1%",
							Value:  "/internal_location_splits_1_split_2",
						},
					},
				},
			},
			msg: "Normal Split",
		},
		{
			splits: []conf_v1.Split{
				{
					Weight: 90,
					Action: &conf_v1.Action{
						Proxy: &conf_v1.ActionProxy{
							Upstream:    "coffee-v1",
							RewritePath: "/rewrite",
						},
					},
				},
				{
					Weight: 0,
					Action: &conf_v1.Action{
						Pass: "coffee-v2",
					},
				},
				{
					Weight: 10,
					Action: &conf_v1.Action{
						Return: &conf_v1.ActionReturn{
							Body: "hello",
						},
					},
				},
			},
			expectedSplitClients: []version2.SplitClient{
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_splits_1",
					Distributions: []version2.Distribution{
						{
							Weight: "90%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "10%",
							Value:  "/internal_location_splits_1_split_2",
						},
					},
				},
			},
			msg: "Split with 0 weight",
		},
	}
	originalPath := "/path"

	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServer(&virtualServer)
	variableNamer := NewVSVariableNamer(&virtualServer)
	scIndex := 1
	cfgParams := ConfigParams{Context: context.Background()}
	crUpstreams := map[string]conf_v1.Upstream{
		"vs_default_cafe_coffee-v1": {
			Service: "coffee-v1",
		},
		"vs_default_cafe_coffee-v2": {
			Service: "coffee-v2",
		},
	}
	locSnippet := "# location snippet"
	enableSnippets := true
	errorPages := []conf_v1.ErrorPage{
		{
			Codes: []int{400, 500},
			Return: &conf_v1.ErrorPageReturn{
				ActionReturn: conf_v1.ActionReturn{
					Code: 200,
					Type: "application/json",
					Body: `{\"message\": \"ok\"}`,
					Headers: []conf_v1.Header{
						{
							Name:  "Set-Cookie",
							Value: "cookie1=value",
						},
					},
				},
			},
			Redirect: nil,
		},
		{
			Codes:  []int{500, 502},
			Return: nil,
			Redirect: &conf_v1.ErrorPageRedirect{
				ActionRedirect: conf_v1.ActionRedirect{
					URL:  "http://nginx.com",
					Code: 301,
				},
			},
		},
	}
	expectedLocations := []version2.Location{
		{
			Path:      "/internal_location_splits_1_split_0",
			ProxyPass: "http://vs_default_cafe_coffee-v1",
			Rewrites: []string{
				"^ $request_uri_no_args",
				fmt.Sprintf(`"^%v(.*)$" "/rewrite$1" break`, originalPath),
			},
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyInterceptErrors:     true,
			Internal:                 true,
			ErrorPages: []version2.ErrorPage{
				{
					Name:         "@error_page_0_0",
					Codes:        "400 500",
					ResponseCode: 200,
				},
				{
					Name:         "http://nginx.com",
					Codes:        "500 502",
					ResponseCode: 301,
				},
			},
			ProxySSLName:            "coffee-v1.default.svc",
			ProxyPassRequestHeaders: true,
			ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
			Snippets:                []string{locSnippet},
			ServiceName:             "coffee-v1",
			IsVSR:                   true,
			VSRName:                 "coffee",
			VSRNamespace:            "default",
		},
		{
			Path:                     "/internal_location_splits_1_split_1",
			ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			ProxyInterceptErrors:     true,
			Internal:                 true,
			ErrorPages: []version2.ErrorPage{
				{
					Name:         "@error_page_0_0",
					Codes:        "400 500",
					ResponseCode: 200,
				},
				{
					Name:         "http://nginx.com",
					Codes:        "500 502",
					ResponseCode: 301,
				},
			},
			ProxySSLName:            "coffee-v2.default.svc",
			ProxyPassRequestHeaders: true,
			ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
			Snippets:                []string{locSnippet},
			ServiceName:             "coffee-v2",
			IsVSR:                   true,
			VSRName:                 "coffee",
			VSRNamespace:            "default",
		},
		{
			Path:                 "/internal_location_splits_1_split_2",
			ProxyInterceptErrors: true,
			ErrorPages: []version2.ErrorPage{
				{
					Name:         "@return_1",
					Codes:        "418",
					ResponseCode: 200,
				},
			},
			InternalProxyPass: "http://unix:/var/lib/nginx/nginx-418-server.sock",
		},
	}
	expectedReturnLocations := []version2.ReturnLocation{
		{
			Name:        "@return_1",
			DefaultType: "text/plain",
			Return: version2.Return{
				Code: 0,
				Text: "hello",
			},
		},
	}
	returnLocationIndex := 1

	errorPageDetails := errorPageDetails{
		pages: errorPages,
		index: 0,
		owner: nil,
	}

	vsc := newVirtualServerConfigurator(&cfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			resultSplitClients, resultLocations, resultReturnLocations, _, _, _, _ := generateSplits(
				test.splits,
				upstreamNamer,
				crUpstreams,
				variableNamer,
				scIndex,
				&cfgParams,
				errorPageDetails,
				originalPath,
				locSnippet,
				enableSnippets,
				returnLocationIndex,
				true,
				"coffee",
				"default",
				vsc.warnings,
				vsc.DynamicWeightChangesReload,
			)

			if !cmp.Equal(test.expectedSplitClients, resultSplitClients) {
				t.Errorf("generateSplits() resultSplitClient mismatch (-want +got):\n%s", cmp.Diff(test.expectedSplitClients, resultSplitClients))
			}
			if !cmp.Equal(expectedLocations, resultLocations) {
				t.Errorf("generateSplits() resultLocations mismatch (-want +got):\n%s", cmp.Diff(expectedLocations, resultLocations))
			}
			if !cmp.Equal(expectedReturnLocations, resultReturnLocations) {
				t.Errorf("generateSplits() resultReturnLocations mismatch (-want +got):\n%s", cmp.Diff(expectedReturnLocations, resultReturnLocations))
			}
		})
	}
}

func TestGenerateSplitsWeightChangesDynamicReload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		splits               []conf_v1.Split
		expectedSplitClients []version2.SplitClient
		msg                  string
	}{
		{
			splits: []conf_v1.Split{
				{
					Weight: 90,
					Action: &conf_v1.Action{
						Proxy: &conf_v1.ActionProxy{
							Upstream:    "coffee-v1",
							RewritePath: "/rewrite",
						},
					},
				},
				{
					Weight: 10,
					Action: &conf_v1.Action{
						Pass: "coffee-v2",
					},
				},
			},
			expectedSplitClients: []version2.SplitClient{
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_0_100",
					Distributions: []version2.Distribution{
						{
							Weight: "100%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_1_99",
					Distributions: []version2.Distribution{
						{
							Weight: "1%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "99%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_2_98",
					Distributions: []version2.Distribution{
						{
							Weight: "2%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "98%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_3_97",
					Distributions: []version2.Distribution{
						{
							Weight: "3%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "97%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_4_96",
					Distributions: []version2.Distribution{
						{
							Weight: "4%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "96%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_5_95",
					Distributions: []version2.Distribution{
						{
							Weight: "5%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "95%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_6_94",
					Distributions: []version2.Distribution{
						{
							Weight: "6%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "94%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_7_93",
					Distributions: []version2.Distribution{
						{
							Weight: "7%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "93%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_8_92",
					Distributions: []version2.Distribution{
						{
							Weight: "8%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "92%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_9_91",
					Distributions: []version2.Distribution{
						{
							Weight: "9%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "91%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_10_90",
					Distributions: []version2.Distribution{
						{
							Weight: "10%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "90%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_11_89",
					Distributions: []version2.Distribution{
						{
							Weight: "11%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "89%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_12_88",
					Distributions: []version2.Distribution{
						{
							Weight: "12%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "88%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_13_87",
					Distributions: []version2.Distribution{
						{
							Weight: "13%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "87%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_14_86",
					Distributions: []version2.Distribution{
						{
							Weight: "14%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "86%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_15_85",
					Distributions: []version2.Distribution{
						{
							Weight: "15%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "85%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_16_84",
					Distributions: []version2.Distribution{
						{
							Weight: "16%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "84%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_17_83",
					Distributions: []version2.Distribution{
						{
							Weight: "17%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "83%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_18_82",
					Distributions: []version2.Distribution{
						{
							Weight: "18%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "82%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_19_81",
					Distributions: []version2.Distribution{
						{
							Weight: "19%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "81%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_20_80",
					Distributions: []version2.Distribution{
						{
							Weight: "20%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "80%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_21_79",
					Distributions: []version2.Distribution{
						{
							Weight: "21%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "79%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_22_78",
					Distributions: []version2.Distribution{
						{
							Weight: "22%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "78%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_23_77",
					Distributions: []version2.Distribution{
						{
							Weight: "23%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "77%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_24_76",
					Distributions: []version2.Distribution{
						{
							Weight: "24%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "76%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_25_75",
					Distributions: []version2.Distribution{
						{
							Weight: "25%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "75%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_26_74",
					Distributions: []version2.Distribution{
						{
							Weight: "26%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "74%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_27_73",
					Distributions: []version2.Distribution{
						{
							Weight: "27%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "73%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_28_72",
					Distributions: []version2.Distribution{
						{
							Weight: "28%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "72%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_29_71",
					Distributions: []version2.Distribution{
						{
							Weight: "29%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "71%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_30_70",
					Distributions: []version2.Distribution{
						{
							Weight: "30%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "70%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_31_69",
					Distributions: []version2.Distribution{
						{
							Weight: "31%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "69%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_32_68",
					Distributions: []version2.Distribution{
						{
							Weight: "32%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "68%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_33_67",
					Distributions: []version2.Distribution{
						{
							Weight: "33%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "67%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_34_66",
					Distributions: []version2.Distribution{
						{
							Weight: "34%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "66%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_35_65",
					Distributions: []version2.Distribution{
						{
							Weight: "35%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "65%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_36_64",
					Distributions: []version2.Distribution{
						{
							Weight: "36%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "64%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_37_63",
					Distributions: []version2.Distribution{
						{
							Weight: "37%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "63%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_38_62",
					Distributions: []version2.Distribution{
						{
							Weight: "38%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "62%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_39_61",
					Distributions: []version2.Distribution{
						{
							Weight: "39%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "61%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_40_60",
					Distributions: []version2.Distribution{
						{
							Weight: "40%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "60%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_41_59",
					Distributions: []version2.Distribution{
						{
							Weight: "41%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "59%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_42_58",
					Distributions: []version2.Distribution{
						{
							Weight: "42%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "58%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_43_57",
					Distributions: []version2.Distribution{
						{
							Weight: "43%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "57%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_44_56",
					Distributions: []version2.Distribution{
						{
							Weight: "44%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "56%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_45_55",
					Distributions: []version2.Distribution{
						{
							Weight: "45%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "55%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_46_54",
					Distributions: []version2.Distribution{
						{
							Weight: "46%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "54%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_47_53",
					Distributions: []version2.Distribution{
						{
							Weight: "47%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "53%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_48_52",
					Distributions: []version2.Distribution{
						{
							Weight: "48%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "52%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_49_51",
					Distributions: []version2.Distribution{
						{
							Weight: "49%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "51%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_50_50",
					Distributions: []version2.Distribution{
						{
							Weight: "50%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "50%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_51_49",
					Distributions: []version2.Distribution{
						{
							Weight: "51%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "49%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_52_48",
					Distributions: []version2.Distribution{
						{
							Weight: "52%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "48%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_53_47",
					Distributions: []version2.Distribution{
						{
							Weight: "53%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "47%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_54_46",
					Distributions: []version2.Distribution{
						{
							Weight: "54%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "46%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_55_45",
					Distributions: []version2.Distribution{
						{
							Weight: "55%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "45%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_56_44",
					Distributions: []version2.Distribution{
						{
							Weight: "56%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "44%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_57_43",
					Distributions: []version2.Distribution{
						{
							Weight: "57%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "43%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_58_42",
					Distributions: []version2.Distribution{
						{
							Weight: "58%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "42%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_59_41",
					Distributions: []version2.Distribution{
						{
							Weight: "59%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "41%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_60_40",
					Distributions: []version2.Distribution{
						{
							Weight: "60%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "40%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_61_39",
					Distributions: []version2.Distribution{
						{
							Weight: "61%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "39%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_62_38",
					Distributions: []version2.Distribution{
						{
							Weight: "62%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "38%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_63_37",
					Distributions: []version2.Distribution{
						{
							Weight: "63%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "37%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_64_36",
					Distributions: []version2.Distribution{
						{
							Weight: "64%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "36%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_65_35",
					Distributions: []version2.Distribution{
						{
							Weight: "65%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "35%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_66_34",
					Distributions: []version2.Distribution{
						{
							Weight: "66%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "34%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_67_33",
					Distributions: []version2.Distribution{
						{
							Weight: "67%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "33%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_68_32",
					Distributions: []version2.Distribution{
						{
							Weight: "68%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "32%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_69_31",
					Distributions: []version2.Distribution{
						{
							Weight: "69%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "31%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_70_30",
					Distributions: []version2.Distribution{
						{
							Weight: "70%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "30%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_71_29",
					Distributions: []version2.Distribution{
						{
							Weight: "71%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "29%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_72_28",
					Distributions: []version2.Distribution{
						{
							Weight: "72%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "28%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_73_27",
					Distributions: []version2.Distribution{
						{
							Weight: "73%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "27%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_74_26",
					Distributions: []version2.Distribution{
						{
							Weight: "74%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "26%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_75_25",
					Distributions: []version2.Distribution{
						{
							Weight: "75%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "25%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_76_24",
					Distributions: []version2.Distribution{
						{
							Weight: "76%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "24%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_77_23",
					Distributions: []version2.Distribution{
						{
							Weight: "77%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "23%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_78_22",
					Distributions: []version2.Distribution{
						{
							Weight: "78%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "22%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_79_21",
					Distributions: []version2.Distribution{
						{
							Weight: "79%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "21%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_80_20",
					Distributions: []version2.Distribution{
						{
							Weight: "80%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "20%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_81_19",
					Distributions: []version2.Distribution{
						{
							Weight: "81%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "19%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_82_18",
					Distributions: []version2.Distribution{
						{
							Weight: "82%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "18%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_83_17",
					Distributions: []version2.Distribution{
						{
							Weight: "83%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "17%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_84_16",
					Distributions: []version2.Distribution{
						{
							Weight: "84%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "16%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_85_15",
					Distributions: []version2.Distribution{
						{
							Weight: "85%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "15%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_86_14",
					Distributions: []version2.Distribution{
						{
							Weight: "86%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "14%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_87_13",
					Distributions: []version2.Distribution{
						{
							Weight: "87%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "13%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_88_12",
					Distributions: []version2.Distribution{
						{
							Weight: "88%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "12%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_89_11",
					Distributions: []version2.Distribution{
						{
							Weight: "89%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "11%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_90_10",
					Distributions: []version2.Distribution{
						{
							Weight: "90%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "10%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_91_9",
					Distributions: []version2.Distribution{
						{
							Weight: "91%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "9%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_92_8",
					Distributions: []version2.Distribution{
						{
							Weight: "92%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "8%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_93_7",
					Distributions: []version2.Distribution{
						{
							Weight: "93%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "7%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_94_6",
					Distributions: []version2.Distribution{
						{
							Weight: "94%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "6%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_95_5",
					Distributions: []version2.Distribution{
						{
							Weight: "95%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "5%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_96_4",
					Distributions: []version2.Distribution{
						{
							Weight: "96%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "4%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_97_3",
					Distributions: []version2.Distribution{
						{
							Weight: "97%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "3%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_98_2",
					Distributions: []version2.Distribution{
						{
							Weight: "98%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "2%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_99_1",
					Distributions: []version2.Distribution{
						{
							Weight: "99%",
							Value:  "/internal_location_splits_1_split_0",
						},
						{
							Weight: "1%",
							Value:  "/internal_location_splits_1_split_1",
						},
					},
				},
				{
					Source:   "$request_id",
					Variable: "$vs_default_cafe_split_clients_1_100_0",
					Distributions: []version2.Distribution{
						{
							Weight: "100%",
							Value:  "/internal_location_splits_1_split_0",
						},
					},
				},
			},
			msg: "Normal Split",
		},
	}
	originalPath := "/path"

	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServer(&virtualServer)
	variableNamer := NewVSVariableNamer(&virtualServer)
	scIndex := 1
	cfgParams := ConfigParams{Context: context.Background()}
	crUpstreams := map[string]conf_v1.Upstream{
		"vs_default_cafe_coffee-v1": {
			Service: "coffee-v1",
		},
		"vs_default_cafe_coffee-v2": {
			Service: "coffee-v2",
		},
	}
	enableSnippets := false
	expectedLocations := []version2.Location{
		{
			Path:      "/internal_location_splits_1_split_0",
			ProxyPass: "http://vs_default_cafe_coffee-v1",
			Rewrites: []string{
				"^ $request_uri_no_args",
				fmt.Sprintf(`"^%v(.*)$" "/rewrite$1" break`, originalPath),
			},
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 true,
			ProxySSLName:             "coffee-v1.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "coffee-v1",
			IsVSR:                    true,
			VSRName:                  "coffee",
			VSRNamespace:             "default",
		},
		{
			Path:                     "/internal_location_splits_1_split_1",
			ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 true,
			ProxySSLName:             "coffee-v2.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "coffee-v2",
			IsVSR:                    true,
			VSRName:                  "coffee",
			VSRNamespace:             "default",
		},
	}

	expectedMaps := []version2.Map{
		{
			Source:   "$vs_default_cafe_keyval_split_clients_1",
			Variable: "$vs_default_cafe_map_split_clients_1",
			Parameters: []version2.Parameter{
				{Value: `"vs_default_cafe_split_clients_1_0_100"`, Result: "$vs_default_cafe_split_clients_1_0_100"},
				{Value: `"vs_default_cafe_split_clients_1_1_99"`, Result: "$vs_default_cafe_split_clients_1_1_99"},
				{Value: `"vs_default_cafe_split_clients_1_2_98"`, Result: "$vs_default_cafe_split_clients_1_2_98"},
				{Value: `"vs_default_cafe_split_clients_1_3_97"`, Result: "$vs_default_cafe_split_clients_1_3_97"},
				{Value: `"vs_default_cafe_split_clients_1_4_96"`, Result: "$vs_default_cafe_split_clients_1_4_96"},
				{Value: `"vs_default_cafe_split_clients_1_5_95"`, Result: "$vs_default_cafe_split_clients_1_5_95"},
				{Value: `"vs_default_cafe_split_clients_1_6_94"`, Result: "$vs_default_cafe_split_clients_1_6_94"},
				{Value: `"vs_default_cafe_split_clients_1_7_93"`, Result: "$vs_default_cafe_split_clients_1_7_93"},
				{Value: `"vs_default_cafe_split_clients_1_8_92"`, Result: "$vs_default_cafe_split_clients_1_8_92"},
				{Value: `"vs_default_cafe_split_clients_1_9_91"`, Result: "$vs_default_cafe_split_clients_1_9_91"},
				{Value: `"vs_default_cafe_split_clients_1_10_90"`, Result: "$vs_default_cafe_split_clients_1_10_90"},
				{Value: `"vs_default_cafe_split_clients_1_11_89"`, Result: "$vs_default_cafe_split_clients_1_11_89"},
				{Value: `"vs_default_cafe_split_clients_1_12_88"`, Result: "$vs_default_cafe_split_clients_1_12_88"},
				{Value: `"vs_default_cafe_split_clients_1_13_87"`, Result: "$vs_default_cafe_split_clients_1_13_87"},
				{Value: `"vs_default_cafe_split_clients_1_14_86"`, Result: "$vs_default_cafe_split_clients_1_14_86"},
				{Value: `"vs_default_cafe_split_clients_1_15_85"`, Result: "$vs_default_cafe_split_clients_1_15_85"},
				{Value: `"vs_default_cafe_split_clients_1_16_84"`, Result: "$vs_default_cafe_split_clients_1_16_84"},
				{Value: `"vs_default_cafe_split_clients_1_17_83"`, Result: "$vs_default_cafe_split_clients_1_17_83"},
				{Value: `"vs_default_cafe_split_clients_1_18_82"`, Result: "$vs_default_cafe_split_clients_1_18_82"},
				{Value: `"vs_default_cafe_split_clients_1_19_81"`, Result: "$vs_default_cafe_split_clients_1_19_81"},
				{Value: `"vs_default_cafe_split_clients_1_20_80"`, Result: "$vs_default_cafe_split_clients_1_20_80"},
				{Value: `"vs_default_cafe_split_clients_1_21_79"`, Result: "$vs_default_cafe_split_clients_1_21_79"},
				{Value: `"vs_default_cafe_split_clients_1_22_78"`, Result: "$vs_default_cafe_split_clients_1_22_78"},
				{Value: `"vs_default_cafe_split_clients_1_23_77"`, Result: "$vs_default_cafe_split_clients_1_23_77"},
				{Value: `"vs_default_cafe_split_clients_1_24_76"`, Result: "$vs_default_cafe_split_clients_1_24_76"},
				{Value: `"vs_default_cafe_split_clients_1_25_75"`, Result: "$vs_default_cafe_split_clients_1_25_75"},
				{Value: `"vs_default_cafe_split_clients_1_26_74"`, Result: "$vs_default_cafe_split_clients_1_26_74"},
				{Value: `"vs_default_cafe_split_clients_1_27_73"`, Result: "$vs_default_cafe_split_clients_1_27_73"},
				{Value: `"vs_default_cafe_split_clients_1_28_72"`, Result: "$vs_default_cafe_split_clients_1_28_72"},
				{Value: `"vs_default_cafe_split_clients_1_29_71"`, Result: "$vs_default_cafe_split_clients_1_29_71"},
				{Value: `"vs_default_cafe_split_clients_1_30_70"`, Result: "$vs_default_cafe_split_clients_1_30_70"},
				{Value: `"vs_default_cafe_split_clients_1_31_69"`, Result: "$vs_default_cafe_split_clients_1_31_69"},
				{Value: `"vs_default_cafe_split_clients_1_32_68"`, Result: "$vs_default_cafe_split_clients_1_32_68"},
				{Value: `"vs_default_cafe_split_clients_1_33_67"`, Result: "$vs_default_cafe_split_clients_1_33_67"},
				{Value: `"vs_default_cafe_split_clients_1_34_66"`, Result: "$vs_default_cafe_split_clients_1_34_66"},
				{Value: `"vs_default_cafe_split_clients_1_35_65"`, Result: "$vs_default_cafe_split_clients_1_35_65"},
				{Value: `"vs_default_cafe_split_clients_1_36_64"`, Result: "$vs_default_cafe_split_clients_1_36_64"},
				{Value: `"vs_default_cafe_split_clients_1_37_63"`, Result: "$vs_default_cafe_split_clients_1_37_63"},
				{Value: `"vs_default_cafe_split_clients_1_38_62"`, Result: "$vs_default_cafe_split_clients_1_38_62"},
				{Value: `"vs_default_cafe_split_clients_1_39_61"`, Result: "$vs_default_cafe_split_clients_1_39_61"},
				{Value: `"vs_default_cafe_split_clients_1_40_60"`, Result: "$vs_default_cafe_split_clients_1_40_60"},
				{Value: `"vs_default_cafe_split_clients_1_41_59"`, Result: "$vs_default_cafe_split_clients_1_41_59"},
				{Value: `"vs_default_cafe_split_clients_1_42_58"`, Result: "$vs_default_cafe_split_clients_1_42_58"},
				{Value: `"vs_default_cafe_split_clients_1_43_57"`, Result: "$vs_default_cafe_split_clients_1_43_57"},
				{Value: `"vs_default_cafe_split_clients_1_44_56"`, Result: "$vs_default_cafe_split_clients_1_44_56"},
				{Value: `"vs_default_cafe_split_clients_1_45_55"`, Result: "$vs_default_cafe_split_clients_1_45_55"},
				{Value: `"vs_default_cafe_split_clients_1_46_54"`, Result: "$vs_default_cafe_split_clients_1_46_54"},
				{Value: `"vs_default_cafe_split_clients_1_47_53"`, Result: "$vs_default_cafe_split_clients_1_47_53"},
				{Value: `"vs_default_cafe_split_clients_1_48_52"`, Result: "$vs_default_cafe_split_clients_1_48_52"},
				{Value: `"vs_default_cafe_split_clients_1_49_51"`, Result: "$vs_default_cafe_split_clients_1_49_51"},
				{Value: `"vs_default_cafe_split_clients_1_50_50"`, Result: "$vs_default_cafe_split_clients_1_50_50"},
				{Value: `"vs_default_cafe_split_clients_1_51_49"`, Result: "$vs_default_cafe_split_clients_1_51_49"},
				{Value: `"vs_default_cafe_split_clients_1_52_48"`, Result: "$vs_default_cafe_split_clients_1_52_48"},
				{Value: `"vs_default_cafe_split_clients_1_53_47"`, Result: "$vs_default_cafe_split_clients_1_53_47"},
				{Value: `"vs_default_cafe_split_clients_1_54_46"`, Result: "$vs_default_cafe_split_clients_1_54_46"},
				{Value: `"vs_default_cafe_split_clients_1_55_45"`, Result: "$vs_default_cafe_split_clients_1_55_45"},
				{Value: `"vs_default_cafe_split_clients_1_56_44"`, Result: "$vs_default_cafe_split_clients_1_56_44"},
				{Value: `"vs_default_cafe_split_clients_1_57_43"`, Result: "$vs_default_cafe_split_clients_1_57_43"},
				{Value: `"vs_default_cafe_split_clients_1_58_42"`, Result: "$vs_default_cafe_split_clients_1_58_42"},
				{Value: `"vs_default_cafe_split_clients_1_59_41"`, Result: "$vs_default_cafe_split_clients_1_59_41"},
				{Value: `"vs_default_cafe_split_clients_1_60_40"`, Result: "$vs_default_cafe_split_clients_1_60_40"},
				{Value: `"vs_default_cafe_split_clients_1_61_39"`, Result: "$vs_default_cafe_split_clients_1_61_39"},
				{Value: `"vs_default_cafe_split_clients_1_62_38"`, Result: "$vs_default_cafe_split_clients_1_62_38"},
				{Value: `"vs_default_cafe_split_clients_1_63_37"`, Result: "$vs_default_cafe_split_clients_1_63_37"},
				{Value: `"vs_default_cafe_split_clients_1_64_36"`, Result: "$vs_default_cafe_split_clients_1_64_36"},
				{Value: `"vs_default_cafe_split_clients_1_65_35"`, Result: "$vs_default_cafe_split_clients_1_65_35"},
				{Value: `"vs_default_cafe_split_clients_1_66_34"`, Result: "$vs_default_cafe_split_clients_1_66_34"},
				{Value: `"vs_default_cafe_split_clients_1_67_33"`, Result: "$vs_default_cafe_split_clients_1_67_33"},
				{Value: `"vs_default_cafe_split_clients_1_68_32"`, Result: "$vs_default_cafe_split_clients_1_68_32"},
				{Value: `"vs_default_cafe_split_clients_1_69_31"`, Result: "$vs_default_cafe_split_clients_1_69_31"},
				{Value: `"vs_default_cafe_split_clients_1_70_30"`, Result: "$vs_default_cafe_split_clients_1_70_30"},
				{Value: `"vs_default_cafe_split_clients_1_71_29"`, Result: "$vs_default_cafe_split_clients_1_71_29"},
				{Value: `"vs_default_cafe_split_clients_1_72_28"`, Result: "$vs_default_cafe_split_clients_1_72_28"},
				{Value: `"vs_default_cafe_split_clients_1_73_27"`, Result: "$vs_default_cafe_split_clients_1_73_27"},
				{Value: `"vs_default_cafe_split_clients_1_74_26"`, Result: "$vs_default_cafe_split_clients_1_74_26"},
				{Value: `"vs_default_cafe_split_clients_1_75_25"`, Result: "$vs_default_cafe_split_clients_1_75_25"},
				{Value: `"vs_default_cafe_split_clients_1_76_24"`, Result: "$vs_default_cafe_split_clients_1_76_24"},
				{Value: `"vs_default_cafe_split_clients_1_77_23"`, Result: "$vs_default_cafe_split_clients_1_77_23"},
				{Value: `"vs_default_cafe_split_clients_1_78_22"`, Result: "$vs_default_cafe_split_clients_1_78_22"},
				{Value: `"vs_default_cafe_split_clients_1_79_21"`, Result: "$vs_default_cafe_split_clients_1_79_21"},
				{Value: `"vs_default_cafe_split_clients_1_80_20"`, Result: "$vs_default_cafe_split_clients_1_80_20"},
				{Value: `"vs_default_cafe_split_clients_1_81_19"`, Result: "$vs_default_cafe_split_clients_1_81_19"},
				{Value: `"vs_default_cafe_split_clients_1_82_18"`, Result: "$vs_default_cafe_split_clients_1_82_18"},
				{Value: `"vs_default_cafe_split_clients_1_83_17"`, Result: "$vs_default_cafe_split_clients_1_83_17"},
				{Value: `"vs_default_cafe_split_clients_1_84_16"`, Result: "$vs_default_cafe_split_clients_1_84_16"},
				{Value: `"vs_default_cafe_split_clients_1_85_15"`, Result: "$vs_default_cafe_split_clients_1_85_15"},
				{Value: `"vs_default_cafe_split_clients_1_86_14"`, Result: "$vs_default_cafe_split_clients_1_86_14"},
				{Value: `"vs_default_cafe_split_clients_1_87_13"`, Result: "$vs_default_cafe_split_clients_1_87_13"},
				{Value: `"vs_default_cafe_split_clients_1_88_12"`, Result: "$vs_default_cafe_split_clients_1_88_12"},
				{Value: `"vs_default_cafe_split_clients_1_89_11"`, Result: "$vs_default_cafe_split_clients_1_89_11"},
				{Value: `"vs_default_cafe_split_clients_1_90_10"`, Result: "$vs_default_cafe_split_clients_1_90_10"},
				{Value: `"vs_default_cafe_split_clients_1_91_9"`, Result: "$vs_default_cafe_split_clients_1_91_9"},
				{Value: `"vs_default_cafe_split_clients_1_92_8"`, Result: "$vs_default_cafe_split_clients_1_92_8"},
				{Value: `"vs_default_cafe_split_clients_1_93_7"`, Result: "$vs_default_cafe_split_clients_1_93_7"},
				{Value: `"vs_default_cafe_split_clients_1_94_6"`, Result: "$vs_default_cafe_split_clients_1_94_6"},
				{Value: `"vs_default_cafe_split_clients_1_95_5"`, Result: "$vs_default_cafe_split_clients_1_95_5"},
				{Value: `"vs_default_cafe_split_clients_1_96_4"`, Result: "$vs_default_cafe_split_clients_1_96_4"},
				{Value: `"vs_default_cafe_split_clients_1_97_3"`, Result: "$vs_default_cafe_split_clients_1_97_3"},
				{Value: `"vs_default_cafe_split_clients_1_98_2"`, Result: "$vs_default_cafe_split_clients_1_98_2"},
				{Value: `"vs_default_cafe_split_clients_1_99_1"`, Result: "$vs_default_cafe_split_clients_1_99_1"},
				{Value: `"vs_default_cafe_split_clients_1_100_0"`, Result: "$vs_default_cafe_split_clients_1_100_0"},
				{Value: "default", Result: "$vs_default_cafe_split_clients_1_100_0"},
			},
		},
	}

	expectedKeyValZones := []version2.KeyValZone{
		{
			Name:  "vs_default_cafe_keyval_zone_split_clients_1",
			Size:  "100k",
			State: "/etc/nginx/state_files/vs_default_cafe_keyval_zone_split_clients_1.json",
		},
	}

	expectedKeyVals := []version2.KeyVal{
		{
			Key:      `"vs_default_cafe_keyval_key_split_clients_1"`,
			Variable: "$vs_default_cafe_keyval_split_clients_1",
			ZoneName: "vs_default_cafe_keyval_zone_split_clients_1",
		},
	}

	expectedTwoWaySplitClients := []version2.TwoWaySplitClients{
		{
			Key:               `"vs_default_cafe_keyval_key_split_clients_1"`,
			Variable:          "$vs_default_cafe_keyval_split_clients_1",
			ZoneName:          "vs_default_cafe_keyval_zone_split_clients_1",
			SplitClientsIndex: 1,
			Weights:           []int{90, 10},
		},
	}
	returnLocationIndex := 1

	staticConfigParams := &StaticConfigParams{
		DynamicWeightChangesReload: true,
	}

	vsc := newVirtualServerConfigurator(&cfgParams, true, false, staticConfigParams, false, &fakeBV)
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			resultSplitClients, resultLocations, _, resultMaps, resultKeyValZones, resultKeyVals, resultTwoWaySplitClients := generateSplits(
				test.splits,
				upstreamNamer,
				crUpstreams,
				variableNamer,
				scIndex,
				&cfgParams,
				errorPageDetails{},
				originalPath,
				"",
				enableSnippets,
				returnLocationIndex,
				true,
				"coffee",
				"default",
				vsc.warnings,
				vsc.DynamicWeightChangesReload,
			)

			if !cmp.Equal(test.expectedSplitClients, resultSplitClients) {
				t.Errorf("generateSplits() resultSplitClient mismatch (-want +got):\n%s", cmp.Diff(test.expectedSplitClients, resultSplitClients))
			}
			if !cmp.Equal(expectedLocations, resultLocations) {
				t.Errorf("generateSplits() resultLocations mismatch (-want +got):\n%s", cmp.Diff(expectedLocations, resultLocations))
			}

			if !cmp.Equal(expectedMaps, resultMaps) {
				t.Errorf("generateSplits() resultLocations mismatch (-want +got):\n%s", cmp.Diff(expectedMaps, resultMaps))
			}

			if !cmp.Equal(expectedKeyValZones, resultKeyValZones) {
				t.Errorf("generateSplits() resultKeyValZones mismatch (-want +got):\n%s", cmp.Diff(expectedKeyValZones, resultKeyValZones))
			}

			if !cmp.Equal(expectedKeyVals, resultKeyVals) {
				t.Errorf("generateSplits() resultKeyVals mismatch (-want +got):\n%s", cmp.Diff(expectedKeyVals, resultKeyVals))
			}

			if !cmp.Equal(expectedTwoWaySplitClients, resultTwoWaySplitClients) {
				t.Errorf("generateSplits() resultTwoWaySplitClients mismatch (-want +got):\n%s", cmp.Diff(expectedTwoWaySplitClients, resultTwoWaySplitClients))
			}
		})
	}
}

func TestGenerateDefaultSplitsConfig(t *testing.T) {
	t.Parallel()
	route := conf_v1.Route{
		Path: "/",
		Splits: []conf_v1.Split{
			{
				Weight: 90,
				Action: &conf_v1.Action{
					Pass: "coffee-v1",
				},
			},
			{
				Weight: 10,
				Action: &conf_v1.Action{
					Pass: "coffee-v2",
				},
			},
		},
	}
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServer(&virtualServer)
	variableNamer := NewVSVariableNamer(&virtualServer)
	index := 1

	expected := routingCfg{
		SplitClients: []version2.SplitClient{
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_1",
				Distributions: []version2.Distribution{
					{
						Weight: "90%",
						Value:  "/internal_location_splits_1_split_0",
					},
					{
						Weight: "10%",
						Value:  "/internal_location_splits_1_split_1",
					},
				},
			},
		},
		Locations: []version2.Location{
			{
				Path:                     "/internal_location_splits_1_split_0",
				ProxyPass:                "http://vs_default_cafe_coffee-v1$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ProxySSLName:             "coffee-v1.default.svc",
				ProxyPassRequestHeaders:  true,
				ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:              "coffee-v1",
				IsVSR:                    true,
				VSRName:                  "coffee",
				VSRNamespace:             "default",
			},
			{
				Path:                     "/internal_location_splits_1_split_1",
				ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ProxySSLName:             "coffee-v2.default.svc",
				ProxyPassRequestHeaders:  true,
				ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:              "coffee-v2",
				IsVSR:                    true,
				VSRName:                  "coffee",
				VSRNamespace:             "default",
			},
		},
		InternalRedirectLocation: version2.InternalRedirectLocation{
			Path:        "/",
			Destination: "$vs_default_cafe_splits_1",
		},
	}

	cfgParams := ConfigParams{Context: context.Background()}
	locSnippet := ""
	enableSnippets := false
	weightChangesDynamicReload := false
	crUpstreams := map[string]conf_v1.Upstream{
		"vs_default_cafe_coffee-v1": {
			Service: "coffee-v1",
		},
		"vs_default_cafe_coffee-v2": {
			Service: "coffee-v2",
		},
	}

	errorPageDetails := errorPageDetails{
		pages: route.ErrorPages,
		index: 0,
		owner: nil,
	}

	result := generateDefaultSplitsConfig(route, upstreamNamer, crUpstreams, variableNamer, index, &cfgParams,
		errorPageDetails, "", locSnippet, enableSnippets, 0, true, "coffee", "default", Warnings{}, weightChangesDynamicReload)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("generateDefaultSplitsConfig() returned \n%+v but expected \n%+v", result, expected)
	}
}

func TestGenerateMatchesConfig(t *testing.T) {
	t.Parallel()
	route := conf_v1.Route{
		Path: "/",
		Matches: []conf_v1.Match{
			{
				Conditions: []conf_v1.Condition{
					{
						Header: "x-version",
						Value:  "v1",
					},
					{
						Cookie: "user",
						Value:  "john",
					},
					{
						Argument: "answer",
						Value:    "yes",
					},
					{
						Variable: "$request_method",
						Value:    "GET",
					},
				},
				Action: &conf_v1.Action{
					Pass: "coffee-v1",
				},
			},
			{
				Conditions: []conf_v1.Condition{
					{
						Header: "x-version",
						Value:  "v2",
					},
					{
						Cookie: "user",
						Value:  "paul",
					},
					{
						Argument: "answer",
						Value:    "no",
					},
					{
						Variable: "$request_method",
						Value:    "POST",
					},
				},
				Splits: []conf_v1.Split{
					{
						Weight: 90,
						Action: &conf_v1.Action{
							Pass: "coffee-v1",
						},
					},
					{
						Weight: 10,
						Action: &conf_v1.Action{
							Pass: "coffee-v2",
						},
					},
				},
			},
		},
		Action: &conf_v1.Action{
			Pass: "tea",
		},
	}
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	errorPages := []conf_v1.ErrorPage{
		{
			Codes: []int{400, 500},
			Return: &conf_v1.ErrorPageReturn{
				ActionReturn: conf_v1.ActionReturn{
					Code: 200,
					Type: "application/json",
					Body: `{\"message\": \"ok\"}`,
					Headers: []conf_v1.Header{
						{
							Name:  "Set-Cookie",
							Value: "cookie1=value",
						},
					},
				},
			},
			Redirect: nil,
		},
		{
			Codes:  []int{500, 502},
			Return: nil,
			Redirect: &conf_v1.ErrorPageRedirect{
				ActionRedirect: conf_v1.ActionRedirect{
					URL:  "http://nginx.com",
					Code: 301,
				},
			},
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServer(&virtualServer)
	variableNamer := NewVSVariableNamer(&virtualServer)
	index := 1
	scIndex := 2

	expected := routingCfg{
		Maps: []version2.Map{
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_cafe_matches_1_match_0_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v1"`,
						Result: "$vs_default_cafe_matches_1_match_0_cond_1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$cookie_user",
				Variable: "$vs_default_cafe_matches_1_match_0_cond_1",
				Parameters: []version2.Parameter{
					{
						Value:  `"john"`,
						Result: "$vs_default_cafe_matches_1_match_0_cond_2",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$arg_answer",
				Variable: "$vs_default_cafe_matches_1_match_0_cond_2",
				Parameters: []version2.Parameter{
					{
						Value:  `"yes"`,
						Result: "$vs_default_cafe_matches_1_match_0_cond_3",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$request_method",
				Variable: "$vs_default_cafe_matches_1_match_0_cond_3",
				Parameters: []version2.Parameter{
					{
						Value:  `"GET"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_cafe_matches_1_match_1_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v2"`,
						Result: "$vs_default_cafe_matches_1_match_1_cond_1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$cookie_user",
				Variable: "$vs_default_cafe_matches_1_match_1_cond_1",
				Parameters: []version2.Parameter{
					{
						Value:  `"paul"`,
						Result: "$vs_default_cafe_matches_1_match_1_cond_2",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$arg_answer",
				Variable: "$vs_default_cafe_matches_1_match_1_cond_2",
				Parameters: []version2.Parameter{
					{
						Value:  `"no"`,
						Result: "$vs_default_cafe_matches_1_match_1_cond_3",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$request_method",
				Variable: "$vs_default_cafe_matches_1_match_1_cond_3",
				Parameters: []version2.Parameter{
					{
						Value:  `"POST"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$vs_default_cafe_matches_1_match_0_cond_0$vs_default_cafe_matches_1_match_1_cond_0",
				Variable: "$vs_default_cafe_matches_1",
				Parameters: []version2.Parameter{
					{
						Value:  "~^1",
						Result: "/internal_location_matches_1_match_0",
					},
					{
						Value:  "~^01",
						Result: "$vs_default_cafe_splits_2",
					},
					{
						Value:  "default",
						Result: "/internal_location_matches_1_default",
					},
				},
			},
		},
		Locations: []version2.Location{
			{
				Path:                     "/internal_location_matches_1_match_0",
				ProxyPass:                "http://vs_default_cafe_coffee-v1$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				ProxyInterceptErrors:     true,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_2_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxySSLName:            "coffee-v1.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v1",
				IsVSR:                   false,
				VSRName:                 "",
				VSRNamespace:            "",
			},
			{
				Path:                     "/internal_location_splits_2_split_0",
				ProxyPass:                "http://vs_default_cafe_coffee-v1$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				ProxyInterceptErrors:     true,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_2_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxySSLName:            "coffee-v1.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v1",
				IsVSR:                   false,
				VSRName:                 "",
				VSRNamespace:            "",
			},
			{
				Path:                     "/internal_location_splits_2_split_1",
				ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				ProxyInterceptErrors:     true,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_2_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxySSLName:            "coffee-v2.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v2",
				IsVSR:                   false,
				VSRName:                 "",
				VSRNamespace:            "",
			},
			{
				Path:                     "/internal_location_matches_1_default",
				ProxyPass:                "http://vs_default_cafe_tea$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				ProxyInterceptErrors:     true,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_2_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxySSLName:            "tea.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "tea",
				IsVSR:                   false,
				VSRName:                 "",
				VSRNamespace:            "",
			},
		},
		InternalRedirectLocation: version2.InternalRedirectLocation{
			Path:        "/",
			Destination: "$vs_default_cafe_matches_1",
		},
		SplitClients: []version2.SplitClient{
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_2",
				Distributions: []version2.Distribution{
					{
						Weight: "90%",
						Value:  "/internal_location_splits_2_split_0",
					},
					{
						Weight: "10%",
						Value:  "/internal_location_splits_2_split_1",
					},
				},
			},
		},
	}

	cfgParams := ConfigParams{Context: context.Background()}
	enableSnippets := false
	weightChangesDynamicReload := false
	locSnippets := ""
	crUpstreams := map[string]conf_v1.Upstream{
		"vs_default_cafe_coffee-v1": {Service: "coffee-v1"},
		"vs_default_cafe_coffee-v2": {Service: "coffee-v2"},
		"vs_default_cafe_tea":       {Service: "tea"},
	}

	errorPageDetails := errorPageDetails{
		pages: errorPages,
		index: 2,
		owner: nil,
	}

	result := generateMatchesConfig(
		route,
		upstreamNamer,
		crUpstreams,
		variableNamer,
		index,
		scIndex,
		&cfgParams,
		errorPageDetails,
		locSnippets,
		enableSnippets,
		0,
		false,
		"",
		"",
		Warnings{},
		weightChangesDynamicReload,
	)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("generateMatchesConfig() returned \n%+v but expected \n%+v", result, expected)
	}
}

func TestGenerateMatchesConfigWithMultipleSplits(t *testing.T) {
	t.Parallel()
	route := conf_v1.Route{
		Path: "/",
		Matches: []conf_v1.Match{
			{
				Conditions: []conf_v1.Condition{
					{
						Header: "x-version",
						Value:  "v1",
					},
				},
				Splits: []conf_v1.Split{
					{
						Weight: 30,
						Action: &conf_v1.Action{
							Pass: "coffee-v1",
						},
					},
					{
						Weight: 70,
						Action: &conf_v1.Action{
							Pass: "coffee-v2",
						},
					},
				},
			},
			{
				Conditions: []conf_v1.Condition{
					{
						Header: "x-version",
						Value:  "v2",
					},
				},
				Splits: []conf_v1.Split{
					{
						Weight: 90,
						Action: &conf_v1.Action{
							Pass: "coffee-v2",
						},
					},
					{
						Weight: 10,
						Action: &conf_v1.Action{
							Pass: "coffee-v1",
						},
					},
				},
			},
		},
		Splits: []conf_v1.Split{
			{
				Weight: 99,
				Action: &conf_v1.Action{
					Pass: "coffee-v1",
				},
			},
			{
				Weight: 1,
				Action: &conf_v1.Action{
					Pass: "coffee-v2",
				},
			},
		},
	}
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServer(&virtualServer)
	variableNamer := NewVSVariableNamer(&virtualServer)
	index := 1
	scIndex := 2
	errorPages := []conf_v1.ErrorPage{
		{
			Codes: []int{400, 500},
			Return: &conf_v1.ErrorPageReturn{
				ActionReturn: conf_v1.ActionReturn{
					Code: 200,
					Type: "application/json",
					Body: `{\"message\": \"ok\"}`,
					Headers: []conf_v1.Header{
						{
							Name:  "Set-Cookie",
							Value: "cookie1=value",
						},
					},
				},
			},
			Redirect: nil,
		},
		{
			Codes:  []int{500, 502},
			Return: nil,
			Redirect: &conf_v1.ErrorPageRedirect{
				ActionRedirect: conf_v1.ActionRedirect{
					URL:  "http://nginx.com",
					Code: 301,
				},
			},
		},
	}

	expected := routingCfg{
		Maps: []version2.Map{
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_cafe_matches_1_match_0_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v1"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$http_x_version",
				Variable: "$vs_default_cafe_matches_1_match_1_cond_0",
				Parameters: []version2.Parameter{
					{
						Value:  `"v2"`,
						Result: "1",
					},
					{
						Value:  "default",
						Result: "0",
					},
				},
			},
			{
				Source:   "$vs_default_cafe_matches_1_match_0_cond_0$vs_default_cafe_matches_1_match_1_cond_0",
				Variable: "$vs_default_cafe_matches_1",
				Parameters: []version2.Parameter{
					{
						Value:  "~^1",
						Result: "$vs_default_cafe_splits_2",
					},
					{
						Value:  "~^01",
						Result: "$vs_default_cafe_splits_3",
					},
					{
						Value:  "default",
						Result: "$vs_default_cafe_splits_4",
					},
				},
			},
		},
		Locations: []version2.Location{
			{
				Path:                     "/internal_location_splits_2_split_0",
				ProxyPass:                "http://vs_default_cafe_coffee-v1$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_0_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors:    true,
				ProxySSLName:            "coffee-v1.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v1",
				IsVSR:                   true,
				VSRName:                 "coffee",
				VSRNamespace:            "default",
			},
			{
				Path:                     "/internal_location_splits_2_split_1",
				ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_0_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors:    true,
				ProxySSLName:            "coffee-v2.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v2",
				IsVSR:                   true,
				VSRName:                 "coffee",
				VSRNamespace:            "default",
			},
			{
				Path:                     "/internal_location_splits_3_split_0",
				ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_0_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors:    true,
				ProxySSLName:            "coffee-v2.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v2",
				IsVSR:                   true,
				VSRName:                 "coffee",
				VSRNamespace:            "default",
			},
			{
				Path:                     "/internal_location_splits_3_split_1",
				ProxyPass:                "http://vs_default_cafe_coffee-v1$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_0_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors:    true,
				ProxySSLName:            "coffee-v1.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v1",
				IsVSR:                   true,
				VSRName:                 "coffee",
				VSRNamespace:            "default",
			},
			{
				Path:                     "/internal_location_splits_4_split_0",
				ProxyPass:                "http://vs_default_cafe_coffee-v1$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_0_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors:    true,
				ProxySSLName:            "coffee-v1.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v1",
				IsVSR:                   true,
				VSRName:                 "coffee",
				VSRNamespace:            "default",
			},
			{
				Path:                     "/internal_location_splits_4_split_1",
				ProxyPass:                "http://vs_default_cafe_coffee-v2$request_uri",
				ProxyNextUpstream:        "error timeout",
				ProxyNextUpstreamTimeout: "0s",
				ProxyNextUpstreamTries:   0,
				Internal:                 true,
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@error_page_0_0",
						Codes:        "400 500",
						ResponseCode: 200,
					},
					{
						Name:         "http://nginx.com",
						Codes:        "500 502",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors:    true,
				ProxySSLName:            "coffee-v2.default.svc",
				ProxyPassRequestHeaders: true,
				ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
				ServiceName:             "coffee-v2",
				IsVSR:                   true,
				VSRName:                 "coffee",
				VSRNamespace:            "default",
			},
		},
		InternalRedirectLocation: version2.InternalRedirectLocation{
			Path:        "/",
			Destination: "$vs_default_cafe_matches_1",
		},
		SplitClients: []version2.SplitClient{
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_2",
				Distributions: []version2.Distribution{
					{
						Weight: "30%",
						Value:  "/internal_location_splits_2_split_0",
					},
					{
						Weight: "70%",
						Value:  "/internal_location_splits_2_split_1",
					},
				},
			},
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_3",
				Distributions: []version2.Distribution{
					{
						Weight: "90%",
						Value:  "/internal_location_splits_3_split_0",
					},
					{
						Weight: "10%",
						Value:  "/internal_location_splits_3_split_1",
					},
				},
			},
			{
				Source:   "$request_id",
				Variable: "$vs_default_cafe_splits_4",
				Distributions: []version2.Distribution{
					{
						Weight: "99%",
						Value:  "/internal_location_splits_4_split_0",
					},
					{
						Weight: "1%",
						Value:  "/internal_location_splits_4_split_1",
					},
				},
			},
		},
	}

	cfgParams := ConfigParams{Context: context.Background()}
	enableSnippets := false
	weightChangesWithoutReload := false
	locSnippets := ""
	crUpstreams := map[string]conf_v1.Upstream{
		"vs_default_cafe_coffee-v1": {Service: "coffee-v1"},
		"vs_default_cafe_coffee-v2": {Service: "coffee-v2"},
	}

	errorPageDetails := errorPageDetails{
		pages: errorPages,
		index: 0,
		owner: nil,
	}

	result := generateMatchesConfig(
		route,
		upstreamNamer,
		crUpstreams,
		variableNamer,
		index,
		scIndex,
		&cfgParams,
		errorPageDetails,
		locSnippets,
		enableSnippets,
		0,
		true,
		"coffee",
		"default",
		Warnings{},
		weightChangesWithoutReload,
	)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("generateMatchesConfig() returned \n%+v but expected \n%+v", result, expected)
	}
}

func TestGenerateValueForMatchesRouteMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input              string
		expectedValue      string
		expectedIsNegative bool
	}{
		{
			input:              "default",
			expectedValue:      `\default`,
			expectedIsNegative: false,
		},
		{
			input:              "!default",
			expectedValue:      `\default`,
			expectedIsNegative: true,
		},
		{
			input:              "hostnames",
			expectedValue:      `\hostnames`,
			expectedIsNegative: false,
		},
		{
			input:              "include",
			expectedValue:      `\include`,
			expectedIsNegative: false,
		},
		{
			input:              "volatile",
			expectedValue:      `\volatile`,
			expectedIsNegative: false,
		},
		{
			input:              "abc",
			expectedValue:      `"abc"`,
			expectedIsNegative: false,
		},
		{
			input:              "!abc",
			expectedValue:      `"abc"`,
			expectedIsNegative: true,
		},
		{
			input:              "",
			expectedValue:      `""`,
			expectedIsNegative: false,
		},
		{
			input:              "!",
			expectedValue:      `""`,
			expectedIsNegative: true,
		},
	}

	for _, test := range tests {
		resultValue, resultIsNegative := generateValueForMatchesRouteMap(test.input)
		if resultValue != test.expectedValue {
			t.Errorf("generateValueForMatchesRouteMap(%q) returned %q but expected %q as the value", test.input, resultValue, test.expectedValue)
		}
		if resultIsNegative != test.expectedIsNegative {
			t.Errorf("generateValueForMatchesRouteMap(%q) returned %v but expected %v as the isNegative", test.input, resultIsNegative, test.expectedIsNegative)
		}
	}
}

func TestGenerateParametersForMatchesRouteMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputMatchedValue     string
		inputSuccessfulResult string
		expected              []version2.Parameter
	}{
		{
			inputMatchedValue:     "abc",
			inputSuccessfulResult: "1",
			expected: []version2.Parameter{
				{
					Value:  `"abc"`,
					Result: "1",
				},
				{
					Value:  "default",
					Result: "0",
				},
			},
		},
		{
			inputMatchedValue:     "!abc",
			inputSuccessfulResult: "1",
			expected: []version2.Parameter{
				{
					Value:  `"abc"`,
					Result: "0",
				},
				{
					Value:  "default",
					Result: "1",
				},
			},
		},
	}

	for _, test := range tests {
		result := generateParametersForMatchesRouteMap(test.inputMatchedValue, test.inputSuccessfulResult)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateParametersForMatchesRouteMap(%q, %q) returned %v but expected %v", test.inputMatchedValue, test.inputSuccessfulResult, result, test.expected)
		}
	}
}

func TestGetNameForSourceForMatchesRouteMapFromCondition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    conf_v1.Condition
		expected string
	}{
		{
			input: conf_v1.Condition{
				Header: "x-version",
			},
			expected: "$http_x_version",
		},
		{
			input: conf_v1.Condition{
				Cookie: "mycookie",
			},
			expected: "$cookie_mycookie",
		},
		{
			input: conf_v1.Condition{
				Argument: "arg",
			},
			expected: "$arg_arg",
		},
		{
			input: conf_v1.Condition{
				Variable: "$request_method",
			},
			expected: "$request_method",
		},
	}

	for _, test := range tests {
		result := getNameForSourceForMatchesRouteMapFromCondition(test.input)
		if result != test.expected {
			t.Errorf("getNameForSourceForMatchesRouteMapFromCondition() returned %q but expected %q for input %v", result, test.expected, test.input)
		}
	}
}

// TestGenerateVirtualServerConfigForVSRWithMultipleRegexSubroutes verifies that when a single
// VirtualServerRoute is referenced by multiple VS regex routes, each subroute produces a
// separate nginx location block with the correct regex path format.
func TestGenerateVirtualServerConfigForVSRWithMultipleRegexSubroutes(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Routes: []conf_v1.Route{
					{
						Path:  "~/api/v1",
						Route: "default/api",
					},
					{
						Path:  "~/api/v2",
						Route: "default/api",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/api-svc:80": {
				"10.0.0.10:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "api-svc",
							Service: "api-svc",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "~/api/v1",
							Action: &conf_v1.Action{
								Pass: "api-svc",
							},
						},
						{
							Path: "~/api/v2",
							Action: &conf_v1.Action{
								Pass: "api-svc",
							},
						},
					},
				},
			},
		},
	}

	baseCfgParams := ConfigParams{Context: context.Background()}

	expected := []version2.Location{
		{
			Path:                     `~ "/api/v1"`,
			ProxyPass:                "http://vs_default_cafe_vsr_default_api_api-svc",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 false,
			ProxySSLName:             "api-svc.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "api-svc",
			IsVSR:                    true,
			VSRName:                  "api",
			VSRNamespace:             "default",
		},
		{
			Path:                     `~ "/api/v2"`,
			ProxyPass:                "http://vs_default_cafe_vsr_default_api_api-svc",
			ProxyNextUpstream:        "error timeout",
			ProxyNextUpstreamTimeout: "0s",
			ProxyNextUpstreamTries:   0,
			Internal:                 false,
			ProxySSLName:             "api-svc.default.svc",
			ProxyPassRequestHeaders:  true,
			ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
			ServiceName:              "api-svc",
			IsVSR:                    true,
			VSRName:                  "api",
			VSRNamespace:             "default",
		},
	}

	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{}, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result.Server.Locations); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned unexpected warnings: %v", warnings)
	}
}
