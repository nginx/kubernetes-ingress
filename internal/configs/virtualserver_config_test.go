package configs

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateVSConfig_GeneratesConfigWithGunzipOn(t *testing.T) {
	t.Parallel()

	vsc := newVirtualServerConfigurator(&baseCfgParams, true, false, &StaticConfigParams{TLSPassthrough: true}, false, &fakeBV)

	want := version2.VirtualServerConfig{
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			Gunzip:          true,
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerExWithGunzipOn, nil, nil)
	if len(warnings) > 0 {
		t.Fatalf("want no warnings, got: %v", vsc.warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateVSConfig_GeneratesConfigWithGunzipOff(t *testing.T) {
	t.Parallel()

	vsc := newVirtualServerConfigurator(&baseCfgParams, true, false, &StaticConfigParams{TLSPassthrough: true}, false, &fakeBV)

	want := version2.VirtualServerConfig{
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			Gunzip:          false,
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerExWithGunzipOff, nil, nil)
	if len(warnings) > 0 {
		t.Fatalf("want no warnings, got: %v", vsc.warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateVSConfig_GeneratesConfigWithNoGunzip(t *testing.T) {
	t.Parallel()

	vsc := newVirtualServerConfigurator(&baseCfgParams, true, false, &StaticConfigParams{TLSPassthrough: true}, false, &fakeBV)

	want := version2.VirtualServerConfig{
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			Gunzip:          false,
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerExWithNoGunzip, nil, nil)
	if len(warnings) > 0 {
		t.Fatalf("want no warnings, got: %v", vsc.warnings)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGenerateVirtualServerConfigWithBackupForNGINXPlus(t *testing.T) {
	t.Parallel()

	virtualServerEx := vsEx()
	virtualServerEx.VirtualServer.Spec.Upstreams[2].LBMethod = "least_conn"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].Backup = "backup-svc"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].BackupPort = new(uint16(8090))
	virtualServerEx.Endpoints = map[string][]string{
		"default/tea-svc:80": {
			"10.0.0.20:80",
		},
		"default/tea-svc_version=v1:80": {
			"10.0.0.30:80",
		},
		"default/coffee-svc:80": {
			"10.0.0.40:80",
		},
		"default/sub-tea-svc_version=v1:80": {
			"10.0.0.50:80",
		},
		"default/backup-svc:8090": {
			"clustertwo.corp.local:8090",
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

	want := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
				BackupServers: []version2.UpstreamServer{
					{
						Address: "clustertwo.corp.local:8090",
					},
				},
				LBMethod: "least_conn",
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			HTTPPort:        0,
			HTTPSPort:       0,
			CustomListeners: false,
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	isPlus := true
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	sort.Slice(want.Upstreams, func(i, j int) bool {
		return want.Upstreams[i].Name < want.Upstreams[j].Name
	})

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfig_DoesNotGenerateBackupOnMissingBackupNameForNGINXPlus(t *testing.T) {
	t.Parallel()

	virtualServerEx := vsEx()
	virtualServerEx.VirtualServer.Spec.Upstreams[2].LBMethod = "least_conn"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].Backup = ""
	virtualServerEx.VirtualServer.Spec.Upstreams[2].BackupPort = new(uint16(8090))
	virtualServerEx.Endpoints = map[string][]string{
		"default/tea-svc:80": {
			"10.0.0.20:80",
		},
		"default/tea-svc_version=v1:80": {
			"10.0.0.30:80",
		},
		"default/coffee-svc:80": {
			"10.0.0.40:80",
		},
		"default/sub-tea-svc_version=v1:80": {
			"10.0.0.50:80",
		},
		"default/backup-svc:8090": {
			"clustertwo.corp.local:8090",
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

	want := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
				LBMethod:  "least_conn",
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			HTTPPort:        0,
			HTTPSPort:       0,
			CustomListeners: false,
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	isPlus := true
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	sort.Slice(want.Upstreams, func(i, j int) bool {
		return want.Upstreams[i].Name < want.Upstreams[j].Name
	})

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfig_DoesNotGenerateBackupOnMissingBackupPortForNGINXPlus(t *testing.T) {
	t.Parallel()

	virtualServerEx := vsEx()
	virtualServerEx.VirtualServer.Spec.Upstreams[2].LBMethod = "least_conn"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].Backup = "backup-svc"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].BackupPort = nil
	virtualServerEx.Endpoints = map[string][]string{
		"default/tea-svc:80": {
			"10.0.0.20:80",
		},
		"default/tea-svc_version=v1:80": {
			"10.0.0.30:80",
		},
		"default/coffee-svc:80": {
			"10.0.0.40:80",
		},
		"default/sub-tea-svc_version=v1:80": {
			"10.0.0.50:80",
		},
		"default/backup-svc:8090": {
			"clustertwo.corp.local:8090",
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

	want := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
				LBMethod:  "least_conn",
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			HTTPPort:        0,
			HTTPSPort:       0,
			CustomListeners: false,
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	sort.Slice(want.Upstreams, func(i, j int) bool {
		return want.Upstreams[i].Name < want.Upstreams[j].Name
	})

	isPlus := true
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfig_DoesNotGenerateBackupOnMissingBackupPortAndNameForNGINXPlus(t *testing.T) {
	t.Parallel()

	virtualServerEx := vsEx()
	virtualServerEx.VirtualServer.Spec.Upstreams[2].LBMethod = "least_conn"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].Backup = ""
	virtualServerEx.VirtualServer.Spec.Upstreams[2].BackupPort = nil
	virtualServerEx.Endpoints = map[string][]string{
		"default/tea-svc:80": {
			"10.0.0.20:80",
		},
		"default/tea-svc_version=v1:80": {
			"10.0.0.30:80",
		},
		"default/coffee-svc:80": {
			"10.0.0.40:80",
		},
		"default/sub-tea-svc_version=v1:80": {
			"10.0.0.50:80",
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

	want := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
				LBMethod:  "least_conn",
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			HTTPPort:        0,
			HTTPSPort:       0,
			CustomListeners: false,
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	isPlus := true
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	sort.Slice(want.Upstreams, func(i, j int) bool {
		return want.Upstreams[i].Name < want.Upstreams[j].Name
	})

	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfig(t *testing.T) {
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
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
					{
						Name:        "tea-latest",
						Service:     "tea-svc",
						Subselector: map[string]string{"version": "v1"},
						Port:        80,
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
						Path: "/tea-latest",
						Action: &conf_v1.Action{
							Pass: "tea-latest",
						},
					},
					{
						Path:  "/coffee",
						Route: "default/coffee",
					},
					{
						Path:  "/subtea",
						Route: "default/subtea",
					},
					{
						Path: "/coffee-errorpage",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
						ErrorPages: []conf_v1.ErrorPage{
							{
								Codes: []int{401, 403},
								Redirect: &conf_v1.ErrorPageRedirect{
									ActionRedirect: conf_v1.ActionRedirect{
										URL:  "http://nginx.com",
										Code: 301,
									},
								},
							},
						},
					},
					{
						Path:  "/coffee-errorpage-subroute",
						Route: "default/subcoffee",
						ErrorPages: []conf_v1.ErrorPage{
							{
								Codes: []int{401, 403},
								Redirect: &conf_v1.ErrorPageRedirect{
									ActionRedirect: conf_v1.ActionRedirect{
										URL:  "http://nginx.com",
										Code: 301,
									},
								},
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
			"default/tea-svc_version=v1:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.40:80",
			},
			"default/sub-tea-svc_version=v1:80": {
				"10.0.0.50:80",
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
							Name:    "coffee",
							Service: "coffee-svc",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Action: &conf_v1.Action{
								Pass: "coffee",
							},
						},
					},
				},
			},
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "subtea",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:        "subtea",
							Service:     "sub-tea-svc",
							Port:        80,
							Subselector: map[string]string{"version": "v1"},
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/subtea",
							Action: &conf_v1.Action{
								Pass: "subtea",
							},
						},
					},
				},
			},
			{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "subcoffee",
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Host: "cafe.example.com",
					Upstreams: []conf_v1.Upstream{
						{
							Name:    "coffee",
							Service: "coffee-svc",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee-errorpage-subroute",
							Action: &conf_v1.Action{
								Pass: "coffee",
							},
						},
						{
							Path: "/coffee-errorpage-subroute-defined",
							Action: &conf_v1.Action{
								Pass: "coffee",
							},
							ErrorPages: []conf_v1.ErrorPage{
								{
									Codes: []int{502, 503},
									Return: &conf_v1.ErrorPageReturn{
										ActionReturn: conf_v1.ActionReturn{
											Code: 200,
											Type: "text/plain",
											Body: "All Good",
										},
									},
								},
							},
						},
					},
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

	expected := version2.VirtualServerConfig{
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
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
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
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_tea-latest",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "coffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_coffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subcoffee",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subcoffee_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.40:80",
					},
				},
				Keepalive: 16,
			},
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "sub-tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "subtea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_subtea_subtea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.50:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			HTTPPort:        0,
			HTTPSPort:       0,
			CustomListeners: false,
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/tea-latest",
					ProxyPass:                "http://vs_default_cafe_tea-latest",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				// Order changes here because we generate first all the VS Routes and then all the VSR Subroutes (separated for loops)
				{
					Path:                     "/coffee-errorpage",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_vsr_default_coffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					IsVSR:                    true,
					VSRName:                  "coffee",
					VSRNamespace:             "default",
				},
				{
					Path:                     "/subtea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subtea_subtea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "sub-tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "sub-tea-svc",
					IsVSR:                    true,
					VSRName:                  "subtea",
					VSRNamespace:             "default",
				},

				{
					Path:                     "/coffee-errorpage-subroute",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "http://nginx.com",
							Codes:        "401 403",
							ResponseCode: 301,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
				{
					Path:                     "/coffee-errorpage-subroute-defined",
					ProxyPass:                "http://vs_default_cafe_vsr_default_subcoffee_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxyInterceptErrors:     true,
					ErrorPages: []version2.ErrorPage{
						{
							Name:         "@error_page_0_0",
							Codes:        "502 503",
							ResponseCode: 200,
						},
					},
					ProxySSLName:            "coffee-svc.default.svc",
					ProxyPassRequestHeaders: true,
					ProxySetHeaders:         []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:             "coffee-svc",
					IsVSR:                   true,
					VSRName:                 "subcoffee",
					VSRNamespace:            "default",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
		},
	}

	sort.Slice(expected.Upstreams, func(i, j int) bool {
		return expected.Upstreams[i].Name < expected.Upstreams[j].Name
	})

	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{TLSPassthrough: true},
		isWildcardEnabled,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithCustomHttpAndHttpsListeners(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithCustomHTTPAndHTTPSListeners.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithCustomHTTPAndHTTPSListeners.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithCustomHTTPAndHTTPSListeners.VirtualServer.Namespace,
			VSName:          virtualServerExWithCustomHTTPAndHTTPSListeners.VirtualServer.Name,
			DisableIPV6:     true,
			HTTPPort:        virtualServerExWithCustomHTTPAndHTTPSListeners.HTTPPort,
			HTTPSPort:       virtualServerExWithCustomHTTPAndHTTPSListeners.HTTPSPort,
			CustomListeners: true,
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithCustomHTTPAndHTTPSListeners,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithCustomHttpListener(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithCustomHTTPListener.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithCustomHTTPListener.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithCustomHTTPListener.VirtualServer.Namespace,
			VSName:          virtualServerExWithCustomHTTPListener.VirtualServer.Name,
			DisableIPV6:     true,
			HTTPPort:        virtualServerExWithCustomHTTPListener.HTTPPort,
			HTTPSPort:       virtualServerExWithCustomHTTPListener.HTTPSPort,
			CustomListeners: true,
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithCustomHTTPListener,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithCustomHttpsListener(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithCustomHTTPSListener.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithCustomHTTPSListener.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithCustomHTTPSListener.VirtualServer.Namespace,
			VSName:          virtualServerExWithCustomHTTPSListener.VirtualServer.Name,
			DisableIPV6:     true,
			HTTPPort:        virtualServerExWithCustomHTTPSListener.HTTPPort,
			HTTPSPort:       virtualServerExWithCustomHTTPSListener.HTTPSPort,
			CustomListeners: true,
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithCustomHTTPSListener,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithCustomHttpAndHttpsIPListeners(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithCustomHTTPAndHTTPSIPListeners.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithCustomHTTPAndHTTPSIPListeners.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithCustomHTTPAndHTTPSIPListeners.VirtualServer.Namespace,
			VSName:          virtualServerExWithCustomHTTPAndHTTPSIPListeners.VirtualServer.Name,
			DisableIPV6:     false,
			HTTPPort:        virtualServerExWithCustomHTTPAndHTTPSIPListeners.HTTPPort,
			HTTPSPort:       virtualServerExWithCustomHTTPAndHTTPSIPListeners.HTTPSPort,
			HTTPIPv4:        virtualServerExWithCustomHTTPAndHTTPSIPListeners.HTTPIPv4,
			HTTPIPv6:        virtualServerExWithCustomHTTPAndHTTPSIPListeners.HTTPIPv6,
			HTTPSIPv4:       virtualServerExWithCustomHTTPAndHTTPSIPListeners.HTTPSIPv4,
			HTTPSIPv6:       virtualServerExWithCustomHTTPAndHTTPSIPListeners.HTTPSIPv6,
			CustomListeners: true,
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: false},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithCustomHTTPAndHTTPSIPListeners,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithCustomHttpIPListener(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithCustomHTTPIPListener.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithCustomHTTPIPListener.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithCustomHTTPIPListener.VirtualServer.Namespace,
			VSName:          virtualServerExWithCustomHTTPIPListener.VirtualServer.Name,
			DisableIPV6:     false,
			HTTPPort:        virtualServerExWithCustomHTTPIPListener.HTTPPort,
			HTTPSPort:       virtualServerExWithCustomHTTPIPListener.HTTPSPort,
			HTTPIPv4:        virtualServerExWithCustomHTTPIPListener.HTTPIPv4,
			HTTPIPv6:        virtualServerExWithCustomHTTPIPListener.HTTPIPv6,
			HTTPSIPv4:       virtualServerExWithCustomHTTPIPListener.HTTPSIPv4,
			HTTPSIPv6:       virtualServerExWithCustomHTTPIPListener.HTTPSIPv6,
			CustomListeners: true,
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: false},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithCustomHTTPIPListener,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithCustomHttpsIPListener(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithCustomHTTPSIPListener.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithCustomHTTPSIPListener.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithCustomHTTPSIPListener.VirtualServer.Namespace,
			VSName:          virtualServerExWithCustomHTTPSIPListener.VirtualServer.Name,
			DisableIPV6:     false,
			HTTPPort:        virtualServerExWithCustomHTTPSIPListener.HTTPPort,
			HTTPSPort:       virtualServerExWithCustomHTTPSIPListener.HTTPSPort,
			HTTPIPv4:        virtualServerExWithCustomHTTPSIPListener.HTTPIPv4,
			HTTPIPv6:        virtualServerExWithCustomHTTPSIPListener.HTTPIPv6,
			HTTPSIPv4:       virtualServerExWithCustomHTTPSIPListener.HTTPSIPv4,
			HTTPSIPv6:       virtualServerExWithCustomHTTPSIPListener.HTTPSIPv6,
			CustomListeners: true,
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: false},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithCustomHTTPSIPListener,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithNilListener(t *testing.T) {
	t.Parallel()

	expected := version2.VirtualServerConfig{
		Upstreams:     nil,
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      virtualServerExWithNilListener.VirtualServer.Spec.Host,
			StatusZone:      virtualServerExWithNilListener.VirtualServer.Spec.Host,
			VSNamespace:     virtualServerExWithNilListener.VirtualServer.Namespace,
			VSName:          virtualServerExWithNilListener.VirtualServer.Name,
			DisableIPV6:     true,
			HTTPPort:        virtualServerExWithNilListener.HTTPPort,
			HTTPSPort:       virtualServerExWithNilListener.HTTPSPort,
			CustomListeners: false,
			ProxyProtocol:   true,
			ServerTokens:    baseCfgParams.ServerTokens,
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations:       nil,
		},
	}

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{DisableIPV6: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(
		&virtualServerExWithNilListener,
		nil,
		nil)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigIPV6Disabled(t *testing.T) {
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
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.40:80",
			},
		},
	}

	baseCfgParams := ConfigParams{Context: context.Background()}

	expected := version2.VirtualServerConfig{
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
						Address: "10.0.0.40:80",
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
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:  "cafe.example.com",
			StatusZone:  "cafe.example.com",
			VSNamespace: "default",
			VSName:      "cafe",
			DisableIPV6: true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
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
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
				},
			},
		},
	}

	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		isPlus,
		isResolverConfigured,
		&StaticConfigParams{DisableIPV6: true},
		isWildcardEnabled,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigGrpcErrorPageWarning(t *testing.T) {
	t.Parallel()
	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				TLS: &conf_v1.TLS{
					Secret: "",
				},
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "grpc-app-1",
						Service: "grpc-svc",
						Port:    50051,
						Type:    "grpc",
						TLS: conf_v1.UpstreamTLS{
							Enable: true,
						},
					},
					{
						Name:    "grpc-app-2",
						Service: "grpc-svc2",
						Port:    50052,
						Type:    "grpc",
						TLS: conf_v1.UpstreamTLS{
							Enable: true,
						},
					},
					{
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/grpc-errorpage",
						Action: &conf_v1.Action{
							Pass: "grpc-app-1",
						},
						ErrorPages: []conf_v1.ErrorPage{
							{
								Codes: []int{404, 405},
								Return: &conf_v1.ErrorPageReturn{
									ActionReturn: conf_v1.ActionReturn{
										Code: 200,
										Type: "text/plain",
										Body: "All Good",
									},
								},
							},
						},
					},
					{
						Path: "/grpc-matches",
						Matches: []conf_v1.Match{
							{
								Conditions: []conf_v1.Condition{
									{
										Variable: "$request_method",
										Value:    "POST",
									},
								},
								Action: &conf_v1.Action{
									Pass: "grpc-app-2",
								},
							},
						},
						Action: &conf_v1.Action{
							Pass: "tea",
						},
						ErrorPages: []conf_v1.ErrorPage{
							{
								Codes: []int{404},
								Return: &conf_v1.ErrorPageReturn{
									ActionReturn: conf_v1.ActionReturn{
										Code: 200,
										Type: "text/plain",
										Body: "Original resource not found, but success!",
									},
								},
							},
						},
					},
					{
						Path: "/grpc-splits",
						Splits: []conf_v1.Split{
							{
								Weight: 90,
								Action: &conf_v1.Action{
									Pass: "grpc-app-1",
								},
							},
							{
								Weight: 10,
								Action: &conf_v1.Action{
									Pass: "grpc-app-2",
								},
							},
						},
						ErrorPages: []conf_v1.ErrorPage{
							{
								Codes: []int{404, 405},
								Return: &conf_v1.ErrorPageReturn{
									ActionReturn: conf_v1.ActionReturn{
										Code: 200,
										Type: "text/plain",
										Body: "All Good",
									},
								},
							},
						},
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/grpc-svc:50051": {
				"10.0.0.20:80",
			},
		},
	}

	baseCfgParams := ConfigParams{
		Context: context.Background(),
		HTTP2:   true,
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "grpc-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_grpc-app-1",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
			},
			{
				Name: "vs_default_cafe_grpc-app-2",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "grpc-svc2",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "unix:/var/lib/nginx/nginx-502-server.sock",
					},
				},
			},
			{
				Name: "vs_default_cafe_tea",
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "unix:/var/lib/nginx/nginx-502-server.sock",
					},
				},
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Maps: []version2.Map{
			{
				Source:   "$request_method",
				Variable: "$vs_default_cafe_matches_0_match_0_cond_0",
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
		},
		Server: version2.Server{
			ServerName:  "cafe.example.com",
			StatusZone:  "cafe.example.com",
			VSNamespace: "default",
			VSName:      "cafe",
			SSL: &version2.SSL{
				HTTP2:          true,
				Certificate:    "/etc/nginx/secrets/wildcard",
				CertificateKey: "/etc/nginx/secrets/wildcard",
			},
			InternalRedirectLocations: []version2.InternalRedirectLocation{
				{
					Path:        "/grpc-matches",
					Destination: "$vs_default_cafe_matches_0",
				},
				{
					Path:        "/grpc-splits",
					Destination: "$vs_default_cafe_splits_0",
				},
			},
			Locations: []version2.Location{
				{
					Path:                     "/grpc-errorpage",
					ProxyPass:                "https://vs_default_cafe_grpc-app-1",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ErrorPages:               []version2.ErrorPage{{Name: "@error_page_0_0", Codes: "404 405", ResponseCode: 200}},
					ProxyInterceptErrors:     true,
					ProxySSLName:             "grpc-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "grpc-svc",
					GRPCPass:                 "grpcs://vs_default_cafe_grpc-app-1",
				},
				{
					Path:                     "/internal_location_matches_0_match_0",
					Internal:                 true,
					ProxyPass:                "https://vs_default_cafe_grpc-app-2$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					Rewrites:                 []string{"^ $request_uri break"},
					ErrorPages:               []version2.ErrorPage{{Name: "@error_page_1_0", Codes: "404", ResponseCode: 200}},
					ProxyInterceptErrors:     true,
					ProxySSLName:             "grpc-svc2.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "grpc-svc2",
					GRPCPass:                 "grpcs://vs_default_cafe_grpc-app-2",
				},
				{
					Path:                     "/internal_location_matches_0_default",
					Internal:                 true,
					ProxyPass:                "http://vs_default_cafe_tea$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					ErrorPages:               []version2.ErrorPage{{Name: "@error_page_1_0", Codes: "404", ResponseCode: 200}},
					ProxyInterceptErrors:     true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
				{
					Path:                     "/internal_location_splits_0_split_0",
					Internal:                 true,
					ProxyPass:                "https://vs_default_cafe_grpc-app-1$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             false,
					ErrorPages:               []version2.ErrorPage{{Name: "@error_page_2_0", Codes: "404 405", ResponseCode: 200}},
					ProxyInterceptErrors:     true,
					Rewrites:                 []string{"^ $request_uri break"},
					ProxySSLName:             "grpc-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "grpc-svc",
					GRPCPass:                 "grpcs://vs_default_cafe_grpc-app-1",
				},
				{
					Path:                     "/internal_location_splits_0_split_1",
					Internal:                 true,
					ProxyPass:                "https://vs_default_cafe_grpc-app-2$request_uri",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             false,
					ErrorPages:               []version2.ErrorPage{{Name: "@error_page_2_0", Codes: "404 405", ResponseCode: 200}},
					ProxyInterceptErrors:     true,
					Rewrites:                 []string{"^ $request_uri break"},
					ProxySSLName:             "grpc-svc2.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "grpc-svc2",
					GRPCPass:                 "grpcs://vs_default_cafe_grpc-app-2",
				},
			},
			ErrorPageLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return:      &version2.Return{Text: "All Good"},
				},
				{
					Name:        "@error_page_1_0",
					DefaultType: "text/plain",
					Return:      &version2.Return{Text: "Original resource not found, but success!"},
				},
				{
					Name:        "@error_page_2_0",
					DefaultType: "text/plain",
					Return:      &version2.Return{Text: "All Good"},
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
		},
	}
	expectedWarnings := Warnings{
		virtualServerEx.VirtualServer: {
			`The error page configuration for the upstream grpc-app-1 is ignored for status code(s) [404 405], which cannot be used for GRPC upstreams.`,
			`The error page configuration for the upstream grpc-app-2 is ignored for status code(s) [404], which cannot be used for GRPC upstreams.`,
			`The error page configuration for the upstream grpc-app-1 is ignored for status code(s) [404 405], which cannot be used for GRPC upstreams.`,
			`The error page configuration for the upstream grpc-app-2 is ignored for status code(s) [404 405], which cannot be used for GRPC upstreams.`,
		},
	}
	isPlus := false
	isResolverConfigured := false
	isWildcardEnabled := true
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, &StaticConfigParams{}, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("TestGenerateVirtualServerConfigGrpcErrorPageWarning() mismatch (-want +got):\n%s", diff)
	}

	if !reflect.DeepEqual(vsc.warnings, expectedWarnings) {
		t.Errorf("GenerateVirtualServerConfig() returned warnings of \n%v but expected \n%v", warnings, expectedWarnings)
	}
}

func TestGenerateVirtualServerConfigWithSpiffeCerts(t *testing.T) {
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
						Name:    "tea",
						Service: "tea-svc",
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
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
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

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "https://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
			},
		},
		SpiffeClientCerts: true,
	}

	isPlus := false
	isResolverConfigured := false
	staticConfigParams := &StaticConfigParams{TLSPassthrough: true, NginxServiceMesh: true}
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, staticConfigParams, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithInternalRoutes(t *testing.T) {
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
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
						TLS:     conf_v1.UpstreamTLS{Enable: false},
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
					},
				},
				InternalRoute: true,
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
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

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
			},
		},
		SpiffeCerts:       true,
		SpiffeClientCerts: false,
	}

	isPlus := false
	isResolverConfigured := false
	staticConfigParams := &StaticConfigParams{TLSPassthrough: true, NginxServiceMesh: true, EnableInternalRoutes: true}
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, staticConfigParams, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigWithInternalRoutesWarning(t *testing.T) {
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
						Name:    "tea",
						Service: "tea-svc",
						Port:    80,
						TLS:     conf_v1.UpstreamTLS{Enable: false},
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/",
						Action: &conf_v1.Action{
							Pass: "tea",
						},
					},
				},
				InternalRoute: true,
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
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

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
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
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			Locations: []version2.Location{
				{
					Path:                     "/",
					ProxyPass:                "http://vs_default_cafe_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "tea-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "tea-svc",
				},
			},
		},
		SpiffeCerts:       true,
		SpiffeClientCerts: true,
	}

	isPlus := false
	isResolverConfigured := false
	staticConfigParams := &StaticConfigParams{TLSPassthrough: true, NginxServiceMesh: true, EnableInternalRoutes: false}
	isWildcardEnabled := false
	vsc := newVirtualServerConfigurator(&baseCfgParams, isPlus, isResolverConfigured, staticConfigParams, isWildcardEnabled, &fakeBV)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if diff := cmp.Diff(expected, result); diff == "" {
		t.Errorf("GenerateVirtualServerConfig() should not configure internal route")
	}

	if len(warnings) != 1 {
		t.Errorf("GenerateVirtualServerConfig should return warning to enable internal routing")
	}
}

func TestGenerateVirtualServerConfigWithForeignNamespaceService(t *testing.T) {
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
						Name:    "coffee",
						Service: "coffee/coffee-svc",
						Port:    80,
					},
				},
				Routes: []conf_v1.Route{
					{
						Path: "/coffee",
						Action: &conf_v1.Action{
							Pass: "coffee",
						},
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"coffee/coffee-svc:80": {
				"10.0.0.20:80",
			},
		},
		VirtualServerRoutes: []*conf_v1.VirtualServerRoute{},
	}

	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, nil)
	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", warnings)
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "coffee/coffee-svc",
					ResourceType:      "virtualserver",
					ResourceName:      "cafe",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_coffee",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.20:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations: []version2.Location{
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders: []version2.Header{
						{
							Name:  "Host",
							Value: "$host",
						},
					},
					HasKeepalive: true,
					ProxySSLName: "coffee-svc.coffee.svc",
					ServiceName:  "coffee-svc",
				},
			},
		},
		SpiffeClientCerts: false,
	}

	if !cmp.Equal(expected, result) {
		t.Error(cmp.Diff(expected, result))
	}
}

func TestGenerateVirtualServerConfigWithForeignNamespaceServiceInVSR(t *testing.T) {
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
						Path:  "/tea",
						Route: "default/tea",
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"tea/tea-svc:80": {
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
							Service: "tea/tea-svc",
							Port:    80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/tea",
							Action: &conf_v1.Action{
								Pass: "tea",
							},
						},
					},
				},
			},
		},
	}

	vsc := newVirtualServerConfigurator(&baseCfgParams, false, false, &StaticConfigParams{}, false, nil)
	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", warnings)
	}

	expected := version2.VirtualServerConfig{
		Upstreams: []version2.Upstream{
			{
				UpstreamLabels: version2.UpstreamLabels{
					Service:           "tea/tea-svc",
					ResourceType:      "virtualserverroute",
					ResourceName:      "tea",
					ResourceNamespace: "default",
				},
				Name: "vs_default_cafe_vsr_default_tea_tea",
				Servers: []version2.UpstreamServer{
					{
						Address: "10.0.0.30:80",
					},
				},
				Keepalive: 16,
			},
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			VSNamespace:     "default",
			VSName:          "cafe",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPHeader:    "X-Real-IP",
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			Locations: []version2.Location{
				{
					Path:                     "/tea",
					ProxyPass:                "http://vs_default_cafe_vsr_default_tea_tea",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders: []version2.Header{
						{
							Name:  "Host",
							Value: "$host",
						},
					},
					HasKeepalive: true,
					ProxySSLName: "tea-svc.tea.svc",
					ServiceName:  "tea-svc",
					IsVSR:        true,
					VSRName:      "tea",
					VSRNamespace: "default",
				},
			},
		},
		SpiffeClientCerts: false,
	}

	if !cmp.Equal(expected, result) {
		t.Error(cmp.Diff(expected, result))
	}
}
