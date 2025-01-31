package configs

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func createPointerFromBool(b bool) *bool {
	return &b
}

func createPointerFromInt(n int) *int {
	return &n
}

func TestVirtualServerExString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    *VirtualServerEx
		expected string
	}{
		{
			input: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "cafe",
						Namespace: "default",
					},
				},
			},
			expected: "default/cafe",
		},
		{
			input:    &VirtualServerEx{},
			expected: "VirtualServerEx has no VirtualServer",
		},
		{
			input:    nil,
			expected: "<nil>",
		},
	}

	for _, test := range tests {
		result := test.input.String()
		if result != test.expected {
			t.Errorf("VirtualServerEx.String() returned %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateEndpointsKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		serviceNamespace string
		serviceName      string
		port             uint16
		subselector      map[string]string
		expected         string
	}{
		{
			serviceNamespace: "default",
			serviceName:      "test",
			port:             80,
			subselector:      nil,
			expected:         "default/test:80",
		},
		{
			serviceNamespace: "default",
			serviceName:      "test",
			port:             80,
			subselector:      map[string]string{"version": "v1"},
			expected:         "default/test_version=v1:80",
		},
		{
			serviceNamespace: "default",
			serviceName:      "backup-svc",
			port:             8090,
			subselector:      nil,
			expected:         "default/backup-svc:8090",
		},
	}

	for _, test := range tests {
		result := GenerateEndpointsKey(test.serviceNamespace, test.serviceName, test.subselector, test.port)
		if result != test.expected {
			t.Errorf("GenerateEndpointsKey() returned %q but expected %q", result, test.expected)
		}
	}
}

func TestUpstreamNamerForVirtualServer(t *testing.T) {
	t.Parallel()
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServer(&virtualServer)
	upstream := "test"

	expected := "vs_default_cafe_test"

	result := upstreamNamer.GetNameForUpstream(upstream)
	if result != expected {
		t.Errorf("GetNameForUpstream() returned %q but expected %q", result, expected)
	}
}

func TestUpstreamNamerForVirtualServerRoute(t *testing.T) {
	t.Parallel()
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	virtualServerRoute := conf_v1.VirtualServerRoute{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "coffee",
			Namespace: "default",
		},
	}
	upstreamNamer := NewUpstreamNamerForVirtualServerRoute(&virtualServer, &virtualServerRoute)
	upstream := "test"

	expected := "vs_default_cafe_vsr_default_coffee_test"

	result := upstreamNamer.GetNameForUpstream(upstream)
	if result != expected {
		t.Errorf("GetNameForUpstream() returned %q but expected %q", result, expected)
	}
}

func TestVariableNamerSafeNsName(t *testing.T) {
	t.Parallel()
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe-test",
			Namespace: "default",
		},
	}

	expected := "default_cafe_test"

	variableNamer := NewVSVariableNamer(&virtualServer)

	if variableNamer.safeNsName != expected {
		t.Errorf(
			"newVariableNamer() returned variableNamer with safeNsName=%q but expected %q",
			variableNamer.safeNsName,
			expected,
		)
	}
}

func TestVariableNamer(t *testing.T) {
	t.Parallel()
	virtualServer := conf_v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
	}
	variableNamer := NewVSVariableNamer(&virtualServer)

	// GetNameForSplitClientVariable()
	index := 0

	expected := "$vs_default_cafe_splits_0"

	result := variableNamer.GetNameForSplitClientVariable(index)
	if result != expected {
		t.Errorf("GetNameForSplitClientVariable() returned %q but expected %q", result, expected)
	}

	// GetNameForVariableForMatchesRouteMap()
	matchesIndex := 1
	matchIndex := 2
	conditionIndex := 3

	expected = "$vs_default_cafe_matches_1_match_2_cond_3"

	result = variableNamer.GetNameForVariableForMatchesRouteMap(matchesIndex, matchIndex, conditionIndex)
	if result != expected {
		t.Errorf("GetNameForVariableForMatchesRouteMap() returned %q but expected %q", result, expected)
	}

	// GetNameForVariableForMatchesRouteMainMap()
	matchesIndex = 2

	expected = "$vs_default_cafe_matches_2"

	result = variableNamer.GetNameForVariableForMatchesRouteMainMap(matchesIndex)
	if result != expected {
		t.Errorf("GetNameForVariableForMatchesRouteMainMap() returned %q but expected %q", result, expected)
	}
}

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

// createPointerFromUInt16 is a helper that takes a uint16
// and returns a pointer to the value. It is used for testing
// BackupService configuration for Virtual and Transport Servers.
func createPointerFromUInt16(n uint16) *uint16 {
	return &n
}

// vsEx returns Virtual Server Ex config struct.
// It's safe to modify returned config for parallel test execution.
func vsEx() VirtualServerEx {
	return VirtualServerEx{
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
		Endpoints: map[string][]string{},
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
}

func TestGenerateVirtualServerConfigWithBackupForNGINXPlus(t *testing.T) {
	t.Parallel()

	virtualServerEx := vsEx()
	virtualServerEx.VirtualServer.Spec.Upstreams[2].LBMethod = "least_conn"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].Backup = "backup-svc"
	virtualServerEx.VirtualServer.Spec.Upstreams[2].BackupPort = createPointerFromUInt16(8090)
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
	virtualServerEx.VirtualServer.Spec.Upstreams[2].BackupPort = createPointerFromUInt16(8090)
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
			VSNamespace:     virtualServerExWithCustomHTTPAndHTTPSListeners.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithCustomHTTPAndHTTPSListeners.VirtualServer.ObjectMeta.Name,
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
			VSNamespace:     virtualServerExWithCustomHTTPListener.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithCustomHTTPListener.VirtualServer.ObjectMeta.Name,
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
			VSNamespace:     virtualServerExWithCustomHTTPSListener.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithCustomHTTPSListener.VirtualServer.ObjectMeta.Name,
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
			VSNamespace:     virtualServerExWithCustomHTTPAndHTTPSIPListeners.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithCustomHTTPAndHTTPSIPListeners.VirtualServer.ObjectMeta.Name,
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
			VSNamespace:     virtualServerExWithCustomHTTPIPListener.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithCustomHTTPIPListener.VirtualServer.ObjectMeta.Name,
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
			VSNamespace:     virtualServerExWithCustomHTTPSIPListener.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithCustomHTTPSIPListener.VirtualServer.ObjectMeta.Name,
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
			VSNamespace:     virtualServerExWithNilListener.VirtualServer.ObjectMeta.Namespace,
			VSName:          virtualServerExWithNilListener.VirtualServer.ObjectMeta.Name,
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

func TestGenerateVirtualServerConfigJWKSPolicy(t *testing.T) {
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
						Name: "jwt-policy",
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
								Name: "jwt-policy-route",
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
								Name: "jwt-policy-route",
							},
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/jwt-policy": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwt-policy",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					JWTAuth: &conf_v1.JWTAuth{
						Realm:    "Spec Realm API",
						JwksURI:  "https://idp.spec.example.com:443/spec-keys",
						KeyCache: "1h",
					},
				},
			},
			"default/jwt-policy-route": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwt-policy-route",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					JWTAuth: &conf_v1.JWTAuth{
						Realm:    "Route Realm API",
						JwksURI:  "http://idp.route.example.com:80/route-keys",
						KeyCache: "1h",
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
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			JWTAuthList: map[string]*version2.JWTAuth{
				"default/jwt-policy": {
					Key:      "default/jwt-policy",
					Realm:    "Spec Realm API",
					KeyCache: "1h",
					JwksURI: version2.JwksURI{
						JwksScheme: "https",
						JwksHost:   "idp.spec.example.com",
						JwksPort:   "443",
						JwksPath:   "/spec-keys",
					},
				},
				"default/jwt-policy-route": {
					Key:      "default/jwt-policy-route",
					Realm:    "Route Realm API",
					KeyCache: "1h",
					JwksURI: version2.JwksURI{
						JwksScheme: "http",
						JwksHost:   "idp.route.example.com",
						JwksPort:   "80",
						JwksPath:   "/route-keys",
					},
				},
			},
			JWTAuth: &version2.JWTAuth{
				Key:      "default/jwt-policy",
				Realm:    "Spec Realm API",
				KeyCache: "1h",
				JwksURI: version2.JwksURI{
					JwksScheme: "https",
					JwksHost:   "idp.spec.example.com",
					JwksPort:   "443",
					JwksPath:   "/spec-keys",
				},
			},
			JWKSAuthEnabled: true,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
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
					JWTAuth: &version2.JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						KeyCache: "1h",
						JwksURI: version2.JwksURI{
							JwksScheme: "http",
							JwksHost:   "idp.route.example.com",
							JwksPort:   "80",
							JwksPath:   "/route-keys",
						},
					},
				},
				{
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					JWTAuth: &version2.JWTAuth{
						Key:      "default/jwt-policy-route",
						Realm:    "Route Realm API",
						KeyCache: "1h",
						JwksURI: version2.JwksURI{
							JwksScheme: "http",
							JwksHost:   "idp.route.example.com",
							JwksPort:   "80",
							JwksPath:   "/route-keys",
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

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
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

func TestGenerateVirtualServerConfigAPIKeyPolicy(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		SecretRefs: map[string]*secrets.SecretReference{
			"default/api-key-secret-spec": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"clientSpec": []byte("password"),
					},
				},
			},
			"default/api-key-secret-route": {
				Secret: &api_v1.Secret{
					Type: secrets.SecretTypeAPIKey,
					Data: map[string][]byte{
						"clientRoute": []byte("password2"),
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
						Name: "api-key-policy-spec",
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
						Policies: []conf_v1.PolicyReference{
							{
								Name: "api-key-policy-route",
							},
						},
					},
				},
			},
		},
		Policies: map[string]*conf_v1.Policy{
			"default/api-key-policy-spec": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-spec",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Header: []string{"X-API-Key"},
							Query:  []string{"apikey"},
						},
						ClientSecret: "api-key-secret-spec",
					},
				},
			},
			"default/api-key-policy-route": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-route",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Query: []string{"api-key"},
						},
						ClientSecret: "api-key-secret-route",
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
				Source:   "$apikey_auth_token",
				Variable: "$apikey_auth_client_name_default_cafe_api_key_policy_route",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: `""`,
					},
					{
						Value:  `"6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4"`,
						Result: `"clientRoute"`,
					},
				},
			},
			{
				Source:   "$apikey_auth_token",
				Variable: "$apikey_auth_client_name_default_cafe_api_key_policy_spec",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: `""`,
					},
					{
						Value:  `"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"`,
						Result: `"clientSpec"`,
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
		},
		HTTPSnippets:  []string{},
		LimitReqZones: []version2.LimitReqZone{},
		Server: version2.Server{
			JWTAuthList:     nil,
			JWTAuth:         nil,
			JWKSAuthEnabled: false,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			APIKeyEnabled:   true,
			APIKey: &version2.APIKey{
				Header:  []string{"X-API-Key"},
				Query:   []string{"apikey"},
				MapName: "apikey_auth_client_name_default_cafe_api_key_policy_spec",
			},
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
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
					ProxySSLName:             "coffee-svc.default.svc",
					ProxyPassRequestHeaders:  true,
					ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
					ServiceName:              "coffee-svc",
					APIKey: &version2.APIKey{
						MapName: "apikey_auth_client_name_default_cafe_api_key_policy_route",
						Query:   []string{"api-key"},
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

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	sort.Slice(result.Maps, func(i, j int) bool {
		return result.Maps[i].Variable < result.Maps[j].Variable
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGenerateVirtualServerConfigAPIKeyClientMaps(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		SecretRefs: map[string]*secrets.SecretReference{
			"default/api-key-secret-1": {
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
		Policies: map[string]*conf_v1.Policy{
			"default/api-key-policy-1": {
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-policy-1",
					Namespace: "default",
				},
				Spec: conf_v1.PolicySpec{
					APIKey: &conf_v1.APIKey{
						SuppliedIn: &conf_v1.SuppliedIn{
							Header: []string{"X-API-Key"},
							Query:  []string{"apikey"},
						},
						ClientSecret: "api-key-secret-1",
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
							Header: []string{"api-key"},
						},
						ClientSecret: "api-key-secret-2",
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

	expectedAPIKey1 := &version2.APIKey{
		MapName: "apikey_auth_client_name_default_cafe_api_key_policy_1",
		Header:  []string{"X-API-Key"},
		Query:   []string{"apikey"},
	}

	expectedAPIKey2 := &version2.APIKey{
		MapName: "apikey_auth_client_name_default_cafe_api_key_policy_2",
		Header:  []string{"api-key"},
	}

	expectedMap1 := version2.Map{
		Source:   "$apikey_auth_token",
		Variable: "$apikey_auth_client_name_default_cafe_api_key_policy_1",
		Parameters: []version2.Parameter{
			{
				Value:  "default",
				Result: `""`,
			},
			{
				Value:  `"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"`,
				Result: `"client1"`,
			},
		},
	}

	expectedMap2 := version2.Map{
		Source:   "$apikey_auth_token",
		Variable: "$apikey_auth_client_name_default_cafe_api_key_policy_2",
		Parameters: []version2.Parameter{
			{
				Value:  "default",
				Result: `""`,
			},
			{
				Value:  `"6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4"`,
				Result: `"client2"`,
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

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	tests := []struct {
		specPolicies         []conf_v1.PolicyReference
		route1Policies       []conf_v1.PolicyReference
		route2Policies       []conf_v1.PolicyReference
		expectedSpecAPIKey   *version2.APIKey
		expectedRoute1APIKey *version2.APIKey
		expectedRoute2APIKey *version2.APIKey
		expectedMapList      []version2.Map
		name                 string
	}{
		{
			specPolicies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-1",
				},
			},
			route1Policies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-2",
				},
			},
			route2Policies:       nil,
			expectedSpecAPIKey:   expectedAPIKey1,
			expectedRoute1APIKey: expectedAPIKey2,
			expectedRoute2APIKey: nil,
			expectedMapList:      []version2.Map{expectedMap1, expectedMap2},
			name:                 "policy in spec, route 1 and route 2",
		},
		{
			specPolicies: nil,
			route1Policies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-1",
				},
			},
			route2Policies:     nil,
			expectedSpecAPIKey: nil,

			expectedRoute1APIKey: expectedAPIKey1,
			expectedRoute2APIKey: nil,
			expectedMapList:      []version2.Map{expectedMap1},
			name:                 "policy in route 1 only",
		},
		{
			specPolicies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-2",
				},
			},
			route1Policies:       nil,
			route2Policies:       nil,
			expectedSpecAPIKey:   expectedAPIKey2,
			expectedRoute1APIKey: nil,
			expectedRoute2APIKey: nil,
			expectedMapList:      []version2.Map{expectedMap2},
			name:                 "policy in spec only",
		},
		{
			specPolicies:         nil,
			route1Policies:       nil,
			route2Policies:       nil,
			expectedRoute1APIKey: nil,
			expectedRoute2APIKey: nil,
			expectedMapList:      nil,
			name:                 "no policies",
		},
	}

	invalidTests := []struct {
		specPolicies     []conf_v1.PolicyReference
		teaPolicies      []conf_v1.PolicyReference
		coffeePolicies   []conf_v1.PolicyReference
		expectedMapList  []version2.Map
		expectedWarnings Warnings
		name             string
	}{
		{
			specPolicies: []conf_v1.PolicyReference{
				{
					Name: "api-key-policy-3",
				},
			},
			coffeePolicies: nil,
			teaPolicies:    nil,
			// expectedTeaPolicy:    expectedAPIKey2,
			// expectedCoffeePolicy: expectedAPIKey1,
			expectedMapList: nil,
			expectedWarnings: Warnings{
				nil: {
					"Policy default/api-key-policy-3 is missing or invalid",
				},
			},
			name: "policy does not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			virtualServerEx.VirtualServer.Spec.Policies = tc.specPolicies
			virtualServerEx.VirtualServer.Spec.Routes[0].Policies = tc.route1Policies
			virtualServerEx.VirtualServer.Spec.Routes[1].Policies = tc.route2Policies
			vsConf, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

			sort.Slice(vsConf.Maps, func(i, j int) bool {
				return vsConf.Maps[i].Variable < vsConf.Maps[j].Variable
			})

			if !cmp.Equal(tc.expectedSpecAPIKey, vsConf.Server.APIKey) {
				t.Error(cmp.Diff(tc.expectedSpecAPIKey, vsConf.Server.APIKey))
			}

			if !cmp.Equal(tc.expectedRoute1APIKey, vsConf.Server.Locations[0].APIKey) {
				t.Error(cmp.Diff(tc.expectedRoute1APIKey, vsConf.Server.Locations[0].APIKey))
			}

			if !cmp.Equal(tc.expectedRoute2APIKey, vsConf.Server.Locations[1].APIKey) {
				t.Error(cmp.Diff(tc.expectedRoute2APIKey, vsConf.Server.Locations[1].APIKey))
			}

			if !cmp.Equal(tc.expectedMapList, vsConf.Maps) {
				t.Error(cmp.Diff(tc.expectedMapList, vsConf.Maps))
			}

			if len(warnings) != 0 {
				t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
			}
		})

		for _, tc := range invalidTests {
			t.Run(tc.name, func(t *testing.T) {
				virtualServerEx.VirtualServer.Spec.Policies = tc.specPolicies
				virtualServerEx.VirtualServer.Spec.Routes[0].Policies = tc.teaPolicies
				virtualServerEx.VirtualServer.Spec.Routes[1].Policies = tc.coffeePolicies
				_, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

				if len(warnings) == 0 {
					t.Errorf("GenerateVirtualServerConfig() does not return the expected error %v", tc.expectedWarnings)
				}
			})
		}
	}
}

func TestGenerateVirtualServerConfigRateLimitPolicyAuthJwt(t *testing.T) {
	t.Parallel()

	dryRunOverride := true
	rejectCodeOverride := 505

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
						Name: "gold-rate-limit-policy",
					},
					{
						Name: "silver-rate-limit-policy",
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
			"default/gold-rate-limit-policy": {
				Spec: conf_v1.PolicySpec{
					RateLimit: &conf_v1.RateLimit{
						Key:        "test",
						ZoneSize:   "10M",
						Rate:       "10r/s",
						DryRun:     &dryRunOverride,
						RejectCode: &rejectCodeOverride,
						Condition: &conf_v1.RateLimitCondition{
							JWT: conf_v1.JWTCondition{
								Claim: "user_type.tier",
								Match: "gold",
							},
						},
					},
				},
			},
			"default/silver-rate-limit-policy": {
				Spec: conf_v1.PolicySpec{
					RateLimit: &conf_v1.RateLimit{
						Key:      "test",
						ZoneSize: "20M",
						Rate:     "20r/s",
						DryRun:   &dryRunOverride,
						//LogLevel:   "info",
						RejectCode: &rejectCodeOverride,
						Condition: &conf_v1.RateLimitCondition{
							JWT: conf_v1.JWTCondition{
								Claim: "user_type.tier",
								Match: "silver",
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
	}

	expected := version2.VirtualServerConfig{
		Maps:             nil,
		AuthJWTClaimSets: []version2.AuthJWTClaimSet{{Variable: "$jwt_default_cafe_user_type_tier", Claim: "user_type tier"}},

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
		},
		HTTPSnippets: []string{},
		LimitReqZones: []version2.LimitReqZone{
			{"test", "pol_rl_default_gold-rate-limit-policy_default_cafe", "10M", "10r/s"},
			{"test", "pol_rl_default_silver-rate-limit-policy_default_cafe", "20M", "20r/s"},
		},
		Server: version2.Server{
			JWTAuthList:     nil,
			JWTAuth:         nil,
			JWKSAuthEnabled: false,
			ServerName:      "cafe.example.com",
			StatusZone:      "cafe.example.com",
			ProxyProtocol:   true,
			ServerTokens:    "off",
			RealIPHeader:    "X-Real-IP",
			SetRealIPFrom:   []string{"0.0.0.0/0"},
			RealIPRecursive: true,
			Snippets:        []string{"# server snippet"},
			TLSPassthrough:  true,
			VSNamespace:     "default",
			VSName:          "cafe",
			APIKeyEnabled:   false,
			LimitReqs: []version2.LimitReq{
				{"pol_rl_default_gold-rate-limit-policy_default_cafe", 0, false, 0},
				{"pol_rl_default_silver-rate-limit-policy_default_cafe", 0, false, 0},
			},
			LimitReqOptions: version2.LimitReqOptions{
				DryRun:     true,
				LogLevel:   "error",
				RejectCode: 505,
			},
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
					Path:                     "/coffee",
					ProxyPass:                "http://vs_default_cafe_coffee",
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "0s",
					ProxyNextUpstreamTries:   0,
					HasKeepalive:             true,
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

	vsc := newVirtualServerConfigurator(
		&baseCfgParams,
		false,
		false,
		&StaticConfigParams{TLSPassthrough: true},
		false,
		&fakeBV,
	)

	result, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)

	sort.Slice(result.Maps, func(i, j int) bool {
		return result.Maps[i].Variable < result.Maps[j].Variable
	})

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("GenerateVirtualServerConfig() mismatch (-want +got):\n%s", diff)
	}

	if len(warnings) != 0 {
		t.Errorf("GenerateVirtualServerConfig returned warnings: %v", vsc.warnings)
	}
}

func TestGeneratePolicies(t *testing.T) {
	t.Parallel()
	ownerDetails := policyOwnerDetails{
		owner:          nil, // nil is OK for the unit test
		ownerNamespace: "default",
		vsNamespace:    "default",
		vsName:         "test",
	}
	mTLSCertPath := "/etc/nginx/secrets/default-ingress-mtls-secret-ca.crt"
	mTLSCrlPath := "/etc/nginx/secrets/default-ingress-mtls-secret-ca.crl"
	mTLSCertAndCrlPath := fmt.Sprintf("%s %s", mTLSCertPath, mTLSCrlPath)
	policyOpts := policyOptions{
		tls: true,
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
				Allow: []string{"127.0.0.1"},
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
				Allow: []string{"127.0.0.1"},
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
				Allow: []string{"127.0.0.1", "127.0.0.2"},
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
				RateLimit: rateLimit{
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit-policy_default_test",
						},
					},
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							ZoneName: "pol_rl_default_rateLimit-policy_default_test",
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
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
						},
					},
				},
				"default/rateLimit-policy2": {
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
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							ZoneName: "pol_rl_default_rateLimit-policy_default_test",
						},
						{
							Key:      "test2",
							ZoneSize: "20M",
							Rate:     "20r/s",
							ZoneName: "pol_rl_default_rateLimit-policy2_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "error",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit-policy_default_test",
						},
						{
							ZoneName: "pol_rl_default_rateLimit-policy2_default_test",
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
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "5r/s",
							ZoneName: "pol_rl_default_rateLimitScale-policy_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "notice",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimitScale-policy_default_test",
						},
					},
				},
			},
			msg: "rate limit reference with scale",
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
				JWTAuth: jwtAuth{
					Auth: &version2.JWTAuth{
						Key:   "default/jwt-policy-2",
						Realm: "My Test API",
						JwksURI: version2.JwksURI{
							JwksScheme: "https",
							JwksHost:   "idp.example.com",
							JwksPort:   "443",
							JwksPath:   "/keys",
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
				JWTAuth: jwtAuth{
					Auth: &version2.JWTAuth{
						Key:   "default/jwt-policy-2",
						Realm: "My Test API",
						JwksURI: version2.JwksURI{
							JwksScheme: "https",
							JwksHost:   "idp.example.com",
							JwksPort:   "",
							JwksPath:   "/keys",
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
				OIDC: true,
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
			expected: policiesCfg{
				WAF: &version2.WAF{
					Enable:              "on",
					ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
					ApSecurityLogEnable: true,
					ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf syslog:server=127.0.0.1:514"},
				},
			},
			msg: "WAF reference",
		},
	}

	vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, false, false, &StaticConfigParams{}, false, &fakeBV)
	// required to test the scaling of the ratelimit
	vsc.IngressControllerReplicas = 2

	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			result := vsc.generatePolicies(ownerDetails, tc.policyRefs, tc.policies, tc.context, policyOpts)
			result.BundleValidator = nil

			if !cmp.Equal(tc.expected, result) {
				t.Error(cmp.Diff(tc.expected, result))
			}
			if len(vsc.warnings) > 0 {
				t.Errorf("generatePolicies() returned unexpected warnings %v for the case of %s", vsc.warnings, tc.msg)
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
			vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, false, false, &StaticConfigParams{}, false, &fakeBV)
			res := vsc.generatePolicies(ownerDetails, tc.policyRefs, tc.policies, tc.context, policyOptions{apResources: &appProtectResourcesForVS{}})
			res.BundleValidator = nil
			if !cmp.Equal(tc.want, res) {
				t.Error(cmp.Diff(tc.want, res))
			}
		})
	}
}

func TestGeneratePoliciesFails(t *testing.T) {
	t.Parallel()
	ownerDetails := policyOwnerDetails{
		owner:          nil, // nil is OK for the unit test
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
				Allow: []string{"127.0.0.1"},
				Deny:  []string{"127.0.0.2"},
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
					Spec: conf_v1.PolicySpec{
						RateLimit: &conf_v1.RateLimit{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
						},
					},
				},
				"default/rateLimit-policy2": {
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
				RateLimit: rateLimit{
					Zones: []version2.LimitReqZone{
						{
							Key:      "test",
							ZoneSize: "10M",
							Rate:     "10r/s",
							ZoneName: "pol_rl_default_rateLimit-policy_default_test",
						},
						{
							Key:      "test2",
							ZoneSize: "20M",
							Rate:     "20r/s",
							ZoneName: "pol_rl_default_rateLimit-policy2_default_test",
						},
					},
					Options: version2.LimitReqOptions{
						LogLevel:   "error",
						RejectCode: 503,
					},
					Reqs: []version2.LimitReq{
						{
							ZoneName: "pol_rl_default_rateLimit-policy_default_test",
						},
						{
							ZoneName: "pol_rl_default_rateLimit-policy2_default_test",
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
				OIDC: true,
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
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, false, false, &StaticConfigParams{}, false, &fakeBV)

			if test.oidcPolCfg != nil {
				vsc.oidcPolCfg = test.oidcPolCfg
			}

			result := vsc.generatePolicies(ownerDetails, test.policyRefs, test.policies, test.context, test.policyOpts)
			result.BundleValidator = nil
			if diff := cmp.Diff(test.expected, result); diff != "" {
				t.Errorf("generatePolicies() '%v' mismatch (-want +got):\n%s", test.msg, diff)
			}
			if !reflect.DeepEqual(vsc.warnings, test.expectedWarnings) {
				t.Errorf(
					"generatePolicies() returned warnings of \n%v but expected \n%v for the case of %s",
					vsc.warnings,
					test.expectedWarnings,
					test.msg,
				)
			}
			if diff := cmp.Diff(test.expectedOidc.oidc, vsc.oidcPolCfg.oidc); diff != "" {
				t.Errorf("generatePolicies() '%v' mismatch (-want +got):\n%s", test.msg, diff)
			}
			if diff := cmp.Diff(test.expectedOidc.key, vsc.oidcPolCfg.key); diff != "" {
				t.Errorf("generatePolicies() '%v' mismatch (-want +got):\n%s", test.msg, diff)
			}
		})
	}
}

func TestRemoveDuplicateLimitReqZones(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rlz      []version2.LimitReqZone
		expected []version2.LimitReqZone
	}{
		{
			rlz: []version2.LimitReqZone{
				{ZoneName: "test"},
				{ZoneName: "test"},
				{ZoneName: "test2"},
				{ZoneName: "test3"},
			},
			expected: []version2.LimitReqZone{
				{ZoneName: "test"},
				{ZoneName: "test2"},
				{ZoneName: "test3"},
			},
		},
		{
			rlz: []version2.LimitReqZone{
				{ZoneName: "test"},
				{ZoneName: "test"},
				{ZoneName: "test2"},
				{ZoneName: "test3"},
				{ZoneName: "test3"},
			},
			expected: []version2.LimitReqZone{
				{ZoneName: "test"},
				{ZoneName: "test2"},
				{ZoneName: "test3"},
			},
		},
	}
	for _, test := range tests {
		result := removeDuplicateLimitReqZones(test.rlz)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("removeDuplicateLimitReqZones() returned \n%v, but expected \n%v", result, test.expected)
		}
	}
}

// TODO: write test for removeDuplicateAuthJWTClaimSets
func TestRemoveDuplicateAuthJWTClaimSets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ajcs     []version2.AuthJWTClaimSet
		expected []version2.AuthJWTClaimSet
	}{
		{
			ajcs: []version2.AuthJWTClaimSet{
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
			},
			expected: []version2.AuthJWTClaimSet{
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
			},
		},
		{
			ajcs: []version2.AuthJWTClaimSet{
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
			},
			expected: []version2.AuthJWTClaimSet{
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
			},
		},
		{
			ajcs: []version2.AuthJWTClaimSet{
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
				{
					Variable: "$jwt_default_webapp_user_group_type",
				},
			},
			expected: []version2.AuthJWTClaimSet{
				{
					Variable: "$jwt_default_webapp_consumer_group_type",
				},
				{
					Variable: "$jwt_default_webapp_user_group_type",
				},
			},
		},
	}
	for _, test := range tests {
		result := removeDuplicateAuthJWTClaimSets(test.ajcs)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("removeDuplicateAuthJWTClaimSets() returned \n%v, but expected \n%v", result, test.expected)
		}
	}
}

func TestAddPoliciesCfgToLocations(t *testing.T) {
	t.Parallel()
	cfg := policiesCfg{
		Allow: []string{"127.0.0.1"},
		Deny:  []string{"127.0.0.2"},
		ErrorReturn: &version2.Return{
			Code: 400,
		},
	}

	locations := []version2.Location{
		{
			Path: "/",
		},
	}

	expectedLocations := []version2.Location{
		{
			Path:  "/",
			Allow: []string{"127.0.0.1"},
			Deny:  []string{"127.0.0.2"},
			PoliciesErrorReturn: &version2.Return{
				Code: 400,
			},
		},
	}

	addPoliciesCfgToLocations(cfg, locations)
	if !reflect.DeepEqual(locations, expectedLocations) {
		t.Errorf("addPoliciesCfgToLocations() returned \n%+v but expected \n%+v", locations, expectedLocations)
	}
}

func TestGenerateUpstream(t *testing.T) {
	t.Parallel()
	name := "test-upstream"
	upstream := conf_v1.Upstream{Service: name, Port: 80}
	endpoints := []string{
		"192.168.10.10:8080",
	}
	backupEndpoints := []string{
		"backup.service.svc.test.corp.local:8080",
	}
	cfgParams := ConfigParams{
		Context:          context.Background(),
		LBMethod:         "random",
		MaxFails:         1,
		MaxConns:         0,
		FailTimeout:      "10s",
		Keepalive:        21,
		UpstreamZoneSize: "256k",
	}

	expected := version2.Upstream{
		Name: "test-upstream",
		UpstreamLabels: version2.UpstreamLabels{
			Service: "test-upstream",
		},
		Servers: []version2.UpstreamServer{
			{
				Address: "192.168.10.10:8080",
			},
		},
		MaxFails:         1,
		MaxConns:         0,
		FailTimeout:      "10s",
		LBMethod:         "random",
		Keepalive:        21,
		UpstreamZoneSize: "256k",
		BackupServers: []version2.UpstreamServer{
			{
				Address: "backup.service.svc.test.corp.local:8080",
			},
		},
	}

	vsc := newVirtualServerConfigurator(&cfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)
	result := vsc.generateUpstream(nil, name, upstream, false, endpoints, backupEndpoints)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("generateUpstream() returned %v but expected %v", result, expected)
	}

	if len(vsc.warnings) != 0 {
		t.Errorf("generateUpstream returned warnings for %v", upstream)
	}
}

func TestGenerateUpstreamWithKeepalive(t *testing.T) {
	t.Parallel()
	name := "test-upstream"
	noKeepalive := 0
	keepalive := 32
	endpoints := []string{
		"192.168.10.10:8080",
	}

	tests := []struct {
		upstream  conf_v1.Upstream
		cfgParams *ConfigParams
		expected  version2.Upstream
		msg       string
	}{
		{
			conf_v1.Upstream{Keepalive: &keepalive, Service: name, Port: 80},
			&ConfigParams{Keepalive: 21},
			version2.Upstream{
				Name: "test-upstream",
				UpstreamLabels: version2.UpstreamLabels{
					Service: "test-upstream",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "192.168.10.10:8080",
					},
				},
				Keepalive: 32,
			},
			"upstream keepalive set, configparam set",
		},
		{
			conf_v1.Upstream{Service: name, Port: 80},
			&ConfigParams{Keepalive: 21},
			version2.Upstream{
				Name: "test-upstream",
				UpstreamLabels: version2.UpstreamLabels{
					Service: "test-upstream",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "192.168.10.10:8080",
					},
				},
				Keepalive: 21,
			},
			"upstream keepalive not set, configparam set",
		},
		{
			conf_v1.Upstream{Keepalive: &noKeepalive, Service: name, Port: 80},
			&ConfigParams{Keepalive: 21},
			version2.Upstream{
				Name: "test-upstream",
				UpstreamLabels: version2.UpstreamLabels{
					Service: "test-upstream",
				},
				Servers: []version2.UpstreamServer{
					{
						Address: "192.168.10.10:8080",
					},
				},
			},
			"upstream keepalive set to 0, configparam set",
		},
	}

	for _, test := range tests {
		vsc := newVirtualServerConfigurator(test.cfgParams, false, false, &StaticConfigParams{}, false, &fakeBV)
		result := vsc.generateUpstream(nil, name, test.upstream, false, endpoints, nil)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateUpstream() returned %v but expected %v for the case of %v", result, test.expected, test.msg)
		}

		if len(vsc.warnings) != 0 {
			t.Errorf("generateUpstream() returned warnings for %v", test.upstream)
		}
	}
}

func TestGenerateUpstreamForExternalNameService(t *testing.T) {
	t.Parallel()
	name := "test-upstream"
	endpoints := []string{"example.com"}
	upstream := conf_v1.Upstream{Service: name}
	cfgParams := ConfigParams{Context: context.Background()}

	expected := version2.Upstream{
		Name: name,
		UpstreamLabels: version2.UpstreamLabels{
			Service: "test-upstream",
		},
		Servers: []version2.UpstreamServer{
			{
				Address: "example.com",
			},
		},
		Resolve: true,
	}

	vsc := newVirtualServerConfigurator(&cfgParams, true, true, &StaticConfigParams{}, false, &fakeBV)
	result := vsc.generateUpstream(nil, name, upstream, true, endpoints, nil)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("generateUpstream() returned %v but expected %v", result, expected)
	}

	if len(vsc.warnings) != 0 {
		t.Errorf("generateUpstream() returned warnings for %v", upstream)
	}
}

func TestGenerateUpstreamWithNTLM(t *testing.T) {
	t.Parallel()
	name := "test-upstream"
	upstream := conf_v1.Upstream{Service: name, Port: 80, NTLM: true}
	endpoints := []string{
		"192.168.10.10:8080",
	}
	cfgParams := ConfigParams{
		Context:          context.Background(),
		LBMethod:         "random",
		MaxFails:         1,
		MaxConns:         0,
		FailTimeout:      "10s",
		Keepalive:        21,
		UpstreamZoneSize: "256k",
	}

	expected := version2.Upstream{
		Name: "test-upstream",
		UpstreamLabels: version2.UpstreamLabels{
			Service: "test-upstream",
		},
		Servers: []version2.UpstreamServer{
			{
				Address: "192.168.10.10:8080",
			},
		},
		MaxFails:         1,
		MaxConns:         0,
		FailTimeout:      "10s",
		LBMethod:         "random",
		Keepalive:        21,
		UpstreamZoneSize: "256k",
		NTLM:             true,
	}

	vsc := newVirtualServerConfigurator(&cfgParams, true, false, &StaticConfigParams{}, false, &fakeBV)
	result := vsc.generateUpstream(nil, name, upstream, false, endpoints, nil)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("generateUpstream() returned %v but expected %v", result, expected)
	}

	if len(vsc.warnings) != 0 {
		t.Errorf("generateUpstream returned warnings for %v", upstream)
	}
}

func TestGenerateProxyPass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tlsEnabled   bool
		upstreamName string
		internal     bool
		expected     string
	}{
		{
			tlsEnabled:   false,
			upstreamName: "test-upstream",
			internal:     false,
			expected:     "http://test-upstream",
		},
		{
			tlsEnabled:   true,
			upstreamName: "test-upstream",
			internal:     false,
			expected:     "https://test-upstream",
		},
		{
			tlsEnabled:   false,
			upstreamName: "test-upstream",
			internal:     true,
			expected:     "http://test-upstream$request_uri",
		},
		{
			tlsEnabled:   true,
			upstreamName: "test-upstream",
			internal:     true,
			expected:     "https://test-upstream$request_uri",
		},
	}

	for _, test := range tests {
		result := generateProxyPass(test.tlsEnabled, test.upstreamName, test.internal, nil)
		if result != test.expected {
			t.Errorf("generateProxyPass(%v, %v, %v) returned %v but expected %v", test.tlsEnabled, test.upstreamName, test.internal, result, test.expected)
		}
	}
}

func TestGenerateProxyPassProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstream conf_v1.Upstream
		expected string
	}{
		{
			upstream: conf_v1.Upstream{},
			expected: "http",
		},
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: true,
				},
			},
			expected: "https",
		},
	}

	for _, test := range tests {
		result := generateProxyPassProtocol(test.upstream.TLS.Enable)
		if result != test.expected {
			t.Errorf("generateProxyPassProtocol(%v) returned %v but expected %v", test.upstream.TLS.Enable, result, test.expected)
		}
	}
}

func TestGenerateGRPCPass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		grpcEnabled  bool
		tlsEnabled   bool
		upstreamName string
		expected     string
	}{
		{
			grpcEnabled:  false,
			tlsEnabled:   false,
			upstreamName: "test-upstream",
			expected:     "",
		},
		{
			grpcEnabled:  true,
			tlsEnabled:   false,
			upstreamName: "test-upstream",
			expected:     "grpc://test-upstream",
		},
		{
			grpcEnabled:  true,
			tlsEnabled:   true,
			upstreamName: "test-upstream",
			expected:     "grpcs://test-upstream",
		},
	}

	for _, test := range tests {
		result := generateGRPCPass(test.grpcEnabled, test.tlsEnabled, test.upstreamName)
		if result != test.expected {
			t.Errorf("generateGRPCPass(%v, %v, %v) returned %v but expected %v", test.grpcEnabled, test.tlsEnabled, test.upstreamName, result, test.expected)
		}
	}
}

func TestGenerateGRPCPassProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstream conf_v1.Upstream
		expected string
	}{
		{
			upstream: conf_v1.Upstream{},
			expected: "grpc",
		},
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: true,
				},
			},
			expected: "grpcs",
		},
	}

	for _, test := range tests {
		result := generateGRPCPassProtocol(test.upstream.TLS.Enable)
		if result != test.expected {
			t.Errorf("generateGRPCPassProtocol(%v) returned %v but expected %v", test.upstream.TLS.Enable, result, test.expected)
		}
	}
}

func TestGenerateString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputS   string
		expected string
	}{
		{
			inputS:   "http_404",
			expected: "http_404",
		},
		{
			inputS:   "",
			expected: "error timeout",
		},
	}

	for _, test := range tests {
		result := generateString(test.inputS, "error timeout")
		if result != test.expected {
			t.Errorf("generateString() return %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateAuthJwtClaimSetVariable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		claim       string
		vsNamespace string
		vsName      string
		expected    string
	}{
		{
			claim:       "consumer_group.type",
			vsNamespace: "default",
			vsName:      "webapp",
			expected:    "$jwt_default_webapp_consumer_group_type",
		},
		{
			claim:       "type",
			vsNamespace: "default",
			vsName:      "webapp",
			expected:    "$jwt_default_webapp_type",
		},
		{
			claim:       "a.b.c",
			vsNamespace: "default",
			vsName:      "webapp",
			expected:    "$jwt_default_webapp_a_b_c",
		},
	}

	for _, test := range tests {
		result := generateAuthJwtClaimSetVariable(test.claim, test.vsNamespace, test.vsName)
		if result != test.expected {
			t.Errorf("generateAuthJwtClaimSetVariable() return %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateAuthJwtClaimSetClaim(t *testing.T) {
	t.Parallel()
	tests := []struct {
		claim    string
		expected string
	}{
		{
			claim:    "consumer_group.type",
			expected: "consumer_group type",
		},
		{
			claim:    "consumer_group.type",
			expected: "consumer_group type",
		},
		{
			claim:    "type",
			expected: "type",
		},
		{
			claim:    "a.b.c",
			expected: "a b c",
		},
	}

	for _, test := range tests {
		result := generateAuthJwtClaimSetClaim(test.claim)
		if result != test.expected {
			t.Errorf("generateAuthJwtClaimSetClaim() return %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateSnippets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		enableSnippets bool
		s              string
		defaultS       []string
		expected       []string
	}{
		{
			true,
			"test",
			[]string{},
			[]string{"test"},
		},
		{
			true,
			"",
			[]string{"default"},
			[]string{"default"},
		},
		{
			true,
			"test\none\ntwo",
			[]string{},
			[]string{"test", "one", "two"},
		},
		{
			false,
			"test",
			nil,
			nil,
		},
	}
	for _, test := range tests {
		result := generateSnippets(test.enableSnippets, test.s, test.defaultS)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateSnippets() return %v, but expected %v", result, test.expected)
		}
	}
}

func TestGenerateBuffer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputS   *conf_v1.UpstreamBuffers
		expected string
	}{
		{
			inputS:   nil,
			expected: "8 4k",
		},
		{
			inputS:   &conf_v1.UpstreamBuffers{Number: 8, Size: "16K"},
			expected: "8 16K",
		},
	}

	for _, test := range tests {
		result := generateBuffers(test.inputS, "8 4k")
		if result != test.expected {
			t.Errorf("generateBuffer() return %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateLocationForProxying(t *testing.T) {
	t.Parallel()
	cfgParams := ConfigParams{
		Context:              context.Background(),
		ProxyConnectTimeout:  "30s",
		ProxyReadTimeout:     "31s",
		ProxySendTimeout:     "32s",
		ClientMaxBodySize:    "1m",
		ProxyMaxTempFileSize: "1024m",
		ProxyBuffering:       true,
		ProxyBuffers:         "8 4k",
		ProxyBufferSize:      "4k",
		LocationSnippets:     []string{"# location snippet"},
	}
	path := "/"
	upstreamName := "test-upstream"
	vsLocSnippets := []string{"# vs location snippet"}

	expected := version2.Location{
		Path:                     "/",
		Snippets:                 vsLocSnippets,
		ProxyConnectTimeout:      "30s",
		ProxyReadTimeout:         "31s",
		ProxySendTimeout:         "32s",
		ClientMaxBodySize:        "1m",
		ProxyMaxTempFileSize:     "1024m",
		ProxyBuffering:           true,
		ProxyBuffers:             "8 4k",
		ProxyBufferSize:          "4k",
		ProxyPass:                "http://test-upstream",
		ProxyNextUpstream:        "error timeout",
		ProxyNextUpstreamTimeout: "0s",
		ProxyNextUpstreamTries:   0,
		ProxyPassRequestHeaders:  true,
		ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
		ServiceName:              "",
		IsVSR:                    false,
		VSRName:                  "",
		VSRNamespace:             "",
	}

	result := generateLocationForProxying(path, upstreamName, conf_v1.Upstream{}, &cfgParams, nil, false, 0, "", nil, "", vsLocSnippets, false, "", "")
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateLocationForProxying() mismatch (-want +got):\n%s", diff)
	}
}

func TestGenerateLocationForGrpcProxying(t *testing.T) {
	t.Parallel()
	cfgParams := ConfigParams{
		Context:              context.Background(),
		ProxyConnectTimeout:  "30s",
		ProxyReadTimeout:     "31s",
		ProxySendTimeout:     "32s",
		ClientMaxBodySize:    "1m",
		ProxyMaxTempFileSize: "1024m",
		ProxyBuffering:       true,
		ProxyBuffers:         "8 4k",
		ProxyBufferSize:      "4k",
		LocationSnippets:     []string{"# location snippet"},
		HTTP2:                true,
	}
	path := "/"
	upstreamName := "test-upstream"
	vsLocSnippets := []string{"# vs location snippet"}

	expected := version2.Location{
		Path:                     "/",
		Snippets:                 vsLocSnippets,
		ProxyConnectTimeout:      "30s",
		ProxyReadTimeout:         "31s",
		ProxySendTimeout:         "32s",
		ClientMaxBodySize:        "1m",
		ProxyMaxTempFileSize:     "1024m",
		ProxyBuffering:           true,
		ProxyBuffers:             "8 4k",
		ProxyBufferSize:          "4k",
		ProxyPass:                "http://test-upstream",
		ProxyNextUpstream:        "error timeout",
		ProxyNextUpstreamTimeout: "0s",
		ProxyNextUpstreamTries:   0,
		ProxyPassRequestHeaders:  true,
		ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
		GRPCPass:                 "grpc://test-upstream",
	}

	result := generateLocationForProxying(path, upstreamName, conf_v1.Upstream{Type: "grpc"}, &cfgParams, nil, false, 0, "", nil, "", vsLocSnippets, false, "", "")
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("generateLocationForForGrpcProxying() mismatch (-want +got):\n%s", diff)
	}
}

func TestGenerateReturnBlock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		text        string
		code        int
		defaultCode int
		expected    *version2.Return
	}{
		{
			text:        "Hello World!",
			code:        0, // Not set
			defaultCode: 200,
			expected: &version2.Return{
				Code: 200,
				Text: "Hello World!",
			},
		},
		{
			text:        "Hello World!",
			code:        400,
			defaultCode: 200,
			expected: &version2.Return{
				Code: 400,
				Text: "Hello World!",
			},
		},
	}

	for _, test := range tests {
		result := generateReturnBlock(test.text, test.code, test.defaultCode)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateReturnBlock() returned %v but expected %v", result, test.expected)
		}
	}
}

func TestGenerateLocationForReturn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		actionReturn           *conf_v1.ActionReturn
		expectedLocation       version2.Location
		expectedReturnLocation *version2.ReturnLocation
		msg                    string
	}{
		{
			actionReturn: &conf_v1.ActionReturn{
				Body: "hello",
			},

			expectedLocation: version2.Location{
				Path:     "/",
				Snippets: []string{"# location snippet"},
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@return_1",
						Codes:        "418",
						ResponseCode: 200,
					},
				},
				ProxyInterceptErrors: true,
				InternalProxyPass:    "http://unix:/var/lib/nginx/nginx-418-server.sock",
			},
			expectedReturnLocation: &version2.ReturnLocation{
				Name:        "@return_1",
				DefaultType: "text/plain",
				Return: version2.Return{
					Code: 0,
					Text: "hello",
				},
			},
			msg: "return without code and type",
		},
		{
			actionReturn: &conf_v1.ActionReturn{
				Code: 400,
				Type: "text/html",
				Body: "hello",
			},

			expectedLocation: version2.Location{
				Path:     "/",
				Snippets: []string{"# location snippet"},
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "@return_1",
						Codes:        "418",
						ResponseCode: 400,
					},
				},
				ProxyInterceptErrors: true,
				InternalProxyPass:    "http://unix:/var/lib/nginx/nginx-418-server.sock",
			},
			expectedReturnLocation: &version2.ReturnLocation{
				Name:        "@return_1",
				DefaultType: "text/html",
				Return: version2.Return{
					Code: 0,
					Text: "hello",
				},
			},
			msg: "return with all fields defined",
		},
	}
	path := "/"
	snippets := []string{"# location snippet"}
	returnLocationIndex := 1

	for _, test := range tests {
		location, returnLocation := generateLocationForReturn(path, snippets, test.actionReturn, returnLocationIndex)
		if !reflect.DeepEqual(location, test.expectedLocation) {
			t.Errorf("generateLocationForReturn() returned  \n%+v but expected \n%+v for the case of %s",
				location, test.expectedLocation, test.msg)
		}
		if !reflect.DeepEqual(returnLocation, test.expectedReturnLocation) {
			t.Errorf("generateLocationForReturn() returned  \n%+v but expected \n%+v for the case of %s",
				returnLocation, test.expectedReturnLocation, test.msg)
		}
	}
}

func TestGenerateLocationForRedirect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		redirect *conf_v1.ActionRedirect
		expected version2.Location
		msg      string
	}{
		{
			redirect: &conf_v1.ActionRedirect{
				URL: "http://nginx.org",
			},

			expected: version2.Location{
				Path:     "/",
				Snippets: []string{"# location snippet"},
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "http://nginx.org",
						Codes:        "418",
						ResponseCode: 301,
					},
				},
				ProxyInterceptErrors: true,
				InternalProxyPass:    "http://unix:/var/lib/nginx/nginx-418-server.sock",
			},
			msg: "redirect without code",
		},
		{
			redirect: &conf_v1.ActionRedirect{
				Code: 302,
				URL:  "http://nginx.org",
			},

			expected: version2.Location{
				Path:     "/",
				Snippets: []string{"# location snippet"},
				ErrorPages: []version2.ErrorPage{
					{
						Name:         "http://nginx.org",
						Codes:        "418",
						ResponseCode: 302,
					},
				},
				ProxyInterceptErrors: true,
				InternalProxyPass:    "http://unix:/var/lib/nginx/nginx-418-server.sock",
			},
			msg: "redirect with all fields defined",
		},
	}

	for _, test := range tests {
		result := generateLocationForRedirect("/", []string{"# location snippet"}, test.redirect)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateLocationForReturn() returned \n%+v but expected \n%+v for the case of %s",
				result, test.expected, test.msg)
		}
	}
}

func TestGenerateSSLConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputTLS         *conf_v1.TLS
		inputSecretRefs  map[string]*secrets.SecretReference
		inputCfgParams   *ConfigParams
		wildcard         bool
		expectedSSL      *version2.SSL
		expectedWarnings Warnings
		msg              string
	}{
		{
			inputTLS:         nil,
			inputSecretRefs:  map[string]*secrets.SecretReference{},
			inputCfgParams:   &ConfigParams{Context: context.Background()},
			wildcard:         false,
			expectedSSL:      nil,
			expectedWarnings: Warnings{},
			msg:              "no TLS field",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "",
			},
			inputSecretRefs:  map[string]*secrets.SecretReference{},
			inputCfgParams:   &ConfigParams{Context: context.Background()},
			wildcard:         false,
			expectedSSL:      nil,
			expectedWarnings: Warnings{},
			msg:              "TLS field with empty secret and wildcard cert disabled",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "",
			},
			inputSecretRefs: map[string]*secrets.SecretReference{},
			inputCfgParams:  &ConfigParams{Context: context.Background()},
			wildcard:        true,
			expectedSSL: &version2.SSL{
				HTTP2:           false,
				Certificate:     pemFileNameForWildcardTLSSecret,
				CertificateKey:  pemFileNameForWildcardTLSSecret,
				RejectHandshake: false,
			},
			expectedWarnings: Warnings{},
			msg:              "TLS field with empty secret and wildcard cert enabled",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "missing",
			},
			inputCfgParams: &ConfigParams{Context: context.Background()},
			wildcard:       false,
			inputSecretRefs: map[string]*secrets.SecretReference{
				"default/missing": {
					Error: errors.New("missing doesn't exist"),
				},
			},
			expectedSSL: &version2.SSL{
				HTTP2:           false,
				RejectHandshake: true,
			},
			expectedWarnings: Warnings{
				nil: []string{"TLS secret missing is invalid: missing doesn't exist"},
			},
			msg: "missing doesn't exist in the cluster with HTTPS",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "mistyped",
			},
			inputCfgParams: &ConfigParams{Context: context.Background()},
			wildcard:       false,
			inputSecretRefs: map[string]*secrets.SecretReference{
				"default/mistyped": {
					Secret: &api_v1.Secret{
						Type: secrets.SecretTypeCA,
					},
				},
			},
			expectedSSL: &version2.SSL{
				HTTP2:           false,
				RejectHandshake: true,
			},
			expectedWarnings: Warnings{
				nil: []string{"TLS secret mistyped is of a wrong type 'nginx.org/ca', must be 'kubernetes.io/tls'"},
			},
			msg: "wrong secret type",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "secret",
			},
			inputSecretRefs: map[string]*secrets.SecretReference{
				"default/secret": {
					Secret: &api_v1.Secret{
						Type: api_v1.SecretTypeTLS,
					},
					Path: "secret.pem",
				},
			},
			inputCfgParams: &ConfigParams{Context: context.Background()},
			wildcard:       false,
			expectedSSL: &version2.SSL{
				HTTP2:           false,
				Certificate:     "secret.pem",
				CertificateKey:  "secret.pem",
				RejectHandshake: false,
			},
			expectedWarnings: Warnings{},
			msg:              "normal case with HTTPS",
		},
	}

	namespace := "default"

	for _, test := range tests {
		vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, false, false, &StaticConfigParams{}, test.wildcard, &fakeBV)

		// it is ok to use nil as the owner
		result := vsc.generateSSLConfig(nil, test.inputTLS, namespace, test.inputSecretRefs, test.inputCfgParams)
		if !reflect.DeepEqual(result, test.expectedSSL) {
			t.Errorf("generateSSLConfig() returned %v but expected %v for the case of %s", result, test.expectedSSL, test.msg)
		}
		if !reflect.DeepEqual(vsc.warnings, test.expectedWarnings) {
			t.Errorf("generateSSLConfig() returned warnings of \n%v but expected \n%v for the case of %s", vsc.warnings, test.expectedWarnings, test.msg)
		}
	}
}

func TestGenerateRedirectConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputTLS *conf_v1.TLS
		expected *version2.TLSRedirect
		msg      string
	}{
		{
			inputTLS: nil,
			expected: nil,
			msg:      "no TLS field",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret:   "secret",
				Redirect: nil,
			},
			expected: nil,
			msg:      "no redirect field",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret:   "secret",
				Redirect: &conf_v1.TLSRedirect{Enable: false},
			},
			expected: nil,
			msg:      "redirect disabled",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "secret",
				Redirect: &conf_v1.TLSRedirect{
					Enable: true,
				},
			},
			expected: &version2.TLSRedirect{
				Code:    301,
				BasedOn: "$scheme",
			},
			msg: "normal case with defaults",
		},
		{
			inputTLS: &conf_v1.TLS{
				Secret: "secret",
				Redirect: &conf_v1.TLSRedirect{
					Enable:  true,
					BasedOn: "x-forwarded-proto",
				},
			},
			expected: &version2.TLSRedirect{
				Code:    301,
				BasedOn: "$http_x_forwarded_proto",
			},
			msg: "normal case with BasedOn set",
		},
	}

	for _, test := range tests {
		result := generateTLSRedirectConfig(test.inputTLS)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateTLSRedirectConfig() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestGenerateTLSRedirectBasedOn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		basedOn  string
		expected string
	}{
		{
			basedOn:  "scheme",
			expected: "$scheme",
		},
		{
			basedOn:  "x-forwarded-proto",
			expected: "$http_x_forwarded_proto",
		},
		{
			basedOn:  "",
			expected: "$scheme",
		},
	}
	for _, test := range tests {
		result := generateTLSRedirectBasedOn(test.basedOn)
		if result != test.expected {
			t.Errorf("generateTLSRedirectBasedOn(%v) returned %v but expected %v", test.basedOn, result, test.expected)
		}
	}
}

func TestCreateUpstreamsForPlus(t *testing.T) {
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
						Name:    "test",
						Service: "test-svc",
						Port:    80,
					},
					{
						Name:        "subselector-test",
						Service:     "test-svc",
						Subselector: map[string]string{"vs": "works"},
						Port:        80,
					},
					{
						Name:    "external",
						Service: "external-svc",
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
						Path:  "/coffee",
						Route: "default/coffee",
					},
					{
						Path: "/external",
						Action: &conf_v1.Action{
							Pass: "external",
						},
					},
				},
			},
		},
		Endpoints: map[string][]string{
			"default/tea-svc:80": {
				"10.0.0.20:80",
			},
			"default/test-svc:80": {},
			"default/test-svc_vs=works:80": {
				"10.0.0.30:80",
			},
			"default/coffee-svc:80": {
				"10.0.0.40:80",
			},
			"default/test-svc_vsr=works:80": {
				"10.0.0.50:80",
			},
			"default/external-svc:80": {
				"example.com:80",
			},
		},
		ExternalNameSvcs: map[string]bool{
			"default/external-svc": true,
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
						{
							Name:        "subselector-test",
							Service:     "test-svc",
							Subselector: map[string]string{"vsr": "works"},
							Port:        80,
						},
					},
					Subroutes: []conf_v1.Route{
						{
							Path: "/coffee",
							Action: &conf_v1.Action{
								Pass: "coffee",
							},
						},
						{
							Path: "/coffee/sub",
							Action: &conf_v1.Action{
								Pass: "subselector-test",
							},
						},
					},
				},
			},
		},
	}

	expected := []version2.Upstream{
		{
			Name: "vs_default_cafe_tea",
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "tea-svc",
				ResourceType:      "virtualserver",
				ResourceNamespace: "default",
				ResourceName:      "cafe",
			},
			Servers: []version2.UpstreamServer{
				{
					Address: "10.0.0.20:80",
				},
			},
		},
		{
			Name: "vs_default_cafe_test",
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "test-svc",
				ResourceType:      "virtualserver",
				ResourceNamespace: "default",
				ResourceName:      "cafe",
			},
			Servers: nil,
		},
		{
			Name: "vs_default_cafe_subselector-test",
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "test-svc",
				ResourceType:      "virtualserver",
				ResourceNamespace: "default",
				ResourceName:      "cafe",
			},
			Servers: []version2.UpstreamServer{
				{
					Address: "10.0.0.30:80",
				},
			},
		},
		{
			Name: "vs_default_cafe_vsr_default_coffee_coffee",
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "coffee-svc",
				ResourceType:      "virtualserverroute",
				ResourceNamespace: "default",
				ResourceName:      "coffee",
			},
			Servers: []version2.UpstreamServer{
				{
					Address: "10.0.0.40:80",
				},
			},
		},
		{
			Name: "vs_default_cafe_vsr_default_coffee_subselector-test",
			UpstreamLabels: version2.UpstreamLabels{
				Service:           "test-svc",
				ResourceType:      "virtualserverroute",
				ResourceNamespace: "default",
				ResourceName:      "coffee",
			},
			Servers: []version2.UpstreamServer{
				{
					Address: "10.0.0.50:80",
				},
			},
		},
	}

	result := createUpstreamsForPlus(&virtualServerEx, &ConfigParams{Context: context.Background()}, &StaticConfigParams{})
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("createUpstreamsForPlus returned \n%v but expected \n%v", result, expected)
	}
}

func TestCreateUpstreamServersConfigForPlus(t *testing.T) {
	t.Parallel()
	upstream := version2.Upstream{
		Servers: []version2.UpstreamServer{
			{
				Address: "10.0.0.20:80",
			},
		},
		MaxFails:    21,
		MaxConns:    16,
		FailTimeout: "30s",
		SlowStart:   "50s",
	}

	expected := nginx.ServerConfig{
		MaxFails:    21,
		MaxConns:    16,
		FailTimeout: "30s",
		SlowStart:   "50s",
	}

	result := createUpstreamServersConfigForPlus(upstream)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("createUpstreamServersConfigForPlus returned %v but expected %v", result, expected)
	}
}

func TestCreateUpstreamServersConfigForPlusNoUpstreams(t *testing.T) {
	t.Parallel()
	noUpstream := version2.Upstream{}
	expected := nginx.ServerConfig{}

	result := createUpstreamServersConfigForPlus(noUpstream)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("createUpstreamServersConfigForPlus returned %v but expected %v", result, expected)
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

func TestGenerateLBMethod(t *testing.T) {
	t.Parallel()
	defaultMethod := "random two least_conn"

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "",
			expected: defaultMethod,
		},
		{
			input:    "round_robin",
			expected: "",
		},
		{
			input:    "random",
			expected: "random",
		},
	}
	for _, test := range tests {
		result := generateLBMethod(test.input, defaultMethod)
		if result != test.expected {
			t.Errorf("generateLBMethod() returned %q but expected %q for input '%v'", result, test.expected, test.input)
		}
	}
}

func TestUpstreamHasKeepalive(t *testing.T) {
	t.Parallel()
	noKeepalive := 0
	keepalive := 32

	tests := []struct {
		upstream  conf_v1.Upstream
		cfgParams *ConfigParams
		expected  bool
		msg       string
	}{
		{
			conf_v1.Upstream{},
			&ConfigParams{Keepalive: keepalive},
			true,
			"upstream keepalive not set, configparam keepalive set",
		},
		{
			conf_v1.Upstream{Keepalive: &noKeepalive},
			&ConfigParams{Keepalive: keepalive},
			false,
			"upstream keepalive set to 0, configparam keepalive set",
		},
		{
			conf_v1.Upstream{Keepalive: &keepalive},
			&ConfigParams{Keepalive: noKeepalive},
			true,
			"upstream keepalive set, configparam keepalive set to 0",
		},
	}

	for _, test := range tests {
		result := upstreamHasKeepalive(test.upstream, test.cfgParams)
		if result != test.expected {
			t.Errorf("upstreamHasKeepalive() returned %v, but expected %v for the case of %v", result, test.expected, test.msg)
		}
	}
}

func TestNewHealthCheckWithDefaults(t *testing.T) {
	t.Parallel()
	upstreamName := "test-upstream"
	baseCfgParams := &ConfigParams{
		ProxySendTimeout:    "5s",
		ProxyReadTimeout:    "5s",
		ProxyConnectTimeout: "5s",
	}
	expected := &version2.HealthCheck{
		Name:                upstreamName,
		ProxySendTimeout:    "5s",
		ProxyReadTimeout:    "5s",
		ProxyConnectTimeout: "5s",
		ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
		URI:                 "/",
		Interval:            "5s",
		Jitter:              "0s",
		KeepaliveTime:       "60s",
		Fails:               1,
		Passes:              1,
		Headers:             make(map[string]string),
	}

	result := newHealthCheckWithDefaults(conf_v1.Upstream{}, upstreamName, baseCfgParams)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("newHealthCheckWithDefaults returned \n%v but expected \n%v", result, expected)
	}
}

func TestGenerateHealthCheck(t *testing.T) {
	t.Parallel()
	upstreamName := "test-upstream"
	tests := []struct {
		upstream     conf_v1.Upstream
		upstreamName string
		expected     *version2.HealthCheck
		msg          string
	}{
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable:         true,
					Path:           "/healthz",
					Interval:       "5s",
					Jitter:         "2s",
					KeepaliveTime:  "120s",
					Fails:          3,
					Passes:         2,
					Port:           8080,
					ConnectTimeout: "20s",
					SendTimeout:    "20s",
					ReadTimeout:    "20s",
					Headers: []conf_v1.Header{
						{
							Name:  "Host",
							Value: "my.service",
						},
						{
							Name:  "User-Agent",
							Value: "nginx",
						},
					},
					StatusMatch: "! 500",
				},
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "20s",
				ProxySendTimeout:    "20s",
				ProxyReadTimeout:    "20s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				URI:                 "/healthz",
				Interval:            "5s",
				Jitter:              "2s",
				KeepaliveTime:       "120s",
				Fails:               3,
				Passes:              2,
				Port:                8080,
				Headers: map[string]string{
					"Host":       "my.service",
					"User-Agent": "nginx",
				},
				Match: fmt.Sprintf("%v_match", upstreamName),
			},
			msg: "HealthCheck with changed parameters",
		},
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable: true,
				},
				ProxyConnectTimeout: "30s",
				ProxyReadTimeout:    "30s",
				ProxySendTimeout:    "30s",
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "30s",
				ProxyReadTimeout:    "30s",
				ProxySendTimeout:    "30s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				URI:                 "/",
				Interval:            "5s",
				Jitter:              "0s",
				KeepaliveTime:       "60s",
				Fails:               1,
				Passes:              1,
				Headers:             make(map[string]string),
			},
			msg: "HealthCheck with default parameters from Upstream",
		},
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable: true,
				},
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "5s",
				ProxyReadTimeout:    "5s",
				ProxySendTimeout:    "5s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				URI:                 "/",
				Interval:            "5s",
				Jitter:              "0s",
				KeepaliveTime:       "60s",
				Fails:               1,
				Passes:              1,
				Headers:             make(map[string]string),
			},
			msg: "HealthCheck with default parameters from ConfigMap (not defined in Upstream)",
		},
		{
			upstream:     conf_v1.Upstream{},
			upstreamName: upstreamName,
			expected:     nil,
			msg:          "HealthCheck not enabled",
		},
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable:         true,
					Interval:       "1m 5s",
					Jitter:         "2m 3s",
					KeepaliveTime:  "1m 6s",
					ConnectTimeout: "1m 10s",
					SendTimeout:    "1m 20s",
					ReadTimeout:    "1m 30s",
				},
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "1m10s",
				ProxySendTimeout:    "1m20s",
				ProxyReadTimeout:    "1m30s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				URI:                 "/",
				Interval:            "1m5s",
				Jitter:              "2m3s",
				KeepaliveTime:       "1m6s",
				Fails:               1,
				Passes:              1,
				Headers:             make(map[string]string),
			},
			msg: "HealthCheck with time parameters have correct format",
		},
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable:     true,
					Mandatory:  true,
					Persistent: true,
				},
				ProxyConnectTimeout: "30s",
				ProxyReadTimeout:    "30s",
				ProxySendTimeout:    "30s",
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "30s",
				ProxyReadTimeout:    "30s",
				ProxySendTimeout:    "30s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				URI:                 "/",
				Interval:            "5s",
				Jitter:              "0s",
				KeepaliveTime:       "60s",
				Fails:               1,
				Passes:              1,
				Headers:             make(map[string]string),
				Mandatory:           true,
				Persistent:          true,
			},
			msg: "HealthCheck with mandatory and persistent set",
		},
	}

	baseCfgParams := &ConfigParams{
		ProxySendTimeout:    "5s",
		ProxyReadTimeout:    "5s",
		ProxyConnectTimeout: "5s",
	}

	for _, test := range tests {
		result := generateHealthCheck(test.upstream, test.upstreamName, baseCfgParams)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateHealthCheck returned \n%v but expected \n%v \n for case: %v", result, test.expected, test.msg)
		}
	}
}

func TestGenerateGrpcHealthCheck(t *testing.T) {
	t.Parallel()
	upstreamName := "test-upstream"
	tests := []struct {
		upstream     conf_v1.Upstream
		upstreamName string
		expected     *version2.HealthCheck
		msg          string
	}{
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable:         true,
					Interval:       "5s",
					Jitter:         "2s",
					KeepaliveTime:  "120s",
					Fails:          3,
					Passes:         2,
					Port:           50051,
					ConnectTimeout: "20s",
					SendTimeout:    "20s",
					ReadTimeout:    "20s",
					GRPCStatus:     createPointerFromInt(12),
					GRPCService:    "grpc-service",
					Headers: []conf_v1.Header{
						{
							Name:  "Host",
							Value: "my.service",
						},
						{
							Name:  "User-Agent",
							Value: "nginx",
						},
					},
				},
				Type: "grpc",
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "20s",
				ProxySendTimeout:    "20s",
				ProxyReadTimeout:    "20s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				GRPCPass:            fmt.Sprintf("grpc://%v", upstreamName),
				Interval:            "5s",
				Jitter:              "2s",
				KeepaliveTime:       "120s",
				Fails:               3,
				Passes:              2,
				Port:                50051,
				GRPCStatus:          createPointerFromInt(12),
				GRPCService:         "grpc-service",
				Headers: map[string]string{
					"Host":       "my.service",
					"User-Agent": "nginx",
				},
				IsGRPC: true,
			},
			msg: "HealthCheck with changed parameters",
		},
		{
			upstream: conf_v1.Upstream{
				HealthCheck: &conf_v1.HealthCheck{
					Enable: true,
				},
				ProxyConnectTimeout: "30s",
				ProxyReadTimeout:    "30s",
				ProxySendTimeout:    "30s",
				Type:                "grpc",
			},
			upstreamName: upstreamName,
			expected: &version2.HealthCheck{
				Name:                upstreamName,
				ProxyConnectTimeout: "30s",
				ProxyReadTimeout:    "30s",
				ProxySendTimeout:    "30s",
				ProxyPass:           fmt.Sprintf("http://%v", upstreamName),
				GRPCPass:            fmt.Sprintf("grpc://%v", upstreamName),
				Interval:            "5s",
				Jitter:              "0s",
				KeepaliveTime:       "60s",
				Fails:               1,
				Passes:              1,
				Headers:             make(map[string]string),
				IsGRPC:              true,
			},
			msg: "HealthCheck with default parameters from Upstream",
		},
	}

	baseCfgParams := &ConfigParams{
		ProxySendTimeout:    "5s",
		ProxyReadTimeout:    "5s",
		ProxyConnectTimeout: "5s",
	}

	for _, test := range tests {
		result := generateHealthCheck(test.upstream, test.upstreamName, baseCfgParams)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateHealthCheck returned \n%v but expected \n%v \n for case: %v", result, test.expected, test.msg)
		}
	}
}

func TestGenerateEndpointsForUpstream(t *testing.T) {
	t.Parallel()
	name := "test"
	namespace := "test-namespace"

	tests := []struct {
		upstream             conf_v1.Upstream
		vsEx                 *VirtualServerEx
		isPlus               bool
		isResolverConfigured bool
		expected             []string
		warningsExpected     bool
		msg                  string
	}{
		{
			upstream: conf_v1.Upstream{
				Service: name,
				Port:    80,
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{
					"test-namespace/test:80": {"example.com:80"},
				},
				ExternalNameSvcs: map[string]bool{
					"test-namespace/test": true,
				},
			},
			isPlus:               true,
			isResolverConfigured: true,
			expected:             []string{"example.com:80"},
			msg:                  "ExternalName service",
		},
		{
			upstream: conf_v1.Upstream{
				Service: name,
				Port:    80,
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{
					"test-namespace/test:80": {"example.com:80"},
				},
				ExternalNameSvcs: map[string]bool{
					"test-namespace/test": true,
				},
			},
			isPlus:               true,
			isResolverConfigured: false,
			warningsExpected:     true,
			expected:             []string{},
			msg:                  "ExternalName service without resolver configured",
		},
		{
			upstream: conf_v1.Upstream{
				Service: name,
				Port:    8080,
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{
					"test-namespace/test:8080": {"192.168.10.10:8080"},
				},
			},
			isPlus:               false,
			isResolverConfigured: false,
			expected:             []string{"192.168.10.10:8080"},
			msg:                  "Service with endpoints",
		},
		{
			upstream: conf_v1.Upstream{
				Service: name,
				Port:    8080,
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{},
			},
			isPlus:               false,
			isResolverConfigured: false,
			expected:             []string{nginx502Server},
			msg:                  "Service with no endpoints",
		},
		{
			upstream: conf_v1.Upstream{
				Service: name,
				Port:    8080,
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{},
			},
			isPlus:               true,
			isResolverConfigured: false,
			expected:             nil,
			msg:                  "Service with no endpoints",
		},
		{
			upstream: conf_v1.Upstream{
				Service:     name,
				Port:        8080,
				Subselector: map[string]string{"version": "test"},
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{
					"test-namespace/test_version=test:8080": {"192.168.10.10:8080"},
				},
			},
			isPlus:               false,
			isResolverConfigured: false,
			expected:             []string{"192.168.10.10:8080"},
			msg:                  "Upstream with subselector, with a matching endpoint",
		},
		{
			upstream: conf_v1.Upstream{
				Service:     name,
				Port:        8080,
				Subselector: map[string]string{"version": "test"},
			},
			vsEx: &VirtualServerEx{
				VirtualServer: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
				Endpoints: map[string][]string{
					"test-namespace/test:8080": {"192.168.10.10:8080"},
				},
			},
			isPlus:               false,
			isResolverConfigured: false,
			expected:             []string{nginx502Server},
			msg:                  "Upstream with subselector, without a matching endpoint",
		},
	}

	for _, test := range tests {
		isWildcardEnabled := false
		vsc := newVirtualServerConfigurator(
			&ConfigParams{Context: context.Background()},
			test.isPlus,
			test.isResolverConfigured,
			&StaticConfigParams{},
			isWildcardEnabled,
			&fakeBV,
		)
		result := vsc.generateEndpointsForUpstream(test.vsEx.VirtualServer, namespace, test.upstream, test.vsEx)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateEndpointsForUpstream(isPlus=%v, isResolverConfigured=%v) returned %v, but expected %v for case: %v",
				test.isPlus, test.isResolverConfigured, result, test.expected, test.msg)
		}

		if len(vsc.warnings) == 0 && test.warningsExpected {
			t.Errorf(
				"generateEndpointsForUpstream(isPlus=%v, isResolverConfigured=%v) didn't return any warnings for %v but warnings expected",
				test.isPlus,
				test.isResolverConfigured,
				test.upstream,
			)
		}

		if len(vsc.warnings) != 0 && !test.warningsExpected {
			t.Errorf("generateEndpointsForUpstream(isPlus=%v, isResolverConfigured=%v) returned warnings for %v",
				test.isPlus, test.isResolverConfigured, test.upstream)
		}
	}
}

func TestGenerateSlowStartForPlusWithInCompatibleLBMethods(t *testing.T) {
	t.Parallel()
	serviceName := "test-slowstart-with-incompatible-LBMethods"
	upstream := conf_v1.Upstream{Service: serviceName, Port: 80, SlowStart: "10s"}
	expected := ""

	tests := []string{
		"random",
		"ip_hash",
		"hash 123",
		"random two",
		"random two least_conn",
		"random two least_time=header",
		"random two least_time=last_byte",
	}

	for _, lbMethod := range tests {
		vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, true, false, &StaticConfigParams{}, false, &fakeBV)
		result := vsc.generateSlowStartForPlus(&conf_v1.VirtualServer{}, upstream, lbMethod)

		if !reflect.DeepEqual(result, expected) {
			t.Errorf("generateSlowStartForPlus returned %v, but expected %v for lbMethod %v", result, expected, lbMethod)
		}

		if len(vsc.warnings) == 0 {
			t.Errorf("generateSlowStartForPlus returned no warnings for %v but warnings expected", upstream)
		}
	}
}

func TestGenerateSlowStartForPlus(t *testing.T) {
	serviceName := "test-slowstart"

	tests := []struct {
		upstream conf_v1.Upstream
		lbMethod string
		expected string
	}{
		{
			upstream: conf_v1.Upstream{Service: serviceName, Port: 80, SlowStart: "", LBMethod: "least_conn"},
			lbMethod: "least_conn",
			expected: "",
		},
		{
			upstream: conf_v1.Upstream{Service: serviceName, Port: 80, SlowStart: "10s", LBMethod: "least_conn"},
			lbMethod: "least_conn",
			expected: "10s",
		},
	}

	for _, test := range tests {
		vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, true, false, &StaticConfigParams{}, false, &fakeBV)
		result := vsc.generateSlowStartForPlus(&conf_v1.VirtualServer{}, test.upstream, test.lbMethod)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateSlowStartForPlus returned %v, but expected %v", result, test.expected)
		}

		if len(vsc.warnings) != 0 {
			t.Errorf("generateSlowStartForPlus returned warnings for %v", test.upstream)
		}
	}
}

func TestCreateEndpointsFromUpstream(t *testing.T) {
	t.Parallel()
	ups := version2.Upstream{
		Servers: []version2.UpstreamServer{
			{
				Address: "10.0.0.20:80",
			},
			{
				Address: "10.0.0.30:80",
			},
		},
	}

	expected := []string{
		"10.0.0.20:80",
		"10.0.0.30:80",
	}

	endpoints := createEndpointsFromUpstream(ups)
	if !reflect.DeepEqual(endpoints, expected) {
		t.Errorf("createEndpointsFromUpstream returned %v, but expected %v", endpoints, expected)
	}
}

func TestGenerateUpstreamWithQueue(t *testing.T) {
	t.Parallel()
	serviceName := "test-queue"

	tests := []struct {
		name     string
		upstream conf_v1.Upstream
		isPlus   bool
		expected version2.Upstream
		msg      string
	}{
		{
			name: "test-upstream-queue",
			upstream: conf_v1.Upstream{Service: serviceName, Port: 80, Queue: &conf_v1.UpstreamQueue{
				Size:    10,
				Timeout: "10s",
			}},
			isPlus: true,
			expected: version2.Upstream{
				UpstreamLabels: version2.UpstreamLabels{
					Service: "test-queue",
				},
				Name: "test-upstream-queue",
				Queue: &version2.Queue{
					Size:    10,
					Timeout: "10s",
				},
			},
			msg: "upstream queue with size and timeout",
		},
		{
			name: "test-upstream-queue-with-default-timeout",
			upstream: conf_v1.Upstream{
				Service: serviceName,
				Port:    80,
				Queue:   &conf_v1.UpstreamQueue{Size: 10, Timeout: ""},
			},
			isPlus: true,
			expected: version2.Upstream{
				UpstreamLabels: version2.UpstreamLabels{
					Service: "test-queue",
				},
				Name: "test-upstream-queue-with-default-timeout",
				Queue: &version2.Queue{
					Size:    10,
					Timeout: "60s",
				},
			},
			msg: "upstream queue with only size",
		},
		{
			name:     "test-upstream-queue-nil",
			upstream: conf_v1.Upstream{Service: serviceName, Port: 80, Queue: nil},
			isPlus:   false,
			expected: version2.Upstream{
				UpstreamLabels: version2.UpstreamLabels{
					Service: "test-queue",
				},
				Name: "test-upstream-queue-nil",
			},
			msg: "upstream queue with nil for OSS",
		},
	}

	for _, test := range tests {
		vsc := newVirtualServerConfigurator(&ConfigParams{Context: context.Background()}, test.isPlus, false, &StaticConfigParams{}, false, &fakeBV)
		result := vsc.generateUpstream(nil, test.name, test.upstream, false, []string{}, []string{})
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateUpstream() returned %v but expected %v for the case of %v", result, test.expected, test.msg)
		}
	}
}

func TestGenerateQueueForPlus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreamQueue *conf_v1.UpstreamQueue
		expected      *version2.Queue
		msg           string
	}{
		{
			upstreamQueue: &conf_v1.UpstreamQueue{Size: 10, Timeout: "10s"},
			expected:      &version2.Queue{Size: 10, Timeout: "10s"},
			msg:           "upstream queue with size and timeout",
		},
		{
			upstreamQueue: nil,
			expected:      nil,
			msg:           "upstream queue with nil",
		},
		{
			upstreamQueue: &conf_v1.UpstreamQueue{Size: 10},
			expected:      &version2.Queue{Size: 10, Timeout: "60s"},
			msg:           "upstream queue with only size",
		},
	}

	for _, test := range tests {
		result := generateQueueForPlus(test.upstreamQueue, "60s")
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateQueueForPlus() returned %v but expected %v for the case of %v", result, test.expected, test.msg)
		}
	}
}

func TestGenerateSessionCookie(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sc       *conf_v1.SessionCookie
		expected *version2.SessionCookie
		msg      string
	}{
		{
			sc:       &conf_v1.SessionCookie{Enable: true, Name: "test"},
			expected: &version2.SessionCookie{Enable: true, Name: "test"},
			msg:      "session cookie with name",
		},
		{
			sc:       nil,
			expected: nil,
			msg:      "session cookie with nil",
		},
		{
			sc:       &conf_v1.SessionCookie{Name: "test"},
			expected: nil,
			msg:      "session cookie not enabled",
		},
		{
			sc:       &conf_v1.SessionCookie{Enable: true, Name: "testcookie", SameSite: "lax"},
			expected: &version2.SessionCookie{Enable: true, Name: "testcookie", SameSite: "lax"},
			msg:      "session cookie with samesite param",
		},
	}
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			result := generateSessionCookie(test.sc)
			if !cmp.Equal(test.expected, result) {
				t.Error(cmp.Diff(test.expected, result))
			}
		})
	}
}

func TestGeneratePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path     string
		expected string
	}{
		{
			path:     "/",
			expected: "/",
		},
		{
			path:     "=/exact/match",
			expected: "=/exact/match",
		},
		{
			path:     `~ *\\.jpg`,
			expected: `~ "*\\.jpg"`,
		},
		{
			path:     `~* *\\.PNG`,
			expected: `~* "*\\.PNG"`,
		},
	}

	for _, test := range tests {
		result := generatePath(test.path)
		if result != test.expected {
			t.Errorf("generatePath() returned %v, but expected %v.", result, test.expected)
		}
	}
}

func TestGenerateErrorPageName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		routeIndex int
		index      int
		expected   string
	}{
		{
			0,
			0,
			"@error_page_0_0",
		},
		{
			0,
			1,
			"@error_page_0_1",
		},
		{
			1,
			0,
			"@error_page_1_0",
		},
	}

	for _, test := range tests {
		result := generateErrorPageName(test.routeIndex, test.index)
		if result != test.expected {
			t.Errorf("generateErrorPageName(%v, %v) returned %v but expected %v", test.routeIndex, test.index, result, test.expected)
		}
	}
}

func TestGenerateErrorPageCodes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		codes    []int
		expected string
	}{
		{
			codes:    []int{400},
			expected: "400",
		},
		{
			codes:    []int{404, 405, 502},
			expected: "404 405 502",
		},
	}

	for _, test := range tests {
		result := generateErrorPageCodes(test.codes)
		if result != test.expected {
			t.Errorf("generateErrorPageCodes(%v) returned %v but expected %v", test.codes, result, test.expected)
		}
	}
}

func TestGenerateErrorPages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreamName string
		errorPages   []conf_v1.ErrorPage
		expected     []version2.ErrorPage
	}{
		{}, // empty errorPages
		{
			"vs_test_test",
			[]conf_v1.ErrorPage{
				{
					Codes: []int{404, 405, 500, 502},
					Return: &conf_v1.ErrorPageReturn{
						ActionReturn: conf_v1.ActionReturn{
							Code:    200,
							Headers: nil,
						},
					},
					Redirect: nil,
				},
			},
			[]version2.ErrorPage{
				{
					Name:         "@error_page_1_0",
					Codes:        "404 405 500 502",
					ResponseCode: 200,
				},
			},
		},
		{
			"vs_test_test",
			[]conf_v1.ErrorPage{
				{
					Codes:  []int{404, 405, 500, 502},
					Return: nil,
					Redirect: &conf_v1.ErrorPageRedirect{
						ActionRedirect: conf_v1.ActionRedirect{
							URL:  "http://nginx.org",
							Code: 302,
						},
					},
				},
			},
			[]version2.ErrorPage{
				{
					Name:         "http://nginx.org",
					Codes:        "404 405 500 502",
					ResponseCode: 302,
				},
			},
		},
	}

	for i, test := range tests {
		result := generateErrorPages(i, test.errorPages)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateErrorPages(%v, %v) returned %v but expected %v", test.upstreamName, test.errorPages, result, test.expected)
		}
	}
}

func TestGenerateErrorPageLocations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreamName string
		errorPages   []conf_v1.ErrorPage
		expected     []version2.ErrorPageLocation
	}{
		{},
		{
			"vs_test_test",
			[]conf_v1.ErrorPage{
				{
					Codes:  []int{404, 405, 500, 502},
					Return: nil,
					Redirect: &conf_v1.ErrorPageRedirect{
						ActionRedirect: conf_v1.ActionRedirect{
							URL:  "http://nginx.org",
							Code: 302,
						},
					},
				},
			},
			nil,
		},
		{
			"vs_test_test",
			[]conf_v1.ErrorPage{
				{
					Codes: []int{404, 405, 500, 502},
					Return: &conf_v1.ErrorPageReturn{
						ActionReturn: conf_v1.ActionReturn{
							Code: 200,
							Type: "application/json",
							Body: "Hello World",
							Headers: []conf_v1.Header{
								{
									Name:  "HeaderName",
									Value: "HeaderValue",
								},
							},
						},
					},
					Redirect: nil,
				},
			},
			[]version2.ErrorPageLocation{
				{
					Name:        "@error_page_2_0",
					DefaultType: "application/json",
					Return: &version2.Return{
						Code: 0,
						Text: "Hello World",
					},
					Headers: []version2.Header{
						{
							Name:  "HeaderName",
							Value: "HeaderValue",
						},
					},
				},
			},
		},
	}

	for i, test := range tests {
		result := generateErrorPageLocations(i, test.errorPages)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateErrorPageLocations(%v, %v) returned %v but expected %v", test.upstreamName, test.errorPages, result, test.expected)
		}
	}
}

func TestGenerateProxySSLName(t *testing.T) {
	t.Parallel()
	result := generateProxySSLName("coffee-v1", "default")
	if result != "coffee-v1.default.svc" {
		t.Errorf("generateProxySSLName(coffee-v1, default) returned %v but expected coffee-v1.default.svc", result)
	}
}

func TestIsTLSEnabled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstream   conf_v1.Upstream
		spiffeCert bool
		nsmEgress  bool
		expected   bool
	}{
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: false,
				},
			},
			spiffeCert: false,
			expected:   false,
		},
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: false,
				},
			},
			spiffeCert: true,
			expected:   true,
		},
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: true,
				},
			},
			spiffeCert: true,
			expected:   true,
		},
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: true,
				},
			},
			spiffeCert: false,
			expected:   true,
		},
		{
			upstream: conf_v1.Upstream{
				TLS: conf_v1.UpstreamTLS{
					Enable: true,
				},
			},
			nsmEgress:  true,
			spiffeCert: false,
			expected:   false,
		},
	}

	for _, test := range tests {
		result := isTLSEnabled(test.upstream, test.spiffeCert, test.nsmEgress)
		if result != test.expected {
			t.Errorf("isTLSEnabled(%v, %v) returned %v but expected %v", test.upstream, test.spiffeCert, result, test.expected)
		}
	}
}

func TestGenerateRewrites(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path         string
		proxy        *conf_v1.ActionProxy
		internal     bool
		originalPath string
		grpcEnabled  bool
		expected     []string
		msg          string
	}{
		{
			proxy:    nil,
			expected: nil,
			msg:      "action isn't proxy",
		},
		{
			proxy: &conf_v1.ActionProxy{
				RewritePath: "",
			},
			expected: nil,
			msg:      "no rewrite is configured",
		},
		{
			path: "/path",
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: nil,
			msg:      "non-regex rewrite for non-internal location is not needed",
		},
		{
			path:     "/_internal_path",
			internal: true,
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			originalPath: "/path",
			expected:     []string{`^ $request_uri_no_args`, `"^/path(.*)$" "/rewrite$1" break`},
			msg:          "non-regex rewrite for internal location",
		},
		{
			path:     "~/regex",
			internal: true,
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			originalPath: "/path",
			expected:     []string{`^ $request_uri_no_args`, `"^/path(.*)$" "/rewrite$1" break`},
			msg:          "regex rewrite for internal location",
		},
		{
			path:     "~/regex",
			internal: false,
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: []string{`"^/regex" "/rewrite" break`},
			msg:      "regex rewrite for non-internal location",
		},
		{
			path:     "/_internal_path",
			internal: true,
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			originalPath: "/path",
			grpcEnabled:  true,
			expected:     []string{`^ $request_uri_no_args`, `"^/path(.*)$" "/rewrite$1" break`},
			msg:          "non-regex rewrite for internal location with grpc enabled",
		},
		{
			path:         "/_internal_path",
			internal:     true,
			originalPath: "/path",
			grpcEnabled:  true,
			expected:     []string{`^ $request_uri break`},
			msg:          "empty rewrite for internal location with grpc enabled",
		},
	}

	for _, test := range tests {
		result := generateRewrites(test.path, test.proxy, test.internal, test.originalPath, test.grpcEnabled)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("generateRewrites() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGenerateProxyPassRewrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path     string
		proxy    *conf_v1.ActionProxy
		internal bool
		expected string
	}{
		{
			expected: "",
		},
		{
			internal: true,
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: "",
		},
		{
			path: "/path",
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: "/rewrite",
		},
		{
			path: "=/path",
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: "/rewrite",
		},
		{
			path: "~/path",
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: "",
		},
	}

	for _, test := range tests {
		result := generateProxyPassRewrite(test.path, test.proxy, test.internal)
		if result != test.expected {
			t.Errorf("generateProxyPassRewrite(%v, %v, %v) returned %v but expected %v",
				test.path, test.proxy, test.internal, result, test.expected)
		}
	}
}

func TestGenerateProxySetHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proxy    *conf_v1.ActionProxy
		expected []version2.Header
		msg      string
	}{
		{
			proxy:    nil,
			expected: []version2.Header{{Name: "Host", Value: "$host"}},
			msg:      "no action proxy",
		},
		{
			proxy:    &conf_v1.ActionProxy{},
			expected: []version2.Header{{Name: "Host", Value: "$host"}},
			msg:      "empty action proxy",
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Set: []conf_v1.Header{
						{
							Name:  "Header-Name",
							Value: "HeaderValue",
						},
					},
				},
			},
			expected: []version2.Header{
				{
					Name:  "Header-Name",
					Value: "HeaderValue",
				},
				{
					Name:  "Host",
					Value: "$host",
				},
			},
			msg: "set headers without host",
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Set: []conf_v1.Header{
						{
							Name:  "Header-Name",
							Value: "HeaderValue",
						},
						{
							Name:  "Host",
							Value: "example.com",
						},
					},
				},
			},
			expected: []version2.Header{
				{
					Name:  "Header-Name",
					Value: "HeaderValue",
				},
				{
					Name:  "Host",
					Value: "example.com",
				},
			},
			msg: "set headers with host capitalized",
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Set: []conf_v1.Header{
						{
							Name:  "Header-Name",
							Value: "HeaderValue",
						},
						{
							Name:  "hoST",
							Value: "example.com",
						},
					},
				},
			},
			expected: []version2.Header{
				{
					Name:  "Header-Name",
					Value: "HeaderValue",
				},
				{
					Name:  "hoST",
					Value: "example.com",
				},
			},
			msg: "set headers with host in mixed case",
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Set: []conf_v1.Header{
						{
							Name:  "Header-Name",
							Value: "HeaderValue",
						},
						{
							Name:  "Host",
							Value: "one.example.com",
						},
						{
							Name:  "Host",
							Value: "two.example.com",
						},
					},
				},
			},
			expected: []version2.Header{
				{
					Name:  "Header-Name",
					Value: "HeaderValue",
				},
				{
					Name:  "Host",
					Value: "one.example.com",
				},
				{
					Name:  "Host",
					Value: "two.example.com",
				},
			},
			msg: "set headers with multiple hosts",
		},
	}

	for _, test := range tests {
		result := generateProxySetHeaders(test.proxy)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("generateProxySetHeaders() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGenerateProxyPassRequestHeaders(t *testing.T) {
	t.Parallel()
	passTrue := true
	passFalse := false
	tests := []struct {
		proxy    *conf_v1.ActionProxy
		expected bool
	}{
		{
			proxy:    nil,
			expected: true,
		},
		{
			proxy:    &conf_v1.ActionProxy{},
			expected: true,
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Pass: nil,
				},
			},
			expected: true,
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Pass: &passTrue,
				},
			},
			expected: true,
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Pass: &passFalse,
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		result := generateProxyPassRequestHeaders(test.proxy)
		if result != test.expected {
			t.Errorf("generateProxyPassRequestHeaders(%v) returned %v but expected %v", test.proxy, result, test.expected)
		}
	}
}

func TestGenerateProxyHideHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proxy    *conf_v1.ActionProxy
		expected []string
	}{
		{
			proxy:    nil,
			expected: nil,
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: nil,
			},
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: &conf_v1.ProxyResponseHeaders{
					Hide: []string{"Header", "Header-2"},
				},
			},
			expected: []string{"Header", "Header-2"},
		},
	}

	for _, test := range tests {
		result := generateProxyHideHeaders(test.proxy)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateProxyHideHeaders(%v) returned %v but expected %v", test.proxy, result, test.expected)
		}
	}
}

func TestGenerateProxyPassHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proxy    *conf_v1.ActionProxy
		expected []string
	}{
		{
			proxy:    nil,
			expected: nil,
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: nil,
			},
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: &conf_v1.ProxyResponseHeaders{
					Pass: []string{"Header", "Header-2"},
				},
			},
			expected: []string{"Header", "Header-2"},
		},
	}

	for _, test := range tests {
		result := generateProxyPassHeaders(test.proxy)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateProxyPassHeaders(%v) returned %v but expected %v", test.proxy, result, test.expected)
		}
	}
}

func TestGenerateProxyIgnoreHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proxy    *conf_v1.ActionProxy
		expected string
	}{
		{
			proxy:    nil,
			expected: "",
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: nil,
			},
			expected: "",
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: &conf_v1.ProxyResponseHeaders{
					Ignore: []string{"Header", "Header-2"},
				},
			},
			expected: "Header Header-2",
		},
	}

	for _, test := range tests {
		result := generateProxyIgnoreHeaders(test.proxy)
		if result != test.expected {
			t.Errorf("generateProxyIgnoreHeaders(%v) returned %v but expected %v", test.proxy, result, test.expected)
		}
	}
}

func TestGenerateProxyAddHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proxy    *conf_v1.ActionProxy
		expected []version2.AddHeader
	}{
		{
			proxy:    nil,
			expected: nil,
		},
		{
			proxy:    &conf_v1.ActionProxy{},
			expected: nil,
		},
		{
			proxy: &conf_v1.ActionProxy{
				ResponseHeaders: &conf_v1.ProxyResponseHeaders{
					Add: []conf_v1.AddHeader{
						{
							Header: conf_v1.Header{
								Name:  "Header-Name",
								Value: "HeaderValue",
							},
							Always: true,
						},
						{
							Header: conf_v1.Header{
								Name:  "Server",
								Value: "myServer",
							},
							Always: false,
						},
					},
				},
			},
			expected: []version2.AddHeader{
				{
					Header: version2.Header{
						Name:  "Header-Name",
						Value: "HeaderValue",
					},
					Always: true,
				},
				{
					Header: version2.Header{
						Name:  "Server",
						Value: "myServer",
					},
					Always: false,
				},
			},
		},
	}

	for _, test := range tests {
		result := generateProxyAddHeaders(test.proxy)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateProxyAddHeaders(%v) returned %v but expected %v", test.proxy, result, test.expected)
		}
	}
}

func TestGetUpstreamResourceLabels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		owner    runtime.Object
		expected version2.UpstreamLabels
	}{
		{
			owner:    nil,
			expected: version2.UpstreamLabels{},
		},
		{
			owner: &conf_v1.VirtualServer{
				ObjectMeta: meta_v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "name",
				},
			},
			expected: version2.UpstreamLabels{
				ResourceNamespace: "namespace",
				ResourceName:      "name",
				ResourceType:      "virtualserver",
			},
		},
		{
			owner: &conf_v1.VirtualServerRoute{
				ObjectMeta: meta_v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "name",
				},
			},
			expected: version2.UpstreamLabels{
				ResourceNamespace: "namespace",
				ResourceName:      "name",
				ResourceType:      "virtualserverroute",
			},
		},
	}
	for _, test := range tests {
		result := getUpstreamResourceLabels(test.owner)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("getUpstreamResourceLabels(%+v) returned %+v but expected %+v", test.owner, result, test.expected)
		}
	}
}

func TestAddWafConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wafInput     *conf_v1.WAF
		polKey       string
		polNamespace string
		apResources  *appProtectResourcesForVS
		wafConfig    *version2.WAF
		expected     *validationResults
		msg          string
	}{
		{
			wafInput: &conf_v1.WAF{
				Enable: true,
			},
			polKey:       "default/waf-policy",
			polNamespace: "default",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{},
				LogConfs: map[string]string{},
			},
			wafConfig: &version2.WAF{
				Enable: "on",
			},
			expected: &validationResults{isError: false},
			msg:      "valid waf config, default App Protect config",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "dataguard-alarm",
				SecurityLog: &conf_v1.SecurityLog{
					Enable:    true,
					ApLogConf: "logconf",
					LogDest:   "syslog:server=127.0.0.1:514",
				},
			},
			polKey:       "default/waf-policy",
			polNamespace: "default",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{
					"default/dataguard-alarm": "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				},
				LogConfs: map[string]string{
					"default/logconf": "/etc/nginx/waf/nac-logconfs/default-logconf",
				},
			},
			wafConfig: &version2.WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			expected: &validationResults{isError: false},
			msg:      "valid waf config",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "dataguard-alarm",
				SecurityLogs: []*conf_v1.SecurityLog{
					{
						Enable:    true,
						ApLogConf: "logconf",
						LogDest:   "syslog:server=127.0.0.1:514",
					},
				},
			},
			polKey:       "default/waf-policy",
			polNamespace: "default",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{
					"default/dataguard-alarm": "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				},
				LogConfs: map[string]string{
					"default/logconf": "/etc/nginx/waf/nac-logconfs/default-logconf",
				},
			},
			wafConfig: &version2.WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			expected: &validationResults{isError: false},
			msg:      "valid waf config",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "default/dataguard-alarm",
				SecurityLog: &conf_v1.SecurityLog{
					Enable:    true,
					ApLogConf: "default/logconf",
					LogDest:   "syslog:server=127.0.0.1:514",
				},
			},
			polKey:       "default/waf-policy",
			polNamespace: "",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{
					"default/dataguard-alarm": "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				},
				LogConfs: map[string]string{},
			},
			wafConfig: &version2.WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			expected: &validationResults{
				isError: true,
				warnings: []string{
					`WAF policy default/waf-policy references an invalid or non-existing log config default/logconf`,
				},
			},
			msg: "invalid waf config, apLogConf references non-existing log conf",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "default/dataguard-alarm",
				SecurityLog: &conf_v1.SecurityLog{
					Enable:  true,
					LogDest: "syslog:server=127.0.0.1:514",
				},
			},
			polKey:       "default/waf-policy",
			polNamespace: "",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{},
				LogConfs: map[string]string{
					"default/logconf": "/etc/nginx/waf/nac-logconfs/default-logconf",
				},
			},
			wafConfig: &version2.WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				ApSecurityLogEnable: true,
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/default-logconf"},
			},
			expected: &validationResults{
				isError: true,
				warnings: []string{
					`WAF policy default/waf-policy references an invalid or non-existing App Protect policy default/dataguard-alarm`,
				},
			},
			msg: "invalid waf config, apLogConf references non-existing ap conf",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "ns1/dataguard-alarm",
				SecurityLog: &conf_v1.SecurityLog{
					Enable:    true,
					ApLogConf: "ns2/logconf",
					LogDest:   "syslog:server=127.0.0.1:514",
				},
			},
			polKey:       "default/waf-policy",
			polNamespace: "",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{
					"ns1/dataguard-alarm": "/etc/nginx/waf/nac-policies/ns1-dataguard-alarm",
				},
				LogConfs: map[string]string{
					"ns2/logconf": "/etc/nginx/waf/nac-logconfs/ns2-logconf",
				},
			},
			wafConfig: &version2.WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/ns1-dataguard-alarm",
				ApSecurityLogEnable: true,
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/ns2-logconf"},
			},
			expected: &validationResults{},
			msg:      "valid waf config, cross ns reference",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   false,
				ApPolicy: "dataguard-alarm",
			},
			polKey:       "default/waf-policy",
			polNamespace: "default",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{
					"default/dataguard-alarm": "/etc/nginx/waf/nac-policies/ns1-dataguard-alarm",
				},
				LogConfs: map[string]string{
					"default/logconf": "/etc/nginx/waf/nac-logconfs/ns2-logconf",
				},
			},
			wafConfig: &version2.WAF{
				Enable:   "off",
				ApPolicy: "/etc/nginx/waf/nac-policies/ns1-dataguard-alarm",
			},
			expected: &validationResults{},
			msg:      "valid waf config, disable waf",
		},
		{
			wafInput: &conf_v1.WAF{
				Enable:   true,
				ApBundle: "NginxDefaultPolicy.tgz",
				SecurityLog: &conf_v1.SecurityLog{
					Enable:      true,
					ApLogBundle: "secops_dashboard.tgz",
					LogDest:     "syslog:server=127.0.0.1:1514",
				},
			},
			polKey:       "default/waf-policy",
			polNamespace: "",
			apResources: &appProtectResourcesForVS{
				Policies: map[string]string{
					"ns1/dataguard-alarm": "/etc/nginx/waf/nac-policies/ns1-dataguard-alarm",
				},
				LogConfs: map[string]string{
					"ns2/logconf": "/etc/nginx/waf/nac-logconfs/ns2-logconf",
				},
			},
			wafConfig: &version2.WAF{
				ApPolicy:            "/etc/nginx/waf/nac-policies/ns1-dataguard-alarm",
				ApSecurityLogEnable: true,
				ApLogConf:           []string{"/etc/nginx/waf/nac-logconfs/ns2-logconf"},
			},
			expected: &validationResults{},
			msg:      "valid waf config using bundle",
		},
	}

	for _, test := range tests {
		polCfg := newPoliciesConfig(&fakeBV)
		result := polCfg.addWAFConfig(context.Background(), test.wafInput, test.polKey, test.polNamespace, test.apResources)
		if diff := cmp.Diff(test.expected.warnings, result.warnings); diff != "" {
			t.Errorf("policiesCfg.addWAFConfig() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGenerateTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value, expected string
	}{
		{
			value:    "0s",
			expected: "0s",
		},
		{
			value:    "0",
			expected: "0s",
		},
		{
			value:    "1h",
			expected: "1h",
		},
		{
			value:    "1h 30m",
			expected: "1h30m",
		},
	}

	for _, test := range tests {
		result := generateTime(test.value)
		if result != test.expected {
			t.Errorf("generateTime(%q) returned %q but expected %q", test.value, result, test.expected)
		}
	}
}

func TestGenerateTimeWithDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value, defaultValue, expected string
	}{
		{
			value:        "1h 30m",
			defaultValue: "",
			expected:     "1h30m",
		},
		{
			value:        "",
			defaultValue: "60s",
			expected:     "60s",
		},
		{
			value:        "",
			defaultValue: "test",
			expected:     "test",
		},
	}

	for _, test := range tests {
		result := generateTimeWithDefault(test.value, test.defaultValue)
		if result != test.expected {
			t.Errorf("generateTimeWithDefault(%q, %q) returned %q but expected %q", test.value, test.defaultValue, result, test.expected)
		}
	}
}

var (
	baseCfgParams = ConfigParams{
		ServerTokens:    "off",
		Keepalive:       16,
		ServerSnippets:  []string{"# server snippet"},
		ProxyProtocol:   true,
		SetRealIPFrom:   []string{"0.0.0.0/0"},
		RealIPHeader:    "X-Real-IP",
		RealIPRecursive: true,
	}

	virtualServerExWithGunzipOn = VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host:   "cafe.example.com",
				Gunzip: true,
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

	virtualServerExWithGunzipOff = VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host:   "cafe.example.com",
				Gunzip: false,
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

	virtualServerExWithNoGunzip = VirtualServerEx{
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

	virtualServerExWithCustomHTTPAndHTTPSListeners = VirtualServerEx{
		HTTPPort:  8083,
		HTTPSPort: 8443,
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Listener: &conf_v1.VirtualServerListener{
					HTTP:  "http-8083",
					HTTPS: "https-8443",
				},
			},
		},
	}

	virtualServerExWithCustomHTTPListener = VirtualServerEx{
		HTTPPort: 8083,
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Listener: &conf_v1.VirtualServerListener{
					HTTP: "http-8083",
				},
			},
		},
	}

	virtualServerExWithCustomHTTPSListener = VirtualServerEx{
		HTTPSPort: 8443,
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Listener: &conf_v1.VirtualServerListener{
					HTTPS: "https-8443",
				},
			},
		},
	}

	virtualServerExWithCustomHTTPAndHTTPSIPListeners = VirtualServerEx{
		HTTPPort:  8083,
		HTTPSPort: 8443,
		HTTPIPv4:  "192.168.0.2",
		HTTPIPv6:  "::1",
		HTTPSIPv4: "192.168.0.6",
		HTTPSIPv6: "::2",

		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Listener: &conf_v1.VirtualServerListener{
					HTTP:  "http-8083",
					HTTPS: "https-8443",
				},
			},
		},
	}

	virtualServerExWithCustomHTTPIPListener = VirtualServerEx{
		HTTPPort: 8083,
		HTTPIPv4: "192.168.0.2",
		HTTPIPv6: "::1",

		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Listener: &conf_v1.VirtualServerListener{
					HTTP: "http-8083",
				},
			},
		},
	}

	virtualServerExWithCustomHTTPSIPListener = VirtualServerEx{
		HTTPSPort: 8443,
		HTTPSIPv4: "192.168.0.6",
		HTTPSIPv6: "::2",
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Listener: &conf_v1.VirtualServerListener{
					HTTPS: "https-8443",
				},
			},
		},
	}

	virtualServerExWithNilListener = VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host:     "cafe.example.com",
				Listener: nil,
			},
		},
	}

	fakeBV = fakeBundleValidator{}
)

type fakeBundleValidator struct{}

func (*fakeBundleValidator) validate(bundle string) (string, error) {
	bundle = fmt.Sprintf("/fake/bundle/path/%s", bundle)
	if strings.Contains(bundle, "invalid") {
		return bundle, fmt.Errorf("invalid bundle %s", bundle)
	}
	return bundle, nil
}

func TestRFC1123ToSnake(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid",
			input:    "api-policy-1",
			expected: "api_policy_1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !cmp.Equal(rfc1123ToSnake(tt.input), tt.expected) {
				t.Error(cmp.Diff(rfc1123ToSnake(tt.input), tt.expected))
			}
		})
	}
}
