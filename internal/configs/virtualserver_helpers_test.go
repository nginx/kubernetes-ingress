package configs

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
		{
			serviceNamespace: "tea",
			serviceName:      "tea-svc",
			port:             8080,
			subselector:      nil,
			expected:         "tea/tea-svc:8080",
		},
	}

	for _, test := range tests {
		result := GenerateEndpointsKey(test.serviceNamespace, test.serviceName, test.subselector, test.port)
		if result != test.expected {
			t.Errorf("GenerateEndpointsKey() returned %q but expected %q", result, test.expected)
		}
	}
}

func TestParseServiceReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		serviceRef       string
		defaultNamespace string
		expectedNS       string
		expectedSvc      string
	}{
		{
			serviceRef:       "coffee-svc",
			defaultNamespace: "coffee",
			expectedNS:       "coffee",
			expectedSvc:      "coffee-svc",
		},
		{
			serviceRef:       "tea/tea-svc",
			defaultNamespace: "cafe",
			expectedNS:       "tea",
			expectedSvc:      "tea-svc",
		},
	}

	for _, test := range tests {
		namespace, serviceName := ParseServiceReference(test.serviceRef, test.defaultNamespace)
		if namespace != test.expectedNS || serviceName != test.expectedSvc {
			t.Errorf("parseServiceReference(%q, %q) returned (%q, %q) but expected (%q, %q)",
				test.serviceRef, test.defaultNamespace, namespace, serviceName, test.expectedNS, test.expectedSvc)
		}
	}
}

func TestParseResourceReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		resourceRef      string
		defaultNamespace string
		expectedNS       string
		expectedResource string
	}{
		{
			name:             "coffee service without namespace",
			resourceRef:      "coffee-svc",
			defaultNamespace: "coffee",
			expectedNS:       "coffee",
			expectedResource: "coffee-svc",
		},
		{
			name:             "tea service with namespace",
			resourceRef:      "tea/tea-svc",
			defaultNamespace: "cafe",
			expectedNS:       "tea",
			expectedResource: "tea-svc",
		},
		{
			name:             "tls secret with namespace",
			resourceRef:      "default/tls-secret",
			defaultNamespace: "cafe",
			expectedNS:       "default",
			expectedResource: "tls-secret",
		},
		{
			name:             "tls secret without namespace",
			resourceRef:      "tls-secret",
			defaultNamespace: "cafe",
			expectedNS:       "cafe",
			expectedResource: "tls-secret",
		},
		{
			name:             "policy without namespace",
			resourceRef:      "access-control-policy",
			defaultNamespace: "default",
			expectedNS:       "default",
			expectedResource: "access-control-policy",
		},
		{
			name:             "policy with namespace",
			resourceRef:      "ac-ns/access-control-policy",
			defaultNamespace: "default",
			expectedNS:       "ac-ns",
			expectedResource: "access-control-policy",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			namespace, resourceName := ParseResourceReference(test.resourceRef, test.defaultNamespace)
			if namespace != test.expectedNS || resourceName != test.expectedResource {
				t.Errorf("ParseResourceReference(%q, %q) returned (%q, %q) but expected (%q, %q)",
					test.resourceRef, test.defaultNamespace, namespace, resourceName, test.expectedNS, test.expectedResource)
			}
		})
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

func TestRemoveDuplicateMaps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		maps     []version2.Map
		expected []version2.Map
	}{
		{
			maps: []version2.Map{
				{Source: "test", Variable: "test"},
				{Source: "test", Variable: "test"},
				{Source: "test2", Variable: "test2"},
				{Source: "test3", Variable: "test3"},
			},
			expected: []version2.Map{
				{Source: "test", Variable: "test"},
				{Source: "test2", Variable: "test2"},
				{Source: "test3", Variable: "test3"},
			},
		},
		{
			maps: []version2.Map{
				{Source: "test", Variable: "test"},
				{Source: "test", Variable: "test"},
				{Source: "test2", Variable: "test2"},
				{Source: "test3", Variable: "test3"},
				{Source: "test3", Variable: "test3"},
			},
			expected: []version2.Map{
				{Source: "test", Variable: "test"},
				{Source: "test2", Variable: "test2"},
				{Source: "test3", Variable: "test3"},
			},
		},
		{
			maps: []version2.Map{
				{Source: "test", Variable: "no"},
				{Source: "test", Variable: "test"},
				{Source: "test2", Variable: "test2"},
				{Source: "test3", Variable: "test3"},
				{Source: "test3", Variable: "test3"},
			},
			expected: []version2.Map{
				{Source: "test", Variable: "no"},
				{Source: "test", Variable: "test"},
				{Source: "test2", Variable: "test2"},
				{Source: "test3", Variable: "test3"},
			},
		},
	}
	for _, test := range tests {
		result := removeDuplicateMaps(test.maps)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("removeDuplicateMaps() returned \n%v, but expected \n%v", result, test.expected)
		}
	}
}

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

func TestHasDuplicateMapDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		m        version2.Map
		msg      string
		expected bool
	}{
		{
			m: version2.Map{
				Source:   "$my_source_var",
				Variable: "$my_targetvar",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: "my_result1",
					},
					{
						Value:  "default",
						Result: "my_result2",
					},
					{
						Value:  "other_value",
						Result: "different_value",
					},
				},
			},
			msg:      "has duplicate defaults",
			expected: true,
		},
		{
			m: version2.Map{
				Source:   "$my_source_var",
				Variable: "$my_targetvar",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: "my_result1",
					},
					{
						Value:  "other_value",
						Result: "different_value",
					},
				},
			},
			msg:      "doesn't have duplicate defaults",
			expected: false,
		},
		{
			m: version2.Map{
				Source:   "$my_source_var",
				Variable: "$my_targetvar",
				Parameters: []version2.Parameter{
					{
						Value:  "default",
						Result: "my_result1",
					},
					{
						Value:  "other_value",
						Result: "duplicate_value",
					},
					{
						Value:  "other_value",
						Result: "duplicate_value",
					},
				},
			},
			msg:      "has other duplicate values",
			expected: false,
		},
	}

	for _, test := range tests {
		result := hasDuplicateMapDefaults(&test.m)

		if result != test.expected {
			t.Errorf("hasDuplicateMapDefaults() returned \n%t, but expected \n%t for the case of %v", result, test.expected, test.msg)
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
			conf_v1.Upstream{Keepalive: new(32), Service: name, Port: 80},
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
			conf_v1.Upstream{Keepalive: new(0), Service: name, Port: 80},
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
		claim        string
		ownerDetails policyOwnerDetails
		expected     string
	}{
		{
			claim: "consumer_group.type",
			ownerDetails: policyOwnerDetails{
				ownerNamespace:  "default",
				ownerName:       "webapp",
				parentNamespace: "default",
				parentName:      "webapp",
				parentType:      "vs",
			},
			expected: "$jwt_default_webapp_vs_consumer_group_type",
		},
		{
			claim: "type",
			ownerDetails: policyOwnerDetails{
				ownerNamespace:  "default",
				ownerName:       "webapp",
				parentNamespace: "default",
				parentName:      "webapp",
				parentType:      "vs",
			},
			expected: "$jwt_default_webapp_vs_type",
		},
		{
			claim: "a.b.c",
			ownerDetails: policyOwnerDetails{
				ownerNamespace:  "default",
				ownerName:       "webapp",
				parentNamespace: "default",
				parentName:      "webapp",
				parentType:      "vs",
			},
			expected: "$jwt_default_webapp_vs_a_b_c",
		},
	}

	for _, test := range tests {
		result := generateAuthJwtClaimSetVariable(test.claim, test.ownerDetails)
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
		ClientBodyBufferSize: "16k",
		ProxyMaxTempFileSize: "1024m",
		ProxyBuffering:       true,
		ProxyBuffers:         "8 4k",
		ProxyBufferSize:      "4k",
		ProxyBusyBuffersSize: "8k", LocationSnippets: []string{"# location snippet"},
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
		ClientBodyBufferSize:     "16k",
		ProxyMaxTempFileSize:     "1024m",
		ProxyBuffering:           true,
		ProxyBuffers:             "8 4k",
		ProxyBufferSize:          "4k",
		ProxyBusyBuffersSize:     "8k",
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

	result := generateLocationForProxying(path, upstreamName, conf_v1.Upstream{}, &cfgParams, nil, false, 0, "", nil, "", vsLocSnippets, false, "", "", "")
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
		ClientBodyBufferSize: "16k",
		ProxyMaxTempFileSize: "1024m",
		ProxyBuffering:       true,
		ProxyBuffers:         "8 4k",
		ProxyBufferSize:      "4k",
		ProxyBusyBuffersSize: "8k",
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
		ClientBodyBufferSize:     "16k",
		ProxyMaxTempFileSize:     "1024m",
		ProxyBuffering:           true,
		ProxyBuffers:             "8 4k",
		ProxyBufferSize:          "4k",
		ProxyBusyBuffersSize:     "8k",
		ProxyPass:                "http://test-upstream",
		ProxyNextUpstream:        "error timeout",
		ProxyNextUpstreamTimeout: "0s",
		ProxyNextUpstreamTries:   0,
		ProxyPassRequestHeaders:  true,
		ProxySetHeaders:          []version2.Header{{Name: "Host", Value: "$host"}},
		GRPCPass:                 "grpc://test-upstream",
	}

	result := generateLocationForProxying(path, upstreamName, conf_v1.Upstream{Type: "grpc"}, &cfgParams, nil, false, 0, "", nil, "", vsLocSnippets, false, "", "", "")
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
					GRPCStatus:     new(12),
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
				GRPCStatus:          new(12),
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
				Endpoints: map[string][]string{
					"test-namespace/test:8080": {},
				},
			},
			isPlus:               false,
			isResolverConfigured: false,
			expected:             []string{nginx502Server},
			warningsExpected:     true,
			msg:                  "Service exists with no endpoints",
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
					"test-namespace/test:8080": {},
				},
			},
			isPlus:               true,
			isResolverConfigured: false,
			expected:             []string{},
			warningsExpected:     true,
			msg:                  "Service exists with no endpoints (Plus)",
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
			warningsExpected:     false,
			msg:                  "Service unknown, no warning emitted",
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
			warningsExpected:     false,
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
		{
			path:     "^~/images",
			expected: "^~ /images",
		},
		{
			path:     "^~ /images",
			expected: "^~ /images",
		},
		{
			path:     "^~  /images",
			expected: "^~ /images",
		},
		{
			path:     "~\t/api",
			expected: `~ "/api"`,
		},
		{
			path:     "~*\t\t/bar",
			expected: `~* "/bar"`,
		},
		{
			path:     "^~\t/static",
			expected: "^~ /static",
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

func TestGenerateErrorPageDetails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		errorPages     []conf_v1.ErrorPage
		errorLocations []version2.ErrorPageLocation
		owner          runtime.Object
		expected       errorPageDetails
	}{
		{}, // empty
		{
			errorPages: []conf_v1.ErrorPage{
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
			errorLocations: []version2.ErrorPageLocation{
				{
					Name:        "@error_page_0_0",
					DefaultType: "text/plain",
					Return: &version2.Return{
						Text: "All Good",
					},
				},
			},
			owner: &conf_v1.VirtualServer{
				ObjectMeta: meta_v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "name",
				},
			},
			expected: errorPageDetails{
				pages: []conf_v1.ErrorPage{
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
				index: 1,
				owner: &conf_v1.VirtualServer{
					ObjectMeta: meta_v1.ObjectMeta{
						Namespace: "namespace",
						Name:      "name",
					},
				},
			},
		},
	}

	for _, test := range tests {
		result := generateErrorPageDetails(test.errorPages, test.errorLocations, test.owner)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("generateErrorPageDetails() returned %v but expected %v", result, test.expected)
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
		{
			path: "^~/path",
			proxy: &conf_v1.ActionProxy{
				RewritePath: "/rewrite",
			},
			expected: "/rewrite",
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
					Pass: new(true),
				},
			},
			expected: true,
		},
		{
			proxy: &conf_v1.ActionProxy{
				RequestHeaders: &conf_v1.ProxyRequestHeaders{
					Pass: new(false),
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

func TestGetExAuthServicePort(t *testing.T) {
	t.Parallel()

	vsEx := &VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{Name: "test-vs", Namespace: "default"},
		},
	}

	tests := []struct {
		name     string
		cfg      policiesCfg
		expected uint16
	}{
		{
			name: "Ports from policy spec takes precedence over URI port",
			cfg: policiesCfg{
				ExternalAuth: &version2.ExternalAuth{
					URI:          &version2.AuthURI{Port: "80"},
					ServicePorts: []int{9000},
				},
			},
			expected: 9000,
		},
		{
			name: "first port from Ports is used",
			cfg: policiesCfg{
				ExternalAuth: &version2.ExternalAuth{
					ServicePorts: []int{8080, 9000},
				},
			},
			expected: 8080,
		},
		{
			name: "falls back to URI port when Ports is empty",
			cfg: policiesCfg{
				ExternalAuth: &version2.ExternalAuth{
					URI:          &version2.AuthURI{Port: "8443"},
					ServicePorts: []int{},
				},
			},
			expected: 8443,
		},
		{
			name: "falls back to URI port when Ports is nil",
			cfg: policiesCfg{
				ExternalAuth: &version2.ExternalAuth{
					URI: &version2.AuthURI{Port: "3000"},
				},
			},
			expected: 3000,
		},
		{
			name: "defaults to 80 when no Ports and no URI port",
			cfg: policiesCfg{
				ExternalAuth: &version2.ExternalAuth{
					URI: &version2.AuthURI{},
				},
			},
			expected: 80,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vsc := newVirtualServerConfigurator(&ConfigParams{}, false, false, &StaticConfigParams{}, false, &fakeBV)
			got := vsc.getExAuthServicePort(tc.cfg, vsEx)
			if got != tc.expected {
				t.Errorf("getExAuthServicePort() = %d, want %d", got, tc.expected)
			}
		})
	}
}
