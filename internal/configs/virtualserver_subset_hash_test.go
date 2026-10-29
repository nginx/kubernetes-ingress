package configs

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildHashSubsetEndpointGroups(t *testing.T) {
	t.Parallel()
	if groups := buildHashSubsetEndpointGroups([]string{"10.0.0.1:80"}, 0); groups != nil {
		t.Errorf("buildHashSubsetEndpointGroups() = %v for zero subset size, want nil", groups)
	}

	endpoints := []string{
		"10.0.0.10:80",
		"10.0.0.2:80",
		"10.0.0.1:80",
		"10.0.0.3:80",
		"10.0.0.4:80",
		"10.0.0.5:80",
		"10.0.0.6:80",
		"10.0.0.7:80",
		"10.0.0.8:80",
		"10.0.0.9:80",
	}

	want := [][]string{
		{"10.0.0.10:80", "10.0.0.1:80", "10.0.0.2:80"},
		{"10.0.0.3:80", "10.0.0.4:80", "10.0.0.5:80"},
		{"10.0.0.6:80", "10.0.0.7:80", "10.0.0.8:80"},
		{"10.0.0.9:80", "10.0.0.10:80", "10.0.0.1:80"},
	}

	if diff := cmp.Diff(want, buildHashSubsetEndpointGroups(endpoints, 3)); diff != "" {
		t.Errorf("buildHashSubsetEndpointGroups() mismatch (-want +got):\n%s", diff)
	}
}

func TestGenerateVirtualServerConfigWithHashSubset(t *testing.T) {
	t.Parallel()

	virtualServerEx := VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{Name: "cafe", Namespace: "default"},
			Spec: conf_v1.VirtualServerSpec{
				Host: "cafe.example.com",
				Upstreams: []conf_v1.Upstream{
					{
						Name:    "playback",
						Service: "playback-svc",
						Port:    80,
						HashSubset: &conf_v1.HashSubset{
							Key:  "$arg_user",
							Size: 3,
						},
					},
				},
				Routes: []conf_v1.Route{{
					Path: "/",
					Action: &conf_v1.Action{
						Pass: "playback",
					},
				}},
			},
		},
		Endpoints: map[string][]string{
			"default/playback-svc:80": {
				"10.0.0.10:80",
				"10.0.0.2:80",
				"10.0.0.1:80",
				"10.0.0.3:80",
				"10.0.0.4:80",
				"10.0.0.5:80",
				"10.0.0.6:80",
				"10.0.0.7:80",
				"10.0.0.8:80",
				"10.0.0.9:80",
			},
		},
	}

	vsc := newVirtualServerConfigurator(&baseCfgParams, true, false, &StaticConfigParams{}, false, &fakeBV)
	got, warnings := vsc.GenerateVirtualServerConfig(&virtualServerEx, nil, nil)
	if len(warnings) != 0 {
		t.Fatalf("GenerateVirtualServerConfig() returned warnings: %v", warnings)
	}

	wantUpstreams := []version2.Upstream{
		{
			Name:     "vs_default_cafe_playback_hash_subset_1",
			LBMethod: "random",
			Servers: []version2.UpstreamServer{
				{Address: "10.0.0.10:80"},
				{Address: "10.0.0.1:80"},
				{Address: "10.0.0.2:80"},
			},
		},
		{
			Name:     "vs_default_cafe_playback_hash_subset_2",
			LBMethod: "random",
			Servers: []version2.UpstreamServer{
				{Address: "10.0.0.3:80"},
				{Address: "10.0.0.4:80"},
				{Address: "10.0.0.5:80"},
			},
		},
		{
			Name:     "vs_default_cafe_playback_hash_subset_3",
			LBMethod: "random",
			Servers: []version2.UpstreamServer{
				{Address: "10.0.0.6:80"},
				{Address: "10.0.0.7:80"},
				{Address: "10.0.0.8:80"},
			},
		},
		{
			Name:     "vs_default_cafe_playback_hash_subset_4",
			LBMethod: "random",
			Servers: []version2.UpstreamServer{
				{Address: "10.0.0.10:80"},
				{Address: "10.0.0.1:80"},
				{Address: "10.0.0.9:80"},
			},
		},
	}

	for index, upstream := range wantUpstreams {
		if got.Upstreams[index].Name != upstream.Name || got.Upstreams[index].LBMethod != upstream.LBMethod {
			t.Errorf("upstream %d = %#v, want name %q with lb-method %q", index, got.Upstreams[index], upstream.Name, upstream.LBMethod)
		}
		if diff := cmp.Diff(upstream.Servers, got.Upstreams[index].Servers); diff != "" {
			t.Errorf("upstream %s servers mismatch (-want +got):\n%s", upstream.Name, diff)
		}
	}

	wantSplitClient := version2.SplitClient{
		Source:   "$arg_user",
		Variable: "$vs_default_cafe_playback_hash_subset",
		Distributions: []version2.Distribution{
			{Weight: "25.00%", Value: "vs_default_cafe_playback_hash_subset_1"},
			{Weight: "25.00%", Value: "vs_default_cafe_playback_hash_subset_2"},
			{Weight: "25.00%", Value: "vs_default_cafe_playback_hash_subset_3"},
			{Weight: "*", Value: "vs_default_cafe_playback_hash_subset_4"},
		},
	}
	if diff := cmp.Diff([]version2.SplitClient{wantSplitClient}, got.SplitClients); diff != "" {
		t.Errorf("SplitClients mismatch (-want +got):\n%s", diff)
	}

	if got := got.Server.Locations[0].ProxyPass; got != "http://$vs_default_cafe_playback_hash_subset" {
		t.Errorf("location ProxyPass = %q, want subset variable", got)
	}

	executor, err := version2.NewTemplateExecutor("version2/nginx.virtualserver.tmpl", "version2/nginx.transportserver.tmpl", "")
	if err != nil {
		t.Fatalf("NewTemplateExecutor() error: %v", err)
	}
	rendered, err := executor.ExecuteVirtualServerTemplate(&got)
	if err != nil {
		t.Fatalf("ExecuteVirtualServerTemplate() error: %v", err)
	}
	for _, expected := range []string{
		"split_clients $arg_user $vs_default_cafe_playback_hash_subset {",
		"25.00% vs_default_cafe_playback_hash_subset_1;",
		"* vs_default_cafe_playback_hash_subset_4;",
		"proxy_pass http://$vs_default_cafe_playback_hash_subset;",
	} {
		if !strings.Contains(string(rendered), expected) {
			t.Errorf("rendered NGINX config does not contain %q", expected)
		}
	}
}
