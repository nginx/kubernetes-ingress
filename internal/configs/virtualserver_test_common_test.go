package configs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

var (
	l             = slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	ctx           = nl.ContextWithLogger(context.Background(), l)
	baseCfgParams = ConfigParams{
		Context:         ctx,
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

	virtualServerExWithAddHeaderInheritMerge = VirtualServerEx{
		VirtualServer: &conf_v1.VirtualServer{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "cafe",
				Namespace: "default",
			},
			Spec: conf_v1.VirtualServerSpec{
				Host:             "cafe.example.com",
				AddHeaderInherit: "merge",
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
