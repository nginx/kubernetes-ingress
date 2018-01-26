package templates

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/nginxinc/kubernetes-ingress/nginx-controller/nginx"
)

const nginxIngressTmpl = "nginx.ingress.tmpl"
const nginxMainTmpl = "nginx.tmpl"
const nginxPlusIngressTmpl = "nginx-plus.ingress.tmpl"
const nginxPlusMainTmpl = "nginx-plus.tmpl"

var testUpsHTTP = nginx.UpstreamHTTP{
	Name: "test",
	UpstreamServers: []nginx.UpstreamServer{
		{"127.0.0.1", "8181"},
	},
}

var testUpsStream = nginx.UpstreamStream{
	Name: "test",
	UpstreamServers: []nginx.UpstreamServer{
		{"127.0.0.1", "8181"},
	},
}

var ingCfgHTTP = nginx.IngressNginxConfigHTTP{

	Servers: []nginx.ServerHTTP{
		nginx.ServerHTTP{
			Name:              "test.example.com",
			ServerTokens:      "off",
			StatusZone:        "test.example.com",
			JWTKey:            "/etc/nginx/secrets/key.jwk",
			JWTRealm:          "closed site",
			JWTToken:          "$cookie_auth_token",
			JWTLoginURL:       "https://test.example.com/login",
			SSL:               true,
			SSLCertificate:    "secret.pem",
			SSLCertificateKey: "secret.pem",
			SSLPorts:          []int{443},
			SSLRedirect:       true,
			Locations: []nginx.Location{
				nginx.Location{
					Path:                "/",
					Upstream:            testUpsHTTP,
					ProxyConnectTimeout: "10s",
					ProxyReadTimeout:    "10s",
					ClientMaxBodySize:   "2m",
				},
			},
		},
	},
	Upstreams: []nginx.UpstreamHTTP{testUpsHTTP},
	Keepalive: "16",
}

var ingCfgStream = nginx.IngressNginxConfigStream{

	Server: nginx.ServerStream{
		Ports:               []int{10, 20},
		ServerSnippets:      []string{"snippet"},
		ProxyConnectTimeout: "string_connect_timeout",
		ProxyBufferSize:     "string_buffer_size",
	},
	Upstream: testUpsStream,
}

var mainCfg = nginx.NginxMainConfig{
	ServerNamesHashMaxSize: "512",
	ServerTokens:           "off",
	WorkerProcesses:        "auto",
	WorkerCPUAffinity:      "auto",
}

func TestIngressHTTPForNGINXPlus(t *testing.T) {
	tmpl, err := template.New(nginxPlusIngressTmpl).ParseFiles(nginxPlusIngressTmpl)
	if err != nil {
		t.Fatalf("Failed to parse template file: %v", err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, ingCfgHTTP)
	t.Log(string(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}
}

func TestIngressHTTPForNGINX(t *testing.T) {
	tmpl, err := template.New(nginxIngressTmpl).ParseFiles(nginxIngressTmpl)
	if err != nil {
		t.Fatalf("Failed to parse template file: %v", err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, ingCfgHTTP)
	t.Log(string(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}
}

func TestIngressStreamForNGINXPlus(t *testing.T) {
	tmpl, err := template.New(nginxPlusIngressTmpl).ParseFiles(nginxPlusIngressTmpl)
	if err != nil {
		t.Fatalf("Failed to parse template file: %v", err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, ingCfgStream)
	t.Log(string(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}
}

func TestIngressStreamForNGINX(t *testing.T) {
	tmpl, err := template.New(nginxIngressTmpl).ParseFiles(nginxIngressTmpl)
	if err != nil {
		t.Fatalf("Failed to parse template file: %v", err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, ingCfgStream)
	t.Log(string(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}
}

func TestMainForNGINXPlus(t *testing.T) {
	tmpl, err := template.New(nginxPlusMainTmpl).ParseFiles(nginxPlusMainTmpl)
	if err != nil {
		t.Fatalf("Failed to parse template file: %v", err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, mainCfg)
	t.Log(string(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}
}

func TestMainForNGINX(t *testing.T) {
	tmpl, err := template.New(nginxMainTmpl).ParseFiles(nginxMainTmpl)
	if err != nil {
		t.Fatalf("Failed to parse template file: %v", err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, mainCfg)
	t.Log(string(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}
}
