package nginx

import (
	"bytes"
	"html/template"
	"os"
	"os/exec"
	"path"

	"github.com/golang/glog"
)

// NGINXController Updates NGINX configuration, starts and reloads NGINX
type NGINXController struct {
	resolver       string
	nginxConfdPath string
	nginxCertsPath string
	local          bool
}

// IngressNGINXConfig describes an NGINX configuration
type IngressNGINXConfig struct {
	Upstreams []Upstream
	Servers   []Server
}

// Upstream describes an NGINX upstream
type Upstream struct {
	Name            string
	UpstreamServers []UpstreamServer
}

// UpstreamServer describes a server in an NGINX upstream
type UpstreamServer struct {
	Address string
	Port    string
}

// Server describes an NGINX server
type Server struct {
	Name              string
	Locations         []Location
	SSL               bool
	SSLCertificate    string
	SSLCertificateKey string
}

// Location describes an NGINX location
type Location struct {
	Path     string
	Upstream Upstream
}

// NewUpstreamWithDefaultServer creates an upstream with the default server.
// proxy_pass to an upstream with the default server returns 502.
// We use it for services that have no endpoints
func NewUpstreamWithDefaultServer(name string) Upstream {
	return Upstream{
		Name:            name,
		UpstreamServers: []UpstreamServer{UpstreamServer{Address: "127.0.0.1", Port: "8181"}},
	}
}

// NewNGINXController creates a NGINX controller
func NewNGINXController(resolver string, nginxConfPath string, local bool) (*NGINXController, error) {
	ngxc := NGINXController{
		resolver:       resolver,
		nginxConfdPath: path.Join(nginxConfPath, "conf.d"),
		nginxCertsPath: path.Join(nginxConfPath, "ssl"),
		local:          local,
	}

	if !local {
		ngxc.createCertsDir()
	}

	return &ngxc, nil
}

// DeleteIngress deletes the configuration file, which corresponds for the
// specified ingress from NGINX conf directory
func (nginx *NGINXController) DeleteIngress(name string) {
	filename := nginx.getIngressNGINXConfigFileName(name)
	glog.Infof("deleting %v", filename)

	if !nginx.local {
		if err := os.Remove(filename); err != nil {
			glog.Warningf("Failed to delete %v: %v", filename, err)
		}
	}
}

// AddOrUpdateIngress creates or updates a file with
// the specified configuration for the specified ingress
func (nginx *NGINXController) AddOrUpdateIngress(name string, config IngressNGINXConfig) {
	glog.Infof("Updating NGINX configuration")
	filename := nginx.getIngressNGINXConfigFileName(name)
	nginx.templateIt(config, filename)
}

// AddOrUpdateCertAndKey creates a .pem file wth the cert and the key with the
// specified name
func (nginx *NGINXController) AddOrUpdateCertAndKey(name string, cert string, key string) string {
	pemFileName := nginx.nginxCertsPath + "/" + name + ".pem"

	if !nginx.local {
		pem, err := os.Create(pemFileName)
		if err != nil {
			glog.Fatalf("Couldn't create pem file %v: %v", pemFileName, err)
		}
		defer pem.Close()

		_, err = pem.WriteString(key)
		if err != nil {
			glog.Fatalf("Couldn't write to pem file %v: %v", pemFileName, err)
		}

		_, err = pem.WriteString("\n")
		if err != nil {
			glog.Fatalf("Couldn't write to pem file %v: %v", pemFileName, err)
		}

		_, err = pem.WriteString(cert)
		if err != nil {
			glog.Fatalf("Couldn't write to pem file %v: %v", pemFileName, err)
		}
	}

	return pemFileName
}

func (nginx *NGINXController) getIngressNGINXConfigFileName(name string) string {
	return path.Join(nginx.nginxConfdPath, name+".conf")
}

func (nginx *NGINXController) templateIt(config IngressNGINXConfig, filename string) {
	tmpl, err := template.New("ingress.tmpl").ParseFiles("ingress.tmpl")
	if err != nil {
		glog.Fatal("Failed to parse template file")
	}

	glog.Infof("Writing NGINX conf to %v", filename)

	tmpl.Execute(os.Stdout, config)

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, config); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	} else {
		// print conf to stdout here
	}

	glog.Infof("NGINX configuration file had been updated")
}

// Reload reloads NGINX
func (nginx *NGINXController) Reload() {
	if !nginx.local {
		shellOut("nginx -s reload")
	}
}

// Start starts NGINX
func (nginx *NGINXController) Start() {
	if !nginx.local {
		command := exec.Command("nginx")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		err := command.Start()
		if err != nil {
			glog.Fatalf("Error while starting nginx: %v", err)
		}
		err = command.Wait()
		if err != nil {
			glog.Fatalf("Error while waiting for nginx: %v", err)
		}
	}
}

func (nginx *NGINXController) createCertsDir() {
	if err := os.Mkdir(nginx.nginxCertsPath, os.ModeDir); err != nil {
		glog.Fatalf("Couldn't create directory %v: %v", nginx.nginxCertsPath, err)
	}
}

func shellOut(cmd string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	glog.Infof("executing %s", cmd)

	command := exec.Command("sh", "-c", cmd)
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Start()
	if err != nil {
		glog.Fatalf("Failed to execute %v, err: %v", cmd, err)
	}

	err = command.Wait()
	if err != nil {
		glog.Errorf("Command %v stdout: %q", cmd, stdout.String())
		glog.Errorf("Command %v stderr: %q", cmd, stderr.String())
		glog.Fatalf("Command %v finished with error: %v", cmd, err)
	}
}
