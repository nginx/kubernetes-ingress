package version2

import (
	"bytes"
	"path"
	"sync"
	"text/template"
)

// bufPool reuses bytes.Buffer instances across template executions to avoid
// repeated growSlice allocations. Pre-grown to 32 KB which covers most
// VirtualServer configs without further growth.
var bufPool = sync.Pool{
	New: func() any {
		buf := new(bytes.Buffer)
		buf.Grow(32 * 1024)
		return buf
	},
}

// #nosec G101
const tlsPassthroughHostsTemplateString = `# mapping between TLS Passthrough hosts and unix sockets
{{ range $h, $u := . }}
{{ $h }} {{ $u }};
{{ end }}
`

// TemplateExecutor executes NGINX configuration templates.
type TemplateExecutor struct {
	originalVirtualServerTemplate  *template.Template
	originalTrasportServerTemplate *template.Template
	virtualServerTemplate          *template.Template
	transportServerTemplate        *template.Template
	tlsPassthroughHostsTemplate    *template.Template
	oidcTemplate                   *template.Template
}

// NewTemplateExecutor creates a TemplateExecutor.
func NewTemplateExecutor(virtualServerTemplatePath string, transportServerTemplatePath string, oidcTemplatePath string) (*TemplateExecutor, error) {
	// template names  must be the base name of the template file https://golang.org/pkg/text/template/#Template.ParseFiles

	vsTemplate, err := template.New(path.Base(virtualServerTemplatePath)).Funcs(helperFunctions).ParseFiles(virtualServerTemplatePath)
	if err != nil {
		return nil, err
	}

	tsTemplate, err := template.New(path.Base(transportServerTemplatePath)).Funcs(helperFunctions).ParseFiles(transportServerTemplatePath)
	if err != nil {
		return nil, err
	}

	tlsPassthroughHostsTemplate, err := template.New("unixSockets").Parse(tlsPassthroughHostsTemplateString)
	if err != nil {
		return nil, err
	}

	var oidcTemplate *template.Template
	if oidcTemplatePath != "" {
		oidcTemplate, err = template.New(path.Base(oidcTemplatePath)).Funcs(helperFunctions).ParseFiles(oidcTemplatePath)
		if err != nil {
			return nil, err
		}
	}
	return &TemplateExecutor{
		originalVirtualServerTemplate:  vsTemplate,
		originalTrasportServerTemplate: tsTemplate,
		virtualServerTemplate:          vsTemplate,
		transportServerTemplate:        tsTemplate,
		tlsPassthroughHostsTemplate:    tlsPassthroughHostsTemplate,
		oidcTemplate:                   oidcTemplate,
	}, nil
}

// UpdateVirtualServerTemplate updates the VirtualServer template.
func (te *TemplateExecutor) UpdateVirtualServerTemplate(templateString *string) error {
	newTemplate, err := template.New("virtualServerTemplate").Funcs(helperFunctions).Parse(*templateString)
	if err != nil {
		return err
	}
	te.virtualServerTemplate = newTemplate
	return nil
}

// UpdateTransportServerTemplate updates the TransportServer template.
func (te *TemplateExecutor) UpdateTransportServerTemplate(templateString *string) error {
	newTemplate, err := template.New("transportServerTemplate").Funcs(helperFunctions).Parse(*templateString)
	if err != nil {
		return err
	}
	te.transportServerTemplate = newTemplate
	return nil
}

// ExecuteVirtualServerTemplate generates the content of an NGINX configuration file for a VirtualServer resource.
func (te *TemplateExecutor) ExecuteVirtualServerTemplate(cfg *VirtualServerConfig) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufPool.Put(buf)
	}()
	if err := te.virtualServerTemplate.Execute(buf, cfg); err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// ExecuteTransportServerTemplate generates the content of an NGINX configuration file for a TransportServer resource.
func (te *TemplateExecutor) ExecuteTransportServerTemplate(cfg *TransportServerConfig) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufPool.Put(buf)
	}()
	if err := te.transportServerTemplate.Execute(buf, cfg); err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// UseOriginalVStemplate updates template executor to
// use the original VS template parsed at startup.
func (te *TemplateExecutor) UseOriginalVStemplate() {
	te.virtualServerTemplate = te.originalVirtualServerTemplate
}

// UseOriginalTStemplate updates template executor to
// use the original TS template parsed at startup.
func (te *TemplateExecutor) UseOriginalTStemplate() {
	te.transportServerTemplate = te.originalTrasportServerTemplate
}

// ExecuteTLSPassthroughHostsTemplate generates the content of an NGINX configuration file for mapping between
// TLS Passthrough hosts and the corresponding unix sockets.
func (te *TemplateExecutor) ExecuteTLSPassthroughHostsTemplate(cfg *TLSPassthroughHostsConfig) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufPool.Put(buf)
	}()
	if err := te.tlsPassthroughHostsTemplate.Execute(buf, cfg); err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// ExecuteOIDCTemplate generates the content of an OIDC configuration file.
func (te *TemplateExecutor) ExecuteOIDCTemplate(cfg *OIDC) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufPool.Put(buf)
	}()
	if err := te.oidcTemplate.Execute(buf, cfg); err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}
