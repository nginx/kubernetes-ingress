package version1

import (
	"bytes"
	"path"
	"text/template"
)

// TemplateExecutor executes NGINX configuration templates.
type TemplateExecutor struct {
	originalMainTemplate    *template.Template
	originalIngressTemplate *template.Template
	mainTemplate            *template.Template
	ingressTemplate         *template.Template
}

// NewTemplateExecutor creates a TemplateExecutor.
func NewTemplateExecutor(mainTemplatePath string, ingressTemplatePath string) (*TemplateExecutor, error) {
	// template name must be the base name of the template file https://golang.org/pkg/text/template/#Template.ParseFiles
	nginxTemplate, err := template.New(path.Base(mainTemplatePath)).Funcs(helperFunctions).ParseFiles(mainTemplatePath)
	if err != nil {
		return nil, err
	}

	ingressTemplate, err := template.New(path.Base(ingressTemplatePath)).Funcs(helperFunctions).ParseFiles(ingressTemplatePath)
	if err != nil {
		return nil, err
	}

	return &TemplateExecutor{
		originalMainTemplate:    nginxTemplate,
		originalIngressTemplate: ingressTemplate,
		mainTemplate:            nginxTemplate,
		ingressTemplate:         ingressTemplate,
	}, nil
}

// UpdateMainTemplate updates the main NGINX template.
func (te *TemplateExecutor) UpdateMainTemplate(templateString *string) error {
	newTemplate, err := template.New("nginxTemplate").Funcs(helperFunctions).Parse(*templateString)
	if err != nil {
		return err
	}
	te.mainTemplate = newTemplate
	return nil
}

// UseOriginalMainTemplate updates template executor to
// use the original main template parsed at startup.
func (te *TemplateExecutor) UseOriginalMainTemplate() {
	te.mainTemplate = te.originalMainTemplate
}

// UpdateIngressTemplate updates the ingress template.
func (te *TemplateExecutor) UpdateIngressTemplate(templateString *string) error {
	newTemplate, err := template.New("ingressTemplate").Funcs(helperFunctions).Parse(*templateString)
	if err != nil {
		return err
	}
	te.ingressTemplate = newTemplate
	return nil
}

// UseOriginalIngressTemplate updates template executor to
// use the original ingress template parsed at startup.
func (te *TemplateExecutor) UseOriginalIngressTemplate() {
	te.ingressTemplate = te.originalIngressTemplate
}

// ExecuteMainConfigTemplate generates the content of the main NGINX configuration file.
func (te *TemplateExecutor) ExecuteMainConfigTemplate(cfg *MainConfig) ([]byte, error) {
	var configBuffer bytes.Buffer
	err := te.mainTemplate.Execute(&configBuffer, cfg)
	return configBuffer.Bytes(), err
}

// ExecuteIngressConfigTemplate generates the content of a NGINX configuration file for an Ingress resource.
func (te *TemplateExecutor) ExecuteIngressConfigTemplate(cfg *IngressNginxConfig) ([]byte, error) {
	var configBuffer bytes.Buffer
	err := te.ingressTemplate.Execute(&configBuffer, cfg)
	return configBuffer.Bytes(), err
}
