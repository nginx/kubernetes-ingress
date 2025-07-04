package main

/*
Usage:
  go run hack/generate-crd-docs.go [flags]

Flags:
  -crd-dir string
        Directory containing CRD YAML files (default "config/crd/bases")
  -output-dir string
        Directory to write markdown files (default "docs/crd")
*/

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// CRDDocGenerator handles CRD documentation generation
type CRDDocGenerator struct {
	crdDir    string
	outputDir string
}

// FieldInfo represents information about a CRD field
type FieldInfo struct {
	Path        string
	Type        string
	Description string
}

// NewCRDDocGenerator creates a new CRD documentation generator
func NewCRDDocGenerator(crdDir, outputDir string) *CRDDocGenerator {
	return &CRDDocGenerator{
		crdDir:    crdDir,
		outputDir: outputDir,
	}
}

// loadCRDYAML loads and parses a CRD YAML file
func (g *CRDDocGenerator) loadCRDYAML(filePath string) (*apiextensionsv1.CustomResourceDefinition, error) {
	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(data, &crd); err != nil {
		return nil, fmt.Errorf("error unmarshaling YAML from %s: %w", filePath, err)
	}

	return &crd, nil
}

// extractEnumValues extracts enum values from a field schema
func (g *CRDDocGenerator) extractEnumValues(schema *apiextensionsv1.JSONSchemaProps) string {
	if len(schema.Enum) == 0 {
		return ""
	}

	var values []string
	for _, enum := range schema.Enum {
		values = append(values, fmt.Sprintf("`%s`", enum.Raw))
	}
	return strings.Join(values, ", ")
}

// getFieldType determines the type of a field from its schema
func (g *CRDDocGenerator) getFieldType(schema *apiextensionsv1.JSONSchemaProps) string {
	if schema.Type != "" {
		switch schema.Type {
		case "array":
			if schema.Items != nil && schema.Items.Schema != nil && schema.Items.Schema.Type != "" {
				itemsType := schema.Items.Schema.Type
				if itemsType != "object" {
					return fmt.Sprintf("array[%s]", itemsType)
				}
			}
			return "array"
		case "object":
			return "object"
		default:
			return schema.Type
		}
	}

	if len(schema.AnyOf) > 0 {
		return "string|integer"
	}

	if schema.Ref != nil {
		return "object"
	}

	return "object"
}

// extractDescription extracts description from a field schema
func (g *CRDDocGenerator) extractDescription(schema *apiextensionsv1.JSONSchemaProps) string {
	description := ""
	if schema.Description != "" {
		description = strings.Join(strings.Fields(schema.Description), " ")
		if len(description) > 0 && description[0] >= 'a' && description[0] <= 'z' {
			description = strings.ToUpper(string(description[0])) + description[1:]
		}
	}

	enumValues := g.extractEnumValues(schema)
	if enumValues != "" {
		if description != "" {
			description += fmt.Sprintf(" Allowed values: %s.", enumValues)
		} else {
			description = fmt.Sprintf("Allowed values: %s.", enumValues)
		}
	}

	if description == "" {
		fieldType := g.getFieldType(schema)
		switch fieldType {
		case "boolean":
			description = "Enable or disable this feature."
		case "integer":
			description = "Numeric configuration value."
		case "string":
			description = "String configuration value."
		case "array":
			description = "List of configuration values."
		case "object":
			description = "Configuration object."
		default:
			description = "Configuration field."
		}
	}

	return description
}

// processProperties processes properties from a schema and returns field information
func (g *CRDDocGenerator) processProperties(properties map[string]apiextensionsv1.JSONSchemaProps, parentPath string) []FieldInfo {
	var fields []FieldInfo

	// Sort property names for consistent output
	var names []string
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		schema := properties[name]
		path := name
		if parentPath != "" {
			path = parentPath + "." + name
		}

		fieldType := g.getFieldType(&schema)
		description := g.extractDescription(&schema)

		fields = append(fields, FieldInfo{
			Path:        path,
			Type:        fieldType,
			Description: description,
		})

		// Process nested properties for objects
		if fieldType == "object" && schema.Properties != nil {
			nestedFields := g.processProperties(schema.Properties, path)
			fields = append(fields, nestedFields...)
		}

		// Process array items properties if they have object structure
		if strings.HasPrefix(fieldType, "array") && schema.Items != nil && schema.Items.Schema != nil {
			itemsSchema := schema.Items.Schema
			if itemsSchema.Properties != nil {
				arrayPath := path + "[]"
				nestedFields := g.processProperties(itemsSchema.Properties, arrayPath)
				fields = append(fields, nestedFields...)
			}
		}
	}

	return fields
}

// getCRDMetadata extracts metadata from CRD
func (g *CRDDocGenerator) getCRDMetadata(crd *apiextensionsv1.CustomResourceDefinition) (string, string, string, string, string) {
	group := crd.Spec.Group
	kind := crd.Spec.Names.Kind
	scope := string(crd.Spec.Scope)

	// Get the version (usually the latest/storage version)
	version := "v1"
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			version = v.Name
			break
		}
	}
	if version == "v1" && len(crd.Spec.Versions) > 0 {
		version = crd.Spec.Versions[0].Name
	}

	description := g.getDescription(kind)
	return kind, group, version, scope, description
}

// getDescription returns description for a CRD kind
func (g *CRDDocGenerator) getDescription(kind string) string {
	descriptions := map[string]string{
		"APLogConf":            "The `APLogConf` resource defines the logging configuration for NGINX App Protect. It allows you to specify the format and content of security logs, as well as filters to control which requests are logged.",
		"APPolicy":             "The `APPolicy` resource defines a security policy for NGINX App Protect. It allows you to configure a wide range of security features, including bot defense, blocking settings, and application language support.",
		"APUserSig":            "The `APUserSig` resource defines a custom user-defined signature for NGINX App Protect. It allows you to create your own signatures to detect specific attack patterns or vulnerabilities.",
		"APDosLogConf":         "The `APDosLogConf` resource defines the logging configuration for the NGINX App Protect DoS module. It allows you to specify the format and content of security logs, as well as filters to control which events are logged.",
		"APDosPolicy":          "The `APDosPolicy` resource defines a security policy for the NGINX App Protect Denial of Service (DoS) module. It allows you to configure various mitigation strategies to protect your applications from DoS attacks.",
		"DosProtectedResource": "The `DosProtectedResource` resource defines a resource that is protected by the NGINX App Protect DoS module. It allows you to enable and configure DoS protection for a specific service or application.",
		"DNSEndpoint":          "The `DNSEndpoint` resource is used to manage DNS records for services exposed through NGINX Ingress Controller. It is typically used in conjunction with ExternalDNS to automatically create and update DNS records.",
		"GlobalConfiguration":  "The `GlobalConfiguration` resource defines global settings for the NGINX Ingress Controller. It allows you to configure listeners for different protocols and ports.",
		"Policy":               "The `Policy` resource defines a security policy for `VirtualServer` and `VirtualServerRoute` resources. It allows you to apply various policies such as access control, authentication, rate limiting, and WAF protection.",
		"VirtualServer":        "The `VirtualServer` resource defines a virtual server for the NGINX Ingress Controller. It provides advanced configuration capabilities beyond standard Kubernetes Ingress resources, including traffic splitting, advanced routing, header manipulation, and integration with NGINX App Protect.",
		"VirtualServerRoute":   "The `VirtualServerRoute` resource defines a route that can be referenced by a `VirtualServer`. It enables modular configuration by allowing routes to be defined separately and referenced by multiple VirtualServers.",
		"TransportServer":      "The `TransportServer` resource defines a TCP or UDP load balancer. It allows you to expose non-HTTP applications running in your Kubernetes cluster with advanced load balancing and health checking capabilities.",
	}

	if desc, exists := descriptions[kind]; exists {
		return desc
	}
	return fmt.Sprintf("The `%s` resource defines configuration for the NGINX Ingress Controller.", kind)
}

// extractSpecSchema extracts the spec schema from a CRD
func (g *CRDDocGenerator) extractSpecSchema(crd *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.JSONSchemaProps {
	for _, v := range crd.Spec.Versions {
		if v.Schema != nil && v.Schema.OpenAPIV3Schema != nil {
			schema := v.Schema.OpenAPIV3Schema
			if schema.Properties != nil {
				if spec, exists := schema.Properties["spec"]; exists {
					return &spec
				}
			}
		}
	}
	return nil
}

// formatMarkdownHeader formats the header section of the markdown documentation
func (g *CRDDocGenerator) formatMarkdownHeader(kind, group, version, scope, description string) string {
	return fmt.Sprintf("# %s\n\n**Group:** `%s`  \n**Version:** `%s`  \n**Kind:** `%s`  \n**Scope:** `%s`\n\n## Description\n\n%s\n\n## Spec Fields\n\nThe `.spec` object supports the following fields:\n\n| Field | Type | Description |\n|---|---|---|\n",
		kind, group, version, kind, scope, description)
}

// formatMarkdownTable formats the table rows for field information
func (g *CRDDocGenerator) formatMarkdownTable(fields []FieldInfo) string {
	var tableRows strings.Builder
	for _, field := range fields {
		fieldType := strings.ReplaceAll(field.Type, "|", "\\|")
		tableRows.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", field.Path, fieldType, field.Description))
	}
	return tableRows.String()
}

// generateMarkdown generates markdown documentation for a CRD
func (g *CRDDocGenerator) generateMarkdown(crd *apiextensionsv1.CustomResourceDefinition) string {
	kind, group, version, scope, description := g.getCRDMetadata(crd)
	specSchema := g.extractSpecSchema(crd)
	if specSchema == nil || specSchema.Properties == nil {
		return fmt.Sprintf("# %s\n\nNo spec properties found for this CRD.\n", kind)
	}

	fields := g.processProperties(specSchema.Properties, "")
	header := g.formatMarkdownHeader(kind, group, version, scope, description)
	table := g.formatMarkdownTable(fields)

	return header + table
}

// processCRDFile processes a single CRD YAML file and generates its documentation
func (g *CRDDocGenerator) processCRDFile(filePath string) error {
	fmt.Printf("Processing %s...\n", filepath.Base(filePath))

	crd, err := g.loadCRDYAML(filePath)
	if err != nil {
		return err
	}

	markdown := g.generateMarkdown(crd)

	// Generate output filename
	filename := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath)) + ".md"
	outputPath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(outputPath, []byte(markdown), 0o600); err != nil {
		return fmt.Errorf("error writing %s: %w", outputPath, err)
	}

	fmt.Printf("Generated %s\n", outputPath)
	return nil
}

// generateAllDocs generates documentation for all CRD YAML files
func (g *CRDDocGenerator) generateAllDocs() error {
	var crdFiles []string

	err := filepath.WalkDir(g.crdDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			crdFiles = append(crdFiles, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking directory %s: %w", g.crdDir, err)
	}

	if len(crdFiles) == 0 {
		return fmt.Errorf("no YAML files found in %s", g.crdDir)
	}

	successCount := 0
	for _, filePath := range crdFiles {
		if err := g.processCRDFile(filePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", filePath, err)
		} else {
			successCount++
		}
	}

	fmt.Printf("\nGenerated documentation for %d/%d CRD files.\n", successCount, len(crdFiles))

	if successCount != len(crdFiles) {
		return fmt.Errorf("failed to process %d files", len(crdFiles)-successCount)
	}

	return nil
}

func main() {
	var (
		crdDir    = flag.String("crd-dir", "config/crd/bases", "Directory containing CRD YAML files")
		outputDir = flag.String("output-dir", "docs/crd", "Directory to write markdown files")
	)
	flag.Parse()

	// Check if CRD directory exists
	if _, err := os.Stat(*crdDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: CRD directory %s does not exist\n", *crdDir)
		os.Exit(1)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory %s: %v\n", *outputDir, err)
		os.Exit(1)
	}

	generator := NewCRDDocGenerator(*crdDir, *outputDir)

	if err := generator.generateAllDocs(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
