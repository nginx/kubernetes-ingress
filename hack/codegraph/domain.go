package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// DomainEntry describes one CRD's wiring across the codebase.
type DomainEntry struct {
	CRD        string   `json:"crd"`       // e.g. VirtualServer
	Group      string   `json:"group"`     // k8s.nginx.org/v1
	TypeFile   string   `json:"type_file"` // pkg/apis/.../types.go
	TypeLine   int      `json:"type_line"`
	Validators []string `json:"validators,omitempty"` // exported funcs whose name contains the CRD name
	Configs    []string `json:"configs,omitempty"`    // version1/2 structs that look related
	Templates  []string `json:"templates,omitempty"`  // .tmpl files referencing the CRD via OSS+Plus pair
	Tests      []string `json:"tests,omitempty"`      // _test.go files that import + mention the CRD
}

// DomainMap is the domain-map.json payload.
type DomainMap struct {
	Entries []DomainEntry `json:"entries"`
}

// crdNames is the closed set of CRD kinds we wire up. Kept explicit to avoid
// surprising matches (every struct embedding TypeMeta would otherwise qualify).
var crdNames = []string{
	"VirtualServer",
	"VirtualServerRoute",
	"TransportServer",
	"Policy",
	"GlobalConfiguration",
	"DNSEndpoint",
	"DosProtectedResource",
}

func buildDomainMap(_ Config, gi *GoIndex, tmpls *TemplateIndex) *DomainMap {
	dm := &DomainMap{}

	// Index symbols by package + name for fast lookup.
	byKey := make(map[string]SymbolInfo, len(gi.Symbols))
	for _, s := range gi.Symbols {
		byKey[symbolKey(s)] = s
	}
	// Symbols by name (across packages) for loose lookups.
	byName := make(map[string][]SymbolInfo)
	for _, s := range gi.Symbols {
		byName[s.Name] = append(byName[s.Name], s)
	}

	for _, crd := range crdNames {
		entry := DomainEntry{CRD: crd}
		// Locate the type definition struct.
		for _, s := range byName[crd] {
			if (s.Kind == "type" || s.Kind == "struct") && strings.Contains(s.Pkg, "/pkg/apis/") {
				entry.TypeFile = s.File
				entry.TypeLine = s.Line
				entry.Group = guessGroup(s.Pkg)
				break
			}
		}

		// Validators: exported funcs in validation packages whose name contains CRD.
		for _, s := range gi.Symbols {
			if s.Kind != "func" || !s.Exported {
				continue
			}
			if !strings.Contains(s.Pkg, "/validation") {
				continue
			}
			if strings.Contains(s.Name, crd) {
				entry.Validators = append(entry.Validators, fmt.Sprintf("%s.%s", short(s.Pkg), s.Name))
			}
		}

		// Configs: structs in version1/version2 named like CRD*Config/Ex.
		for _, s := range gi.Symbols {
			if s.Kind != "struct" {
				continue
			}
			if !(strings.HasSuffix(s.Pkg, "/configs/version1") ||
				strings.HasSuffix(s.Pkg, "/configs/version2") ||
				strings.HasSuffix(s.Pkg, "/configs")) {
				continue
			}
			if strings.Contains(s.Name, crd) {
				entry.Configs = append(entry.Configs, fmt.Sprintf("%s.%s", short(s.Pkg), s.Name))
			}
		}

		// Templates: pair files whose pair name maps to CRD via heuristic.
		for _, t := range tmpls.Files {
			if templateMatchesCRD(t, crd) {
				entry.Templates = append(entry.Templates, t.File)
			}
		}
		sort.Strings(entry.Templates)

		// Tests: _test.go files in our index that contain CRD substring in their path or symbols.
		// Cheap heuristic: any file containing a top-level symbol whose name mentions the CRD and lives in _test.go.
		testFiles := map[string]struct{}{}
		for _, s := range gi.Symbols {
			if !strings.HasSuffix(s.File, "_test.go") {
				continue
			}
			if strings.Contains(s.Name, crd) {
				testFiles[s.File] = struct{}{}
			}
		}
		for f := range testFiles {
			entry.Tests = append(entry.Tests, f)
		}
		sort.Strings(entry.Tests)

		dm.Entries = append(dm.Entries, entry)
		_ = byKey // reserved for future precise lookups
	}

	sort.Slice(dm.Entries, func(i, j int) bool { return dm.Entries[i].CRD < dm.Entries[j].CRD })
	return dm
}

func short(pkgPath string) string {
	return strings.TrimPrefix(pkgPath, ModulePath+"/")
}

func guessGroup(pkgPath string) string {
	switch {
	case strings.Contains(pkgPath, "/apis/configuration/"):
		return "k8s.nginx.org/v1"
	case strings.Contains(pkgPath, "/apis/externaldns/"):
		return "externaldns.nginx.org/v1"
	case strings.Contains(pkgPath, "/apis/dos/"):
		return "appprotectdos.f5.com/v1beta1"
	}
	return ""
}

// templateMatchesCRD returns true when a template clearly belongs to a CRD.
// Heuristics:
//   - VirtualServer / VSR -> virtualserver*.tmpl
//   - TransportServer    -> transportserver*.tmpl
//   - Ingress (not a CRD here but useful) -> ingress*.tmpl
func templateMatchesCRD(t TemplateInfo, crd string) bool {
	name := strings.ToLower(t.File)
	switch crd {
	case "VirtualServer", "VirtualServerRoute", "Policy":
		return strings.Contains(name, "virtualserver")
	case "TransportServer":
		return strings.Contains(name, "transportserver")
	case "GlobalConfiguration":
		// Global config flows through the main nginx.conf templates.
		return strings.HasSuffix(name, "/nginx.tmpl") || strings.HasSuffix(name, "/nginx-plus.tmpl")
	}
	return false
}

// renderDomainMapMarkdown produces a human-readable view backed by DomainMap.
func renderDomainMapMarkdown(dm *DomainMap) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Domain Map\n\n")
	buf.WriteString("Generated by `make codegraph`. For NIC architecture, layer rules, and the secret-store pipeline, load the `nic-structure` skill first.\n\n")
	for _, e := range dm.Entries {
		fmt.Fprintf(&buf, "## %s\n\n", e.CRD)
		if e.Group != "" {
			fmt.Fprintf(&buf, "- **API group**: `%s`\n", e.Group)
		}
		if e.TypeFile != "" {
			fmt.Fprintf(&buf, "- **Type**: [%s:%d](../%s#L%d)\n", e.TypeFile, e.TypeLine, e.TypeFile, e.TypeLine)
		}
		writeBullets(&buf, "Validators", e.Validators)
		writeBullets(&buf, "Config structs", e.Configs)
		writeFileBullets(&buf, "Templates", e.Templates)
		writeFileBullets(&buf, "Tests", e.Tests)
		buf.WriteString("\n")
	}
	return buf.Bytes()
}

func writeBullets(buf *bytes.Buffer, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(buf, "- **%s**:\n", label)
	for _, it := range items {
		fmt.Fprintf(buf, "  - `%s`\n", it)
	}
}

func writeFileBullets(buf *bytes.Buffer, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(buf, "- **%s**:\n", label)
	for _, it := range items {
		fmt.Fprintf(buf, "  - [%s](../%s)\n", it, it)
	}
}
