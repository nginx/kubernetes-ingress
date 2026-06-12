package nicgraph

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
	Validators []string `json:"validators,omitempty"` // qualified function names in /validation/ packages
	Configs    []string `json:"configs,omitempty"`    // structs + generator funcs under internal/configs**
	Templates  []string `json:"templates,omitempty"`  // .tmpl files
	Tests      []string `json:"tests,omitempty"`      // distinct _test.go file paths
	Sources    []string `json:"sources,omitempty"`    // distinct non-test source files most associated with the CRD
}

// DomainMap is the domain-map.json payload.
type DomainMap struct {
	Entries []DomainEntry `json:"entries"`
}

// crdSpec drives the matcher. File substrings are checked against the
// lowercased relative path; symbol substrings against the case-sensitive name.
type crdSpec struct {
	Kind          string
	Group         string
	Files         []string // file-path substrings (lowercase) that claim a file for this CRD
	Symbols       []string // symbol-name substrings that claim a symbol regardless of file
	SymbolsExact  []string // symbol names that must match exactly (no substring)
	ExcludeFiles  []string // file substrings that disqualify a file even if Files matched
	TemplateGlobs []string // file substrings for template matching
}

var crdSpecs = []crdSpec{
	{
		Kind:          "VirtualServer",
		Group:         "k8s.nginx.org/v1",
		Files:         []string{"virtualserver"},
		Symbols:       []string{"VirtualServer"},
		ExcludeFiles:  []string{"virtualserverroute"},
		TemplateGlobs: []string{"virtualserver"},
	},
	{
		Kind:    "VirtualServerRoute",
		Group:   "k8s.nginx.org/v1",
		Files:   []string{"virtualserverroute", "virtualserver_routing"},
		Symbols: []string{"VirtualServerRoute"},
		// VSR is rendered through the VS template (subroutes).
		TemplateGlobs: []string{"virtualserver"},
	},
	{
		Kind:          "TransportServer",
		Group:         "k8s.nginx.org/v1",
		Files:         []string{"transportserver"},
		Symbols:       []string{"TransportServer"},
		TemplateGlobs: []string{"transportserver"},
	},
	{
		Kind:  "Policy",
		Group: "k8s.nginx.org/v1",
		Files: []string{
			"/policy.go", "/policy_test.go",
			"virtualserver_policy",
		},
		SymbolsExact:  []string{"Policy"},
		ExcludeFiles:  []string{"/appprotect", "/appprotectdos", "/apis/dos/"},
		TemplateGlobs: []string{"virtualserver"},
	},
	{
		Kind:          "GlobalConfiguration",
		Group:         "k8s.nginx.org/v1",
		Files:         []string{"globalconfiguration"},
		Symbols:       []string{"GlobalConfiguration"},
		TemplateGlobs: []string{"/nginx.tmpl", "/nginx-plus.tmpl"},
	},
	{
		Kind:         "DosProtectedResource",
		Group:        "appprotectdos.f5.com/v1beta1",
		Files:        []string{"/apis/dos/", "/configs/dos", "appprotectdos", "appprotect_dos"},
		SymbolsExact: []string{"DosProtectedResource"},
	},
	// AppProtect WAF CRDs (appprotect.f5.com) — unstructured, no Go types.
	{
		Kind:         "APPolicy",
		Group:        "appprotect.f5.com/v1beta1",
		Files:        []string{"/validation/appprotect", "/k8s/appprotect_waf", "/k8s/appprotect/"},
		SymbolsExact: []string{"APPolicy"},
		Symbols:      []string{"AppProtectPolicy"},
		ExcludeFiles: []string{"_dos", "appprotectdos"},
	},
	{
		Kind:         "APLogConf",
		Group:        "appprotect.f5.com/v1beta1",
		Files:        []string{"/validation/appprotect", "/k8s/appprotect_waf", "/k8s/appprotect/"},
		SymbolsExact: []string{"APLogConf"},
		Symbols:      []string{"AppProtectLogConf"},
		ExcludeFiles: []string{"_dos", "appprotectdos"},
	},
	{
		Kind:         "APUserSig",
		Group:        "appprotect.f5.com/v1beta1",
		Files:        []string{"/validation/appprotect", "/k8s/appprotect_waf", "/k8s/appprotect/"},
		SymbolsExact: []string{"APUserSig"},
		Symbols:      []string{"AppProtectUserSig"},
		ExcludeFiles: []string{"_dos", "appprotectdos"},
	},
	// AppProtect DoS CRDs (appprotectdos.f5.com) — unstructured, no Go types.
	{
		Kind:         "APDosPolicy",
		Group:        "appprotectdos.f5.com/v1beta1",
		Files:        []string{"/apis/dos/validation/", "/k8s/appprotect_dos", "/k8s/appprotectdos/"},
		SymbolsExact: []string{"APDosPolicy"},
		Symbols:      []string{"AppProtectDosPolicy", "ApDosPolicy"},
		ExcludeFiles: []string{"logconf", "LogConf"},
	},
	{
		Kind:         "APDosLogConf",
		Group:        "appprotectdos.f5.com/v1beta1",
		Files:        []string{"/apis/dos/validation/", "/k8s/appprotect_dos", "/k8s/appprotectdos/"},
		SymbolsExact: []string{"APDosLogConf"},
		Symbols:      []string{"AppProtectDosLogConf", "ApDosLogConf"},
	},
	{
		Kind:    "DNSEndpoint",
		Group:   "externaldns.nginx.org/v1",
		Files:   []string{"externaldns", "external_dns"},
		Symbols: []string{"DNSEndpoint", "ExternalDNS"},
	},
}

// generatorPrefixes are func name prefixes considered "config generators"
// when their file or name matches a CRD.
var generatorPrefixes = []string{"generate", "Generate", "add", "Add", "new", "New", "update", "Update"}

func buildDomainMap(cfg Config, gi *GoIndex, tmpls *TemplateIndex) *DomainMap {
	dm := &DomainMap{}

	// Lowercased file paths cache (keyed by relative path).
	lcFile := make(map[string]string, len(gi.Symbols))
	for _, s := range gi.Symbols {
		if _, ok := lcFile[s.File]; !ok {
			lcFile[s.File] = strings.ToLower(s.File)
		}
	}

	// Symbols by name for fast type-definition lookup.
	byName := make(map[string][]SymbolInfo)
	for _, s := range gi.Symbols {
		byName[s.Name] = append(byName[s.Name], s)
	}

	overrides := loadOverridesSilently(cfg)

	for _, spec := range crdSpecs {
		entry := DomainEntry{CRD: spec.Kind, Group: spec.Group}

		// Type definition: top-level struct/type in /apis/ with this name.
		for _, s := range byName[spec.Kind] {
			if (s.Kind == "type" || s.Kind == "struct") && strings.Contains(s.Pkg, "/pkg/apis/") {
				entry.TypeFile = s.File
				entry.TypeLine = s.Line
				if entry.Group == "" {
					entry.Group = guessGroup(s.Pkg)
				}
				break
			}
		}

		// Classify every symbol against this CRD.
		validators := stringSet{}
		configs := stringSet{}
		tests := stringSet{}
		sources := stringSet{}

		for _, s := range gi.Symbols {
			if !specClaims(spec, s, lcFile[s.File]) {
				continue
			}
			switch {
			case isValidatorSymbol(s):
				if s.Exported {
					validators.add(qualify(s))
				}
			case isConfigSymbol(s):
				configs.add(qualify(s))
			}
			if strings.HasSuffix(s.File, "_test.go") {
				tests.add(s.File)
			} else if isSourceFile(s.File) {
				sources.add(s.File)
			}
		}

		// Templates: independent of symbols.
		for _, t := range tmpls.Files {
			if specMatchesTemplate(spec, t) {
				entry.Templates = append(entry.Templates, t.File)
			}
		}

		// Apply user-supplied overrides last so they always win.
		applyOverride(overrides, spec.Kind, &validators, &configs, &tests, &sources, &entry.Templates)

		entry.Validators = validators.sorted()
		entry.Configs = configs.sorted()
		entry.Tests = tests.sorted()
		entry.Sources = sources.sorted()
		sort.Strings(entry.Templates)
		entry.Templates = dedupSortedStrings(entry.Templates)

		dm.Entries = append(dm.Entries, entry)
	}

	sort.Slice(dm.Entries, func(i, j int) bool { return dm.Entries[i].CRD < dm.Entries[j].CRD })
	return dm
}

// specClaims returns true if the spec matches the symbol via either its file
// path or its symbol name. ExcludeFiles vetoes file matches.
func specClaims(spec crdSpec, s SymbolInfo, lcPath string) bool {
	fileMatched := false
	for _, sub := range spec.Files {
		if strings.Contains(lcPath, sub) {
			fileMatched = true
			break
		}
	}
	if fileMatched {
		for _, ex := range spec.ExcludeFiles {
			if strings.Contains(lcPath, ex) {
				fileMatched = false
				break
			}
		}
	}
	if fileMatched {
		return true
	}
	// Exact symbol-name match (no substring).
	for _, exact := range spec.SymbolsExact {
		if s.Name == exact {
			return true
		}
	}
	// Substring symbol-name match.
	for _, sub := range spec.Symbols {
		if strings.Contains(s.Name, sub) {
			return true
		}
	}
	return false
}

func isValidatorSymbol(s SymbolInfo) bool {
	if s.Kind != "func" {
		return false
	}
	if !strings.Contains(s.Pkg, "/validation") {
		return false
	}
	// Tests live in /validation/*_test.go but belong in the tests bucket.
	if strings.HasSuffix(s.File, "_test.go") {
		return false
	}
	if strings.HasPrefix(s.Name, "Test") || strings.HasPrefix(s.Name, "Benchmark") || strings.HasPrefix(s.Name, "Fuzz") || strings.HasPrefix(s.Name, "Example") {
		return false
	}
	return true
}

// isConfigSymbol returns true for structs anywhere under /internal/configs
// and for funcs in /internal/configs whose name begins with a recognized
// generator prefix (generate/new/add/update). Test funcs are excluded — they
// belong in the tests bucket via the _test.go file-suffix check.
func isConfigSymbol(s SymbolInfo) bool {
	if !strings.Contains(s.Pkg, "/internal/configs") {
		return false
	}
	if strings.HasSuffix(s.File, "_test.go") {
		return false
	}
	if s.Kind == "struct" {
		return true
	}
	if s.Kind != "func" {
		return false
	}
	if strings.HasPrefix(s.Name, "Test") || strings.HasPrefix(s.Name, "Benchmark") || strings.HasPrefix(s.Name, "Fuzz") || strings.HasPrefix(s.Name, "Example") {
		return false
	}
	for _, p := range generatorPrefixes {
		if strings.HasPrefix(s.Name, p) {
			return true
		}
	}
	return false
}

func isSourceFile(file string) bool {
	if !strings.HasSuffix(file, ".go") {
		return false
	}
	if strings.HasSuffix(file, "_test.go") {
		return false
	}
	if strings.Contains(file, "/zz_generated") {
		return false
	}
	return true
}

func qualify(s SymbolInfo) string {
	if s.Kind == "method" && s.Recv != "" {
		return fmt.Sprintf("%s.%s.%s", short(s.Pkg), s.Recv, s.Name)
	}
	return fmt.Sprintf("%s.%s", short(s.Pkg), s.Name)
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

// specMatchesTemplate matches by file substring against TemplateGlobs.
func specMatchesTemplate(spec crdSpec, t TemplateInfo) bool {
	name := strings.ToLower(t.File)
	for _, sub := range spec.TemplateGlobs {
		if strings.Contains(name, sub) {
			return true
		}
	}
	return false
}

// stringSet is a tiny ordered-set helper used to dedupe domain-map values.
type stringSet map[string]struct{}

func (s stringSet) add(v string) {
	if v == "" {
		return
	}
	s[v] = struct{}{}
}

func (s stringSet) remove(v string) {
	delete(s, v)
}

func (s stringSet) sorted() []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupSortedStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:0]
	var prev string
	for i, v := range in {
		if i == 0 || v != prev {
			out = append(out, v)
		}
		prev = v
	}
	return out
}

// renderDomainMapMarkdown produces a human-readable view backed by DomainMap.
func renderDomainMapMarkdown(dm *DomainMap) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Domain Map\n\n")
	buf.WriteString("Generated by `make nic-graph`. For NIC architecture, layer rules, and the secret-store pipeline, load the `nic-structure` skill first.\n\n")
	for _, e := range dm.Entries {
		fmt.Fprintf(&buf, "## %s\n\n", e.CRD)
		if e.Group != "" {
			fmt.Fprintf(&buf, "- **API group**: `%s`\n", e.Group)
		}
		if e.TypeFile != "" {
			fmt.Fprintf(&buf, "- **Type**: [%s:%d](../%s#L%d)\n", e.TypeFile, e.TypeLine, e.TypeFile, e.TypeLine)
		}
		fmt.Fprintf(&buf, "- **Counts**: %d validators, %d configs, %d templates, %d test files, %d source files\n",
			len(e.Validators), len(e.Configs), len(e.Templates), len(e.Tests), len(e.Sources))
		writeBullets(&buf, "Validators", e.Validators)
		writeBullets(&buf, "Config structs / generators", e.Configs)
		writeFileBullets(&buf, "Templates", e.Templates)
		writeFileBullets(&buf, "Tests", e.Tests)
		writeFileBullets(&buf, "Sources", e.Sources)
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
