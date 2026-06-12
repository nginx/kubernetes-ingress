package nicgraph

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Store provides read-only, indexed access to a generated .nic-graph/ tree.
// All lookups are case-sensitive unless documented otherwise.
type Store struct {
	OutDir string

	mu sync.RWMutex

	packages    []PackageInfo
	pkgByPath   map[string]*PackageInfo
	symbols     []SymbolInfo
	byName      map[string][]SymbolInfo // lowercased name -> all symbols
	byQualified map[string]SymbolInfo   // symbolKey -> symbol
	refs        map[string][]RefInfo    // callee key -> callers
	calleesOf   map[string][]RefInfo    // caller key -> callees (inverted)
	imports     map[string][]string
	templates   *TemplateIndex
	helm        *HelmIndex
	domain      *DomainMap
	pyTests     *PythonTestIndex
	examples    *ExamplesIndex
	stats       map[string]int
}

// OpenStore loads every artifact under outDir into memory and builds lookup
// indexes. Returns an error if a required artifact is missing or malformed.
func OpenStore(outDir string) (*Store, error) {
	s := &Store{OutDir: outDir}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload re-reads every artifact from disk and rebuilds the indexes.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.OutDir); err != nil {
		return fmt.Errorf("nic-graph dir not found: %s (run `make nic-graph`)", s.OutDir)
	}

	var pkgs []PackageInfo
	if err := readJSON(filepath.Join(s.OutDir, "packages.json"), &pkgs); err != nil {
		return err
	}
	s.packages = pkgs
	s.pkgByPath = make(map[string]*PackageInfo, len(pkgs))
	for i := range s.packages {
		p := &s.packages[i]
		s.pkgByPath[p.ImportPath] = p
	}

	syms, err := readSymbolsJSONL(filepath.Join(s.OutDir, "symbols.jsonl"))
	if err != nil {
		return err
	}
	s.symbols = syms
	s.byName = make(map[string][]SymbolInfo, len(syms))
	s.byQualified = make(map[string]SymbolInfo, len(syms))
	for _, sym := range syms {
		lc := strings.ToLower(sym.Name)
		s.byName[lc] = append(s.byName[lc], sym)
		s.byQualified[symbolKey(sym)] = sym
	}

	refs, err := readRefsJSONL(filepath.Join(s.OutDir, "refs.jsonl"))
	if err != nil {
		return err
	}
	s.refs = refs
	s.calleesOf = invertRefs(refs)

	var imports map[string][]string
	if err := readJSON(filepath.Join(s.OutDir, "imports.json"), &imports); err != nil {
		return err
	}
	s.imports = imports

	s.templates = &TemplateIndex{}
	if err := readJSON(filepath.Join(s.OutDir, "templates.json"), s.templates); err != nil {
		return err
	}
	s.helm = &HelmIndex{}
	if err := readJSON(filepath.Join(s.OutDir, "helm.json"), s.helm); err != nil {
		return err
	}
	s.domain = &DomainMap{}
	if err := readJSON(filepath.Join(s.OutDir, "domain-map.json"), s.domain); err != nil {
		return err
	}
	s.pyTests = &PythonTestIndex{}
	if err := readJSON(filepath.Join(s.OutDir, "python-tests.json"), s.pyTests); err != nil {
		return err
	}
	s.examples = &ExamplesIndex{}
	if err := readJSON(filepath.Join(s.OutDir, "examples.json"), s.examples); err != nil {
		return err
	}

	s.stats = map[string]int{
		"packages":     len(s.packages),
		"symbols":      len(s.symbols),
		"ref_edges":    edgeCountOf(s.refs),
		"templates":    len(s.templates.Files),
		"helm_keys":    len(s.helm.ValuesKeys),
		"python_files": len(s.pyTests.Files),
		"examples":     len(s.examples.Entries),
		"crds":         len(s.domain.Entries),
	}
	return nil
}

// Stats returns a snapshot of artifact counts.
func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.stats))
	for k, v := range s.stats {
		out[k] = v
	}
	return out
}

// FindSymbol searches for symbols by name. Match strategy:
//  1. exact match (case-sensitive)
//  2. exact match (case-insensitive)
//  3. case-insensitive prefix
//  4. case-insensitive substring
//
// kind filters the result if non-empty (e.g. "func", "method", "type",
// "struct", "interface", "const", "var"). The limit caps results; pass 0
// for no cap.
func (s *Store) FindSymbol(name, kind string, limit int) []SymbolInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name == "" {
		return nil
	}
	lc := strings.ToLower(name)
	var out []SymbolInfo
	seen := make(map[string]struct{})
	push := func(sym SymbolInfo) bool {
		if kind != "" && sym.Kind != kind {
			return false
		}
		k := symbolKey(sym) + "@" + sym.File
		if _, ok := seen[k]; ok {
			return false
		}
		seen[k] = struct{}{}
		out = append(out, sym)
		return limit > 0 && len(out) >= limit
	}
	// Stage 1+2: hit the case-insensitive name bucket; exact-case wins ordering.
	if bucket, ok := s.byName[lc]; ok {
		// stable order: exact name first, then everything else
		var exact, other []SymbolInfo
		for _, sym := range bucket {
			if sym.Name == name {
				exact = append(exact, sym)
			} else {
				other = append(other, sym)
			}
		}
		for _, sym := range exact {
			if push(sym) {
				return out
			}
		}
		for _, sym := range other {
			if push(sym) {
				return out
			}
		}
	}
	// Stage 3: case-insensitive prefix.
	for n, bucket := range s.byName {
		if n == lc || !strings.HasPrefix(n, lc) {
			continue
		}
		for _, sym := range bucket {
			if push(sym) {
				return out
			}
		}
	}
	// Stage 4: case-insensitive substring.
	for n, bucket := range s.byName {
		if n == lc || strings.HasPrefix(n, lc) || !strings.Contains(n, lc) {
			continue
		}
		for _, sym := range bucket {
			if push(sym) {
				return out
			}
		}
	}
	// Stable secondary sort by pkg+file+line for determinism.
	sort.SliceStable(out, func(i, j int) bool {
		ai, bi := out[i], out[j]
		if (ai.Name == name) != (bi.Name == name) {
			return ai.Name == name
		}
		if ai.Pkg != bi.Pkg {
			return ai.Pkg < bi.Pkg
		}
		return ai.Line < bi.Line
	})
	return out
}

// Callers returns the callers of the given fully-qualified symbol (pkg.Name
// or pkg.Recv.Method). Pagination via limit/offset; pass limit=0 for all.
// total is the unpaginated count.
func (s *Store) Callers(symbol string, limit, offset int) (callers []RefInfo, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.refs[symbol]
	total = len(all)
	if offset >= total {
		return nil, total
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	out := make([]RefInfo, end-offset)
	copy(out, all[offset:end])
	return out, total
}

// Callees returns the outgoing call edges from the given fully-qualified
// symbol. Note: the `from` field of each returned RefInfo holds the *callee*
// (qualified name) and File/Line points at the *call site* (in the caller's
// file). Pagination via limit/offset.
func (s *Store) Callees(symbol string, limit, offset int) (callees []RefInfo, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.calleesOf[symbol]
	total = len(all)
	if offset >= total {
		return nil, total
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	out := make([]RefInfo, end-offset)
	copy(out, all[offset:end])
	return out, total
}

// PackageSymbols returns the package meta and exported symbols.
func (s *Store) PackageSymbols(importPath string) (*PackageInfo, []SymbolInfo) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pkgByPath[importPath]
	if !ok {
		return nil, nil
	}
	var syms []SymbolInfo
	for _, sym := range s.symbols {
		if sym.Pkg == importPath {
			syms = append(syms, sym)
		}
	}
	return p, syms
}

// Templates returns templates matching the optional define name and file
// glob. Both filters are case-insensitive substring (define) and filepath
// match (glob). Pass empty strings to skip a filter.
func (s *Store) Templates(define, fileGlob string) []TemplateInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.templates == nil {
		return nil
	}
	defineLC := strings.ToLower(define)
	var out []TemplateInfo
	for _, t := range s.templates.Files {
		if fileGlob != "" {
			matched, err := filepath.Match(fileGlob, filepath.Base(t.File))
			if err != nil || !matched {
				continue
			}
		}
		if defineLC != "" {
			found := false
			for _, d := range t.Defines {
				if strings.Contains(strings.ToLower(d), defineLC) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

// HelmValue returns schema/template usage for a single dotted Helm key.
// schemaKnown indicates whether the key appears in values.schema.json.
type HelmLookup struct {
	Key             string        `json:"key"`
	SchemaKnown     bool          `json:"schema_known"`
	UsedInTemplates []ValueUseRef `json:"used_in_templates,omitempty"`
}

// HelmValue resolves a single dotted Helm key.
func (s *Store) HelmValue(key string) *HelmLookup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.helm == nil {
		return nil
	}
	lk := &HelmLookup{Key: key}
	for _, k := range s.helm.ValuesKeys {
		if k == key {
			lk.SchemaKnown = true
			break
		}
	}
	if uses, ok := s.helm.ValueUsage[key]; ok {
		lk.UsedInTemplates = append(lk.UsedInTemplates, uses...)
	}
	return lk
}

// CRDRelations returns the domain-map entry for a CRD (case-insensitive name).
func (s *Store) CRDRelations(name string) *DomainEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.domain == nil {
		return nil
	}
	for i := range s.domain.Entries {
		if strings.EqualFold(s.domain.Entries[i].CRD, name) {
			return &s.domain.Entries[i]
		}
	}
	return nil
}

// PythonTestHit is one matching pytest function (top-level or method).
type PythonTestHit struct {
	File    string   `json:"file"`
	Class   string   `json:"class,omitempty"`
	Test    string   `json:"test"`
	Line    int      `json:"line"`
	Markers []string `json:"markers,omitempty"`
}

// PythonTests searches pytest functions whose name contains the (case-
// insensitive) query. marker filters by exact marker name if non-empty.
func (s *Store) PythonTests(query, marker string, limit int) []PythonTestHit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pyTests == nil {
		return nil
	}
	q := strings.ToLower(query)
	var out []PythonTestHit
	hit := func(file string, class string, t PythonTest) bool {
		if q != "" && !strings.Contains(strings.ToLower(t.Name), q) {
			return false
		}
		if marker != "" && !containsString(t.Markers, marker) {
			return false
		}
		out = append(out, PythonTestHit{
			File: file, Class: class, Test: t.Name,
			Line: t.Line, Markers: t.Markers,
		})
		return limit > 0 && len(out) >= limit
	}
	for _, f := range s.pyTests.Files {
		for _, t := range f.TopTests {
			if hit(f.File, "", t) {
				return out
			}
		}
		for _, c := range f.Classes {
			for _, t := range c.Tests {
				if hit(f.File, c.Name, t) {
					return out
				}
			}
		}
	}
	return out
}

// Examples returns examples/** entries filtered by kind (required), and
// optionally name (case-insensitive substring) and group (exact subdir).
func (s *Store) Examples(kind, name, group string, limit int) []ExampleEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.examples == nil {
		return nil
	}
	nameLC := strings.ToLower(name)
	var out []ExampleEntry
	for _, e := range s.examples.Entries {
		if kind != "" && !strings.EqualFold(e.Kind, kind) {
			continue
		}
		if group != "" && e.Group != group {
			continue
		}
		if nameLC != "" && !strings.Contains(strings.ToLower(e.Name), nameLC) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// ReadResource returns the bytes of a top-level Markdown artifact by name
// (INDEX.md, domain-map.md, files.md). Unknown names return os.ErrNotExist.
func (s *Store) ReadResource(name string) ([]byte, error) {
	switch name {
	case "INDEX.md", "domain-map.md", "files.md":
		return os.ReadFile(filepath.Join(s.OutDir, name))
	}
	return nil, os.ErrNotExist
}

// ---- helpers ----

func readJSON(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return nil
}

func readSymbolsJSONL(path string) ([]SymbolInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read symbols.jsonl: %w", err)
	}
	defer f.Close()
	var out []SymbolInfo
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var s SymbolInfo
		if err := json.Unmarshal(line, &s); err != nil {
			return nil, fmt.Errorf("parse symbols.jsonl: %w", err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func readRefsJSONL(path string) (map[string][]RefInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read refs.jsonl: %w", err)
	}
	defer f.Close()
	out := make(map[string][]RefInfo, 4096)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var c CalleeRefs
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("parse refs.jsonl: %w", err)
		}
		out[c.To] = c.Callers
	}
	return out, sc.Err()
}

// invertRefs turns callee→[callers] into caller→[callees-with-call-sites].
func invertRefs(refs map[string][]RefInfo) map[string][]RefInfo {
	out := make(map[string][]RefInfo, len(refs))
	for callee, callers := range refs {
		for _, c := range callers {
			out[c.From] = append(out[c.From], RefInfo{
				From: callee, File: c.File, Line: c.Line,
			})
		}
	}
	for k, v := range out {
		sort.Slice(v, func(i, j int) bool {
			if v[i].From != v[j].From {
				return v[i].From < v[j].From
			}
			if v[i].File != v[j].File {
				return v[i].File < v[j].File
			}
			return v[i].Line < v[j].Line
		})
		out[k] = v
	}
	return out
}

func edgeCountOf(refs map[string][]RefInfo) int {
	n := 0
	for _, rs := range refs {
		n += len(rs)
	}
	return n
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
