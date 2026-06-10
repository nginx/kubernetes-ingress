package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// PackageInfo summarizes a Go package in our index.
type PackageInfo struct {
	ImportPath string   `json:"import_path"`
	Dir        string   `json:"dir"`
	Name       string   `json:"name"`
	Doc        string   `json:"doc,omitempty"`
	GoFiles    []string `json:"go_files"`
	Imports    []string `json:"imports,omitempty"` // in-repo only
}

// SymbolInfo is one row of symbols.jsonl.
type SymbolInfo struct {
	Kind      string `json:"kind"` // func, method, type, interface, struct, const, var
	Name      string `json:"name"`
	Pkg       string `json:"pkg"`            // import path
	Recv      string `json:"recv,omitempty"` // receiver type for methods
	File      string `json:"file"`           // repo-relative
	Line      int    `json:"line"`
	Exported  bool   `json:"exported"`
	Signature string `json:"signature,omitempty"`
}

// RefInfo represents one caller of a callee.
type RefInfo struct {
	From string `json:"from"` // qualified caller, e.g. internal/k8s.LoadBalancerController.sync
	File string `json:"file"`
	Line int    `json:"line"`
}

// CalleeRefs is one row of refs.jsonl.
type CalleeRefs struct {
	To        string    `json:"to"`
	Callers   []RefInfo `json:"callers"`
	Truncated bool      `json:"truncated,omitempty"`
}

// GoIndex aggregates all Go-language artifacts.
type GoIndex struct {
	Packages []PackageInfo
	Symbols  []SymbolInfo
	Imports  map[string][]string // pkg -> in-repo imports (sorted)
	// callee qualified name -> callers (sorted by from,file,line, deduped)
	Refs map[string][]RefInfo
	// derived helper: set of fully-qualified symbol names that exist (used for ref filtering and skill checks)
	SymbolKeys map[string]struct{}
}

func (gi *GoIndex) refCount() int {
	n := 0
	for _, rs := range gi.Refs {
		n += len(rs)
	}
	return n
}

func buildGoIndex(cfg Config) (*GoIndex, error) {
	loadCfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedTypesSizes |
			packages.NeedModule,
		Dir:   cfg.Root,
		Tests: false,
	}
	pkgs, err := packages.Load(loadCfg, cfg.GoLoadPatterns()...)
	if err != nil {
		return nil, err
	}
	// Note: packages.Load surfaces errors via pkg.Errors — log but don't fail the
	// build, because partial index is still useful.

	gi := &GoIndex{
		Imports:    make(map[string][]string),
		Refs:       make(map[string][]RefInfo),
		SymbolKeys: make(map[string]struct{}),
	}

	// First pass: collect packages + symbols. Filter excluded packages.
	indexed := make(map[string]*packages.Package) // import path -> pkg (kept)
	for _, p := range pkgs {
		if IsExcludedPackage(p.PkgPath) {
			continue
		}
		indexed[p.PkgPath] = p
	}

	for _, p := range sortedPackages(indexed) {
		info := PackageInfo{
			ImportPath: p.PkgPath,
			Name:       p.Name,
		}
		// Package doc: take from first non-empty file-level doc that comes from a non-test, non-generated file.
		for _, f := range p.Syntax {
			if f.Doc != nil && f.Doc.Text() != "" {
				rel := cfg.RelPath(p.Fset.File(f.Pos()).Name())
				if !IsExcludedGoFile(rel) && !strings.HasSuffix(rel, "_test.go") {
					info.Doc = firstSentence(f.Doc.Text())
					break
				}
			}
		}
		// File list + symbol extraction.
		fileSet := map[string]struct{}{}
		for i, f := range p.Syntax {
			absPath := p.Fset.File(f.Pos()).Name()
			rel := cfg.RelPath(absPath)
			if IsExcludedGoFile(rel) {
				continue
			}
			fileSet[rel] = struct{}{}
			extractSymbols(cfg, p, f, rel, gi)
			_ = i
		}
		for f := range fileSet {
			info.GoFiles = append(info.GoFiles, f)
		}
		sort.Strings(info.GoFiles)
		// Imports (in-repo only).
		for impPath := range p.Imports {
			if !IsExcludedPackage(impPath) {
				if _, ok := indexed[impPath]; ok {
					info.Imports = append(info.Imports, impPath)
				}
			}
		}
		sort.Strings(info.Imports)
		// Derive dir from any go file in this package.
		if len(info.GoFiles) > 0 {
			info.Dir = relDirOf(info.GoFiles[0])
		}
		gi.Packages = append(gi.Packages, info)
		gi.Imports[p.PkgPath] = info.Imports
	}

	// Build symbol key set for ref filtering.
	for _, s := range gi.Symbols {
		gi.SymbolKeys[symbolKey(s)] = struct{}{}
	}

	// Second pass: refs (call edges). Only emit edges where the callee is in
	// our symbol set; the caller can be any function in indexed packages.
	for _, p := range indexed {
		extractRefs(cfg, p, gi)
	}

	// Sort + cap.
	sort.Slice(gi.Symbols, func(i, j int) bool {
		a, b := gi.Symbols[i], gi.Symbols[j]
		if a.Pkg != b.Pkg {
			return a.Pkg < b.Pkg
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	for k, rs := range gi.Refs {
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].From != rs[j].From {
				return rs[i].From < rs[j].From
			}
			if rs[i].File != rs[j].File {
				return rs[i].File < rs[j].File
			}
			return rs[i].Line < rs[j].Line
		})
		// dedupe
		out := rs[:0]
		var prev RefInfo
		for i, r := range rs {
			if i == 0 || r != prev {
				out = append(out, r)
			}
			prev = r
		}
		gi.Refs[k] = out
	}

	return gi, nil
}

func sortedPackages(m map[string]*packages.Package) []*packages.Package {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*packages.Package, len(keys))
	for i, k := range keys {
		out[i] = m[k]
	}
	return out
}

func relDirOf(file string) string {
	if i := strings.LastIndex(file, "/"); i >= 0 {
		return file[:i]
	}
	return "."
}

func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	// First newline-newline (paragraph) or period+space.
	if i := strings.Index(text, "\n\n"); i >= 0 {
		text = text[:i]
	}
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 240 {
		text = text[:237] + "..."
	}
	return text
}

func extractSymbols(_ Config, p *packages.Package, f *ast.File, relFile string, gi *GoIndex) {
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			s := SymbolInfo{
				Name:     d.Name.Name,
				Pkg:      p.PkgPath,
				File:     relFile,
				Line:     posLine(p.Fset, d.Pos()),
				Exported: d.Name.IsExported(),
			}
			if d.Recv != nil && len(d.Recv.List) > 0 {
				s.Kind = "method"
				s.Recv = recvName(d.Recv.List[0].Type)
			} else {
				s.Kind = "func"
			}
			s.Signature = funcSignature(p, d)
			gi.Symbols = append(gi.Symbols, s)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch ss := spec.(type) {
				case *ast.TypeSpec:
					kind := "type"
					if _, ok := ss.Type.(*ast.InterfaceType); ok {
						kind = "interface"
					} else if _, ok := ss.Type.(*ast.StructType); ok {
						kind = "struct"
					}
					gi.Symbols = append(gi.Symbols, SymbolInfo{
						Kind:     kind,
						Name:     ss.Name.Name,
						Pkg:      p.PkgPath,
						File:     relFile,
						Line:     posLine(p.Fset, ss.Pos()),
						Exported: ss.Name.IsExported(),
					})
				case *ast.ValueSpec:
					kind := "var"
					if d.Tok == token.CONST {
						kind = "const"
					}
					for _, n := range ss.Names {
						if n.Name == "_" {
							continue
						}
						gi.Symbols = append(gi.Symbols, SymbolInfo{
							Kind:     kind,
							Name:     n.Name,
							Pkg:      p.PkgPath,
							File:     relFile,
							Line:     posLine(p.Fset, n.Pos()),
							Exported: n.IsExported(),
						})
					}
				}
			}
		}
	}
}

func posLine(fset *token.FileSet, p token.Pos) int {
	return fset.Position(p).Line
}

// recvName extracts the receiver type name from a method declaration, e.g.
// `*LoadBalancerController` -> "LoadBalancerController".
func recvName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	}
	return ""
}

func funcSignature(p *packages.Package, d *ast.FuncDecl) string {
	if p.TypesInfo == nil || d.Name == nil {
		return ""
	}
	obj := p.TypesInfo.Defs[d.Name]
	if obj == nil {
		return ""
	}
	sig := obj.Type().String()
	// Strip package path noise: replace fully qualified types in this module with short form.
	sig = strings.ReplaceAll(sig, ModulePath+"/", "")
	if len(sig) > 200 {
		sig = sig[:197] + "..."
	}
	return sig
}

// symbolKey is the canonical lookup key for a symbol used in refs.jsonl.
// Format: <pkg path>.<Name> for top-level, <pkg path>.<Recv>.<Name> for methods.
func symbolKey(s SymbolInfo) string {
	if s.Kind == "method" && s.Recv != "" {
		return s.Pkg + "." + s.Recv + "." + s.Name
	}
	return s.Pkg + "." + s.Name
}

// extractRefs walks every file's AST collecting CallExpr edges where the
// callee resolves to a symbol we've indexed.
func extractRefs(cfg Config, p *packages.Package, gi *GoIndex) {
	if p.TypesInfo == nil {
		return
	}
	for _, f := range p.Syntax {
		absPath := p.Fset.File(f.Pos()).Name()
		rel := cfg.RelPath(absPath)
		if IsExcludedGoFile(rel) {
			continue
		}
		// Caller scoping: walk decls so we can track enclosing function.
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			callerKey := funcDeclKey(p.PkgPath, fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				calleeKey := resolveCalleeKey(p.TypesInfo, call.Fun)
				if calleeKey == "" {
					return true
				}
				if _, ok := gi.SymbolKeys[calleeKey]; !ok {
					return true
				}
				if calleeKey == callerKey {
					return true // skip self-recursion noise
				}
				pos := p.Fset.Position(call.Pos())
				gi.Refs[calleeKey] = append(gi.Refs[calleeKey], RefInfo{
					From: callerKey,
					File: rel,
					Line: pos.Line,
				})
				return true
			})
		}
	}
}

func funcDeclKey(pkgPath string, fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		r := recvName(fd.Recv.List[0].Type)
		return pkgPath + "." + r + "." + fd.Name.Name
	}
	return pkgPath + "." + fd.Name.Name
}

// resolveCalleeKey turns a CallExpr.Fun into a qualified symbol key, or "" if
// it doesn't resolve to a top-level func/method in a package we care about.
func resolveCalleeKey(info *types.Info, fun ast.Expr) string {
	switch e := fun.(type) {
	case *ast.Ident:
		obj := info.Uses[e]
		return objectKey(obj, "")
	case *ast.SelectorExpr:
		// could be pkg.Func, recv.Method, Type.Method
		obj := info.Uses[e.Sel]
		if obj == nil {
			return ""
		}
		return objectKey(obj, "")
	case *ast.IndexExpr:
		return resolveCalleeKey(info, e.X)
	case *ast.IndexListExpr:
		return resolveCalleeKey(info, e.X)
	}
	return ""
}

func objectKey(obj types.Object, _ string) string {
	fn, ok := obj.(*types.Func)
	if !ok {
		return ""
	}
	pkg := fn.Pkg()
	if pkg == nil {
		return ""
	}
	if IsExcludedPackage(pkg.Path()) {
		return ""
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return pkg.Path() + "." + fn.Name()
	}
	if recv := sig.Recv(); recv != nil {
		return pkg.Path() + "." + recvTypeName(recv.Type()) + "." + fn.Name()
	}
	return pkg.Path() + "." + fn.Name()
}

func recvTypeName(t types.Type) string {
	switch tt := t.(type) {
	case *types.Pointer:
		return recvTypeName(tt.Elem())
	case *types.Named:
		return tt.Obj().Name()
	}
	return ""
}

// emit writes Go-index artifacts into the Artifacts bundle.
func (gi *GoIndex) emit(arts *Artifacts) error {
	if err := arts.PutJSON("packages.json", gi.Packages); err != nil {
		return err
	}
	if err := arts.PutJSON("imports.json", gi.Imports); err != nil {
		return err
	}
	// symbols.jsonl
	var sbuf bytes.Buffer
	for _, s := range gi.Symbols {
		line, err := jsonLine(s)
		if err != nil {
			return err
		}
		sbuf.Write(line)
	}
	arts.PutBytes("symbols.jsonl", sbuf.Bytes())
	// refs.jsonl — one row per callee, sorted by callee key.
	keys := make([]string, 0, len(gi.Refs))
	for k := range gi.Refs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rbuf bytes.Buffer
	for _, k := range keys {
		callers := gi.Refs[k]
		row := CalleeRefs{To: k}
		if len(callers) > MaxCallersPerSymbol {
			row.Callers = callers[:MaxCallersPerSymbol]
			row.Truncated = true
		} else {
			row.Callers = callers
		}
		line, err := jsonLine(row)
		if err != nil {
			return err
		}
		rbuf.Write(line)
	}
	arts.PutBytes("refs.jsonl", rbuf.Bytes())
	return nil
}

func jsonLine(v any) ([]byte, error) {
	b, err := jsonMarshalCompact(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return append(b, '\n'), nil
}
