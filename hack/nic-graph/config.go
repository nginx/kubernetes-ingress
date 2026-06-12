package nicgraph

import (
	"path/filepath"
	"strings"
)

// Config holds repo paths and runtime options.
type Config struct {
	Root    string
	OutDir  string
	Verbose bool
}

// GoLoadPatterns are the package patterns passed to go/packages.Load.
func (c Config) GoLoadPatterns() []string {
	return []string{"./internal/...", "./pkg/apis/..."}
}

// ModulePath is the Go module path for this repo. Hardcoded to avoid
// re-parsing go.mod on every run; nic-graph is only used from this repo.
const ModulePath = "github.com/nginx/kubernetes-ingress"

// MaxCallersPerSymbol caps the number of caller edges retained per callee in
// refs.jsonl to keep file size bounded. Symbols with more than this many
// callers get a `"truncated":true` marker.
const MaxCallersPerSymbol = 25

// IsExcludedGoFile returns true if a Go file should be skipped by the indexer.
// path is workspace-relative (forward slashes).
func IsExcludedGoFile(path string) bool {
	p := filepath.ToSlash(path)
	switch {
	case strings.HasPrefix(p, "pkg/client/"):
		return true
	case strings.Contains(p, "/fake/"):
		return true
	case strings.Contains(p, "/__snapshots__/"):
		return true
	case strings.Contains(p, "/test_files/"):
		return true
	case strings.HasPrefix(filepath.Base(p), "zz_generated"):
		return true
	case strings.HasSuffix(p, "_generated.go"):
		return true
	}
	return false
}

// IsExcludedPackage returns true if a package import path should be skipped.
func IsExcludedPackage(pkgPath string) bool {
	rel := strings.TrimPrefix(pkgPath, ModulePath+"/")
	if rel == pkgPath {
		// Not in our module — external.
		return true
	}
	switch {
	case strings.HasPrefix(rel, "pkg/client/"):
		return true
	case strings.HasSuffix(rel, "/fake"):
		return true
	}
	return false
}

// RelPath converts an absolute path to a repo-relative forward-slash path.
func (c Config) RelPath(abs string) string {
	rel, err := filepath.Rel(c.Root, abs)
	if err != nil {
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}
