package nicgraph

import (
	"fmt"
	"os"
	"path/filepath"
)

// RunBuild executes the full build pipeline and writes artifacts under
// cfg.OutDir. It returns the in-memory Artifacts so callers (e.g. an MCP
// server) can also inspect what was generated without a second pass.
func RunBuild(cfg Config) (*Artifacts, error) {
	arts, err := generate(cfg)
	if err != nil {
		return nil, err
	}
	if err := arts.writeAll(cfg.OutDir); err != nil {
		return nil, fmt.Errorf("write artifacts: %w", err)
	}
	return arts, nil
}

// RunCheck regenerates in-memory and diffs against on-disk content.
// Returns the list of stale file paths (empty == no drift) and an error.
func RunCheck(cfg Config) ([]string, error) {
	arts, err := generate(cfg)
	if err != nil {
		return nil, err
	}
	return arts.diffAll(cfg.OutDir)
}

// ResolveRoot returns the absolute repo root. When explicit is empty, it
// walks upward from cwd until it finds a go.mod.
func ResolveRoot(explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod above %s", cwd)
		}
		dir = parent
	}
}
