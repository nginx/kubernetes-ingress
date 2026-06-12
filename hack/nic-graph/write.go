package nicgraph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Artifacts collects every file the indexer will write to disk. Phases populate
// it independently; writeAll renders the map in one deterministic pass.
type Artifacts struct {
	// path (relative to OutDir) -> bytes
	files map[string][]byte
}

func NewArtifacts() *Artifacts {
	return &Artifacts{files: make(map[string][]byte)}
}

// PutBytes registers a raw byte payload.
func (a *Artifacts) PutBytes(relPath string, b []byte) {
	if !bytes.HasSuffix(b, []byte("\n")) {
		b = append(b, '\n')
	}
	a.files[relPath] = b
}

// PutJSON marshals v with indented JSON and registers it.
func (a *Artifacts) PutJSON(relPath string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", relPath, err)
	}
	a.PutBytes(relPath, b)
	return nil
}

// PutJSONL marshals each item to a single-line JSON object.
func (a *Artifacts) PutJSONL(relPath string, items []any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return fmt.Errorf("marshal %s: %w", relPath, err)
		}
	}
	a.PutBytes(relPath, buf.Bytes())
	return nil
}

// writeAll writes every artifact under outDir, removing any stale files there
// that we didn't generate this run.
func (a *Artifacts) writeAll(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	// Track what we wrote.
	written := make(map[string]struct{}, len(a.files))
	for rel, content := range a.files {
		full := filepath.Join(outDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			return err
		}
		written[rel] = struct{}{}
	}
	// Sweep stale files under outDir.
	return filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(outDir, path)
		if _, ok := written[rel]; !ok {
			return os.Remove(path)
		}
		return nil
	})
}

// diffAll compares artifacts against on-disk content under outDir. Returns the
// list of stale file paths (relative to outDir) and a flag for whether the
// directory contained files we no longer emit.
func (a *Artifacts) diffAll(outDir string) ([]string, error) {
	var stale []string
	seen := make(map[string]struct{}, len(a.files))
	for rel, content := range a.files {
		seen[rel] = struct{}{}
		full := filepath.Join(outDir, rel)
		existing, err := os.ReadFile(full)
		if err != nil {
			stale = append(stale, rel)
			continue
		}
		if !bytes.Equal(existing, content) {
			stale = append(stale, rel)
		}
	}
	// Detect files on disk that we no longer emit.
	_ = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(outDir, path)
		if _, ok := seen[rel]; !ok {
			stale = append(stale, rel+" (orphan)")
		}
		return nil
	})
	return stale, nil
}
