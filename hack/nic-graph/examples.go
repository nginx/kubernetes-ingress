package nicgraph

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ExampleEntry describes an examples/ file.
type ExampleEntry struct {
	File  string `json:"file"`
	Kind  string `json:"kind,omitempty"`  // K8s kind for YAML, or "md"
	Name  string `json:"name,omitempty"`  // metadata.name or markdown title
	Group string `json:"group,omitempty"` // top-level subdir under examples/
}

// ExamplesIndex is the examples.json payload.
type ExamplesIndex struct {
	Entries []ExampleEntry `json:"entries"`
}

func buildExamples(cfg Config) (*ExamplesIndex, error) {
	idx := &ExamplesIndex{}
	root := filepath.Join(cfg.Root, "examples")
	if _, err := os.Stat(root); err != nil {
		return idx, nil
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		rel := cfg.RelPath(path)
		entry := ExampleEntry{File: rel, Group: groupOf(rel, "examples")}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml":
			kind, name := readYAMLKindName(path)
			entry.Kind = kind
			entry.Name = name
		case ".md":
			entry.Kind = "md"
			entry.Name = readFirstHeading(path)
		default:
			return nil
		}
		idx.Entries = append(idx.Entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(idx.Entries, func(i, j int) bool { return idx.Entries[i].File < idx.Entries[j].File })
	return idx, nil
}

// readYAMLKindName extracts top-level `kind:` and `metadata.name:` without a YAML parser.
// Good-enough for K8s manifests; handles multi-doc files by returning the first doc.
func readYAMLKindName(path string) (kind, name string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	inMeta := false
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" && kind != "" {
			return // stop at first doc once we have a kind
		}
		if strings.HasPrefix(line, "kind:") {
			kind = strings.TrimSpace(strings.TrimPrefix(line, "kind:"))
			continue
		}
		if strings.HasPrefix(line, "metadata:") {
			inMeta = true
			continue
		}
		if inMeta {
			// look for `  name: ...` at exactly 2 spaces indent
			if strings.HasPrefix(line, "  name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "  name:"))
				if kind != "" {
					return
				}
			} else if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inMeta = false
			}
		}
	}
	return kind, name
}

func readFirstHeading(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
	}
	return ""
}

func groupOf(rel, parent string) string {
	prefix := parent + "/"
	if !strings.HasPrefix(rel, prefix) {
		return ""
	}
	tail := rel[len(prefix):]
	if i := strings.Index(tail, "/"); i >= 0 {
		return tail[:i]
	}
	return ""
}
