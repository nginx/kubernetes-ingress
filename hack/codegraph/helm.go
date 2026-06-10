package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// HelmIndex is the helm.json payload.
type HelmIndex struct {
	ValuesKeys   []string                 `json:"values_keys"`   // dotted keys derived from values.schema.json
	Templates    []string                 `json:"templates"`     // template files (repo-relative)
	ValueUsage   map[string][]ValueUseRef `json:"value_usage"`   // .Values.X.Y -> list of (file:line)
	IncludeUsage map[string][]ValueUseRef `json:"include_usage"` // named partial -> list of (file:line)
}

// ValueUseRef points at a single textual usage of a value or include.
type ValueUseRef struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

var (
	helmValuesRe  = regexp.MustCompile(`\.Values((?:\.[A-Za-z0-9_]+)+)`)
	helmIncludeRe = regexp.MustCompile(`include\s+"([^"]+)"`)
)

func buildHelm(cfg Config) (*HelmIndex, error) {
	idx := &HelmIndex{
		ValueUsage:   map[string][]ValueUseRef{},
		IncludeUsage: map[string][]ValueUseRef{},
	}
	// 1) values.schema.json -> dotted keys.
	schemaPath := filepath.Join(cfg.Root, "charts/nginx-ingress/values.schema.json")
	if data, err := os.ReadFile(schemaPath); err == nil {
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err == nil {
			collectSchemaKeys("", schema, &idx.ValuesKeys)
			sort.Strings(idx.ValuesKeys)
		}
	}

	// 2) walk templates dir.
	tmplDir := filepath.Join(cfg.Root, "charts/nginx-ingress/templates")
	err := filepath.Walk(tmplDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel := cfg.RelPath(path)
		idx.Templates = append(idx.Templates, rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		recordHelmUsages(rel, data, idx)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(idx.Templates)
	// Sort the slice values for stable diffs.
	for k := range idx.ValueUsage {
		sort.Slice(idx.ValueUsage[k], func(i, j int) bool {
			a, b := idx.ValueUsage[k][i], idx.ValueUsage[k][j]
			if a.File != b.File {
				return a.File < b.File
			}
			return a.Line < b.Line
		})
	}
	for k := range idx.IncludeUsage {
		sort.Slice(idx.IncludeUsage[k], func(i, j int) bool {
			a, b := idx.IncludeUsage[k][i], idx.IncludeUsage[k][j]
			if a.File != b.File {
				return a.File < b.File
			}
			return a.Line < b.Line
		})
	}
	return idx, nil
}

func recordHelmUsages(rel string, data []byte, idx *HelmIndex) {
	for i, line := range strings.Split(string(data), "\n") {
		for _, m := range helmValuesRe.FindAllStringSubmatch(line, -1) {
			key := strings.TrimPrefix(m[1], ".")
			idx.ValueUsage[key] = append(idx.ValueUsage[key], ValueUseRef{File: rel, Line: i + 1})
		}
		for _, m := range helmIncludeRe.FindAllStringSubmatch(line, -1) {
			idx.IncludeUsage[m[1]] = append(idx.IncludeUsage[m[1]], ValueUseRef{File: rel, Line: i + 1})
		}
	}
}

// collectSchemaKeys walks a JSON schema object and emits dotted leaf paths.
func collectSchemaKeys(prefix string, node any, out *[]string) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	if props, ok := obj["properties"].(map[string]any); ok {
		for name, sub := range props {
			key := name
			if prefix != "" {
				key = prefix + "." + name
			}
			*out = append(*out, key)
			collectSchemaKeys(key, sub, out)
		}
	}
}
