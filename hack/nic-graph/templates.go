package nicgraph

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// TemplateInfo summarizes one .tmpl file.
type TemplateInfo struct {
	File     string   `json:"file"`               // repo-relative
	Variant  string   `json:"variant"`            // oss, plus, or unknown
	Pair     string   `json:"pair,omitempty"`     // basename without variant prefix, used to pair OSS/Plus
	Defines  []string `json:"defines,omitempty"`  // {{ define "X" }} names
	Includes []string `json:"includes,omitempty"` // {{ template "X" ... }} names
	Blocks   []string `json:"blocks,omitempty"`   // {{ block "X" ... }} names
}

// TemplateIndex is the templates.json payload.
type TemplateIndex struct {
	Files []TemplateInfo `json:"files"`
	// Pairs maps pair name -> [oss file, plus file] when both exist.
	Pairs map[string][]string `json:"pairs"`
}

var (
	tmplDefineRe   = regexp.MustCompile(`{{-?\s*define\s+"([^"]+)"`)
	tmplTemplateRe = regexp.MustCompile(`{{-?\s*template\s+"([^"]+)"`)
	tmplBlockRe    = regexp.MustCompile(`{{-?\s*block\s+"([^"]+)"`)
)

func buildTemplates(cfg Config) (*TemplateIndex, error) {
	idx := &TemplateIndex{Pairs: map[string][]string{}}
	for _, sub := range []string{"internal/configs/version1", "internal/configs/version2"} {
		dir := filepath.Join(cfg.Root, sub)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if info.IsDir() {
				if info.Name() == "__snapshots__" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(info.Name(), ".tmpl") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel := cfg.RelPath(path)
			t := TemplateInfo{
				File:     rel,
				Variant:  templateVariant(info.Name()),
				Pair:     templatePair(info.Name()),
				Defines:  unique(findAll(tmplDefineRe, data)),
				Includes: unique(findAll(tmplTemplateRe, data)),
				Blocks:   unique(findAll(tmplBlockRe, data)),
			}
			idx.Files = append(idx.Files, t)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].File < idx.Files[j].File })
	// Build pairs.
	for _, f := range idx.Files {
		if f.Pair == "" {
			continue
		}
		idx.Pairs[f.Pair] = append(idx.Pairs[f.Pair], f.File)
	}
	for k := range idx.Pairs {
		sort.Strings(idx.Pairs[k])
	}
	return idx, nil
}

func templateVariant(name string) string {
	switch {
	case strings.HasPrefix(name, "nginx-plus"):
		return "plus"
	case strings.HasPrefix(name, "nginx."):
		return "oss"
	}
	return "unknown"
}

// templatePair returns a normalized pair key so OSS + Plus variants group.
// e.g. "nginx-plus.virtualserver.tmpl" and "nginx.virtualserver.tmpl" both
// yield "virtualserver.tmpl".
func templatePair(name string) string {
	switch {
	case strings.HasPrefix(name, "nginx-plus."):
		return strings.TrimPrefix(name, "nginx-plus.")
	case strings.HasPrefix(name, "nginx."):
		return strings.TrimPrefix(name, "nginx.")
	}
	return ""
}

func findAll(re *regexp.Regexp, data []byte) []string {
	matches := re.FindAllSubmatch(data, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, string(m[1]))
	}
	return out
}

func unique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
