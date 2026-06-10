package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// renderFilesMarkdown produces a per-package, per-file summary.
//
// Format:
//
//	## <import path>
//	_<package doc first sentence>_
//	- `file.go` — top-level exports: A, B, C
func renderFilesMarkdown(gi *GoIndex) []byte {
	// Group symbols by file.
	type fileSyms struct {
		file    string
		exports []string
	}
	byFile := map[string]*fileSyms{}
	for _, s := range gi.Symbols {
		if !s.Exported {
			continue
		}
		fs := byFile[s.File]
		if fs == nil {
			fs = &fileSyms{file: s.File}
			byFile[s.File] = fs
		}
		if s.Kind == "method" {
			fs.exports = append(fs.exports, fmt.Sprintf("(%s).%s", s.Recv, s.Name))
		} else {
			fs.exports = append(fs.exports, s.Name)
		}
	}

	var buf bytes.Buffer
	buf.WriteString("# Files\n\n")
	buf.WriteString("Per-package file index with top-level exported symbols. For wider context (architecture, layers, pipeline) load the `nic-structure` skill.\n\n")
	for _, p := range gi.Packages {
		fmt.Fprintf(&buf, "## %s\n\n", p.ImportPath)
		if p.Doc != "" {
			fmt.Fprintf(&buf, "_%s_\n\n", p.Doc)
		}
		for _, f := range p.GoFiles {
			fs := byFile[f]
			exports := ""
			if fs != nil && len(fs.exports) > 0 {
				cap := fs.exports
				sort.Strings(cap)
				if len(cap) > 12 {
					cap = append(cap[:12:12], "…")
				}
				exports = " — " + strings.Join(cap, ", ")
			}
			fmt.Fprintf(&buf, "- [%s](../%s)%s\n", f, f, exports)
		}
		buf.WriteString("\n")
	}
	return buf.Bytes()
}
