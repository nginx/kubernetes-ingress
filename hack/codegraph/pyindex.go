package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// PythonTestFile mirrors py_index.py's per-file output.
type PythonTestFile struct {
	File     string        `json:"file"`
	Classes  []PythonClass `json:"classes,omitempty"`
	TopTests []PythonTest  `json:"top_tests,omitempty"`
	Markers  []string      `json:"markers,omitempty"`
	Fixtures []string      `json:"fixtures,omitempty"`
}

// PythonClass groups tests inside a class.
type PythonClass struct {
	Name  string       `json:"name"`
	Line  int          `json:"line"`
	Tests []PythonTest `json:"tests,omitempty"`
}

// PythonTest is a single test function.
type PythonTest struct {
	Name    string   `json:"name"`
	Line    int      `json:"line"`
	Markers []string `json:"markers,omitempty"`
}

// PythonTestIndex is the python-tests.json payload.
type PythonTestIndex struct {
	Files []PythonTestFile `json:"files"`
	Error string           `json:"error,omitempty"`
}

func buildPythonTests(cfg Config) (*PythonTestIndex, error) {
	script := filepath.Join(cfg.Root, "hack/codegraph/py_index.py")
	if _, err := os.Stat(script); err != nil {
		return &PythonTestIndex{Error: fmt.Sprintf("py_index.py missing: %v", err)}, nil
	}
	root := filepath.Join(cfg.Root, "tests/suite")
	if _, err := os.Stat(root); err != nil {
		// No tests dir: emit empty index instead of erroring.
		return &PythonTestIndex{}, nil
	}
	python := os.Getenv("CODEGRAPH_PYTHON")
	if python == "" {
		python = "python3"
	}
	cmd := exec.Command(python, script, "--root", root, "--repo-root", cfg.Root)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		// Don't fail the whole build — Python may be missing in some environments.
		return &PythonTestIndex{Error: fmt.Sprintf("py_index.py failed: %v", err)}, nil
	}
	var idx PythonTestIndex
	if err := json.Unmarshal(out, &idx); err != nil {
		return &PythonTestIndex{Error: fmt.Sprintf("py_index.py output parse: %v", err)}, nil
	}
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].File < idx.Files[j].File })
	return &idx, nil
}
