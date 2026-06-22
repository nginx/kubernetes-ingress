package nicgraph

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
	script := filepath.Join(cfg.Root, "hack/nic-graph/py_index.py")
	if _, err := os.Stat(script); err != nil {
		return &PythonTestIndex{Error: fmt.Sprintf("py_index.py missing: %v", err)}, nil
	}
	root := filepath.Join(cfg.Root, "tests/suite")
	if _, err := os.Stat(root); err != nil {
		// No tests dir: emit empty index instead of erroring.
		return &PythonTestIndex{}, nil
	}
	python, err := findPython()
	if err != nil {
		return &PythonTestIndex{Error: err.Error()}, nil
	}
	cmd := exec.Command(python, script, "--root", root, "--repo-root", cfg.Root)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return &PythonTestIndex{Error: fmt.Sprintf("py_index.py failed via %s: %v (run `nic-graph doctor` to diagnose)", python, err)}, nil
	}
	var idx PythonTestIndex
	if err := json.Unmarshal(out, &idx); err != nil {
		return &PythonTestIndex{Error: fmt.Sprintf("py_index.py output parse: %v", err)}, nil
	}
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].File < idx.Files[j].File })
	return &idx, nil
}

// findPython locates a usable Python 3 interpreter. Tries $NIC_GRAPH_PYTHON,
// then python3, then python (verifying major version 3). Returns a clear
// error if none is usable.
func findPython() (string, error) {
	candidates := []string{}
	if env := os.Getenv("NIC_GRAPH_PYTHON"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, "python3", "python")
	var tried []string
	for _, c := range candidates {
		path, err := exec.LookPath(c)
		if err != nil {
			tried = append(tried, c+" (not on PATH)")
			continue
		}
		ok, ver, vErr := isPython3(path)
		if vErr != nil {
			tried = append(tried, fmt.Sprintf("%s (%v)", path, vErr))
			continue
		}
		if !ok {
			tried = append(tried, fmt.Sprintf("%s (got %s, need 3.x)", path, ver))
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("no python3 interpreter found (tried: %v) — run `nic-graph doctor --install` to install one", tried)
}

func isPython3(path string) (ok bool, version string, err error) {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return false, "", err
	}
	version = string(out)
	if len(version) > 0 && version[len(version)-1] == '\n' {
		version = version[:len(version)-1]
	}
	// "Python 3.x.y" or "Python 2.7.x"
	return len(version) >= 8 && version[:8] == "Python 3", version, nil
}
