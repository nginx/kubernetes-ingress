// Doctor subcommand: detect required/optional tools, optionally install
// missing ones via the system package manager. Designed for ephemeral
// sandboxes (Docker, devcontainers) where Python may not be present.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// toolCheck describes a runtime dependency.
type toolCheck struct {
	Name     string `json:"name"`
	Why      string `json:"why"`
	Required bool   `json:"required"`
	// candidates lists alternative executable names to try, in order.
	Candidates []string `json:"-"`
	// minMajor / minMinor enforce a minimum semver if >0.
	MinMajor int `json:"-"`
	MinMinor int `json:"-"`
	// pkgs maps package-manager name (apt, apk, dnf, brew) to its install name.
	Pkgs map[string]string `json:"-"`
}

type toolResult struct {
	toolCheck
	Found      bool   `json:"found"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	VersionErr string `json:"version_error,omitempty"`
}

var tools = []toolCheck{
	{
		Name:       "go",
		Why:        "compile and run nic-graph",
		Required:   true,
		Candidates: []string{"go"},
		MinMajor:   1, MinMinor: 21,
		Pkgs: map[string]string{"apt": "golang-go", "apk": "go", "dnf": "golang", "brew": "go"},
	},
	{
		Name:       "python3",
		Why:        "index pytest files under tests/suite/ (py_index.py)",
		Required:   true,
		Candidates: []string{"python3", "python"},
		MinMajor:   3, MinMinor: 0,
		Pkgs: map[string]string{"apt": "python3-minimal", "apk": "python3", "dnf": "python3", "brew": "python@3"},
	},
	{
		Name:       "jq",
		Why:        "optional: pretty-print / filter JSON output from nic-graph",
		Required:   false,
		Candidates: []string{"jq"},
		Pkgs:       map[string]string{"apt": "jq", "apk": "jq", "dnf": "jq", "brew": "jq"},
	},
}

func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	doInstall := fs.Bool("install", false, "best-effort install of missing required deps via detected package manager")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of a table")
	_ = fs.Parse(args)

	results := make([]toolResult, 0, len(tools))
	for _, t := range tools {
		results = append(results, checkTool(t))
	}

	if *jsonOut {
		emit(map[string]any{"tools": results, "os": runtime.GOOS, "package_manager": detectPM()})
		os.Exit(exitCodeForResults(results))
	}

	printDoctorTable(os.Stderr, results)

	missing := missingRequired(results)
	if *doInstall && len(missing) > 0 {
		if err := installMissing(missing); err != nil {
			fmt.Fprintf(os.Stderr, "\ninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "\nre-checking after install…")
		results = results[:0]
		for _, t := range tools {
			results = append(results, checkTool(t))
		}
		printDoctorTable(os.Stderr, results)
	}
	os.Exit(exitCodeForResults(results))
}

func checkTool(t toolCheck) toolResult {
	r := toolResult{toolCheck: t}
	for _, cand := range t.Candidates {
		path, err := exec.LookPath(cand)
		if err != nil {
			continue
		}
		r.Found = true
		r.Path = path
		v, vErr := readVersion(cand)
		r.Version = v
		if vErr != nil {
			r.VersionErr = vErr.Error()
		}
		if t.MinMajor > 0 {
			maj, min, ok := parseSemver(v)
			if !ok {
				r.VersionErr = "unable to parse version"
			} else if maj < t.MinMajor || (maj == t.MinMajor && min < t.MinMinor) {
				r.VersionErr = fmt.Sprintf("version %d.%d below required %d.%d", maj, min, t.MinMajor, t.MinMinor)
			}
		}
		break
	}
	return r
}

// readVersion runs `<cmd> --version` (with a special case for Go) and
// returns the first line of trimmed output.
func readVersion(cmd string) (string, error) {
	flag := "--version"
	if cmd == "go" {
		flag = "version"
	}
	out, err := exec.Command(cmd, flag).CombinedOutput()
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return line, nil
}

// parseSemver extracts the first major.minor pair from a version string.
// Tolerates prefixes like "Python ", "go version go", "jq-".
func parseSemver(s string) (major, minor int, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		j := i
		for j < len(s) && (s[j] >= '0' && s[j] <= '9') {
			j++
		}
		if j >= len(s) || s[j] != '.' {
			i = j
			continue
		}
		k := j + 1
		for k < len(s) && (s[k] >= '0' && s[k] <= '9') {
			k++
		}
		if k == j+1 {
			i = j
			continue
		}
		_, errMaj := fmt.Sscanf(s[i:j], "%d", &major)
		_, errMin := fmt.Sscanf(s[j+1:k], "%d", &minor)
		if errMaj == nil && errMin == nil {
			return major, minor, true
		}
	}
	return 0, 0, false
}

func missingRequired(results []toolResult) []toolResult {
	var out []toolResult
	for _, r := range results {
		if r.Required && (!r.Found || r.VersionErr != "") {
			out = append(out, r)
		}
	}
	return out
}

func exitCodeForResults(results []toolResult) int {
	if len(missingRequired(results)) > 0 {
		return 1
	}
	return 0
}

func printDoctorTable(w io.Writer, results []toolResult) {
	fmt.Fprintln(w, "nic-graph doctor — runtime dependency check")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-10s %-9s %-30s %s\n", "TOOL", "STATUS", "VERSION/PATH", "NOTE")
	fmt.Fprintf(w, "  %-10s %-9s %-30s %s\n", "----", "------", "------------", "----")
	for _, r := range results {
		status := "MISSING"
		switch {
		case r.Found && r.VersionErr == "":
			status = "OK"
		case r.Found:
			status = "BAD"
		case !r.Required:
			status = "absent"
		}
		ver := r.Version
		if ver == "" {
			ver = "\u2014"
		}
		note := r.Why
		if r.VersionErr != "" {
			note = r.VersionErr
		}
		fmt.Fprintf(w, "  %-10s %-9s %-30s %s\n", r.Name, status, truncate(ver, 30), note)
	}
	fmt.Fprintln(w)
	missing := missingRequired(results)
	if len(missing) == 0 {
		fmt.Fprintln(w, "all required dependencies present.")
		return
	}
	pm := detectPM()
	fmt.Fprintf(w, "missing required dependencies: ")
	names := []string{}
	for _, r := range missing {
		names = append(names, r.Name)
	}
	fmt.Fprintln(w, strings.Join(names, ", "))
	if cmd := installCommand(pm, missing); cmd != "" {
		fmt.Fprintf(w, "to install (detected %s): %s\n", pm, cmd)
		fmt.Fprintln(w, "or run: nic-graph doctor --install")
	} else {
		fmt.Fprintln(w, "no supported package manager detected; install manually.")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "go toolchain: nic-graph requires Go ≥1.21 locally. The exact patch")
	fmt.Fprintln(w, "version in go.mod is fetched automatically via GOTOOLCHAIN=auto")
	fmt.Fprintln(w, "(default on Go 1.21+) — no need to install a specific Go version.")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// detectPM returns the first supported package manager found on PATH.
func detectPM() string {
	for _, pm := range []string{"apt-get", "apk", "dnf", "yum", "brew"} {
		if _, err := exec.LookPath(pm); err == nil {
			switch pm {
			case "apt-get":
				return "apt"
			case "yum":
				return "dnf"
			default:
				return pm
			}
		}
	}
	return ""
}

func installCommand(pm string, missing []toolResult) string {
	if pm == "" {
		return ""
	}
	var pkgs []string
	for _, r := range missing {
		if p := r.Pkgs[pm]; p != "" {
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) == 0 {
		return ""
	}
	pkgList := strings.Join(pkgs, " ")
	switch pm {
	case "apt":
		return "sudo apt-get update && sudo apt-get install -y " + pkgList
	case "apk":
		return "apk add --no-cache " + pkgList
	case "dnf":
		return "sudo dnf install -y " + pkgList
	case "brew":
		return "brew install " + pkgList
	}
	return ""
}

func installMissing(missing []toolResult) error {
	pm := detectPM()
	if pm == "" {
		return errors.New("no supported package manager (apt/apk/dnf/brew) found on PATH")
	}
	var pkgs []string
	for _, r := range missing {
		if p := r.Pkgs[pm]; p != "" {
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) == 0 {
		return errors.New("no install names available for the missing tools on this OS")
	}

	type step struct {
		name string
		args []string
	}
	var steps []step
	switch pm {
	case "apt":
		if os.Geteuid() != 0 {
			steps = []step{
				{"sudo", []string{"apt-get", "update"}},
				{"sudo", append([]string{"apt-get", "install", "-y"}, pkgs...)},
			}
		} else {
			steps = []step{
				{"apt-get", []string{"update"}},
				{"apt-get", append([]string{"install", "-y"}, pkgs...)},
			}
		}
	case "apk":
		steps = []step{{"apk", append([]string{"add", "--no-cache"}, pkgs...)}}
	case "dnf":
		if os.Geteuid() != 0 {
			steps = []step{{"sudo", append([]string{"dnf", "install", "-y"}, pkgs...)}}
		} else {
			steps = []step{{"dnf", append([]string{"install", "-y"}, pkgs...)}}
		}
	case "brew":
		steps = []step{{"brew", append([]string{"install"}, pkgs...)}}
	}

	for _, s := range steps {
		fmt.Fprintf(os.Stderr, "+ %s %s\n", s.name, strings.Join(s.args, " "))
		cmd := exec.Command(s.name, s.args...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s %s: %w", s.name, strings.Join(s.args, " "), err)
		}
	}
	return nil
}
