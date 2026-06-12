package nicgraph

import (
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// overridesFile is the schema for hack/nic-graph/overrides.yaml.
//
//	entries:
//	  - crd: VirtualServerRoute
//	    add:
//	      validators: ["pkg/apis/configuration/validation.NewVirtualServerValidator"]
//	      configs:    ["internal/configs.VirtualServerEx"]
//	      tests:      ["internal/configs/virtualserver_routing_test.go"]
//	      sources:    ["internal/configs/virtualserver.go"]
//	      templates:  ["internal/configs/version2/nginx.virtualserver.tmpl"]
//	    remove:
//	      configs: ["internal/configs.someFalsePositive"]
type overridesFile struct {
	Entries []overrideEntry `yaml:"entries"`
}

type overrideEntry struct {
	CRD    string             `yaml:"crd"`
	Add    overrideCategories `yaml:"add"`
	Remove overrideCategories `yaml:"remove"`
}

type overrideCategories struct {
	Validators []string `yaml:"validators"`
	Configs    []string `yaml:"configs"`
	Tests      []string `yaml:"tests"`
	Sources    []string `yaml:"sources"`
	Templates  []string `yaml:"templates"`
}

// loadOverridesSilently reads hack/nic-graph/overrides.yaml relative to the
// repo root. Missing or malformed files yield an empty override set; the
// generator never fails on overrides.
func loadOverridesSilently(cfg Config) map[string]overrideEntry {
	path := filepath.Join(cfg.Root, "hack", "nic-graph", "overrides.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f overridesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil
	}
	out := make(map[string]overrideEntry, len(f.Entries))
	for _, e := range f.Entries {
		if e.CRD == "" {
			continue
		}
		out[e.CRD] = e
	}
	return out
}

// applyOverride mutates the per-CRD sets and the templates slice in place
// according to an overrides.yaml entry, if one exists for crd.
func applyOverride(
	overrides map[string]overrideEntry,
	crd string,
	validators, configs, tests, sources *stringSet,
	templates *[]string,
) {
	if overrides == nil {
		return
	}
	ov, ok := overrides[crd]
	if !ok {
		return
	}
	for _, v := range ov.Add.Validators {
		validators.add(v)
	}
	for _, v := range ov.Add.Configs {
		configs.add(v)
	}
	for _, v := range ov.Add.Tests {
		tests.add(v)
	}
	for _, v := range ov.Add.Sources {
		sources.add(v)
	}
	for _, v := range ov.Remove.Validators {
		validators.remove(v)
	}
	for _, v := range ov.Remove.Configs {
		configs.remove(v)
	}
	for _, v := range ov.Remove.Tests {
		tests.remove(v)
	}
	for _, v := range ov.Remove.Sources {
		sources.remove(v)
	}
	if len(ov.Add.Templates) > 0 || len(ov.Remove.Templates) > 0 {
		seen := stringSet{}
		for _, v := range *templates {
			seen.add(v)
		}
		for _, v := range ov.Add.Templates {
			seen.add(v)
		}
		for _, v := range ov.Remove.Templates {
			seen.remove(v)
		}
		out := make([]string, 0, len(seen))
		for k := range seen {
			out = append(out, k)
		}
		sort.Strings(out)
		*templates = out
	}
}
