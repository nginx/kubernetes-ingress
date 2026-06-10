package main

import (
	"fmt"
	"log"
)

// runBuild executes every phase and writes the artifacts to disk.
func runBuild(cfg Config) error {
	arts, err := generate(cfg)
	if err != nil {
		return err
	}
	if err := arts.writeAll(cfg.OutDir); err != nil {
		return fmt.Errorf("write artifacts: %w", err)
	}
	return nil
}

// runCheck regenerates in-memory and diffs against disk. Returns (ok, err).
func runCheck(cfg Config) (bool, error) {
	arts, err := generate(cfg)
	if err != nil {
		return false, err
	}
	stale, err := arts.diffAll(cfg.OutDir)
	if err != nil {
		return false, err
	}
	if len(stale) == 0 {
		return true, nil
	}
	for _, s := range stale {
		fmt.Printf("  stale: %s\n", s)
	}
	return false, nil
}

// generate runs every phase and assembles all artifacts.
func generate(cfg Config) (*Artifacts, error) {
	arts := NewArtifacts()

	// Phase 1 — Go core: packages, symbols, imports, refs.
	gi, err := buildGoIndex(cfg)
	if err != nil {
		return nil, fmt.Errorf("go index: %w", err)
	}
	if err := gi.emit(arts); err != nil {
		return nil, err
	}
	if cfg.Verbose {
		log.Printf("go: %d packages, %d symbols, %d ref edges", len(gi.Packages), len(gi.Symbols), gi.refCount())
	}

	// Phase 4 — Templates & Helm.
	tmpls, err := buildTemplates(cfg)
	if err != nil {
		return nil, fmt.Errorf("templates: %w", err)
	}
	if err := arts.PutJSON("templates.json", tmpls); err != nil {
		return nil, err
	}

	helm, err := buildHelm(cfg)
	if err != nil {
		return nil, fmt.Errorf("helm: %w", err)
	}
	if err := arts.PutJSON("helm.json", helm); err != nil {
		return nil, err
	}

	// Phase 2 — Domain map (depends on Go index + templates).
	dm := buildDomainMap(cfg, gi, tmpls)
	if err := arts.PutJSON("domain-map.json", dm); err != nil {
		return nil, err
	}
	arts.PutBytes("domain-map.md", renderDomainMapMarkdown(dm))

	// Phase 3 — File & package summaries.
	arts.PutBytes("files.md", renderFilesMarkdown(gi))

	// Phase 5 — Python and examples. docs/ is intentionally NOT indexed
	// (human-only consumption).
	pt, err := buildPythonTests(cfg)
	if err != nil {
		return nil, fmt.Errorf("python tests: %w", err)
	}
	if err := arts.PutJSON("python-tests.json", pt); err != nil {
		return nil, err
	}

	ex, err := buildExamples(cfg)
	if err != nil {
		return nil, fmt.Errorf("examples: %w", err)
	}
	if err := arts.PutJSON("examples.json", ex); err != nil {
		return nil, err
	}

	// Phase 6 — INDEX.md (last, summarises everything).
	arts.PutBytes("INDEX.md", renderIndexMarkdown(gi, dm, tmpls, helm, pt, ex))

	return arts, nil
}
