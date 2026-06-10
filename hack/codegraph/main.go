// Command codegraph builds a static index of the NIC repository under
// `.codegraph/` to give AI agents fast, low-token lookups for symbols,
// callers, CRD→template chains, Helm values, and more.
//
// See hack/codegraph/README.md for details.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("codegraph: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	root := fs.String("root", "", "repo root (default: auto-detect from cwd)")
	outDir := fs.String("out", ".codegraph", "output directory relative to repo root")
	verbose := fs.Bool("v", false, "verbose logging")
	_ = fs.Parse(os.Args[2:])

	resolvedRoot, err := resolveRoot(*root)
	if err != nil {
		log.Fatal(err)
	}
	cfg := Config{
		Root:    resolvedRoot,
		OutDir:  filepath.Join(resolvedRoot, *outDir),
		Verbose: *verbose,
	}

	start := time.Now()
	switch cmd {
	case "build":
		if err := runBuild(cfg); err != nil {
			log.Fatal(err)
		}
		log.Printf("build done in %s", time.Since(start).Round(time.Millisecond))
	case "check":
		ok, err := runCheck(cfg)
		if err != nil {
			log.Fatal(err)
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "codegraph: .codegraph/ is stale. Run `make codegraph` and commit the result.")
			os.Exit(1)
		}
		log.Printf("check ok in %s", time.Since(start).Round(time.Millisecond))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: codegraph <command> [flags]

Commands:
  build    Generate the index under .codegraph/
  check    Verify .codegraph/ matches what would be generated (drift check)

Flags:
  -root <dir>   Repo root (default: auto-detect)
  -out <dir>    Output directory relative to root (default: .codegraph)
  -v            Verbose logging`)
}

func resolveRoot(explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Walk upward until we find go.mod.
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod above %s", cwd)
		}
		dir = parent
	}
}
