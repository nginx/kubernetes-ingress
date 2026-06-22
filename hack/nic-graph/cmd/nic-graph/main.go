// Command nic-graph builds and queries the static NIC code index under
// .nic-graph/. It is the single entry point for everything humans and AI
// agents need: build the index, drift-check it in CI, and run typed
// lookups (symbols, callers, templates, Helm values, CRD wiring, tests,
// examples). Every query subcommand prints JSON to stdout.
//
// See hack/nic-graph/README.md for full usage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	nicgraph "github.com/nginx/kubernetes-ingress/hack/nic-graph"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("nic-graph: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "build":
		runBuild(args)
	case "check":
		runCheck(args)
	case "stats":
		runStats(args)
	case "doctor":
		runDoctor(args)
	case "find-symbol":
		runFindSymbol(args)
	case "find-callers":
		runFindCallers(args)
	case "find-callees":
		runFindCallees(args)
	case "list-package":
		runListPackage(args)
	case "find-template":
		runFindTemplate(args)
	case "find-helm-value":
		runFindHelmValue(args)
	case "crd-relations":
		runCRDRelations(args)
	case "find-python-test":
		runFindPythonTest(args)
	case "find-example":
		runFindExample(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

// ---- common ----

// commonFlags wires --root and --out onto a flag set and returns pointers.
func commonFlags(fs *flag.FlagSet) (root, out *string) {
	root = fs.String("root", "", "repo root (default: auto-detect from cwd)")
	out = fs.String("out", ".nic-graph", "output directory relative to repo root")
	return
}

func resolveConfig(root, out string, verbose bool) nicgraph.Config {
	resolved, err := nicgraph.ResolveRoot(root)
	if err != nil {
		log.Fatal(err)
	}
	return nicgraph.Config{
		Root:    resolved,
		OutDir:  filepath.Join(resolved, out),
		Verbose: verbose,
	}
}

// openStore opens the store, auto-building if .nic-graph/ is absent.
func openStore(cfg nicgraph.Config, autoBuild bool) *nicgraph.Store {
	if _, err := os.Stat(cfg.OutDir); err != nil {
		if !autoBuild {
			log.Fatalf("%s not found; run `make nic-graph` first", cfg.OutDir)
		}
		log.Printf("%s missing; running initial build…", cfg.OutDir)
		if _, err := nicgraph.RunBuild(cfg); err != nil {
			log.Fatalf("initial build failed: %v", err)
		}
	}
	store, err := nicgraph.OpenStore(cfg.OutDir)
	if err != nil {
		log.Fatal(err)
	}
	return store
}

// emit pretty-prints v as JSON to stdout.
func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}

// ---- build / check / stats ----

func runBuild(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	root, out := commonFlags(fs)
	verbose := fs.Bool("v", false, "verbose logging")
	_ = fs.Parse(args)
	cfg := resolveConfig(*root, *out, *verbose)
	start := time.Now()
	if _, err := nicgraph.RunBuild(cfg); err != nil {
		log.Fatal(err)
	}
	log.Printf("build done in %s", time.Since(start).Round(time.Millisecond))
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	root, out := commonFlags(fs)
	verbose := fs.Bool("v", false, "verbose logging")
	_ = fs.Parse(args)
	cfg := resolveConfig(*root, *out, *verbose)
	start := time.Now()
	stale, err := nicgraph.RunCheck(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if len(stale) > 0 {
		for _, s := range stale {
			fmt.Printf("  stale: %s\n", s)
		}
		fmt.Fprintln(os.Stderr, "nic-graph: .nic-graph/ is stale. Run `make nic-graph` and commit the result.")
		os.Exit(1)
	}
	log.Printf("check ok in %s", time.Since(start).Round(time.Millisecond))
}

func runStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	root, out := commonFlags(fs)
	_ = fs.Parse(args)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	emit(store.Stats())
}

// ---- query subcommands ----

func runFindSymbol(args []string) {
	fs := flag.NewFlagSet("find-symbol", flag.ExitOnError)
	root, out := commonFlags(fs)
	kind := fs.String("kind", "", "filter by kind (func, method, type, struct, interface, const, var)")
	limit := fs.Int("limit", 50, "max results (0 = no cap)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph find-symbol <name> [flags]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	name := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	matches := store.FindSymbol(name, *kind, *limit)
	emit(map[string]any{"matches": matches, "total": len(matches)})
}

type callerEntry struct {
	From string `json:"from"`
	File string `json:"file"`
	Line int    `json:"line"`
}

func runFindCallers(args []string) {
	fs := flag.NewFlagSet("find-callers", flag.ExitOnError)
	root, out := commonFlags(fs)
	limit := fs.Int("limit", 25, "max results (0 = no cap)")
	offset := fs.Int("offset", 0, "pagination offset")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph find-callers <qualified-symbol> [flags]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	symbol := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	refs, total := store.Callers(symbol, *limit, *offset)
	entries := make([]callerEntry, 0, len(refs))
	for _, r := range refs {
		entries = append(entries, callerEntry{From: r.From, File: r.File, Line: r.Line})
	}
	emit(map[string]any{"symbol": symbol, "callers": entries, "total": total})
}

type calleeEntry struct {
	To   string `json:"to"`
	File string `json:"file"`
	Line int    `json:"line"`
}

func runFindCallees(args []string) {
	fs := flag.NewFlagSet("find-callees", flag.ExitOnError)
	root, out := commonFlags(fs)
	limit := fs.Int("limit", 25, "max results (0 = no cap)")
	offset := fs.Int("offset", 0, "pagination offset")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph find-callees <qualified-symbol> [flags]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	symbol := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	refs, total := store.Callees(symbol, *limit, *offset)
	entries := make([]calleeEntry, 0, len(refs))
	for _, r := range refs {
		entries = append(entries, calleeEntry{To: r.From, File: r.File, Line: r.Line})
	}
	emit(map[string]any{"symbol": symbol, "callees": entries, "total": total})
}

func runListPackage(args []string) {
	fs := flag.NewFlagSet("list-package", flag.ExitOnError)
	root, out := commonFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph list-package <import-path>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	importPath := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	pkg, syms := store.PackageSymbols(importPath)
	if pkg == nil {
		fmt.Fprintf(os.Stderr, "package not found: %s\n", importPath)
		os.Exit(1)
	}
	emit(map[string]any{"package": pkg, "symbols": syms})
}

func runFindTemplate(args []string) {
	fs := flag.NewFlagSet("find-template", flag.ExitOnError)
	root, out := commonFlags(fs)
	define := fs.String("define", "", "filter by define name (case-insensitive substring)")
	glob := fs.String("glob", "", "filter by filename glob (e.g. nginx-plus*.tmpl)")
	_ = fs.Parse(args)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	tmpls := store.Templates(*define, *glob)
	emit(map[string]any{"templates": tmpls, "total": len(tmpls)})
}

func runFindHelmValue(args []string) {
	fs := flag.NewFlagSet("find-helm-value", flag.ExitOnError)
	root, out := commonFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph find-helm-value <dotted.key>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	key := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	emit(store.HelmValue(key))
}

func runCRDRelations(args []string) {
	fs := flag.NewFlagSet("crd-relations", flag.ExitOnError)
	root, out := commonFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph crd-relations <CRDName>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	name := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	entry := store.CRDRelations(name)
	if entry == nil {
		fmt.Fprintf(os.Stderr, "CRD not found: %s\n", name)
		os.Exit(1)
	}
	emit(entry)
}

func runFindPythonTest(args []string) {
	fs := flag.NewFlagSet("find-python-test", flag.ExitOnError)
	root, out := commonFlags(fs)
	marker := fs.String("marker", "", "filter by exact pytest marker name")
	limit := fs.Int("limit", 25, "max results (0 = no cap)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph find-python-test <query> [flags]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	query := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	hits := store.PythonTests(query, *marker, *limit)
	emit(map[string]any{"tests": hits, "total": len(hits)})
}

func runFindExample(args []string) {
	fs := flag.NewFlagSet("find-example", flag.ExitOnError)
	root, out := commonFlags(fs)
	name := fs.String("name", "", "filter by name (case-insensitive substring)")
	group := fs.String("group", "", "filter by top-level group (subdir under examples/)")
	limit := fs.Int("limit", 25, "max results (0 = no cap)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nic-graph find-example <Kind> [flags]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	kind := fs.Arg(0)
	cfg := resolveConfig(*root, *out, false)
	store := openStore(cfg, true)
	hits := store.Examples(kind, *name, *group, *limit)
	emit(map[string]any{"examples": hits, "total": len(hits)})
}

// ---- usage ----

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: nic-graph <command> [args] [flags]

Index management:
  build                              Generate .nic-graph/
  check                              Verify .nic-graph/ is up to date (CI/pre-commit)
  stats                              Print artifact counts as JSON
  doctor                             Check runtime deps (go, python3, jq); -install adds missing

Lookups (auto-build .nic-graph/ on first use; output is JSON on stdout):
  find-symbol <name>                 Locate Go symbols by name (--kind, --limit)
  find-callers <qualified-symbol>    List callers (--limit, --offset)
  find-callees <qualified-symbol>    List outgoing call sites
  list-package <import-path>         Files + symbols in a Go package
  find-template                      NGINX .tmpl defines (--define, --glob)
  find-helm-value <dotted.key>       Helm value: schema + template usage
  crd-relations <CRDName>            CRD -> validators, configs, templates, tests
  find-python-test <query>           Pytest functions (--marker, --limit)
  find-example <Kind>                Examples manifests (--name, --group, --limit)

Common flags (any subcommand):
  -root <dir>   Repo root (default: auto-detect)
  -out  <dir>   Output directory relative to root (default: .nic-graph)

Examples:
  nic-graph build
  nic-graph find-symbol LoadBalancerController -kind=struct
  nic-graph find-callers github.com/nginx/kubernetes-ingress/internal/k8s.LoadBalancerController.sync
  nic-graph find-helm-value controller.replicaCount
  nic-graph crd-relations VirtualServer
  nic-graph find-python-test rate_limit -marker=vs

See hack/nic-graph/README.md for the full reference.`)
}
