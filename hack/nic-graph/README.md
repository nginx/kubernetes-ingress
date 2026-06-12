# nic-graph

`nic-graph` is a single Go binary that builds, checks, and queries the
NGINX Ingress Controller's static code index under `.nic-graph/`.

The index lets AI agents and humans answer "where does X live?" — symbols,
callers, templates, Helm values, CRD wiring, tests, examples — without
re-grepping the whole tree.

```
.
├── hack/nic-graph/             # library (package nicgraph) + CLI
│   ├── *.go                    # builders + Store reader
│   ├── overrides.yaml          # domain-map heuristic patches
│   ├── py_index.py             # pytest discovery helper
│   └── cmd/nic-graph/          # single CLI entry point
└── .nic-graph/                 # generated artifacts (committed)
```

## Build

```bash
make nic-graph-bin                                    # builds bin/nic-graph + runs doctor
# or, equivalently:
go build -o bin/nic-graph ./hack/nic-graph/cmd/nic-graph
```

The binary is pure Go (no CGO), so it cross-compiles cleanly to every
Go-supported target — `GOOS=linux GOARCH=arm64 go build …` etc. `bin/` is
gitignored, so each host rebuilds its own; a Mach-O arm64 binary copied to a
Linux box produces `Exec format error`.

Or run directly via `go run` — no install step needed:

```bash
go run ./hack/nic-graph/cmd/nic-graph <subcommand> [args]
```

## Requirements

| Tool | Required? | Why |
| --- | --- | --- |
| **Go ≥ 1.21** | required | Build/run. The exact patch in `go.mod` is fetched on-demand via `GOTOOLCHAIN=auto` (default since 1.21), so any Go ≥ 1.21 works — no need to match the `go.mod` directive locally. |
| **Python 3** | required for full index | `py_index.py` walks `tests/suite/**.py` for the pytest catalog. If missing, the index is still produced but `python-tests.json` records an `error` instead of the test list. |
| **jq** | optional | Only used in the shell examples below for piping JSON. |

Run `nic-graph doctor` to see what's installed locally, and `nic-graph doctor -install` to install the missing required deps via the detected package manager (apt-get / apk / dnf / brew). Sandbox / Docker containers that ship without Python should run `doctor -install` (or `apt-get install -y python3-minimal`) once before `nic-graph build`.

## Make targets

```bash
make nic-graph                            # regenerate .nic-graph/
make nic-graph-check                      # CI/pre-commit drift check (non-zero if stale)
make nic-graph-bin                        # build bin/nic-graph for the host OS/arch + run doctor
make nic-graph-doctor                     # check runtime deps
make nic-graph-doctor ARGS="-install"     # best-effort install of missing required deps
```

## Subcommands

All subcommands accept `-root <dir>` (auto-detect repo root) and
`-out <dir>` (output dir relative to root, default `.nic-graph`).
Query subcommands auto-build the index on first use (~2 s) if it's missing.

### Index management

| Command | Purpose |
| --- | --- |
| `nic-graph build` | Generate `.nic-graph/` |
| `nic-graph check` | Verify `.nic-graph/` matches what would be generated (drift) |
| `nic-graph stats` | Print artifact counts as JSON |
| `nic-graph doctor [-install] [-json]` | Check that `go` / `python3` / `jq` are present; install missing required ones with `-install` |

### Lookups (output is JSON on stdout)

| Command | Description |
| --- | --- |
| `nic-graph find-symbol <name> [-kind=…] [-limit=N]` | Locate Go symbols. Match order: exact → CI exact → CI prefix → CI substring. |
| `nic-graph find-callers <qualified-symbol> [-limit=N] [-offset=N]` | Callers of a symbol (intra-repo, capped 25 per callee). |
| `nic-graph find-callees <qualified-symbol> [-limit=N] [-offset=N]` | Functions called by a symbol. |
| `nic-graph list-package <import-path>` | Files + symbols in a Go package. |
| `nic-graph find-template [-define=…] [-glob=…]` | NGINX `.tmpl` defines/includes (OSS+Plus paired). |
| `nic-graph find-helm-value <dotted.key>` | Helm value: schema flag + chart template usage. |
| `nic-graph crd-relations <CRDName>` | CRD → validators, configs, templates, tests. Case-insensitive. |
| `nic-graph find-python-test <query> [-marker=…] [-limit=N]` | Pytest functions by name (CI substring) or marker. |
| `nic-graph find-example <Kind> [-name=…] [-group=…] [-limit=N]` | K8s manifests under `examples/`. |

## Examples

> All examples below use `./bin/nic-graph` (output of `make nic-graph-bin`). If you haven't built the binary, substitute `go run ./hack/nic-graph/cmd/nic-graph` everywhere. A bare `nic-graph` only works if you've added `bin/` to `$PATH` or installed the binary somewhere on `$PATH`.

```bash
# Where is the LoadBalancerController struct?
./bin/nic-graph find-symbol LoadBalancerController -kind=struct

# Who calls (*LoadBalancerController).sync ?
./bin/nic-graph find-callers \
  github.com/nginx/kubernetes-ingress/internal/k8s.LoadBalancerController.sync

# Where is .Values.controller.replicaCount used in the chart?
./bin/nic-graph find-helm-value controller.replicaCount

# Full CRD wiring for VirtualServer:
./bin/nic-graph crd-relations VirtualServer | jq .

# Plus-only templates:
./bin/nic-graph find-template -glob='nginx-plus*.tmpl'

# Rate-limit related pytest functions on VirtualServer:
./bin/nic-graph find-python-test rate_limit -marker=vs

# Print a single field with jq:
./bin/nic-graph find-symbol Sync -kind=method -limit=1 | jq -r '.matches[0].file'
```

## What gets generated

Files written under `.nic-graph/`:

| File | Contents |
| --- | --- |
| `INDEX.md` | Human-oriented directory + query cookbook (≤120 lines) |
| `packages.json` | Go package meta + intra-repo imports |
| `symbols.jsonl` | One symbol per line (kind, name, pkg, file, line, signature) |
| `refs.jsonl` | Caller→callee edges, intra-repo, capped 25 per callee |
| `imports.json` | Go package import-graph adjacency |
| `files.md` | Per-file one-line summary, grouped by package |
| `domain-map.md` + `.json` | CRD → validator → config struct → template → tests |
| `templates.json` | NGINX `.tmpl` defines/includes (OSS+Plus paired) |
| `helm.json` | Helm values keys ↔ chart template usage |
| `python-tests.json` | pytest files: classes, tests, markers, fixtures |
| `examples.json` | `examples/**` K8s manifests by kind/name |

## Scope & exclusions

Indexed: `internal/**`, `pkg/apis/**`, `internal/configs/version{1,2}/*.tmpl`,
`charts/nginx-ingress/{values.schema.json,templates/**}`, `tests/suite/**.py`,
`examples/**`.

Excluded: `pkg/client/**` (generated), `**/zz_generated*.go`, `**/fake/**`,
`**/__snapshots__/**`, `_vendor/**`, vendored or auto-formatted assets.

## Overrides

`hack/nic-graph/overrides.yaml` lets you patch the domain map when heuristics
miss (e.g. validator name doesn't textually mention a CRD field). The schema
is reserved; wiring into the generator is pending.

## Refreshing

`make nic-graph` is fast (~2 s on a warm machine). The pre-commit hook
regenerates `.nic-graph/` automatically when Go, template, Helm, example, or
python test sources change, and CI fails on stale indexes via
`make nic-graph-check`. Always commit `.nic-graph/` after changes that affect
it.

## Library use

The same library powers internal tooling — import
`github.com/nginx/kubernetes-ingress/hack/nic-graph` (package `nicgraph`) and
use `nicgraph.RunBuild`, `nicgraph.RunCheck`, or `nicgraph.OpenStore` to query
artifacts programmatically. The `*nicgraph.Store` exposes typed methods
(`FindSymbol`, `Callers`, `HelmValue`, `CRDRelations`, …) — see `store.go` for
the full surface.
