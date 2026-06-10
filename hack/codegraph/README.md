# codegraph

Generates a static, always-available code index under `.codegraph/` at the repo
root. Used by AI agents (see `.agents/skills/nic-codegraph/SKILL.md`) and humans
to answer "where does X live?" without re-grepping the whole tree.

## Usage

```bash
make codegraph        # regenerate .codegraph/
make codegraph-check  # exit non-zero if .codegraph/ is stale
```

Or directly:

```bash
go run ./hack/codegraph build   # write .codegraph/
go run ./hack/codegraph check   # drift check (no writes)
```

## What it produces

| File | Purpose |
| --- | --- |
| `INDEX.md` | Always-loaded directory + query cookbook (≤120 lines) |
| `packages.json` | Go package meta + imports |
| `symbols.jsonl` | One symbol per line (kind, name, pkg, file, line, sig) |
| `refs.jsonl` | Caller→callee edges, intra-repo, capped per callee |
| `imports.json` | Go package import graph |
| `files.md` | Per-file 1-line summary, grouped by package |
| `domain-map.md` + `.json` | CRD → validator → config struct → template → tests |
| `templates.json` | NGINX `.tmpl` defines/includes (OSS+Plus paired) |
| `helm.json` | Helm values keys ↔ template usage |
| `python-tests.json` | pytest files: classes, tests, markers, fixtures |
| `examples.json` | `examples/**` K8s manifests |

## Scope & exclusions

Indexed: `internal/**`, `pkg/apis/**`, `internal/configs/version{1,2}/*.tmpl`,
`charts/nginx-ingress/{values.schema.json,templates/**}`, `tests/suite/**.py`,
`examples/**`.

Excluded: `pkg/client/**` (generated), `**/zz_generated*.go`, `**/fake/**`,
`**/__snapshots__/**`, `_vendor/**`, vendored or auto-formatted assets.

## Overrides

`hack/codegraph/overrides.yaml` lets you patch the domain map when heuristics
miss (e.g. validator name doesn't textually mention a CRD field).
