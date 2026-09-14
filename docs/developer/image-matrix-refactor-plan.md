# Image Matrix Refactor Plan

Plan for reworking `.github/data/matrix-images-*.json` to add `build_os` and
remove redundant image rows, and the corresponding GitHub Actions workflow
changes required to consume the new schema.

## Background

The matrix files (`matrix-images-oss.json`, `matrix-images-plus.json`,
`matrix-images-plus-lts.json`, `matrix-images-nap.json`) are loaded by
`ci.yml`, `image-promotion.yml`, `release-prep.yml`, `release-prep-lts.yml`,
`build-base-images.yml` and `cache-update.yml`, and consumed via
`strategy.matrix` by `build-artifacts.yml` -> `build-oss.yml` / `build-plus.yml`.

Today `matrix.image` is overloaded seven ways: `BUILD_OS` build arg,
published registry path (derived via `contains(inputs.image, ...)`),
published tag suffix (same `contains()` pattern, copied across five files),
prebuilt base-image cache tag, GHA cache scope, concurrency group key, and
job name / Scout results directory. The `contains()` suffix derivation is
duplicated in `build-oss.yml`, `build-plus.yml`, `image-promotion.yml`,
`setup-smoke.yml` and `regression.yml`, and has already drifted:
`regression.yml:292` is missing the `-agent` component that
`setup-smoke.yml:66` has, so a regression run against `debian-plus-nap-agent`
pulls the wrong tag.

## Schema

```jsonc
{
  "build_os":   "ubi-10-plus-nap-agent",           // Dockerfile stage -> BUILD_OS build arg
  "image":      "nginx-ic-nap/nginx-plus-ingress", // repo path under the registry prefix
  "tag_suffix": "-ubi-agent",                      // literal tag postfix, "" for the base variant
  "platforms":  "linux/amd64",
  "target":     "goreleaser",                      // plus/nap only
  "nap_modules":"waf"                              // nap only
}
```

Invariants, enforced in CI:

- `(build_os, nap_modules)` is unique per file — the **build** key.
- `(image, tag_suffix)` is unique per file — the **identity** key.
- Every `build_os` matches a `FROM ... AS <stage>` in `build/Dockerfile`.

`image` is not unique per row (e.g. all four `matrix-images-plus.json` rows
share `nginx-ic/nginx-plus-ingress`). Anything that needs a unique per-job
key — concurrency group, GHA cache scope, prebuilt base-image tag, job name,
Scout results directory — must use `build_os` (+ `nap_modules` for NAP), never
`image`. Keying on `image` would serialise the four Plus jobs into one
concurrency group and collide their caches.

### JSON changes already made

- All four matrix files migrated to the `build_os` / `image` / `tag_suffix`
  schema.
- `matrix-images-nap.json`: dropped the agent-v2 DoS-only rows
  (`debian-plus-nap|dos`, `ubi-10-plus-nap|dos`). DoS-only is now built from
  the `-agent` (v3) stage only, matching `Makefile` targets
  `debian-image-dos-plus` / `ubi-image-dos-plus`.
- Naming standardised on the values actually documented/published live:
  `nginx-plus-ingress` (not `nginx-ingress-plus`) and `nginx-ic-nap-dos` (not
  the internal `nginx-ic-dos-nap`) — see [Naming rename](#naming-rename-nginx-ic-dos-nap---nginx-ic-nap-dos)
  below.

Validated: `(build_os, nap_modules)` unique, `(image, tag_suffix)` unique,
all 19 `build_os` values match a Dockerfile stage.

## Naming rename: `nginx-ic-dos-nap` -> `nginx-ic-nap-dos`

The WAF+DoS image path is inconsistent today:

| Location | Current WAF+DoS path |
| --- | --- |
| NGINX public registry (customer-facing) | `nginx-ic-nap-dos` (`config-plus-nginx:2`) |
| `plus-release.yml:147,241` reading staging | `nginx-ic-nap-dos` |
| dev + release GCR, staging writes | `nginx-ic-dos-nap` (`copy-images.sh:48,54`) |

`config-prep-nginx-test` deliberately leaves prefixes at their defaults so
prep writes staging as `nginx-ic-dos-nap`, while `plus-release.yml:147`
reads staging back as `nginx-ic-nap-dos` — the WAF+DoS copy from staging to
the public NGINX registry cannot be resolving correctly today. Standardising
on `nginx-ic-nap-dos` (the documented, customer-facing name) fixes this.

### Branch scoping

`update-docker-images.yml`'s `variables` job checkout has no `ref`, so
`patch-images.json` is read from `github.ref`. Local reusable workflows
(`uses: ./.github/workflows/...`) resolve against the caller's ref too, and
downstream `plus-release.yml` calls pass `branch: release-X.Y` explicitly, so
`copy-images.sh` and `config-*` there also come from the release branch.
`create-release-branch.yml` / `release-version-update.sh` do not template
`patch-images.json`, so a release branch simply carries whatever `main` had
at cut time.

Consequence: renaming in `main` cannot break an existing release branch's
patch run — the two GCR paths (`main`'s new name, the release branch's old
name) coexist as distinct repository paths.

The one residual risk is the weekly cron in `update-docker-images.yml`
(`0 1 * * 0`), which GitHub restricts to the default branch. It reads
`main`'s `patch-images.json` and resolves the tag to patch via
`git tag --sort=-version:refname | head -n1` — the globally newest tag. Between
the rename landing in `main` and the first release cut under the new name,
this cron would look for `release/nginx-ic-nap-dos/...:<latest-tag>`, which
would not exist yet unless backfilled (see Step 0).

## Execution order

### Step 0 — Backfill (operational, before the PR merges)

One-off manifest-level copy, no rebuild, run by someone with GCR write
credentials — outside the PR.

For each tag that must remain patchable (latest release `X.Y.Z`, short
`X.Y`, `latest`, any `X.Y.Z-<date>` patch tags still in use) and each postfix
in `NAP_WAF_DOS_TAG_POSTFIX_LIST = ("" "-ubi" "-agent" "-ubi-agent")`
(`config-plus-gcr-release:11`):

```sh
skopeo copy -a \
  docker://gcr.io/f5-gcs-7899-ptg-ingrss-ctlr/release/nginx-ic-dos-nap/nginx-plus-ingress:<tag><postfix> \
  docker://gcr.io/f5-gcs-7899-ptg-ingrss-ctlr/release/nginx-ic-nap-dos/nginx-plus-ingress:<tag><postfix>
```

Verify with `skopeo inspect` on the new path before merging. Once green,
`patch-images.json`'s `source_image` can flip in the same PR as everything
else, with no window where the weekly cron fails. Old `release/nginx-ic-dos-nap`
tags stay in place — existing release branches keep using them unchanged.

### Step 1 — PR content

**Phase A — build path**

1. `build-oss.yml` — add `build-os` (required), `image`, `tag-suffix`
   inputs; rewire job name (`:61`), registry path + suffix in `docker meta`
   (`:134,136`), base-image tag (`:152`), cache scopes (`:181,218,219`),
   `BUILD_OS` build arg (`:190,232`), Scout results dir (`:242,252`).
2. `build-plus.yml` — same new inputs; rewire job name (`:77`), registry
   path + suffix (`:154,156` — drop all `contains()` heuristics), base-image
   tag (`:167` — drop the separate `-v5` append, it's already inside
   `build_os`), cache scopes (`:196,236,237`), `BUILD_OS` (`:204,249`), Scout
   dir (`:264,274`). Keep `inputs.target` for `ANNOTATIONS_LEVELS` (`:162`),
   `target:` (`:238`) and `sbom` (`:246`).
3. `build-artifacts.yml` — concurrency groups (`:236,268,301`) -> `matrix.build_os`
   (+ `matrix.nap_modules` for NAP); pass `build-os` / `image` / `tag-suffix`
   at `:243-244,275-277,308-310`. Callers (`ci.yml`, `image-promotion.yml`,
   `release-prep.yml`, `release-prep-lts.yml`) forward whole JSON blobs and
   need no change.
4. `build-base-images.yml` — base-image registry, stays keyed on `build_os`
   throughout: tag suffix (`:101,191,291`), cache scope
   (`:110,111,200,201,300,301`), `BUILD_OS` (`:118,208,308`).
5. `image-promotion.yml` — 3 scan jobs: job names (`:326,426,526`), results
   dirs (`:344,444,551`) -> `build_os` (+ `nap_modules`); `docker meta`
   (`:355-356,455-456,560-563`) -> `matrix.image` + `matrix.tag_suffix`.
   Delete the `nap_modules` step at `:540-546` — it has a live bug
   (`&& modules=… || name=…` leaves `name` empty for `waf,dos`) and is no
   longer needed. This also fixes `:563` silently omitting `-agent`, which
   today causes agent-variant rows to scan the wrong tag.
6. `cache-update.yml` — pass-through of the three new fields at
   `:51-52,77-79,102-107`.

**Phase B — rename fanout**

Phase A makes the dev GCR WAF+DoS path come from `matrix.image`, i.e. it
becomes `nginx-ic-nap-dos` the moment Phase A lands, so the rest of the
fanout must land in the same PR:

7. `setup-smoke.yml:65`, `regression.yml:291` — flip `{-dos}{-nap}` ordering
   to `-nap-dos`. Currently dead code (no matrix has a `waf,dos` row) but
   must be correct before one is added.
8. `copy-images.sh:48` (`SOURCE_NAP_WAF_DOS_IMAGE_PREFIX`) and `:54`
   (`TARGET_NAP_WAF_DOS_IMAGE_PREFIX`) -> `nginx-ic-nap-dos/nginx-plus-ingress`.
   Fixing `:54` also resolves the prep/publish mismatch described above.
9. `plus-release.yml:146-148,240-242` — delete the now-redundant
   `SOURCE_NAP_WAF_DOS_IMAGE_PREFIX` overrides.
10. `tests/data/modules/data.json:192,619,953,1011` — dev GCR path.
11. `patch-images.json:93,95,99,101,141,143,147,149` — both `source_image`
    and `target_image` for the WAF+DoS rows (source only safe after Step 0's
    backfill).

**Required fix**

12. `matrix-smoke-nap.json` — repoint the `debian-plus-nap|dos` and
    `ubi-10-plus-nap|dos` rows to their `-agent` `build_os` equivalents.
    These reference the two rows dropped from `matrix-images-nap.json`;
    without this fix those smoke jobs pull a tag nothing builds.
    (`debian-plus-nap-agent|waf` for `AGENT_V3_NAP` is already correct and
    stays as-is.)

**Guardrail + docs**

13. New `jq` invariant check wired into `lint-format.yml`: `(build_os,
    nap_modules)` unique, `(image, tag_suffix)` unique, every `build_os`
    matches a `FROM ... AS` Dockerfile stage, across all four matrix files.
14. Update `.github/skills/nic-ci-pipelines/SKILL.md:178-184` (matrix file
    descriptions) and `.github/skills/nic-docker-images/SKILL.md:50,171`
    ("every NAP image appears twice" / "add NAP stages in pairs" no longer
    hold for DoS-only). `.agents/skills` and `.claude/skills` are symlinks to
    `.github/skills`, so one edit covers all three.

### Step 2 — Verify

- `actionlint` and `.github/scripts/validate-workflow-gating.sh`.
- Bijection check: every `(image, tag_suffix)` in the matrix files against
  the postfix lists in `copy-images.sh:57-62`, `config-prep-nginx-test` and
  `config-plus-gcr-release`. `NAP_DOS_TAG_POSTFIX_LIST=("" "-ubi")` should now
  be satisfied entirely by the agent-v3 rows.
- Dry-run `release-prep.yml` with `dry_run: true` to confirm the staging
  prefix set.
- Expect one full CI rebuild: the matrix JSONs and
  `build-{oss,plus,artifacts}.yml` are not in
  `.github/scripts/exclude_ci_files.txt`, so `get_actions_md5()` ->
  `stable_tag` changes; the base-image tag format change also invalidates
  cached `nginx-ic-base/*` layers.

## Deferred follow-ups (out of scope for this PR)

- Migrate `matrix-smoke-*.json` / `matrix-regression.json` to the same
  schema. This removes the last two copies of the `contains()` suffix
  derivation and fixes `regression.yml:292`'s missing `-agent` bug.
- `patch-images.json`'s `source_os` field is a misnomer — `patch-image.yml`
  actually uses it as a tag suffix, with `debian` as the sentinel for "no
  suffix". Natural candidate to rename to `tag_suffix` once the smoke/
  regression matrices are migrated.
- `build/Dockerfile:786` defines an orphan `ubi-10-plus-agent` stage with no
  matrix row and no Makefile target referencing it.
