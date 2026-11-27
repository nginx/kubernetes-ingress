# CI Branch Unification Plan

Goal: `.github/workflows`, `.github/actions`, `.github/scripts` and `.github/config` are byte-identical on `main` and every
supported release branch (today `release-5.8` and `release-2026-lts`). What runs on a branch is decided by
branch-local data in `.github/data/` and by what the branch's code supports, not by per-branch workflow edits.

Related: nginx/nic-private#192 (CI centralisation), #193 (unification plan), #234 (`registries.json`).

Audit date: 26 Nov 2026. Branch heads: `main` 41016e773, `release-5.8` 7c820dd78, `release-2026-lts` 019bd247a.
Run history covers 26 Sep - 26 Nov 2026 on `nginx/kubernetes-ingress` (public) and
`nginx/kubernetes-ingress-internal` (internal).

## 1. Unused workflows

| What | Where | Evidence | Action |
| --- | --- | --- | --- |
| `notifications.yml` | LTS only | `workflow_run` only fires from the default branch, and `main` removed it in #9550, so it can never trigger | Delete |
| `updates-notification.yml` | LTS only | `workflow_call` with no caller on LTS | Delete |
| `cache-update.yml` | all 3 | 0 runs ever on both repos | Delete |
| `mend.yml` | no current branch | Still registered on both repos, last run 12 Aug | `gh workflow disable` |
| `release.yml` | `release-5.5` only | Last real run 16 Jul | `gh workflow disable` |
| `mirror-test-artifactory-oidc.yml`, `plus-release-lts-test.yml` | internal test branches | Leftovers on `chore/runner-test` etc. | Delete the branches |
| `config-plus-azure`, `config-plus-gcr-public` | 5.8 only | Only referenced by the old `plus-release.yml` | Removed by the #11542 cherry-pick |
| `exclude_ci_files.txt` entries | all | `build-ot-dependency.yml` and `docs-build-push.yml` exist nowhere. `notifications.yml` and `updates-notification.yml` are deleted above | Remove the entries |
| `codeql-analysis.yml`, `image-promotion.yml` on internal | internal | About 200 runs each, all skipped by the public-repo gate | Noise only. Optional: gate at trigger level |

Bug found during the audit: `release-2026-lts` `build-plus.yml` (NAP modules step, around line 145) assigns `modules=` where it
should assign `name=`, so `waf,dos` builds pass an empty `NAP_MODULES`. `main` has the correct line.

## 2. `workflow_dispatch`-only workflows with no runs since 26 Sep

| Workflow | Last run (public / internal) | Proposal |
| --- | --- | --- |
| `cache-update.yml` | never / never | Delete (see section 1) |
| `certify-ubi-image.yml` | never / never | Keep only as a break-glass tool. The `certify-openshift-image` action is already used inside the release workflows |
| `pull-nap-images.yml` | 13 Jul, failed (last 3 sampled runs all failed) / never | Broken. Fix or delete |
| `build-single-image.yml` | 12 Aug, failed / never | Fix or delete |
| `update-docker-sha.yml` | 16 Jul / never | Superseded by Renovate's `container digests` group. Delete |
| `release-pr.yml` | 4 Sep, cancelled / never | 5.8.0, 5.8.1 and LTS r11/r12 shipped without it. Confirm with the release owner whether it's replaced |

Used recently, keep: `create-release-branch`, `nkp-catalog-pr`, `release-prep(-lts)` (internal), `release-publish(-lts)`,
`update-release-draft`, `version-bump`.

`oss-release`, `plus-release-lts` and `retag-images` have never been dispatched manually, but other workflows call them,
so they are in use. Their `workflow_dispatch` triggers are optional. Workflows that are only called by other workflows
don't appear in the runs API; each was checked for a live caller instead.

## 3. Branch drift

Of the 125 files under `.github/`, 47 are identical on all three branches.

### `release-5.8` (about 25 files)

All of it is 5.8 lagging behind `main`: the Artifactory/proxy build arguments in `build-oss.yml`, `build-plus.yml` and
`build-base-images.yml`, the `registries.json` release refactor (`chore/ci-7.2-release-5.8`), `nkp-catalog`, and
small fixes. 5.8's code is nearly the same as `main`'s, so these cherry-pick cleanly.

### `release-2026-lts` (54 files)

Some of it is lag. The rest exists because LTS's code is different, so `main`'s workflows need to cope with it:

| What `main`'s workflows assume | What LTS has | Shim in `main`'s files |
| --- | --- | --- |
| Dockerfile args `PLUS_PACKAGE_REPO`, `WAF_PACKAGE_REPO`, `DOS_PACKAGE_REPO` | single `PACKAGE_REPO` | Pass both forms. Docker ignores build args the Dockerfile doesn't declare (at worst a warning) |
| pytest `--plm-helm-repo`, `--junitxml`, `-rfE` | no `--plm-helm-repo` option (pytest errors) | Pass it only when `grep -q plm-helm-repo tests/conftest.py` succeeds |
| `make update-helm-schema`, `ubi-image*` targets, `config/crd/upstream` | missing | Check the file or target exists before calling it, e.g. `hashFiles(...)` or `[ -d ... ]` |
| UBI naming from `contains(image,'ubi')` | separate `ubi-9` and `ubi-8` images | Add a `tag_suffix` field to the matrix rows in `.github/data/` |
| waf-compiler `5.16.3` hardcoded in `build-single-image.yml` | `5.13.0` | Move the version to `.github/data/` |
| `tech-specs.json` in `.github/scripts/` | branch-specific content | Move it to `.github/data/` |

### Ownership of paths

| Paths | Ownership |
| --- | --- |
| `.github/{workflows,actions,scripts,config}/**`, `.github/actionlint.yaml`, `.github/labeler.yml`, `.github/skills/nic-ci-pipelines/**` | Synced from `main`, identical everywhere |
| `.github/data/**`, other `.github/skills/**` | Branch-local (they describe the branch's code) |
| Issue and PR templates, `copilot-instructions.md` | Don't matter: GitHub reads them from the default branch only |

### Considered: `branch.json` policy file

#### What it is

A per-branch file, `.github/data/branch.json`, that holds policy flags: differences between branches that are
decisions rather than capabilities. For example:

```json
{
  "line": "lts",
  "publish_nkp_catalog": false,
  "publish_public_registries": true
}
```

A workflow would load it once (for example in the `checks` job, next to the image matrices) and gate jobs with
`if: fromJSON(needs.checks.outputs.branch).publish_nkp_catalog`.

#### What it would bring

- **One place for branch policy.** "What does this branch do differently?" would be answered by one small file instead
  of conditions spread across workflows.
- **Merging the `-lts` workflow pairs.** `release-prep.yml`/`release-prep-lts.yml` (47 changed lines between them) and
  `plus-release.yml`/`plus-release-lts.yml` (8) differ mostly in which registries, image matrix and Helm chart they
  use. A `line` field could select those, and each pair could become one workflow. `release-publish.yml` and
  `release-publish-lts.yml` differ by 206 lines, so that pair would need more work first.
- **No branch names in workflow code.** It would replace checks like `github.ref_name == 'main'` in
  `build-ubi-dependency.yml` and `startsWith(github.ref_name, 'release-')` in `ci.yml`/`image-promotion.yml` with named
  flags, so renaming or adding a branch never touches workflows.
- **Simpler new release branches.** `create-release-branch.yml` could write the new branch's `branch.json` (for example
  set `line`, turn off `main`-only jobs) as part of cutting it.

#### Decision: not now (26 Nov 2026)

- **No current drift needs it.** Every difference found in this audit is either lag (fixed by cherry-picking) or
  something the workflow can detect from the branch's code (section 3). None of them is a policy choice.
- **It would be a second source of truth.** Branch identity already lives in the branch name, `RELEASE_BRANCHES`
  (section 5) and `registries.json`. A fourth place that has to agree with them is more to keep in step.
- **Flags without users go stale.** Flags added before any workflow reads them tend to end up set wrongly or unused.
- **The current mechanisms cover the known cases.** Registry differences belong in `registries.json` (#234), and
  `main`-only jobs can keep checking `github.event.repository.default_branch`, which never names a branch.

#### When to revisit

Add `branch.json` when either of these happens:

- the first real policy difference appears that no existing data file covers, for example "LTS never runs job X";
- someone takes on merging the `-lts` workflow pairs.

Start it with only the fields that change needs.

## 4. Phases

1. **Cleanup** (1 PR to `main`). Make the deletions in sections 1 and 2 and fix `exclude_ci_files.txt`. Fix the LTS
   `build-plus.yml` bug directly on LTS.
2. **Catch up `release-5.8`.** Land `chore/ci-7.2-release-5.8`, then cherry-pick the remaining lagging files. Finished
   when `git diff origin/main origin/release-5.8 -- <synced paths>` is empty.
3. **Make `main`'s workflows work on LTS.** One PR per shim in section 3, each with a full CI run on LTS. Then replace
   LTS's synced paths with `main`'s and delete LTS-only files.
4. **Enforce.** Add the auto cherry-pick (section 5), the nightly sync and drift check (section 6), then the Renovate
   changes (section 7). The Renovate changes depend on the nightly sync existing.

## 5. Auto cherry-pick workflow

The branch list is a repository variable on the public repo:

```text
RELEASE_BRANCHES = {"stable": ["release-5.8"], "lts": ["release-2026-lts"]}
```

- When 5.9 is cut: `stable` becomes `["release-5.9"]`.
- When a new LTS is cut: append it to `lts`, e.g. `["release-2026-lts", "release-2027-lts"]`.
- When an LTS reaches end of life: remove it.

Labels name a role, not a branch, so they never change: `backport/stable`, `backport/lts`, `backport/all`.

Design:

- **Trigger:** `pull_request_target: types: [closed, labeled]` on `main`, running only when the PR is merged. That also
  covers labels added after the merge. The workflow never checks out or runs PR code; it only cherry-picks the merge
  commit. That matters because `pull_request_target` has access to secrets.
- **Steps:**
  1. Work out the target branches from the labels plus `fromJSON(vars.RELEASE_BRANCHES)`.
  2. Cherry-pick in a matrix over those branches, one PR per branch.
  3. On a conflict, open the PR as a draft and comment on the original PR.
- **Reuse:** move the body of `cherry-pick.yml` (merge/squash/rebase detection, push, create PR) into
  `.github/scripts/cherry-pick.sh`. Both the `/cherry-pick to ...` comment command and the new workflow call it.
- **CI changes get labelled automatically:** add a `labeler.yml` rule that applies `backport/all` when
  `.github/{workflows,actions,scripts,config}/**` changes.

## 6. Nightly sync and drift check

A scheduled workflow on `main` that, for each branch in `RELEASE_BRANCHES`:

1. Checks out the release branch.
2. Copies the synced paths from `main` over it, including deleting files that were removed on `main`.
3. Opens or updates a PR on `ci/sync-<branch>` if anything changed.

This catches missed cherry-picks and Renovate's changes to `main`'s workflows.

The same job also fails if Renovate's `baseBranchPatterns` doesn't equal `main` plus `RELEASE_BRANCHES`, or if the
internal repo's `MIRROR_SYNC_BRANCHES` targets don't match. Renovate can't read GitHub variables, so this check keeps the
lists in step.

## 7. Renovate traffic

343 Renovate PRs since 26 Sep: `main` 146, `release-2026-lts` 73, `release-5.7` 61, `release-5.6` 42,
`release-5.8` 21.

1. **Skip `.github/**` on `release-*` branches** once the nightly sync exists. This reverses the current
   `renovate.json` decision, which is now safe because the sync keeps LTS's pins current. It removes 71 of the 197
   release-branch PRs (36%).
2. **One weekly grouped PR per release branch** for everything except security fixes (`matchBaseBranches: ["/^release-/"]`,
   a single `groupName`, `schedule: before 6am on monday`). Keep the UBI chain out of the group, as the current config
   does. LTS goes from about 8 PRs a week to about 1. The cost is that one bad update blocks the whole batch.
3. **Weekly schedule on `main` for the busiest Go groups:** `aws-sdk-v2` (30 PRs), `regexp2` (18), `go-snaps`,
   `golang.org/x`.
4. **Optional, needs a team decision:** on LTS, only patch and security updates for Go modules.

Estimated effect: total volume about halves, and release branches drop by about 80%.

## Risks and open questions

- Phase 3 is the risky phase. Every shim must pass a full CI run against LTS's Dockerfile and Makefile, for the
  remaining life of LTS (until 2029).
- Not checked: whether the internal repo's scheduled workflows (`regression`, `build-test-image`, etc.) do useful work
  or just skip.
- `release-pr.yml`: confirm with the release owner whether it's been replaced.
