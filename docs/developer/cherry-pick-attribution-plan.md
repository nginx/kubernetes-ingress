# Plan: Preserve Contributor & Cherry-Pick Credits (#9516)

## Status: Implemented

## Summary

**Issue:** [#9516](https://github.com/nginx/kubernetes-ingress/issues/9516)

**Goal:** Release notes credit the people who did the work, not the bot that opened the PR. In particular:

1. The **original PR author** of a cherry-picked change.
2. Everyone who **committed to** a PR, e.g. two maintainers on one PR, a maintainer fixing up a community or Renovate PR, or a community member co-authoring a maintainer's PR.
3. The **actor who triggered** `/cherry-pick` or the version-bump workflow.

The rules are role-agnostic: maintainers and community contributors (including PRs from forks) are credited the same way. "Maintainer" in the examples below is only the common case.

This applies across three stages:

1. **Cherry-pick and version-bump PRs:** `.github/workflows/cherry-pick.yml`, `.github/workflows/version-bump.yml`
2. **GitHub release draft:** `.github/workflows/image-promotion.yml`, `.github/workflows/update-release-draft.yml`
3. **Docs release notes:** `.github/scripts/pull-release-notes.py`, which `release-pr.yml` calls via `release-docs.sh`

> **Out of scope:**
> - `release-publish.yml` and `release-publish-lts.yml`, which do not modify release notes text.
> - `update-docker-sha.yml`. It is rarely used, since dependency updates are almost all Renovate, and its PRs fall back to `nginx-bot` credit.
> - Commit trailers. Squash merges on `main` already add `Co-authored-by:`, `git cherry-pick -x` preserves author and message, and the cherry-pick actor is recorded as the git committer.

---

## Current Behaviour & Root Causes

| Stage | File(s) | Current Behaviour / Root Cause |
|---|---|---|
| **1. Bot-opened PRs** | `cherry-pick.yml`, `version-bump.yml` | PRs are opened with the `nic-create-pr[bot]` GitHub App token. GitHub records `nic-create-pr[bot]` as the PR author. The human who triggered the workflow is not recorded anywhere on the PR, and neither is the original author of a cherry-pick. |
| **2. GitHub release draft** | `image-promotion.yml`, `update-release-draft.yml` | `lucacome/draft-release@v2.2.2` calls GitHub's `repos.generateReleaseNotes`. GitHub credits only the PR opener (`* <title> by @nic-create-pr[bot] in <url>`), ignores other committers, and lists `@nic-create-pr[bot]` under `## New Contributors`. |
| **3. Docs release notes** | `pull-release-notes.py` | `change_regex = r"^(.*) by @.* in (.*)$"` (line 61) discards the `by @...` credit entirely, so the docs show no credit. The greedy `(.*)` also mis-parses a line containing a second ` by @` (e.g. `(cherry-picked by @x)`). The `[cherry-pick to release-X.Y]` prefix leaks into docs titles. |

---

## Credit Rules

Apply these to each changelog line:

1. **Never credit** `nic-create-pr[bot]`. It only opens PRs on someone else's behalf. Also never credit `web-flow` or `github-actions[bot]`.
2. **Authors:** credit the PR opener plus every commit author and `Co-authored-by:` name on the PR, deduplicated with the opener first. This includes bots that genuinely authored work, such as `renovate[bot]`.
   - Ignore merge commits (more than one parent). The "Update branch" button would otherwise credit whoever clicked it.
   - **Commit authors with no linked GitHub login** (`author: null`, common for community commits made with an unlinked email): credit them by their plain git name, unlinked and without `@`, e.g. `by @AlexFenlon & Dana Smith`.
     - Skip the plain name if its git email or name matches someone already credited by login.
     - Deduplicate plain names by email.
     - Plain names are never placed first. The PR opener always has a login, so every credit starts with `@`. This keeps the Phase 3 regex unambiguous.
     - Strip markdown-significant characters (`` [ ] ( ) * _ < > ` ``) and `&` / `,` from plain names before rendering.
   - Reviewing or merging alone earns no credit.
3. **Cherry-pick PRs:** take the authors from the **original** PR using rule 2, then append `(cherry-picked by @actor)`. If the actor is the only original author, omit the suffix.
4. **`nginx-bot`** is credited only when it is the sole remaining author. It is dropped when any human is credited.
5. **Fallback** when no author remains after rules 1–4:
   1. Use the `actor` from the PR-body metadata, e.g. version-bump PRs → `by @actor`.
   2. Otherwise use `nginx-bot`, if it authored the commits.
   3. Otherwise remove the `by @...` segment.

   A line never keeps `@nic-create-pr[bot]`.
6. **Joining:** `@a` / `@a & @b` / `@a, @b & @c`.
7. **New Contributors:**
   - Remove `@nic-create-pr[bot]` and `@nginx-bot` entries. Remove the heading if it is left empty.
   - Add first-time contributors whose PRs were cherry-picked. GitHub does not list them on release-branch drafts because the bot opened the release-branch PR. Add `* @<login> made their first contribution in <original PR url>` when all of these hold:
     - the original PR's opener is not a bot;
     - they are not already listed;
     - the original PR is their earliest merged PR in the repo.

     Create the heading if it doesn't exist. Only PR openers with a login are added, never commit-only or plain-name authors, matching GitHub's own behaviour.

| Case | Draft credit |
|---|---|
| Direct PR, opened by Alex, Paul also committed | `by @AlexFenlon & @pdabelf5` |
| Cherry-pick of Alex's PR, triggered by Paul | `by @AlexFenlon (cherry-picked by @pdabelf5)` |
| Cherry-pick where the author picked their own PR | `by @AlexFenlon` |
| Community PR (fork), only Dana committed | `by @dana` (unchanged) |
| Community PR, maintainer pushed a fix | `by @dana & @AlexFenlon` |
| Maintainer PR, community member co-authored | `by @AlexFenlon & @dana` |
| Two community contributors on one PR | `by @dana & @erin` |
| Community co-author with an unlinked email | `by @AlexFenlon & Dana Smith` |
| Cherry-pick of Dana's community PR | `by @dana (cherry-picked by @AlexFenlon)`, and Dana is added to New Contributors if this is her first PR |
| Renovate only | `by @renovate[bot]` (unchanged) |
| Renovate, Paul pushed a fix | `by @renovate[bot] & @pdabelf5` |
| Cherry-pick of a Renovate PR | `by @renovate[bot] (cherry-picked by @AlexFenlon)` |
| Version bump, triggered by Venktesh | `by @vepatel` |
| Docker image update, `nginx-bot` commits only | `by @nginx-bot` |

---

## Implementation Steps

### Phase 1 — Record attribution on bot-opened PRs

Keep changes to existing workflows to the minimum.

#### `.github/workflows/cherry-pick.yml`

Change only the existing `core.setOutput('body', ...)` line, so the cherry-pick PR body gets a footer and a metadata comment:

```markdown
---
Cherry-picked from #<source_pr> by @<actor>
<!-- nic-attribution: {"source_pr":<num>,"actor":"<actor>"} -->
```

- `actor` is `context.actor`.
- The original authors are not stored here. The draft rewriter looks them up from `source_pr`.
- No changes to the `git cherry-pick` logic, and no commit trailers.
- The existing `listCommits` `per_page: 250` (capped at 100 by the API) is a separate bug, left for its own PR.

#### `.github/workflows/version-bump.yml`

Append the metadata comment to the `Create Pull Request` body:

```markdown
<!-- nic-attribution: {"actor":"${{ github.actor }}"} -->
```

---

### Phase 2 — Rewrite credits in the GitHub release draft

#### New: `.github/scripts/release-notes-attribution.py`

- **Dependencies:** standard library only (`urllib`), so the workflow step needs no `pip install` or `setup-python`.
- **Flow:** `main()` reads `GITHUB_TOKEN`, `GITHUB_REPOSITORY` and `RELEASE_ID`. It fetches the draft, calls `rewrite()`, and PATCHes the body only if it changed. It does nothing if `RELEASE_ID` is empty or the release is not a draft.
- **Line matching:**
  - Only `* <title>[ by <credit>] in <pr url>[, <pr url>...]` lines that point at this repository are rewritten.
  - Everything else passes through unchanged: headers, `<details>` blocks, header/footer, `**Full Changelog**`, and the New Contributors entries.
- **Grouped Renovate lines** (multiple URLs, from `draft-release` grouping) stay grouped. Credits from all the grouped PRs are merged, e.g. `by @renovate[bot] & @pdabelf5 in url1, url2`.
- **Cherry-pick detection:** the PR is opened by `nic-create-pr[bot]` and its head ref contains `cherry-pick-`.
  - The original PR comes from the metadata `source_pr`. For older cherry-picks it comes from the `(cherry picked from commit <sha>)` line, via the commit's associated merged PR.
  - The actor comes from the metadata, otherwise from the committer of the cherry-picked commit.
  - The original PR is credited recursively, so a cherry-pick of a version bump credits the bump's actor.
  - If the original can't be resolved, the cherry-pick's own commits are credited and a `::warning::` is logged.
  - When a PR body contains more than one metadata block (the original PR body is copied into the cherry-pick body), the last one wins.
- **Data fetching:** a batched GraphQL query (25 PRs per request) returns, for each PR, the author, head ref, body and the first 100 commits.
- **New Contributors:** for each cherry-picked original PR whose opener is human and not yet listed, a search query (`repo:<owner>/<repo> is:pr is:merged author:<login>`, oldest first) checks whether it is their first merged PR.
- **Idempotent:** `draft-release` regenerates the draft on every run, and rewriting an already-rewritten body gives the same body.
- Add the script to `.github/scripts/exclude_ci_files.txt` so `variables.sh stable_tag` (`get_actions_md5`) is unchanged.

#### `.github/workflows/update-release-draft.yml` and `.github/workflows/image-promotion.yml`

Add a step after `Create/Update Draft`:

```yaml
- name: Fix release note attribution
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    RELEASE_ID: ${{ steps.release-notes.outputs.release-id }}
  run: python3 .github/scripts/release-notes-attribution.py
  if: <same condition as Create/Update Draft>  # image-promotion.yml only: push to release-*
```

- The action output is `release-id`, not `id`.
- Add `pull-requests: read` to both jobs' `permissions`.

---

### Phase 3 — Docs release notes

#### `.github/scripts/pull-release-notes.py`

Minimal in-place change (about 6 lines), with no restructuring:

1. **Regex (line 61):** `change_regex = r"^(.*?)(?: by (@.+?))? in (https://\S+.*)$"`. Groups are title, optional credit, and PR link(s).
2. **Title:** strip a leading `[cherry-pick to <branch>] ` prefix before `.capitalize()`.
3. **Credit:** link each `@login` (`[@x](https://github.com/x)`) and append ` by <credit>` to `pr["title"]`.
   - The existing `parsed_changes.append(...)` lines are untouched.
   - Plain names stay unlinked.
   - Grouped `Bump Go/Docker dependencies` lines use their own fixed titles, so they carry no credit.
4. `get_github_release()` is unchanged. Drafts created by `draft-release` already have `tag_name == v<version>`.

`release-pr.yml`, `release-docs.sh` and `release-notes.j2` need no changes. The `&amp;` → `&` sed in `release-docs.sh:115` already handles autoescaped `&`. Any future workflow that calls `release-docs.sh` or `pull-release-notes.py`, such as an LTS docs flow, picks this up automatically.

No unit tests are added, consistent with the other scripts in `.github/scripts/`.

---

## Files Changing

**New**
- `.github/scripts/release-notes-attribution.py`

**Modified (small diffs)**
- `.github/workflows/cherry-pick.yml` (1 line)
- `.github/workflows/version-bump.yml` (+2)
- `.github/workflows/update-release-draft.yml` (+7)
- `.github/workflows/image-promotion.yml` (+8)
- `.github/scripts/pull-release-notes.py` (~6 lines)
- `.github/scripts/exclude_ci_files.txt` (+1)

**Unchanged**
- `release-pr.yml`
- `release-docs.sh`
- `release-notes.j2`
- `lint-format.yml`

---

## Rollout

1. Merge to `main`.
2. Cherry-pick to every active release branch, including `release-*-lts`. `update-release-draft.yml` checks out the release branch, and `image-promotion.yml` and `release-pr.yml` run the scripts from the release branch, so the scripts must exist there.

---

## Expected Output

### GitHub release draft

```markdown
## What's Changed
### 🚀 Features
* Add OIDC PKCE support by @AlexFenlon & @pdabelf5 in https://github.com/nginx/kubernetes-ingress/pull/11300
* [cherry-pick to release-5.8] Add JWT claim validation by @AlexFenlon (cherry-picked by @pdabelf5) in https://github.com/nginx/kubernetes-ingress/pull/11310
### 🐛 Bug Fixes
* Fix route matching for regex paths by @dana & @AlexFenlon in https://github.com/nginx/kubernetes-ingress/pull/11290
* [cherry-pick to release-5.8] Fix upstream reload race by @sbreen, @pdabelf5 & @AlexFenlon (cherry-picked by @vepatel) in https://github.com/nginx/kubernetes-ingress/pull/11315
* [cherry-pick to release-5.8] Fix TLS passthrough port by @erin (cherry-picked by @AlexFenlon) in https://github.com/nginx/kubernetes-ingress/pull/11318
* Fix ingress class defaulting by @AlexFenlon & Dana Smith in https://github.com/nginx/kubernetes-ingress/pull/11295
### ⬆️ Dependencies
* Update AWS SDK v2 by @renovate[bot] & @pdabelf5 in https://github.com/nginx/kubernetes-ingress/pull/11257, https://github.com/nginx/kubernetes-ingress/pull/11266
* Update module github.com/gkampitakis/go-snaps to v0.5.25 by @renovate[bot] in https://github.com/nginx/kubernetes-ingress/pull/11267
* [cherry-pick to release-5.8] Update cert-manager to v1.21.3 by @renovate[bot] (cherry-picked by @AlexFenlon) in https://github.com/nginx/kubernetes-ingress/pull/11325
* Docker image update 1a2b3c4d by @nginx-bot in https://github.com/nginx/kubernetes-ingress/pull/11320
### 🔨 Maintenance
* Version Bump for 5.8.1 by @vepatel in https://github.com/nginx/kubernetes-ingress/pull/11330

## New Contributors
* @dana made their first contribution in https://github.com/nginx/kubernetes-ingress/pull/11290
* @erin made their first contribution in https://github.com/nginx/kubernetes-ingress/pull/11240
```

- **11318:** first-time community contributor Erin's PR #11240, cherry-picked. Erin is credited on the line and added to New Contributors, linked to her original PR.
- **11295:** a community co-author whose commit email isn't linked to a GitHub account, so she is credited by plain name.

### Docs release notes

```markdown
### {{% icon rocket %}} Features

- [11300](https://github.com/nginx/kubernetes-ingress/pull/11300) Add oidc pkce support by [@AlexFenlon](https://github.com/AlexFenlon) & [@pdabelf5](https://github.com/pdabelf5)
- [11310](https://github.com/nginx/kubernetes-ingress/pull/11310) Add jwt claim validation by [@AlexFenlon](https://github.com/AlexFenlon) (cherry-picked by [@pdabelf5](https://github.com/pdabelf5))

### {{% icon bug %}} Fixes

- [11290](https://github.com/nginx/kubernetes-ingress/pull/11290) Fix route matching for regex paths by [@dana](https://github.com/dana) & [@AlexFenlon](https://github.com/AlexFenlon)
- [11315](https://github.com/nginx/kubernetes-ingress/pull/11315) Fix upstream reload race by [@sbreen](https://github.com/sbreen), [@pdabelf5](https://github.com/pdabelf5) & [@AlexFenlon](https://github.com/AlexFenlon) (cherry-picked by [@vepatel](https://github.com/vepatel))
- [11318](https://github.com/nginx/kubernetes-ingress/pull/11318) Fix tls passthrough port by [@erin](https://github.com/erin) (cherry-picked by [@AlexFenlon](https://github.com/AlexFenlon))
- [11295](https://github.com/nginx/kubernetes-ingress/pull/11295) Fix ingress class defaulting by [@AlexFenlon](https://github.com/AlexFenlon) & Dana Smith

### {{% icon arrow-up %}} Dependencies

- [11257](https://github.com/nginx/kubernetes-ingress/pull/11257), [11266](https://github.com/nginx/kubernetes-ingress/pull/11266), [11267](https://github.com/nginx/kubernetes-ingress/pull/11267) & [11325](https://github.com/nginx/kubernetes-ingress/pull/11325) Bump Go dependencies
- [11320](https://github.com/nginx/kubernetes-ingress/pull/11320) Bump Docker dependencies
```

Maintenance and New Contributors are not rendered in the docs, as today. Logins above are illustrative.

---

## Verification Checklist

1. `actionlint` is clean, and `.github/scripts/validate-workflow-gating.sh` and `.github/scripts/validate-workflow-gating_test.sh` pass.
2. `.github/scripts/variables.sh stable_tag` is unchanged before and after the change.
3. On a test release branch, run `update-release-draft.yml` twice and check that the draft matches the expected output and does not change on the second run.
4. Run `release-pr.yml` with `dry_run: true` and check the generated docs release notes.
