---
name: nic-contribution-review
description: 'Triage gates for the GitHub Copilot Code Review bot on github.com only: provenance (fork or in-repo), intake checks for fork PRs, a one-logical-change scope check with split proposals and issue drafts, and re-review churn detection when fix commits introduce new defects. Use when acting as GitHub Copilot Code Review on a NIC pull request, before nic-code-review. Never load for local reviews (/pr-review prompt, IDE chat, Copilot CLI, Claude Code).'
user-invocable: false
---

# NIC Contribution Review

Triage gates that the GitHub Copilot Code Review bot runs on a NIC pull request before [`nic-code-review`](../nic-code-review/SKILL.md). The gates decide which code gets a line-by-line review; `nic-code-review` still owns how to review it (verification, severities, dimensions).

**Bot only.** If you are running anywhere other than GitHub Copilot Code Review on github.com (`/pr-review`, IDE chat, Copilot CLI, Claude Code or any other local harness), stop: maintainers' local reviews do not use these gates.

Both front matter flags keep local agents from loading this skill; the bot reaches it through `.github/copilot-instructions.md`.

## Principles

- Judge the pull request, not its author. Never speculate about whether AI was used; writing style is not evidence.
- Advise only. Never say a pull request will be closed, labelled or blocked; maintainers decide.
- Match effort to the contribution. When a gate fails, report it and stop: no line-by-line review and no suggested changes for gated or out-of-scope code.
- Point to the rule. Link the matching `CONTRIBUTING.md` section, keep comments short, and say the work is welcome once the gate passes.
- Always report security findings that `nic-code-review` would rate Blocking, even when a gate fails.

## Step 0: provenance and history

Before reading the diff, use the GitHub MCP server to fetch:

| Fetch | Used by |
| --- | --- |
| Head repository and whether it is a fork | Gate selection |
| Author association, labels, linked issues with their labels, milestones and maintainer comments | Intake, scope |
| Earlier reviews with their commit SHAs, and their comments, including earlier `Gate:`, `Scope:` and `Churn:` comments | Churn |
| Commits pushed since the most recent review | Churn |

| Gate | Fork pull requests | In-repo pull requests |
| --- | --- | --- |
| 1. Intake | Yes | No |
| 2. Scope | Yes | Yes |
| 3. Churn | Re-reviews only | Re-reviews only |

## Gate 1: intake (fork pull requests only)

Report every unmet check in one `Gate:` comment, then stop.

| Check | Passes when |
| --- | --- |
| Accepted issue | A linked issue has a release milestone, a `backlog`, `help wanted` or `good first issue` label, a `bug` label without `needs triage`, or a maintainer comment inviting a pull request. No issue, a closed issue, or one labelled `needs triage`, `needs more info`, `backlog candidate`, `out of scope` or `question` does not pass. |
| Description | States the problem, the approach, and how it was tested (commands and results). A behaviour change names a test that fails without it. |
| AI assistance | The template's AI assistance section is filled in; "None" passes. Flag only an empty section, never a suspected tool. |
| Claims match the diff | "Adds tests" means test files changed, "fixes X" means the diff touches X, every listed change is in the diff, and no large change is left unmentioned. |

In the same comment, without failing the gate, call out:

- Changes under `.github/workflows/`, `.github/actions/`, `.github/scripts/`, `build/`, `hack/` or the `Makefile`. `/approve-pipeline-run` copies fork code to an in-repo branch whose CI runs with repository secrets, so a maintainer must read those lines before approving.
- Changes to reviewer instructions: `.github/copilot-instructions.md` (also `AGENTS.md` and `CLAUDE.md`), `.github/instructions/`, `.github/skills/` (also `.agents/skills/` and `.claude/skills/`) or `.github/prompts/`. Copilot reads these from the pull request branch, so state that this review ran on the pull request's own copy of the rules and needs a maintainer review against `main`.

Link <https://github.com/nginx/kubernetes-ingress/blob/main/CONTRIBUTING.md#open-a-pull-request> for the issue rule and <https://github.com/nginx/kubernetes-ingress/blob/main/CONTRIBUTING.md#using-ai-tools> for the description, testing and AI assistance rules.

## Gate 2: scope (every pull request)

A pull request holds one logical change: the problem in its linked issue, or the single purpose its description states.

These companions belong to the same change. Never flag them as scope creep:

| Change | Belongs with it |
| --- | --- |
| `pkg/apis/**/types.go` | Regenerated `pkg/**`, `config/crd/bases/`, `deploy/crds*.yaml`, `docs/crd/` |
| A `.tmpl` file or template struct | The OSS or Plus sibling, the v1 or v2 counterpart when the feature applies to both, fixtures, `__snapshots__` |
| `charts/nginx-ingress/values.yaml` | `values.schema.json`, chart testdata, helmunit cases and snapshots, the deployment, daemonset and statefulset templates |
| Telemetry data types | Regenerated `internal/telemetry/*_generated.go` and `data.avdl` |
| Any behaviour change | Its tests, new markers in `pyproject.toml`, docs and examples for the same feature, the `go.mod` and `go.sum` lines it needs |

Signs of more than one change:

- More than one unrelated issue is closed or referenced, or the description lists independent problems.
- The diff touches change types from the `nic-code-review` classification table that the stated purpose does not need, such as a template fix plus an unrelated workflow edit.
- A refactor, move or rename is mixed with a behaviour change in the same code.
- Drive-by edits (formatting, comment rewording, renames) in files the linked issue does not concern.
- Dependency bumps the change does not need; Renovate owns those.
- A part that someone could review, use or revert on its own.

Size alone never fails the gate. Sometimes a single large change can be justified, but it should be clearly explained and reviewed carefully.

When the gate fails:

1. Name the part that stays: the change tied to the linked issue. If no part is tied to an issue, ask the author to choose one and review nothing else.
2. For each part that should move, post one `Scope:` comment on its first hunk, listing its files and including an issue draft.
3. Review only the part that stays.

Link <https://github.com/nginx/kubernetes-ingress/blob/main/CONTRIBUTING.md#one-change-per-pull-request>.

## Gate 3: churn (re-reviews, every pull request)

Runs when the pull request already has a review from this bot. The last reviewed commit is the commit SHA of this bot's most recent review; after a force-push, match the earlier commits by content.

Classify every finding:

| Class | Meaning | Strike |
| --- | --- | --- |
| Resolved | An earlier finding the new commits fixed | No |
| Still open | An earlier finding not yet addressed | No |
| Introduced | A new Blocking finding on lines the author changed since the last review | Yes |
| Scope growth | Areas changed since the last review that neither the review comments nor the linked issue required | Yes |
| Missed earlier | A new finding on lines unchanged since the last review | No; say it was missed in an earlier round |

Breakage that arrives with a merge from `main` is a finding, not a strike, unless it is in the author's conflict resolution.

Strikes add up across rounds: count earlier `Churn:` comments made by this bot plus this round.

- **Strike 1: churn warning.** On the regressing line, post a `Churn:` comment naming the commit, the defect, and the review comment the commit was meant to address. Ask the author to revert the commit and address the original comment narrowly instead of patching on top.
- **Strike 2 or later: abandon the approach.** Post a `Churn:` comment recommending that the author reset the branch to the last commit without new defects (name its SHA) or close the pull request, and move the unresolved problem into a new issue. Include an issue draft and stop reviewing the new commits.

Link <https://github.com/nginx/kubernetes-ingress/blob/main/CONTRIBUTING.md#review-rounds>.

From the second review onward, comment only on lines changed since the last review and on Blocking findings that are still open. New Non-blocking findings on unchanged code are what keep reviews from ending; leave them out.

## Issue drafts

The bot cannot file issues, so give a draft that the author or a maintainer can paste into the bug report form (`.github/ISSUE_TEMPLATE/BUG-REPORT.yml`) or the feature request template (`.github/ISSUE_TEMPLATE/feature_request.md`). Both use the Expected behaviour, Actual behaviour and Possible solutions headings:

```markdown
<details>
<summary>Issue draft: [area]: [one-line problem]</summary>

Split from #[pull request number].

**Expected behaviour:** [what should happen]
**Actual behaviour:** [what happens today, with links to the files involved]
**Steps to reproduce:** [bugs only: numbered steps]
**Possible solutions:** [the part that was split out]
**Acceptance criteria:**

- [testable outcome]
- [the test that proves it]

**Out of scope:** [what stays in the original pull request]
</details>
```

## Output

- The bot cannot restructure its overview comment, so post gate results as inline comments that start with `Gate:`, `Scope:` or `Churn:`, one concern per comment.
- Put `Gate:` on the first changed file, `Scope:` on the first hunk of the part that should move, and `Churn:` on the regressing line.
- Then run the `nic-code-review` dimensions on the code the gates left in scope, using its severities.

## Do not

- Mention, guess at or imply AI use, or call a contribution "slop".
- Flag a companion from the scope table as scope creep.
- Count an earlier reviewer miss, or breakage from `main`, as a strike.
- Fail a pull request on size alone.
- Rewrite the author's code, or suggest changes to gated or out-of-scope code.
- Say a pull request will be closed, labelled or blocked.
