---
description: 'Review the diff between the current branch and its base as if it were a pull request.'
---

# PR Review

Load and follow the **`nic-code-review`** skill at [`.github/skills/nic-code-review/SKILL.md`](../skills/nic-code-review/SKILL.md).

## Task

1. Determine the base and head:
   - Default base: `origin/main` (or `origin/release-*` if the current branch name starts with `release-`).
   - Head: the current working branch.
2. Get the diff. Prefer the `get_changed_files` tool; fall back to `git diff <base>...HEAD`.
3. Classify the change using the **Change type classification** table in the skill and load any referenced sub-skills.
4. Walk the applicable **dimension checklists** in the skill (Security -> Correctness -> Architecture -> Tests -> layer-specific).
5. Verify each finding by reading the actual file, not just the hunk. Never fabricate line numbers or symbol names.
6. Produce the review in the **Output format** defined in the skill (Summary / Blocking / Non-blocking / Questions).

## Constraints

- Comment only at >80% confidence.
- Do not compliment, do not restate what the diff does, do not rewrite the diff for the author.
- Never quote credentials, tokens, or license contents in review output.
