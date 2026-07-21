# GitHub comment commands available

## `/cherry-pick to <branch>`

Functionality is in the [cherry-pick.yml](../../.github/workflows/cherry-pick.yml) file.

### What it does

1. saves the target branch per the comment
2. figures out the merged PR's prefix (`chore/`, `fix/`, `ci/` [^1])
3. creates a new cherry pick branch named `<prefix>/cherry-pick-<target branch>-<sha>` on top of the original PR's target branch
4. decides on a merge strategy based on the commits in the original PR against the target branch
   1. [-m 1](https://git-scm.com/docs/git-cherry-pick#Documentation/git-cherry-pick.txt--mparent-number) for branches with 2+ parents
   2. [-x <merge sha>](https://git-scm.com/docs/git-cherry-pick#Documentation/git-cherry-pick.txt--x) for branches with 1 parent on base (all changes that are in the merge commit)
   3. [-x <merge sha>~<# of commit>..<merge sha>](https://git-scm.com/docs/git-cherry-pick#Documentation/git-cherry-pick.txt--x) direct cherry picks for rebases (each individual commit one by one)
5. (force) pushes the cherry-pick branch
6. creates a new PR from the cherry-pick branch against the target in the comment 

[^1]: it only checks [a-z], so `new-feature/other-branch-name` would NOT get `new-feature`, because `-` is not in the regex

### When it fires

All of these need to be true:

* on new issue comments
* if the repository is `nginx/kubernetes-ingress` (so forks and mirrors do not fire)
* that are Pull Requests (PRs are also issue comments per the GitHub API with an extra flag)
* where the person making the comment is either a repository member or owner
* the comment body contains `/cherry-pick to`
* that's followed by either `release-x.y` or `release-2026-lts` [(technically a regex, but the point is that it needs to be one of the release branches)](../../.github/workflows/cherry-pick.yml#L62)

## `/approve-pipeline-run`

Functionality is in [external-pr.yml](../../.github/workflows/external-pr.yml) file.

### What it does

1. Checks out the branch of the PR from the fork
2. adds the NIC repository as an upstream
3. creates a new branch named `chore/<original-branch-name>-<short-sha>-do-not-merge`
4. pushes that branch onto our repository in GitHub
5. creates a PR in the NIC repository
   1. with the title `DO NOT MERGE <original PR title>`
   2. with the original body content
   3. as a draft PR

### When it fires

All of these need to be true:

* on new PR comments (GitHub `issue_comment` event, `created` type)
* that are Pull Requests
* where the PR is opened from a forked repository (the internal mirror job only runs when `is_fork == 'true'`)
* where the target repository is `nginx/kubernetes-ingress` (so PRs against forks and mirrors do not fire)
* and the comment body is exactly `/approve-pipeline-run`
* and the commenter has `admin`, `write`, or `maintain` permission on the repository
