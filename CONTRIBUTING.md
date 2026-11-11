# Contributing Guidelines

The following is a set of guidelines for contributing to NGINX Ingress Controller. We really appreciate that you are
considering contributing!

## Table Of Contents

[Ask a Question](#ask-a-question)

[Getting Started](#getting-started)

[Contributing](#contributing)

[Style Guides](#style-guides)

- [Git Style Guide](#git-style-guide)
- [Go Style Guide](#go-style-guide)

[Code of Conduct](CODE_OF_CONDUCT.md)

## Ask a Question

To ask a question please use [Github Discussions](https://github.com/nginx/kubernetes-ingress/discussions).

You can also get help through the [NGINX Community Forum](https://community.nginx.org/).

Please reserve GitHub issues for feature requests and bugs rather than general questions.

## Getting Started

Follow our [Installation Guide](https://docs.nginx.com/nginx-ingress-controller/install/) to
get NGINX Ingress Controller up and running.

Read the [documentation](https://docs.nginx.com/nginx-ingress-controller) and
[configuration](https://github.com/nginx/kubernetes-ingress/tree/main/examples) examples

### Project Structure

- NGINX Ingress Controller is written in Go and supports both the open source NGINX software and NGINX Plus.
- The project follows a standard Go project layout
  - The main code is found at `cmd/nginx-ingress/`
  - The internal code is found at `internal/`
  - Build files for Docker are found at `build/`
  - CI files are found at `.github/workflows/`
  - Deployment yaml files, and Helm files are found at `deployments/`
  - We use [Go modules](https://github.com/golang/go/wiki/Modules) for managing dependencies.

## Contributing

### Report a Bug

To report a bug, open an issue on GitHub and choose the type 'Bug report'. Please ensure the issue has not already been
reported, and that you fill in the template as provided, as this can reduce turnaround time.

### Suggest a new feature or other improvement

To suggest an new feature or other improvement, create an issue on Github and choose the type 'Feature request'. Please
fill in the template as provided.

### Open a Pull Request

- Before working on a possible pull request, first open an associated issue describing the proposed change. This allows
  the core development team to discuss the potential pull request with you before you do the work.
- Fork the repo, create a branch, submit a PR when your changes are tested and ready for review
- Fill in [our pull request template](.github/PULL_REQUEST_TEMPLATE.md)

> **Note**
>
> Remember to create a feature request / bug report issue first to start a discussion about the proposed change.

### One change per pull request

- Each pull request should solve one problem: the one described in its linked issue. If you spot something else along the
  way, open a separate issue or pull request for it.
- Keep refactors, file moves and renames out of pull requests that change behaviour, unless the change can't be made
  without them.
- One change can still touch many files. Regenerated code and CRDs, snapshots, both the NGINX and NGINX Plus templates,
  Helm chart schema updates, and the tests and docs for the same feature all belong in the same pull request.
- Smaller pull requests get reviewed faster. If yours is large, explain in the description why it can't be split.

### Review rounds

- Push fixes for review comments as new commits, so reviewers can see what changed since their last review. Only squash
  when a maintainer asks you to.
- Keep each fix narrow: address the comment and nothing else.
- If a fix introduces a new problem, revert it and address the original comment again instead of patching on top. If
  that happens a second time, we will ask you to reset the branch to its last good state or close the pull request, and
  to move the unresolved problem into a new issue. This is not a rejection: it stops reviews from going in circles, and
  we are happy to review the work again as a smaller pull request.

### Using AI tools

You are welcome to use AI tools, but you are the author and you are accountable for every line you submit.

- Understand your change. You must be able to explain what it does and how it fits into the rest of the controller
  without help from an AI tool. If you can't, don't submit it.
- Prove that it works. Include a test that fails without your change, and describe in the pull request how you ran it.
- Disclose it. Fill in the AI assistance section of the pull request template with the tool you used and what it did,
  or write "None".
- Write the pull request description and your replies to review comments yourself. Reviewers want to talk with you, not
  with your tool.
- Don't let agents act for you. Pull requests, issues and comments that an agent posts without your review may be closed
  without review.
- Maintainers may close a pull request when reviewing it would cost more than it brings to the project, for example when
  it bundles unrelated changes or its author can't explain it.

### Issue lifecycle

- When an issue or PR is created, it will be triaged by the core development team and assigned a label to indicate the
  type of issue it is (bug, feature request, etc) and to determine the milestone. Please see the [Issue
  Lifecycle](ISSUE_LIFECYCLE.md) document for more information.

### F5 Contributor License Agreement (CLA)

F5 requires all external contributors to agree to [the terms of the F5 CLA](https://github.com/f5/.github/blob/main/CLA/cla-markdown.md))
before any of their changes can be incorporated into an F5 Open Source repository.

If you have not yet agreed to the F5 CLA terms and submit a PR to this repository, a bot will prompt you to view and
agree to the F5 CLA. You will have to agree to the F5 CLA terms through a comment in the PR before any of your changes
can be merged. Your agreement signature will be safely stored by F5 and no longer be required in future PRs.

## Style Guides

### Git Style Guide

- Keep a clean, concise and meaningful git commit history on your branch, rebasing locally and squashing before
  submitting a PR
- Follow the guidelines of writing a good commit message as described here <https://chris.beams.io/posts/git-commit/>
  and summarized in the next few points
  - In the subject line, use the present tense ("Add feature" not "Added feature")
  - In the subject line, use the imperative mood ("Move cursor to..." not "Moves cursor to...")
  - Limit the subject line to 72 characters or less
  - Reference issues and pull requests liberally after the subject line
  - Add more detailed description in the body of the git message (`git commit -a` to give you more space and time in
    your text editor to write a good message instead of `git commit -am`)

### Go Style Guide

- Run `gofmt` over your code to automatically resolve a lot of style issues. Most editors support this running
  automatically when saving a code file.
- Run `go lint` and `go vet` on your code too to catch any other issues.
- Follow this guide on some good practice and idioms for Go -  <https://github.com/golang/go/wiki/CodeReviewComments>
- To check for extra issues, install [golangci-lint](https://github.com/golangci/golangci-lint) and run `make lint` or
  `golangci-lint run`
