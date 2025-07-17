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

Follow our [Installation Guide](https://docs.nginx.com/nginx-ingress-controller/installation/) to
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
