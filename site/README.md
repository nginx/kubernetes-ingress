# NGINX Ingress Controller Documentation

This directory contains all of the user documentation for NGINX Ingress Controller, as well as the requirements for building and publishing the documentation.

We write our documentation in Markdown. We build it with [Hugo](https://gohugo.io) and our custom [NGINX Hugo theme](https://github.com/nginxinc/nginx-hugo-theme). We set up previews and deployments using our [docs-actions](https://github.com/nginx/docs-actions?tab=readme-ov-file#docs-actions) workflow.

## Setup

Hugo is the only requirement for building documentation, but the repository's integration tooling uses markdownlint-cli.

> **Note**: We currently use [Hugo v0.115.3](https://github.com/gohugoio/hugo/releases/tag/v0.115.3) in production.

Although not a strict requirement, markdown-link-check is also used in documentation development.

If you have [Docker](https://www.docker.com/get-started/) installed, there are fallbacks for all in the [Makefile](Makefile), meaning you do need to install them.

- [Installing Hugo](https://gohugo.io/getting-started/installing/)
- [Installing markdownlint-cli](https://github.com/igorshubovych/markdownlint-cli?tab=readme-ov-file#installation)
- [Installing markdown-link-check](https://github.com/tcort/markdown-link-check?tab=readme-ov-file#installation).

The configuration files are as follows:

- *Hugo*: `config/_default/config.toml`
- *markdownlint-cli*: `.markdownlint.json`
- *markdown-link-check* `md-linkcheck-config.json`

## Repository guidelines

To work on documentation, create a feature branch in a forked repository then target `main` with your pull requests, which is the default repository branch.

The documentation is published from the latest public release branch. If your changes require immediate publication, create a pull request to cherry-pick changes from `main` to the public release branch.

## Develop documentation locally

To build the documentation locally, use the `make` command in the documentation folder with these targets:

```text
make docs           - Builds the documentation
make watch          - Runs a local Hugo server to automatically preview changes
make drafts         - Runs a local Hugo server, and displays documentation marked as drafts
make clean          - Removes the output 'public' directory created by Hugo
make hugo-get       - Updates the go module file with the latest version of the theme
make hugo-tidy      - Removes unnecessary dependencies from the go module file
make hugo-update    - Runs the hugo-get and hugo-tidy targets in sequence
make lint-markdown  - Runs markdownlint on the content folder
make link-check     - Runs markdown-link-check on all Markdown files
```

## Adding new documentation

### Generate a new documentation file using Hugo

To create a new documentation file containing the pre-configured Hugo front-matter with the task template, **run the following command in the documentation directory**:

`hugo new <SECTIONNAME>/<FILENAME>.<FORMAT>`

For example:

```shell
hugo new getting-started/install.md
```

The default template -- task -- should be used for most documentation. To create documentation using the other content templates, you can use the `--kind` flag:

```shell
hugo new tutorials/deploy.md --kind tutorial
```

The available content templates (`kind`) are:

- concept: Help a user learn about a specific feature or feature set.
- tutorial: Walk a user through an example use case scenario.
- reference: Describes an API, command line tool, configuration options, etc.
- troubleshooting: Guide a user towards solving a specific problem.
- openapi: A template with the requirements to render an openapi.yaml specification.

## Documentation formatting

### Basic markdown formatting

There are multiple ways to format text: for consistency and clarity, these are our conventions:

- Bold: Two asterisks on each side - `**Bolded text**`.
- Italic: One underscore on each side - `_Italicized text_`.
- Unordered lists: One dash - `- Unordered list item`.
- Ordered lists: The 1 character followed by a stop - `1. Ordered list item`.

> **Note**: The ordered notation automatically enumerates lists when built by Hugo.

Close every section with a horizontal line by using three dashes: `---`.

### How to format internal links

Internal links should use Hugo [ref and relref shortcodes](https://gohugo.io/content-management/cross-references/).

- Although file extensions are optional for Hugo, we include them as best practice for page anchors.
- Relative paths are preferred, but just the filename is permissible.
- Paths without a leading forward slash (`/`) are first resolved relative to the current page, then the remainder of the website.

Here are two examples:

```md
To install <software>, refer to the [installation instructions]({{< ref "install.md" >}}).
To install <integation>, refer to the [integration instructions]({{< relref "/integration/thing.md#section" >}}).
```

### How to add images

Use the `img` [shortcode](#using-hugo-shortcodes) to add images into your documentation.

1. Add the image to the `/static/img` directory.
1. Add the `img` shortcode:
    `{{< img src="<img-file.png>" >}}`
   - **Do not include a forward slash at the beginning of the file path.**
   - This will break the image when it's rendered: read about the  [Hugo relURL Function](https://gohugo.io/functions/relurl/#input-begins-with-a-slash) to learn more.

> **Note**: The `img` shortcode accepts all of the same parameters as the Hugo [figure shortcode](https://gohugo.io/content-management/shortcodes/#figure).

### Using Hugo shortcodes

[Hugo shortcodes](https://github.com/nginxinc/nginx-hugo-theme/tree/main/layouts/shortcodes) are used to format callouts, add images, and reuse content across different pages.

For example, to use the `note` callout:

```md
{{< note >}}Provide the text of the note here.{{< /note >}}
```

The callout shortcodes support multi-line blocks:

```md
{{< caution >}}
You should probably never do this specific thing in a production environment.

If you do, and things break, don't say we didn't warn you.
{{< /caution >}}
```

Supported callouts:

- `caution`
- `important`
- `note`
- `see-also`
- `tip`
- `warning`

Here are some other shortcodes:

- `fa`: Inserts a Font Awesome icon
- `collapse`: Make a section collapsible
- `tab`: Create mutually exclusive tabbed window panes, useful for parallel instructions
- `table`: Add scrollbars to wide tables for browsers with smaller viewports
- `link`: Link to a file, prepending its path with the Hugo baseUrl
- `openapi`: Loads an OpenAPI specifcation and render it as HTML using ReDoc
- `include`: Include the content of a file in another file; the included file must be present in the '/content/includes/' directory
- `raw-html`: Include a block of raw HTML
- `readfile`: Include the content of another file in the current file, which can be in an arbitrary location.
