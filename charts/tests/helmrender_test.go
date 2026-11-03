//go:build helmunit

package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helmOptions is the subset of terratest's helm.Options that these tests used:
// a namespace and a list of values files.
type helmOptions struct {
	namespace   string
	valuesFiles []string
}

// renderTemplateE shells out to `helm template` and returns its stdout, passed
// through normalizeRendered so the result is independent of the helm binary's
// major version.
//
// The argument order deliberately mirrors what terratest's helm.RenderTemplateE
// built:
//
//	helm template [--namespace ns] [-f <abs values file>]... [extra args...] <release> <chart dir>
//
// Values files are resolved with filepath.Abs, as terratest did, so relative
// paths in the test tables keep working regardless of helm's own path handling.
//
// The returned error embeds helm's stderr, which is where schema and template
// validation failures are reported and what the negative tests assert on.
func renderTemplateE(chartDir, releaseName string, opts helmOptions, extraArgs ...string) (string, error) {
	absChartDir, err := filepath.Abs(chartDir)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(absChartDir); err != nil {
		return "", fmt.Errorf("chart dir %q not found: %w", chartDir, err)
	}

	args := []string{"template"}
	if opts.namespace != "" {
		args = append(args, "--namespace", opts.namespace)
	}
	for _, valuesFile := range opts.valuesFiles {
		absValuesFile, err := filepath.Abs(valuesFile)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(absValuesFile); err != nil {
			return "", fmt.Errorf("values file %q not found: %w", valuesFile, err)
		}
		args = append(args, "-f", absValuesFile)
	}
	args = append(args, extraArgs...)
	args = append(args, releaseName, chartDir)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("helm", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return normalizeRendered(stdout.String()),
			fmt.Errorf("error while running command: %w; %s", err, trimTrailingNewline(stderr.String()))
	}

	return normalizeRendered(stdout.String()), nil
}

// trimTrailingNewline drops the single trailing newline helm writes. It is used
// for stderr, which carries helm's schema and template validation messages and
// must stay verbatim for the negative tests to assert on.
func trimTrailingNewline(s string) string {
	return strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// normalizeRendered rewrites `helm template` output into a form that does not
// depend on the major version of the helm binary on PATH.
//
// Helm 3 and Helm 4 render this chart to semantically identical manifests but
// serialize them differently. Helm 4 preserves trailing whitespace that Helm 3
// stripped, and for a template that renders to nothing Helm 3 emits a
// placeholder document (a lone `# Source:` comment between two separators)
// where Helm 4 emits blank lines. Both differences are cosmetic: rendering
// every fixture through both binaries and comparing the parsed objects yields
// no differences. Left unnormalized they would couple the committed snapshots
// to whichever helm binary produced them.
//
// The normal form is one `---` separated document per rendered object, each
// preceded by the `# Source:` comment naming the template it came from, with
// blank lines and trailing whitespace removed. Helm prints `# Source:` once per
// template file, so a document following an inner `---` inherits the source of
// the file being rendered. Documents with no content are dropped together with
// their source comment, which is what lets a test assert that a template
// rendered nothing at all.
//
// Caveat: blank lines inside block scalars are removed as well. That is safe
// here because every block scalar this chart emits uses `|-` (strip chomping),
// so trailing newlines are not part of the value. A future `|` or `|+` scalar
// whose trailing newlines are significant would need this revisited.
func normalizeRendered(s string) string {
	var (
		docs   []string
		body   []string
		source string
	)

	flush := func() {
		if len(body) > 0 {
			docs = append(docs, "---\n"+source+"\n"+strings.Join(body, "\n"))
		}
		body = nil
	}

	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, " \t")

		switch {
		case line == "---":
			flush()
		case strings.HasPrefix(line, "# Source:"):
			source = line
		case line != "":
			body = append(body, line)
		}
	}
	flush()

	return strings.Join(docs, "\n")
}

// renderTemplate is renderTemplateE but fails the test instead of returning an error.
func renderTemplate(t *testing.T, chartDir, releaseName string, opts helmOptions, extraArgs ...string) string {
	t.Helper()

	output, err := renderTemplateE(chartDir, releaseName, opts, extraArgs...)
	if err != nil {
		t.Fatalf("helm template %s: %v", releaseName, err)
	}

	return output
}
