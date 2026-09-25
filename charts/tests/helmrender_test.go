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

// renderTemplateE shells out to `helm template` and returns its stdout.
//
// The argument order deliberately mirrors what terratest's helm.RenderTemplateE
// built, so the committed snapshots keep matching:
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
		return trimTrailingNewline(stdout.String()),
			fmt.Errorf("error while running command: %w; %s", err, trimTrailingNewline(stderr.String()))
	}

	return trimTrailingNewline(stdout.String()), nil
}

// trimTrailingNewline drops the single trailing newline helm writes.
//
// terratest accumulated command output line by line and rejoined it with
// strings.Join(lines, "\n"), which discarded that final newline. The committed
// snapshots were recorded through that path, so reproduce it here rather than
// rewriting 39 snapshot files.
func trimTrailingNewline(s string) string {
	return strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
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
