import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "ci-preview.py"


def preview(*args):
    return subprocess.run([sys.executable, SCRIPT, *args], check=True, capture_output=True, text=True).stdout


def stages(output):
    """{flag: 'RUN '|'skip'} from the Stages section."""
    section = output.split("Stages:\n", 1)[1]
    return {line[8:].split()[0]: line[2:6] for line in section.splitlines() if line.strip()}


class PreviewTest(unittest.TestCase):
    # stage combinations per kind of change; the full rule matrix is in test_selective_ci.py
    CASES = {
        "go": (["internal/k8s/controller.go"], {"run_codegen", "run_staticcheck", "run_smoke_tests"}, set()),
        "helm": (["charts/nginx-ingress/values.yaml"], {"run_helm_tests"}, {"run_staticcheck", "run_package_tests"}),
        "docs": (["docs/README.md"], set(), {"run_unit_tests", "run_build_images", "run_smoke_tests"}),
        "template": (["internal/configs/version1/nginx.ingress.tmpl"], {"run_smoke_tests"}, {"run_codegen"}),
        "dockerfile": (["build/Dockerfile"], {"run_build_images", "run_package_tests"}, {"run_govulncheck"}),
    }

    def test_change_kinds(self):
        for name, (files, want_run, want_skip) in self.CASES.items():
            with self.subTest(name):
                got = stages(preview("--files", *files))
                self.assertTrue(all(got[f] == "RUN " for f in want_run), got)
                self.assertTrue(all(got[f] == "skip" for f in want_skip), got)

    def test_labels(self):
        got = stages(preview("--labels", "ci:skip-smoke, ci:run-codegen", "--files", "internal/k8s/controller.go"))
        self.assertEqual(got["run_smoke_tests"], "skip")
        self.assertEqual(got["run_codegen"], "RUN ")

    def test_unmatched_file_is_flagged(self):
        out = preview("--files", "brand/new.file")
        self.assertIn("NO RULE: runs every stage", out)
        self.assertNotIn("skip", stages(out).values())

    def test_lists_jobs(self):
        self.assertIn("smoke-tests-oss", preview("--files"))

    def test_help_labels(self):
        self.assertIn("ci:skip-<stage>", preview("--help-labels"))


if __name__ == "__main__":
    unittest.main()
