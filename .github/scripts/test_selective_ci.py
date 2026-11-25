import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import selective_ci  # noqa: E402

CONFIG = selective_ci.load_config()
ALL = set(CONFIG["stages"])
IMAGE_STAGES = {"run_unit_tests", "run_build_images", "run_package_tests", "run_helm_tests", "run_smoke_tests"}


def on(files, labels=()):
    return {flag for flag, value in selective_ci.compute_flags(CONFIG, files, labels).items() if value}


class GlobTest(unittest.TestCase):
    def test_glob(self):
        cases = [
            ("**/*.md", "README.md", True),
            ("**/*.md", "docs/a/b.md", True),
            ("**/*.go", "cmd/main.go", True),
            ("docs/**", "docs/a/b", True),
            ("docs/**", "docsx/a", False),
            (".github/data/matrix-images-*.json", ".github/data/matrix-images-oss.json", True),
            (".github/data/matrix-images-*.json", ".github/data/sub/matrix-images-oss.json", False),
            ("go.mod", "x/go.mod", False),
            ("tests/Makefile", "tests/Makefile", True),
            ("a?c", "a/c", False),
        ]
        for pattern, path, want in cases:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(bool(selective_ci.glob_to_regex(pattern).fullmatch(path)), want)


class ConfigTest(unittest.TestCase):
    def test_every_tracked_file_matches_a_rule(self):
        files = subprocess.run(["git", "ls-files"], check=True, capture_output=True, text=True).stdout.split()
        unmatched = [f for f in files if not selective_ci.matching_rules(CONFIG, f)]
        self.assertEqual(unmatched, [], "add these paths to .github/ci-paths.json or they run every stage")

    def test_unknown_flag_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump({"stages": {"run_a": "a"}, "rules": [{"name": "x", "paths": ["*"], "flags": ["run_b"]}]}, f)
            f.flush()
            with self.assertRaises(ValueError):
                selective_ci.load_config(f.name)


class FlagsTest(unittest.TestCase):
    def test_docs_only_runs_nothing(self):
        self.assertEqual(on(["README.md", "docs/content/x.md", "examples/foo/bar.yaml"]), set())

    def test_go_runs_everything(self):
        self.assertEqual(on(["internal/k8s/controller.go"]), ALL)

    def test_go_test_file_runs_everything(self):
        self.assertEqual(on(["internal/k8s/controller_test.go"]), ALL)

    def test_template(self):
        self.assertEqual(on(["internal/configs/version2/nginx-plus.virtualserver.tmpl"]), IMAGE_STAGES)

    def test_chart(self):
        self.assertEqual(
            on(["charts/nginx-ingress/values.yaml"]),
            {"run_codegen", "run_unit_tests", "run_build_images", "run_helm_tests", "run_smoke_tests"},
        )

    def test_dockerfile(self):
        self.assertEqual(on(["build/Dockerfile"]), IMAGE_STAGES)

    def test_python_tests(self):
        self.assertEqual(
            on(["tests/suite/test_virtual_server.py"]), {"run_unit_tests", "run_build_images", "run_smoke_tests"}
        )

    def test_package_script(self):
        self.assertEqual(
            on(["tests/scripts/check_container_packages.py"]),
            {"run_unit_tests", "run_build_images", "run_package_tests", "run_smoke_tests"},
        )

    def test_unmatched_file_runs_everything(self):
        self.assertEqual(on(["some/new/thing.txt"]), ALL)

    def test_workflow_change_runs_everything(self):
        self.assertEqual(on([".github/workflows/ci.yml"]), ALL)

    def test_no_file_list_runs_everything(self):
        self.assertEqual(on(None), ALL)

    def test_empty_diff_runs_nothing(self):
        self.assertEqual(on([]), set())


class LabelTest(unittest.TestCase):
    def test_run_all(self):
        self.assertEqual(on(["README.md"], ["ci:run-all"]), ALL)

    def test_run_stage_pulls_in_dependencies(self):
        self.assertEqual(on(["README.md"], ["ci:run-smoke"]), {"run_smoke_tests", "run_build_images", "run_unit_tests"})

    def test_skip_stage(self):
        self.assertEqual(on(["internal/k8s/controller.go"], ["ci:skip-smoke"]), ALL - {"run_smoke_tests"})

    def test_run_wins_over_skip(self):
        self.assertIn("run_smoke_tests", on(["README.md"], ["ci:skip-smoke", "ci:run-smoke"]))

    def test_skip_dependency_is_restored(self):
        self.assertIn("run_build_images", on(["internal/k8s/controller.go"], ["ci:skip-build"]))


class MainTest(unittest.TestCase):
    def test_push_prints_every_flag_true(self):
        result = subprocess.run(
            [sys.executable, selective_ci.__file__, "flags", "--event", "push", "--labels", "null"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.splitlines(), [f"{flag}=true" for flag in CONFIG["stages"]])


if __name__ == "__main__":
    unittest.main()
