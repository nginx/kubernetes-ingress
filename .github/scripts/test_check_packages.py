#!/usr/bin/env python3
"""Unit tests for check-packages.py.

Uses the standard library unittest module without external dependencies.
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

# Load check-packages.py dynamically
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "check-packages.py"
spec = importlib.util.spec_from_file_location("check_packages", str(SCRIPT_PATH))
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)


class TestSemverKey(unittest.TestCase):
    def test_numeric_sorting(self):
        versions = ["1.2.9", "1.2.10", "1.2.2"]
        sorted_vers = sorted(versions, key=cp.parse_semver_key)
        self.assertEqual(sorted_vers, ["1.2.2", "1.2.9", "1.2.10"])

    def test_alphanumeric_tokens(self):
        versions = ["R33", "R32", "R33.1", "R33.2"]
        sorted_vers = sorted(versions, key=cp.parse_semver_key)
        self.assertEqual(sorted_vers, ["R32", "R33", "R33.1", "R33.2"])


class TestNormalizeVersion(unittest.TestCase):
    def test_nginx_scheme(self):
        self.assertEqual(cp.normalize_version("nginx", "1.31.5-1~bookworm"), "1.31.5")
        self.assertEqual(cp.normalize_version("nginx", "1.25.0"), "1.25.0")
        self.assertIsNone(cp.normalize_version("nginx", "invalid-version"))

    def test_plus_scheme(self):
        self.assertEqual(cp.normalize_version("plus", "33-1~bookworm"), "R33")
        self.assertEqual(cp.normalize_version("plus", "33.1-1~bookworm"), "R33.1")
        # Debian plus module with +
        self.assertEqual(cp.normalize_version("plus", "37.1+1.0.1"), "R37.1")
        # Alpine plus module with .
        self.assertEqual(cp.normalize_version("plus", "37.1.1.0.1"), "R37.1")

    def test_waf_scheme(self):
        self.assertEqual(cp.normalize_version("waf", "37.1+5.715.0-1~bookworm"), "37.1+5.715.0")
        self.assertEqual(cp.normalize_version("waf", "37.1.5.715.0"), "37.1+5.715.0")

    def test_dos_scheme(self):
        self.assertEqual(cp.normalize_version("dos", "1+2.3.4-1"), "1+2.3.4")
        self.assertEqual(cp.normalize_version("dos", "1.2.3.4"), "1+2.3.4")

    def test_plain_scheme(self):
        self.assertEqual(cp.normalize_version("plain", "2.34.0-1"), "2.34.0")
        self.assertEqual(cp.normalize_version("plain", "3.0.0~rc1"), "3.0.0")


class TestVersionMatches(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(cp.version_matches("1.31.5", "1.31.5"))

    def test_component_boundary_match(self):
        self.assertTrue(cp.version_matches("37.1+5.715", "37.1+5.715.0"))
        self.assertTrue(cp.version_matches("3", "3.12.0"))

    def test_mismatch_and_non_boundary(self):
        self.assertFalse(cp.version_matches("1.31.4", "1.31.45"))
        self.assertFalse(cp.version_matches("2", "3.12.0"))


class TestParseDockerfile(unittest.TestCase):
    def test_parse_dockerfile_args(self):
        content = """\
ARG NGINX_OSS_VERSION=1.31.5
ARG QUOTED_VAL="2.0.0" # with comment
ARG SINGLE_QUOTED='3.0.0'
ARG INLINE_COMMENT=4.0.0 # comment here
ARG COMMENT_INSIDE="val#with#hash"
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = f.name
        try:
            args = cp.parse_dockerfile_args(tmp_path)
            self.assertEqual(args.get("NGINX_OSS_VERSION"), "1.31.5")
            self.assertEqual(args.get("QUOTED_VAL"), "2.0.0")
            self.assertEqual(args.get("SINGLE_QUOTED"), "3.0.0")
            self.assertEqual(args.get("INLINE_COMMENT"), "4.0.0")
            self.assertEqual(args.get("COMMENT_INSIDE"), "val#with#hash")
        finally:
            os.remove(tmp_path)

    def test_resolve_distro_versions(self):
        content = """\
FROM alpine:3.24 AS build
FROM debian:13-slim AS debian-build
FROM redhat/ubi10-minimal AS ubi
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = f.name
        try:
            distros = cp.resolve_distro_versions(tmp_path)
            self.assertEqual(distros["alpine"], ["3.24"])
            self.assertEqual(distros["debian"], ["13"])
            self.assertEqual(distros["centos"], ["10"])
        finally:
            os.remove(tmp_path)


class TestParseChartImageTag(unittest.TestCase):
    def test_active_and_commented_tags(self):
        content = """
nginx:
  image:
    repository: nginx/nginx-ingress
    # tag: "3.5.0"
    pullPolicy: IfNotPresent

agent:
  image:
    repository: nginx/nginx-agent
    tag: "2.35.0"
    pullPolicy: Always
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = f.name
        try:
            self.assertIsNone(cp.parse_chart_image_tag(tmp_path, "nginx/nginx-ingress"))
            self.assertEqual(cp.parse_chart_image_tag(tmp_path, "nginx/nginx-agent"), "2.35.0")
        finally:
            os.remove(tmp_path)


class TestTableFormatting(unittest.TestCase):
    def setUp(self):
        self._orig_color = cp._COLOR
        cp._COLOR = False

    def tearDown(self):
        cp._COLOR = self._orig_color

    def test_visible_len_and_ljust(self):
        colored = "\033[32mhello\033[0m"
        self.assertEqual(cp.visible_len(colored), 5)
        self.assertEqual(cp.visible_len(12345), 5)
        self.assertEqual(len(cp.ljust_visible("test", 10)), 10)

    def test_target_cell(self):
        dep = cp.Dependency("test-pkg", {"host": "example.com", "uri": "/test"})
        dep.required_targets_cache = {("alpine", "3.24", "x86")}
        dep.oses = {("alpine", "3.24", "x86")}

        # Matching build target
        self.assertEqual(cp.target_cell(dep, "alpine", "3.24"), "x86")

        # Not installed on target
        self.assertEqual(cp.target_cell(dep, "debian", "13"), "n/a")

        # Missing target
        dep.oses = set()
        self.assertEqual(cp.target_cell(dep, "alpine", "3.24"), "MISSING")

    def test_matrix_cell(self):
        dep = cp.Dependency("test-pkg", {"host": "example.com", "uri": "/test"})
        targets = {("alpine", "3.24", "x86"), ("alpine", "3.24", "arm")}

        # Exact match
        dep.oses = {("alpine", "3.24", "arm"), ("alpine", "3.24", "x86")}
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", targets), "arm+x86")

        # Incomplete match
        dep.oses = {("alpine", "3.24", "x86")}
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", targets), "x86!")

        # Missing required
        dep.oses = set()
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", targets), "MISSING")

        # Not required but in repo
        dep.repos = {("alpine", "3.24")}
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", set()), "-")

        # Not required and no repo
        dep.repos = set()
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", set()), ".")

        # Index fetch error
        dep.oses = None
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", targets), "?")

    def test_target_and_matrix_cell_no_green_color(self):
        cp._COLOR = True
        dep = cp.Dependency("test-pkg", {"host": "example.com", "uri": "/test"})
        dep.required_targets_cache = {("alpine", "3.24", "x86")}
        dep.oses = {("alpine", "3.24", "x86")}
        targets = {("alpine", "3.24", "x86")}

        # Architectures should not have green color ANSI sequences
        self.assertEqual(cp.target_cell(dep, "alpine", "3.24"), "x86")
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", targets), "x86")

        # But missing / incomplete still get colored
        dep.oses = set()
        self.assertEqual(cp.target_cell(dep, "alpine", "3.24"), f"\033[{cp.RED}mMISSING\033[0m")
        self.assertEqual(cp.matrix_cell(dep, "alpine", "3.24", targets), f"\033[{cp.RED}mMISSING\033[0m")


class TestMatrixResolution(unittest.TestCase):
    def test_parse_matrix_file(self):
        data_dir = SCRIPT_DIR.parent / "data"
        oss_distros, oss_plats = cp.parse_matrix_file(str(data_dir / "matrix-images-oss.json"))
        self.assertEqual(oss_plats, ["linux/amd64", "linux/arm64"])
        self.assertEqual(oss_distros["alpine"], {"x86", "arm"})
        self.assertEqual(oss_distros["debian"], {"x86", "arm"})
        self.assertEqual(oss_distros["centos"], {"x86", "arm"})

        nap_distros, nap_plats = cp.parse_matrix_file(str(data_dir / "matrix-images-nap.json"))
        self.assertEqual(nap_plats, ["linux/amd64"])
        self.assertEqual(nap_distros["alpine"], {"x86"})
        self.assertEqual(nap_distros["debian"], {"x86"})
        self.assertEqual(nap_distros["centos"], {"x86"})

    def test_resolve_matrix_distros(self):
        data_dir = SCRIPT_DIR.parent / "data"
        group_distros, default_platforms = cp.resolve_matrix_distros(str(data_dir))
        self.assertEqual(default_platforms, ["linux/amd64", "linux/arm64"])
        self.assertIn("oss", group_distros)
        self.assertIn("plus", group_distros)
        self.assertIn("agent", group_distros)
        self.assertIn("nap-waf", group_distros)
        self.assertIn("nap-signatures", group_distros)
        self.assertIn("nap-dos", group_distros)
        # Verify NAP groups are x86 only
        self.assertEqual(group_distros["nap-waf"]["alpine"], {"x86"})
        self.assertEqual(group_distros["nap-signatures"]["debian"], {"x86"})


class TestConfigParsing(unittest.TestCase):
    def test_ini_matrix_distros_and_overrides(self):
        ini_path = SCRIPT_DIR.parent / "data" / "dependency-check.ini"
        deps = cp.load_config(str(ini_path))
        dep_map = {d.name: d for d in deps}

        # Check matrix distros dynamically inherited for OSS
        nginx_dep = dep_map["nginx"]
        self.assertEqual(nginx_dep.distros["alpine"], {"arm", "x86"})
        self.assertEqual(nginx_dep.distros["debian"], {"arm", "x86"})
        self.assertEqual(nginx_dep.distros["centos"], {"arm", "x86"})

        # Check geoip override (centos omitted)
        geoip_dep = dep_map["nginx-module-geoip"]
        self.assertEqual(geoip_dep.distros["alpine"], {"arm", "x86"})
        self.assertEqual(geoip_dep.distros["debian"], {"arm", "x86"})
        self.assertNotIn("centos", geoip_dep.distros)

        # Check NAP WAF dynamically inherited (x86 only)
        waf_dep = dep_map["waf-v4"]
        self.assertEqual(waf_dep.distros["alpine"], {"x86"})
        self.assertEqual(waf_dep.distros["debian"], {"x86"})
        self.assertEqual(waf_dep.distros["centos"], {"x86"})

        # Check NAP WAF engine override (debian only)
        engine_dep = dep_map["waf-v4-engine"]
        self.assertEqual(engine_dep.distros, {"debian": {"x86"}})

        # Check DoS override (alpine omitted)
        dos_dep = dep_map["dos"]
        self.assertEqual(dos_dep.distros, {"debian": {"x86"}, "centos": {"x86"}})

        # Check nic-image dynamically inherited platforms
        nic_img = dep_map["nic-image"]
        self.assertEqual(nic_img.platforms, ["linux/amd64", "linux/arm64"])


if __name__ == "__main__":
    unittest.main()
