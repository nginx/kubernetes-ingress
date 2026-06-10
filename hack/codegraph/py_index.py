#!/usr/bin/env python3
"""Index pytest files under tests/suite/ for the codegraph tool.

Writes a single JSON document to stdout. Uses only the stdlib (ast).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path
from typing import List


def _decorator_names(decorators: List[ast.expr]) -> List[str]:
    out: List[str] = []
    for d in decorators:
        # @pytest.mark.foo or @pytest.mark.foo(...)
        node = d.func if isinstance(d, ast.Call) else d
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        if parts:
            out.append(".".join(reversed(parts)))
    return out


def _is_pytest_marker(name: str) -> bool:
    return name.startswith("pytest.mark.") or name.startswith("mark.")


def _fixtures_from_args(args: ast.arguments) -> List[str]:
    return [a.arg for a in args.args if a.arg not in ("self", "cls")]


def index_file(path: Path, repo_root: Path) -> dict | None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return None
    rel = str(path.relative_to(repo_root)).replace(os.sep, "/")
    out: dict = {"file": rel}
    classes: List[dict] = []
    top_tests: List[dict] = []
    file_markers: set[str] = set()
    fixtures: set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            cls = {"name": node.name, "line": node.lineno, "tests": []}
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name.startswith("test_"):
                    deco = _decorator_names(sub.decorator_list)
                    markers = [d for d in deco if _is_pytest_marker(d)]
                    fixtures.update(_fixtures_from_args(sub.args))
                    file_markers.update(markers)
                    cls["tests"].append({"name": sub.name, "line": sub.lineno, "markers": markers or None})
            if cls["tests"]:
                classes.append(cls)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            deco = _decorator_names(node.decorator_list)
            markers = [d for d in deco if _is_pytest_marker(d)]
            fixtures.update(_fixtures_from_args(node.args))
            file_markers.update(markers)
            top_tests.append({"name": node.name, "line": node.lineno, "markers": markers or None})

    if not (classes or top_tests):
        return None
    if classes:
        out["classes"] = [_strip_nulls(c) for c in classes]
    if top_tests:
        out["top_tests"] = [_strip_nulls(t) for t in top_tests]
    if file_markers:
        out["markers"] = sorted(file_markers)
    if fixtures:
        out["fixtures"] = sorted(fixtures)
    return out


def _strip_nulls(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="directory to scan")
    ap.add_argument("--repo-root", required=True, help="repo root for relative paths")
    args = ap.parse_args()

    root = Path(args.root)
    repo_root = Path(args.repo_root)
    files: List[dict] = []
    for path in sorted(root.rglob("*.py")):
        if any(part.startswith(".") for part in path.parts):
            continue
        entry = index_file(path, repo_root)
        if entry is not None:
            files.append(entry)
    json.dump({"files": files}, sys.stdout, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
