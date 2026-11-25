#!/usr/bin/env python3
"""Selective CI: decide which ci.yml stages run for a set of changed files.

The rules live in .github/ci-paths.json. This module is the only matcher, used by the
ci-flags action in CI and by ci-preview.py locally, so both always agree.
"""

import argparse
import json
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "ci-paths.json"
RUN_ALL_LABEL = "ci:run-all"


def load_config(path=DEFAULT_CONFIG):
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
    flags = set(config["stages"])
    for rule in config["rules"]:
        unknown = set(rule["flags"]) - flags
        if unknown:
            raise ValueError(f"rule {rule['name']!r} uses unknown flags {sorted(unknown)}")
    for flag, needed in config.get("implies", {}).items():
        unknown = ({flag} | set(needed)) - flags
        if unknown:
            raise ValueError(f"implies uses unknown flags {sorted(unknown)}")
    return config


@lru_cache(maxsize=None)
def glob_to_regex(pattern):
    """'**/' matches zero or more directories, '**' anything, '*' and '?' never cross '/'."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out)


def matching_rules(config, path):
    return [r for r in config["rules"] if any(glob_to_regex(p).fullmatch(path) for p in r["paths"])]


def compute_flags(config, files, labels=(), run_all=False):
    """Return {flag: bool}. Unmatched files, no file list, or ci:run-all turn every flag on."""
    all_flags = list(config["stages"])
    if run_all or RUN_ALL_LABEL in labels or files is None:
        return dict.fromkeys(all_flags, True)

    on = set()
    for path in files:
        rules = matching_rules(config, path)
        if not rules:
            # unknown path: fail safe and run everything
            return dict.fromkeys(all_flags, True)
        for rule in rules:
            on.update(rule["flags"])

    # ci:skip-<stage> first, then ci:run-<stage>, so a label conflict runs the stage
    for flag, stage in config["stages"].items():
        if f"ci:skip-{stage}" in labels:
            on.discard(flag)
    for flag, stage in config["stages"].items():
        if f"ci:run-{stage}" in labels:
            on.add(flag)

    # a stage cannot run without the jobs it needs
    todo = list(on)
    while todo:
        for needed in config.get("implies", {}).get(todo.pop(), []):
            if needed not in on:
                on.add(needed)
                todo.append(needed)

    return {flag: flag in on for flag in all_flags}


def changed_files(*diff_args):
    """Files changed by `git diff --name-only <diff_args>`, or None if git fails."""
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", *diff_args], check=True, capture_output=True, text=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"::warning::git diff {' '.join(diff_args)} failed, running every stage: {e}", file=sys.stderr)
        return None
    return [line for line in out.splitlines() if line]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)
    flags = sub.add_parser("flags", help="print run_*=true|false lines for $GITHUB_OUTPUT")
    flags.add_argument("--event", required=True, help="github.event_name")
    flags.add_argument("--labels", default="[]", help="JSON list of PR label names")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    labels = json.loads(args.labels) or []
    # PR checkouts are merge commits, so HEAD^1..HEAD is exactly what the PR changes
    files = changed_files("HEAD^1", "HEAD") if args.event == "pull_request" else None
    for flag, value in compute_flags(config, files, labels).items():
        print(f"{flag}={str(value).lower()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
