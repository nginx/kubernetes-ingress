#!/usr/bin/env python3
"""Preview which ci.yml stages Selective CI would run for your branch.

Compares the working tree (committed and uncommitted changes, not untracked files) with the
merge base of BASE, using the same rules and matcher as the ci-flags action.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import selective_ci  # noqa: E402


def render(config, files, labels):
    flags = selective_ci.compute_flags(config, files, labels)
    jobs = config.get("jobs", {})
    lines = [f"Changed files: {len(files)}"]
    for path in files:
        rules = [r["name"] for r in selective_ci.matching_rules(config, path)]
        lines.append(f"  {path}  [{', '.join(rules) or 'NO RULE: runs every stage'}]")
    if labels:
        lines.append(f"Labels: {', '.join(labels)}")
    lines.append("")
    lines.append("Stages:")
    for flag, value in flags.items():
        stage_jobs = ", ".join(job for job, f in jobs.items() if f == flag)
        lines.append(f"  {'RUN ' if value else 'skip'}  {flag:<18} {stage_jobs}")
    return "\n".join(lines)


def usage(config):
    stages = ", ".join(config["stages"].values())
    return (
        "Selective CI runs only the ci.yml stages that the changed files need (.github/ci-paths.json).\n"
        "A changed file that matches no rule runs every stage. Push and merge-queue runs always run everything.\n\n"
        "PR labels:\n"
        "  ci:run-all          run every stage\n"
        "  ci:run-<stage>      force a stage on (and the stages it needs)\n"
        "  ci:skip-<stage>     turn a stage off\n"
        f"  <stage> is one of: {stages}\n\n"
        "Local preview:\n"
        "  make ci-preview                       diff against origin/main\n"
        "  make ci-preview BASE=origin/release-5.8\n"
        "  make ci-preview LABELS=ci:skip-smoke  comma-separated labels\n"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="branch the PR targets (default: origin/main)")
    parser.add_argument("--labels", default="", help="comma-separated PR labels to simulate")
    parser.add_argument("--files", nargs="*", help="use these paths instead of the git diff")
    parser.add_argument("--help-labels", action="store_true", help="explain Selective CI and its labels")
    args = parser.parse_args(argv)

    config = selective_ci.load_config()
    if args.help_labels:
        print(usage(config))
        return 0

    files = args.files
    if files is None:
        files = selective_ci.changed_files("--merge-base", args.base)
        if files is None:
            return 1
    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    print(render(config, files, labels))
    return 0


if __name__ == "__main__":
    sys.exit(main())
