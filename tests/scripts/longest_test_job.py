#!/usr/bin/env python3
"""Analyse GitHub Actions CI runs.

Two modes:

* ``jobs`` (default): list workflow runs and any of their jobs that took
  longer than a threshold. Useful for spotting slow shards.
* ``durations``: download job logs for jobs matching a filter, parse the
  ``slowest N durations`` block emitted by pytest, and print aggregate
  per-test statistics across recent runs. Useful for informing shard
  rebalancing decisions.
"""

import argparse
import re
import statistics
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import requests
from github import Auth, Github


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--token", required=True, help="GitHub access token")
    parser.add_argument("-o", "--owner", default="nginx", help="GitHub repository owner")
    parser.add_argument("-r", "--repo", default="kubernetes-ingress", help="GitHub repository name")
    parser.add_argument("-w", "--workflow", default="CI", help="GitHub Actions workflow name")
    parser.add_argument(
        "-b",
        "--branch",
        default="main",
        help="GitHub repository branch (pass empty string to include all branches)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        default=900,
        type=int,
        help="Minimum job duration in seconds (jobs mode)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["jobs", "durations"],
        default="jobs",
        help="Analysis mode",
    )
    parser.add_argument(
        "--job-filter",
        default="smoke tests / setup-smoke",
        help="Substring to match job names in durations mode",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Max number of recent completed runs to analyse in durations mode",
    )
    parser.add_argument(
        "--since-days",
        type=int,
        default=30,
        help="Ignore runs older than this many days (GitHub retains job logs ~90 days)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        help="How many slowest tests to print in durations mode",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Parallel workers for downloading job logs",
    )
    parser.add_argument(
        "--group-by",
        choices=["test", "file"],
        default="test",
        help="Aggregate durations per full test id or per test file",
    )
    return parser.parse_args()


def get_github_handle(token):
    auth = Auth.Token(token)
    return Github(auth=auth)


def get_github_repo(owner, repo, handle):
    return handle.get_repo(f"{owner}/{repo}")


def get_workflow_runs(repo, workflow_name, branch=None):
    for workflow in repo.get_workflows():
        if workflow.name == workflow_name:
            kwargs = {"status": "completed"}
            if branch:
                kwargs["branch"] = branch
            return workflow.get_runs(**kwargs)
    return None


def get_run_branch_jobs(runs):
    return {run.id: run.jobs() for run in runs}


def get_run_durations(runs):
    results = {}
    for run in runs:
        duration_ms = run.timing().run_duration_ms
        results[run.id] = duration_ms / 1000 if duration_ms is not None else None
    return results


def convert_seconds(seconds):
    minutes, remaining_seconds = divmod(int(seconds), 60)
    hour, minutes = divmod(minutes, 60)
    return "%d:%02d:%02d" % (hour, minutes, remaining_seconds)


def filter_recent_runs(runs, since_days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    return [run for run in runs if run.created_at >= cutoff]


def run_jobs_mode(runs, threshold):
    wj = get_run_branch_jobs(runs)
    wd = get_run_durations(runs)
    for run_id in sorted(wj.keys()):
        duration = wd.get(run_id)
        if duration is None:
            continue
        print(f"Workflow Run ID: {run_id}, Duration: {convert_seconds(duration)}")
        for job in wj[run_id]:
            job_duration = (job.completed_at - job.started_at).total_seconds()
            if job.status == "completed" and job.conclusion == "success" and job_duration > threshold:
                print(f"  Job: {job.name}, " f"Duration: {convert_seconds(job_duration)}, " f"URL: {job.html_url}")


# Matches pytest --durations output lines, with or without the GH Actions
# timestamp prefix, e.g.:
#   "  120.45s call     tests/suite/test_x.py::TestC::test_m[param]"
#   "2026-07-17T10:15:23.4567890Z 120.45s call tests/suite/test_x.py::test_thing"
DURATION_LINE = re.compile(r"(?P<seconds>\d+\.\d+)s\s+(?P<phase>call|setup|teardown)\s+(?P<test>\S+)")
DURATION_HEADER = re.compile(r"slowest\s+\d+\s+durations", re.IGNORECASE)


def collect_smoke_jobs(runs, name_filter, max_runs):
    """Yield (run_id, job) for jobs whose name contains name_filter."""
    seen_runs = 0
    for run in runs:
        seen_runs += 1
        if seen_runs > max_runs:
            return
        for job in run.jobs():
            if job.status != "completed" or job.conclusion != "success":
                continue
            if name_filter in job.name:
                yield run.id, job


def fetch_job_log(session, owner, repo, job_id):
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
    resp = session.get(url, allow_redirects=True, timeout=60)
    resp.raise_for_status()
    return resp.text


def parse_durations(log_text):
    """Return list of (test_id, seconds) parsed from the log's durations block."""
    entries = []
    in_block = False
    for line in log_text.splitlines():
        if DURATION_HEADER.search(line):
            in_block = True
            continue
        if not in_block:
            continue
        m = DURATION_LINE.search(line)
        if m:
            if m.group("phase") == "call":
                entries.append((m.group("test"), float(m.group("seconds"))))
            continue
        # Block ends at the pytest summary line, e.g. "==== 42 passed in ... ===="
        if "=" in line and ("passed" in line or "failed" in line or "error" in line):
            in_block = False
    return entries


def group_key(test_id, group_by):
    if group_by == "file":
        return test_id.split("::", 1)[0]
    return test_id


def run_durations_mode(runs, args):
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {args.token}",
            "Accept": "application/vnd.github+json",
        }
    )

    jobs = list(collect_smoke_jobs(runs, args.job_filter, args.runs))
    if not jobs:
        print(f"No jobs matched filter '{args.job_filter}' in the last {args.runs} runs.")
        return

    print(f"Analysing {len(jobs)} job(s) matching '{args.job_filter}'...")

    per_test = defaultdict(list)
    failures = 0

    def worker(job):
        try:
            log = fetch_job_log(session, args.owner, args.repo, job.id)
            return job.id, parse_durations(log)
        except Exception as exc:  # noqa: BLE001
            return job.id, exc

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(worker, job) for _, job in jobs]
        for fut in as_completed(futures):
            job_id, result = fut.result()
            if isinstance(result, Exception):
                failures += 1
                print(f"  ! failed to fetch log for job {job_id}: {result}")
                continue
            for test_id, seconds in result:
                per_test[group_key(test_id, args.group_by)].append(seconds)

    if failures:
        print(f"({failures} job logs could not be fetched)")

    aggregated = [(key, statistics.mean(samples), max(samples), len(samples)) for key, samples in per_test.items()]
    aggregated.sort(key=lambda row: row[1], reverse=True)

    print()
    print(f"Top {args.top} slowest by mean call duration (grouped by {args.group_by}):")
    print(f"{'mean':>8}  {'max':>8}  {'n':>4}  test")
    for key, mean_s, max_s, n in aggregated[: args.top]:
        print(f"{mean_s:8.2f}  {max_s:8.2f}  {n:4d}  {key}")


def main():
    args = parse_args()
    g = get_github_handle(args.token)
    if g is None:
        print("Failed to authenticate to GitHub")
        raise SystemExit(1)
    try:
        repo = get_github_repo(args.owner, args.repo, g)
        branch = args.branch or None
        runs = get_workflow_runs(repo, args.workflow, branch=branch)
        if not runs:
            print("No workflow runs found.")
            raise SystemExit(1)

        recent = filter_recent_runs(runs, args.since_days)
        if not recent:
            print(f"No runs in the last {args.since_days} days.")
            raise SystemExit(1)
        print(f"Found {len(recent)} run(s) in the last {args.since_days} days.")

        if args.mode == "jobs":
            run_jobs_mode(recent, args.duration)
        else:
            run_durations_mode(recent, args)
    finally:
        g.close()


if __name__ == "__main__":
    main()
