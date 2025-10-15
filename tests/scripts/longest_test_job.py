#!/usr/bin/env python3

import argparse

from github import Auth, Github

# parse args
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--token", required=True, help="GitHub access token")
parser.add_argument("-o", "--owner", required=False, default="nginx", help="GitHub repository owner")
parser.add_argument("-r", "--repo", help="GitHub repository name", required=False, default="kubernetes-ingress")
parser.add_argument("-w", "--workflow", help="GitHub Actions workflow name", required=False, default="CI")
parser.add_argument("-b", "--branch", help="GitHub repository branch", required=False, default="main")
parser.add_argument(
    "-d", "--duration", help="Minimum duration of jobs in seconds", required=False, default=900, type=int
)
args = parser.parse_args()
TOKEN = args.token
OWNER = args.owner
REPO = args.repo
BRANCH = args.branch
DURATION = args.duration
WORKFLOW = args.workflow


def get_github_repo(owner, repo, token):
    # Authenticate to GitHub
    auth = Auth.Token(token)
    g = Github(auth=auth)

    # Get the repository
    repository = g.get_repo(f"{owner}/{repo}")
    g.close()  # Close the connection
    return repository


def get_workflow_runs(repo, workflow_name, branch=None):
    workflows = repo.get_workflows()
    for workflow in workflows:
        if workflow.name == workflow_name:
            return workflow.get_runs(branch=branch, status="completed")
    return None


def get_run_branch_jobs(runs):
    results = {}
    for run in runs:
        results[run.id] = run.jobs()
    return results


def get_run_durations(runs):
    results = {}
    for run in runs:
        results[run.id] = run.timing().run_duration_ms / 1000
    return results


def convert_seconds(seconds):
    min, sec = divmod(seconds, 60)
    hour, min = divmod(min, 60)
    return "%d:%02d:%02d" % (hour, min, sec)


r = get_github_repo(OWNER, REPO, TOKEN)

# Get the latest workflow runs
runs = get_workflow_runs(r, WORKFLOW, branch=BRANCH)
if not runs:
    print("No workflow runs found.")
    exit(1)
wj = get_run_branch_jobs(runs)
wd = get_run_durations(runs)
for run_id in sorted(wj.keys()):
    duration = wd.get(run_id)
    print(f"Workflow Run ID: {run_id}, Duration: {convert_seconds(duration)}")
    for job in wj[run_id]:
        job_duration = (job.completed_at - job.started_at).total_seconds()
        if job.status == "completed" and job.conclusion == "success" and job_duration > DURATION:
            print(f"  Job: {job.name}, Duration: {convert_seconds(job_duration)}, URL: {job.html_url}")
