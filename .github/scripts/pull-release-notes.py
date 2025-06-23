#!/usr/bin/env python

import argparse
import os
import re
import sys

from github import Auth, Github
from jinja2 import Environment, FileSystemLoader

# parse args
parser = argparse.ArgumentParser()
parser.add_argument("nic_version", help="NGINX Ingress Controller version")
parser.add_argument("helm_chart_version", help="NGINX Ingress Controller Helm chart version")
parser.add_argument("k8s_versions", help="Kubernetes versions")
parser.add_argument("release_date", help="Release date")
args = parser.parse_args()
NIC_VERSION = args.nic_version
HELM_CHART_VERSION = args.helm_chart_version
K8S_VERSIONS = args.k8s_versions
RELEASE_DATE = args.release_date

# Set up Jinja2 environment
template_dir = os.path.dirname(os.path.abspath(__file__))
env = Environment(loader=FileSystemLoader(template_dir))
template = env.get_template("release-notes.j2")

# Set github environment
github_org = os.getenv("GITHUB_ORG", "nginx")
github_repo = os.getenv("GITHUB_REPO", "kubernetes-ingress")
token = os.environ.get("GITHUB_TOKEN")
docker_pr_strings = ["Docker image update", "docker group", "docker-images group", "in /build"]
golang_pr_strings = ["go group", "go_modules group"]


def parse_sections(markdown: str):
    sections = {}
    section_name = None
    for line in markdown.splitlines():
        # Check if the line starts with a section header
        # Section headers start with "### "
        # We will use the section header as the key in the sections dictionary
        # and the lines below it as the values (until the next section header)
        line = line.strip()
        if not line:
            continue  # skip empty lines
        if line.startswith("### "):
            section_name = line[3:].strip()
            sections[section_name] = []
        # If the line starts with "* " and contains "made their first contribution",
        # we will skip it as it is not a change but a contributor note
        elif section_name and line.startswith("* ") and "made their first contribution" in line:
            continue
        # Check if the line starts with "* " or "- "
        # If it does, we will add the line to the current section
        # We will also strip the "* " or "- " from the beginning of the line
        elif section_name and line.strip().startswith("* "):
            sections[section_name].append(line.strip()[2:].strip())
    return sections


def format_pr_groups(prs, title):
    # join the PR's into a comma, space separated string
    comma_sep_prs = "".join([f"{dep['details']}, " for dep in prs])

    # strip the last comma and space, and add the first PR title
    trimmed_comma_sep_prs = f"{comma_sep_prs.rstrip(', ')} {title}"

    # split the string by the last comma and join with an ampersand
    split_result = trimmed_comma_sep_prs.rsplit(",", 1)
    return " &".join(split_result)


# Get release text
def get_github_release(version, github_org, github_repo, token):
    if token == "":
        print("ERROR: GITHUB token variable cannot be empty")
        return None
    auth = Auth.Token(token)
    g = Github(auth=auth)
    repo = g.get_organization(github_org).get_repo(github_repo)
    release = None
    releases = repo.get_releases()
    for rel in releases:
        if rel.tag_name == f"v{version}":
            release = rel
            break
    g.close()
    if release is not None:
        return release.body
    print(f"ERROR: Release v{NIC_VERSION} not found in {github_org}/{github_repo}.")
    return None


## Main section of script

release_body = get_github_release(NIC_VERSION, github_org, github_repo, token)
if release_body is None:
    print("ERROR: Cannot get release from Github.  Exiting...")
    sys.exit(1)

# Parse the release body to extract sections
sections = parse_sections(release_body or "")

# Prepare the data for rendering
# We will create a dictionary with the categories and their changes
# Also, we will handle dependencies separately for Go and Docker images
# and format them accordingly
catagories = {}
dependencies_title = ""
for title, changes in sections.items():
    if any(x in title for x in ["Other Changes", "Documentation", "Maintenance", "Tests"]):
        # These sections do not show up in the docs release notes
        continue
    parsed_changes = []
    go_dependencies = []
    docker_dependencies = []
    for line in changes:
        change = re.search("^(.*) by @.* in (.*)$", line)
        change_title = change.group(1)
        pr_link = change.group(2)
        pr_number = re.search(r"^.*pull/(\d+)$", pr_link).group(1)
        pr = {"details": f"[{pr_number}]({pr_link})", "title": change_title.capitalize()}
        if "Dependencies" in title:
            # save section title for later use as lookup key to categories dict
            dependencies_title = title

            # Append Golang changes in to the go_dependencies list for later processing
            if any(str in change_title for str in golang_pr_strings):
                go_dependencies.append(pr)
            # Append Docker changes in to the docker_dependencies list for later processing
            elif any(str in change_title for str in docker_pr_strings):
                docker_dependencies.append(pr)
            # Treat this change like any other ungrouped change
            else:
                parsed_changes.append(f"{pr['details']} {pr['title']}")
        else:
            parsed_changes.append(f"{pr['details']} {pr['title']}")

    catagories[title] = parsed_changes

# Add grouped dependencies to the Dependencies category
catagories[dependencies_title].append(format_pr_groups(docker_dependencies, "Bump Docker dependencies"))
catagories[dependencies_title].append(format_pr_groups(go_dependencies, "Bump Go dependencies"))
catagories[dependencies_title].reverse()

# Populates the data needed for rendering the template
# The data will be passed to the Jinja2 template for rendering
data = {
    "version": NIC_VERSION,
    "release_date": RELEASE_DATE,
    "sections": catagories,
    "HELM_CHART_VERSION": HELM_CHART_VERSION,
    "K8S_VERSIONS": K8S_VERSIONS,
}

# Render with Jinja2
print(template.render(**data))
