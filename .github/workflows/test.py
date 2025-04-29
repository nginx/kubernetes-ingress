import os

from yaml import dump, load

try:
    from yaml import CDumper as Dumper
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Dumper, Loader

# Authentication is defined via github.Auth
from github import Auth, Github

# Constants
nic_repo = "nginx/kubernetes-ingress"
release_yaml = ".github/release.yml"

# Authentication using personal access token
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    print("Error: GITHUB_TOKEN not set")
    exit(1)

# using an access token
auth = Auth.Token(GITHUB_TOKEN)


def paginated_list_contains(list, search_string):
    for item in list:
        if search_string in item.full_name:
            return True
    return False


def get_pull_requests(client, repo_name):
    repo = client.get_repo(repo_name)
    pull_requests = repo.get_pulls(state="open", sort="created", base="main")
    return pull_requests


def main():
    client = Github(auth=auth)

    if paginated_list_contains(client.get_user().get_repos(), nic_repo):
        print(f"User has access to {nic_repo}")
    else:
        print(f"User does not have access to {nic_repo}")

    pull_requests = get_pull_requests(client, nic_repo)

    with open(release_yaml) as file:
        content = file.read()
        parsed_yaml = load(content, Loader=Loader)

        # Loop through the parsed YAML and print the categories and related PRs
        for category in parsed_yaml["changelog"]["categories"]:
            print(f"{category['title']}")
            for label in category["labels"]:
                # Loop through the pull requests and check if they have the label for this category
                for pr in pull_requests:
                    for pr_label in pr.labels:
                        if label in pr_label.name:
                            print(f"    PR: {pr.title} - {pr.html_url} - {pr_label.name}")

    client.close()


if __name__ == "__main__":
    main()
