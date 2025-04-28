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

    # for pr in get_pull_requests(client, nic_repo):
    #     print(f"Pull request #{pr.number} - {pr.title}")
    #     print(f"Created by: {pr.user.login}")
    #     print(f"URL: {pr.html_url}")
    #     print(f"Created at: {pr.created_at}")
    #     print(f"Updated at: {pr.updated_at}")
    #     print(f"State: {pr.state}")
    #     print(f"Labels: {[label.name for label in pr.labels]}")
    #     print("-" * 40)

    client.close()

    with open(release_yaml) as file:
        content = file.read()
        parsed_yaml = load(content, Loader=Loader)
        print(f"Parsed YAML content: {parsed_yaml}")
        for category in parsed_yaml["changelog"]["categories"]:
            print(f"Category: {category['title']}")
            for label in category["labels"]:
                print(f"  Label: {label}")


if __name__ == "__main__":
    main()
