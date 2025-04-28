import os

# Authentication is defined via github.Auth
from github import Auth, Github

# Authentication using personal access token
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    print("Error: GITHUB_TOKEN not set")
    exit(1)

# using an access token
auth = Auth.Token(GITHUB_TOKEN)


def main():
    client = Github(auth=auth)

    # List all repositories available to the token's user
    print("Fetching repositories:")
    for repo in client.get_user().get_repos():
        print(repo.full_name)

    client.close()


if __name__ == "__main__":
    main()
