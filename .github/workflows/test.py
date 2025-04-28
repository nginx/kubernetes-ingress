from github import Github

# Authentication using personal access token
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    print("Error: GITHUB_TOKEN not set")
    exit(1)

def main():
    github_client = Github(GITHUB_TOKEN)
    
    # List all repositories available to the token's user
    print("Fetching repositories:")
    for repo in github_client.get_user().get_repos():
        print(repo.full_name)
        
if __name__ == "__main__":
    main()