import argparse
import re

def parse_version(version):
    """Parse the Semantic Version string into major, minor, and patch."""
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"Invalid Semantic Versioning format: {version}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))

def decide_next_version(current_version, release_type):
    """Determine the next version based on the release type (major, minor, patch)."""
    major, minor, patch = parse_version(current_version)

    if release_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif release_type == "minor":
        minor += 1
        patch = 0
    elif release_type == "patch":
        patch += 1
    else:
        raise ValueError(f"Invalid release type: {release_type}")
    
    return f"{major}.{minor}.{patch}"

def main(source_tag, release_branch):
    """Main logic for determining the next version."""



    if "main" in release_branch or "master" in release_branch:
        release_type = "major"
    elif "feature" in release_branch:
        release_type = "minor"
    elif "hotfix" in release_branch or "bugfix" in release_branch:
        release_type = "patch"
    else:
        release_type = "patch"

    next_version = decide_next_version(source_tag, release_type)

    # Write the next version to a file
    with open("next_version.txt", "w") as file:
        file.write(next_version)

    print(f"Next version determined: {next_version}")
    print("Version saved to next_version.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Determine the next version.")
    parser.add_argument("--current-tag", required=True, help="Current source tag (e.g., 1.2.3)")
    parser.add_argument("--release-branch", required=True, help="Release branch (e.g., master, hotfix, feature)")

    args = parser.parse_args()

    # Execute main logic
    main(args.current_tag, args.release_branch)