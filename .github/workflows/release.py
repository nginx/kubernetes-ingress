import re
import json
import sys

# Keywords and their categories for grouping
KEYWORD_CATEGORIES = {
    "CHANGES": "Miscellaneous",
    "FEATURES": "Enhancements",
    "BUGFIXES": "Bug Fixes",
    "IMPROVEMENTS": "Enhancements",
    "HELM CHART": "Miscellaneous",
    "UPGRADE": "Miscellaneous"
}

def initialize_categories():
    """
    Initialize an empty dictionary for each category.
    Returns:
        dict: A dictionary with categories as keys and empty lists as values.
    """
    categories = {}
    for category in set(KEYWORD_CATEGORIES.values()):
        categories[category] = []
    return categories

def parse_log_file(file_path):
    """
    Parse the changelog file and categorize pull requests based on headings.
    Args:
        file_path (str): Path to the markdown file.
    Returns:
        dict: Parsed and categorized pull requests.
    """
    categorized_data = initialize_categories()
    current_category = None  # Tracks the active category (e.g., "Enhancements" or "Bug Fixes")
    
    with open(file_path, "r") as log_file:
        for line in log_file:
            line = line.strip()
            
            # Detect category headings (CHANGES, FEATURES, etc.)
            heading_match = re.match(r"^(CHANGES|FEATURES|BUGFIXES|IMPROVEMENTS|HELM CHART|UPGRADE):?$", line, re.IGNORECASE)
            if heading_match:
                # Map the keyword to a category
                keyword = heading_match.group(1).upper()
                current_category = KEYWORD_CATEGORIES.get(keyword)
                continue
            
            # Match pull request links, e.g., `[1373](https://github.com/nginx/kubernetes-ingress/pull/1373)`
            pr_match = re.findall(r"\[(\d+)\]\(https://github\.com/[^/]+/[^/]+/pull/(\d+)\)", line)
            if pr_match and current_category:
                for match in pr_match:
                    pr_number = match[0]
                    pr_id = match[1]
                    pull_request = {
                        "title": f"PR #{pr_number}",
                        "number": int(pr_id),
                        "url": f"https://github.com/nginx/kubernetes-ingress/pull/{pr_id}"
                    }
                    categorized_data[current_category].append(pull_request)
    
    return categorized_data

def save_to_json(data, output_file):
    """
    Save the categorized data to a JSON file.
    Args:
        data (dict): The categorized data to save.
        output_file (str): Path to the output JSON file.
    """
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=4)

def main():
    """
    Main function to parse a markdown file and generate categorized JSON output.
    """
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_changelog_file>")
        sys.exit(1)
    log_file = sys.argv[1]
    output_file = "release_notes.json"
    print(f"Parsing changelog file: {log_file}...")
    
    try:
        categorized_data = parse_log_file(log_file)
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found!")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred - {e}")
        sys.exit(1)
    
    print("Saving results to JSON...")
    save_to_json(categorized_data, output_file)
    print(f"Release notes saved to '{output_file}'!")

if __name__ == "__main__":
    main()