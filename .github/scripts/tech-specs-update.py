#!/usr/bin/env python3
import argparse
import os
import re
import sys
import warnings
from datetime import datetime, timedelta
from pathlib import Path

from github import Auth, Github

# Suppress urllib3 warnings about LibreSSL
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL 1.1.1+")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="github")


def github_release_dates():
    """Fetch NIC release dates from GitHub API."""
    tok = os.getenv("GITHUB_TOKEN")
    if not tok:
        sys.exit("GITHUB_TOKEN env-var missing")
    auth = Auth.Token(tok)
    repo = Github(auth=auth).get_repo("nginx/kubernetes-ingress")
    return {r.tag_name.lstrip("v"): r.created_at for r in repo.get_releases()}


def shortcode_ver(path: Path):
    """Extract version from shortcode file."""
    if not path.exists():
        return "?"
    txt = path.read_text(encoding="utf-8")
    m = re.search(r"(\d+\.\d+(\.\d+)?([^\s<]*)?)", txt)
    return m.group(1) if m else txt.strip()


def plus2y(dt):
    """Add 2 years to the previous NIC release."""
    return dt + timedelta(days=730)


def is_patch_release(new_version, old_version):
    """Return True if only the patch number changed."""

    def parse(v):
        parts = v.split(".")
        return tuple(int(x) if x.isdigit() else 0 for x in (parts + ["0", "0"])[:3])

    n_major, n_minor, n_patch = parse(new_version)
    o_major, o_minor, o_patch = parse(old_version)
    return n_major == o_major and n_minor == o_minor and n_patch != o_patch


def update_nap_table(table_file, nic_version, nap_waf_version, config_manager_version, enforcer_version, docs_root):
    """
    Update NAP compatibility table similar to tech specs table.
    If patch release: just update shortcodes (no table changes needed)
    If major/minor release: move current shortcode row to historical entry and update shortcodes
    """
    if not table_file.exists():
        print(f"ERROR: NAP compatibility table file not found: {table_file}")
        return False

    # Get current NIC version from shortcode to determine if patch release
    docs = Path(docs_root)
    sc_dir = docs / "layouts" / "shortcodes"
    current_nic_version = shortcode_ver(sc_dir / "nic-version.html")

    # Check if this is a patch release
    patch = is_patch_release(nic_version, current_nic_version)

    if patch:
        print(
            f"INFO: Patch release detected ({current_nic_version} -> {nic_version}), shortcodes will be updated automatically"
        )
        return True

    print(
        f"INFO: Major/minor release detected ({current_nic_version} -> {nic_version}), updating NAP compatibility table"
    )

    content = table_file.read_text(encoding="utf-8")

    # Find the table pattern - support both old bootstrap-table and new table formats
    table_pattern = r"(\{\{<\s*(bootstrap-)?table[^>]*>\}\}\n)(.*?)(\n\{\{[<%]\s*/(bootstrap-)?table\s*[%>]\}\})"
    match = re.search(table_pattern, content, re.DOTALL)

    if not match:
        print("ERROR: Could not find table or bootstrap-table shortcode in the file")
        return False

    table_start, bootstrap_prefix, table_content, table_end, bootstrap_suffix = match.groups()

    # Convert old bootstrap-table format to new table format
    if bootstrap_prefix or bootstrap_suffix:
        print("INFO: Converting old bootstrap-table format to new table format")
        table_start = table_start.replace("bootstrap-table", "table")
        table_end = table_end.replace("/bootstrap-table", "/table").replace("{%", "{{<").replace("%}", ">}}")

    # Split table into lines
    lines = table_content.strip().split("\n")

    # Find header and separator
    header_line = None
    separator_line = None
    data_lines = []

    for i, line in enumerate(lines):
        if "|" in line:
            if "NIC Version" in line or "NAP-WAF Version" in line:
                header_line = line
                if i + 1 < len(lines):
                    separator_line = lines[i + 1]
                data_lines = lines[i + 2 :]
                break

    if not header_line or not separator_line:
        print("ERROR: Could not find table header")
        return False

    # Find the shortcode row and get current NAP versions from it
    shortcode_row_found = False
    current_nap_waf = None
    current_config_mgr = None
    current_enforcer = None
    other_rows = []

    for line in data_lines:
        line = line.strip()
        if not line:
            continue
        if "{{< nic-version >}}" in line:
            # Extract current NAP versions from shortcode row
            cols = [col.strip() for col in line.split("|")[1:-1]]
            if len(cols) >= 4:
                # Handle mixed format like "35+{{< appprotect-compiler-version>}}"
                nap_waf_col = cols[1].strip()
                if "+{{< appprotect-compiler-version" in nap_waf_col:
                    # Extract the NGINX Plus version part and get compiler version from shortcode
                    plus_version = nap_waf_col.split("+")[0]
                    compiler_version = shortcode_ver(sc_dir / "appprotect-compiler-version.html")
                    current_nap_waf = f"{plus_version}+{compiler_version}"
                elif "{{< nic-waf-version >}}" in nap_waf_col:
                    current_nap_waf = shortcode_ver(sc_dir / "nic-waf-version.html")
                else:
                    current_nap_waf = nap_waf_col

                # Handle config manager and enforcer versions
                current_config_mgr = cols[2].replace("{{< nic-waf-release-version >}}", "").strip()
                current_enforcer = cols[3].replace("{{< nic-waf-release-version >}}", "").strip()

                if "{{< nic-waf-release-version >}}" in cols[2]:
                    current_config_mgr = shortcode_ver(sc_dir / "nic-waf-release-version.html")
                if "{{< nic-waf-release-version >}}" in cols[3]:
                    current_enforcer = shortcode_ver(sc_dir / "nic-waf-release-version.html")

                # Create historical entry with current NIC version and current NAP versions
                historical_entry = (
                    f"| {current_nic_version} | {current_nap_waf} | {current_config_mgr} | {current_enforcer} |"
                )
                other_rows.append(historical_entry)
                shortcode_row_found = True
        else:
            other_rows.append(line)

    if not shortcode_row_found:
        print("ERROR: Could not find shortcode row in NAP table")
        return False

    # Create new shortcode row with updated versions
    new_shortcode_row = f"| {{{{< nic-version >}}}} | {{{{< nic-waf-version >}}}} | {{{{< nic-waf-release-version >}}}} | {{{{< nic-waf-release-version >}}}} |"

    # Rebuild the table
    new_table_lines = [header_line, separator_line, new_shortcode_row] + other_rows
    new_table_content = "\n".join(new_table_lines)
    new_content = content.replace(match.group(0), table_start + new_table_content + table_end)

    table_file.write_text(new_content, encoding="utf-8")
    return True


def update(md, k8s_new, nginx_new, ic_version, docs_root):
    """Update the NIC tech specs table in the docs folder
       Read the shortcode files to get the current versions
         and update the table with the new versions.
         If the new version is a patch release, do not move the previous
            row down, just update the versions in the current row.
         If the new version is not a patch release, move the previous row down
            and insert the new row at the top of the table.
        Removes rows that are past their EOS date.
    ."""
    docs = Path(docs_root)
    sc_dir = docs / "layouts" / "shortcodes"
    helm = shortcode_ver(sc_dir / "nic-helm-version.html")
    oper = shortcode_ver(sc_dir / "nic-operator-version.html")
    main = shortcode_ver(sc_dir / "nic-version.html")

    releases = github_release_dates()
    main_eol = plus2y(releases.get(main, datetime.now())).strftime("%b %d, %Y")

    pat = r"(\{\{<\s*table[^>]*>\}\}\n)(.*?)(\n\{\{<\s*/table\s*>\}\})"
    m = re.search(pat, md, re.S)
    if not m:
        sys.exit("table shortcode not found")
    open_tag, tbl_txt, close_tag = m.groups()

    rows = tbl_txt.rstrip("\n").split("\n")
    header, sep, body = rows[0], rows[1], rows[2:]

    sc_idx = next(i for i, r in enumerate(body) if "{{<" in r)
    sc_cols = [c.strip() for c in body[sc_idx].split("|")[1:-1]]

    orig_k8s, orig_nginx = sc_cols[1], sc_cols[4]
    sc_cols[1], sc_cols[4] = k8s_new, nginx_new
    new_sc_row = "| " + " | ".join(sc_cols) + " |"

    patch = is_patch_release(ic_version, main)
    prev_row = f"| {main} | {orig_k8s} | {helm} | {oper} | {orig_nginx} | {main_eol} |"

    now = datetime.now()
    new_body, prev_seen = [], False
    for r in body:
        if "{{<" in r or not r.strip():
            continue
        cols = [c.strip() for c in r.split("|")[1:-1]]
        if not cols:
            continue
        # Only move down previous top line if not a patch release
        if cols[0] == main:
            if not patch:
                new_body.append(prev_row)
                prev_seen = True
            continue
        try:
            if now > datetime.strptime(cols[5], "%b %d, %Y"):
                continue
        except Exception:
            pass
        new_body.append(r)

    if not prev_seen and not patch:
        new_body.insert(0, prev_row)

    final_tbl = "\n".join([header, sep, new_sc_row] + new_body)
    updated_md = re.sub(pat, open_tag + final_tbl + close_tag, md, count=1, flags=re.S)

    # Update any references to the previous NGINX versions in the text outside the table
    if orig_nginx and orig_nginx != nginx_new:
        # Parse old and new NGINX versions (format: "OSS_VERSION / PLUS_VERSION")
        def parse_nginx_version(version_str):
            if " / " in version_str:
                parts = version_str.split(" / ")
                return parts[0].strip(), parts[1].strip()
            return version_str.strip(), None

        old_oss, old_plus = parse_nginx_version(orig_nginx)
        new_oss, new_plus = parse_nginx_version(nginx_new)

        # Update OSS version references
        if old_oss and new_oss and old_oss != new_oss:
            updated_md = updated_md.replace(old_oss, new_oss)

        # Update Plus version references
        if old_plus and new_plus and old_plus != new_plus:
            updated_md = updated_md.replace(old_plus, new_plus)

        # Also replace the full version string
        updated_md = updated_md.replace(orig_nginx, nginx_new)

    return updated_md


def main():
    parser = argparse.ArgumentParser(
        description="Update NIC tech specs table for a new release.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update tech specs only
  %(prog)s "5.2.0" "1.27-1.33" "1.25.3" "/path/to/docs"

  # Update tech specs and NAP compatibility table
  %(prog)s "5.2.0" "1.27-1.33" "1.25.3" "/path/to/docs" "35+5.527" "5.9.0" "5.9.0"
        """,
    )
    parser.add_argument("ic_version", help="New NGINX Ingress Controller version")
    parser.add_argument("k8s_versions", help="New Kubernetes versions string")
    parser.add_argument("nginx_version", help="New NGINX/NGINX Plus version string")
    parser.add_argument("docs_root", help="Path to documentation root directory")
    parser.add_argument("nap_waf_version", nargs="?", help="NAP-WAF version (e.g., '36+5.600') - optional")
    parser.add_argument("config_manager_version", nargs="?", help="NAP Config Manager version - optional")
    parser.add_argument("enforcer_version", nargs="?", help="NAP Enforcer version - optional")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Validate inputs
    if not Path(args.docs_root).exists():
        sys.exit(f"ERROR: Documentation root directory not found: {args.docs_root}")

    if args.verbose:
        print(f"Processing release: {args.ic_version}")
        print(f"Kubernetes versions: {args.k8s_versions}")
        print(f"NGINX version: {args.nginx_version}")
        print(f"Documentation root: {args.docs_root}")
        if args.nap_waf_version:
            print(
                f"NAP versions - WAF: {args.nap_waf_version}, Config Manager: {args.config_manager_version}, Enforcer: {args.enforcer_version}"
            )

    # Update tech specs table
    tech = Path(args.docs_root) / "content" / "nic" / "technical-specifications.md"
    if not tech.exists():
        sys.exit(f"ERROR: Technical specifications file not found: {tech}")
    try:
        if args.verbose:
            print("Reading technical specifications file...")
        original_content = tech.read_text(encoding="utf-8")

        if args.verbose:
            print("Updating technical specifications table...")
        updated_content = update(
            original_content, args.k8s_versions, args.nginx_version, args.ic_version, args.docs_root
        )

        if args.verbose:
            print("Writing updated technical specifications...")
        tech.write_text(updated_content, encoding="utf-8")
        print("updated", tech)
    except Exception as e:
        sys.exit(f"ERROR: Failed to update technical specifications: {e}")

    # Update NAP compatibility table if WAF version provided (combined format)
    if args.nap_waf_version:
        print(f"INFO: NAP WAF version provided, looking for compatibility table...")
        nap_table = Path(args.docs_root) / "content" / "includes" / "nic" / "compatibility-tables" / "nic-nap.md"
        print(f"INFO: Checking NAP table path: {nap_table}")

        if not nap_table.exists():
            print(f"WARNING: NAP compatibility table not found: {nap_table}")
            # Try to find NAP table files in the docs repo
            docs_root = Path(args.docs_root)
            nap_files = list(docs_root.rglob("*nap*.md"))
            if nap_files:
                print(f"INFO: Found potential NAP files: {[str(f) for f in nap_files[:5]]}")
            print("Skipping NAP table update")
        else:
            print("INFO: Found NAP compatibility table, updating...")
            try:
                # For the combined format, we use the full WAF version and pass empty strings for the others
                if update_nap_table(
                    nap_table,
                    args.ic_version,
                    args.nap_waf_version,
                    args.config_manager_version or "",
                    args.enforcer_version or "",
                    args.docs_root,
                ):
                    print("updated", nap_table)
                else:
                    print("ERROR: Failed to update NAP table")
                    sys.exit(1)
            except Exception as e:
                print(f"ERROR: Exception while updating NAP table: {e}")
                sys.exit(1)
    else:
        print("INFO: No NAP WAF version provided, skipping NAP table update")


if __name__ == "__main__":
    main()
