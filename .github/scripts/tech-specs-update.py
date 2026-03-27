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


def update_nap_table(
    table_file,
    nic_version,
    nap_waf_version,
    config_manager_version,
    enforcer_version,
    docs_root,
):
    """
    Update NAP compatibility table.
    If patch release: skip table row changes (shortcodes are updated separately).
    If major/minor release: freeze the current shortcode row as a historical entry
    and write a fresh shortcode row for the new release.
    """
    if not table_file.exists():
        print(f"ERROR: NAP compatibility table file not found: {table_file}")
        return False

    docs = Path(docs_root)
    sc_dir = docs / "layouts" / "shortcodes"
    current_nic_version = shortcode_ver(sc_dir / "nic-version.html")

    patch = is_patch_release(nic_version, current_nic_version)

    if patch:
        print(
            f"INFO: Patch release detected ({current_nic_version} -> {nic_version}), "
            "shortcodes will be updated automatically, skipping NAP table row changes"
        )
        return True

    print(
        f"INFO: Major/minor release detected ({current_nic_version} -> {nic_version}), "
        "updating NAP compatibility table"
    )

    content = table_file.read_text(encoding="utf-8")

    # Match both {{< table >}} and {{% bootstrap-table %}} shortcode wrappers
    table_pattern = (
        r"(\{\{[<%]\s*(?:bootstrap-)?table[^>%]*[>%]\}\}\n)(.*?)(\n\{\{[<%]\s*/(?:bootstrap-)?table\s*[>%]\}\})"
    )
    match = re.search(table_pattern, content, re.DOTALL)

    if not match:
        print("ERROR: Could not find table shortcode in the NAP compatibility file")
        return False

    table_start, table_content, table_end = match.groups()

    lines = table_content.strip().split("\n")

    # Locate the header row (contains "NIC Version" or "NAP-WAF Version")
    header_line = separator_line = None
    data_lines = []
    for i, line in enumerate(lines):
        if "|" in line and ("NIC Version" in line or "NAP-WAF Version" in line):
            header_line = line
            if i + 1 < len(lines):
                separator_line = lines[i + 1]
            data_lines = lines[i + 2 :]
            break

    if not header_line or not separator_line:
        print("ERROR: Could not find table header row in NAP compatibility file")
        return False

    # Find the live shortcode row and snapshot its current versions
    shortcode_row_found = False
    other_rows = []

    for line in data_lines:
        line = line.strip()
        if not line:
            continue
        if "{{< nic-version >}}" in line:
            cols = [c.strip() for c in line.split("|")[1:-1]]
            if len(cols) < 4:
                print("ERROR: Unexpected column count in NAP shortcode row")
                return False

            # Resolve the NAP-WAF column (may contain shortcodes or literal version)
            nap_waf_col = cols[1]
            if "+{{< appprotect-compiler-version" in nap_waf_col:
                plus_part = nap_waf_col.split("+")[0]
                compiler_ver = shortcode_ver(sc_dir / "appprotect-compiler-version.html")
                current_nap_waf = f"{plus_part}+{compiler_ver}"
            elif "{{< nic-waf-version >}}" in nap_waf_col:
                current_nap_waf = shortcode_ver(sc_dir / "nic-waf-version.html")
            else:
                current_nap_waf = nap_waf_col

            # Resolve config manager and enforcer (may use shortcodes)
            def resolve_col(col):
                if "{{< nic-waf-release-version >}}" in col:
                    return shortcode_ver(sc_dir / "nic-waf-release-version.html")
                return col

            current_config_mgr = resolve_col(cols[2])
            current_enforcer = resolve_col(cols[3])

            other_rows.append(
                f"| {current_nic_version} | {current_nap_waf} | {current_config_mgr} | {current_enforcer} |"
            )
            shortcode_row_found = True
        else:
            other_rows.append(line)

    if not shortcode_row_found:
        print("ERROR: Could not find shortcode row in NAP table")
        return False

    # Build the new live shortcode row with the incoming NAP versions
    new_shortcode_row = (
        f"| {{{{< nic-version >}}}} | {nap_waf_version} " f"| {config_manager_version} | {enforcer_version} |"
    )

    new_table_content = "\n".join([header_line, separator_line, new_shortcode_row] + other_rows)
    new_content = re.sub(
        table_pattern,
        table_start + new_table_content + table_end,
        content,
        count=1,
        flags=re.DOTALL,
    )

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

    # Parse the new NGINX version into OSS and Plus parts.
    # Format: "OSS_VERSION / PLUS_VERSION" (e.g. "1.29.7 / R36 P3")
    def parse_nginx_version(version_str):
        if " / " in version_str:
            parts = version_str.split(" / ")
            return parts[0].strip(), parts[1].strip()
        return version_str.strip(), None

    new_oss, new_plus = parse_nginx_version(nginx_new)

    # --- 1. Replace the combined version string from the compatibility table ---
    if orig_nginx and orig_nginx != nginx_new:
        old_oss_tbl, old_plus_tbl = parse_nginx_version(orig_nginx)

        updated_md = re.sub(r"\b" + re.escape(orig_nginx) + r"\b", nginx_new, updated_md)
        if old_oss_tbl and new_oss and old_oss_tbl != new_oss:
            updated_md = re.sub(r"\b" + re.escape(old_oss_tbl) + r"\b", new_oss, updated_md)
        if old_plus_tbl and new_plus and old_plus_tbl != new_plus:
            updated_md = re.sub(r"\b" + re.escape(old_plus_tbl) + r"\b", new_plus, updated_md)

    # --- 2. Update NGINX version references in prose and image tables ---
    # The compatibility table may carry a different version string from the prose
    # sections (e.g. "Images with NGINX" and "Images with NGINX Plus"), so we
    # extract the current versions directly from the prose and replace them.

    # NGINX OSS: "_All images include NGINX X.Y.Z._" and base images "nginx:X.Y.Z"
    if new_oss:
        oss_match = re.search(r"All images include NGINX (\d+\.\d+\.\d+)", updated_md)
        if oss_match:
            current_oss = oss_match.group(1)
            if current_oss != new_oss:
                updated_md = re.sub(r"\b" + re.escape(current_oss) + r"\b", new_oss, updated_md)

    # NGINX Plus: "NGINX Plus images include NGINX Plus RXX" or "RXX PY"
    if new_plus:
        plus_match = re.search(r"NGINX Plus images include NGINX Plus (R\d+(?:\s+P\d+)?)", updated_md)
        if plus_match:
            current_plus = plus_match.group(1)
            if current_plus != new_plus:
                updated_md = re.sub(r"\b" + re.escape(current_plus) + r"\b", new_plus, updated_md)

    return updated_md


def main():
    parser = argparse.ArgumentParser(
        description="Update NIC tech specs table for a new release.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update tech specs
  %(prog)s "5.2.0" "1.27-1.33" "1.25.3" "/path/to/docs"
        """,
    )
    parser.add_argument("ic_version", help="New NGINX Ingress Controller version")
    parser.add_argument("k8s_versions", help="New Kubernetes versions string")
    parser.add_argument("nginx_version", help="New NGINX/NGINX Plus version string")
    parser.add_argument("docs_root", help="Path to documentation root directory")
    parser.add_argument(
        "nap_waf_version",
        nargs="?",
        help="NAP-WAF version (e.g., '36+5.600') - optional",
    )
    parser.add_argument(
        "config_manager_version",
        nargs="?",
        help="NAP Config Manager version - optional",
    )
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
            original_content,
            args.k8s_versions,
            args.nginx_version,
            args.ic_version,
            args.docs_root,
        )

        if args.verbose:
            print("Writing updated technical specifications...")
        tech.write_text(updated_content, encoding="utf-8")
        print("updated", tech)
    except Exception as e:
        sys.exit(f"ERROR: Failed to update technical specifications: {e}")

    # Update NAP compatibility table if WAF version provided
    if args.nap_waf_version:
        nap_table = Path(args.docs_root) / "content" / "includes" / "nic" / "compatibility-tables" / "nic-nap.md"
        if not nap_table.exists():
            print(f"WARNING: NAP compatibility table not found at {nap_table}, skipping NAP table update")
        else:
            print(f"INFO: Updating NAP compatibility table at {nap_table}")
            try:
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
                sys.exit(f"ERROR: Exception while updating NAP table: {e}")
    else:
        print("INFO: No NAP WAF version provided, skipping NAP table update")


if __name__ == "__main__":
    main()
