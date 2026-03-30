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
    orig_shortcode_row = ""
    other_rows = []

    for line in data_lines:
        if not line.strip():
            continue
        if "{{< nic-version >}}" in line:
            orig_shortcode_row = line
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

            # Freeze the current live row as a historical entry with literal values
            other_rows.append(
                f"| {current_nic_version} | {current_nap_waf} | {current_config_mgr} | {current_enforcer} |"
            )
            shortcode_row_found = True
        else:
            other_rows.append(line)

    if not shortcode_row_found:
        print("ERROR: Could not find shortcode row in NAP table")
        return False

    # Preserve the original shortcode row formatting/whitespace.
    # Only update the R-number prefix (e.g. "36+") if it changed.
    new_shortcode_row = orig_shortcode_row
    if "+" in nap_waf_version:
        new_prefix = nap_waf_version.split("+")[0]
        prefix_match = re.search(r"(\d+)\+", orig_shortcode_row)
        if prefix_match:
            old_prefix = prefix_match.group(1)
            if old_prefix != new_prefix:
                new_shortcode_row = orig_shortcode_row.replace(old_prefix + "+", new_prefix + "+", 1)

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


def parse_nginx_version(version_str):
    """Parse "OSS_VERSION / PLUS_VERSION" (e.g. "1.29.7 / R36 P3") into parts."""
    if " / " in version_str:
        parts = version_str.split(" / ")
        return parts[0].strip(), parts[1].strip()
    return version_str.strip(), None


def update_compat_table(md, k8s_new, nginx_new, ic_version, docs_root):
    """Update the NIC/K8s compatibility table in the nic-k8s.md include file.

    Reads shortcode files to get current versions, updates the shortcode row
    with new K8s and NGINX versions.  On a major/minor release the previous
    row is frozen as a historical entry and expired rows are pruned.
    """
    docs = Path(docs_root)
    sc_dir = docs / "layouts" / "shortcodes"
    helm = shortcode_ver(sc_dir / "nic-helm-version.html")
    oper = shortcode_ver(sc_dir / "nic-operator-version.html")
    main = shortcode_ver(sc_dir / "nic-version.html")

    releases = github_release_dates()
    main_eol = plus2y(releases.get(main, datetime.now())).strftime("%b %d, %Y")

    pat = r"(\{\{[<%]\s*(?:bootstrap-)?table[^>%]*[>%]\}\}\n)(.*?)(\n\{\{[<%]\s*/(?:bootstrap-)?table\s*[>%]\}\})"
    m = re.search(pat, md, re.S)
    if not m:
        sys.exit("table shortcode not found in compatibility table file")
    open_tag, tbl_txt, close_tag = m.groups()

    rows = tbl_txt.rstrip("\n").split("\n")
    header, sep, body = rows[0], rows[1], rows[2:]

    sc_idx = next(i for i, r in enumerate(body) if "{{<" in r or "{{%" in r)
    sc_cols = [c.strip() for c in body[sc_idx].split("|")[1:-1]]

    orig_k8s, orig_nginx = sc_cols[1], sc_cols[4]

    # Update the shortcode row in-place to preserve column formatting/whitespace
    new_sc_row = body[sc_idx]
    if orig_k8s != k8s_new:
        new_sc_row = new_sc_row.replace(orig_k8s, k8s_new, 1)
    if orig_nginx != nginx_new:
        new_sc_row = new_sc_row.replace(orig_nginx, nginx_new, 1)

    patch = is_patch_release(ic_version, main)
    prev_row = f"| {main} | {orig_k8s} | {helm} | {oper} | {orig_nginx} | {main_eol} |"

    now = datetime.now()
    new_body, prev_seen = [], False
    expired_rows = []
    for r in body:
        if "{{<" in r or "{{%" in r or not r.strip():
            continue
        cols = [c.strip() for c in r.split("|")[1:-1]]
        if not cols:
            continue
        if cols[0] == main:
            if not patch:
                new_body.append(prev_row)
                prev_seen = True
            continue
        try:
            eol_date = datetime.strptime(cols[5], "%b %d, %Y")
            if now > eol_date:
                expired_rows.append((eol_date, r))
                continue
        except Exception:
            pass
        new_body.append(r)

    if not prev_seen and not patch:
        new_body.insert(0, prev_row)

    # Keep the most recently expired row as a migration reference
    if expired_rows:
        expired_rows.sort(key=lambda x: x[0], reverse=True)
        new_body.append(expired_rows[0][1])

    final_tbl = "\n".join([header, sep, new_sc_row] + new_body)
    updated_md = re.sub(pat, open_tag + final_tbl + close_tag, md, count=1, flags=re.S)
    return updated_md


def update_nginx_prose(md, nginx_new):
    """Update NGINX version references in technical-specifications.md prose.

    Targets the "_All images include NGINX X.Y.Z._" text, base image tags
    like ``nginx:X.Y.Z-alpine``, and "NGINX Plus images include NGINX Plus RXX PY."
    Does NOT modify any table shortcode blocks.
    """
    new_oss, new_plus = parse_nginx_version(nginx_new)

    # NGINX OSS: "_All images include NGINX X.Y.Z._" and base images "nginx:X.Y.Z"
    if new_oss:
        oss_match = re.search(r"All images include NGINX (\d+\.\d+\.\d+)", md)
        if oss_match:
            current_oss = oss_match.group(1)
            if current_oss != new_oss:
                md = re.sub(r"\b" + re.escape(current_oss) + r"\b", new_oss, md)

    # NGINX Plus: "NGINX Plus images include NGINX Plus RXX" or "RXX PY"
    if new_plus:
        plus_match = re.search(r"NGINX Plus images include NGINX Plus (R\d+(?:\s+P\d+)?)", md)
        if plus_match:
            current_plus = plus_match.group(1)
            if current_plus != new_plus:
                md = re.sub(r"\b" + re.escape(current_plus) + r"\b", new_plus, md)

    return md


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

    # --- 1. Update the NIC/K8s compatibility table (nic-k8s.md include file) ---
    # The compatibility table lives in a separate include file, not in
    # technical-specifications.md itself.  Targeting the wrong file would corrupt
    # the NGINX Plus images table that appears first in technical-specifications.md.
    nic_k8s = Path(args.docs_root) / "content" / "includes" / "nic" / "compatibility-tables" / "nic-k8s.md"
    if not nic_k8s.exists():
        sys.exit(f"ERROR: Compatibility table file not found: {nic_k8s}")
    try:
        if args.verbose:
            print(f"Updating compatibility table in {nic_k8s}...")
        nic_k8s.write_text(
            update_compat_table(
                nic_k8s.read_text(encoding="utf-8"),
                args.k8s_versions,
                args.nginx_version,
                args.ic_version,
                args.docs_root,
            ),
            encoding="utf-8",
        )
        print("updated", nic_k8s)
    except Exception as e:
        sys.exit(f"ERROR: Failed to update compatibility table: {e}")

    # --- 2. Update NGINX version prose in technical-specifications.md ---
    tech = Path(args.docs_root) / "content" / "nic" / "technical-specifications.md"
    if not tech.exists():
        sys.exit(f"ERROR: Technical specifications file not found: {tech}")
    try:
        if args.verbose:
            print(f"Updating NGINX version prose in {tech}...")
        tech.write_text(
            update_nginx_prose(
                tech.read_text(encoding="utf-8"),
                args.nginx_version,
            ),
            encoding="utf-8",
        )
        print("updated", tech)
    except Exception as e:
        sys.exit(f"ERROR: Failed to update technical specifications prose: {e}")

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
