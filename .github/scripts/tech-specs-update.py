#!/usr/bin/env python3
import argparse
import re
import sys
from datetime import datetime
from pathlib import Path


def shortcode_ver(path: Path):
    """Extract version string from a Hugo shortcode HTML file."""
    if not path.exists():
        return "?"
    txt = path.read_text(encoding="utf-8")
    m = re.search(r"(\d+\.\d+(\.\d+)?([^\s<]*)?)", txt)
    return m.group(1) if m else txt.strip()


def is_minor_or_major(new_version, old_version):
    """Return True if the major.minor part differs between two versions."""

    def major_minor(v):
        parts = v.split(".")
        return f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else v

    return major_minor(new_version) != major_minor(old_version)


def update_nap_table(table_file, nap_waf_version, ic_version, docs_root):
    """
    Update NAP compatibility table.
    On a minor/major release: freeze the current shortcode row as a historical
    entry with literal values, then update the shortcode row's R-number prefix.
    On a patch release or re-run: only update the R-number prefix if changed.
    Shortcode values (compiler version, waf release version) are updated
    separately by docs-shortcode-update.sh.
    """
    if not table_file.exists():
        print(f"ERROR: NAP compatibility table file not found: {table_file}")
        return False

    docs = Path(docs_root)
    sc_dir = docs / "layouts" / "shortcodes"
    current_nic_version = shortcode_ver(sc_dir / "nic-version.html")
    freeze = is_minor_or_major(ic_version, current_nic_version)

    if freeze:
        print(f"INFO: Minor/major release ({current_nic_version} -> {ic_version}), freezing NAP row")
    else:
        print(f"INFO: Patch release or re-run ({current_nic_version} -> {ic_version}), updating NAP table in-place")

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

    # Preserve leading/trailing blank lines inside the table shortcode block
    leading_ws = "\n" if table_content.startswith("\n") else ""
    trailing_ws = "\n" if table_content.endswith("\n") else ""

    lines = table_content.strip().split("\n")

    # Locate the header and separator rows
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

    # Find the live shortcode row; keep all other rows as-is
    shortcode_row_found = False
    orig_shortcode_row = ""
    other_rows = []

    for line in data_lines:
        if not line.strip():
            continue
        if "{{< nic-version >}}" in line:
            orig_shortcode_row = line
            shortcode_row_found = True
        else:
            other_rows.append(line)

    if not shortcode_row_found:
        print("ERROR: Could not find shortcode row in NAP table")
        return False

    # For minor/major releases: resolve current shortcode values and freeze as historical row
    if freeze:
        cols = [c.strip() for c in orig_shortcode_row.split("|")[1:-1]]

        # Resolve NAP-WAF column
        nap_waf_col = cols[1]
        if "+{{< appprotect-compiler-version" in nap_waf_col:
            plus_part = nap_waf_col.split("+")[0]
            compiler_ver = shortcode_ver(sc_dir / "appprotect-compiler-version.html")
            current_nap_waf = f"{plus_part}+{compiler_ver}"
        else:
            current_nap_waf = nap_waf_col

        # Resolve config manager and enforcer
        def resolve_col(col):
            if "{{< nic-waf-release-version >}}" in col:
                return shortcode_ver(sc_dir / "nic-waf-release-version.html")
            return col

        current_config_mgr = resolve_col(cols[2])
        current_enforcer = resolve_col(cols[3])

        # Pad values to match the column widths from the separator row
        sep_cols = [c for c in separator_line.split("|")[1:-1]]
        col_widths = [len(c) for c in sep_cols]
        values = [
            current_nic_version,
            current_nap_waf,
            current_config_mgr,
            current_enforcer,
        ]
        padded = [f" {v.ljust(w - 1)}" if w > len(v) + 1 else f" {v} " for v, w in zip(values, col_widths)]
        frozen_row = "|" + "|".join(padded) + "|"
        other_rows.insert(0, frozen_row)

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

    new_table_content = (
        leading_ws + "\n".join([header_line, separator_line, new_shortcode_row] + other_rows) + trailing_ws
    )
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
    """Parse "OSS_VERSION[/PLUS_VERSION]" (e.g. "1.29.7 / R36 P3" or "1.29.7/R36 P3") into parts."""
    # Allow optional whitespace around the '/' separator so both "1.29.7 / R36 P3"
    # and "1.29.7/R36 P3" (and similar variants) are handled consistently.
    parts = re.split(r"\s*/\s*", version_str.strip(), maxsplit=1)
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    return version_str.strip(), None


def update_compat_table(md, k8s_new, nginx_new, ic_version, docs_root):
    """Update the NIC/K8s compatibility table in the nic-k8s.md include file.

    On a minor/major release: freeze the current shortcode row as a historical
    entry with literal values, then update the shortcode row in-place.
    On a patch release or re-run: only update the shortcode row values.
    Prunes rows past their End of Technical Support date, keeping the most
    recently expired row as a reference.
    """
    docs = Path(docs_root)
    sc_dir = docs / "layouts" / "shortcodes"
    current_nic = shortcode_ver(sc_dir / "nic-version.html")
    freeze = is_minor_or_major(ic_version, current_nic)

    if freeze:
        helm = shortcode_ver(sc_dir / "nic-helm-version.html")
        oper = shortcode_ver(sc_dir / "nic-operator-version.html")
        print(f"INFO: Minor/major release ({current_nic} -> {ic_version}), freezing compat row")
    else:
        print(f"INFO: Patch release or re-run ({current_nic} -> {ic_version}), updating compat table in-place")

    pat = r"(\{\{[<%]\s*(?:bootstrap-)?table[^>%]*[>%]\}\}\n)(.*?)(\n\{\{[<%]\s*/(?:bootstrap-)?table\s*[>%]\}\})"
    m = re.search(pat, md, re.S)
    if not m:
        sys.exit("table shortcode not found in compatibility table file")
    open_tag, tbl_txt, close_tag = m.groups()

    # Preserve leading/trailing blank lines inside the table shortcode block
    leading_ws = "\n" if tbl_txt.startswith("\n") else ""
    trailing_ws = "\n" if tbl_txt.endswith("\n") else ""

    rows = tbl_txt.strip().split("\n")

    # Find the header row and separator row by content, not position.
    header = rows[0]
    sep = None
    sep_idx = None
    for i, r in enumerate(rows[1:], 1):
        cells = [c.strip() for c in r.split("|")[1:-1]]
        if cells and all(re.match(r"-+\s*$", c) for c in cells):
            sep = r
            sep_idx = i
            break

    if sep is None:
        col_count = len(header.split("|")) - 2
        sep = "| " + " | ".join(["---"] * col_count) + " |"
        body = rows[1:]
    else:
        body = rows[sep_idx + 1 :]

    # Find the shortcode row and update K8s + NGINX version values in-place
    sc_idx = next((i for i, r in enumerate(body) if "{{<" in r or "{{%" in r), None)
    if sc_idx is None:
        # Shortcode row may be above separator (corrupted table from previous runs).
        # Search all rows and prepend to body so the rebuild places it correctly.
        for r in rows:
            if ("{{<" in r or "{{%" in r) and "table" not in r.lower():
                body.insert(0, r)
                sc_idx = 0
                break
        if sc_idx is None:
            sys.exit("No shortcode row found in compatibility table")

    sc_cols = [c.strip() for c in body[sc_idx].split("|")[1:-1]]
    orig_k8s, orig_nginx = sc_cols[1], sc_cols[4]

    new_sc_row = body[sc_idx]
    if orig_k8s != k8s_new:
        new_sc_row = new_sc_row.replace(orig_k8s, k8s_new, 1)
    if orig_nginx != nginx_new:
        new_sc_row = new_sc_row.replace(orig_nginx, nginx_new, 1)

    # Collect data rows, pruning expired ones (keep most recently expired)
    now = datetime.now()
    new_body = []
    expired_rows = []
    for r in body:
        if "{{<" in r or "{{%" in r or not r.strip():
            continue
        cols = [c.strip() for c in r.split("|")[1:-1]]
        if not cols:
            continue
        # Skip rows for the current NIC version (will be re-added as frozen row if needed)
        if cols[0] == current_nic:
            continue
        try:
            eol_date = datetime.strptime(cols[5], "%b %d, %Y")
            if now > eol_date:
                expired_rows.append((eol_date, r))
                continue
        except (IndexError, ValueError):
            # If the EOL date is missing or malformed, treat the row as non-expired
            pass
        new_body.append(r)

    # For minor/major releases: insert frozen row with current resolved values
    if freeze:
        frozen_row = f"| {current_nic} | {orig_k8s} | {helm} | {oper} | {orig_nginx} | - |"
        new_body.insert(0, frozen_row)

    # Keep the most recently expired row as a migration reference
    if expired_rows:
        expired_rows.sort(key=lambda x: x[0], reverse=True)
        new_body.append(expired_rows[0][1])

    final_tbl = leading_ws + "\n".join([header, sep, new_sc_row] + new_body) + trailing_ws
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
                if update_nap_table(nap_table, args.nap_waf_version, args.ic_version, args.docs_root):
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
