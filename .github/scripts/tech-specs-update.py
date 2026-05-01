#!/usr/bin/env python3
"""Update NIC tech spec tables from a JSON data file.

This script drives the NIC/K8s and NAP compatibility tables in the
nginx/documentation repo from a tech-specs.json file stored in the NIC repo.

Modes
-----
Full mode (default):
    Reads JSON for historical rows, reads docs shortcode files for the
    current live version, generates Markdown tables in the docs repo.

JSON-only mode (--json-only):
    Only updates the JSON file (freeze row, update shortcode_row values).
    Does not touch docs files.  Requires --current-* arguments.

In both modes, --update-json writes the modified JSON back to disk.
Positional arguments (k8s_versions, nginx_version, nap_waf_version)
serve as overrides; when empty the script falls back to JSON values.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def parse_nginx_version(version_str):
    """Parse "OSS_VERSION[/PLUS_VERSION]" into (oss, plus|None)."""
    parts = re.split(r"\s*/\s*", version_str.strip(), maxsplit=1)
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    return version_str.strip(), None


def normalize_k8s_versions(v):
    """Ensure spaces around the dash in K8s version ranges.

    Converts e.g. '1.28-1.35' to '1.28 - 1.35' to match the docs convention.
    Already-spaced ranges like '1.28 - 1.35' are returned unchanged.
    """
    if not v:
        return v
    return re.sub(r"(\d+\.\d+)\s*-\s*(\d+\.\d+)", r"\1 - \2", v)


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------


def load_json(path):
    """Load and return the tech-specs JSON data."""
    p = Path(path)
    if not p.exists():
        sys.exit(f"ERROR: JSON file not found: {path}")
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    """Write tech-specs JSON data back to disk."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


# ---------------------------------------------------------------------------
# Table generation from JSON
# ---------------------------------------------------------------------------

TABLE_PATTERN = (
    r"(\{\{[<%]\s*(?:bootstrap-)?table[^>%]*[>%]\}\}\n)" r"(.*?)" r"(\n\{\{[<%]\s*/(?:bootstrap-)?table\s*[>%]\}\})"
)


def extract_shortcode_row(file_path):
    """Extract the live shortcode row from a docs table file.

    Returns the full Markdown line (including pipes and spacing) or None
    if no shortcode row is found.  The returned line preserves the original
    formatting so it can be re-inserted with minimal diff.
    """
    content = file_path.read_text(encoding="utf-8")
    m = re.search(TABLE_PATTERN, content, re.DOTALL)
    if not m:
        return None
    for line in m.group(2).strip().split("\n"):
        if ("{{<" in line or "{{%" in line) and "table" not in line.lower():
            return line
    return None


def update_compat_sc_row(sc_row, k8s_new, nginx_new):
    """Update K8s and NGINX version values in an existing compat shortcode row.

    Performs targeted replacements of the literal values within the row,
    preserving all other formatting (spacing, shortcode syntax, etc.).
    """
    cols = [c.strip() for c in sc_row.split("|")[1:-1]]
    orig_k8s, orig_nginx = cols[1], cols[4]
    result = sc_row
    if orig_k8s != k8s_new:
        result = result.replace(orig_k8s, k8s_new, 1)
    if orig_nginx != nginx_new:
        result = result.replace(orig_nginx, nginx_new, 1)
    return result


def update_nap_sc_row(sc_row, nap_waf_version):
    """Update the NAP-WAF prefix in an existing NAP shortcode row.

    Replaces only the R-number prefix (e.g. '36+' -> '37+'), preserving
    all other formatting including trailing padding spaces.
    """
    if nap_waf_version and "+" in nap_waf_version:
        new_prefix = nap_waf_version.split("+")[0]
        m = re.search(r"(\d+)\+", sc_row)
        if m and m.group(1) != new_prefix:
            return sc_row.replace(m.group(1) + "+", new_prefix + "+", 1)
    return sc_row


def replace_table_in_file(file_path, new_table_md):
    """Replace the table content inside {{< table >}} wrapper in a docs file."""
    content = file_path.read_text(encoding="utf-8")
    m = re.search(TABLE_PATTERN, content, re.DOTALL)
    if not m:
        sys.exit(f"ERROR: table shortcode not found in {file_path}")

    open_tag, _, close_tag = m.groups()
    new_content = re.sub(
        TABLE_PATTERN,
        open_tag + "\n" + new_table_md + "\n" + close_tag,
        content,
        count=1,
        flags=re.DOTALL,
    )
    file_path.write_text(new_content, encoding="utf-8")


def generate_compat_table_md(json_data, sc_row=None):
    """Generate the NIC/K8s compatibility table Markdown from JSON data.

    If *sc_row* is provided (extracted from the existing docs file), it is
    used as-is to preserve original formatting.  Otherwise a fresh shortcode
    row is generated from the JSON shortcode_row values.

    Prunes rows past their End of Technical Support date, keeping the most
    recently expired row as a reference.
    """
    sr = json_data["nic_k8s"]["shortcode_row"]
    rows = json_data["nic_k8s"]["rows"]

    header = (
        "| NIC version | Kubernetes versions tested  "
        "| NIC Helm Chart version | NIC Operator version "
        "| NGINX / NGINX Plus version | End of Technical Support |"
    )
    sep = "| --- | --- | --- | --- | --- | --- |"

    if sc_row is None:
        sc_row = (
            f"| {{{{< nic-version >}}}} | {sr['k8s_versions']} "
            f"| {{{{< nic-helm-version >}}}} | {{{{< nic-operator-version >}}}} "
            f"| {sr['nginx_version']} | - |"
        )

    # EOL pruning
    now = datetime.now()
    active_rows = []
    expired_rows = []
    for row in rows:
        eol = row.get("eol_date", "-")
        if eol and eol != "-":
            try:
                eol_date = datetime.strptime(eol, "%b %d, %Y")
                if now > eol_date:
                    expired_rows.append((eol_date, row))
                    continue
            except ValueError:
                pass
        active_rows.append(row)

    # Keep the most recently expired row as a migration reference
    if expired_rows:
        expired_rows.sort(key=lambda x: x[0], reverse=True)
        active_rows.append(expired_rows[0][1])

    data_lines = []
    for row in active_rows:
        data_lines.append(
            f"| {row['nic_version']} | {row['k8s_versions']} "
            f"| {row['helm_version']} | {row['operator_version']} "
            f"| {row['nginx_version']} | {row['eol_date']} |"
        )

    return "\n".join([header, sep, sc_row] + data_lines)


def generate_nap_table_md(json_data, sc_row=None):
    """Generate the NAP WAF compatibility table Markdown from JSON data.

    If *sc_row* is provided (extracted from the existing docs file), it is
    used as-is to preserve original formatting.  Otherwise a fresh shortcode
    row is generated.

    Uses column-width padding for header, separator, and data rows.
    Column widths are derived from headers and data rows.  Column 0 is
    expanded to fit ``{{< nic-version >}}`` (19 chars).
    """
    sr = json_data["nic_nap"]["shortcode_row"]
    rows = json_data["nic_nap"]["rows"]

    headers = ["NIC Version", "NAP-WAF Version", "Config Manager", "Enforcer"]

    # Build data cell values
    data = []
    for row in rows:
        data.append(
            [
                row["nic_version"],
                row["nap_waf_version"],
                row["config_mgr_version"],
                row["enforcer_version"],
            ]
        )

    # Compute column widths from headers and data rows.
    # Expand col 0 to fit {{< nic-version >}} (19 chars) so the shortcode
    # row aligns without overflow in that column.
    nic_sc = "{{< nic-version >}}"
    col_widths = [max(len(h), len(nic_sc)) if i == 0 else len(h) for i, h in enumerate(headers)]
    for row_data in data:
        for i, cell in enumerate(row_data):
            col_widths[i] = max(col_widths[i], len(cell))

    def pad_row(cells):
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, col_widths)) + " |"

    header_line = pad_row(headers)
    sep_line = "| " + " | ".join("-" * w for w in col_widths) + " |"

    if sc_row is None:
        sc_cells = [
            nic_sc,
            f"{sr['nap_waf_prefix']}+{{{{< appprotect-compiler-version>}}}}",
            "{{< nic-waf-release-version >}}",
            "{{< nic-waf-release-version >}}",
        ]
        sc_row = "| " + " | ".join(c.ljust(w) for c, w in zip(sc_cells, col_widths)) + " |"

    data_lines = [pad_row(r) for r in data]

    return "\n".join([header_line, sep_line, sc_row] + data_lines)


# ---------------------------------------------------------------------------
# NGINX prose update (unchanged from original)
# ---------------------------------------------------------------------------


def update_nginx_prose(md, nginx_new):
    """Update NGINX version references in technical-specifications.md.

    Finds the current NGINX OSS version from the "All images include NGINX X.Y.Z"
    text and the NGINX Plus version from the "NGINX Plus images include" text,
    then replaces all occurrences of the old versions with the new ones throughout
    the file, including in base image tags like ``nginx:X.Y.Z-alpine``.
    """
    new_oss, new_plus = parse_nginx_version(nginx_new)

    if new_oss:
        oss_match = re.search(r"All images include NGINX (\d+\.\d+\.\d+)", md)
        if oss_match:
            current_oss = oss_match.group(1)
            if current_oss != new_oss:
                md = re.sub(r"\b" + re.escape(current_oss) + r"\b", new_oss, md)

    if new_plus:
        plus_match = re.search(r"NGINX Plus images include NGINX Plus (R\d+(?:\s+P\d+)?)", md)
        if plus_match:
            current_plus = plus_match.group(1)
            if current_plus != new_plus:
                md = re.sub(r"\b" + re.escape(current_plus) + r"\b", new_plus, md)

    return md


# ---------------------------------------------------------------------------
# Core: freeze logic and JSON updates
# ---------------------------------------------------------------------------


def freeze_compat_row(json_data, ic_version, current_nic, current_helm, current_operator):
    """Freeze the current shortcode row as a historical entry in the JSON.

    Only called for minor/major releases.  Builds a frozen row from the
    current NIC/Helm/Operator versions and the shortcode_row values for
    K8s and NGINX versions, then prepends it to the rows list.
    Skips the freeze if current_nic is already present (idempotent on retry).
    """
    existing = [r["nic_version"] for r in json_data["nic_k8s"]["rows"]]
    if current_nic in existing:
        print(f"INFO: Compat row for {current_nic} already exists, skipping freeze")
        return

    sr = json_data["nic_k8s"]["shortcode_row"]
    frozen = {
        "nic_version": current_nic,
        "k8s_versions": sr["k8s_versions"],
        "helm_version": current_helm,
        "operator_version": current_operator,
        "nginx_version": sr["nginx_version"],
        "eol_date": "-",
    }
    json_data["nic_k8s"]["rows"].insert(0, frozen)
    print(f"INFO: Frozen compat row for {current_nic}")


def freeze_nap_row(json_data, current_nic):
    """Freeze the current NAP shortcode row as a historical entry in the JSON.

    Only called for minor/major releases.  Builds the frozen NAP-WAF version
    from the shortcode_row prefix + compiler_version.
    Skips the freeze if current_nic is already present (idempotent on retry).
    """
    existing = [r["nic_version"] for r in json_data["nic_nap"]["rows"]]
    if current_nic in existing:
        print(f"INFO: NAP row for {current_nic} already exists, skipping freeze")
        return

    sr = json_data["nic_nap"]["shortcode_row"]
    frozen = {
        "nic_version": current_nic,
        "nap_waf_version": f"{sr['nap_waf_prefix']}+{sr['compiler_version']}",
        "config_mgr_version": sr["waf_release_version"],
        "enforcer_version": sr["waf_release_version"],
    }
    json_data["nic_nap"]["rows"].insert(0, frozen)
    print(f"INFO: Frozen NAP row for {current_nic}")


def update_shortcode_row_values(
    json_data,
    k8s_versions,
    nginx_version,
    nap_waf_version=None,
    nap_waf_release_version=None,
):
    """Update the shortcode_row entries in the JSON with new values.

    Only updates a field if a non-empty value is provided; otherwise the
    existing JSON value is preserved (i.e. the JSON acts as the default).
    """
    if k8s_versions:
        json_data["nic_k8s"]["shortcode_row"]["k8s_versions"] = k8s_versions
    if nginx_version:
        json_data["nic_k8s"]["shortcode_row"]["nginx_version"] = nginx_version

    if nap_waf_version and "+" in nap_waf_version:
        new_prefix, new_compiler = nap_waf_version.split("+", 1)
        json_data["nic_nap"]["shortcode_row"]["nap_waf_prefix"] = new_prefix
        json_data["nic_nap"]["shortcode_row"]["compiler_version"] = new_compiler
    if nap_waf_release_version:
        json_data["nic_nap"]["shortcode_row"]["waf_release_version"] = nap_waf_release_version


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Update NIC tech spec tables from a JSON data file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full mode — update docs tables from JSON
  %(prog)s --json-file tech-specs.json "5.5.0" "1.28-1.35" "1.29.7 / R36 P3" /docs

  # Full mode with NAP
  %(prog)s --json-file tech-specs.json "5.5.0" "1.28-1.35" "1.29.7 / R36 P3" /docs "36+5.607"

  # JSON-only mode — update the JSON file without touching docs
  %(prog)s --json-file tech-specs.json --json-only --update-json \\
    --current-nic-version 5.4.0 --current-helm-version 2.5.0 \\
    --current-operator-version 3.5.0 \\
    "5.5.0" "1.28-1.35" "1.29.7 / R36 P3"
        """,
    )

    # Positional arguments (backward-compatible with release-docs.sh)
    parser.add_argument("ic_version", help="New NGINX Ingress Controller version")
    parser.add_argument(
        "k8s_versions",
        nargs="?",
        default="",
        help="Kubernetes versions string (override; empty = use JSON)",
    )
    parser.add_argument(
        "nginx_version",
        nargs="?",
        default="",
        help="NGINX/NGINX Plus version string (override; empty = use JSON)",
    )
    parser.add_argument(
        "docs_root",
        nargs="?",
        default=None,
        help="Path to documentation root (required unless --json-only)",
    )
    parser.add_argument(
        "nap_waf_version",
        nargs="?",
        default=None,
        help="NAP-WAF version e.g. '36+5.607' (optional)",
    )

    # JSON control
    parser.add_argument("--json-file", required=True, help="Path to tech-specs.json")
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only update JSON, skip docs table generation",
    )
    parser.add_argument("--update-json", action="store_true", help="Write updated JSON back to file")

    # Current versions for freeze in --json-only mode
    parser.add_argument(
        "--current-nic-version",
        default=None,
        help="Current NIC version (required with --json-only for freeze)",
    )
    parser.add_argument(
        "--current-helm-version",
        default=None,
        help="Current Helm chart version (required with --json-only for freeze)",
    )
    parser.add_argument(
        "--current-operator-version",
        default=None,
        help="Current Operator version (required with --json-only for freeze)",
    )
    parser.add_argument(
        "--nap-waf-release-version",
        default=None,
        help="NAP WAF release version for JSON shortcode_row update",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # ---- Validation ----
    if not args.json_only and not args.docs_root:
        sys.exit("ERROR: docs_root is required unless --json-only is set")
    if not args.json_only and args.docs_root and not Path(args.docs_root).exists():
        sys.exit(f"ERROR: Documentation root directory not found: {args.docs_root}")
    if args.json_only:
        for attr in (
            "current_nic_version",
            "current_helm_version",
            "current_operator_version",
        ):
            if not getattr(args, attr):
                sys.exit(f"ERROR: --{attr.replace('_', '-')} is required with --json-only")

    # ---- Load JSON ----
    json_data = load_json(args.json_file)

    if args.verbose:
        print(f"Processing release: {args.ic_version}")
        print(f"Kubernetes versions override: {args.k8s_versions or '(from JSON)'}")
        print(f"NGINX version override: {args.nginx_version or '(from JSON)'}")
        print(f"JSON file: {args.json_file}")
        print(f"Mode: {'json-only' if args.json_only else 'full'}")
        if args.nap_waf_version:
            print(f"NAP WAF version: {args.nap_waf_version}")

    # ---- Determine current versions (for freeze) ----
    if args.json_only:
        current_nic = args.current_nic_version
        current_helm = args.current_helm_version
        current_operator = args.current_operator_version
    else:
        docs = Path(args.docs_root)
        sc_dir = docs / "layouts" / "shortcodes"
        current_nic = shortcode_ver(sc_dir / "nic-version.html")
        current_helm = shortcode_ver(sc_dir / "nic-helm-version.html")
        current_operator = shortcode_ver(sc_dir / "nic-operator-version.html")

    # ---- Freeze if minor/major release ----
    freeze = is_minor_or_major(args.ic_version, current_nic)
    if freeze:
        print(f"INFO: Minor/major release ({current_nic} -> {args.ic_version}), freezing rows")
        freeze_compat_row(json_data, args.ic_version, current_nic, current_helm, current_operator)
        if args.nap_waf_version:
            freeze_nap_row(json_data, current_nic)
    else:
        print(f"INFO: Patch release or re-run ({current_nic} -> {args.ic_version}), updating in-place")

    # ---- Normalize k8s version format (ensure spaces around dash) ----
    if args.k8s_versions:
        args.k8s_versions = normalize_k8s_versions(args.k8s_versions)

    # ---- Update shortcode_row values ----
    update_shortcode_row_values(
        json_data,
        k8s_versions=args.k8s_versions,
        nginx_version=args.nginx_version,
        nap_waf_version=args.nap_waf_version,
        nap_waf_release_version=args.nap_waf_release_version,
    )

    # ---- Generate and write docs tables (full mode only) ----
    if not args.json_only:
        docs_root = Path(args.docs_root)

        # Resolve values for shortcode row updates (overrides or JSON defaults)
        k8s = args.k8s_versions or json_data["nic_k8s"]["shortcode_row"]["k8s_versions"]
        nginx = args.nginx_version or json_data["nic_k8s"]["shortcode_row"]["nginx_version"]

        # 1. NIC/K8s compatibility table
        nic_k8s = docs_root / "content" / "includes" / "nic" / "compatibility-tables" / "nic-k8s.md"
        if not nic_k8s.exists():
            sys.exit(f"ERROR: Compatibility table file not found: {nic_k8s}")
        if args.verbose:
            print(f"Updating compatibility table in {nic_k8s}...")
        # Extract existing shortcode row, update values, preserve formatting
        existing_k8s_sc = extract_shortcode_row(nic_k8s)
        updated_k8s_sc = update_compat_sc_row(existing_k8s_sc, k8s, nginx) if existing_k8s_sc else None
        replace_table_in_file(nic_k8s, generate_compat_table_md(json_data, sc_row=updated_k8s_sc))
        print("updated", nic_k8s)

        # 2. NGINX version prose in technical-specifications.md
        tech = docs_root / "content" / "nic" / "technical-specifications.md"
        if not tech.exists():
            sys.exit(f"ERROR: Technical specifications file not found: {tech}")
        if args.verbose:
            print(f"Updating NGINX version prose in {tech}...")
        tech.write_text(
            update_nginx_prose(tech.read_text(encoding="utf-8"), nginx),
            encoding="utf-8",
        )
        print("updated", tech)

        # 3. NAP compatibility table (if WAF version provided)
        if args.nap_waf_version:
            nap_table = docs_root / "content" / "includes" / "nic" / "compatibility-tables" / "nic-nap.md"
            if not nap_table.exists():
                print(f"WARNING: NAP compatibility table not found at {nap_table}, skipping")
            else:
                if args.verbose:
                    print(f"Updating NAP compatibility table at {nap_table}...")
                # Extract existing shortcode row, update prefix, preserve formatting
                existing_nap_sc = extract_shortcode_row(nap_table)
                updated_nap_sc = update_nap_sc_row(existing_nap_sc, args.nap_waf_version) if existing_nap_sc else None
                replace_table_in_file(
                    nap_table,
                    generate_nap_table_md(json_data, sc_row=updated_nap_sc),
                )
                print("updated", nap_table)
        else:
            print("INFO: No NAP WAF version provided, skipping NAP table update")

    # ---- Write JSON back (if requested) ----
    if args.update_json:
        save_json(args.json_file, json_data)
        print(f"updated {args.json_file}")


if __name__ == "__main__":
    main()
