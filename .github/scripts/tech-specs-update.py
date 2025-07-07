#!/usr/bin/env python3
import argparse
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from github import Github


def github_release_dates():
    """Fetch NIC release dates from GitHub API."""
    tok = os.getenv("GITHUB_TOKEN")
    if not tok:
        sys.exit("GITHUB_TOKEN env-var missing")
    repo = Github(tok).get_repo("nginx/kubernetes-ingress")
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

    pat = r"(\{\{<\s*bootstrap-table[^>]*>\}\}\n)(.*?)(\n\{\{%.*/bootstrap-table\s*%\}\})"
    m = re.search(pat, md, re.S)
    if not m:
        sys.exit("bootstrap-table not found")
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
    return re.sub(pat, open_tag + final_tbl + close_tag, md, count=1, flags=re.S)


def main():
    parser = argparse.ArgumentParser(description="Update NIC tech specs table for a new release.")
    parser.add_argument("ic_version", help="New NGINX Ingress Controller version")
    parser.add_argument("k8s_versions", help="New Kubernetes versions string")
    parser.add_argument("nginx_version", help="New NGINX/NGINX Plus version string")
    parser.add_argument("docs_root", help="Path to documentation root directory")
    args = parser.parse_args()
    tech = Path(args.docs_root) / "content" / "nic" / "technical-specifications.md"
    if not tech.exists():
        sys.exit("technical-specifications.md not found")
    tech.write_text(
        update(
            tech.read_text(encoding="utf-8"), args.k8s_versions, args.nginx_version, args.ic_version, args.docs_root
        ),
        encoding="utf-8",
    )
    print("updated", tech)


if __name__ == "__main__":
    main()
