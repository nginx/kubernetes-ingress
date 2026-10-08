#!/usr/bin/env python

"""Verify that the expected NGINX packages are installed in the NIC container images.

Reads the image/package matrix from ``tests/data/modules/data.json``, inspects every
image on every platform, and writes a markdown report suitable for posting as a pull
request comment. Every image is checked even if an earlier one fails; the script exits
non-zero at the end if anything did not match.
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field

import docker
import docker.errors

SYSTEMS = {
    "alpine": {
        "cmd": "apk list -I",
        "regex": "^(.+?)-(\\d+.+?)\\s+(\\w+).*",
    },
    "debian": {
        "cmd": "dpkg -l",
        "regex": "ii\\s+(.+?)\\s+(.+?)\\s+(\\w+?)\\s",
    },
    "ubi": {
        "cmd": "rpm -q",
        "regex": "(.+?)-(\\d+.+)(?:\\.ngx)?\\.(\\w+)",
    },
}

# Packages promoted to their own column in the report table. The first package name
# that exists in a given image wins, so OSS images show `nginx` and Plus images show
# `nginx-plus` in the same column.
HIGHLIGHTS = (
    ("NGINX", ("nginx-plus", "nginx")),
    ("Agent", ("nginx-agent",)),
    ("WAF", ("app-protect-module-plus", "app-protect")),
    ("DoS", ("app-protect-dos",)),
)

# GitHub rejects comments larger than 65536 characters.
MAX_COMMENT_CHARS = 60000

EMPTY = "&ndash;"
NOT_INSTALLED = "not installed"
IMAGE_UNAVAILABLE = "image unavailable"

logger = logging.getLogger("package_checker")


@dataclass
class Check:
    """The result of looking for a single package in a single image on a single platform."""

    repo: str
    tag_suffix: str
    system: str
    platform: str
    name: str
    expected: str
    installed: str = ""
    error: str = ""
    image_size: int = 0

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class Group:
    """All checks for one image variant, across every platform it is built for."""

    repo: str
    tag_suffix: str
    system: str
    platforms: list = field(default_factory=list)
    packages: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return f"{self.repo}{self.tag_suffix}"

    @property
    def failures(self) -> list:
        return [c for c in self.checks if not c.ok]

    @property
    def checks(self) -> list:
        return [c for pkg in self.packages.values() for c in pkg["by_platform"].values()]


def registry_prefix(repos) -> str:
    """Return the registry path shared by every image, e.g. ``gcr.io/org/dev``."""
    prefix = os.path.commonprefix(sorted(set(repos)))
    return prefix.rsplit("/", 1)[0] if "/" in prefix else prefix


def short_platform(platform: str) -> str:
    """``linux/amd64`` -> ``amd64``."""
    return platform.split("/")[-1]


def ensure_image(client, reference: str, platform: str):
    """Pull ``reference`` unless an image for ``platform`` is already present locally."""
    try:
        image = client.images.get(reference)
        local = f"{image.attrs['Os']}/{image.attrs['Architecture']}"
        if local != platform:
            raise docker.errors.ImageNotFound(f"{reference} is {local}, wanted {platform}")
        return image
    except docker.errors.ImageNotFound:
        logger.debug(f"Pulling image {reference} for platform {platform}")
        repository, _, tag = reference.rpartition(":")
        image = client.images.pull(repository=repository, tag=tag, platform=platform)
        logger.debug(f"Image {image.id} pulled successfully")
        return image


def query_package(client, reference: str, platform: str, system: str, package: str) -> str:
    """Run the package manager inside the image and return the installed version."""
    command = f"{SYSTEMS[system]['cmd']} {package}"
    try:
        output = client.containers.run(reference, command, entrypoint="", platform=platform, remove=True, detach=False)
    except (docker.errors.ContainerError, docker.errors.NotFound) as e:
        logger.debug(f"{e}, retrying")
        output = client.containers.run(reference, command, entrypoint="", platform=platform, remove=True, detach=False)

    text = output.decode("utf-8").strip()
    result = re.search(SYSTEMS[system]["regex"], text)
    if not result:
        raise LookupError(f"could not parse `{command}` output: {text}")
    return result.group(2)


def check_image(client, image: dict, tag: str) -> list:
    """Check every package of one image entry, on every platform, collecting failures."""
    checks = []
    reference = f"{image['image']}:{tag}"

    for platform in image["platforms"]:
        arch = short_platform(platform)
        try:
            size = ensure_image(client, reference, platform).attrs.get("Size", 0)
        except Exception as e:  # noqa: BLE001 - one broken image must not hide the rest
            logger.error(f"{reference} [{arch}]: {e}")
            checks.extend(
                Check(
                    repo=image["image"],
                    tag_suffix=image["tag_suffix"],
                    system=image["system"],
                    platform=arch,
                    name=package["name"],
                    expected=package["version"],
                    error=IMAGE_UNAVAILABLE,
                )
                for package in image["packages"]
            )
            continue

        for package in image["packages"]:
            check = Check(
                repo=image["image"],
                tag_suffix=image["tag_suffix"],
                system=image["system"],
                platform=arch,
                name=package["name"],
                expected=package["version"],
                image_size=size,
            )
            try:
                check.installed = query_package(client, reference, platform, image["system"], package["name"])
                if not check.installed.startswith(package["version"]):
                    check.error = "version mismatch"
            except (docker.errors.ContainerError, docker.errors.NotFound) as e:
                logger.debug(f"{reference} [{arch}] {package['name']}: {e}")
                check.error = NOT_INSTALLED
            except LookupError as e:
                logger.debug(f"{reference} [{arch}] {package['name']}: {e}")
                check.error = "unreadable version"
            except Exception as e:  # noqa: BLE001 - record and carry on with the next package
                logger.debug(f"{reference} [{arch}] {package['name']}: {e}")
                check.error = "check failed"

            if check.ok:
                logger.info(f"{reference} [{arch}] {check.name} {check.installed}")
            else:
                logger.error(
                    f"{reference} [{arch}] {check.name}: {check.error} "
                    f"(expected {check.expected}, found {check.installed or 'nothing'})"
                )
            checks.append(check)

    return checks


def group_checks(checks: list, registry: str = "") -> list:
    """Collapse a flat list of checks into one group per image variant.

    ``registry`` is stripped from the image names, since it is reported once in the
    report header rather than repeated on every row.
    """
    groups = {}
    for check in checks:
        key = (check.repo, check.tag_suffix)
        repo = check.repo.removeprefix(f"{registry}/") if registry else check.repo
        group = groups.setdefault(key, Group(repo, check.tag_suffix, check.system))
        if check.platform not in group.platforms:
            group.platforms.append(check.platform)
        package = group.packages.setdefault(check.name, {"expected": check.expected, "by_platform": {}})
        package["by_platform"][check.platform] = check
    return list(groups.values())


def versions(group: Group, package: dict) -> str:
    """Installed version of one package, collapsed to a single value when every platform agrees."""
    found = {}
    for platform in group.platforms:
        check = package["by_platform"].get(platform)
        found[platform] = (check.installed or f"_{check.error}_") if check else EMPTY
    if len(set(found.values())) == 1:
        return found[group.platforms[0]]
    return " / ".join(f"{v} ({p})" for p, v in found.items())


def version_cell(group: Group, package_names) -> str:
    """Headline column: the version of the first of ``package_names`` present in the image."""
    for name in package_names:
        package = group.packages.get(name)
        if package:
            return versions(group, package) if all(c.ok for c in package["by_platform"].values()) else "&#10060;"
    return EMPTY


def packages_cell(group: Group, expand: bool) -> str:
    """Every package in the image, collapsed behind its count unless something failed."""
    if not expand:
        return str(len(group.packages))
    items = []
    for name, package in group.packages.items():
        item = f"{name} {versions(group, package)}"
        if not all(c.ok for c in package["by_platform"].values()):
            item += f" &#10060; want {package['expected']}"
        items.append(item)
    tag = "<details open>" if group.failures else "<details>"
    return f"{tag}<summary>{len(items)}</summary>{'<br>'.join(items)}</details>"


def render_table(groups: list, expand_passing: bool = True) -> list:
    """One row per image variant; essentials on the left, the package list last."""
    headers = ["", "Image", "Arch", *(label for label, _ in HIGHLIGHTS), "Size", "Packages"]
    lines = ["| " + " | ".join(headers) + " |", "| :-: |" + " --- |" * (len(headers) - 1)]
    for group in groups:
        failures = len(group.failures)
        # Uncompressed size, in the same order as the Arch column.
        sizes = {c.platform: c.image_size for c in group.checks}
        row = [
            f"&#10060; {failures}" if failures else "&#9989;",
            f"`{group.repo}`" + (f" `{group.tag_suffix}`" if group.tag_suffix else ""),
            ", ".join(group.platforms),
            *(version_cell(group, names) for _, names in HIGHLIGHTS),
            " / ".join(f"{s / 1e6:.0f}" if s else "?" for s in sizes.values()) + " MB",
            packages_cell(group, expand_passing or bool(failures)),
        ]
        lines.append("| " + " | ".join(row) + " |")
    return lines + [""]


def render_mismatches(groups: list) -> list:
    lines = [
        "#### Mismatches",
        "",
        "| Image | Arch | Package | Expected | Found |",
        "| --- | --- | --- | --- | --- |",
    ]
    for group in groups:
        for platform in group.platforms:
            failures = [c for c in group.failures if c.platform == platform]
            if not failures:
                continue
            # An image that could not be pulled fails every one of its packages
            # identically; report that once rather than once per package.
            reasons = {c.error for c in failures}
            if len(failures) == len(group.packages) and len(reasons) == 1 and not any(c.installed for c in failures):
                lines.append(f"| `{group.name}` | {platform} | _all {len(failures)}_ | {EMPTY} | _{reasons.pop()}_ |")
                continue
            for check in failures:
                found = check.installed if check.installed else f"_{check.error}_"
                lines.append(f"| `{group.name}` | {platform} | {check.name} | {check.expected} | {found} |")
    lines.append("")
    return lines


def render_report(checks: list, registry: str, tag: str, commit: str = "", run_url: str = "") -> str:
    groups = group_checks(checks, registry)
    failed = [g for g in groups if g.failures]
    failures = sum(len(g.failures) for g in groups)
    verdict = f"&#10060; **{failures} mismatched**" if failures else "&#9989; **all matched**"

    summary = [verdict, f"{len(groups)} images", f"{len(checks)} checks"]
    if commit:
        # A bare SHA is auto-linked and shortened by GitHub.
        summary.append(f"commit {commit}")
    if run_url:
        summary.append(f"[CI run]({run_url})")
    head = [
        "### Package Report",
        "",
        " &middot; ".join(summary),
        "",
        f"<sub>Full reference is <code>{registry}/&lt;image&gt;:{tag}&lt;variant&gt;</code>. "
        "Sizes are uncompressed, per arch.</sub>",
        "",
    ]
    if failures:
        head += render_mismatches(failed)

    report = "\n".join(head + render_table(groups)).rstrip() + "\n"
    if len(report) <= MAX_COMMENT_CHARS:
        return report

    # Too large for a single comment: only list the packages of images that failed.
    notice = (
        "<sub>Package lists for passing images omitted to stay within the comment size limit; "
        "see the CI run linked above for the full list.</sub>"
    )
    return "\n".join(head + [notice, ""] + render_table(groups, expand_passing=False)).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-t", "--tag", type=str, help="NGINX Ingress Controller image tag", default="edge")
    parser.add_argument("-r", "--report", type=str, help="markdown report output file", required=False)
    args = parser.parse_args()

    logger.setLevel(logging.DEBUG)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(stream_handler)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    with open(f"{script_dir}/../data/modules/data.json") as file:
        images = json.load(file)["images"]

    client = docker.from_env()
    checks = []
    for image in images:
        checks.extend(check_image(client, image, f"{args.tag}{image['tag_suffix']}"))

    registry = registry_prefix(entry["image"] for entry in images)
    if args.report:
        with open(args.report, "w") as file:
            commit, run_url = os.environ.get("PR_HEAD_SHA", ""), os.environ.get("RUN_URL", "")
            file.write(render_report(checks, registry, args.tag, commit, run_url))
        logger.info(f"Wrote package report to {args.report}")

    failures = [c for c in checks if not c.ok]
    if failures:
        logger.error(f"{len(failures)} of {len(checks)} package checks failed")
        return 1
    logger.info(f"All {len(checks)} package checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
