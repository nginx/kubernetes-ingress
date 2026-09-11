#!/usr/bin/env python3
"""Pre-release dependency availability check.

Asserts that everything NIC depends on is actually published: NGINX packages
via index.xml in each package repository, and the container images the Helm
chart deploys via the registry API.

Three independent assertions per dependency:

  EXISTS    the declared version or tag is published at all
  COMPLETE  published for every distro/arch NIC builds, or every required
            image platform
  CURRENT   nothing newer is available (warning only)

EXISTS and COMPLETE failures exit non-zero. CURRENT only warns, so a deliberate
hold on an older version does not block a release. A dependency marked
gate = false is reported but can never block.

Declared versions are read from build/Dockerfile and the chart rather than
duplicated in config, so the check cannot pass against a stale copy of the
truth. Availability per build target is folded into the results table; the
per-group OS matrices behind --matrix additionally cover distros NIC does not
build on.
"""

import argparse
import base64
import configparser
import gzip
import http.client
import io
import json
import os
import re
import ssl
import sys
import tarfile
import textwrap
import urllib.parse
import xml.etree.ElementTree as ET

# Repository arches, mapped to a short display label. x86_64/amd64 and
# aarch64/arm64 are the same family under different naming conventions.
# Anything else (sles "source" repos, centos ppc64le) is ignored for OS
# reporting, but still counts towards version discovery.
ARCH_LABELS = {
    "x86_64": "x86",
    "amd64": "x86",
    "aarch64": "arm",
    "arm64": "arm",
}

# Debian images are pinned by codename in some stages and by number in others
# (build/Dockerfile:144 uses trixie-slim, :440 uses 13-slim).
DEBIAN_CODENAMES = {
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
    "forky": "14",
}

# Dependency metadata is addressed by codename, not by number.
DEBIAN_NUMBERS = {v: k for k, v in DEBIAN_CODENAMES.items()}

# Separators that terminate a version component, so a declared 1.31.4 does not
# match a published 1.31.45.
VERSION_BOUNDARIES = (".", "+", "-", "_", "~")

KIND_PACKAGE = "package"
KIND_IMAGE = "image"

# Native arch names per distro family, for the dependency metadata paths.
NATIVE_ARCH = {
    ("alpine", "x86"): "x86_64",
    ("alpine", "arm"): "aarch64",
    ("debian", "x86"): "amd64",
    ("debian", "arm"): "arm64",
    ("centos", "x86"): "x86_64",
    ("centos", "arm"): "aarch64",
}

REPO_NS = "{http://linux.duke.edu/metadata/repo}"
COMMON_NS = "{http://linux.duke.edu/metadata/common}"
RPM_NS = "{http://linux.duke.edu/metadata/rpm}"

# Ask for index/list types first so a multi-arch image resolves to its manifest
# list rather than one platform's manifest.
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    )
)

MANIFEST_LIST_TYPES = (
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
)

# Registry tags worth comparing for "newer available". Excludes floating tags
# (latest, edge, nightly) and variant tags (5.6.1-alpine, 5.6.1-20260906-ubi),
# which would otherwise be picked as newest.
TAG_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Staging locations, where release candidates land before promotion to the
# public ones. Unlike production, every path in the staging package repository
# is behind mTLS, including the OSS ones that are public on packages.nginx.org.
STAGING_HOST = "pkgs-test.nginx.com"
STAGING_REGISTRY = "private-registry-test.nginx.com"
DOCKER_HUB_HOST = "registry-1.docker.io"

STATUS_OK = "OK"
STATUS_STALE = "STALE"
STATUS_MISSING = "MISSING"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_ERROR = "ERROR"
STATUS_INFO = "INFO"

BLOCKING = (STATUS_MISSING, STATUS_INCOMPLETE, STATUS_ERROR)

# SGR codes. Foreground only, so padding inside a coloured span stays invisible.
BOLD = "1"
RED = "31"
GREEN = "32"
YELLOW = "33"
CYAN = "36"
GREY = "90"
BRIGHT_RED = "91"

STATUS_COLORS = {
    STATUS_OK: GREEN,
    STATUS_STALE: YELLOW,
    STATUS_MISSING: RED,
    STATUS_INCOMPLETE: RED,
    STATUS_ERROR: BRIGHT_RED,
    STATUS_INFO: CYAN,
}

ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# Set once from --color before anything is printed.
_COLOR = False


def should_color(mode):
    """Decide whether to emit SGR codes.

    CI is excluded even though GitHub Actions renders ANSI in logs, because the
    report is also embedded in $GITHUB_STEP_SUMMARY as a markdown code block,
    where escape codes would show up as literal noise.
    """
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):  # https://no-color.org
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("CI"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def paint(text, code):
    """Wrap text in an SGR code. Padding is applied outside, never inside."""
    if not _COLOR or not code:
        return text
    return f"\033[{code}m{text}\033[0m"


def visible_len(s):
    """Length of s as rendered, ignoring SGR sequences."""
    return len(ANSI_RE.sub("", s))


def ljust_visible(s, width):
    """Left-justify to a visible width, padding outside any SGR span."""
    return s + " " * max(0, width - visible_len(s))


def parse_semver_key(v):
    """Split version string into numeric and non-numeric tokens for natural sorting."""
    tokens = re.findall(r"\d+|\D+", v)
    return [int(t) if t.isdigit() else t for t in tokens]


def fetch_index_xml(host, uri, cert_file=None, key_file=None):
    """Fetch and parse index.xml from the given repository host and URI using mTLS if certs exist."""
    context = ssl.create_default_context()
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    conn = http.client.HTTPSConnection(host, context=context, timeout=30)
    path = f"{uri.rstrip('/')}/index.xml"
    conn.request("GET", path)
    res = conn.getresponse()
    if res.status != 200:
        raise RuntimeError(f"HTTP {res.status} {res.reason} for {path} on {host}")
    data = res.read()
    conn.close()
    return ET.fromstring(data)


def _tls_context(cert_file, key_file):
    context = ssl.create_default_context()
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def _http_get(host, path, cert_file, key_file, headers=None):
    conn = http.client.HTTPSConnection(host, context=_tls_context(cert_file, key_file), timeout=30)
    try:
        conn.request("GET", path, headers=headers or {})
        res = conn.getresponse()
        body = res.read()
        return res.status, {k.lower(): v for k, v in res.getheaders()}, body
    finally:
        conn.close()


def _bearer_token(host, challenge, cert_file, key_file, jwt=None):
    """Resolve a registry bearer token from a WWW-Authenticate challenge.

    Docker Hub answers with a challenge naming a realm, service and scope.
    The NGINX private registries name only a realm -- no service, and no scope
    even on a repository endpoint -- and mint a subscription-wide token, so the
    scopeless request they ask for is the one that works.

    The JWT is sent as HTTP Basic, subscription token as the username and a
    literal 'any' as the password, which is the scheme `docker login
    private-registry.nginx.com` uses.

    It is sent ONLY when the realm is on the same host as the registry itself.
    That is true of the NGINX registries (private-registry.nginx.com/_token)
    and false of Docker Hub, whose realm is auth.docker.io while its registry
    is registry-1.docker.io. Without this check an anonymous Docker Hub lookup
    would hand our F5 subscription credential to a third party, and a rogue or
    spoofed challenge could redirect it anywhere it liked.
    """
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.pop("realm", "")
    if not realm:
        return None
    parts = urllib.parse.urlsplit(realm)
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
    path = parts.path + ("?" + query if query else "")
    headers = {}
    if jwt and parts.netloc == host:
        basic = base64.b64encode(f"{jwt}:any".encode()).decode()
        headers["Authorization"] = f"Basic {basic}"
    status, _headers, body = _http_get(parts.netloc, path, cert_file, key_file, headers)
    if status != 200:
        return None
    return json.loads(body).get("token") or json.loads(body).get("access_token")


def load_registry_jwt(path):
    """Read the NGINX subscription JWT, or None if it is not available.

    A missing file is normal -- Docker Hub needs no credential -- so this is
    not an error here; the caller warns only if a private registry is in play.
    The token is a single line and any stray newline would corrupt the Basic
    header, so it is stripped.
    """
    if not path or not os.path.exists(path):
        return None
    with open(path, "r") as f:
        token = f.read().strip()
    return token or None


def _registry_cert(host, cert_file, key_file):
    """Decide whether to present the client certificate to a registry.

    The two registries want opposite things, so this cannot be uniform:

      private-registry.nginx.com      needs the certificate. The JWT alone is
                                      entitled to nginx-ic*, but nap/* answers
                                      401 without it.
      private-registry-test.nginx.com must NOT get the certificate. It accepts
                                      it at /v2/, then answers 403 on every
                                      repository path -- even alongside a valid
                                      bearer token, which the certificate
                                      appears to override. Sending it there
                                      turns a working request into a failure.

    Verified against both registries for nginx-ic, nginx-ic-nap, nginx-ic-dos
    and all four nap/* repositories.
    """
    if host == STAGING_REGISTRY:
        return None, None
    return cert_file, key_file


def registry_get(host, path, cert_file, key_file, accept=None, jwt=None):
    """GET a registry endpoint, following a bearer-token challenge once."""
    cert_file, key_file = _registry_cert(host, cert_file, key_file)
    headers = {"Accept": accept} if accept else {}
    status, res_headers, body = _http_get(host, path, cert_file, key_file, headers)
    if status == 401 and "www-authenticate" in res_headers:
        token = _bearer_token(host, res_headers["www-authenticate"], cert_file, key_file, jwt)
        if token:
            headers["Authorization"] = f"Bearer {token}"
            status, res_headers, body = _http_get(host, path, cert_file, key_file, headers)
    return status, res_headers, body


def registry_error(status, host, path, cert_file):
    """Build an actionable message for a failed registry call.

    401/403 here means the credential is accepted by the registry but not
    authorised for this repository, which is a different fix from a wrong tag.
    """
    if status in (401, 403):
        cred = "nginx-repo.jwt" if host == STAGING_REGISTRY else f"'{cert_file}' / nginx-repo.jwt"
        return RuntimeError(
            f"HTTP {status} for {path} on {host} -- {cred} is not authorised for "
            f"this repository. A registry may accept a credential at /v2/ and still "
            f"refuse individual repositories."
        )
    return RuntimeError(f"HTTP {status} for {path} on {host}")


def fetch_image_manifest(host, repository, tag, cert_file=None, key_file=None, jwt=None):
    """Return (exists, platforms) for an image tag.

    platforms is a sorted list of os/arch strings for a manifest list, or an
    empty list for a single-architecture manifest.
    """
    path = f"/v2/{repository}/manifests/{urllib.parse.quote(tag)}"
    status, _headers, body = registry_get(host, path, cert_file, key_file, MANIFEST_ACCEPT, jwt)
    if status == 404:
        return False, []
    if status != 200:
        raise registry_error(status, host, path, cert_file)

    platforms = []
    manifest = json.loads(body)
    if manifest.get("mediaType") in MANIFEST_LIST_TYPES:
        for entry in manifest.get("manifests", []):
            plat = entry.get("platform") or {}
            os_name, arch = plat.get("os"), plat.get("architecture")
            if os_name and arch and "unknown" not in (os_name, arch):
                platforms.append(f"{os_name}/{arch}")
    return True, sorted(set(platforms))


def fetch_image_tags(host, repository, cert_file=None, key_file=None, jwt=None):
    """Return published tags that look like plain versions, naturally sorted."""
    path = f"/v2/{repository}/tags/list"
    status, _headers, body = registry_get(host, path, cert_file, key_file, None, jwt)
    if status != 200:
        raise registry_error(status, host, path, cert_file)
    tags = json.loads(body).get("tags") or []
    return sorted((t for t in tags if TAG_VERSION_RE.match(t)), key=parse_semver_key)


def parse_chart_appversion(path):
    """Read appVersion from Chart.yaml -- the default tag for the NIC image."""
    with open(path, "r") as f:
        for line in f:
            m = re.match(r"^appVersion:\s*[\"']?([^\"'\s]+)", line)
            if m:
                return m.group(1)
    raise RuntimeError(f"appVersion not found in {path}")


def parse_chart_image_tag(path, repository):
    """Find the tag belonging to a given image repository in values.yaml.

    Keyed on the repository string rather than a YAML path, so it survives the
    values file being reorganised. Returns None when the tag is commented out,
    which is how the chart expresses "fall back to appVersion"
    (charts/nginx-ingress/templates/_helpers.tpl:164-166).
    """
    with open(path, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if re.match(r"^\s*repository:\s*" + re.escape(repository) + r"\s*$", line):
            for following in lines[i + 1 :]:
                if re.match(r"^\s*repository:\s*\S", following):
                    break  # next image block, no tag for this one
                m = re.match(r"^\s*tag:\s*[\"']?([^\"'\s]+)", following)
                if m:
                    return m.group(1)
            return None
    raise RuntimeError(f"image repository '{repository}' not found in {path}")


def _fetch_bytes(host, path, cert_file, key_file):
    status, _headers, body = _http_get(host, path, cert_file, key_file)
    if status != 200:
        raise RuntimeError(f"HTTP {status} for {path} on {host}")
    return body


def parse_deb_packages(body):
    """Parse a Debian Packages file into {name: [(version, [deps])]}.

    Only Depends and Pre-Depends are collected. Recommends and Suggests are
    deliberately ignored because every image installs with
    --no-install-recommends --no-install-suggests, so they are never present.
    """
    out = {}
    for stanza in body.decode("utf-8", "replace").split("\n\n"):
        if not stanza.strip():
            continue
        fields = {}
        key = None
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") and key:
                fields[key] += " " + line.strip()
            elif ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                fields[key] = value.strip()
        name = fields.get("Package")
        if not name:
            continue
        deps = []
        for field in ("Pre-Depends", "Depends"):
            if fields.get(field):
                deps.extend(d.strip() for d in fields[field].split(",") if d.strip())
        out.setdefault(name, []).append((fields.get("Version", ""), deps))
    return out


def parse_apkindex(body):
    """Parse APKINDEX.tar.gz into {name: [(version, [deps])]}.

    APKINDEX fields are single-character keys: P name, V version, D depends.
    """
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        member = tar.extractfile("APKINDEX")
        if member is None:
            raise RuntimeError("APKINDEX missing from archive")
        text = member.read().decode("utf-8", "replace")

    out = {}
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:]
        name = fields.get("P")
        if not name:
            continue
        out.setdefault(name, []).append((fields.get("V", ""), fields.get("D", "").split()))
    return out


def parse_rpm_primary(body):
    """Parse a gzipped primary.xml into {name: [(version, [requires])]}."""
    root = ET.fromstring(gzip.decompress(body))
    out = {}
    for pkg in root.findall(f"{COMMON_NS}package"):
        name = pkg.findtext(f"{COMMON_NS}name") or ""
        if not name:
            continue
        v_el = pkg.find(f"{COMMON_NS}version")
        version = v_el.get("ver", "") if v_el is not None else ""
        requires = [
            e.get("name")
            for e in pkg.findall(f"{COMMON_NS}format/{RPM_NS}requires/{RPM_NS}entry")
            if e.get("name")
        ]
        out.setdefault(name, []).append((version, requires))
    return out


def fetch_distro_metadata(host, base, distro, distro_version, arch, component, cert_file, key_file):
    """Fetch and parse the native dependency metadata for one distro repo.

    Returns {package name: [(raw version, [dependency tokens])]}.
    """
    native = NATIVE_ARCH[(distro, arch)]
    if distro == "alpine":
        path = f"{base}/alpine/v{distro_version}/main/{native}/APKINDEX.tar.gz"
        return parse_apkindex(_fetch_bytes(host, path, cert_file, key_file))
    if distro == "debian":
        codename = DEBIAN_NUMBERS.get(distro_version, distro_version)
        path = f"{base}/debian/dists/{codename}/{component}/binary-{native}/Packages"
        return parse_deb_packages(_fetch_bytes(host, path, cert_file, key_file))
    if distro == "centos":
        repo = f"{base}/centos/{distro_version}/{native}"
        repomd = ET.fromstring(_fetch_bytes(host, f"{repo}/repodata/repomd.xml", cert_file, key_file))
        href = None
        for data in repomd.findall(f"{REPO_NS}data"):
            if data.get("type") == "primary":
                location = data.find(f"{REPO_NS}location")
                if location is not None:
                    href = location.get("href")
        if not href:
            raise RuntimeError(f"no primary metadata listed in {repo}/repodata/repomd.xml")
        return parse_rpm_primary(_fetch_bytes(host, f"{repo}/{href}", cert_file, key_file))
    raise RuntimeError(f"no dependency metadata layout known for distro '{distro}'")


def parse_yaml_image_tag(path, repository):
    """Find the tag of `image: <repository>:<tag>` in a Kubernetes manifest.

    Used for images pinned in example manifests rather than chart values, so
    the check reads the tag that is actually deployed instead of inferring it
    from a sibling image that happens to share a release train.
    """
    pattern = re.compile(r"^\s*-?\s*image:\s*[\"']?" + re.escape(repository) + r":([^\"'\s]+)")
    with open(path, "r") as f:
        for line in f:
            m = pattern.match(line)
            if m:
                return m.group(1)
    raise RuntimeError(f"image '{repository}' not found in {path}")


def parse_dockerfile_args(path):
    """Collect ARG NAME=VALUE defaults from a Dockerfile.

    Bare `ARG NAME` re-declarations carry no value and are skipped. The first
    definition wins, which is the top-of-file block that Makefile mirrors.
    """
    args = {}
    with open(path, "r") as f:
        for line in f:
            m = re.match(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(.*?)\s*$", line)
            if m:
                args.setdefault(m.group(1), m.group(2))
    return args


def resolve_distro_versions(path):
    """Resolve which distro versions NIC builds on, from the Dockerfile itself.

    Returns {distro: [versions]}. More than one version is legitimate mid
    migration, in which case every one of them must carry the dependency.
    """
    with open(path, "r") as f:
        text = f.read()

    alpine = sorted(set(re.findall(r"^FROM\s+alpine:(\d+\.\d+)", text, re.M)), key=parse_semver_key)

    debian = set()
    for token in re.findall(r"^FROM\s+debian:(\S+?)(?:-slim)?(?:@|\s)", text, re.M):
        debian.add(DEBIAN_CODENAMES.get(token, token))
    debian = sorted(debian, key=parse_semver_key)

    centos = sorted(set(re.findall(r"centos/(\d+)", text)), key=parse_semver_key)

    resolved = {"alpine": alpine, "debian": debian, "centos": centos}
    missing = [d for d, v in resolved.items() if not v]
    if missing:
        raise RuntimeError(f"could not resolve distro versions from {path} for: {', '.join(missing)}")
    return resolved


def normalize_version(scheme, ver):
    """Normalize a raw ver attribute into a comparable release string.

    Returns None when the version should be skipped.

    Normalizing before grouping matters: apk and deb/rpm publish the same
    release under different strings (WAF is 37.1.5.715.0 on Alpine but
    37.1+5.715.0 on Debian), and several nginx-plus point releases collapse
    into a single R release. Grouping on the raw ver would split one release
    into several.
    """
    if scheme == "nginx":
        m = re.match(r"^(\d+\.\d+\.\d+)", ver)
        return m.group(1) if m else None

    if scheme == "plus":
        # Plus modules carry the module version after the release: the njs
        # module is 37.1+1.0.1 on deb and 37.1.1.0.1 on apk. Dropping anything
        # after '+' collapses both onto R37.1, the same key nginx-plus itself
        # produces. No nginx-plus version contains '+', so this is a no-op there.
        clean = re.split(r"[-_~]", ver)[0].split("+")[0]
        parts = clean.split(".")
        if len(parts) == 1:
            return f"R{parts[0]}"
        return f"R{parts[0]}.{parts[1]}"

    if scheme in ("waf", "dos"):
        if "+" in ver:
            return re.split(r"[-_~]", ver)[0]
        if re.match(r"^\d+\.\d+\.\d+\.\d+", ver):
            parts = re.split(r"[-_~]", ver)[0].split(".")
            if scheme == "waf":
                return f"{parts[0]}.{parts[1]}+{'.'.join(parts[2:])}"
            return f"{parts[0]}+{'.'.join(parts[1:])}"
        return None

    return re.split(r"[-_~]", ver)[0]


def extract_releases(dep, root):
    """Map each release of a dependency to the repositories that carry it.

    Returns (releases, repos) where:
      releases: {normalized version: {(distro, distro_version, arch_label)}}
      repos:    {(distro, distro_version)} present anywhere in this index

    repos is needed to tell "this distro has a repo but not this version"
    apart from "this distro has no repo at all".

    Arch filtering only applies to the OS sets, never to version discovery, so
    a release published solely on a filtered arch still shows up in the version
    list (with an empty OS set).
    """
    releases = {}
    repos = set()

    for repo in root.findall("repository"):
        distro = repo.get("distro") or ""
        distro_version = repo.get("version") or ""
        arch = ARCH_LABELS.get(repo.get("arch") or "")
        tracked = bool(distro) and arch is not None
        if tracked:
            repos.add((distro, distro_version))

        for p in repo.findall(".//package"):
            if p.findtext("name") not in dep.packages:
                continue
            v_el = p.find("version")
            if v_el is None:
                continue
            key = normalize_version(dep.scheme, v_el.get("ver", ""))
            if key is None:
                continue
            entry = releases.setdefault(key, set())
            if tracked:
                entry.add((distro, distro_version, arch))

    return releases, repos


def version_matches(declared, available):
    """Prefix match on component boundaries.

    Mirrors how build/Dockerfile installs: `=${NAP_WAF_VERSION}*`,
    `~${AGENT_V3_VERSION}`. Declared 37.1+5.715 matches published
    37.1+5.715.0, and declared 3 matches 3.12.0, but 1.31.4 does not match
    1.31.45.
    """
    if available == declared:
        return True
    return available.startswith(declared) and available[len(declared)] in VERSION_BOUNDARIES


class Dependency:
    def __init__(self, name, section):
        self.name = name
        self.group = section.get("group", "default").strip()
        self.kind = section.get("kind", KIND_PACKAGE).strip()
        if self.kind not in (KIND_PACKAGE, KIND_IMAGE):
            raise RuntimeError(f"[{name}] unknown kind '{self.kind}'")
        self.host = section["host"]
        # Staging serves the same paths as production, so only the host differs.
        # Packages default to the staging package repository and images to the
        # staging container registry; a section can name its own if it stages
        # somewhere else. Defaulting rather than requiring a per-section key
        # means a newly added image is covered by --staging automatically.
        self.explicit_staging = bool(section.get("staging", "").strip())
        if self.explicit_staging:
            self.staging_host = section["staging"].strip()
        elif self.kind == KIND_IMAGE:
            self.staging_host = STAGING_REGISTRY
        else:
            self.staging_host = STAGING_HOST
        self.uri = section["uri"]
        self.version_source = section.get("version", "unpinned")
        self.packages = {p.strip() for p in section.get("packages", "").split(",") if p.strip()}
        self.scheme = section.get("scheme", "plain")
        # Dependency metadata (Packages / APKINDEX / primary.xml) lives under a
        # per-distro path below this base. It differs from uri only where the
        # repository embeds a version segment, so ${ARG} placeholders are
        # resolved from build/Dockerfile. Defaults to uri.
        self.meta_base = section.get("meta_base", "").strip() or self.uri
        self.deb_component = section.get("deb_component", "nginx").strip()
        # Images only: platforms the manifest list must advertise. Empty skips
        # the check, which is right for the single-arch NAP sidecars.
        self.platforms = [p.strip() for p in section.get("platforms", "").split(",") if p.strip()]
        # Images only: reported but never blocking. The NIC image at the version
        # being released does not exist yet -- it is the artifact being built,
        # not a dependency.
        self.gate = section.get("gate", "true").strip().lower() != "false"
        # Scope for the CURRENT check. Empty means "newest in the whole repo".
        # Needed where a repo carries several deliberately separate lines, e.g.
        # nginx-agent ships 2.x and 3.x side by side and a 2.x pin must not be
        # reported stale because 3.x exists.
        self.track = section.get("track", "").strip()
        self.distros = {}
        for token in section.get("distros", "").split():
            distro, _, arches = token.partition(":")
            self.distros[distro] = {a.strip() for a in arches.split(",") if a.strip()}

        # Filled in during the run.
        self.declared = None
        self.resolved = None
        self.newest = None
        self.oses = None
        self.repos = None
        self.platforms_found = []
        self.required_targets_cache = set()
        self.meta_base_resolved = self.meta_base
        self.status = STATUS_ERROR
        self.detail = ""

    def resolve_declared(self, dockerfile_args, chart_values=None, chart_yaml=None, repo_root=""):
        if self.version_source == "unpinned":
            self.declared = None
            return
        if self.version_source.startswith("literal:"):
            self.declared = self.version_source.split(":", 1)[1]
            return
        if self.version_source == "chart-appversion":
            self.declared = parse_chart_appversion(chart_yaml)
            return
        if self.version_source.startswith("chart-image:"):
            repository = self.version_source.split(":", 1)[1]
            tag = parse_chart_image_tag(chart_values, repository)
            # A commented-out tag means the chart falls back to appVersion.
            self.declared = tag if tag else parse_chart_appversion(chart_yaml)
            return
        if self.version_source.startswith("yaml-image:"):
            _, path, repository = self.version_source.split(":", 2)
            self.declared = parse_yaml_image_tag(os.path.join(repo_root, path), repository)
            return
        if self.version_source not in dockerfile_args:
            raise RuntimeError(f"ARG {self.version_source} not found in Dockerfile")
        self.declared = dockerfile_args[self.version_source]

    def required_targets(self, distro_versions):
        """Expand distro families into concrete (distro, version, arch) targets."""
        targets = set()
        for distro, arches in self.distros.items():
            for version in distro_versions.get(distro, []):
                for arch in arches:
                    targets.add((distro, version, arch))
        return targets


def load_config(path):
    parser = configparser.ConfigParser()
    parser.optionxform = str
    if not parser.read(path):
        raise RuntimeError(f"could not read config '{path}'")
    return [Dependency(name, parser[name]) for name in parser.sections()]


def evaluate_image(dep, cert_file, key_file, jwt=None):
    """Apply EXISTS / COMPLETE / CURRENT to a container image tag.

    COMPLETE means the manifest list advertises every required platform. There
    is no OS/arch matrix for images, so they are excluded from that report.
    """
    tags = fetch_image_tags(dep.host, dep.uri, cert_file, key_file, jwt)
    dep.newest = tags[-1] if tags else None

    if dep.declared is None:
        dep.status = STATUS_INFO
        dep.detail = "no tag declared, not gated"
        return

    exists, platforms = fetch_image_manifest(dep.host, dep.uri, dep.declared, cert_file, key_file, jwt)
    dep.platforms_found = platforms

    if not exists:
        if not dep.gate:
            dep.status = STATUS_INFO
            dep.detail = f"{dep.declared} not published yet (newest is {dep.newest or 'nothing'}), not gated"
            return
        dep.status = STATUS_MISSING
        dep.detail = f"{dep.declared} not published (newest is {dep.newest or 'nothing'})"
        return

    dep.resolved = dep.declared

    missing = [p for p in dep.platforms if p not in platforms]
    if missing:
        found = ", ".join(platforms) if platforms else "single-architecture manifest"
        dep.status = STATUS_INCOMPLETE if dep.gate else STATUS_INFO
        dep.detail = f"missing platform(s) {', '.join(missing)} -- manifest advertises {found}"
        return

    plat_note = ", ".join(platforms) if platforms else "single-architecture manifest"
    if dep.newest and dep.newest != dep.declared and parse_semver_key(dep.newest) > parse_semver_key(dep.declared):
        dep.status = STATUS_STALE
        dep.detail = f"{dep.newest} available; {plat_note}"
        return

    dep.status = STATUS_OK
    dep.detail = plat_note


def evaluate(dep, releases, repos, distro_versions):
    """Apply the EXISTS / COMPLETE / CURRENT assertions."""
    versions = sorted(releases.keys(), key=parse_semver_key)
    dep.repos = repos

    tracked = [v for v in versions if not dep.track or version_matches(dep.track, v)]
    dep.newest = tracked[-1] if tracked else None

    if dep.track and dep.declared is not None and not version_matches(dep.track, dep.declared):
        dep.oses = set()
        dep.status = STATUS_ERROR
        dep.detail = f"declared {dep.declared} is outside tracked line {dep.track}"
        return

    if dep.declared is None:
        dep.oses = releases.get(dep.newest, set()) if dep.newest else set()
        dep.status = STATUS_INFO
        dep.detail = "unpinned, not gated"
        return

    matching = [v for v in versions if version_matches(dep.declared, v)]
    if not matching:
        dep.oses = set()
        dep.status = STATUS_MISSING
        dep.detail = f"{dep.declared} not published (newest is {dep.newest or 'nothing'})"
        return

    dep.resolved = matching[-1]
    dep.oses = releases[dep.resolved]

    missing = sorted(dep.required_targets(distro_versions) - dep.oses)
    if missing:
        dep.status = STATUS_INCOMPLETE
        dep.detail = "absent on " + ", ".join(f"{d}:{v}/{a}" for d, v, a in missing)
        return

    if dep.newest != dep.resolved:
        dep.status = STATUS_STALE
        dep.detail = f"{dep.newest} available"
        return

    dep.status = STATUS_OK


def print_table(headers, rows):
    """Render a table, sizing columns by visible width so colour cannot skew it."""
    if not rows:
        return
    widths = [max(len(h), *(visible_len(r[i]) for r in rows)) + 2 for i, h in enumerate(headers)]

    def render(cells):
        return "".join(ljust_visible(c, w) for c, w in zip(cells, widths)).rstrip()

    print(render([paint(h, BOLD) for h in headers]))
    print(render(["-" * (w - 2) for w in widths]))
    for row in rows:
        print(render(row))


def print_repositories(deps):
    """List the distinct places checked, once, so the results table need not
    repeat a host and path on every row."""
    seen = []
    for d in deps:
        if (d.host, d.uri) not in seen:
            seen.append((d.host, d.uri))
    host_w = max(len(h) for h, _ in seen) + 2
    print(paint("Repositories", BOLD))
    for host, uri in seen:
        print(f"  {ljust_visible(host, host_w)}{uri}")


def target_cell(dep, distro, dver):
    """One build target's availability for a package, for the results table.

    n/a means NIC does not install this package on that OS, which is different
    from the package being absent.
    """
    required = {a for d, v, a in dep.required_targets_cache if (d, v) == (distro, dver)}
    if not required:
        return paint("n/a", GREY)
    if dep.oses is None:
        return paint("?", BRIGHT_RED)
    found = sorted(a for d, v, a in dep.oses if (d, v) == (distro, dver))
    if not found:
        return paint("MISSING", RED)
    if required - set(found):
        return paint("+".join(found) + "!", YELLOW)
    return paint("+".join(found), GREEN)


def build_targets(distro_versions):
    """Build targets in Dockerfile stage order, not alphabetical."""
    order = ("alpine", "debian", "centos")
    targets = []
    for distro in order:
        for version in distro_versions.get(distro, []):
            targets.append((distro, version))
    for distro in sorted(set(distro_versions) - set(order)):
        for version in distro_versions[distro]:
            targets.append((distro, version))
    return targets


def print_package_results(deps, distro_versions):
    targets = build_targets(distro_versions)
    headers = ["Dependency", "Declared", "Resolved", "Newest"]
    headers += [f"{distro}:{dver}" for distro, dver in targets]
    headers += ["Status"]

    rows = []
    for d in deps:
        d.required_targets_cache = d.required_targets(distro_versions)
        row = [d.name, d.declared or "-", d.resolved or "-", d.newest or "-"]
        row += [target_cell(d, distro, dver) for distro, dver in targets]
        row += [paint(d.status, STATUS_COLORS.get(d.status))]
        rows.append(row)

    print(f"\n{paint('Packages', BOLD)}  (arches per build target: x86 = x86_64/amd64, arm = aarch64/arm64)")
    print_table(headers, rows)


def print_image_results(deps):
    headers = ["Dependency", "Declared", "Resolved", "Newest", "Platforms", "Status"]
    rows = []
    for d in deps:
        if d.platforms_found:
            missing = [p for p in d.platforms if p not in d.platforms_found]
            cell = ", ".join(d.platforms_found)
            cell = paint(cell + " !", YELLOW) if missing else paint(cell, GREEN)
        elif d.resolved:
            cell = paint("single-arch", GREY)
        else:
            cell = paint("-", GREY)
        rows.append(
            [
                d.name,
                d.declared or "-",
                d.resolved or "-",
                d.newest or "-",
                cell,
                paint(d.status, STATUS_COLORS.get(d.status)),
            ]
        )

    print(f"\n{paint('Images', BOLD)}")
    print_table(headers, rows)


def resolve_meta_base(template, dockerfile_args):
    """Substitute ${ARG} placeholders in a metadata base path.

    NGINX_PLUS_MAJOR is synthesised the way the Dockerfile derives it
    (${NGINX_PLUS_VERSION%%.*}), because the DoS repository is keyed on the
    Plus major alone.
    """
    values = dict(dockerfile_args)
    values["NGINX_PLUS_MAJOR"] = values.get("NGINX_PLUS_VERSION", "").split(".")[0]

    def substitute(match):
        key = match.group(1)
        if not values.get(key):
            raise RuntimeError(f"meta_base references unknown or empty ARG {key}")
        return values[key]

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", substitute, template)


def select_metadata_entry(dep, entries, want):
    """Pick the metadata entry matching the version being validated.

    Packages files list every published version, so without this the inventory
    would union the dependencies of every release ever shipped -- which showed
    up as fourteen different nginx-rX.Y.Z ABI pins instead of one.
    """
    matches = [
        (raw, deps) for raw, deps in entries if normalize_version(dep.scheme, raw) == want
    ]
    if not matches:
        return None
    matches.sort(key=lambda pair: parse_semver_key(pair[0]))
    return matches[-1]


def dependency_identity(token):
    """Strip the version constraint from a dependency token for deduplication.

      debian  libc6 (>= 2.34)                    -> libc6
      alpine  app-protect-engine=11.792.0-r1     -> app-protect-engine
              nginx~1.31.4                       -> nginx
      centos  libssl.so.3(OPENSSL_3.0.0)(64bit)  -> libssl.so.3
              rtld(GNU_HASH)                     -> rtld

    Without this, rpm symbol versions alone produce thirty-odd entries for one
    library and "distinct dependencies" stops meaning anything.

    This removes constraints only. It deliberately does NOT map identifiers
    between distros: libssl3t64, so:libssl.so.3 and libssl.so.3 stay separate,
    because any such mapping would be guesswork.
    """
    return re.split(r"[(=<>~]", token, maxsplit=1)[0].strip()


def print_dependency_inventory(deps, distro_versions, arch, cert_file, key_file):
    print(f"\n{paint('Dependency inventory', BOLD)}  (what our packages depend on -- never gated)")
    print(f"  Architecture {arch}. Identifiers are verbatim per distro and are not comparable")
    print("  across them: the same library is a package name on Debian, a soname on Alpine")
    print("  and a soname plus symbol version on CentOS/UBI.")
    print("  Debian Recommends and Suggests are excluded -- images install with")
    print("  --no-install-recommends --no-install-suggests.")

    metadata_cache = {}
    for distro, dver in build_targets(distro_versions):
        members = [d for d in deps if arch in d.distros.get(distro, set())]
        if not members:
            continue

        native = NATIVE_ARCH[(distro, arch)]
        fmt = {"alpine": "apk", "debian": "deb", "centos": "rpm"}[distro]
        print(f"\n{paint(f'{distro}:{dver} / {native}', BOLD)}  --  {fmt}")

        per_package = []
        union = {}
        for dep in members:
            want = dep.resolved or dep.newest
            if not want:
                per_package.append((dep.name, None, "no resolved version to look up"))
                continue

            key = (dep.host, dep.meta_base_resolved, distro, dver, dep.deb_component)
            try:
                if key not in metadata_cache:
                    metadata_cache[key] = fetch_distro_metadata(
                        dep.host, dep.meta_base_resolved, distro, dver, arch, dep.deb_component, cert_file, key_file
                    )
                metadata = metadata_cache[key]
            except Exception as e:  # a missing repo is reported, not fatal
                per_package.append((dep.name, None, str(e)))
                continue

            for pkg_name in sorted(dep.packages):
                entries = metadata.get(pkg_name)
                if not entries:
                    continue
                selected = select_metadata_entry(dep, entries, want)
                if selected is None:
                    per_package.append((pkg_name, None, f"{want} not present in {fmt} metadata"))
                    continue
                raw, tokens = selected
                per_package.append((pkg_name, sorted(tokens), raw))
                for token in tokens:
                    union.setdefault(dependency_identity(token), set()).add(pkg_name)

        label_w = max((len(name) for name, _, _ in per_package), default=10) + 2
        for name, tokens, note in per_package:
            if tokens is None:
                print(f"  {ljust_visible(name, label_w)}{paint(note, YELLOW)}")
                continue
            # Plain text only: textwrap counts escape sequences as width.
            body = ", ".join(tokens) if tokens else "(none)"
            print(
                textwrap.fill(
                    body,
                    width=110,
                    initial_indent="  " + name.ljust(label_w - 2) + "  ",
                    subsequent_indent=" " * (label_w + 2),
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )

        if union:
            print(f"\n  {paint(f'Distinct dependencies ({len(union)})', BOLD)}")
            id_w = max(len(k) for k in union) + 2
            for identity in sorted(union):
                requiring = ", ".join(sorted(union[identity]))
                print(
                    textwrap.fill(
                        requiring,
                        width=110,
                        initial_indent="    " + identity.ljust(id_w - 2) + "  ",
                        subsequent_indent=" " * (id_w + 4),
                        break_long_words=False,
                        break_on_hyphens=False,
                    )
                )


def wrap_names(names):
    """Indent and wrap a dependency list so a long verdict does not run off."""
    return textwrap.fill(
        ", ".join(names),
        width=100,
        initial_indent="  ",
        subsequent_indent="  ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def print_details(deps):
    for d in deps:
        if d.detail:
            label = paint(d.status, STATUS_COLORS.get(d.status))
            print(f"  {ljust_visible(label, 11)}{d.name}: {d.detail}")


def print_matrix_legend(deps):
    """Print the matrix key once, ahead of the per-group matrices."""
    print("\nOS availability (version being validated, see Resolved column above)")
    print("  x86 = x86_64/amd64   arm = aarch64/arm64")
    print(f"  {paint('MISSING', RED)} = required by a NIC build but not published")
    print(f"  {paint('!', YELLOW)}       = published, but not for every required arch")
    print(f"  {paint('-', GREY)}       = repo exists but this version is absent (not a NIC target)")
    print(f"  {paint('.', GREY)}       = no repo for this distro")
    if any(d.oses is None for d in deps):
        print(f"  {paint('?', BRIGHT_RED)}       = index could not be fetched")


def print_os_matrix(deps, distro_versions, os_filter=None, title=None):
    """Print an OS/arch availability matrix for the version being validated.

    Rendered per group: one matrix spanning every package would be hundreds of
    columns wide.
    """
    rows = set()
    for d in deps:
        if d.oses:
            rows.update((distro, dver) for distro, dver, _arch in d.oses)
    # Always show the targets NIC builds on, even when nothing provides them.
    for d in deps:
        rows.update((distro, dver) for distro, dver, _arch in d.required_targets(distro_versions))

    if os_filter:
        rows = {r for r in rows if r[0] in os_filter}
    if not rows:
        print(f"\n{title or 'OS availability'}: no data.")
        return

    ordered = sorted(rows, key=lambda r: (r[0], parse_semver_key(r[1])))
    labels = [f"{distro}:{dver}" for distro, dver in ordered]

    columns = []
    for d in deps:
        targets = d.required_targets(distro_versions)
        cells = []
        for distro, dver in ordered:
            if d.oses is None:
                cells.append(paint("?", BRIGHT_RED))
                continue
            arches = sorted(a for dd, vv, a in d.oses if (dd, vv) == (distro, dver))
            required = {a for dd, vv, a in targets if (dd, vv) == (distro, dver)}
            # Only rows NIC actually builds on are coloured, so the handful of
            # target rows stand out from the informational ones.
            if arches:
                cell = "+".join(arches)
                if required - set(arches):
                    cell = paint(cell + "!", YELLOW)
                elif required:
                    cell = paint(cell, GREEN)
            elif required:
                cell = paint("MISSING", RED)
            elif (distro, dver) in (d.repos or set()):
                cell = paint("-", GREY)
            else:
                cell = paint(".", GREY)
            cells.append(cell)
        columns.append((d.name, cells))

    label_w = max([len("OS")] + [len(x) for x in labels]) + 2
    widths = [max([len(name)] + [visible_len(c) for c in cells]) + 2 for name, cells in columns]

    def render(first, rest):
        out = ljust_visible(first, label_w)
        for cell, width in zip(rest, widths):
            out += ljust_visible(cell, width)
        return out.rstrip()

    if title:
        print(f"\n{paint(title, BOLD)}")
    print(render(paint("OS", BOLD), [paint(name, BOLD) for name, _ in columns]))
    print(render("-" * (label_w - 2), ["-" * (w - 2) for w in widths]))
    for i, label in enumerate(labels):
        print(render(label, [cells[i] for _, cells in columns]))


def run(args):
    global _COLOR
    _COLOR = should_color(args.color)

    deps = load_config(args.config)

    # Captured before --group filtering so combining --group and --host does not
    # reject a name that is legitimately in the config.
    groups = {d.group for d in deps}
    known = {d.name for d in deps} | groups

    if args.group:
        wanted = {g.strip() for g in args.group.split(",") if g.strip()}
        unknown = wanted - groups
        if unknown:
            raise RuntimeError(
                f"--group names not in config: {', '.join(sorted(unknown))}. Known: {', '.join(sorted(groups))}"
            )
        deps = [d for d in deps if d.group in wanted]

    host_overrides = {}
    for item in args.host or []:
        name, _, host = item.partition("=")
        if not host:
            raise RuntimeError(f"--host expects <dep|group>=<host>, got '{item}'")
        host_overrides[name] = host
    unknown = set(host_overrides) - known
    if unknown:
        raise RuntimeError(f"--host names match no dependency or group: {', '.join(sorted(unknown))}")

    if args.staging and args.all_hosts:
        raise RuntimeError("--staging and --all-hosts are mutually exclusive")

    # Precedence is explicit here rather than dependent on argv order:
    # --host <dep>= beats --host <group>=, which beats --staging/--all-hosts,
    # which beats the config.
    for dep in deps:
        if args.staging:
            dep.host = dep.staging_host
        elif args.all_hosts and dep.kind == KIND_PACKAGE:
            # A package mirror is not a container registry, so images are never
            # swept by --all-hosts. --staging uses each image's own staging key.
            dep.host = args.all_hosts
        dep.host = host_overrides.get(dep.group, dep.host)
        dep.host = host_overrides.get(dep.name, dep.host)

    dockerfile_args = parse_dockerfile_args(args.dockerfile)
    distro_versions = resolve_distro_versions(args.dockerfile)
    for dep in deps:
        dep.meta_base_resolved = resolve_meta_base(dep.meta_base, dockerfile_args)

    environment = "staging" if args.staging else "custom" if args.all_hosts else "production"
    print(f"Dockerfile:   {args.dockerfile}")
    print(f"Chart:        {args.chart_values}")
    print(f"Build OSes:   " + "  ".join(f"{d}:{','.join(v)}" for d, v in sorted(distro_versions.items())))
    print(f"Environment:  {environment}")
    if args.all_hosts:
        images = [d.name for d in deps if d.kind == KIND_IMAGE]
        if images:
            print(paint("Note: --all-hosts covers packages only, images left alone: " + ", ".join(images), GREY))

    # Every staging path is behind mTLS, including the OSS ones that need no
    # credentials in production. Say so up front rather than emitting seven
    # identical 401s.
    if not args.index_dir and any(d.host == STAGING_HOST for d in deps):
        if not (os.path.exists(args.cert) and os.path.exists(args.key)):
            print(
                paint(
                    f"Warning: {STAGING_HOST} requires a client certificate for every path, "
                    f"but '{args.cert}' or '{args.key}' is missing -- expect HTTP 401.",
                    YELLOW,
                )
            )

    # The private registries authenticate with the subscription JWT, not the
    # client certificate. Docker Hub is anonymous and needs neither.
    registry_jwt = load_registry_jwt(args.jwt)
    if registry_jwt is None and any(d.kind == KIND_IMAGE and d.host != DOCKER_HUB_HOST for d in deps):
        print(
            paint(
                f"Warning: '{args.jwt}' is missing -- private registry image checks "
                f"will get HTTP 401. Download it from MyF5.",
                YELLOW,
            )
        )
    print()
    print_repositories(deps)

    # Many packages share a repository -- /nginx/mainline backs seven entries and
    # /plus four. Fetch each index once; without this the run would pull ~24 MB
    # of duplicate XML.
    index_cache = {}

    def load_index(dep):
        key = (dep.host, dep.uri) if not args.index_dir else dep.uri
        if key not in index_cache:
            if args.index_dir:
                path = os.path.join(args.index_dir, f"{dep.uri.strip('/').replace('/', '-')}.xml")
                index_cache[key] = ET.parse(path).getroot()
            else:
                index_cache[key] = fetch_index_xml(dep.host, dep.uri, args.cert, args.key)
        return index_cache[key]

    for dep in deps:
        try:
            dep.resolve_declared(dockerfile_args, args.chart_values, args.chart_yaml, args.repo_root)
            if dep.kind == KIND_IMAGE:
                if args.index_dir:
                    dep.status = STATUS_INFO
                    dep.detail = "skipped: --index-dir has no offline data for registries"
                    continue
                evaluate_image(dep, args.cert, args.key, registry_jwt)
            else:
                root = load_index(dep)
                releases, repos = extract_releases(dep, root)
                evaluate(dep, releases, repos, distro_versions)
        except Exception as e:  # any failure to resolve or fetch is a failed check
            # gate = false means "report, never block". That has to hold for
            # fetch and parse failures too, otherwise an ungated dependency can
            # still fail a release -- which is the opposite of ungated.
            dep.status = STATUS_ERROR if dep.gate else STATUS_INFO
            dep.detail = str(e) if dep.gate else f"{e} (not gated)"

    # Packages and images get separate tables: a distro:arch column means
    # nothing for an image, and a platform list means nothing for a package.
    packages = [d for d in deps if d.kind == KIND_PACKAGE]
    images = [d for d in deps if d.kind == KIND_IMAGE]

    if packages:
        print_package_results(packages, distro_versions)
    if images:
        print_image_results(images)
    print()
    print_details(deps)

    # Inventory of what our packages themselves depend on. Reported only, and
    # deliberately after the verdict inputs are computed so it can reuse the
    # resolved versions. Failures here never change the exit code.
    if args.deps and packages:
        if args.index_dir:
            print(paint("\nDependency inventory skipped: --index-dir has no offline metadata.", YELLOW))
        else:
            print_dependency_inventory(packages, distro_versions, args.deps_arch, args.cert, args.key)

    # The per-group matrices cover every distro the repositories carry, not just
    # the ones NIC builds on. That is planning information rather than release
    # gating, so it is opt-in now that the build targets are in the table.
    if args.matrix and packages:
        os_filter = {d.strip() for d in args.os.split(",") if d.strip()}
        print_matrix_legend(packages)
        seen = []
        for dep in packages:  # config order, not alphabetical
            if dep.group not in seen:
                seen.append(dep.group)
        for group in seen:
            members = [d for d in packages if d.group == group]
            print_os_matrix(members, distro_versions, os_filter, title=group)

    blocking = [d for d in deps if d.status in BLOCKING]
    stale = [d for d in deps if d.status == STATUS_STALE]

    print()
    if blocking:
        print(
            paint(f"FAIL: {len(blocking)} dependency check(s) blocking:", f"{BOLD};{RED}")
            + "\n"
            + wrap_names(d.name for d in blocking)
        )
    if stale:
        print(
            paint(f"WARN: {len(stale)} newer version(s) available:", YELLOW)
            + "\n"
            + wrap_names(d.name for d in stale)
        )
    if not blocking and not stale:
        print(paint("PASS: all dependencies published and up to date", f"{BOLD};{GREEN}"))
    elif not blocking:
        print(paint("PASS: all dependencies published (with warnings)", GREEN))

    if blocking:
        return 1
    if stale and args.strict:
        return 1
    return 0


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--config",
        default=os.path.join(repo_root, ".github/data/dependency-check.ini"),
        help="Dependency config (default: .github/data/dependency-check.ini)",
    )
    parser.add_argument(
        "--dockerfile",
        default=os.path.join(repo_root, "build/Dockerfile"),
        help="Dockerfile to read declared versions and build OSes from (default: build/Dockerfile)",
    )
    parser.add_argument(
        "--chart-values",
        default=os.path.join(repo_root, "charts/nginx-ingress/values.yaml"),
        help="Chart values file to read image tags from (default: charts/nginx-ingress/values.yaml)",
    )
    parser.add_argument(
        "--chart-yaml",
        default=os.path.join(repo_root, "charts/nginx-ingress/Chart.yaml"),
        help="Chart.yaml to read appVersion from (default: charts/nginx-ingress/Chart.yaml)",
    )
    parser.add_argument(
        "--repo-root",
        default=repo_root,
        help="Repository root, used to resolve yaml-image paths (default: inferred from script location)",
    )
    parser.add_argument("--cert", default="nginx-repo.crt", help="Client certificate path (default: nginx-repo.crt)")
    parser.add_argument("--key", default="nginx-repo.key", help="Client key path (default: nginx-repo.key)")
    parser.add_argument(
        "--jwt",
        default="nginx-repo.jwt",
        help="NGINX subscription JWT for the private registries (default: nginx-repo.jwt)",
    )
    parser.add_argument("--host", action="append", help="Override a repository host: <dep>=<host>. Repeatable.")
    parser.add_argument(
        "--staging",
        action="store_true",
        help=f"Check every dependency against the staging repository ({STAGING_HOST}), "
        "where release candidates land. Requires a client certificate for all paths.",
    )
    parser.add_argument(
        "--all-hosts",
        metavar="HOST",
        help="Check every dependency against this host. Mutually exclusive with --staging.",
    )
    parser.add_argument("--strict", action="store_true", help="Also fail when a newer version is available")
    parser.add_argument(
        "--deps",
        action="store_true",
        help="Also list what our packages themselves depend on, per build target. "
        "Informational only -- never affects the exit code",
    )
    parser.add_argument(
        "--deps-arch",
        choices=("x86", "arm"),
        default="x86",
        help="Architecture for --deps (default: x86). Dependencies differ by arch because "
        "sonames are arch-specific",
    )
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="Also print the full per-group OS matrices, covering every distro the "
        "repositories carry rather than just the build targets",
    )
    parser.add_argument("--os", default="", help="Comma-separated distros to show in the matrix (default: all)")
    parser.add_argument(
        "--group",
        default="",
        help="Comma-separated groups to check, e.g. oss,nap-waf (default: all)",
    )
    parser.add_argument("--index-dir", help="Read <dep>.xml from this dir instead of fetching (offline debugging)")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Colourise the results. auto (default) disables colour in CI, when piped, "
        "when NO_COLOR is set, or for TERM=dumb",
    )

    args = parser.parse_args()
    try:
        sys.exit(run(args))
    except Exception as e:  # surface config errors as a failed check
        # stderr is a separate stream, so decide independently of stdout.
        prefix = "Error:" if not (_COLOR and sys.stderr.isatty()) else paint("Error:", f"{BOLD};{BRIGHT_RED}")
        print(f"{prefix} {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
