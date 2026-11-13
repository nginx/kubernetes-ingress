#!/usr/bin/env python3
"""Rewrite contributor credits in a GitHub release draft.

Runs after lucacome/draft-release. GitHub only credits the PR opener, which is
@nic-create-pr[bot] for cherry-picks and version bumps, and ignores everyone
else who committed to a PR. See docs/developer/cherry-pick-attribution-plan.md.

Env: GITHUB_TOKEN, GITHUB_REPOSITORY, RELEASE_ID
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NEVER_CREDIT = {"nic-create-pr[bot]", "web-flow", "github-actions[bot]"}
FALLBACK_ONLY = {"nginx-bot"}  # credited only when nobody else is left
CHERRY_PICK_OPENER = "nic-create-pr[bot]"
NEW_CONTRIBUTORS = "## New Contributors"

PR_URL = r"https://github\.com/[^/\s]+/[^/\s]+/pull/\d+"
CHANGE_RE = re.compile(rf"^\* (?P<title>.+?)(?: by (?P<credit>@.+?))? in (?P<urls>{PR_URL}(?:, {PR_URL})*)$")
NEW_CONTRIBUTOR_RE = re.compile(r"^\* @(?P<login>\S+) made their first contribution in ")
METADATA_RE = re.compile(r"<!--\s*nic-attribution:\s*(\{.*?\})\s*-->", re.DOTALL)
CHERRY_PICKED_RE = re.compile(r"\(cherry picked from commit ([0-9a-f]{40})\)")
NOREPLY_RE = re.compile(r"^(?:\d+\+)?([^@]+)@users\.noreply\.github\.com$", re.IGNORECASE)
UNSAFE_NAME_RE = re.compile(r"[\[\]()*_<>`&,@]")


@dataclass
class Person:
    login: str | None = None  # None for commit authors not linked to a GitHub account
    name: str | None = None
    email: str | None = None

    def key(self):
        return ("login:" + self.login if self.login else "email:" + (self.email or self.name or "")).lower()

    def render(self):
        return f"@{self.login}" if self.login else self.name


@dataclass
class Commit:
    authors: list
    parents: int = 1
    message: str = ""
    committer: Person | None = None


@dataclass
class PullRequest:
    number: int
    author: str | None
    author_is_bot: bool = False
    head_ref: str = ""
    body: str = ""
    commits: list = field(default_factory=list)


# --- credit rules -----------------------------------------------------------


def ident(p):
    return (p.login or p.name or "").lower()


def join(names):
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} & {names[-1]}"


def metadata(body):
    """Last nic-attribution block wins (cherry-pick bodies embed the original body)."""
    found = METADATA_RE.findall(body or "")
    try:
        data = json.loads(found[-1]) if found else {}
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def people(pr):
    """Opener plus non-merge commit authors / co-authors, deduplicated."""
    found = [Person(login=pr.author)] if pr.author else []
    for c in pr.commits:
        if c.parents == 1:  # skip merge commits, e.g. "Update branch"
            found += c.authors
    found = [p for p in found if (p.login or p.name) and ident(p) not in NEVER_CREDIT]
    known = {(p.email or "").lower() for p in found if p.login} | {(p.name or "").lower() for p in found if p.login}
    result, seen = [], set()
    for p in found:
        if not p.login:
            p.name = " ".join(UNSAFE_NAME_RE.sub("", p.name).split())
            if not p.name or (p.email or "").lower() in known or p.name.lower() in known:
                continue
        if p.key() not in seen:
            seen.add(p.key())
            result.append(p)
    return result


def authors_for(found, meta):
    """Logins first, plain names after; fall back to actor, then nginx-bot."""
    others = [p for p in found if ident(p) not in FALLBACK_ONLY]
    logins = [p for p in others if p.login]
    if logins:
        return logins + [p for p in others if not p.login]
    if meta.get("actor"):
        return [Person(login=str(meta["actor"]))]
    return [Person(login="nginx-bot")] if len(others) < len(found) else []


def credit_for(pr, gh, depth=0):
    """Return (authors, cherry-pick actor or None, original PR or None)."""
    meta = metadata(pr.body)
    is_pick = (pr.author or "").lower() == CHERRY_PICK_OPENER and "cherry-pick-" in pr.head_ref
    if not is_pick or depth >= 3:
        return authors_for(people(pr), meta), None, None

    actor = Person(login=str(meta["actor"])) if meta.get("actor") else None
    number = meta.get("source_pr")
    for c in pr.commits:  # legacy cherry-picks without metadata
        match = CHERRY_PICKED_RE.search(c.message)
        if match:
            actor = actor or (c.committer if c.committer and c.committer.login else None)
            number = number or gh.pr_for_commit(match.group(1))
    original = gh.pull_requests([int(number)]).get(int(number)) if number else None
    if original is None:
        print(f"::warning::Could not resolve the original PR for cherry-pick #{pr.number}")
        authors = authors_for(people(pr), {})
    else:
        authors = credit_for(original, gh, depth + 1)[0]
    if not authors:
        return ([actor] if actor else []), None, original
    if actor and len(authors) == 1 and authors[0].key() == actor.key():
        actor = None
    return authors, actor, original


def format_credit(authors, actors):
    if not authors:
        return ""
    text = join([p.render() for p in authors])
    return text + (f" (cherry-picked by {join([p.render() for p in actors])})" if actors else "")


def dedupe(found):
    seen = set()
    return [p for p in found if not (p.key() in seen or seen.add(p.key()))]


# --- body rewrite -----------------------------------------------------------


def rewrite(body, gh, repository):
    lines = body.split("\n")
    pr_re = re.compile(rf"^https://github\.com/{re.escape(repository)}/pull/(\d+)$", re.IGNORECASE)

    parsed, section = {}, ""
    for i, line in enumerate(lines):
        if line.startswith("## ") or line.startswith("**Full Changelog"):
            section = line.strip()
        match = CHANGE_RE.match(line)
        if section == NEW_CONTRIBUTORS or not match:
            continue
        numbers = [pr_re.match(u.strip()) for u in match.group("urls").split(",")]
        if all(numbers):
            parsed[i] = (match, [int(n.group(1)) for n in numbers])

    prs = gh.pull_requests(sorted({n for _, ns in parsed.values() for n in ns}))
    originals = []
    for i, (match, numbers) in parsed.items():
        if not all(n in prs for n in numbers):
            print(f"::warning::Could not fetch PR data, leaving unchanged: {lines[i]}")
            continue
        authors, actors = [], []
        for n in numbers:
            a, actor, original = credit_for(prs[n], gh)
            authors += a
            actors += [actor] if actor else []
            originals += [original] if original else []
        authors = dedupe(authors)
        authors = [p for p in authors if p.login] + [p for p in authors if not p.login]
        actors = [p for p in dedupe(actors) if p.key() not in {a.key() for a in authors}]
        credit = format_credit(authors, actors)
        lines[i] = f"* {match.group('title')}{f' by {credit}' if credit else ''} in {match.group('urls')}"

    return "\n".join(new_contributors(lines, originals, gh, repository))


def new_contributors(lines, originals, gh, repository):
    """Drop bot entries and add first-time authors of cherry-picked PRs."""
    listed = set()
    kept = []
    for line in lines:
        match = NEW_CONTRIBUTOR_RE.match(line)
        if match:
            login = match.group("login").lower()
            if login in NEVER_CREDIT | FALLBACK_ONLY:
                continue
            listed.add(login)
        kept.append(line)
    lines = kept

    additions = []
    for pr in {o.number: o for o in originals}.values():
        login = pr.author
        if not login or pr.author_is_bot or login.lower() in listed | NEVER_CREDIT | FALLBACK_ONLY:
            continue
        if gh.is_first_contribution(login, pr.number):
            listed.add(login.lower())
            additions.append(
                f"* @{login} made their first contribution in https://github.com/{repository}/pull/{pr.number}"
            )

    if NEW_CONTRIBUTORS in lines:
        start = lines.index(NEW_CONTRIBUTORS)
        end = start + 1
        while end < len(lines) and not lines[end].startswith(("#", "**Full Changelog")):
            end += 1
        entries = [line for line in lines[start + 1 : end] if line.strip()]
        if not entries and not additions:
            del lines[start:end]  # section now empty
        else:
            last = max(i for i in range(start, end) if i == start or lines[i].strip())
            lines[last + 1 : last + 1] = additions
    elif additions:
        anchor = next((i for i, line in enumerate(lines) if line.startswith("**Full Changelog")), None)
        if anchor is None:
            lines += ["", NEW_CONTRIBUTORS, *additions]
        else:
            lines[anchor:anchor] = [NEW_CONTRIBUTORS, *additions, ""]
    return lines


# --- GitHub API -------------------------------------------------------------

PR_QUERY = """
fragment PR on PullRequest {
  number headRefName body
  author { __typename login }
  commits(first: 100) { nodes { commit {
    message
    parents { totalCount }
    committer { name email user { login } }
    authors(first: 20) { nodes { name email user { login } } }
  } } }
}
"""


def to_person(node):
    if not node:
        return None
    match = NOREPLY_RE.match(node.get("email") or "")
    login = (node.get("user") or {}).get("login") or (match.group(1) if match else None)
    return Person(login=login, name=node.get("name"), email=node.get("email"))


class GitHub:
    def __init__(self, token, repository):
        self.repository = repository
        self.owner, self.name = repository.split("/", 1)
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "nic-release-notes-attribution",
        }
        self.cache = {}

    def request(self, method, path, payload=None, params=None):
        url = f"https://api.github.com{path}" + (f"?{urlencode(params)}" if params else "")
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {**self.headers, **({"Content-Type": "application/json"} if data else {})}
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=60) as response:
            return json.loads(response.read() or b"{}")

    def graphql(self, query):
        result = self.request("POST", "/graphql", {"query": query})
        for error in result.get("errors") or []:
            print(f"::warning::GraphQL: {error.get('message')}")
        return (result.get("data") or {}).get("repository") or {}

    def pull_requests(self, numbers):
        missing = [n for n in numbers if n not in self.cache]
        for start in range(0, len(missing), 25):
            chunk = missing[start : start + 25]
            fields = " ".join(f"pr{n}: pullRequest(number: {n}) {{ ...PR }}" for n in chunk)
            repo = self.graphql(
                f'query {{ repository(owner: "{self.owner}", name: "{self.name}") {{ {fields} }} }} {PR_QUERY}'
            )
            for n in chunk:
                if repo.get(f"pr{n}"):
                    self.cache[n] = self.to_pr(repo[f"pr{n}"])
        return {n: self.cache[n] for n in numbers if n in self.cache}

    @staticmethod
    def to_pr(node):
        author = node.get("author") or {}
        is_bot = author.get("__typename") == "Bot"
        login = author.get("login")
        if login and is_bot and not login.endswith("[bot]"):
            login += "[bot]"
        commits = [
            Commit(
                authors=[to_person(a) for a in c["commit"]["authors"]["nodes"]],
                parents=c["commit"]["parents"]["totalCount"],
                message=c["commit"]["message"] or "",
                committer=to_person(c["commit"]["committer"]),
            )
            for c in node["commits"]["nodes"]
        ]
        return PullRequest(node["number"], login, is_bot, node["headRefName"] or "", node["body"] or "", commits)

    def pr_for_commit(self, sha):
        repo = self.graphql(
            f'query {{ repository(owner: "{self.owner}", name: "{self.name}") {{ object(oid: "{sha}") {{ '
            "... on Commit { associatedPullRequests(first: 5) { nodes { number merged } } } } } }"
        )
        prs = ((repo.get("object") or {}).get("associatedPullRequests") or {}).get("nodes") or []
        return next((p["number"] for p in prs if p["merged"]), None)

    def is_first_contribution(self, login, number):
        query = f"repo:{self.repository} is:pr is:merged author:{login}"
        params = {"q": query, "sort": "created", "order": "asc", "per_page": 1}
        items = self.request("GET", "/search/issues", params=params).get("items") or []
        return bool(items) and items[0]["number"] == number


def main():
    token, repository = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    release_id = os.environ.get("RELEASE_ID")
    if not token or not repository:
        print("ERROR: GITHUB_TOKEN and GITHUB_REPOSITORY must be set")
        return 1
    if not release_id:
        print("No RELEASE_ID provided, nothing to do")
        return 0
    gh = GitHub(token, repository)
    release = gh.request("GET", f"/repos/{repository}/releases/{release_id}")
    if not release.get("draft"):
        print(f"Release {release_id} is not a draft, leaving it unchanged")
        return 0
    body = release.get("body") or ""
    new_body = rewrite(body, gh, repository)
    if new_body != body:
        gh.request("PATCH", f"/repos/{repository}/releases/{release_id}", {"body": new_body})
        print("Updated release draft attribution")
    return 0


if __name__ == "__main__":
    sys.exit(main())
