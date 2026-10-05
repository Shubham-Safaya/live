"""
Release Radar: a weekly brief of dependency changes that need attention.

Adapted from the Release Radar agent in awesome-llm-apps, as a single
standard-library script that fits this hub's GitHub Actions setup.

It scans every non-fork repo owned by OWNER (or a local folder of clones),
collects GitHub Actions, requirements.txt / pyproject.toml packages and
package.json packages, and reports only what needs a decision:

  security    release notes mention a CVE / GHSA / security fix
  breaking    release notes mention a breaking change or removed support
  yanked      the newest PyPI release is yanked, or npm marks it deprecated
  runtime     an Action's release moves to a new Node runtime
  major       a newer major exists than the one you pin, or a >= floor will
              auto-install a new major on the next run
  deprecation release notes announce a deprecation or end of life

Routine patch and minor releases are dropped.

Default is a dry run that prints the brief. With --issue it keeps one open
issue labeled `release-radar` in ISSUE_REPO: the body always holds the
current brief, a comment is added only when new findings appear, and the
issue is closed when nothing is left.

Usage:
  python scripts/release_radar.py --owner Shubham-Safaya            # dry run
  python scripts/release_radar.py --local ~/code --days 30          # scan clones
  python scripts/release_radar.py --sample                          # offline demo
  python scripts/release_radar.py --owner X --issue --issue-repo X/live

Env: READ_TOKEN (optional, needed for private repos and higher rate limits),
ISSUE_TOKEN (needs issues:write on the issue repo, only with --issue).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

GITHUB_API = "https://api.github.com"
LABEL = "release-radar"
FP_MARKER = re.compile(r"<!-- radar-fingerprints: (.*?) -->", re.S)
FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

SIGNAL_TERMS = {
    "security": ("security fix", "security vulnerability", "vulnerability", "cve-", "ghsa-",
                 "security advisory"),
    "breaking": ("breaking change", "breaking:", "not backward compatible", "not backwards compatible",
                 "migration required", "removed support", "drop support", "dropped support",
                 "drops support"),
    "deprecation": ("deprecated", "deprecation", "will be removed", "end of life", "end-of-life"),
}
NODE_RUNTIME = re.compile(r"\bnode\s?(?:js\s?)?(\d{2})\b", re.I)
SEVERITY = {"security": 100, "breaking": 90, "yanked": 85, "runtime": 75, "major": 70, "deprecation": 60}
LABELS = {"security": "Security fix", "breaking": "Breaking change", "yanked": "Yanked or deprecated",
          "runtime": "Runtime change", "major": "New major version", "deprecation": "Deprecation"}

FetchJson = Callable[[str], Optional[object]]


# ── Data model ──────────────────────────────────────────────────────

@dataclass
class Dependency:
    ecosystem: str          # "action" | "pypi" | "npm"
    name: str               # actions/checkout, requests, vite
    spec: str               # v4, >=2.31, ^5.4.11
    used_by: set[str] = field(default_factory=set)


@dataclass
class Finding:
    signal: str
    dependency: str
    ecosystem: str
    detail: str
    used_by: list[str]
    url: str = ""
    key: str = ""

    @property
    def score(self) -> int:
        return SEVERITY[self.signal]

    @property
    def fingerprint(self) -> str:
        return f"{self.signal}:{self.ecosystem}:{self.dependency}:{self.key or self.detail}"


# ── Version helpers ─────────────────────────────────────────────────

def major_of(version: str) -> Optional[int]:
    m = re.match(r"^\s*v?(\d+)", version or "")
    return int(m.group(1)) if m else None


TAG_REF = re.compile(r"^v?\d+(?:\.\d+){0,2}$")


def floor_major(spec: str, ecosystem: str = "") -> Optional[int]:
    """Lowest major a spec allows: ^5.4 -> 5, >=2.31 -> 2, v4 -> 4, ~=1.2 -> 1.
    Action refs that are commit SHAs or branches have no major."""
    spec = (spec or "").strip()
    if ecosystem == "action" and not TAG_REF.match(spec):
        return None
    m = re.search(r"(?:\^|~=|~|>=|==|=|v|^)\s*(\d+)", spec)
    return int(m.group(1)) if m else None


def caps_major(ecosystem: str, spec: str) -> bool:
    """True when the spec cannot reach a new major on its own."""
    spec = spec or ""
    if ecosystem == "action":
        return True
    if ecosystem == "npm":
        return not spec.strip().startswith((">", "*")) and spec.strip() not in ("", "latest")
    return "<" in spec or "==" in spec or "~=" in spec  # pypi


# ── Manifest parsing ────────────────────────────────────────────────

ACTION_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^@\s'\"]*)?@([^\s'\"#]+)", re.M)
REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?\s*([^;#]*)")


def parse_workflow(text: str) -> list[tuple[str, str]]:
    return [(name, ref) for name, ref in ACTION_RE.findall(text)]


def parse_requirement(line: str) -> Optional[tuple[str, str]]:
    line = line.strip()
    if not line or line.startswith(("#", "-", "git+", "http")):
        return None
    m = REQ_RE.match(line)
    return (m.group(1).lower(), m.group(3).strip()) if m else None


def parse_requirements(text: str) -> list[tuple[str, str]]:
    return [r for r in (parse_requirement(l) for l in text.splitlines()) if r]


def parse_pyproject(text: str) -> list[tuple[str, str]]:
    project = tomllib.loads(text).get("project", {})
    lines = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        lines += extra
    return [r for r in (parse_requirement(l) for l in lines) if r]


def parse_package_json(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return [(n, s) for n, s in deps.items() if not s.startswith(("file:", "link:", "workspace:", "git"))]


def collect(files: dict[str, dict[str, str]]) -> dict[tuple[str, str], Dependency]:
    """files: {repo: {path: text}} -> dependencies keyed by (ecosystem, name)."""
    deps: dict[tuple[str, str], Dependency] = {}

    def add(eco, name, spec, repo):
        dep = deps.setdefault((eco, name), Dependency(eco, name, spec))
        dep.used_by.add(repo)
        new, old = floor_major(spec, eco), floor_major(dep.spec, eco)
        if new is not None and (old is None or new < old):
            dep.spec = spec  # keep the oldest pin, it is the one most at risk

    for repo, paths in files.items():
        for path, text in paths.items():
            try:
                if path.startswith(".github/workflows/"):
                    pairs, eco = parse_workflow(text), "action"
                elif path.endswith("requirements.txt"):
                    pairs, eco = parse_requirements(text), "pypi"
                elif path.endswith("pyproject.toml"):
                    pairs, eco = parse_pyproject(text), "pypi"
                elif path.endswith("package.json"):
                    pairs, eco = parse_package_json(text), "npm"
                else:
                    continue
            except (ValueError, tomllib.TOMLDecodeError) as e:
                print(f"  skip {repo}/{path}: {e}", file=sys.stderr)
                continue
            for name, spec in pairs:
                add(eco, name, spec, repo)
    return deps


# ── Sources of manifests ────────────────────────────────────────────

MANIFESTS = ("requirements.txt", "pyproject.toml", "package.json")


def local_files(root: Path) -> dict[str, dict[str, str]]:
    out = {}
    for repo in sorted(p for p in root.iterdir() if (p / ".git").exists()):
        paths = {}
        for wf in sorted((repo / ".github" / "workflows").glob("*.y*ml")):
            paths[f".github/workflows/{wf.name}"] = wf.read_text(errors="ignore")
        for name in MANIFESTS:
            if (repo / name).exists():
                paths[name] = (repo / name).read_text(errors="ignore")
        if paths:
            out[repo.name] = paths
    return out


def github_files(owner: str, gh: "GitHub") -> dict[str, dict[str, str]]:
    repos = gh.get(f"/users/{owner}/repos?per_page=100&type=owner") or []
    if gh.token:  # a personal token also lists private repos; the Actions token cannot
        try:
            mine = gh.get("/user/repos?per_page=100&affiliation=owner") or []
        except urllib.error.HTTPError:
            mine = []
        seen = {r["full_name"] for r in repos}
        repos += [r for r in mine if r["full_name"] not in seen and r["owner"]["login"].lower() == owner.lower()]
    out = {}
    for r in repos:
        if r.get("fork") or r.get("archived"):
            continue
        full, paths = r["full_name"], {}
        listing = gh.get(f"/repos/{full}/contents/.github/workflows") or []
        for item in listing if isinstance(listing, list) else []:
            if item.get("name", "").endswith((".yml", ".yaml")):
                text = gh.file(full, item["path"])
                if text:
                    paths[item["path"]] = text
        for name in MANIFESTS:
            text = gh.file(full, name)
            if text:
                paths[name] = text
        if paths:
            out[r["name"]] = paths
    return out


# ── HTTP ────────────────────────────────────────────────────────────

def http_json(url: str, token: str = "", method: str = "GET", body: Optional[dict] = None):
    headers = {"User-Agent": "release-radar", "Accept": "application/json"}
    if token and url.startswith(GITHUB_API):
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
    data = json.dumps(body).encode() if body is not None else None
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


class GitHub:
    def __init__(self, token: str = "", fetch: Optional[FetchJson] = None):
        self.token = token
        self._fetch = fetch

    def get(self, path: str):
        url = GITHUB_API + path
        return self._fetch(url) if self._fetch else http_json(url, self.token)

    def file(self, full: str, path: str) -> Optional[str]:
        item = self.get(f"/repos/{full}/contents/{path}")
        if isinstance(item, dict) and item.get("encoding") == "base64":
            return base64.b64decode(item["content"]).decode("utf-8", "ignore")
        return None

    def send(self, method: str, path: str, body: Optional[dict] = None):
        return http_json(GITHUB_API + path, self.token, method, body)


# ── Registry lookups ────────────────────────────────────────────────

GITHUB_REPO_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?]|$)")


def github_repo_from(*urls: str) -> Optional[str]:
    for u in urls:
        m = GITHUB_REPO_RE.search(u or "")
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    return None


def pypi_info(name: str, fetch: FetchJson) -> dict:
    data = fetch(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json") or {}
    info = data.get("info", {})
    latest = info.get("version", "")
    files = data.get("releases", {}).get(latest, [])
    urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page") or ""]
    return {"latest": latest, "yanked": bool(info.get("yanked")) or (bool(files) and all(f.get("yanked") for f in files)),
            "yanked_reason": info.get("yanked_reason") or "", "repo": github_repo_from(*urls),
            "url": f"https://pypi.org/project/{name}/"}


def npm_info(name: str, fetch: FetchJson) -> dict:
    data = fetch(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}") or {}
    latest = (data.get("dist-tags") or {}).get("latest", "")
    meta = (data.get("versions") or {}).get(latest, {})
    repo = data.get("repository") or {}
    return {"latest": latest, "yanked": bool(meta.get("deprecated")), "yanked_reason": meta.get("deprecated") or "",
            "repo": github_repo_from(repo.get("url", "") if isinstance(repo, dict) else str(repo)),
            "url": f"https://www.npmjs.com/package/{name}"}


def classify_release(text: str, is_action: bool) -> list[str]:
    lowered = (text or "").lower()
    signals = [s for s, terms in SIGNAL_TERMS.items() if any(t in lowered for t in terms)]
    if is_action and NODE_RUNTIME.search(text or ""):
        signals.append("runtime")
    return signals


# ── Scan ────────────────────────────────────────────────────────────

def scan(deps: dict, gh: GitHub, fetch: FetchJson, since: datetime) -> list[Finding]:
    findings: list[Finding] = []
    release_cache: dict[str, list] = {}

    def releases(repo: str) -> list:
        if repo not in release_cache:
            release_cache[repo] = gh.get(f"/repos/{repo}/releases?per_page=15") or []
        return release_cache[repo]

    for (eco, name), dep in sorted(deps.items()):
        used = sorted(dep.used_by)
        if eco == "action":
            repo, latest, url = name, "", f"https://github.com/{name}/releases"
            rels = [r for r in releases(repo) if not r.get("draft") and not r.get("prerelease")]
            # Highest major wins: a v4 backport published after v5 must not hide v5.
            tagged = [r for r in rels if major_of(r["tag_name"]) is not None]
            latest = max(tagged, key=lambda r: major_of(r["tag_name"]))["tag_name"] if tagged else ""
            info = {"latest": latest, "yanked": False, "url": url}
        else:
            info = (pypi_info if eco == "pypi" else npm_info)(name, fetch)
            repo = info.get("repo")
            if not info.get("latest"):
                continue

        if info.get("yanked"):
            reason = f": {info['yanked_reason']}" if info.get("yanked_reason") else ""
            findings.append(Finding("yanked", name, eco, f"latest {info['latest']} is yanked or deprecated{reason}",
                                    used, info["url"], key=info["latest"]))

        used_major, latest_major = floor_major(dep.spec, eco), major_of(info["latest"])
        if used_major is not None and latest_major is not None and latest_major > used_major:
            if caps_major(eco, dep.spec):
                detail = f"you pin {dep.spec}, latest is {info['latest']}"
            else:
                detail = f"{dep.spec} will install {info['latest']} on the next run"
            findings.append(Finding("major", name, eco, detail, used, info["url"],
                                    key=f"{dep.spec}->{latest_major}"))

        if not repo:
            continue
        for rel in releases(repo):
            published = rel.get("published_at") or ""
            if rel.get("draft") or rel.get("prerelease") or not published:
                continue
            if datetime.fromisoformat(published.replace("Z", "+00:00")) < since:
                continue
            text = f"{rel.get('name') or ''}\n{rel.get('body') or ''}"
            for signal in classify_release(text, eco == "action"):
                if signal == "runtime":
                    node = NODE_RUNTIME.search(text).group(1)
                    detail = f"{rel['tag_name']} moves the action to Node {node}"
                else:
                    detail = f"{rel['tag_name']} release notes flag a {LABELS[signal].lower()}"
                findings.append(Finding(signal, name, eco, detail, used, rel.get("html_url", ""), key=rel["tag_name"]))

    unique = {f.fingerprint: f for f in findings}
    return sorted(unique.values(), key=lambda f: (-f.score, f.dependency))


# ── Report and issue ────────────────────────────────────────────────

def render(findings: list[Finding], scanned: int, deps: int, since: datetime) -> str:
    lines = [f"## Release radar, {datetime.now(timezone.utc):%Y-%m-%d}", "",
             f"Scanned {deps} dependencies across {scanned} repos. Release notes checked since {since:%Y-%m-%d}.", ""]
    if not findings:
        lines.append("Nothing needs attention.")
    for signal in SEVERITY:
        group = [f for f in findings if f.signal == signal]
        if not group:
            continue
        lines += [f"### {LABELS[signal]} ({len(group)})", ""]
        for f in group:
            link = f"[{f.dependency}]({f.url})" if f.url else f.dependency
            lines.append(f"- **{link}** ({f.ecosystem}): {f.detail}. Used by {', '.join(f.used_by)}.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def sync_issue(gh: GitHub, issue_repo: str, findings: list[Finding], report: str) -> str:
    current = {f.fingerprint for f in findings}
    body = f"{report}\n<!-- radar-fingerprints: {'|'.join(sorted(current))} -->\n"
    issues = gh.send("GET", f"/repos/{issue_repo}/issues?labels={LABEL}&state=open&per_page=1") or []
    existing = issues[0] if issues else None

    if not findings:
        if existing:
            gh.send("POST", f"/repos/{issue_repo}/issues/{existing['number']}/comments",
                    {"body": "Nothing left on the radar. Auto-closed."})
            gh.send("PATCH", f"/repos/{issue_repo}/issues/{existing['number']}", {"state": "closed"})
            return f"closed #{existing['number']}"
        return "nothing to report"

    if not existing:
        if gh.send("GET", f"/repos/{issue_repo}/labels/{LABEL}") is None:
            gh.send("POST", f"/repos/{issue_repo}/labels", {"name": LABEL, "color": "1D76DB"})
        made = gh.send("POST", f"/repos/{issue_repo}/issues", {"title": "Release radar", "labels": [LABEL], "body": body})
        return f"opened #{made['number']}"

    m = FP_MARKER.search(existing.get("body") or "")
    previous = set(filter(None, m.group(1).split("|"))) if m else set()
    new = [f for f in findings if f.fingerprint not in previous]
    gh.send("PATCH", f"/repos/{issue_repo}/issues/{existing['number']}", {"body": body})
    if new:
        items = "\n".join(f"- **{f.dependency}**: {f.detail}" for f in new)
        gh.send("POST", f"/repos/{issue_repo}/issues/{existing['number']}/comments",
                {"body": f"New on the radar:\n\n{items}"})
        return f"updated #{existing['number']} with {len(new)} new"
    return f"updated #{existing['number']}, nothing new"


# ── CLI ─────────────────────────────────────────────────────────────

def sample_fetch(url: str):
    """Offline fixture lookups for --sample and tests."""
    fixtures = json.loads((FIXTURES / "radar_sample.json").read_text())
    return fixtures.get(url)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--owner", help="GitHub user whose repos to scan")
    src.add_argument("--local", type=Path, help="Folder of cloned repos to scan instead")
    src.add_argument("--sample", action="store_true", help="Offline demo with fixture data")
    ap.add_argument("--days", type=int, default=8, help="Release-note window (default 8)")
    ap.add_argument("--issue", action="store_true", help="Open/update/close the release-radar issue")
    ap.add_argument("--issue-repo", default=os.getenv("GITHUB_REPOSITORY", ""))
    args = ap.parse_args(argv)

    since = datetime.now(timezone.utc) - timedelta(days=args.days)
    if args.sample:
        fetch = sample_fetch
        gh = GitHub(fetch=sample_fetch)
        files = json.loads((FIXTURES / "radar_sample_repos.json").read_text())
        since = datetime(2026, 9, 1, tzinfo=timezone.utc)
    else:
        fetch = http_json
        gh = GitHub(os.getenv("READ_TOKEN", ""))
        files = local_files(args.local.expanduser()) if args.local else github_files(args.owner, gh)

    deps = collect(files)
    findings = scan(deps, gh, fetch, since)
    report = render(findings, len(files), len(deps), since)
    print(report)

    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(report)

    if args.issue:
        if not args.issue_repo:
            ap.error("--issue needs --issue-repo or GITHUB_REPOSITORY")
        print(sync_issue(GitHub(os.getenv("ISSUE_TOKEN", "")), args.issue_repo, findings, report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
