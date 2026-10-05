"""Offline tests for scripts/release_radar.py. Standard library only: python -m unittest -v"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import release_radar as rr  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
SINCE = datetime(2026, 9, 1, tzinfo=timezone.utc)


class ParsingTests(unittest.TestCase):
    def test_workflow_refs(self):
        text = ("steps:\n  - uses: actions/checkout@v4\n  - uses: 'actions/setup-python@v5.1.0'\n"
                "  - uses: github/codeql-action/init@v3\n  - uses: ./local\n  - uses: docker://alpine:3\n"
                "  - name: x\n    uses: org/act@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v4\n")
        self.assertEqual(rr.parse_workflow(text), [
            ("actions/checkout", "v4"), ("actions/setup-python", "v5.1.0"),
            ("github/codeql-action", "v3"), ("org/act", "8e5e7e5ab8b370d6c329ec480221332ada57f0ab")])

    def test_requirements(self):
        text = "# c\nrequests>=2.31\nFoo_Bar[x]==1.2 ; python_version>'3'\n-r dev.txt\ngit+https://x\n\nplain\n"
        self.assertEqual(rr.parse_requirements(text),
                         [("requests", ">=2.31"), ("foo_bar", "==1.2"), ("plain", "")])

    def test_pyproject(self):
        text = '[project]\ndependencies = ["networkx>=3.0"]\n[project.optional-dependencies]\ndev = ["pytest>=7.0"]\n'
        self.assertEqual(rr.parse_pyproject(text), [("networkx", ">=3.0"), ("pytest", ">=7.0")])

    def test_package_json_skips_local(self):
        text = json.dumps({"dependencies": {"react": "^18.3.1", "lib": "file:../lib"},
                           "devDependencies": {"vite": "^5.4.11"}})
        self.assertEqual(rr.parse_package_json(text), [("react", "^18.3.1"), ("vite", "^5.4.11")])


class VersionTests(unittest.TestCase):
    def test_floor_major(self):
        cases = {"^5.4.11": 5, ">=2.31,<3": 2, "v4": 4, "~=1.2": 1, "==3.0": 3, "4.1.2": 4, "": None, "*": None}
        for spec, want in cases.items():
            self.assertEqual(rr.floor_major(spec), want, spec)

    def test_action_sha_and_branch_have_no_major(self):
        self.assertIsNone(rr.floor_major("11bd71901bbe5b1630ceea73d27597364c9af683", "action"))
        self.assertIsNone(rr.floor_major("main", "action"))
        self.assertEqual(rr.floor_major("v4.2", "action"), 4)

    def test_caps_major(self):
        self.assertTrue(rr.caps_major("npm", "^18.3.1"))
        self.assertFalse(rr.caps_major("npm", ">=18"))
        self.assertTrue(rr.caps_major("pypi", ">=2,<3"))
        self.assertFalse(rr.caps_major("pypi", ">=2.31"))
        self.assertTrue(rr.caps_major("action", "v4"))


class ClassifyTests(unittest.TestCase):
    def test_signals(self):
        self.assertEqual(rr.classify_release("Fixes CVE-2026-1", False), ["security"])
        self.assertEqual(rr.classify_release("BREAKING CHANGE: drop support for 3.9", False), ["breaking"])
        self.assertEqual(rr.classify_release("This is deprecated", False), ["deprecation"])
        self.assertEqual(rr.classify_release("Routine bump", False), [])

    def test_runtime_only_for_actions(self):
        self.assertIn("runtime", rr.classify_release("Moves to node24", True))
        self.assertNotIn("runtime", rr.classify_release("Moves to node24", False))


class CollectTests(unittest.TestCase):
    def test_merges_repos_and_keeps_oldest_pin(self):
        files = {"a": {".github/workflows/x.yml": "- uses: actions/checkout@v4\n", "requirements.txt": "requests\n"},
                 "b": {".github/workflows/y.yml": "- uses: actions/checkout@v3\n", "requirements.txt": "requests>=2\n"}}
        deps = rr.collect(files)
        self.assertEqual(deps[("action", "actions/checkout")].spec, "v3")
        self.assertEqual(deps[("action", "actions/checkout")].used_by, {"a", "b"})
        self.assertEqual(deps[("pypi", "requests")].spec, ">=2")

    def test_bad_manifest_is_skipped(self):
        deps = rr.collect({"a": {"package.json": "{not json", "requirements.txt": "requests\n"}})
        self.assertEqual(list(deps), [("pypi", "requests")])


class ScanSampleTests(unittest.TestCase):
    def setUp(self):
        files = json.loads((FIXTURES / "radar_sample_repos.json").read_text())
        self.deps = rr.collect(files)
        self.findings = rr.scan(self.deps, rr.GitHub(fetch=rr.sample_fetch), rr.sample_fetch, SINCE)
        self.pairs = {(f.signal, f.dependency) for f in self.findings}

    def test_expected_findings(self):
        self.assertEqual(self.pairs, {
            ("security", "vite"),
            ("breaking", "actions/checkout"), ("runtime", "actions/checkout"), ("major", "actions/checkout"),
            ("breaking", "networkx"), ("major", "networkx"),
            ("yanked", "example-legacy"),
            ("major", "react"),
            ("deprecation", "actions/upload-pages-artifact"),
        })

    def test_ignores_old_releases_prereleases_and_sha_pins(self):
        deps = {d for _, d in self.pairs}
        self.assertNotIn("requests", deps)              # its CVE release predates the window
        self.assertNotIn("actions/setup-python", deps)  # only a prerelease is newer
        self.assertNotIn("example-org/pinned-action", deps)

    def test_sorted_by_severity_and_runtime_names_node(self):
        self.assertEqual(self.findings[0].signal, "security")
        runtime = next(f for f in self.findings if f.signal == "runtime")
        self.assertIn("Node 24", runtime.detail)

    def test_render(self):
        report = rr.render(self.findings, 2, len(self.deps), SINCE)
        self.assertIn("### Security fix (1)", report)
        self.assertIn("you pin v4, latest is v5.0.0", report)
        self.assertIn(">=3.0 will install 4.0 on the next run", report)
        self.assertEqual(rr.render([], 2, 9, SINCE).count("Nothing needs attention."), 1)


class FakeGitHub:
    def __init__(self, open_issue=None, label_exists=True):
        self.calls, self.open_issue, self.label_exists = [], open_issue, label_exists

    def send(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and "/issues?" in path:
            return [self.open_issue] if self.open_issue else []
        if method == "GET" and "/labels/" in path:
            return {"name": rr.LABEL} if self.label_exists else None
        if method == "POST" and path.endswith("/issues"):
            return {"number": 7}
        return {}

    def writes(self):
        return [(m, p) for m, p, _ in self.calls if m != "GET"]


def finding(dep, signal="major"):
    return rr.Finding(signal, dep, "npm", f"{dep} detail", ["site"])


class ActionLatestTests(unittest.TestCase):
    def test_backport_does_not_hide_newer_major(self):
        rels = [{"tag_name": "v4.3.1", "published_at": "2026-01-02T00:00:00Z", "body": ""},
                {"tag_name": "v5.0.0", "published_at": "2026-01-01T00:00:00Z", "body": ""}]
        fetch = lambda url: rels if url.endswith("/repos/actions/checkout/releases?per_page=15") else None
        deps = rr.collect({"a": {".github/workflows/x.yml": "- uses: actions/checkout@v4\n"}})
        findings = rr.scan(deps, rr.GitHub(fetch=fetch), fetch, SINCE)
        self.assertEqual([f.detail for f in findings if f.signal == "major"], ["you pin v4, latest is v5.0.0"])


class IssueSyncTests(unittest.TestCase):
    def test_opens_issue_and_label(self):
        gh = FakeGitHub(label_exists=False)
        self.assertEqual(rr.sync_issue(gh, "o/live", [finding("vite")], "report"), "opened #7")
        self.assertEqual(gh.writes(), [("POST", "/repos/o/live/labels"), ("POST", "/repos/o/live/issues")])
        body = gh.calls[-1][2]["body"]
        self.assertIn("radar-fingerprints: major:npm:vite:vite detail", body)

    def test_update_without_new_findings_does_not_comment(self):
        f = finding("vite")
        issue = {"number": 3, "body": f"old\n<!-- radar-fingerprints: {f.fingerprint} -->"}
        gh = FakeGitHub(open_issue=issue)
        self.assertEqual(rr.sync_issue(gh, "o/live", [f], "report"), "updated #3, nothing new")
        self.assertEqual(gh.writes(), [("PATCH", "/repos/o/live/issues/3")])

    def test_new_findings_add_a_comment(self):
        old, new = finding("vite"), finding("react")
        issue = {"number": 3, "body": f"<!-- radar-fingerprints: {old.fingerprint} -->"}
        gh = FakeGitHub(open_issue=issue)
        self.assertEqual(rr.sync_issue(gh, "o/live", [old, new], "report"), "updated #3 with 1 new")
        comment = gh.calls[-1][2]["body"]
        self.assertIn("react", comment)
        self.assertNotIn("vite", comment)

    def test_closes_when_clear(self):
        gh = FakeGitHub(open_issue={"number": 3, "body": ""})
        self.assertEqual(rr.sync_issue(gh, "o/live", [], "report"), "closed #3")
        self.assertEqual(gh.writes(), [("POST", "/repos/o/live/issues/3/comments"), ("PATCH", "/repos/o/live/issues/3")])

    def test_nothing_to_do(self):
        gh = FakeGitHub()
        self.assertEqual(rr.sync_issue(gh, "o/live", [], "report"), "nothing to report")
        self.assertEqual(gh.writes(), [])


class CliTests(unittest.TestCase):
    def test_sample_run_writes_step_summary(self):
        with tempfile.NamedTemporaryFile("r", suffix=".md") as summary:
            os.environ["GITHUB_STEP_SUMMARY"] = summary.name
            try:
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(rr.main(["--sample"]), 0)
            finally:
                del os.environ["GITHUB_STEP_SUMMARY"]
            self.assertIn("## Release radar", Path(summary.name).read_text())
        self.assertIn("Security fix", out.getvalue())


if __name__ == "__main__":
    unittest.main()
