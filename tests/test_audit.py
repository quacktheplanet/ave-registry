"""
The expected-match matrix. This is the registry's specificity test: every
advisory must hit the configurations it describes and nothing else. A new
advisory that lights up `hardened-support-agent` is too broad and should not
merge.

Locks are scanned the way the CLI scans them, with the capability catalogue.
`identities-only-emitter` states no capabilities at all and depends on it; its
0003 match is POSSIBLE without the catalogue (see tests/test_catalogue.py).

    python -m unittest discover tests
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import audit  # noqa: E402

EXPECTED = {
    "cursor-dev-workstation":       {"affected": {"AVE-2026-0002", "AVE-2026-0003", "AVE-2026-0004", "AVE-2026-0011"}, "possible": set()},
    "claude-desktop-github":        {"affected": {"AVE-2026-0001"}, "possible": set()},
    "gemini-cli-unsandboxed":       {"affected": {"AVE-2026-0010"}, "possible": set()},
    "hardened-support-agent":       {"affected": set(), "possible": set()},
    "ci-coding-agent-patched":      {"affected": set(), "possible": set()},
    "hosted-deep-research-today":   {"affected": set(), "possible": set()},
    "partial-lock-minimal-emitter": {"affected": set(), "possible": {"AVE-2026-0003", "AVE-2026-0004", "AVE-2026-0011"}},
    "identities-only-emitter":      {"affected": {"AVE-2026-0003"}, "possible": set()},
}

CATALOGUE = audit.load_catalogue(ROOT / "catalogue")


def scan(lock):
    got = {"affected": set(), "possible": set()}
    for adv in audit.load_registry(ROOT / "advisories"):
        status, _, _ = audit.evaluate(adv, lock, CATALOGUE)
        if status:
            got[status].add(adv["id"])
    return got


class MatchMatrix(unittest.TestCase):
    def test_every_example_lock(self):
        for name, want in EXPECTED.items():
            with self.subTest(lock=name):
                lock = json.loads((ROOT / "examples" / "locks" / f"{name}.json").read_text(encoding="utf-8"))
                self.assertEqual(scan(lock), want)

    def test_every_example_lock_is_covered(self):
        on_disk = {p.stem for p in (ROOT / "examples" / "locks").glob("*.json")}
        self.assertEqual(on_disk, set(EXPECTED))


class Versions(unittest.TestCase):
    def test_ranges(self):
        r = audit.version_in_ranges
        self.assertEqual(r("0.1.15", [">=0.0.5 <0.1.16"]), audit.TRUE)
        self.assertEqual(r("0.1.16", [">=0.0.5 <0.1.16"]), audit.FALSE)
        self.assertEqual(r("1.84.0", ["=1.84.0"]), audit.TRUE)
        self.assertEqual(r("19.2.3", [">=18.9 <=19.1.7", ">=19.2 <=19.2.5"]), audit.TRUE)
        self.assertEqual(r("19.2.6", [">=18.9 <=19.1.7", ">=19.2 <=19.2.5"]), audit.FALSE)

    def test_calver_and_padding(self):
        self.assertEqual(audit.version_in_ranges("2025.9.25", ["<2025.12.18"]), audit.TRUE)
        self.assertEqual(audit.version_in_ranges("1.3", ["<1.3"]), audit.FALSE)
        self.assertEqual(audit.version_in_ranges("1.3.0", ["<1.3"]), audit.FALSE)

    def test_missing_version_is_unknown_not_safe(self):
        self.assertEqual(audit.version_in_ranges(None, ["<1.3"]), audit.UNKNOWN)


class Identity(unittest.TestCase):
    def test_unlabelled_tool_is_not_every_package(self):
        spec = {"source": "pkg:npm/mcp-remote"}
        self.assertEqual(audit.eval_one_tool(spec, {"name": "terminal"}), audit.FALSE)

    def test_name_coinciding_with_package_is_unknown(self):
        spec = {"source": "pkg:npm/mcp-remote"}
        self.assertEqual(audit.eval_one_tool(spec, {"name": "mcp-remote"}), audit.UNKNOWN)


class HostedRemediation(unittest.TestCase):
    ADV = {"affected": {"all": [{"harness": {"name": "x", "hosted": True}}]},
           "fixedBy": [{"remediatedServerSide": "2025-08"}]}

    def lock(self, **kw):
        return {"harness": {"name": "x", "hosted": True}, "tools": [], **kw}

    def test_lock_after_fix_is_clear(self):
        self.assertIsNone(audit.evaluate(self.ADV, self.lock(generated="2026-01-01T00:00:00Z"))[0])

    def test_lock_before_fix_is_affected(self):
        self.assertEqual(audit.evaluate(self.ADV, self.lock(generated="2025-07-01T00:00:00Z"))[0], "affected")

    def test_undated_lock_is_possible(self):
        self.assertEqual(audit.evaluate(self.ADV, self.lock())[0], "possible")


if __name__ == "__main__":
    unittest.main()
