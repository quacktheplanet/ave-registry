"""
The capability catalogue fills in what a lock does not state. It must only
ever resolve a MAYBE - never override what a lock says, never read an
unclaimed capability as absent, and never clear a match on a claim whose
conditions the lock does not record.

    python -m unittest discover tests
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import audit  # noqa: E402

CATALOGUE = audit.load_catalogue(ROOT / "catalogue")
REGISTRY = audit.load_registry(ROOT / "advisories")
T, F, U = audit.TRUE, audit.FALSE, audit.UNKNOWN


def example(name):
    return json.loads((ROOT / "examples" / "locks" / f"{name}.json").read_text(encoding="utf-8"))


def advisory(ave):
    return next(a for a in REGISTRY if a["id"] == ave)


def scan(lock, catalogue):
    got = {"affected": set(), "possible": set()}
    for adv in REGISTRY:
        status, _, _ = audit.evaluate(adv, lock, catalogue)
        if status:
            got[status].add(adv["id"])
    return got


def caps(tool, catalogue=CATALOGUE):
    resolved, report = audit.resolve_tool(tool, catalogue)
    get = audit.capability_lookup(resolved)
    return {c: get(c) for c in audit.CAPABILITIES}, report


class FillsTheGap(unittest.TestCase):
    def test_identities_only_lock_goes_from_maybe_to_affected(self):
        lock = example("identities-only-emitter")
        self.assertEqual(audit.evaluate(advisory("AVE-2026-0003"), lock)[0], "possible")
        self.assertEqual(audit.evaluate(advisory("AVE-2026-0003"), lock, CATALOGUE)[0], "affected")

    def test_version_specific_advisories_still_use_the_version(self):
        # postmark-mcp 1.0.15 predates the malicious release; git 2025.12.18 is patched.
        got = scan(example("identities-only-emitter"), CATALOGUE)
        self.assertNotIn("AVE-2026-0016", got["affected"] | got["possible"])
        self.assertNotIn("AVE-2026-0005", got["affected"] | got["possible"])

    def test_filled_values_are_reported_as_catalogue_derived(self):
        _, reports = audit.resolve(example("identities-only-emitter"), CATALOGUE)
        whatsapp = next(r for r in reports if r["tool"] == "whatsapp")
        self.assertEqual(whatsapp["origin"], "catalogue")
        self.assertEqual(whatsapp["filled"], {"ingests-untrusted-content": T, "reads-private-data": T, "external-egress": T})


class StaysNarrow(unittest.TestCase):
    def test_hardened_and_patched_locks_stay_clear(self):
        for name in ("hardened-support-agent", "ci-coding-agent-patched"):
            with self.subTest(lock=name):
                self.assertEqual(scan(example(name), CATALOGUE), {"affected": set(), "possible": set()})

    def test_catalogue_only_ever_resolves_a_maybe(self):
        # Resolution replaces unknowns and nothing else, so with three-valued
        # logic any result the lock already decided must be unchanged.
        for path in sorted((ROOT / "examples" / "locks").glob("*.json")):
            lock = json.loads(path.read_text(encoding="utf-8"))
            for adv in REGISTRY:
                without = audit.evaluate(adv, lock)[0]
                with_ = audit.evaluate(adv, lock, CATALOGUE)[0]
                if without != "possible":
                    with self.subTest(lock=path.stem, advisory=adv["id"]):
                        self.assertEqual(with_, without)

    def test_unclaimed_capability_is_unknown_not_absent(self):
        values, _ = caps({"name": "fs", "source": "pkg:npm/@modelcontextprotocol/server-filesystem"})
        self.assertEqual(values["writes-filesystem"], T)
        self.assertEqual(values["external-egress"], U)

    def test_entry_with_no_claims_decides_nothing(self):
        values, report = caps({"name": "slack", "source": "pkg:npm/@modelcontextprotocol/server-slack"})
        self.assertEqual(set(values.values()), {U})
        self.assertEqual(report["filled"], {})

    def test_no_source_means_no_lookup_even_if_the_name_matches(self):
        values, report = caps({"name": "whatsapp-mcp"})
        self.assertEqual(set(values.values()), {U})
        self.assertEqual(report["origin"], "no-source")

    def test_without_capabilities_or_catalogue_the_partial_lock_is_unchanged(self):
        self.assertEqual(scan(example("partial-lock-minimal-emitter"), CATALOGUE),
                         scan(example("partial-lock-minimal-emitter"), {}))


class LockWins(unittest.TestCase):
    def test_lock_value_overrides_catalogue_and_conflict_is_noted(self):
        lock = example("identities-only-emitter")
        for tool in lock["tools"]:
            tool["capabilities"] = []  # the operator states these tools can do nothing listed
        self.assertEqual(scan(lock, CATALOGUE), {"affected": set(), "possible": set()})
        _, reports = audit.resolve(lock, CATALOGUE)
        whatsapp = next(r for r in reports if r["tool"] == "whatsapp")
        self.assertEqual(whatsapp["origin"], "lock")
        self.assertEqual({c["capability"] for c in whatsapp["conflicts"]},
                         {"ingests-untrusted-content", "reads-private-data", "external-egress"})
        self.assertTrue(all(c["lock"] == F and c["catalogue"] == T for c in whatsapp["conflicts"]))

    def test_agreeing_lock_has_no_conflicts(self):
        for name in ("cursor-dev-workstation", "claude-desktop-github", "ci-coding-agent-patched"):
            with self.subTest(lock=name):
                _, reports = audit.resolve(example(name), CATALOGUE)
                self.assertEqual([r for r in reports if r["conflicts"]], [])

    def test_resolution_does_not_change_the_input_lock(self):
        lock = example("identities-only-emitter")
        before = copy.deepcopy(lock)
        audit.resolve(lock, CATALOGUE)
        self.assertEqual(lock, before)


class ConfigurationDependent(unittest.TestCase):
    SUPABASE = "pkg:npm/@supabase/mcp-server-supabase"

    def test_unrecorded_grant_leaves_the_claim_unknown(self):
        values, report = caps({"name": "db", "source": self.SUPABASE, "grants": {"credential": "service_role"}})
        self.assertEqual(values["reads-private-data"], T)
        self.assertEqual(values["external-egress"], U)
        self.assertEqual(report["pending"]["external-egress"], ["grants.readOnly"])

    def test_write_access_establishes_egress(self):
        values, _ = caps({"name": "db", "source": self.SUPABASE, "grants": {"readOnly": False}})
        self.assertEqual(values["external-egress"], T)
        self.assertEqual(values["reads-private-data"], U)  # credential not recorded

    def test_read_only_is_not_recorded_as_safe(self):
        # The source says read-only removes the write channel, not every channel.
        values, _ = caps({"name": "db", "source": self.SUPABASE, "grants": {"readOnly": True}})
        self.assertEqual(values["external-egress"], U)


class AbsenceClaims(unittest.TestCase):
    """A present:false claim is the only way the catalogue can clear a match.
    No seeded entry has one yet; these pin the semantics for the first."""

    ENTRY = {"source": "pkg:npm/example", "_file": "npm/example.json", "claims": [
        {"capability": "external-egress", "present": False, "versions": [">=2.0"],
         "when": {"grants": {"readOnly": True}}, "evidence": [{"url": "https://example.org", "note": "x"}]},
        {"capability": "external-egress", "present": True, "versions": ["<2.0"],
         "evidence": [{"url": "https://example.org", "note": "x"}]},
    ]}

    def value(self, **tool):
        return caps({"name": "t", "source": "pkg:npm/example", **tool}, {"pkg:npm/example": self.ENTRY})[0]["external-egress"]

    def test_definite_absence_when_every_condition_is_recorded(self):
        self.assertEqual(self.value(version="2.1", grants={"readOnly": True}), F)

    def test_unrecorded_version_is_unknown(self):
        self.assertEqual(self.value(grants={"readOnly": True}), U)

    def test_unrecorded_grant_is_unknown(self):
        self.assertEqual(self.value(version="2.1"), U)

    def test_presence_claim_applies_by_version(self):
        self.assertEqual(self.value(version="1.9", grants={"readOnly": True}), T)

    def test_absence_can_clear_a_toolset_match(self):
        lock = {"harness": {"name": "x"}, "tools": [
            {"name": "t", "source": "pkg:npm/example", "version": "2.1", "grants": {"readOnly": True}}]}
        clause = {"toolset": {"capabilities": {"includesAny": ["external-egress"]}}}
        self.assertEqual(audit.eval_clause(clause, lock), U)
        resolved, _ = audit.resolve(lock, {"pkg:npm/example": self.ENTRY})
        self.assertEqual(audit.eval_clause(clause, resolved), F)


try:
    import validate  # needs jsonschema
except ImportError:  # pragma: no cover
    validate = None


@unittest.skipIf(validate is None, "jsonschema not installed")
class Validation(unittest.TestCase):
    GOOD = {"schemaVersion": "0.1", "source": "pkg:npm/example", "title": "Example", "reviewed": "2026-10-08",
            "claims": [{"capability": "external-egress", "present": True,
                        "evidence": [{"url": "https://example.org/post", "note": "It sends email."}]}]}

    def errors(self, doc, relpath="npm/example.json"):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(doc), encoding="utf-8")
            return validate.check_catalogue([path], {"AVE-2026-0001"}, Path(d))

    def test_seeded_catalogue_is_valid(self):
        ids = {a["id"] for a in REGISTRY}
        self.assertEqual(validate.check_catalogue(sorted((ROOT / "catalogue").rglob("*.json")), ids), [])

    def test_good_entry(self):
        self.assertEqual(self.errors(self.GOOD), [])

    def test_claim_without_evidence(self):
        doc = copy.deepcopy(self.GOOD)
        doc["claims"][0]["evidence"] = []
        self.assertTrue(self.errors(doc))

    def test_capability_outside_vocabulary(self):
        doc = copy.deepcopy(self.GOOD)
        doc["claims"][0]["capability"] = "sends-email"
        self.assertTrue(any("vocabulary" in e for e in self.errors(doc)))

    def test_file_must_live_at_its_purl(self):
        self.assertTrue(any("should be catalogue/npm/example.json" in e for e in self.errors(self.GOOD, "npm/other.json")))

    def test_contradictory_claims(self):
        doc = copy.deepcopy(self.GOOD)
        doc["claims"].append({**doc["claims"][0], "present": False})
        self.assertTrue(any("contradicts" in e for e in self.errors(doc)))

    def test_claimed_and_unknown_at_once(self):
        doc = copy.deepcopy(self.GOOD)
        doc["unknown"] = [{"capability": "external-egress", "note": "unsure"}]
        self.assertTrue(any("also claimed" in e for e in self.errors(doc)))

    def test_unknown_advisory(self):
        doc = copy.deepcopy(self.GOOD)
        doc["advisories"] = ["AVE-2026-9999"]
        self.assertTrue(any("does not exist" in e for e in self.errors(doc)))


if __name__ == "__main__":
    unittest.main()
