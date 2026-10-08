#!/usr/bin/env python3
"""
agent-audit — match agent.lock files against the AVE registry.

Runs entirely locally. Standard library only. Nothing about your
configuration leaves the machine.

    python tools/audit.py examples/locks/
    python tools/audit.py my-agent.lock --explain AVE-2026-0001
    python tools/audit.py runs/ --fail-on high        # CI gate

Matching is three-valued. A clause is TRUE, FALSE, or UNKNOWN — unknown when
the lock does not record the field the clause tests. A lock is:

    AFFECTED   every clause TRUE and no exemption applies
    POSSIBLE   no clause FALSE, but at least one UNKNOWN
    (clear)    any clause FALSE, or an exemption is TRUE

A lockfile that omits a field must never read as safe, so missing data
degrades to POSSIBLE rather than to clear.

Tool capabilities a lock does not state are filled from the capability
catalogue (catalogue/), looked up by the tool's `source` purl and version.
A catalogue entry is not a complete list: a capability it does not claim stays
UNKNOWN. A capability list the lock does state always wins; disagreements with
the catalogue are reported, not resolved in the catalogue's favour.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TRUE, FALSE, UNKNOWN = "true", "false", "unknown"
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES = (
    "ingests-untrusted-content", "reads-private-data", "external-egress",
    "code-execution", "writes-filesystem", "writes-agent-config",
)


# ── three-valued logic ───────────────────────────────────────────────────────

def all_of(values):
    values = list(values)
    if FALSE in values:
        return FALSE
    return UNKNOWN if UNKNOWN in values else TRUE


def any_of(values):
    values = list(values)
    if TRUE in values:
        return TRUE
    return UNKNOWN if UNKNOWN in values else FALSE


def negate(value):
    return {TRUE: FALSE, FALSE: TRUE}.get(value, UNKNOWN)


def tv(condition: bool) -> str:
    return TRUE if condition else FALSE


# ── versions ─────────────────────────────────────────────────────────────────

_COMPARATOR = re.compile(r"^(>=|<=|>|<|=)(.+)$")


def parse_version(text: str) -> tuple:
    """Numeric release segments only: '1.0.111' and calver '2025.12.18' both
    work; pre-release/build suffixes are ignored."""
    release = re.split(r"[-+]", text.strip().lstrip("v"), maxsplit=1)[0]
    return tuple(int(p) for p in release.split(".") if p.isdigit())


def _cmp(a: tuple, b: tuple) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def version_in_ranges(version, ranges) -> str:
    if version is None:
        return UNKNOWN
    have = parse_version(str(version))
    if not have:
        return UNKNOWN
    for rng in ranges:
        ok = True
        for part in rng.split():
            op, want = _COMPARATOR.match(part).groups()
            c = _cmp(have, parse_version(want))
            ok = ok and {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
        if ok:
            return TRUE
    return FALSE


# ── field matchers ───────────────────────────────────────────────────────────

def match_name(actual, expected) -> str:
    if actual is None:
        return UNKNOWN
    names = [expected] if isinstance(expected, str) else expected
    return tv(str(actual).lower() in {n.lower() for n in names})


def match_value(actual, matcher, present: bool) -> str:
    if isinstance(matcher, dict):
        (op, arg), = matcher.items()
        if op == "exists":
            return tv(present == arg)
        if not present:
            return UNKNOWN
        if op == "in":
            return tv(actual in arg)
        if op == "not":
            return tv(actual != arg)
        if op == "minCount":
            return tv(isinstance(actual, (list, dict)) and len(actual) >= arg)
        raise ValueError(f"unknown matcher op: {op}")
    if not present:
        return UNKNOWN
    return tv(actual == matcher)


def match_fields(obj: dict, spec: dict) -> str:
    return all_of(match_value(obj.get(k), m, k in obj) for k, m in spec.items())


def match_caps(get, spec: dict) -> str:
    """Set matcher over per-capability truth values. `get(capability)`
    returns TRUE, FALSE or UNKNOWN."""
    results = []
    if "includesAll" in spec:
        results.append(all_of(get(c) for c in spec["includesAll"]))
    if "includesAny" in spec:
        results.append(any_of(get(c) for c in spec["includesAny"]))
    return all_of(results)


def match_set(actual, spec: dict) -> str:
    if actual is None:
        return UNKNOWN
    have = set(actual)
    results = []
    if "includesAll" in spec:
        results.append(tv(set(spec["includesAll"]) <= have))
    if "includesAny" in spec:
        results.append(tv(bool(set(spec["includesAny"]) & have)))
    return all_of(results)


# ── clauses ──────────────────────────────────────────────────────────────────

def eval_harness(spec, lock):
    h = lock.get("harness", {})
    out = []
    if "name" in spec:
        out.append(match_name(h.get("name"), spec["name"]))
    if "versions" in spec:
        # A hosted agent has no operator-visible version; that is UNKNOWN, not clear.
        out.append(version_in_ranges(h.get("version"), spec["versions"]))
    if "hosted" in spec:
        out.append(match_value(h.get("hosted"), spec["hosted"], "hosted" in h))
    if "settings" in spec:
        out.append(match_fields(h.get("settings", {}), spec["settings"]))
    return all_of(out)


def eval_model(spec, lock):
    if spec.get("any"):
        return TRUE
    m = lock.get("model", {})
    return all_of(match_name(m.get(k), v) for k, v in spec.items())


def match_source(tool, expected) -> str:
    """Identity is not a property. An emitter may not know a tool's grants, but
    it always knows what the tool is, so a missing `source` is a non-match, not
    an unknown - otherwise every unlabelled tool 'might be' every package. The
    one exception: no source recorded, but the name equals the package name."""
    if tool.get("source") is not None:
        return match_name(tool["source"], expected)
    purls = [expected] if isinstance(expected, str) else expected
    tails = {p.rsplit("/", 1)[-1].lower() for p in purls}
    return UNKNOWN if str(tool.get("name", "")).lower() in tails else FALSE


def eval_one_tool(spec, tool):
    out = []
    if "name" in spec:
        out.append(match_name(tool.get("name"), spec["name"]))
    if "source" in spec:
        out.append(match_source(tool, spec["source"]))
    if "versions" in spec:
        out.append(version_in_ranges(tool.get("version"), spec["versions"]))
    if "transport" in spec:
        out.append(match_value(tool.get("transport"), spec["transport"], "transport" in tool))
    if "pinned" in spec:
        out.append(match_value(tool.get("pinned"), spec["pinned"], "pinned" in tool))
    if "capabilities" in spec:
        out.append(match_caps(capability_lookup(tool), spec["capabilities"]))
    if "grants" in spec:
        out.append(match_fields(tool.get("grants", {}), spec["grants"]))
    return all_of(out)


def eval_tool(spec, lock):
    tools = lock.get("tools", [])
    return any_of(eval_one_tool(spec, t) for t in tools) if tools else FALSE


def eval_toolset(spec, lock):
    # The union, per capability: present if any tool has it, unknown if no
    # tool has it but an unclassified one might supply it.
    lookups = [capability_lookup(t) for t in lock.get("tools", [])]
    return match_caps(lambda c: any_of(get(c) for get in lookups), spec["capabilities"])


def eval_runtime(spec, lock):
    return match_fields(lock.get("runtime", {}), spec)


def eval_goal(spec, lock):
    return match_set(lock.get("goal", {}).get("properties"), spec["properties"])


def eval_clause(clause, lock):
    (kind, spec), = clause.items()
    if kind == "any":
        return any_of(eval_clause(c, lock) for c in spec)
    if kind == "not":
        return negate(eval_clause(spec, lock))
    return {
        "harness": eval_harness, "model": eval_model, "tool": eval_tool,
        "toolset": eval_toolset, "runtime": eval_runtime, "goal": eval_goal,
    }[kind](spec, lock)


# ── capability catalogue ─────────────────────────────────────────────────────
#
# A lock's own `capabilities` list is complete: what it lists is present, what
# it omits is absent. A lock that omits the list entirely says nothing, and
# each capability is UNKNOWN unless the catalogue decides it. Resolution is
# stored on a copy of each tool under "_capabilities", a full per-capability
# map, so the clause evaluators above never need to know where a value came
# from.

def capability_lookup(tool):
    resolved = tool.get("_capabilities")
    if resolved is not None:
        return lambda c: resolved.get(c, UNKNOWN)
    stated = tool.get("capabilities")
    if stated is not None:
        return lambda c: tv(c in stated)
    return lambda c: UNKNOWN


def catalogue_path(source: str):
    """pkg:npm/@scope/name -> npm/@scope/name.json (relative to catalogue/)."""
    m = re.match(r"^pkg:([a-z]+)/(.+)$", source)
    return f"{m.group(1)}/{m.group(2)}.json" if m else None


def load_catalogue(path: Path) -> dict:
    """purl (lowercased) -> entry. A missing directory is an empty catalogue."""
    entries = {}
    if path.is_dir():
        for f in sorted(path.rglob("*.json")):
            entry = json.loads(f.read_text(encoding="utf-8"))
            entry["_file"] = f.relative_to(path).as_posix()
            entries[entry["source"].lower()] = entry
    return entries


def claim_applies(claim, tool) -> str:
    out = []
    if "versions" in claim:
        out.append(version_in_ranges(tool.get("version"), claim["versions"]))
    if "grants" in claim.get("when", {}):
        out.append(match_fields(tool.get("grants", {}), claim["when"]["grants"]))
    return all_of(out)


def catalogue_value(entry, tool, capability):
    """(value, claims that decided it). FALSE only when a present:false claim
    definitely applies and no present:true claim could; a capability the
    entry does not decide is UNKNOWN, never absent."""
    applies = [(c, claim_applies(c, tool)) for c in entry["claims"] if c["capability"] == capability]
    present = [c for c, a in applies if c["present"] and a == TRUE]
    if present:
        return TRUE, present
    if any(a == UNKNOWN for _, a in applies):
        return UNKNOWN, [c for c, a in applies if a == UNKNOWN]
    absent = [c for c, a in applies if not c["present"] and a == TRUE]
    if absent:
        return FALSE, absent
    return UNKNOWN, []


def resolve_tool(tool, catalogue):
    """Returns (resolved tool copy, report). The report says where each
    capability value came from and lists lock/catalogue disagreements."""
    source = tool.get("source")
    entry = catalogue.get(str(source).lower()) if source else None
    report = {"tool": tool.get("name"), "source": source, "origin": "lock",
              "entry": entry and entry["_file"], "filled": {}, "pending": {}, "conflicts": []}
    stated = tool.get("capabilities")
    if stated is not None:
        for c in CAPABILITIES:
            cat, _ = catalogue_value(entry, tool, c) if entry else (UNKNOWN, [])
            if cat != UNKNOWN and cat != tv(c in stated):
                report["conflicts"].append({"capability": c, "lock": tv(c in stated), "catalogue": cat})
        return tool, report  # the lock's statement stands, unchanged
    if entry is None:
        report["origin"] = "none" if source else "no-source"
        return tool, report
    report["origin"] = "catalogue"
    values = {}
    for c in CAPABILITIES:
        value, claims = catalogue_value(entry, tool, c)
        values[c] = value
        if value != UNKNOWN:
            report["filled"][c] = value
        elif claims:
            # A claim exists but the lock lacks the version or grant it depends on.
            report["pending"][c] = [k for cl in claims for k in
                                    (["version"] if "versions" in cl else []) +
                                    [f"grants.{g}" for g in cl.get("when", {}).get("grants", {})]]
    return {**tool, "_capabilities": values}, report


def resolve(lock, catalogue):
    """A copy of the lock with every tool's capabilities resolved, plus the
    per-tool report. Lock-stated lists are unchanged by resolution."""
    pairs = [resolve_tool(t, catalogue) for t in lock.get("tools", [])]
    return {**lock, "tools": [t for t, _ in pairs]}, [r for _, r in pairs]


# ── advisories ───────────────────────────────────────────────────────────────

def remediated_before(advisory, lock):
    """Hosted agents have no version to match, so a vendor-side fix is matched
    on time instead: a lock generated after the remediation date is clear.
    Dates may be partial ('2025-08'); an undated lock is UNKNOWN."""
    dates = [f["remediatedServerSide"] for f in advisory["fixedBy"] if "remediatedServerSide" in f]
    if not dates:
        return None
    fixed = max(dates)
    generated = lock.get("generated")
    if not generated:
        return fixed, UNKNOWN
    prefix = generated[:len(fixed)]
    if prefix > fixed:
        return fixed, TRUE
    return fixed, (UNKNOWN if prefix == fixed else FALSE)


def evaluate(advisory, lock, catalogue=None):
    """Returns (status, clause_results, exemption_results); status is
    'affected', 'possible', or None. With a catalogue, tool capabilities the
    lock does not state are resolved from it first."""
    if catalogue is not None:
        lock, _ = resolve(lock, catalogue)
    clauses = [(c, eval_clause(c, lock)) for c in advisory["affected"]["all"]]
    exempt = [(c, eval_clause(c, lock)) for c in advisory.get("notAffectedIf", [])]
    hit = all_of(r for _, r in clauses)
    out = any_of(r for _, r in exempt) if exempt else FALSE
    remediated = remediated_before(advisory, lock)
    if remediated is not None:
        exempt.append(({"remediatedServerSide": remediated[0]}, remediated[1]))
        out = any_of([out, remediated[1]])
    if hit == FALSE or out == TRUE:
        status = None
    elif hit == TRUE and out == FALSE:
        status = "affected"
    else:
        status = "possible"
    return status, clauses, exempt


def load_registry(path: Path):
    advisories = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(path.rglob("AVE-*.json"))]
    return sorted(advisories, key=lambda a: a["id"])


def load_locks(paths):
    for raw in paths:
        p = Path(raw)
        files = sorted(p.rglob("*.json")) + sorted(p.rglob("*.lock")) if p.is_dir() else [p]
        for f in files:
            yield f, json.loads(f.read_text(encoding="utf-8"))


def via_catalogue(clause, result, raw_lock) -> str:
    """Marks a clause whose result the catalogue decided. Resolution only
    replaces unknowns, so a changed result was unknown without it."""
    return "  <- catalogue (unknown without it)" if eval_clause(clause, raw_lock) != result else ""


def explain_capabilities(tool_reports):
    for t in tool_reports:
        label = f"{t['tool']} ({t['source']})" if t["source"] else t["tool"]
        if t["origin"] == "catalogue":
            print(f"  capabilities of {label}: from catalogue/{t['entry']} (lock states none)")
            for c in CAPABILITIES:
                if c in t["filled"]:
                    print(f"      {c}: {'present' if t['filled'][c] == TRUE else 'absent'}  [catalogue]")
                elif c in t["pending"]:
                    print(f"      {c}: unknown - catalogue claim depends on {', '.join(t['pending'][c])}, not in the lock")
            print("      every other capability: unknown")
        elif t["origin"] == "none":
            print(f"  capabilities of {label}: unknown (lock states none, no catalogue entry)")
        elif t["origin"] == "no-source":
            print(f"  capabilities of {label}: unknown (lock states none, and no source to look up)")
        for c in t["conflicts"]:
            print(f"  conflict: {label} - lock says {c['capability']} is "
                  f"{'present' if c['lock'] == TRUE else 'absent'}, catalogue/{t['entry']} says "
                  f"{'present' if c['catalogue'] == TRUE else 'absent'}; lock value used")


def describe_fix(fix) -> str:
    if "upgrade" in fix:
        u = fix["upgrade"]
        return f"upgrade {u['name']} to {u['version']}"
    if "mitigation" in fix:
        return fix["mitigation"]
    return f"fixed server-side {fix['remediatedServerSide']}; no operator action"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Match agent.lock files against the AVE registry.")
    ap.add_argument("locks", nargs="+", help="lockfiles or directories of them")
    ap.add_argument("--registry", default=str(ROOT / "advisories"))
    ap.add_argument("--catalogue", default=str(ROOT / "catalogue"), help="capability catalogue directory")
    ap.add_argument("--no-catalogue", action="store_true", help="use only the capabilities each lock states")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if an AFFECTED match is at or above this severity")
    ap.add_argument("--explain", metavar="AVE-ID", help="show clause-by-clause reasoning for one advisory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    registry = load_registry(Path(args.registry))
    catalogue = {} if args.no_catalogue else load_catalogue(Path(args.catalogue))
    locks = list(load_locks(args.locks))
    report, worst, notes = [], -1, {}

    for path, lock in locks:
        label = lock.get("label") or path.stem
        resolved, tool_reports = resolve(lock, catalogue)
        notes[label] = tool_reports
        for adv in registry:
            if args.explain and adv["id"] != args.explain:
                continue
            status, clauses, exempt = evaluate(adv, resolved)
            if args.explain:
                print(f"{adv['id']} against {label}: {status or 'clear'}")
                explain_capabilities(tool_reports)
                # A clause is marked when the catalogue changed its result.
                for c, r in clauses:
                    print(f"  [{r:>7}] {json.dumps(c)}{via_catalogue(c, r, lock)}")
                for c, r in exempt:
                    tag = via_catalogue(c, r, lock) if "remediatedServerSide" not in c else ""
                    print(f"  [{r:>7}] exempt-if {json.dumps(c)}{tag}")
                print()
                continue
            if status:
                report.append({"lock": label, "id": adv["id"], "status": status,
                               "severity": adv["severity"], "title": adv["title"],
                               "viaCatalogue": status != evaluate(adv, lock)[0],
                               "fix": [describe_fix(f) for f in adv["fixedBy"]]})
                if status == "affected":
                    worst = max(worst, SEVERITY_ORDER[adv["severity"]])

    if args.explain:
        return 0

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Scanned {len(locks)} lockfile(s) against {len(registry)} advisories.\n")
        for path, lock in locks:
            label = lock.get("label") or path.stem
            rows = [r for r in report if r["lock"] == label]
            print(f"{label}: {'clear' if not rows else f'{len(rows)} match(es)'}")
            for r in sorted(rows, key=lambda r: (r["status"] != "affected", -SEVERITY_ORDER[r["severity"]])):
                tag = r["severity"].upper() if r["status"] == "affected" else "MAYBE"
                via = "  [via catalogue]" if r["viaCatalogue"] else ""
                print(f"  {tag:<6} {r['id']}  {r['title']}{via}")
                for i, fix in enumerate(r["fix"]):
                    print(f"         {'Fix:' if i == 0 else 'Or: '} {fix}")
            filled = [t["tool"] for t in notes[label] if t["filled"]]
            if filled:
                print(f"  capabilities from catalogue: {', '.join(filled)} (--explain <id> for detail)")
            for t in notes[label]:
                for c in t["conflicts"]:
                    print(f"  note: {t['tool']} - lock says {c['capability']} is "
                          f"{'present' if c['lock'] == TRUE else 'absent'}, catalogue says "
                          f"{'present' if c['catalogue'] == TRUE else 'absent'}; lock value used")
            print()

    if args.fail_on and worst >= SEVERITY_ORDER[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
