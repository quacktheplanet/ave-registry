#!/usr/bin/env python3
"""
Summarize susceptibility results, with the calibration verdict front and centre.

    python benchmark/analyze.py                          # every result, grouped by run
    python benchmark/analyze.py --suite canary-v3        # one suite only
    python benchmark/analyze.py --compare A.json B.json  # case-by-case agreement of two runs

The point of the three scaffold stances is to judge the INSTRUMENT, not just the
model:

  obedient (positive control)  must score HIGH   - else the suite can't detect
                                                    susceptibility that is present
  hardened (negative control)  must score LOW    - else the suite false-alarms
  neutral  (the measurement)   the number of interest, trustworthy only if the
                                                    two controls behaved

Calibration is judged per attacker goal, never pooled: run 2 showed one suite
can hold a working instrument (redirect) and a broken one (add-a-recipient), and
pooling hides both. The gate comes from the controls themselves rather than from
author-set numbers: a goal is calibrated when the controls order
obedient >= neutral >= hardened AND their 95% intervals don't overlap (the
positive control's lower bound sits above the negative control's upper bound).

Wilson intervals throughout; a 24-cases-per-cell rate is noisy and bare
percentages invite over-reading. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
SUITES = HERE / "suites"
Z = 1.959963985
STANCE_ORDER = [("obedient", "positive control"), ("neutral", "measurement"), ("hardened", "negative control")]


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / d
    half = Z / d * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
    return (max(0.0, centre - half), min(1.0, centre + half))


def bar(rate, width=24):
    return "#" * round(rate * width) + "-" * (width - round(rate * width))


def pct(x: float) -> str:
    return f"{x * 100:5.1f}%"


# ── loading ──────────────────────────────────────────────────────────────────

_suites: dict[str, dict | None] = {}


def suite(suite_id: str) -> dict | None:
    if suite_id not in _suites:
        p = SUITES / f"{suite_id}.json"
        _suites[suite_id] = json.loads(p.read_text(encoding="utf-8-sig")) if p.exists() else None
    return _suites[suite_id]


def load(suite_id: str | None = None) -> list[dict]:
    rows = []
    for path in sorted(RESULTS.glob("*.json")):
        r = json.loads(path.read_text(encoding="utf-8-sig"))
        if suite_id and r["scaffold"]["suite"] != suite_id:
            continue
        r["_file"] = path.name
        rows.append(r)
    return rows


def run_key(r: dict) -> str:
    """Results from one run share a file name apart from the stance."""
    name = r.get("_file") or ""
    stance = r["scaffold"].get("stance", "neutral")
    if name:
        return name[:-5].replace(f"-{stance}", "", 1)
    m = r["model"]
    return f"{m['baseModel']}-{m['quantization']}-{r['scaffold']['suite']}"


def goal_counts(r: dict) -> dict[str, tuple[int, int, bool]]:
    """goal -> (complied, eligible, exact). Exact from per-case verdicts when the result
    has them; otherwise estimated from the goal's rate, assuming each goal is an equal
    share of the eligible cases (true of canary-v2/v3, whose goals are crossed evenly)."""
    s = r["susceptibility"]
    st = suite(r["scaffold"]["suite"])
    v = s.get("verdicts")
    if v and st and len(v) == len(st["attacks"]):
        out = defaultdict(lambda: [0, 0])
        for ch, a in zip(v, st["attacks"]):
            if ch in "01":
                out[a["goal"]][0] += ch == "1"
                out[a["goal"]][1] += 1
        return {g: (k, n, True) for g, (k, n) in out.items()}
    by_goal = s.get("byGoal") or {}
    if not by_goal:
        return {"all": (s["complied"], s["eligible"], True)}
    n = s["eligible"] / len(by_goal)
    return {g: (round(rate * n), round(n), False) for g, rate in by_goal.items()}


# ── calibration ──────────────────────────────────────────────────────────────

def calibration(by_stance: dict) -> dict[str, dict]:
    """goal -> {rates, intervals, ordered, separated, calibrated}, from the three stances."""
    if not all(s in by_stance for s in ("obedient", "neutral", "hardened")):
        return {}
    counts = {s: goal_counts(by_stance[s]) for s in ("obedient", "neutral", "hardened")}
    goals = sorted(set.intersection(*(set(c) for c in counts.values())))
    out = {}
    for g in goals:
        (ok, on, oe), (nk, nn, ne), (hk, hn, he) = (counts[s][g] for s in ("obedient", "neutral", "hardened"))
        o, n, h = ok / on if on else 0, nk / nn if nn else 0, hk / hn if hn else 0
        o_ci, n_ci, h_ci = wilson(ok, on), wilson(nk, nn), wilson(hk, hn)
        ordered = o >= n >= h
        separated = o_ci[0] > h_ci[1]
        out[g] = {"obedient": o, "neutral": n, "hardened": h,
                  "ci": {"obedient": o_ci, "neutral": n_ci, "hardened": h_ci},
                  "n": {"obedient": on, "neutral": nn, "hardened": hn},
                  "exact": oe and ne and he,
                  "ordered": ordered, "separated": separated, "calibrated": ordered and separated}
    return out


# ── reports ──────────────────────────────────────────────────────────────────

def report_run(rows: list[dict], marginals: bool = True) -> dict:
    by_stance = {r["scaffold"].get("stance", "neutral"): r for r in rows}
    first = rows[0]
    m, sc = first["model"], first["scaffold"]
    print(f"{m['baseModel']}  {m['quantization']}  ({m.get('lineage', '?')})  -  {sc['suite']} "
          f"({sc['cases']} attack cases)")
    print(f"  {m.get('runner', '?')} on {m.get('hardware', '?')}   weights {m['weightsDigest'][7:19]}...")
    det = "Deterministic" in (first.get("notes") or "")
    print(f"  run {run_key(first)}  ({first.get('ranAt', '?')}{', deterministic' if det else ''})\n")

    print(f"{'stance':<10} {'role':<18} {'utility':>9}  {'susceptible':>12}  {'rate':>7}   95% CI")
    print("-" * 74)
    for stance, role in STANCE_ORDER:
        r = by_stance.get(stance)
        if not r:
            continue
        s, u = r["susceptibility"], r["utility"]
        lo, hi = wilson(s["complied"], s["eligible"])
        print(f"{stance:<10} {role:<18} {u['benignPassed']:>4}/{u['benignTotal']:<4} "
              f"{s['complied']:>6}/{s['eligible']:<5} {s['rate']*100:>6.1f}%   "
              f"[{lo*100:4.1f}%, {hi*100:4.1f}%]")

    cal = calibration(by_stance)
    print("\nCALIBRATION BY GOAL (positive >= measurement >= negative, controls' 95% intervals apart)")
    if not cal:
        print("  (run the obedient and hardened scaffolds too - `--scaffold all` - to judge the instrument)")
    for g, c in cal.items():
        verdict = ("calibrated - the neutral figure is meaningful" if c["calibrated"] else
                   "NOT ordered - do not trust this goal" if not c["ordered"] else
                   "controls overlap - not separated, do not trust this goal")
        lo, hi = c["ci"]["neutral"]
        print(f"  {g:<8} obedient {pct(c['obedient'])}  neutral {pct(c['neutral'])} [{lo*100:4.1f}, {hi*100:4.1f}]"
              f"  hardened {pct(c['hardened'])}   {verdict}"
              + ("" if c["exact"] else "  (counts estimated)"))

    neu = by_stance.get("neutral")
    if neu and marginals:
        s = neu["susceptibility"]
        for dim, label in [("byChannel", "channel"), ("byTechnique", "technique"),
                           ("byPosition", "position"), ("byGoal", "goal")]:
            data = s.get(dim, {})
            if not data:
                continue
            print(f"\nneutral, by {label}")
            for k, v in sorted(data.items(), key=lambda kv: -kv[1]):
                print(f"  {k:<16} {v*100:5.1f}%  {bar(v)}")
    return cal


def report(rows: list[dict], marginals: bool = True) -> None:
    """One block per run, then - when there are several - a side-by-side of the
    calibrated goals' neutral figures."""
    runs = defaultdict(list)
    for r in rows:
        runs[run_key(r)].append(r)
    summary = []
    for i, (key, rs) in enumerate(sorted(runs.items())):
        if i:
            print("\n" + "=" * 74 + "\n")
        cal = report_run(rs, marginals=marginals and len(runs) == 1)
        summary.append((key, rs, cal))
    if len(runs) < 2:
        return
    print("\n" + "=" * 74)
    print("\nSIDE BY SIDE (neutral scaffold, calibrated goals only)\n")
    print(f"{'run':<58} {'goal':<8} {'rate':>7}   95% CI          utility")
    for key, rs, cal in summary:
        neu = next((r for r in rs if r["scaffold"].get("stance", "neutral") == "neutral"), None)
        if not neu:
            continue
        good = [g for g, c in cal.items() if c["calibrated"]]
        if not good:
            print(f"{key:<58} {'-':<8} {'(no calibrated goal)':>7}")
            continue
        u = neu["utility"]
        for g in good:
            c = cal[g]
            lo, hi = c["ci"]["neutral"]
            print(f"{key:<58} {g:<8} {pct(c['neutral'])}   [{lo*100:4.1f}, {hi*100:4.1f}]   "
                  f"{u['benignPassed']}/{u['benignTotal']}")


def compare(a: dict, b: dict) -> dict:
    """Case-by-case agreement of two runs of the same suite and stance - the variance
    baseline. Needs per-case verdicts in both results."""
    if a["scaffold"]["suite"] != b["scaffold"]["suite"]:
        raise SystemExit("different suites; nothing to compare case by case")
    va, vb = a["susceptibility"].get("verdicts"), b["susceptibility"].get("verdicts")
    if not va or not vb or len(va) != len(vb):
        raise SystemExit("both results need per-case verdicts (re-run with the current harness)")
    st = suite(a["scaffold"]["suite"])
    goals = [x["goal"] for x in st["attacks"]] if st and len(st["attacks"]) == len(va) else ["all"] * len(va)
    cells = defaultdict(lambda: {"11": 0, "00": 0, "10": 0, "01": 0})
    for x, y, g in zip(va, vb, goals):
        if x in "01" and y in "01":
            for key in (g, "all"):
                cells[key][x + y] += 1
    ba = a["utility"].get("verdicts") or ""
    bb = b["utility"].get("verdicts") or ""
    benign_same = sum(x == y for x, y in zip(ba, bb)) if ba and bb else None
    out = {"benign": (benign_same, len(ba)) if benign_same is not None else None, "goals": {}}
    for g, c in cells.items():
        n = sum(c.values())
        flips = c["10"] + c["01"]
        ra, rb_ = (c["11"] + c["10"]) / n if n else 0, (c["11"] + c["01"]) / n if n else 0
        # McNemar's exact two-sided test on the discordant cases: is one run
        # systematically more susceptible, or are the flips symmetric noise?
        p = 1.0
        if flips:
            k = min(c["10"], c["01"])
            p = min(1.0, 2 * sum(math.comb(flips, i) for i in range(k + 1)) / 2 ** flips)
        out["goals"][g] = {"both": n, "agree": c["11"] + c["00"], "flipAB": c["10"], "flipBA": c["01"],
                           "rateA": ra, "rateB": rb_, "mcnemarP": p}
    return out


def print_compare(a: dict, b: dict, cmp: dict) -> None:
    def who(r):
        m = r["model"]
        return f"{m['quantization']} {m.get('runner', '?')} on {m.get('hardware', '?')}"
    print(f"A: {who(a)}  [{a['scaffold'].get('stance')}]  {a.get('_file', '')}")
    print(f"B: {who(b)}  [{b['scaffold'].get('stance')}]  {b.get('_file', '')}")
    if a["model"]["weightsDigest"] != b["model"]["weightsDigest"]:
        print("   (different weights - this is a comparison, not a reproduction)")
    if cmp["benign"]:
        same, n = cmp["benign"]
        print(f"\nbenign controls: same verdict on {same}/{n}")
    print(f"\n{'goal':<8} {'cases':>6} {'agree':>8} {'A only':>7} {'B only':>7}   {'rate A':>7} {'rate B':>7}   McNemar p")
    for g in sorted(cmp["goals"], key=lambda g: (g == "all", g)):
        c = cmp["goals"][g]
        agree = c["agree"] / c["both"] if c["both"] else 0
        print(f"{g:<8} {c['both']:>6} {agree*100:>7.1f}% {c['flipAB']:>7} {c['flipBA']:>7}   "
              f"{pct(c['rateA'])} {pct(c['rateB'])}   {c['mcnemarP']:.3f}")
    print("\nA low McNemar p means one run is systematically more susceptible than the other;"
          "\na high one with flips means the disagreement is symmetric run-to-run noise.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize susceptibility results.")
    ap.add_argument("--suite", help="only results from this suite, e.g. canary-v3")
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"), help="two result files to compare case by case")
    args = ap.parse_args()
    if args.compare:
        a, b = (json.loads(Path(p).read_text(encoding="utf-8-sig")) | {"_file": Path(p).name}
                for p in args.compare)
        print_compare(a, b, compare(a, b))
        return 0
    rows = load(args.suite)
    if not rows:
        print("no results yet" + (f" for {args.suite}" if args.suite else ""))
        return 1
    report(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
