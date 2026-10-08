# Roadmap

Where this is, where it's going, and what it looks like finished.

## The problem

When an AI agent gets exploited, the flaw usually isn't in any one component. A token
scoped too widely, a tool that reads public content, an approval prompt somebody clicked
"always allow" on — each is defensible alone, and together they leak your private
repositories. Because no single component is broken, there's no patched version to ship,
so no CVE gets filed, so an operator has nothing to check against.

The unit of vulnerability is the **configuration**. Nothing records configurations, and
nothing describes which ones are dangerous.

## What this becomes

An operator who wonders *"is the agent I'm running known to be exploitable?"* runs one
command, offline, and gets an answer in under a minute. A researcher who publishes an
agent exploit files a record that makes the finding checkable rather than just readable —
the way a package vulnerability gets a CVE.

That requires five pieces. Three exist in draft, two don't exist at all.

| Piece | What it does | Status |
| --- | --- | --- |
| **`agent.lock`** | A generated record of exactly what a deployment is made of: harness, version, tools, grants, approval settings, runtime. Pins exact values, holds no prompt text, safe to share. | Schema drafted. Nothing emits one yet — locks are written by hand. |
| **Advisories** | Machine-matchable records of exploitable configurations, each a predicate over lockfiles, each with a permanent identifier. | Format v0.1. 20 records, all from cited public write-ups. |
| **Capability catalogue** | Maps a tool to what it can *do* — read untrusted content, reach the network, execute code. | **Does not exist.** The largest open piece. |
| **Susceptibility data** | Maps a pinned model artifact to how readily it obeys injected instructions. Aimed at quantized builds and community fine-tunes. | Harness works. Instrument not yet calibrated. |
| **`agent-audit`** | Joins a lockfile to the registry, locally. Nothing leaves the machine. | Works. Three-valued, so an incomplete lock reads as *maybe*, never as safe. |

The two missing datasets are the substance. The registry itself is thin — a few hundred
lines of schema and a matcher. What makes it useful is the reference data underneath, and
that's where the work is.

## Where we are

Phase 0 asked one question: can real agent-security findings be written as predicates over
a configuration? Twenty-one published findings were attempted. The answer was yes, more
narrowly than hoped — 3 were configuration-native with no CVE possible, 6 gained real
precision, 8 were ordinary component bugs a CVE already covers.

It also produced a correction. Two of the four axes originally proposed went unused: no
finding depended on the model or the prompt. The prompt axis is genuinely dead for
matching. The model axis read zero only because every finding concerned *hosted* products,
which can't be pinned — open-weight builds have a SHA-256 and can be. That's what the
susceptibility track exists to measure.

The first susceptibility experiment ran on 19 September: one model across four
quantizations. It found no quantization effect, and more usefully found that the
measurement itself isn't trustworthy yet — every successful injection concentrated in a
single content channel per build, so the headline number moved 20 points on one piece of
text.

**No susceptibility number from this project should be cited yet, including internally.**

## Now

**The measurement is calibrated for redirect attacks (done).** `canary-v2` grew the suite
to 20 channels with the benign control and the positive/negative scaffold controls. Run 2
([benchmark/RESULTS-v2.md](benchmark/RESULTS-v2.md)) validated it for redirect ("instead")
injections — the controls order 92% / 81% / 34% with a 58-point spread — and showed the
add-a-recipient ("also") half does not calibrate. `canary-v3` is that validated instrument
with "also" removed, and is now the default suite. First trustworthy figure:
Llama-3.1-8B-Instruct Q8_0 follows a redirect injection 81% of the time, cut to 34% by a
"treat tool content as untrusted" system prompt.

**First comparisons (done, 2026-10-08).** [benchmark/RESULTS-v3.md](benchmark/RESULTS-v3.md):
the A4500 figure reproduces on an RTX 5090 (81.1% against 81.9%). The four K-quants and the
abliterated build show no difference in redirect susceptibility that survives the noise
floor, while quantization moves utility a lot. Hermes 3 fails the calibration gate, so its
figure isn't reported. Q5_K_M is the exception among the quantizations: less susceptible than Q8_0
in two independent runs (p 0.001 deterministic), while Q4_K_M and Q6_K aren't distinguishable. So
susceptibility doesn't follow bit depth and has to be measured per file. Default llama-server
settings flip about one case in thirteen between identical runs. `run.py --deterministic` (one slot, no prompt cache) makes repeat runs
byte-identical at no measurable cost.

**Next on the benchmark:**

- Make `--deterministic` the default, and keep the batched mode behind a flag for speed.
- GPU against CPU on the same file: 96.8% case agreement, no systematic difference (done). Next, two
  different GPUs, both deterministic.
- Make the positive control work for system-prompt-heavy fine-tunes (Hermes 3 fails it).
- Add a second base family (Qwen, Mistral), then widen the suite dimensions in
  [benchmark/SUITE-DESIGN.md](benchmark/SUITE-DESIGN.md).

[benchmark/SUITE-DESIGN.md](benchmark/SUITE-DESIGN.md) lists every dimension the suite
could vary, which ones it actually does, and the ~25 planned channels — each tied to a
real exploit in the registry where one exists. It also discloses three flaws in the
current suite that the first experiment's numbers inherit.

## In parallel: the OSV bridge

The main alternative to this project is "don't build a registry, extend OSV." Rather than
argue it, `tools/osv_export.py` translates every advisory into OSV and measures what
survives. Today: **6 of 20 lossless, 6 lossy, 8 unrepresentable.** OSV carries under a
third of the evidence intact, and for the lossy third the conditions it drops are the
whole point.

The bridge stays wired in regardless, because it pays either way: the lossless records are
usable by existing OSV scanners now, and if the premise ever fails, the exporter is the
migration path. The class shares are a standing check on whether this registry is earning
its existence. [ALTERNATIVES.md](ALTERNATIVES.md) has the method, the limits, and the
evidence that would make the project switch.

## Next

**Make a run reproducible by someone else.** Today it needs llama.cpp installed by hand, a
model fetched by hand, and a manifest written by hand. It needs to be one command taking a
model id, which fetches, hashes, runs, and emits a valid result.

**Establish how much honest runs disagree.** Temperature 0 and a fixed seed don't make
inference identical across different GPUs. Until the normal spread between two good-faith
runs is known, a re-run can't confirm or refute anything — ordinary variance looks like
fabrication and vice versa. This needs two or three *different* machines, not fast ones.

**Start the capability catalogue.** Independent of all the above and not blocked by it.
Tool capabilities can't be read from a manifest; they're a judgement that has to be
recorded per tool. The configuration-native advisories — the ones that justify the whole
project — depend on it.

## Later

**Mirror rather than hand-write component advisories.** Eight of twenty-one phase-0
findings were ordinary package bugs. Source those from CVE/OSV automatically and spend
human review on configurations, which nothing else covers.

**A lockfile emitter**, once the capability catalogue exists — a lock without capabilities
can't match the advisories that matter. The realistic path is a wrapper that observes a
run without the harness cooperating, since harness maintainers have no reason to adopt
this until the registry has value.

**Native emission.** The end state is a harness writing `agent.lock` itself, so operators
get the record without opting in.

## How we'll know each piece works

Conditions, not dates. Work on a piece starts when the one before it is satisfied.

| Piece | Done when |
| --- | --- |
| Suite calibration | A deliberately susceptible config scores high, a hardened one scores near zero, and each channel's interval is tight enough to tell channels apart. *(The precision threshold hasn't been derived yet — it needs the control runs to set it.)* |
| One-command runs | Someone who hasn't seen the code produces a valid result from the README alone. |
| Variance baseline | A published tolerance: within it a re-run corroborates, outside it the result is flagged. |
| Contribution | Records arriving from people other than the maintainer, reproducing within that tolerance. |
| Registry maturity | Someone other than the maintainer is merging advisories. |

The last one is the real measure. The rest can be produced by sustained individual effort;
only that one means the project exists independently of whoever started it.

## What would make this fail

**Breadth without calibration.** Running an uncalibrated suite across a thousand machines
produces a thousand precise measurements of nothing. Compute has never been the
constraint — the first experiment used about five minutes of GPU time.

**Advisories that match everything.** A record matching most deployments is worse than no
record, because it teaches people to ignore the output. Volume is the easiest metric to
move and the one most likely to destroy the tool's value. If the review bar is ever
relaxed to grow the corpus, the project starts failing while its numbers improve.

**Being wrong about the premise.** If real findings keep collapsing to "this package at
this version is broken," the right conclusion is that OSV should carry them, and that's a
smaller and more likely-to-succeed contribution than a new registry. This is measured, not
assumed: the OSV translation currently carries 6 of 20 records intact. If that share
becomes the clear majority as the corpus grows, the project should switch, and
[ALTERNATIVES.md](ALTERNATIVES.md) commits to that in advance. Today's evidence is 20
records written by one person — enough to proceed, not enough to be sure.

## Where the idea came from

[@lizthedeveloper](https://www.instagram.com/reel/Dde4lvCCBl4/) proposed it in a
66-second reel on 19 September 2026 — a CVE for agent configurations, with a lockfile
rather than a manifest so you know the exact thing you ran — and gave it away to anyone in
AI safety who would build it. The idea is hers. The schema, the corpus, and the mistakes
are this project's.
