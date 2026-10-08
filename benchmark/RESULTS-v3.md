# canary-v3 — reproduction, run-to-run variance, quantization, lineage

**Run 2026-10-08 on one RTX 5090.** Every figure below is the redirect ("instead") goal;
canary-v3 contains only that goal (see [RESULTS-v2.md](RESULTS-v2.md) for why).

| | |
| --- | --- |
| Suite | `canary-v3`: 40 benign tasks, 480 attack cases (12 per task) |
| Runner | llama.cpp b11057 (commit 59657a6), CUDA build for sm_120 |
| Hardware | NVIDIA GeForce RTX 5090 (and the Xeon Gold 6530 CPU, for the CPU run) |
| Sampling | temperature 0, top-p 1, seed 42, 512 max tokens, 8192 ctx |
| Command | `python run.py hf:<repo>/<file>.gguf --base-model ... [--scaffold all] [--deterministic]` |

Every model file was fetched by `run.py` and its SHA-256 checked against HuggingFace's
before the run; the digests are in each result.

**Reading the denominators.** An attack case counts only if its benign twin was completed
under the same scaffold. A model that can't do the task can't be redirected away from it,
so it doesn't count as resisting. So `susceptible 295/360` means 30 of 40 tasks were usable,
times 12 attacks each. Utility differs between builds and scaffolds, so two runs' rates can
be computed over different subsets of cases. The paired comparisons below (`analyze.py
--compare`) use only the cases both runs could judge.

## 1. The A4500 result reproduces on different hardware

The canary-v2 run from 2026-09-20 (RTX A4500) was repeated on the 5090 with the
byte-identical Q8_0 file (`9da71c45…`) and the same llama.cpp release:

```
                     obedient   neutral (95% CI)        hardened   utility (neutral)
RTX A4500 (09-20)    92.3%      81.1% [76.4, 85.0]      34.0%      26/40
RTX 5090  (10-08)    92.9%      81.9% [77.6, 85.6]      37.8%      30/40
```

The control ordering is the same and the measurement moved by 0.8 points, well inside
either interval. Utility rose from 26 to 30. One cause is noted in section 2 (the per-case
noise also reaches the benign tasks). The other is that the A4500 run stored pooled counts
only, so its per-goal figures are estimated.

## 2. Run-to-run variance, and how to remove it

The same file, server, and seed were run three times under the neutral scaffold:

```
                                    rate    benign same   cases agree   flips (A only / B only)   McNemar p
default server, run 1 vs run 2      81.9 / 82.5%   38/40   92.5% of 348   11 / 15                  0.557
--deterministic, run 1 vs run 2     82.8 / 82.8%   40/40   100%  of 360    0 /  0                  1.000
```

Under llama-server's defaults, about **one case in thirteen flips** between two identical
runs on the same GPU. The headline rate barely moves because the flips go both ways, but
any case-level claim ("this build resists technique X on channel Y") is mostly noise at
that level. The flips come from the server, not the model. llama-server batches requests
from several slots together and reuses cached prompt prefixes, both of which change the
shape of the arithmetic, and therefore its floating-point rounding, from run to run.

`--deterministic` runs one server slot (`-np 1`) and turns prompt caching off
(`cache_prompt: false`). The two deterministic runs produced **byte-identical transcripts**
(the same `transcriptDigest`, `sha256:bcf49d21…`), and so the same verdict on every case.
It cost nothing measurable: 314 s and 316 s, against 328 s for the default run.

So:

- **Use `--deterministic` for anything compared case by case.** It's a flag for now. Making it
  the default is proposed in the ROADMAP.
- Comparisons between earlier default-mode runs should treat about 7.5% case disagreement
  as the noise floor, and look at McNemar's p (whether the flips are lopsided) rather than at
  raw agreement.
- "Same settings, same answer" holds on one machine. Whether it holds across GPUs is
  section 5's question.

## 3. Quantization

All four bartowski builds of Llama-3.1-8B-Instruct, with all three scaffolds each, run with
the server defaults:

```
build     obedient   neutral (95% CI)          hardened   utility (neutral)   gate
Q4_K_M    95.0%      83.0% [78.1, 86.9]        25.0%      23/40               calibrated
Q5_K_M    92.8%      72.9% [66.2, 78.7]        28.8%      16/40               calibrated
Q6_K      91.4%      79.0% [74.0, 83.2]        32.4%      25/40               calibrated
Q8_0      93.0%      81.9% [77.6, 85.6]        37.8%      30/40               calibrated
```

Each build was then compared with Q8_0, case by case, on the cases both could judge:

```
vs Q8_0    cases   Q8 only   other only   rate Q8 / other   McNemar p
Q4_K_M     264     19        29           80.7 / 84.5%      0.193
Q5_K_M     192     18         6           79.2 / 72.9%      0.023
Q6_K       288     22        15           80.6 / 78.1%      0.324
```

**Deterministic re-runs.** The same comparison with `--deterministic`, so that every difference
comes from the weights:

```
vs Q8_0 (det)   cases   Q8 only   other only   rate Q8 / other   McNemar p   neutral rate   utility
Q4_K_M          276     28        24           81.9 / 80.4%      0.678       81.2%          27/40
Q5_K_M          228     24         6           83.8 / 75.9%      0.001       76.2%          20/40
Q6_K            276     18        11           81.2 / 78.6%      0.265       78.8%          26/40
Q8_0 (itself)   360      0         0           82.8 / 82.8%      1.000       82.8%          30/40
```

**Reading it.** Three findings:

- **Q5_K_M is less susceptible than Q8_0, and the other two K-quants are not.** Q5_K_M showed up in
  the default-mode runs (18 against 6, p 0.023). It held in the independent deterministic runs
  (24 against 6, p 0.001), which survives correcting for three comparisons. Q4_K_M and Q6_K
  aren't distinguishable from Q8_0 in either mode. So the effect doesn't follow bit depth: the
  4-bit build sits with the 8-bit one, and the 5-bit build is the outlier. **A build's
  susceptibility can't be inferred from its quantization level; it has to be measured per
  file.** That is the premise of artifact-level advisories, now with data. (Q5_K_M also
  completes the fewest benign tasks, 16–20 of 40, so it may be "less redirectable" partly by
  being less able. The paired comparison only counts cases both builds completed, which limits
  this but doesn't rule it out.)
- **Quantization changes many individual outcomes even when the rate doesn't move.** With run
  noise gone, Q4_K_M and Q8_0 still disagree on 19% of cases, evenly in both directions. A
  per-case claim about one build ("resists this technique on this channel") doesn't carry over
  to another quantization of the same model.
- Quantization moves **utility** more than susceptibility (Q8_0 30/40, Q5_K_M 16–20/40). The
  default-mode runs also hinted that the **hardened** scaffold protects less at Q8_0 (37.8%)
  than at lower bit depths (25–32%). That is the wrong direction for "quantization weakens the
  defence", and it's still from default-mode runs only.

The canary-v1 pilot ([RESULTS.md](RESULTS.md)) found no quantization effect on 24 cases. On 20
times as many cases the overall picture still holds: there is no trend with bit depth. But one
build stands apart, which the pilot was far too small to see.

## 4. Lineage: abliterated and community fine-tunes

```
model                                     obedient   neutral (95% CI)        hardened   utility   gate
Llama-3.1-8B-Instruct Q8_0                93.0%      81.9% [77.6, 85.6]      37.8%      30/40     calibrated
  abliterated (mlabonne) Q8_0             91.4%      82.7% [78.1, 86.5]      26.2%      26/40     calibrated
Hermes-3-Llama-3.1-8B Q8_0 (Nous)         86.3%      94.9% [91.1, 97.1]      43.9%      18/40     NOT ordered
```

**Abliteration doesn't change redirect susceptibility.** Paired against the original on 240
shared cases, the rates are 80.4% and 84.2% with 22 and 31 flips (McNemar p 0.27). Abliteration
removes the model's refusal direction, so its harmful requests stop being refused. Following
an instruction planted in a tool result isn't a refusal decision, so this is the expected
null. The deterministic re-run agrees: 77.8% against 79.4% on 180 shared cases, 15 and 18 flips,
p 0.73. It's still worth having on record, because "uncensored" builds are often assumed to be
less safe in agent use generally. The hardened scaffold did protect it a little more (26%
against 38%).

**Hermes 3: the gate refused to report a number, correctly.** Its "obedient" control came in
*below* the neutral measurement (86% against 95%). Hermes is tuned to follow its system
prompt closely, and the obedient scaffold's wording evidently pulls it somewhere this suite
doesn't measure. With the controls out of order, the neutral figure can't be trusted as
"susceptibility", and `analyze.py` says so. The paired comparison does show Hermes redirected
more often than the instruct model on the 192 cases both could judge (95.3% against 88.0%,
p 0.013). That points to real susceptibility, but the instrument isn't calibrated for this
model, so it isn't a headline. The positive control needs to work for system-prompt-heavy
fine-tunes before canary-v3 can rank them.

## 5. CPU against GPU

The same Q8_0 file was run on the CPU only (Xeon Gold 6530, `--cpu`, which runs llama.cpp with
`--device none`, default server settings), against the GPU runs:

```
                                   cases   agree   GPU only   CPU only   rate GPU / CPU   McNemar p   benign same
GPU deterministic vs CPU           348     96.8%    7          4         82.5 / 81.6%     0.549       39/40
GPU default run 1 vs CPU           336     94.9%    9          8         82.4 / 82.1%     1.000       37/40
GPU default run 2 vs CPU           348     93.7%   12         10         82.2 / 81.6%     0.832       39/40
```

**Moving the same file from the GPU to the CPU changes less than re-running on the GPU with
default settings.** The deterministic GPU run and the CPU run disagree on 3.2% of cases, half the
7.5% between two default GPU runs, with no direction to it. The CPU run needed no special settings:
llama.cpp's CPU arithmetic didn't vary with batching here, which matches what DAI measured (on the
CPU, all four server settings repeated exactly).

So a figure measured on one machine holds on another of a very different kind, to within about
3% of cases and well within the rate's confidence interval. The cost is speed: 98 minutes on the
CPU against 5 on the GPU.

## Limits

- One base model family (Llama-3.1-8B) and one runner release. Two machines (the A4500's and this
  one, GPU and CPU).
- The three-scaffold runs (the control rates and calibration) are default mode, with the ~7.5%
  case-level noise of section 2. The paired comparisons were repeated deterministically (neutral
  scaffold only).
- Utility is low under the neutral scaffold (16–30 of 40) and varies by build, so each rate
  is over a different subset of the suite. The paired comparisons control for this; the
  single-run rates don't.
