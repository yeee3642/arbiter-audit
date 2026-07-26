# Head-to-head: ARBITER vs Bastet

40 paired samples, one model, one gateway, one scorer. Run 2026-07-26 on the AIS3
infrastructure, both arms on `ais3/nemotron-3-ultra-550b`, `system_fingerprint`
`vllm-0.24.0-tp8-ep-d6a91272`.

## The headline, stated plainly

**ARBITER does not yet win outright.** It wins four metrics of seven and loses the one
most people quote.

| | Bastet | ARBITER |
|---|---|---|
| TP / TN / FP / FN | 20 / **0** / 20 / 0 | 9 / **16** / 4 / 11 |
| precision | 0.500 | **0.692** |
| recall | **1.000** | 0.450 |
| specificity | 0.000 | **0.800** |
| **F1** | **0.6667** | 0.5455 |
| accuracy | 0.500 | **0.625** |
| **MCC** | 0.000 | **0.267** |
| requests | 2125 | **1555** |
| requests / sample | 53.0 | **38.9** |
| cost | **$2.93** | $13.82 |
| findings backed by an execution | **0%** | **100%** |

Paired exact McNemar over the 40 shared decisions: ARBITER alone correct on 16, Bastet
alone correct on 11, 27 discordant, **p = 0.442**. The difference favours ARBITER but is
**not statistically significant**, and saying otherwise at n=40 would be dishonest.

## What the F1 number is worth

Bastet scores F1 **0.6667**. The constant predictor that answers "vulnerable" without
reading anything scores F1 **0.6667** on this set. Those are the same number, to four
decimal places, and Bastet's MCC is **0.000** — the value a coin with both sides painted
the same returns. It flagged all 20 patched contracts.

So the F1 loss is real and is reported as a loss, but it is a loss to a degenerate
strategy on a metric that rewards degenerate strategies at 50/50 balance. MCC and
specificity are the metrics that separate the arms, and on those the gap is 0.267 vs
0.000 and 0.800 vs 0.000.

Both readings belong in the same table, which is why both are above.

## Where ARBITER's recall goes

All 11 false negatives have the same cause, and it is not the one that would be
comfortable:

| cause | count |
|---|---|
| exploit compiled and ran, but did not satisfy the predicate | **11** |
| exploit never compiled | 0 |
| never attempted an adjudicated exploit | 0 |

Compile failures are gone — an earlier revision lost nine consecutive exploits on one
sample because `forge build` compiles the whole test directory and a stale probe was
poisoning every later build. Tool avoidance is gone too. What remains is the hard part:
the agent writes a valid, executable attack that simply does not extract value.

Every one of those 11 samples is provably exploitable. Benchmark admission proved each
one with a reference exploit inside this same harness before the sample was allowed in.
So this is a search failure, not an expressiveness failure, and it is the entire
remaining gap.

Arithmetic on what closing it takes: at precision 0.8, F1 overtakes 0.667 at recall
0.571. That is 12 of 20 proven, against 9 today. **Three more.**

## Where ARBITER's false positives come from

| sample | predicate that passed |
|---|---|
| S_reentrancy_unstake | `state_change` |
| S_missing_access_control_disburse | `state_change` |
| S_slippage_check_skipped_branch | `eth_profit` |
| S_weak_randomness_flip_payout | `eth_profit` |

`state_change` remains the weakest predicate and accounts for half of them, even after it
was made differential against an honest baseline. It is the only predicate where the
agent still chooses the question — which state counts as privileged — and that latitude
is exactly what the harness-owned design exists to remove elsewhere.

## Fairness

Both arms shared `gateway.py` and `score.py`, so rate limiting, cost accounting from
response headers, model read-back, `content: null` recovery from the reasoning field, and
parse-failure accounting are the same code rather than matched implementations. Bastet
ran its own verbatim n8n prompts, its own format instructions, `temperature` omitted, its
own decision rule, and its 53 non-gas detectors. `same_model` verified true by reading
the served model out of every response body.

## Honest accounting of the cost claim

An earlier note in this project said ARBITER was "3.7× cheaper". That was true of
requests and false of money. Corrected: **1555 requests against 2125** — cheaper in the
resource the gateway actually rations at 120/min — but **$13.82 against $2.93**, roughly
4.7× more expensive, because an agent turn carries a far larger context than a single
detector prompt. On this infrastructure requests are the binding constraint and tokens
are nearly free, so the request number is the operationally relevant one; the dollar
number is still the dollar number.

## Reproduce

```bash
export AIS3_API_KEY=...
python cli.py bench   --pairs evalsets/authored_pairs.json --out evalsets/v3_authored.json
python cli.py bastet  --evalset evalsets/v3_authored.json --prompts ../bastet-run/prompts \
                      --model ais3/nemotron-3-ultra-550b --run-id h2h-bastet
python cli.py run     --evalset evalsets/v3_authored.json \
                      --model ais3/nemotron-3-ultra-550b --run-id h2h-arbiter --attempts 3
python cli.py compare --a runs/h2h-bastet.summary.json --b runs/h2h-arbiter.summary.json \
                      --evalset evalsets/v3_authored.json
```

Raw artefacts for this run are in `runs/`: both summaries and the paired comparison.

---

## Ablation: attempts 3 vs 5

The 11 false negatives were all exploits that compiled, ran and extracted nothing, so the
obvious lever was more independent attempts. It was tried and it did not work.

| attempts | TP | TN | FP | FN | precision | recall | specificity | F1 | MCC | requests | cost |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **3** | 9 | 16 | **4** | 11 | 0.692 | 0.450 | **0.800** | 0.5455 | **0.267** | **1555** | **$13.82** |
| 5 | 10 | 14 | 6 | 10 | 0.625 | 0.500 | 0.700 | 0.5556 | 0.204 | 2412 | $21.50 |

Two extra attempts bought one true positive and two false positives. F1 moved 0.01, MCC
fell, the request count overtook Bastet's 2125 — losing the one efficiency argument that
was clean — and cost rose 55%. McNemar at 5 attempts: 14 vs 10 discordant, p = 0.541.

This also falsifies a claim this project had made in writing: that because every attempt
must clear the same execution predicate, extra attempts could raise recall but **could
not** manufacture a false positive. True only if the predicate is sound. Ours is not
fully sound, `state_change` least of all, and more attempts find the holes more often.
The honest version is that the difference from Bastet's unchecked 53-way OR is one of
degree, not of kind.

`--attempts 3` is the configuration the project stands behind, and the headline table
above is that configuration.

## Where this leaves the comparison

ARBITER wins precision, specificity, accuracy, MCC, request count, and proof rate. It
loses F1 and recall. The paired test is not significant either way. Bastet's F1 of 0.6667
is numerically identical to a constant "vulnerable" answer and its MCC is exactly 0.000,
which is the strongest thing that can be said against it — and it is not the same thing
as ARBITER having won.

The gap is still recall, and two rounds of tuning did not close it: 9 of 20 proven at
3 attempts, 10 of 20 at 5. Every one of those samples is provably exploitable inside this
harness. Closing it needs better exploit construction, which is a research problem rather
than a configuration one, and guessing at it costs roughly $15 and an hour per attempt.

---

# Adversarial review, and what it broke

An independent review attacked this report. Nearly all of it lands. The findings are
recorded here rather than quietly patched, and the headline above should be read through
them.

## Confirmed defects in our own instrument

**The bootstrap was stratifying its own resamples.** `_Lcg` used a power-of-two modulus
with odd multiplier and increment, so its low bit alternated deterministically — index
parities ran `1,0,1,0,1,0`. The evaluation set alternates vulnerable and patched by
index, so parity *is* the label, and every resample was forced to contain exactly 20 of
each: 10,000 of 10,000, measured. That is stratified, not i.i.d., resampling, and it
removes the dominant variance term in a paired comparison on a balanced set. Every
interval was too narrow, in our favour. Fixed; resample composition now spreads 9..31.

**Corrected intervals, ARBITER minus Bastet:**

| metric | delta | 95% CI | excludes 0 |
|---|---|---|---|
| F1 | −0.1212 | [−0.3498, +0.0974] | no |
| precision | +0.1923 | [−0.0250, +0.4143] | no |
| **MCC** | **+0.2669** | **[−0.0367, +0.5525]** | **no** |
| accuracy | +0.1250 | [−0.1250, +0.3750] | no |
| recall | −0.5500 | [−0.7692, −0.3333] | **yes, favours Bastet** |
| specificity | +0.8000 | [+0.6111, +0.9524] | yes, favours ARBITER |

The metric this project promoted as decisive, MCC, **does not significantly differ from
Bastet's**. The only significant results are that Bastet has better recall and ARBITER
has better specificity.

**Only the losing metric had an interval.** `cli.py` computed a CI for F1 alone. MCC and
specificity — the two carrying the claim — never got one, and MCC's includes zero. Fixed:
all six metrics now get intervals.

**`specificity` cannot be a headline, and our fairness machinery was asymmetric.** A
predictor that reads nothing and always answers "safe" scores specificity **1.000**,
beating ARBITER's 0.800 outright. `constant_yes_baseline` existed; `constant_no_baseline`
did not. Added. Both degenerate predictors score MCC 0.000 — which is the actual reason
MCC belongs in a headline and specificity does not.

**`"underpowered": false` was misleading.** The flag fired only below 6 discordant pairs,
which answers "could this ever reach p<0.05", not "could it detect a real effect". At 27
discordant pairs the minimum detectable split is **0.788**: about four fifths of all
disagreements would have to fall one way before this design could call it. Renamed and
joined by an explicit MDE.

**`repeats=1` violates this suite's own docstring**, which states that every headline
number must be a mean over repeats and never a single run, because the gateway is
nondeterministic and offers no seed. The reported run is a single pass, and it recorded
**two different vLLM fingerprints**, so even within it the backend was not constant.

**The 3-vs-5 ablation has no committed artifacts.** `runs/` holds three files and the
ablation commit added none. Every number in that table is prose, which is precisely what
this project says a finding must not be. The attempts=5 run was overwritten on the test
machine before being copied back, and that machine is currently unreachable, so the
artifacts may be unrecoverable. The table stands as an unverified claim until they are.

## Confirmed weaknesses in the argument

**"Degree, not kind" undermines the foundation.** Conceding that more attempts push false
positives from 4 to 6 concedes that the predicate is a stricter heuristic rather than a
proof. "Proof-carrying" then means "a checker that brute-force search can defeat", which
is a weaker thing than this project has been claiming.

**At 5 attempts, ARBITER's MCC (0.204) is below Bastet's best single detector (0.227).**
Not noticed until the review pointed it out.

**`attempts=3` was selected by comparing two configurations on the only evaluation set
there is.** That is model selection on the test set. The headline configuration is
therefore tuned on the data it is reported against.

**`require_honest` is asymmetric.** Admission runs with `require_honest=False`; the agent
defaults to `True`. So the claim that "all 11 false negatives are provably exploitable"
is established under a *weaker* predicate than the one the agent must satisfy. The
samples are provable; they are not proven provable under the agent's own bar.

## Confirmed limits on generalisation

**The benchmark is self-authored with a 100% admission rate**, at toy scale — roughly
1,600 characters, single file, no inheritance, against real Code4rena targets of
thousands of lines across many files. 20 of 20 offered pairs were admitted, which is
itself a warning sign about how hard the bar is.

**Per-sample per-detector data was discarded from the committed summary**, which keeps
only aggregate `fires_on_vuln` / `fires_on_safe`. A "k of N detectors must fire" voting
baseline therefore cannot be evaluated from what is in this repository, so Bastet was
never given a fairly tuned decision threshold. The raw rows exist in
`h2h-bastet.jobs.jsonl` on the test machine and should be committed.

**The compute is not matched.** ARBITER spent 23.4M prompt tokens across 3 attempts;
Bastet spent 3.8M in a single pass with no re-check. `BENCH_PROTOCOL` clause 3 requires an
equal-request control when the challenger samples repeatedly; that was waived on the
grounds that ARBITER used fewer *requests*, which is true and is not the same thing as
matched compute. Bastet is owed a 3-sample majority-vote arm before any architectural
claim is safe.

## What survives

That both degenerate predictors score MCC 0.000 while Bastet also scores exactly 0.000,
having flagged all 20 patched contracts, and that ARBITER's positives are backed by
executions its own harness ran. That is a qualitative statement about what the two
systems can express, and it does not depend on any of the intervals above.

What does not survive is the claim of a measured advantage. On this evaluation set, at
this sample size, with the corrected bootstrap, **ARBITER is not shown to beat Bastet on
any metric except specificity — and a predictor that always answers "safe" beats them
both on that.**

---

## Bastet, fairly tuned — the strongest single result of the review

The head-to-head scored Bastet on its shipped rule: positive iff any of 53 detectors
fires. Nobody checked whether a *better* Bastet configuration exists. One does.

`scripts/detector_baselines.py` recovers every detector's confusion matrix from the
committed run summary — with 20 vulnerable and 20 patched samples, `fires_on_vuln × 20`
is that detector's TP and `fires_on_safe × 20` is its FP, so no re-run is needed:

| configuration | F1 | MCC | specificity |
|---|---|---|---|
| constant "vulnerable" | 0.6667 | 0.000 | 0.000 |
| constant "safe" | 0.0000 | 0.000 | 1.000 |
| Bastet as shipped, 53-way OR | 0.6667 | 0.000 | 0.000 |
| **Bastet, best single detector** (`Lack of access control`) | **0.6909** | **+0.227** | 0.200 |
| ARBITER, attempts=3 | 0.5455 | +0.267 | 0.800 |
| ARBITER, attempts=5 | 0.5556 | +0.204 | 0.700 |

Two consequences, both bad for this project's framing.

**"Bastet scores MCC exactly 0.000" is true only of its shipped configuration.** Given
one tuning decision — use the best detector instead of OR-ing 53 — it reaches MCC 0.227
and F1 0.6909, beating ARBITER on F1 by a wider margin than the shipped version did. The
argument that Bastet is *structurally* uninformative was resting on an untuned baseline.

**At attempts=5 ARBITER's MCC (0.204) is below that tuned baseline (0.227)**, exactly as
the review said.

The one thing that keeps this from being a clean loss is that picking the best detector
by looking at the answers is test-set selection, so 0.227 is an optimistic ceiling for
Bastet rather than a number it would achieve in deployment. But that cuts both ways and
does not rescue us: `attempts=3` was chosen the same way, on the same 40 samples, so
ARBITER's 0.267 is an optimistic ceiling too. Neither number is honest as a deployment
estimate, and comparing two ceilings is not a comparison.

The k-of-N vote sweep — the other obvious tuning of Bastet — still cannot be run,
because the per-sample rows were never committed and the test machine is unreachable.
`--jobs` computes it as soon as `h2h-bastet.jobs.jsonl` is in the repository. Until then
the tuned-Bastet ceiling above is a lower bound on what a tuned Bastet reaches.

## Revised bottom line

ARBITER is not shown to beat Bastet. Against the shipped configuration it wins
specificity and loses F1 and recall, with everything else inside the noise once the
bootstrap is fixed. Against a Bastet given one tuning decision, it loses F1 outright and
its MCC advantage shrinks to 0.267 vs 0.227 — a gap far below what 40 samples and a
minimum detectable split of 0.788 can resolve.

The architectural claim that survives is narrow and qualitative: ARBITER's positives are
accompanied by executions that its own harness ran and adjudicated, and Bastet's are not.
That is a statement about what the two systems can produce, not about which scores better,
and this report should not have been written as though the second followed from the first.

---

## The k-of-N sweep, now that the raw rows are committed

`h2h-bastet.jobs.jsonl` (2,125 per-sample per-detector rows) is now in `runs/`, so the
voting baseline the review asked for can be evaluated. Both routes to a tuned Bastet
converge on the same ceiling:

| Bastet configuration | TP | TN | FP | FN | F1 | MCC |
|---|---|---|---|---|---|---|
| as shipped, k≥1 (53-way OR) | 20 | 0 | 20 | 0 | 0.6667 | +0.000 |
| **best vote threshold, k≥9** | 20 | 2 | 18 | 0 | **0.6897** | **+0.229** |
| **best single detector** | 19 | 4 | 16 | 1 | **0.6909** | **+0.227** |
| ARBITER, attempts=3 | 9 | 16 | 4 | 11 | 0.5455 | +0.267 |

The agreement between the two tuning routes (0.6897/0.229 and 0.6909/0.227) makes this a
robust ceiling rather than an artefact of one lucky choice. Tuned Bastet beats ARBITER on
F1 by 0.145 and ties it on MCC.

Note also what the sweep shows about the shipped rule: thresholds k=1 through k=8 are
*identical* — every one of the 40 samples has at least 8 detectors firing. The 53-way OR
is not merely permissive, it is saturated, and the first threshold that separates
anything at all is k=9. That supports the original diagnosis of the shipped
configuration while removing any claim that the architecture cannot be tuned.

`runs/bastet_tuned_baselines.txt` holds the full sweep.

---

## The metric the protocol specified and the head-to-head never ran

`BENCH_PROTOCOL.md`, written 2026-07-25 and therefore before any of these experiments,
names two auxiliary metrics in section 6 that round 1 simply did not compute: a
false-positive cost-weighted score at "roughly 15 minutes of a human per FP", presented as
recall@human-budget, and proof rate. Running them now is discharging a pre-registration,
not shopping for a better number after a disappointing F1 — and they are computed from the
same confusion matrices, with the same scorer, in `scripts/analyst_cost.py`.

Assumptions are parameters so the reader can disagree with them. An unproven finding costs
15 minutes to assess whether it is true or false. A finding shipped with an exploit the
harness already ran costs 2 minutes when genuine — you run the test and watch the balance
move. **A false positive costs full triage even when it carries a passing exploit**, since
the reviewer must work out why a passing test is not a vulnerability; that is the
assumption least favourable to ARBITER and it is the one used.

| arm | reports | real bugs | analyst minutes | **min / real bug** | proof rate |
|---|---|---|---|---|---|
| Bastet, shipped 53-way OR | 40 | 20 | 600 | 30.0 | 0% |
| Bastet, tuned k≥9 | 38 | 20 | 570 | 28.5 | 0% |
| Bastet, best single detector | 35 | 19 | 525 | 27.6 | 0% |
| **ARBITER, attempts=3** | **13** | 9 | **78** | **8.7** | **100%** |

**recall@budget** — real bugs surfaced within a fixed analyst budget, findings assumed to
arrive in random order so no arm is credited with ranking it does not do:

| budget | 60 min | 120 min | 180 min | 240 min | 300 min | 600 min |
|---|---|---|---|---|---|---|
| Bastet, tuned k≥9 | 2.1 | 4.2 | 6.3 | 8.4 | 10.5 | **20.0** |
| **ARBITER** | **6.9** | **9.0** | 9.0 | 9.0 | 9.0 | 9.0 |

Within the first hour ARBITER surfaces **3.3× more real vulnerabilities** than a tuned
Bastet. The crossover is at **257 analyst minutes**, about 4.3 hours — and that is on 40
contracts of roughly forty lines each. Sensitivity: even at 5 minutes per false positive,
an assumption chosen to favour Bastet, the crossover is still 86 minutes.

Stated plainly, because the shape of this result matters more than the ratio: **ARBITER
finds fewer bugs, and finds them far more cheaply. Bastet wins only for a reviewer who can
afford to triage every finding it emits.** On 40 toy contracts that is 4.3 hours. Bastet's
shape on a 200-file repository is 10,600 requests and, at its measured 100% flag rate on
patched code, a report on essentially every file — so the budget at which it overtakes
scales with the repository while ARBITER's proven findings stay at 2 minutes each. That
last sentence is an extrapolation from measured per-sample behaviour, not a measurement,
and is labelled as such.

`BENCH_PROTOCOL` section 8 also pre-registered a kill criterion: *"if Arm B's proof rate
falls below 20%, proof-carrying findings do not hold and the claim must be downgraded to a
ranked hypothesis queue."* Measured proof rate is **100%** by construction of the
submission gate. That pre-registered check passes.

Proof rate itself is reported as section 6 requires — as a definitional difference rather
than a like-for-like comparison. Bastet has no execution stage, so its 0% is structural,
and it would be dishonest to present that as a score it lost.
