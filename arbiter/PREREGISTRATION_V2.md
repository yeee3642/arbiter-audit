# Pre-registration: ARBITER vs Bastet, round 2

Written **before** the run, because round 1's headline configuration was chosen by
comparing two settings on the only evaluation set there was. Everything below is fixed
now and may not be changed after seeing a number.

Round 1's outcome, for the record: **ARBITER was not shown to beat Bastet.** Against a
fairly tuned Bastet it loses F1 0.5455 to 0.6909 and ties MCC 0.267 to 0.227. Round 2
exists to answer the question properly, not to keep trying until the answer is
favourable.

---

## 1. What round 1 got wrong, and what each fix is

| defect | fix | status |
|---|---|---|
| bootstrap PRNG stratified its resamples, narrowing every CI in our favour | `random.Random` | **done** |
| CI computed for F1 only — the metric we lose | all six metrics get CIs | **done** |
| `constant_no_baseline` missing while `constant_yes` existed | added; kills specificity as a headline | **done** |
| `underpowered` flag answered the wrong question | renamed; `minimum_detectable_split` added | **done** |
| Bastet never tuned; scored only on its shipped 53-way OR | best-detector and k-of-N sweeps | **done** |
| per-detector rows never committed | `h2h-bastet.jobs.jsonl` committed | **done** |
| `repeats=1` violates this suite's own docstring | `repeats=3`, both arms | round 2 |
| compute not matched: 23.4M vs 3.8M prompt tokens | Bastet gets a 3-sample majority-vote arm | round 2 |
| `attempts=3` selected on the test set | tuning split, frozen before TEST | round 2 |
| ablation table had no artefacts | every arm's raw rows committed | round 2 |
| `require_honest` asymmetric between admission and agent | symmetric, see §5 | round 2 |
| n=40 gives MDE 0.788 | benchmark doubled, see §3 | round 2 |

## 2. Splits — fixed now

The benchmark is split by **pair**, not by sample, so a vulnerable contract and its patch
never land on opposite sides.

| split | pairs | role |
|---|---|---|
| TUNE | 20 (the existing v3 set) | every configuration decision: `attempts`, turn budget, prompt wording, and Bastet's `k`. Read as often as needed. |
| TEST | 20 new pairs, authored after this document | read **once**, after everything is frozen. |

Round 1's 40 samples become TUNE in their entirety. They are burnt for claim purposes:
every number reported from them is a tuning number and will be labelled as such.

## 3. Power, stated before the run rather than after

At α=0.05 and 80% power, exact McNemar needs this many discordant pairs:

| discordant | minimum detectable split |
|---|---|
| 27 (round 1) | 0.788 |
| 49 | 0.700 |
| 90 | 0.650 |

Round 1's discordant rate was 27/40 = 0.675. So:

- **40 TEST samples → ~27 discordant → MDE 0.79.** Same as round 1. Not worth running.
- **80 TEST samples → ~54 discordant → MDE ≈ 0.69.** The practical target.
- 160 TEST samples → ~108 discordant → MDE ≈ 0.64. Better, and probably out of budget.

**Decision: TEST is 40 new pairs = 80 samples.** If the observed discordant count comes in
below 49, the result is reported as underpowered and no comparative claim is made,
whichever direction it points.

## 4. Arms — all four, all at `repeats=3`

| arm | description | requests |
|---|---|---|
| A1 | Bastet, shipped 53-way OR | 80 × 53 × 3 = 12,720 |
| A2 | Bastet, best `k` from TUNE, 3-sample majority vote per detector | 12,720 (reuses A1 draws) |
| B1 | ARBITER, `attempts` fixed from TUNE | 80 × ~39 × 3 ≈ 9,360 |
| B2 | ARBITER, single attempt — the matched-compute control | 80 × ~14 × 3 ≈ 3,360 |

A2 discharges fairness clause 3: it is the equal-compute control that round 1 waived on
the grounds that ARBITER used fewer *requests*, which was true and is not the same thing.
B2 is the reverse control — it shows how much of ARBITER's result comes from the
architecture rather than from repeated sampling.

Estimated total ≈ 38,000 requests. At 45 rpm that is **about 14 hours** and, extrapolating
round 1's per-request cost, **roughly $60–90**. That is the price of an answer that
survives review; it should be approved before starting, not discovered afterwards.

## 5. `require_honest` becomes symmetric

Round 1 ran admission with `require_honest=False` and the agent with `True`, so "these
samples are provably exploitable" was established under a weaker predicate than the agent
had to satisfy. In round 2, **admission runs with `require_honest=True`** and every pair
must supply an `honest_body`. A pair whose reference exploit cannot beat its own honest
baseline does not enter the benchmark.

Expected consequence: the 100% admission rate will fall. That is the point — a 20/20
admission rate is evidence the bar was too low, not that the samples were good.

## 6. Primary outcome and decision rule — fixed now

**Primary metric: MCC.** Chosen because both degenerate predictors score exactly 0.000 on
it, so neither "always vulnerable" nor "always safe" can win it. F1 is reported but is not
primary: it rewards constant-yes at 50/50 balance. Specificity is reported but is not
primary: constant-no scores 1.000.

**Primary comparison: B1 vs A2** — our best configuration against Bastet's best
configuration, both frozen on TUNE. Comparing against A1 alone would be comparing against
a strawman, which is what round 1 did.

Declared before the run:

- **ARBITER wins** iff the paired bootstrap CI for `MCC(B1) − MCC(A2)` excludes zero and
  is positive, **and** the exact McNemar p < 0.05, **and** the discordant count ≥ 49.
- **Bastet wins** under the mirror condition.
- **Inconclusive** otherwise, and it will be reported as inconclusive in the first line of
  the results, not buried under whichever secondary metric happened to look good.
- If B1 does not beat **B2** on MCC, the conclusion is "repeated sampling helped, the
  architecture is unproven", regardless of how either compares to Bastet.

## 7. What would falsify the project's thesis

Written down now so it cannot be renegotiated:

- If A2 matches or beats B1 on MCC, then execution-gating buys nothing a tuned prompt
  ensemble does not already buy, and "proof-carrying" is a presentational difference.
- If B1 − B2 is larger than B1 − A2, the result is about sampling, not architecture.
- If ARBITER's false positives on TEST come predominantly through one predicate again,
  that predicate is a heuristic and the "harness owns the success condition" claim is
  weaker than stated.
- If admission under `require_honest=True` rejects most pairs, the round 1 benchmark was
  too easy and its numbers do not transfer.

## 8. Scope this cannot establish

Even a clean win here is a win on ~1,600-character single-file contracts with no
inheritance, authored for this project, against real audit targets of thousands of lines
across many files. Nothing in this design licenses a claim about Code4rena-scale code.
The honest ceiling on any conclusion from round 2 is: *on small, self-contained, paired
contracts, under one model, one gateway and one scorer.*
