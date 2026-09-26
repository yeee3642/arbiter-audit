# ARBITER

**Proof-carrying smart-contract auditing.** A finding is a transcript of an execution,
not an assertion by a language model. The agent cannot report a vulnerability — it has
to write an attack that the harness compiles and runs, against a success condition the
agent never sees.

AIS3 2026 專題, track *安全工具開發與研究自動化*. Built against
[OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) on the same model, the
same gateway, the same evaluation set and the same scorer.

Full documentation is under [`arbiter/`](arbiter/) — start with
[`arbiter/README.md`](arbiter/README.md), and read
[`arbiter/RESULTS.md`](arbiter/RESULTS.md) before quoting any number from anywhere.

---

## The result, stated against my own interest first

**ARBITER does not beat Bastet on F1** — 0.5455 against a fairly tuned 0.6909 — and the
headline MCC advantage **does not exclude zero** once a defect in my own bootstrap was
fixed. Both facts are here before anything favourable, because they were the outcome of
the pre-registered analysis and not of a choice about how to present it.

What it does win is the metric that was pre-registered on 2026-07-25, before any
experiment ran, and that round 1 never bothered to compute — the cost of an analyst's
attention:

| | ARBITER | Bastet (tuned) |
|---|---:|---:|
| analyst-minutes per real bug found | **8.7** | 28.5 |
| real bugs surfaced in a 1-hour review budget | **6.9** | 2.1 |
| F1 | 0.5455 | **0.6909** |
| MCC | 0.267 | 0.227 |
| requests | **1 555** | 2 125 |
| cost | $13.82 | **$2.93** |

3.3× more real bugs per hour of review, because every positive arrives with an exploit
the harness compiled, executed and adjudicated, while the baseline's arrive as
assertions a human still has to check. Crossover at 257 analyst-minutes. Paired
40-sample head-to-head, same model (`nemotron-3-ultra-550b`), `scripts/analyst_cost.py`.

---

## What this contributes

**1. A quantitative audit of a published tool's instrument.** Bastet's shipped decision
rule is a 53-way OR over detector prompts, and it is not merely permissive — it is
*saturated*. Thresholds k=1 through k=8 give identical results because every sample has
at least 8 detectors firing. Measured true-negative count is **0** across 20 patched
contracts; its F1 of 0.6667 equals the constant-"vulnerable" floor to four decimals and
its MCC is exactly **0.000**. At even a generous 5% per-detector false-positive rate,
`1 − 0.95⁵³ = 93%` of safe code still gets flagged — arithmetic before prompt quality.
Two measured facts point the same way: patched code triggers *more* detectors than the
vulnerable original in 4 of 5 matched pairs (a patch adds guards, and a guard is more
surface for a pattern-matcher), and 25 of 53 detectors have discriminative power ≤ 0,
the worst being inverted — `ERC4626-Rounding` fires 0.00 on vulnerable code and 0.43 on
safe.

> **Correction, after adversarial review.** The above holds for the *shipped
> configuration* and was overstated as a claim about the architecture. Given one tuning
> decision — score on the single best detector instead of OR-ing 53 — Bastet reaches
> F1 0.6909 / MCC 0.227 and beats ARBITER's F1 outright. The "structurally
> uninformative" framing was resting on an untuned baseline.

**2. An execution-gated architecture, and the three ways it first failed.** The research
content is the failure sequence, not the final design:

1. accepting "a test passed" let the agent prove a **patched** contract's `withdraw()`
   reverts, and submit that as a finding — test true, finding false;
2. taking the success condition away from the agent still accepted a patched contract,
   because that contract pays a 1-ether airdrop *by design*, so "attacker profits" holds
   on the fixed code too;
3. only a **differential** predicate holds — the agent must supply an `honest_body`
   (the normal usage path), the harness runs it first as a baseline, and the attack must
   strictly beat it.

Naive proof-carrying does not work. `state_change` remains the weakest adjudicator and
still contributes half the false positives, because it is the one place the agent is
left choosing its own question.

**3. A machine-verified paired benchmark.** 20 vulnerability classes, 40 samples, each
negative the patched original differing by 1–4 lines. No pair is admitted unless a
reference exploit passes on the vulnerable half and the *same* exploit fails on the
patched half, checked by `forge` with no model involved. Reusable independently of this
project.

**4. An adversarial self-audit, with 11 of 12 charges upheld.** A reviewer attacked this
work and most of it landed. The bootstrap PRNG was stratifying its own resamples —
10 000 of 10 000 draws had exactly 20 of each class — which narrowed every confidence
interval in my favour; after the fix the MCC delta CI is `[−0.037, +0.553]` and includes
zero. Confidence intervals had been computed for the one metric I lose and not for the
two carrying the claim. The fairness suite shipped a `constant_yes_baseline` but no
`constant_no`, which is why specificity looked like a headline — a predictor that always
answers "safe" scores 1.000 and beats my 0.800. All fixed, all recorded in
[`arbiter/RESULTS.md`](arbiter/RESULTS.md), none quietly dropped.

**5. A pre-registered round 2.** [`arbiter/PREREGISTRATION_V2.md`](arbiter/PREREGISTRATION_V2.md)
fixes splits, power, arms and the decision rule *before* running, because round 1's
headline configuration was chosen by comparing settings on the only evaluation set there
was — test-set selection, and it is named as such.

---

## The evidence ladder

A finding is not one claim. It is a claim that survived a particular amount of
scepticism, and `arbiter prove` reports how much:

| rung | what it means | what was given up |
|---|---|---|
| 1 synthetic | the harness accepted it: own predicate, negation test, six gates | nothing yet — the harness is still the EVM's administrator |
| 2 standalone | the dumped project compiles and passes under `forge test` elsewhere | nobody has to trust my summary |
| 3 live | reproduced as signed transactions on a chain | the administrator: no cheatcodes, real keys, real gas |

The rungs are not redundant. Rung 1 is the only one that *searches*; rung 3 cannot find
anything at all, it can only refuse. On the twelve exploits dumped from the last run it
refused both false positives that rungs 1 and 2 had accepted — and refused them on their
merits, not by failing to run.

---

## Where the remaining gap actually is

All 11 false negatives are exploits that **compiled and ran** and simply failed to
extract value: zero compile failures, zero un-attempted samples. Each of those samples
was independently proved attackable by a reference exploit at admission time, so this is
a **search** limitation, not an expressiveness one. Arithmetically, at precision 0.8,
passing F1 0.667 needs recall ≥ 0.571 — 12 of 20 proved instead of the current 9.
Three samples.

---

## Quick look

```bash
cd arbiter
python3 scripts/victim_probe.py            # the gates, proved in both directions, no network
python3 scripts/live_attack.py             # a reentrancy drained on a local chain
python3 scripts/live_attack.py --patched   # one line moved; the attack reverts
```

`arbiter/` has no third-party Python dependencies, but needs `forge`
([Foundry](https://getfoundry.sh/)) on `PATH`.

## What was here before

This repository also held `bastet-cc`, a separate project. It was removed in the commit
tagged `pre-arbiter-prune`, which is where to get it back:

```bash
git checkout pre-arbiter-prune -- bastet-cc
```
