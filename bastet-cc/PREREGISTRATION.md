# Pre-registration

Frozen 2026-07-25, before any DEV or TEST scan has been run. `runs/` at the time
of writing contains smoke tests and two single-repository DEV runs; no arm has
been scored.

The point of writing this now is narrow and specific: **the instrument audit
makes it easy to win by accident.** We have shown that upstream's metric is
indistinguishable from a constant classifier on a balanced sample, and that on
such a sample F1 rewards answering "vulnerable" more often. A tool that is
strictly worse but more trigger-happy scores higher on it. If we choose our
headline metric after seeing the results, we cannot rule out having chosen the
one that flattered us. So the metrics, the decision rules, and the failure
conditions are fixed here, in advance.

---

## 1. Hypotheses

| id | claim | metric | decides |
|---|---|---|---|
| **H1** | Upstream's published protocol cannot distinguish its own detector from a constant answer | F1 gain over the analytic constant-"yes" floor | already measured (`runs/upstream_null/`) |
| **H2** | Under a sound protocol, routed is not *worse* than broadcast | McNemar exact, paired (repo, tag) decisions | TEST |
| **H3** | Routed costs at least an order of magnitude less | LLM calls and input tokens, both plans | TRAIN-SYN + TEST |
| **H4** | Synthesis raises tag coverage | tags with ≥1 detector, out of 42 | already measured |
| **H5** | One-hop call closure recovers cross-function recall | McNemar, routed+closure vs routed | DEV, then TEST if DEV is positive |

**H2 is deliberately non-inferiority, not superiority.** Our defensible claim is
"same detection, 27× cheaper, 2.5× the coverage". Superiority would be better and
we test for it, but the project does not depend on it, and pretending otherwise
after the fact is the failure mode this document exists to prevent.

## 2. Primary and secondary metrics

**Primary (H2):** exact McNemar over (repository, tag) decisions on TEST, scored
by the corrected scorer (`aggregate.confusion_by_tag`, no sampling, every cell
scored). Both arms use the same model, the same prompts, the same parser, the
same calibration frozen on DEV. `plan()` is the only difference.

**Secondary:** per-repository macro-F1, paired, reported with a sign test and —
only if n ≥ 10 — a bootstrap CI over repositories. TEST has 12 repositories, so
the bootstrap is admissible by exactly two units; if any repository fails to
scan, it is dropped and the raw twelve differences are reported instead.
`stats.describe_paired` enforces this automatically.

**Also reported, unconditionally:** both arms under upstream's own scorer
(`evaluate.upstream_score`). We must not be seen to win only under a ruler we
built. If we lose there and win under ours, both numbers are reported with the
instrument audit as the explanation — not one of them quietly omitted.

## 3. Power, computed before spending the scan

TEST is 12 repositories. With ~20 scoreable tags that is ~240 paired decisions,
but only *discordant* pairs carry evidence.

```
bastet-cc power --decisions 240 --discordance 0.25
```

| discordant pairs | MDE (share of disagreements the better arm must win) |
|---|---|
| 10 | 0.943 — landslide only |
| 25 | 0.780 — large effects only |
| 60 | 0.681 — workable |
| 240 | 0.590 — workable |

**Registered in advance:** if the observed discordant count on TEST is below 25,
the design cannot resolve H2 and we will say so plainly rather than reporting a
non-significant p-value as though it were evidence of equivalence. Absence of
evidence at n=10 is not evidence of absence.

## 4. Decision rules

Fixed now, applied without amendment.

**H2.** Two-sided exact McNemar, α = 0.05.
- p < 0.05 and b > c → routed superior. Claim it.
- p ≥ 0.05 and discordant ≥ 25 → no detectable difference. **This is the
  expected outcome and it supports the headline claim** (parity at 1/27 the cost).
- p ≥ 0.05 and discordant < 25 → under-powered. Report the counts, claim nothing.
- p < 0.05 and c > b → routed inferior. Report it as the headline, and the cost
  and coverage results become "what we bought and what it cost".

**H3.** No inference needed. Call counts and token counts are census data over
the whole corpus, not samples. Reported from `bastet-cc route`, with wall-clock
derived from the **measured sustained throughput and the 120 rpm gateway cap**,
never from single-call latency divided by concurrency.

**H5.** Closure is evaluated on DEV first. It only goes to TEST if DEV shows
b > c. If it does go, it is reported as a third arm, not folded into the routed
arm — folding it in after seeing that it helps would make the H2 comparison a
different experiment from the one registered here.

## 5. What would falsify the project

- Routed loses H2 significantly on TEST → the cost saving is a recall trade, and
  we report it as one.
- Synthesised detectors show DEV precision below the hand-written ones by a wide
  margin → the fallback is marking them all `gated` (already supported by
  `verify_enablement_table`); the coverage claim survives, the accuracy claim does not.
- The 429 ceiling makes the broadcast control infeasible on TEST → the control is
  scoped to fewer repositories and **the reduction is stated**, not silently absorbed.

## 6. Split protocol

Frozen in `data/splits.json`, sha256 `4b3d5279…`, verified by
`scripts/leakage_audit.py` on every run and by `tests/test_leakage_guard.py` in CI.
32 TRAIN-SYN / 10 DEV / 12 TEST, repository-level.

**TEST is read exactly once**, at the end. One qualification, stated because it
is true and was not previously written down: S3 hint validation computes document
frequencies over the *code* of all 54 repositories, including DEV and TEST.
Labels never leave TRAIN-SYN (`synth.train_syn_frames` is the only reader and it
filters first). This is transductive use of unlabelled code — defensible, and
standard in retrieval — but it is not the same as never touching TEST, and the
distinction belongs in the write-up rather than in a footnote nobody reads.

Three synthesised detectors (`synth__compound`, `synth__eip4494`,
`synth__solidity_version`) were induced with **no training material at all**
(mode `s2b`, `train_findings: []`), because those tags have zero TRAIN-SYN
positives. Their only positive repository is in TEST. They cannot be validated
before the TEST read and are **excluded from any coverage figure that implies
evidence**: the honest count is 35/42 evidence-backed, 38/42 including
taxonomy-only detectors.

## 7. Analysis code frozen with this document

`bastet_cc/stats.py`, `bastet_cc/aggregate.py`, `bastet_cc/evaluate.py`. Any
change to these after the TEST read must be recorded in this file with a reason.
The test suite (157 tests) is the guard: `upstream_equivalence_report` in
particular pins the control arm to upstream's literal rule, and if that identity
breaks, every A/B number is comparing against something that is no longer the
baseline.
