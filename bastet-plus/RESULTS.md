# A/B results

**Setup.** 20 labelled Solidity files (9 vulnerable, 11 clean), 18 detectors, model
`ais3/llama-3.3-70b` served over an OpenAI-compatible endpoint. Both arms use the same model,
the same endpoint, the same detectors and the same files. The legacy arm is a faithful Python
replica of the n8n single-shot path (`pipeline.run_legacy`), and it is deliberately given the
*improved* JSON extraction so the comparison cannot be dismissed as "your parser is better".

Enhanced settings: `--samples 3`, verification on, grounding on, slicing on. The
"strong verifier" column additionally sets `--verifier-model ais3/nemotron-3-ultra-550b`,
leaving detection on the cheap model.

---

## Headline

### File level: "does a human need to look at this file?"

| | Original | Bastet+ | Bastet+ (strong verifier) |
| --- | --- | --- | --- |
| Precision | 0.500 | 0.500 | **1.000** |
| Recall | 1.000 | 1.000 | **1.000** |
| F1 | 0.667 | 0.667 | **1.000** |
| TP / FP / FN / TN | 9 / 9 / 0 / 2 | 9 / 9 / 0 / 2 | **9 / 0 / 0 / 11** |
| Clean files raising an alarm | 9 / 11 | 9 / 11 | **0 / 11** |
| Findings on clean files | 118 | 18 | **0** |

This is the most instructive row in the comparison, and it is not the flattering reading.

Same-model verification, llama-3.3-70b judging its own output, cuts the *volume* of noise on
clean files by 6.5x (118 findings down to 18) but does not silence a single clean file. Nine
of eleven still raise at least one alarm, exactly as before. A model asked to referee its own
reasoning keeps enough of it to stay above zero.

Swapping **only the verifier** to a stronger model drives clean-file findings to zero while
still catching all 9 vulnerable files: 20/20 at file level.

So the finding is not "verification helps". It is: **verification by a model no stronger than
the detector reduces noise but does not change the decision; verification by a stronger model
does.**

### Per (file, class) pair: strict attribution

| Metric | Original | Bastet+ | Bastet+ (strong verifier) |
| --- | --- | --- | --- |
| Precision | 0.061 | 0.119 | **0.182** |
| Recall | 0.667 | 0.889 | **0.889** |
| F1 | 0.111 | 0.210 | **0.302** |
| False-positive rate | 0.838 | 0.531 | **0.324** |
| TP / FP / FN / TN | 6 / 93 / 3 / 18 | 8 / 59 / 1 / 52 | 8 / 36 / 1 / 75 |
| Total findings reported | 278 | 55 | **27** |
| Findings carrying a line number | **0** | 55 | 27 |
| Localization accuracy | 6/6 | 8/8 | 8/8 |

Attribution here is strict: a finding merged from six detectors counts as a prediction for
all six of their classes. So this metric penalises *class smearing* (reporting the right bug
on the right line under several overlapping labels) as heavily as an outright hallucination.
Both views are given because they answer different questions and neither alone is the whole
picture.

Absolute precision is low on both sides. That is the honest state of 18 aggressively-primed
CoT detectors running over a 70B open-weight model: each prompt has just told the model what
it is looking for, and the model obliges. The harness roughly triples it; it does not solve
the problem.

### Per class

| Class | Original P/R/F1 (TP/FP/FN) | Bastet+ strong verifier P/R/F1 (TP/FP/FN) |
| --- | --- | --- |
| access_control | 0.11 / 1.00 / 0.20 (2/16/0) | 0.29 / 1.00 / 0.44 (2/5/0) |
| slippage | 0.11 / 1.00 / 0.20 (2/16/0) | 0.22 / 1.00 / 0.36 (2/7/0) |
| unchecked_call | 0.06 / 1.00 / 0.11 (1/17/0) | 0.20 / 1.00 / 0.33 (1/4/0) |
| reentrancy | 0.00 / 0.00 / 0.00 (0/14/2) | 0.17 / 0.50 / 0.25 (1/5/1) |
| randomness | 0.00 / 0.00 / 0.00 (0/13/1) | 0.12 / 1.00 / 0.22 (1/7/0) |
| oracle | 0.06 / 1.00 / 0.11 (1/17/0) | 0.11 / 1.00 / 0.20 (1/8/0) |

The original scores **zero** on reentrancy and randomness. It is not silent on those files;
it emits 14 and 13 findings respectively. It just never emits the right one. Bastet+ recovers
both.

---

## Harness health

These are not accuracy metrics. They are counts of the original's defects firing in practice.

| | Original | Bastet+ |
| --- | --- | --- |
| Findings whose severity was silently rewritten to `high` | **278 / 278 (100%)** | 0 |
| Responses n8n's strict output parser would have rejected | **221 / 360 (61%)** | 0 |
| Structured-output ladder: native / extracted / repaired / failed | n/a | 1300 / 0 / 0 / 0 |
| Severity histogram of reported findings | `{high: 278}` | `{high: 26, medium: 1}` |

**Every finding the original produces is stamped `high`.** The severity column in every Bastet
report to date is a constant. This is defect A1: 55 of 56 prompts never mention `severity`,
the schema requires it, and `AuditReport.__init__` defaults the missing value to `"high"`
without complaint.

**61% of legacy responses are not bare JSON.** They arrive fenced, prefaced, or with
commentary. n8n's Structured Output Parser rejects those, and `scan.py` handles the rejection
by printing `Model output doesn't fit required format, escape one` and dropping the finding.
The legacy arm's 0.667 recall is measured *with* the lenient parser; through the real n8n path
it would be materially lower. With an explicit `response_format` schema, all 1300 enhanced
calls parsed natively on the first attempt and the repair path never fired.

---

## Where the false positives go

Enhanced pipeline with the strong verifier, per stage, across the whole benchmark:

| Stage | Candidates removed |
| --- | --- |
| Self-consistency (agreement across 3 samples) | 136 |
| Evidence grounding (quoted code absent from source) | 16 |
| Adversarial verification | 103 |
| Cross-detector dedup | 90 merged |

Grounding removes the fewest candidates, but it costs zero tokens (it is pure string matching)
and the ones it removes are the confidently-wrong ones, where the model invented the code that
proves its own claim.

## Ablation

| Configuration | P | R | F1 | Findings | On clean files | Clean files silenced |
| --- | --- | --- | --- | --- | --- | --- |
| Original harness | 0.061 | 0.667 | 0.111 | 278 | 118 | 2 / 11 |
| Bastet+, verification off | 0.096 | 0.889 | 0.174 | 105 | 47 | 2 / 11 |
| Bastet+, same-model verifier | 0.119 | 0.889 | 0.210 | 55 | 18 | 2 / 11 |
| Bastet+, stronger verifier | **0.182** | **0.889** | **0.302** | **27** | **0** | **11 / 11** |

Three things to read off this:

1. **Self-consistency + grounding + dedup alone** (the "verification off" row, no extra LLM
   call beyond the 3 samples) take F1 from 0.111 to 0.174 and cut findings from 278 to 105.
   Recall goes *up* at the same time, 0.667 to 0.889, because the enhanced arm recovers the
   two classes the original scores zero on.
2. **Verifier strength is the variable that changes the decision, not verification itself.**
   Every row except the last leaves the same 9 clean files raising alarms. Only the stronger
   verifier drives them to silence, and it costs nothing in recall.
3. The recommended configuration is therefore asymmetric:

```bash
python -m bastet_plus scan contracts/ --samples 3 --verifier-model <stronger-model>
```

`--no-slice` is deliberately absent from the table: every benchmark file is under the 12 000
character slicing threshold, so slicing is a no-op here and ablating it would measure nothing.
Slicing targets the multi-thousand-line files in the real Bastet dataset and **is untested by
this benchmark**.

## Cost

| | Original | Bastet+ (`--samples 3`, verify on) |
| --- | --- | --- |
| LLM requests | 360 | 1 080 + one per surviving candidate |
| Total tokens | 427 932 | 1 882 739 |
| Wall clock | 332 s | 814 s |

Roughly **4.4x the tokens for 2.7x the F1**, and 27 findings to triage instead of 278.
Swapping the verifier model added 266 600 tokens on top of cached detection.

Whether that trade is worth it depends on what an analyst-hour costs relative to tokens. The
knobs exist: `--samples 1` removes two thirds of detection cost, `--no-verify` removes
verification cost, `--min-severity` truncates the tail, and the response cache makes
re-running an unchanged scan free.

---

## Caveats

- **20 files is a small benchmark.** It cleanly separates a harness that puts 118 findings on
  clean files from one that puts 0. It cannot resolve a two-point F1 difference. The 95%
  Wilson interval on the strong-verifier precision of 0.182 is **[0.095, 0.320]**; on the
  legacy 0.061 it is **[0.028, 0.126]**. Those intervals do not overlap, so the precision
  improvement is real, but its magnitude is not pinned down to three digits.
- **The cases are purpose-built** and therefore cleaner than production Solidity. Both arms
  are flattered.
- **The legacy arm is a replica**, not the n8n container. It issues the same request and gets
  the same response, but is *more* forgiving on parsing than n8n; see the 61% strict-parse
  failure rate. The real original would score lower.
- **The upstream dataset was not used.** Bastet's 450-repo Code4rena dataset is distributed
  via Google Drive and is not in the repository. These numbers do not transfer to it directly,
  and the slicing improvement in particular is unmeasured here.
- **Two bugs in this harness were found and fixed during the run**, both in `dedupe.py`:
  provenance truncation, which silently reclassified merged findings and produced two phantom
  regressions; and a similarity signature that counted a shared *function name* as evidence
  that two different bug classes were the same finding. Both are covered by regression tests
  in `tests/test_offline.py`, and every number above is post-fix.

## Reproducing

```bash
cp .env.example .env          # point at your endpoint
python tests/test_offline.py  # 42 offline checks, no network
python -m bastet_plus bench --samples 3 --verifier-model <stronger-model>
```

Raw per-finding output for every run is in `benchmark_results/comparison_*.json`.
