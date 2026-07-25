# Bastet-CC

Routed smart-contract vulnerability detection, built on
[OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) — and an audit of the
benchmark Bastet is scored on.

AIS3 2026 project, track *安全工具開發與研究自動化*.

---

## What this is

Upstream Bastet keeps 56 hand-written chain-of-thought detectors inside n8n workflow
JSON and scores them with an evaluator that samples *findings* but predicts
*repositories*. Bastet-CC lifts the detectors into portable markdown, routes them at
function granularity, and — before claiming any improvement — measures what the
published scale can actually register.

The order matters. Two of the three things below are about the instrument, not the
detector, and they hold regardless of how good any detector is.

## What we measured

Every number in this section is reproducible. Most need no API key and no corpus
— `scripts/e6_scorer_forensics.py`, `instrument_audit.py`,
`routing_recall_ceiling.py` and `leakage_audit.py` read committed artefacts under
`runs/`. Two do not: the cost ladder needs the corpus on disk (`bastet-cc route`),
and the null test needs the gateway. Both are marked where they appear.

Where a figure is an estimate rather than a measurement it says so. That
distinction was not previously enforced, and one planning estimate reached this
README described as "measured" — see the note under *Routing is free*.

### The evaluator caps out below a perfect score

Hand a predictor the ground truth. For repository *R* and tag *T* it answers "yes"
exactly when *R* genuinely carries a finding tagged *T*, never otherwise. A sound
protocol returns F1 = 1.0.

| | macro-F1 |
|---|---|
| perfect predictor, upstream's protocol | **0.901** |
| perfect predictor, repository-level protocol | 1.000 |

Nine points of macro-F1 are lost to the measurement, not the detection. The worst tag
is `Logic Error` at 0.771 — with **recall 1.000 and precision 0.628**. The perfect
predictor never misses; it is charged with false positives that are correct detections.

The cause is a granularity mismatch. A repository carries 9.2 findings on average, so
one holding both a `DoS` bug and a `Reentrancy` bug enters the `DoS` positive pool via
one row and the negative pool via another. The scanner answers once. One of the two
rows records an error whatever it answers.

`scripts/e6_scorer_forensics.py`

### The published system is indistinguishable from a constant answer

Upstream's own `cli/main.py eval`, its own demo detector, against
`ais3/nemotron-3-ultra-550b`, four independent draws:

| | precision | recall | F1 | accuracy |
|---|---|---|---|---|
| upstream, re-run here (mean of 5) | 0.551 | 0.844 | **0.6597** | 0.578 |
| answer "vulnerable" every time | 0.500 | 1.000 | **0.6667** | 0.500 |

| | gain over floor | per-draw gap, all 5 |
|---|---|---|
| F1 | −0.0069 | −0.111, +0.053, 0.000, +0.053, −0.030 — straddles the floor |
| accuracy | +0.0778 | +0.056, +0.111, +0.056, +0.111, +0.056 — never below it |

Same runs, same data, opposite conclusions. Upstream reports F1.

> Earlier drafts quoted a mean of 4 draws (F1 0.6656) and 95% bootstrap CIs. Two
> corrections. The summary had gone stale against its own `runs.jsonl`: a fifth
> draw was appended without re-running the analysis, and the README cited the
> stale figure. Re-running moves F1 from −0.0011 to −0.0070 — *further* below the
> floor, so the conclusion strengthens. Second, those CIs were a bootstrap over
> four observations. A bootstrap resamples the values it was given; with n=4 the
> interval cannot be narrower than their range, so "95%" overstated what had been
> measured. `stats.paired_bootstrap` now refuses below n=10 and reports the raw
> differences instead, which at this sample size is all the data supports.

This is not purely an indictment: F1 at 50/50 balance flatters constant answers by
construction. But upstream's sampler uses `min(sample_size, |tagged|, |untagged|)`,
which forces exactly that balance — the point where the null model scores highest.

| positives / negatives | constant-"yes" F1 |
|---|---|
| 29 / 29 ← upstream's sampler lands here | **0.667** |
| 17 / 29 | 0.540 |
| 10 / 40 | 0.333 |
| 5 / 45 | 0.182 |

`scripts/upstream_null_test.py`, `scripts/instrument_audit.py`

### Upstream's two published results are not distinguishable by its own instrument

`.sample()` runs without `random_state`. The same predictor moves **0.164** in F1
between draws. The gap between the README's 0.6809 and the CyberSec/ETH-Taipei slides'
0.7742 is **0.093** — inside the noise.

### Routing is free

| stage | LLM calls | input tokens |
|---|---|---|
| upstream, as shipped | 344,008 | 534,857,176 |
| + dependency/test/scope filtering | 100,520 | 225,678,316 |
| + deterministic routing | **42,866** | **60,731,740** (−88.6%) |

Reproduce with `bastet-cc route <repo>` over the corpus; unlike the measurements
above, this one needs the corpus on disk, so no artefact for it is committed.

Wall-clock is governed by the gateway, not by concurrency. `phase7_sustained_w32`
recorded the cap directly — `Limit type: requests. Current limit: 120` — which is
**120 requests per minute regardless of how many workers are running**:

| plan | calls | wall clock at 120 rpm |
|---|---|---|
| upstream, as shipped | 344,008 | **47.8 h** |
| routed | 42,866 | **6.0 h** |
| broadcast control, TEST-12 only | ~22,000 | 3.1 h |

Upstream cannot finish its own competition's test set inside the competition.
Routed can, overnight.

> An earlier draft of this table said "1.7 s per call → 165 h serially, 1.3 h at
> 16-way concurrency". Both figures were wrong. The 1.7 s came from a planning
> estimate in DESIGN §3.2, not from a measurement — the probes measured 1.07 s
> for a single call and 3.54 s mean under 16-way load. And dividing by
> concurrency assumes throughput scales with workers, which the 120 rpm cap
> forbids: `phase7_sustained_w16` showed no errors only because it ran for
> 21.95 s and never crossed a minute boundary. `LLMClient` now carries a token
> bucket so runs are shaped by the cap instead of colliding with it.

With upstream's 56 detectors the saving costs no recall at all. Of 195 (repository,
tag) positives in TRAIN-SYN, routing dropped **0.0%** of everything a detector existed
for. What was unreachable was unreachable in any architecture:

| | upstream's 56 | + 23 synthesised |
|---|---|---|
| unreachable — no detector for the tag | 67 (34.4%) | **4 (2.1%)** |
| unreachable — detector exists, routing missed it | 0 (0.0%) | 3 (1.5%) |
| reachable | 128 (65.6%) | **188 (96.4%)** |

Synthesis buys 31 points of reachable positives and costs 1.6% to routing, because
induced hints are narrower than hand-written ones. The losses are named rather than
averaged away: `EIP712` and `ERC777` route 2 of 3 positives, `Accounting Error` 15 of
16.

`scripts/routing_recall_ceiling.py`

### Coverage was the real ceiling

Upstream's 56 detectors span 15 of the 42 tags the corpus contains. `Accounting Error`
(47 findings), `Governance` (36), `Liquidation` (25), `Cross-Chain`, `MEV`, `ERC1155`,
`DAO`, `Upgradeable`, `ERC777`, `Pause` had no detector at all — no model closes that,
because the rules do not exist.

Synthesis induces detectors for the missing tags from the labelled corpus: S1 localises
each finding back to the function it describes, S2 induces one detector per tag from
those code-level fault patterns, S3 filters routing hints with no model involved
(hallucinated identifiers and ubiquitous ones both go), S4 runs leave-one-repo-out.

**79 detectors now span 38 tags — 35 of them evidence-backed.** 14 of the 23
synthesised are marked `gated`: induced from too little material, or failed the
LORO check. They are kept rather than dropped so the coverage figure stays honest
about which detectors earned their place, and their findings require
corroboration before counting.

Three go further and should not be counted as evidence at all.
`synth__compound`, `synth__eip4494` and `synth__solidity_version` carry
`mode: s2b, train_findings: []` — they were induced from the tag definition
alone, because those three tags have **zero TRAIN-SYN positives**. Their only
positive repository in the whole corpus is in TEST, so they cannot be validated
before the one TEST read, and no LORO fold exists for them. The honest coverage
statement is 35/42 backed by labelled findings, 38/42 counting taxonomy-only
detectors. `scripts/leakage_audit.py` reports them as their own category — not a
leak, since no label was read, but not a clean bill of health either.

### The model recognises the projects but not their findings

Given only filenames and READMEs — no code — the model named 8 of 10 held-out projects
correctly (Moonwell, Perennial Finance, zkSync Era System Contracts, Coinbase Smart
Wallet…). Its tag agreement with ground truth nonetheless does **not** beat a
frequency prior: gap −0.019, 95% CI [−0.117, +0.075].

Recognising a codebase is not remembering its audit. Absolute scores are not inflated
by memorised findings, and the paired architecture comparison is insensitive to
memorisation regardless, since both arms share the model.

`scripts/e7_memorization_probe.py`

### Head to head, same model, one repository

The claim this project exists to make is comparative, so the comparison has its own
command. `bastet-cc compare` is the one that answers "which arm is more often right";
it needs labels. `bastet-cc structural` answers the questions that do not, and it runs
off committed artefacts alone — no API key, no `train.csv`, no 6.8 GB corpus:

```bash
bastet-cc structural --a d1_routed_dev1 --b d1_broadcast_dev1
```

Both runs scanned repository `e5f8a519b24f` with `ais3/nemotron-3-ultra-550b`, the same
detectors and the same parser. Only `plan()` differed.

| | routed | broadcast |
|---|---|---|
| findings reported | 55 | 90 |
| distinct sites | 28 | 37 |
| findings per site | 1.96 | 2.43 |
| in vendor / non-production code | **0.0%** | **13.3%** |
| localisable to a function *(arch)* | 100.0% | 0.0% |
| detectors that fired | 12 | 17 |

Site agreement: 24 shared, 4 routed-only, 13 broadcast-only (Jaccard 0.585).

Two rows carry the argument. **13.3% of broadcast's report is in `contracts/mocks/`** —
not false positives in the labelling sense, the mocks may well contain the pattern, but
nobody is paid to audit them and they cost a reviewer the same attention. Upstream globs
`**/*.sol` with no vendor or test exclusion, so this is its behaviour, not an artefact
of ours.

The localisation row is marked *(arch)* because it is **not** a quality result and must
not be read as one. The broadcast arm sends a whole file as one slice named `<file>`, so
no model-reported function name can ever bind back to it — the arm is unlocalisable by
construction. That is still a real consequence: an unlocalisable finding cannot be
verified by the refutation pass, cannot be deduplicated by site, and cannot be handed to
a developer as a line range.

Nothing in this table ranks detection quality, and `structural` says so in its own
output. One repository is also one repository; it is a worked example of the harness,
not the result. The DEV and TEST runs are what will carry the claim, under `compare`,
with McNemar on repo × tag decisions and a sign test over repositories.

## Three defects found in upstream while standing up the baseline

1. **`erc4626.json` and `flashloan.json` ship identical `webhookId`s** — on both the
   webhook node and the chat trigger. `flashloan.json` is a copy of `erc4626.json` with
   the ids never regenerated. n8n refuses to activate two workflows on one webhook path,
   so **out of the box only 8 of 9 workflows run** and the flashloan detector is dead.
2. **`OPENAI_MODEL_NAME` silently overrides the model declared in every workflow JSON**
   (`import_workflow.py:124`), defaulting to `gpt-4o-mini`. It appears in no
   documentation and not in `.env.example`. Editing the JSON has no effect.
3. **`flashloan.json` points at `os-azure-gpt5-chat`**, a private Azure deployment
   nobody outside OneSavie can reach.

## Architecture

| upstream (n8n) | Bastet-CC | removed |
|---|---|---|
| webhook trigger | `bastet-cc scan` | n8n server |
| 56 `chainLlm` nodes | 56 markdown detectors + routing | LangChain |
| structured output parser | `findings.py`, upstream schema preserved | — |
| merge / if nodes | `aggregate.py` | n8n |
| PostgreSQL | append-only `runs/<id>/results.jsonl` | Postgres, Docker |

```
bastet_cc/
  solidity.py    tree-sitter function index — no compiler, since audit repos rarely build
  routing.py     IDF-weighted detector-to-code matching
  callgraph.py   one-hop call closure: the callees a routed slice would otherwise hide
  plan.py        the ONLY fork between routed and broadcast arms
  executor.py    concurrent execution, resumable
  llm.py         OpenAI-compatible client, lenient JSON recovery, 120 rpm token bucket
  automation/    pinned dual-surface gateway, fair budgets, workflow shim, audit ledger
  hermes.py      deterministic target/modifier/caller/callee/state evidence packets
  twincourt.py   same-model Skeptic verdicts with citation and causality gates
  verify.py      legacy refutation + durable HERMES/TwinCourt adjudication overlay
  quality_benchmark.py  shared-calibration fairness audit and paired claim guardrails
  aggregate.py   repo-level decision layer; upstream == prior=1, tau->0
  evaluate.py    corrected scorer + faithful replica of upstream's
  stats.py       paired inference: exact McNemar, sign test, power, n-guarded bootstrap
  redact.py      credential stripping at the point of capture
  synth/         localize -> induce -> hints -> gate
tests/           offline-first tests; no network, corpus, or API key by default
```

`plan.py` being the single fork point is what makes the comparison fair. The broadcast
arm replicates upstream exactly — `glob('**/*.sol')`, no vendor filtering, whole files,
upstream's prompts — and then shares every downstream stage with the routed arm.

## Install

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e .
export AIS3_API_KEY=...          # AIS3 gateway token; never committed
```

Corpus and labels are not in this repository — 6.8 GB of it is other people's source,
and the competition's terms for redistributing the labelled findings are not stated
anywhere we could find. `data/splits.json` is tracked because it is ours and holds only
repository hashes.

```bash
cd ../data
curl -L -O https://osbastetkagglesa.blob.core.windows.net/kaggle/train.zip
curl -L -O https://osbastetkagglesa.blob.core.windows.net/kaggle/test.zip
unzip -q -o train.zip -x "__MACOSX/*" -d ex
unzip -q -o test.zip  -x "__MACOSX/*" -d ex

# train.csv and test.csv: Kaggle competition `onesavie-bastet`, Data tab.
# Everything except `bastet-cc index` and `route` needs train.csv for ground truth.
```

Enable the credential guard. Git does not install hooks on clone, so this is a
manual step and it is the first one:

```bash
git config core.hooksPath .githooks
```

The hook scans staged *content*, not filenames. It blocks a credential keyword
next to a high-entropy value and merely warns on bare 64-hex, because on a
Solidity corpus most high-entropy hex is an init-code hash or a TYPEHASH — a
shape-only rule flags the UniswapV2 pair hash inside our own detectors. This
repository leaked a gateway key identifier once, 107 times in one probe artefact,
past a `.gitignore` that only guarded `.env`; `bastet_cc/redact.py` now runs at
the point of capture and `scripts/scrub_artifacts.py` cleans what is already on
disk.

## Use

```bash
bastet-cc index  <repo-hash>                 # parse one repository
bastet-cc route  <repo-hash>                 # routed vs broadcast cost
bastet-cc power                              # what the TEST design can resolve — run this first
bastet-cc scan   dev --run dev-routed --arm routed
bastet-cc scan   dev --run dev-bcast  --arm broadcast     # the control condition
bastet-cc scan   dev --run dev-closure --arm routed --closure   # ablation R3
bastet-cc scan   dev --run dev-hermes --arm routed \
  --quality-treatment hermes_twincourt
bastet-cc calibrate --run dev-routed         # fit the decision layer on DEV only
bastet-cc quality-calibrate --run dev-routed # one shared, provenance-carrying DEV fit
bastet-cc quality-compare --a dev-routed --b dev-hermes \
  --calibration runs/quality-calibration.json
bastet-cc evaluate  --run dev-routed --scorer both
bastet-cc structural --a dev-routed --b dev-bcast         # label-free head to head
bastet-cc compare   --a dev-routed --b dev-bcast          # paired McNemar + power
bastet-cc figures
bastet-cc audit                              # leakage + instrument audits
```

`scan` throttles to 115 rpm by default (`--rpm 0` disables) and prints the
resulting wall-clock estimate before it starts, so a six-hour run is not begun
under the impression that it is a one-hour run. `--concurrency` bounds memory;
it does not bound rate.

### HERMES/TwinCourt quality treatment

`--quality-treatment hermes_twincourt` is an opt-in routed verification
treatment. HERMES resolves the reported function from the existing tree-sitter
index, then spends a hard character budget on parser-backed modifier, caller,
callee, and same-contract state relations. It never substitutes physically
nearby functions when a relation is missing. TwinCourt sends that packet to an
isolated Skeptic request on the same configured model; confirmed and rejected
answers are downgraded to uncertain unless their causal or counter-evidence
requirements cite real packet fragment IDs.

Detector output remains append-only in `results.jsonl`. Adjudications are
fsynced to `verify.jsonl` and overlaid when findings are reloaded, so evaluation,
JSON, Markdown, SARIF, and restart/export all see the same verdict without
rewriting the raw detector record.

The treatment is rejected on the frozen broadcast control, when verification is
disabled, or when call closure is also enabled. `quality-compare` refuses
mismatched models, endpoints/gateway profiles, budgets, subjects, repositories,
splits, or calibration provenance. DEV is always exploratory. A TEST
`surpasses` status is possible only after every pre-registered McNemar,
macro-F1, precision, and false-positive guard passes; otherwise the result is
explicitly underpowered, inconclusive, inferior, or unfair. Implementation and
offline tests therefore do not by themselves establish superiority. Mock
gateway runs can exercise DEV exploration, but a claim-bearing automation TEST
comparison requires complete nested automation evidence for both arms,
`provider_mode=live`, and the gateway's fingerprinted
`live-provider-evidence` claim level. Endpoint-only TEST manifests are refused.

Resume and comparison are fail-closed. A run ID cannot be rebound to a changed
provider profile, treatment, task plan, or scan configuration. Detection task
IDs retain their frozen model-and-prompt identity; provider provenance is bound
by the immutable run manifest. The manifest records a hashed plan and an
execution summary. `quality-compare` recomputes that summary from
`tasks.jsonl` and `results.jsonl`, then refuses missing, failed, incomplete, or
unexpected tasks and any result row without a valid planned task ID. Automation
fingerprints are recomputed from the full
immutable gateway payload during both scan and comparison rather than trusted
as opaque strings.

### Same-model automation gateway

Phase 1 adds one loopback-only execution plane below both systems. It exposes an
OpenAI-compatible `/v1/chat/completions` endpoint to Bastet-CC and the three n8n
scan endpoints expected by the unmodified upstream CLI. Both arms are pinned to
`ais3/llama-3.1-8b`; workflow files that name `gpt-4o-mini` or private Azure
deployments cannot select a different provider model.

The earlier result tables retain the model actually used for those historical
runs (`ais3/nemotron-3-ultra-550b`). The current `scan` default intentionally
uses `ais3/llama-3.1-8b` so this experiment compares both tools on the exact
same model.

The n8n service at `http://localhost:5678` remains useful for inspecting the
original workflows. The automation service below is a deliberately smaller
scan-compatible shim, not a replacement n8n workflow engine. Phase 1 supports
the single-`chainLlm` `flashloan` workflow and rejects multi-model workflows
instead of pretending to reproduce their merge semantics.

On Windows, start the offline deterministic gateway from the `bastet-cc`
directory:

```powershell
$upstream = "C:\path\to\frozen\Bastet"
bastet-cc automation serve `
  --workflow-root "$upstream\n8n_workflow" `
  --workflow flashloan `
  --experiment phase1-smoke `
  --subject upstream-example
```

In another terminal, exercise both surfaces with the same subject, then run the
actual upstream CLI unchanged:

```powershell
bastet-cc automation smoke `
  --experiment phase1-smoke `
  --subject upstream-example

.\scripts\run_upstream_shim.ps1 `
  -UpstreamRoot $upstream `
  -GatewayUrl http://127.0.0.1:8765
```

To route a Bastet-CC scan through the same ledger:

```powershell
bastet-cc scan C:\path\to\contracts `
  --run phase1-bastet-cc `
  --automation-url http://127.0.0.1:8765 `
  --automation-experiment phase1-smoke `
  --automation-subject upstream-example
```

Mock mode is the default and needs no credential. Live mode must be explicit,
and the process reads a rotated key only from the environment:

```powershell
$env:AIS3_API_KEY = "<rotated key>"
bastet-cc automation serve `
  --workflow-root "$upstream\n8n_workflow" `
  --workflow flashloan `
  --experiment phase1-live `
  --subject upstream-example `
  --live
```

The manifest stores endpoint, model, subject, workflow/prompt hashes, adapter
versions, and budgets. Before every provider call, the JSONL ledger fsyncs a
worst-case reservation; a second append-only event reconciles actual usage.
This makes crash/restart conservative instead of resetting spent budget. The
ledger stores request metadata, hashes, and usage—never prompts, authorization
headers, or credentials. Completed upstream-compatible results are separately
fsynced to `executions.jsonl` before an execution id is returned, so polling
survives a gateway restart. That result file contains redacted finding output
and should be protected like any other scan artifact.

A mock run proves pipeline and contract readiness. A live smoke proves the
pinned endpoint is callable. Neither is evidence that one arm wins; that
requires the preregistered paired benchmark.

### What a fresh clone can check

Tests, the credential scan and the leakage rules need neither the corpus nor a key:

```bash
make install && make check
```

`make reproduce` regenerates every artefact whose inputs are already in the
repository — the test suite, the structural head-to-head, `upstream_null/summary.json`
re-derived from `runs.jsonl`, the leakage audit's split rules, and every figure except
`fig5_coverage_gap` — and then **prints the list it could not regenerate**. That skip
list is the honest boundary of "nothing is estimated":

| needs | artefacts |
|---|---|
| `data/train.csv` | `runs/e6/`, `runs/instrument/`, `fig5_coverage_gap`, leakage rule 1 |
| extracted corpus | `runs/routing_recall/`, the cost ladder's stage counts |
| an API key | `runs/e7/`, `runs/probe/`, any `scan` |

Commands that need labels fail with a message naming the missing file rather than a
pandas traceback; commands that do not are listed in that message.

Measurement scripts that need no API key (but do need `train.csv`):

```bash
python scripts/e6_scorer_forensics.py        # perfect-predictor ceiling
python scripts/instrument_audit.py           # floor, metric flip, balance sensitivity
python scripts/routing_recall_ceiling.py     # what routing costs in recall
python scripts/leakage_audit.py              # split enforcement (rules 2/3 need nothing)
python scripts/upstream_null_test.py --analyse   # re-derives the null summary
```

Start the safe upstream compatibility baseline without mutating the frozen
checkout or writing a key to `.env`:

```bash
export BASTET_UPSTREAM_ROOT=/path/to/frozen/Bastet
./scripts/setup_upstream_baseline.sh ais3/llama-3.1-8b
```

## Experimental protocol

Splits are **repository-level and frozen** — 32 TRAIN-SYN / 10 DEV / 12 TEST, sha256 in
`data/splits.json`. A repository carries 9.2 findings on average, so splitting rows
would put the same codebase on both sides of the boundary. Upstream's evaluator splits
rows.

| split | role |
|---|---|
| TRAIN-SYN | detector synthesis, routing IDF corpus |
| DEV | threshold and prior calibration, all prompt iteration |
| TEST | read once, after everything is frozen |

`scripts/leakage_audit.py` checks the artefacts on disk rather than trusting the code:
which repositories each synthesised detector cites, which split each run touched, and
whether TEST appears more than once. It also flags the **10 tags with fewer than 2
positive repositories** in TRAIN-SYN — a detector induced from one repository encodes
that repository's naming, not the vulnerability class, and those are reported as such
rather than counted toward coverage.

Known limits, stated rather than hidden:

- 54 repositories is the corpus ceiling. Of the top-15 tags, 11 appear in all three
  splits; `Reentrancy` and `MEV` are absent from DEV, `ERC721` and `Flashloan` from
  TEST. Recorded in `splits.json` under `uncovered`.
- The null-model comparison covers one tag with one detector on the Kaggle corpus, not
  the `dataset_0831` corpus upstream published against. The floor argument generalises;
  that measurement does not, on its own.
- Ground truth has no file or line column, so a true positive means "this repository
  emitted a finding for this tag", not "the model found *that* bug". Localisation is
  unmeasured.
- TEST labels are read once. TEST *code* is not: S3 hint validation computes
  document frequencies over all 54 repositories, DEV and TEST included
  (`synth/__init__.py` states this, and `synth.train_syn_frames` is the only
  reader of labels). This is transductive use of unlabelled code — defensible,
  and standard in retrieval — but it is not "TEST was never touched", and the
  distinction belongs here rather than in a docstring.
- 12 TEST repositories is a hard ceiling on statistical power. The pre-registered
  threshold is 25 discordant decisions; below it the comparison is reported as
  under-powered rather than as evidence of equivalence.

## Status

Complete and measured: instrument audit, routing, cost, coverage analysis, leakage
audit, memorisation probe, upstream control group, figures, detector synthesis
(S1–S4, 23 detectors assembled into `detectors_synth/`). The offline
dual-surface automation path is also implemented: it can run the frozen upstream
scan protocol and Bastet-CC through one pinned-model budget and ledger.

Not yet run: **the DEV and TEST scans**. `runs/` holds smoke tests and two
single-repository DEV runs; no arm has been scored end to end, so no
routed-vs-broadcast accuracy claim exists yet. The claims that are measured are
the instrument audit, cost, and coverage — all of which are independent of that
scan. `PREREGISTRATION.md` fixes the metrics and decision rules for the
comparison before it is run, including what counts as a negative result.

Also not yet claimed: live superiority over upstream with
`ais3/llama-3.1-8b`. That claim remains blocked until a rotated key is supplied
and the preregistered, same-subject, same-budget paired benchmark completes.

Power, before spending the wall-clock: TEST is 12 repositories × ~20 tags ≈ 240
paired decisions, but only *discordant* pairs carry evidence. Below ~25
disagreements the design cannot resolve a difference at all — see
`bastet-cc power`, and §3 of the pre-registration.

## Credits and licence

Built on [OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) (Apache-2.0);
the 56 detector prompts in `detectors/` are theirs, extracted verbatim from their n8n
workflows. Corpus from the Bastet Kaggle competition (1 April – 1 July 2026), labelled
by DeFiHackLabs. Inference on the AIS3 2026 LLM infrastructure.

Apache-2.0. For research and education. Findings should follow responsible disclosure.
