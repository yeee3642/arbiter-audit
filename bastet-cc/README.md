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

Every number here is reproducible from `scripts/`. Nothing is estimated.

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
| upstream, re-run here (mean of 4) | 0.553 | 0.861 | **0.6656** | 0.583 |
| answer "vulnerable" every time | 0.500 | 1.000 | **0.6667** | 0.500 |

| | gain over floor | 95% CI |
|---|---|---|
| F1 | −0.0011 | [−0.070, +0.053] — includes zero |
| accuracy | +0.0833 | [+0.056, +0.111] — excludes zero |

Same runs, same data, opposite conclusions. Upstream reports F1.

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

At the measured 1.7 s per call, upstream needs 165 hours serially — it cannot finish
its own competition's test set. The routed plan finishes in 1.3 hours at 16-way
concurrency.

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

**79 detectors now span 38 tags.** 14 of the 23 synthesised are marked `gated` —
induced from too little material, or failed the LORO check. They are kept rather than
dropped so the coverage figure stays honest about which detectors earned their place,
and their findings require corroboration before counting.

### The model recognises the projects but not their findings

Given only filenames and READMEs — no code — the model named 8 of 10 held-out projects
correctly (Moonwell, Perennial Finance, zkSync Era System Contracts, Coinbase Smart
Wallet…). Its tag agreement with ground truth nonetheless does **not** beat a
frequency prior: gap −0.019, 95% CI [−0.117, +0.075].

Recognising a codebase is not remembering its audit. Absolute scores are not inflated
by memorised findings, and the paired architecture comparison is insensitive to
memorisation regardless, since both arms share the model.

`scripts/e7_memorization_probe.py`

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
  plan.py        the ONLY fork between routed and broadcast arms
  executor.py    concurrent execution, resumable
  llm.py         OpenAI-compatible client with lenient JSON recovery
  verify.py      single-round refutation pass
  aggregate.py   repo-level decision layer; upstream == prior=1, tau->0
  evaluate.py    corrected scorer + faithful replica of upstream's
  synth/         localize -> induce -> hints -> gate
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

Enable the credential guard — git does not version hooks:

```bash
cp .git/hooks/pre-commit .git/hooks/pre-commit   # already present after clone? no:
git config core.hooksPath .githooks               # or copy from the repo root
```

## Use

```bash
bastet-cc index  <repo-hash>                 # parse one repository
bastet-cc route  <repo-hash>                 # routed vs broadcast cost
bastet-cc scan   dev --run dev-routed --arm routed
bastet-cc scan   dev --run dev-bcast  --arm broadcast     # the control condition
bastet-cc calibrate --run dev-routed         # fit the decision layer on DEV only
bastet-cc evaluate  --run dev-routed --scorer both
bastet-cc figures
bastet-cc audit                              # leakage + instrument audits
```

Measurement scripts that need no API key:

```bash
python scripts/e6_scorer_forensics.py        # perfect-predictor ceiling
python scripts/instrument_audit.py           # floor, metric flip, balance sensitivity
python scripts/routing_recall_ceiling.py     # what routing costs in recall
python scripts/leakage_audit.py              # split enforcement
```

Rebuild the upstream control group from zero:

```bash
cd ../upstream-bastet
AIS3_API_KEY=... ./setup_baseline.sh ais3/nemotron-3-ultra-550b
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

## Status

Complete and measured: instrument audit, routing, cost, coverage analysis, leakage
audit, memorisation probe, upstream control group, figures.

In progress: detector synthesis has produced S1 localisation, S2 induction for 23 tags
and S3 hint filtering; assembly into `detectors_synth/` and the TEST run are not done.

## Credits and licence

Built on [OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) (Apache-2.0);
the 56 detector prompts in `detectors/` are theirs, extracted verbatim from their n8n
workflows. Corpus from the Bastet Kaggle competition (1 April – 1 July 2026), labelled
by DeFiHackLabs. Inference on the AIS3 2026 LLM infrastructure.

Apache-2.0. For research and education. Findings should follow responsible disclosure.
