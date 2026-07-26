# Bastet+

A rebuilt harness for [OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet).

Same detector knowledge — all 56 vulnerability prompts are lifted verbatim out of the
original n8n workflows — but the scaffolding around them is replaced. No n8n, no Docker,
no Postgres, no webhooks. One `pip`-free Python package that talks to any OpenAI-compatible
endpoint, plus the pieces the original pipeline was missing: source slicing,
self-consistency sampling, evidence grounding, and an adversarial verification stage.

See [`IMPROVEMENTS.md`](IMPROVEMENTS.md) for the defect-by-defect account of what changed,
and [`RESULTS.md`](RESULTS.md) for the A/B measurement.

Measured head-to-head on `ais3/llama-3.3-70b`, same model and same detectors on both sides:

| | Original harness | Bastet+ |
| --- | --- | --- |
| F1 (per file×class) | 0.111 | **0.302** |
| Recall | 0.667 | **0.889** |
| File-level F1 ("does this file need review?") | 0.667 | **1.000** |
| Findings to triage | 278 | **27** |
| Findings on clean files | 118 | **0** |
| Findings with a line number | 0 | **27** |
| Severity silently defaulted to `high` | 278 / 278 | **0** |

The single most valuable change is verifier asymmetry: run detection on a cheap model and
verification on a stronger one.

```bash
python -m bastet_plus scan contracts/ --samples 3 --verifier-model <stronger-model>
```

---

## Quick start

```bash
cp .env.example .env    # point BASTET_LLM_BASE_URL at your model
python -m bastet_plus packs
python -m bastet_plus scan path/to/contracts --packs slippage,owasp2025
```

No dependencies beyond the Python 3.10+ standard library. Setup is two lines; the original
required Docker Compose, a Postgres volume, an n8n owner account, a manually created n8n API
key, a manually created OpenAI credential whose UUID you paste back into `.env`, and a
workflow import step.

### Run the A/B benchmark

```bash
python -m bastet_plus bench --samples 3
```

Runs both pipelines — the faithful legacy replica and the enhanced one — over the labelled
benchmark in `benchmark/`, using the same model, the same detectors and the same endpoint,
and prints a side-by-side table.

---

## Architecture

```
contract.sol
     |
     v
[ slicing.py ]      Solidity-aware slicing. Every slice carries the pragma,
     |              imports, state variables and modifier definitions of its
     |              contract, so a function is never judged without its storage.
     v
[ detectors.py ]    56 detector prompts extracted from the n8n workflows.
     |              Output contract is generated from schema.py, not hand-written
     |              per prompt, so it cannot drift.
     v
[ llm.py ]          Retry + backoff + timeout + sqlite response cache +
     |  x k         token accounting. Structured-output ladder:
     |              json_schema -> json_object -> text extraction -> repair.
     v
[ dedupe.py ]       Self-consistency. A candidate must be produced by a
     |              majority of the k samples to survive.
     v
[ grounding.py ]    Does the quoted code actually exist in the file?
     |              Zero-token false-positive filter; also assigns line numbers.
     v
[ verify.py ]       A fresh call, framed to refute, that must state a concrete
     |              exploit path or the finding is dropped.
     v
[ dedupe.py ]       One report line per bug, however many detectors saw it.
     v
[ report.py ]       md / json / csv / sarif
```

## Commands

| Command | What it does |
| --- | --- |
| `packs` | list the detector packs and their sizes |
| `scan <path>` | scan a file or directory; `--legacy` runs the original single-shot pipeline instead |
| `bench` | A/B both pipelines against the labelled benchmark |

Useful flags:

| Flag | Effect |
| --- | --- |
| `--samples N` | self-consistency: run each detector N times and require agreement |
| `--no-verify` | skip the adversarial verification stage |
| `--no-slice` | feed whole files, as the original did |
| `--keep-ungrounded` | keep findings whose quoted code is not in the source |
| `--model` / `--verifier-model` | override per run; verification can use a stronger model than detection |
| `--min-severity` | drop findings below a severity floor |
| `--no-cache` | bypass the response cache |

Each of these maps to one improvement, so you can ablate them individually and see what
each is worth on your own model.

## Output formats

`md`, `json`, `csv` — and `sarif`, which is new. SARIF renders as inline annotations on the
changed lines in GitHub code scanning and GitLab, which only became possible once findings
carried line numbers. The original emitted a PDF for CI to publish, which nothing consumes.

## Benchmark

`benchmark/cases/` holds 20 labelled Solidity files: 9 vulnerable, 11 clean. Every
vulnerable case is paired with a functionally equivalent safe twin that differs only in the
defence under test.

That pairing is the point. A detector that answers "yes, slippage" to every function
containing a swap scores 100% recall on the vulnerable half and is worthless. The safe twins
are what make precision measurable, and they are what the upstream `dataset.csv` evaluation —
which only asks "did any workflow output anything for this repo" — cannot measure.

This is a stand-in, not a replacement for the real thing: the upstream Bastet dataset (450
Code4rena codebases, ~4 400 findings) is distributed via Google Drive and is not in the
repository. To evaluate against it, point `bench` at a converted `labels.json`.

## Configuration

Everything is environment-driven; see `.env.example`. The original hard-coded `gpt-4o-mini`
inside all 56 workflow JSON nodes, so changing model meant editing 56 files or clicking
through the n8n UI 56 times.

## Relationship to upstream

The detector prompts are the work of the Bastet authors and are used unmodified except for
their output-contract block. `tools/extract_prompts.py` regenerates `prompts/legacy/` from
`n8n_workflow/*.json`, so upstream prompt changes can be pulled forward in one command.
