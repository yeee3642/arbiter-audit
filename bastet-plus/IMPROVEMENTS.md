# What was wrong, what changed, and what it was worth

Bastet's *detector knowledge* is good — 56 hand-written, example-rich chain-of-thought
prompts covering slippage, oracle, access control, ERC-4626, flash-loan and OWASP SC Top 10
classes. That work is untouched here; all 56 prompts are lifted verbatim out of the n8n
workflows and reused.

What is rebuilt is everything around them. This document lists each defect, what replaced
it, and — where it is measurable — the number.

> **Measurement setup.** `RESULTS.md` holds the A/B run. Both arms use the same model, the
> same endpoint, the same 18 detectors and the same 20 benchmark files, so the difference is
> attributable to the harness. The legacy arm is a faithful Python replica of the n8n path
> (`pipeline.run_legacy`), not the n8n container itself — running the original requires
> Docker, Postgres, an n8n account and an OpenAI key, and reproduces exactly the same
> single-shot request/response.

---

## A. Correctness defects

### A1. The output contract disagrees with the schema it is validated against

Three copies of the finding format existed, and they did not match.

| Where | What it asks for |
| --- | --- |
| The prompt text in 55 of 56 workflow nodes | `summary`, `vulnerability_details.function_name`, `code_snippet`, `recommendation` — and in the two oldest, `Summary` / `Vulnerability Details` / `File Name` in Title Case |
| The Structured Output Parser node's JSON Schema | `summary`, **`severity`**, `vulnerability_details`, `code_snippet`, `recommendation` — all five `required` |
| `cli/models/audit_report.py` | the same five, with `severity` a `Literal["high","medium","low"]` |

**`severity` is required by the schema and by the model, and 55 of the 56 prompts never
mention it.** The model is never told the field exists.

That should be a loud validation error on every single finding. It is not, because of this:

```python
# cli/models/audit_report.py:18
def __init__(self, **data):
    data["severity"] = data.get("severity", "").lower()
    if data["severity"] not in ["high", "medium", "low"]:
        data["severity"] = "high"      # <-- silently
    super().__init__(**data)
```

Every finding is stamped `high`. The severity column in every Bastet report is a constant.
Triage order, CI gating thresholds, the severity breakdown in the PDF — all of it is
downstream of a default.

**Fixed by:** `schema.py` defines the finding format once. The prompt's output-contract block
is *generated* from that definition (`prompt_format_block()`), and the same definition is sent
as the `response_format` JSON Schema. They cannot drift because there is only one of them.
Coercion still happens — models are models — but every substitution is recorded in
`Finding.coerced_fields` and counted in the run stats instead of being swallowed.

### A2. `while True` with no sleep, no timeout, and no retry

```python
# cli/commands/scan/scan.py:99
while True:
    response = requests.get(execution_url, headers=headers)
    execution_data = response.json()
    if execution_data["finished"]:
        break
```

A tight poll loop with no delay: it re-requests the n8n execution API as fast as the network
allows for the entire duration of an LLM call. There is no timeout, so a workflow that errors
without setting `finished` hangs the scan forever, and no retry anywhere in the file — a
single 429 or 502 loses that contract's results silently (`continue`).

**Fixed by:** `llm.py` — bounded exponential backoff with jitter on 408/409/425/429/5xx and
timeouts, a hard per-request timeout, a concurrency semaphore, and no polling at all, because
there is no execution queue to poll.

### A3. `open(contract_file, "r")` with no encoding

```python
# cli/commands/scan/scan.py:57
with open(contract_file, "r") as file:
```

Uses the platform default — cp1252 on Windows — and raises `UnicodeDecodeError` on any
contract with a non-ASCII character in a NatSpec comment. The `evaluate` path does detect
encoding via `charset_normalizer`, so the two commands disagree with each other.

**Fixed by:** `slicing.read_source()` — binary read, decode ladder, replacement as last resort.
Never raises.

### A4. Evaluation metrics

`cli/commands/evaluate/eval.py` has four separate problems:

1. **Scoring stops at the first hit.** `if ans == 1: break` — the repo walk stops at the first
   file that produced any output, so a repo is scored on a prefix of itself.
2. **Any output counts as a hit for the tag under test.**
   `if any("output" in obj and obj["output"] != [] for obj in json_data)` — a slippage
   workflow that reports a reentrancy bug scores a true positive for slippage.
3. **Unguarded division.** `tp / (tp + fp)` crashes with `ZeroDivisionError` at the very end
   of a long run whenever a workflow reports nothing — the worst possible moment.
4. **Irreproducible sampling.** `dataset.sample(n=...)` with no seed, and `y_true` mixes
   `bool` and `int`. Two runs are never comparable, which makes the confusion matrix the
   README prints unfalsifiable.

**Fixed by:** `metrics.py`. The scoring unit is the (file, vulnerability class) pair; a
finding is attributed to a class by the detector that produced it; every ratio is guarded;
and Wilson score intervals are reported, because a 20-file benchmark cannot support three
significant figures and it is better to say so than to imply otherwise.

### A5. Corrupted prompt text

Typographic characters were destroyed somewhere in the workflows' authoring pipeline. In
`slippage_min_amount`:

- `Your output should contain each step? thinking.`
- `If the conclusion of a function is ?o vulnerability?? report with a empty array`
- `report that function? vulnerability`

and in `owasp2025 - SC08 Integer Overflow`, actual numeric literals are gone:
`If we try subtracting ????from an int8`.

The middle one is the damaging one: it is the instruction that tells the model when to return
an empty array, and it has been mangled into something unparseable.

**Fixed by:** a targeted repair table in `detectors.py`, applied to the enhanced path only.
Conservative — only unambiguous reconstructions. The cases where numeric literals were lost
are flagged rather than guessed at; they need an author who knows the original text.

---

## B. Design defects

### B1. Whole files, every time

The original POSTs the entire `.sol` file to every one of the 56 detectors:
`data = {"prompt": file_content}`.

Three consequences:

- **Context dilution.** A needle-shaped question over a 3 000-line haystack. Recall degrades
  with distance from the prompt.
- **Silent truncation.** Nothing checks the file against the context window. A file that
  exceeds it is truncated server-side and the harness reports "no vulnerabilities found".
- **No localisation.** The model sees no structure, so `function_name` is often a guess, and
  there is no line number in the output at all — which is why the reports cannot be diffed
  against ground truth or rendered as CI annotations.

**Fixed by:** `slicing.py`. A brace-matching, comment- and string-aware scanner cuts files
into self-contained slices. Every slice carries the pragma, the imports, and the enclosing
contract's state variables, modifiers and function signatures, so a function is never judged
without the storage it touches. Byte and line offsets are retained. Small files are left
whole — slicing a 200-line contract costs cross-function visibility and buys nothing.

### B2. One sample, one shot

Each detector runs exactly once at whatever temperature the n8n node defaults to. A decoder
that misses a given bug 40% of the time misses it 40% of the time, and there is no signal
distinguishing a confident finding from a fluke.

**Fixed by:** `--samples k` (`dedupe.vote`). Each detector runs k times at a raised
temperature with different seeds; near-duplicate findings are clustered; a cluster must appear
in a majority of the samples to survive. Votes are counted per *distinct sample*, so one
verbose sample cannot outvote two agreeing ones.

### B3. No verification stage

Whatever the detector returned went into the report. But a detector prompt is inherently
biased toward its own bug class — you have just told the model *"you are looking for missing
slippage protection"*, and it obliges, including where a `require(out >= minOut)` sits three
lines below.

This is the largest single source of false positives, and the original has no defence
against it.

**Fixed by:** `verify.py`. Each surviving candidate is re-examined by a fresh call that (a)
does not see the detector's leading question, (b) is framed to *refute*, (c) is told the
reporter over-reports, and (d) must state a concrete exploit path — who calls what, in what
order, and what they gain — or reject. The asymmetric framing is load-bearing: a verifier
prompted neutrally agrees with the claim it is shown almost every time.

`--verify-votes N` runs a panel with per-juror seeds; majority rules.

### B4. Nothing checks that the quoted code exists

Findings quote a `code_snippet`. Nothing ever compares it to the file.

A model that has invented a vulnerability almost always invents the code that proves it,
because it is reciting a pattern from training data rather than reading the file in front of
it. So this is a free, high-precision false-positive filter — and the original leaves it on
the table.

**Fixed by:** `grounding.py`. Whitespace-insensitive but token-exact matching of every
significant snippet line against the source. A majority of lines must be present or the
finding is dropped. Costs zero tokens. As a side effect it produces the **line number** that
makes SARIF output possible.

### B5. Duplicate findings

56 detectors run over the same file and the results are concatenated. A reentrancy bug caught
by both `owasp2025__4` and `access_control__1` appears twice; the 4naly3er pack overlaps the
OWASP pack heavily.

**Fixed by:** `dedupe.merge_across_detectors` — one report line per bug, with the contributing
detectors listed as provenance and the evidence unioned across them.

### B6. `gpt-4o-mini` hard-coded in 56 places

Every `lmChatOpenAi` node pins `gpt-4o-mini`, with no temperature, no seed and no
`max_tokens`. (One node, `flashloan`, pins `os-azure-gpt5-chat` — so the corpus is not even
internally consistent.) Changing model means editing 56 JSON files or clicking through the
n8n UI 56 times. There is no way to use a stronger model for verification than for detection,
because there is no verification.

**Fixed by:** `config.py` — one environment variable. `--verifier-model` allows an asymmetric
setup: cheap wide detection, expensive narrow verification.

### B7. The deployment story

To run the original you need: Docker, Docker Compose, a Postgres volume, an n8n instance, an
n8n owner account, a manually created n8n API key, a manually created OpenAI credential whose
UUID you copy back into `.env`, and a workflow import step — before the first contract is
scanned. The n8n workflows are the source of truth for the prompts, and they are 70 000-line
JSON blobs, so prompt changes are not reviewable in a diff.

**Fixed by:** a standard-library-only Python package. `cp .env.example .env` and run. The
prompts live in `prompts/legacy/*.md` as plain markdown, which means prompt changes show up in
code review as prompt changes. `tools/extract_prompts.py` regenerates them from upstream
workflow JSON in one command, so this does not fork the project.

### B8. No response cache

Every rerun pays full price and returns different answers, which is precisely what makes the
original evaluation impossible to reproduce.

**Fixed by:** a content-addressed sqlite cache keyed on the exact request payload. Reruns are
free, and an A/B where you have only changed the experimental arm replays the control arm
byte-identically instead of re-rolling the dice.

### B9. No CI-consumable output

`csv`, `json`, `md`, `pdf` — the CI templates in `.example.github/` and `.example.gitlab-ci.yml`
generate a **PDF** for the pipeline to publish. Nothing consumes a PDF.

**Fixed by:** SARIF 2.1.0 output, which GitHub code scanning and GitLab both render as inline
annotations on the changed lines. Only possible because findings now carry line numbers (B4).

### B10. A dead async SDK, and dead example code that ships with it

`cli/http_client/n8n/` is a hand-rolled async client for the n8n REST API — nine client
modules covering workflows, executions, credentials, audit, tags, users, variables and source
control, plus pydantic models. Roughly 30 KB of code.

Nothing uses it. `scan.py`, `eval.py`, `fetch.py` and `import_workflow.py` all call `requests`
directly. Its only importer is `cli/check.py`, which is itself example scaffolding that was
committed by accident — it hard-codes a developer's local instance IDs:

```python
project_id = "ERfhTxouVBTw1wVo"
workflow_id = "va8MTPdYK4MDdtnp"
```

Three files in the package (`config/config.ini`, `config/http_config.py`,
`config/__init__.py`) are zero bytes.

**Fixed by:** not carrying it forward. Bastet+ has no n8n dependency, so the SDK has nothing
to talk to.

---

## C. What each change is worth

Every improvement is behind a flag so it can be ablated individually on your own model and
your own corpus:

| Flag | Turns off |
| --- | --- |
| `--no-slice` | B1 source slicing |
| `--samples 1` | B2 self-consistency |
| `--no-verify` | B3 adversarial verification |
| `--keep-ungrounded` | B4 evidence grounding |

Measured on `ais3/llama-3.3-70b`, 20 files, 18 detectors — full detail and caveats in
[`RESULTS.md`](RESULTS.md), development-process disclosures in [`DECISIONS.md`](DECISIONS.md):

| Configuration | P | R | F1 | Findings | Findings on clean files |
| --- | --- | --- | --- | --- | --- |
| *trivial: always answer "vulnerable"* | *0.075* | *1.000* | *0.140* | — | — |
| Original harness | 0.061 | 0.667 | **0.111** | 278 | 118 |
| Bastet+, verification off | 0.096 | 0.889 | 0.174 | 105 | 47 |
| Bastet+, same-model verifier | 0.119 | 0.889 | 0.210 | 55 | 18 |
| Bastet+, stronger verifier | **0.182** | **0.889** | **0.302** | **27** | **0** |

Read that against the trivial baseline, not against zero. **The original harness scores
below a constant "yes".** The honest claim is "crosses the trivial floor", not "2.7x better".

Two things disqualify these from being a generalisation estimate, both detailed in
`DECISIONS.md`: the benchmark was authored by the same agent that built the harness and
**four cases were edited after seeing model output**, and the recommended configuration was
selected on the same 20 files it is reported on.

The `## Discipline` block appended to every detector prompt is also **not** pure plumbing —
it is anti-false-positive detection guidance, so this is not a clean harness-only A/B. Use
`--no-discipline` to isolate it; see `RESULTS.md` for that measurement.

Two of the defects above show up directly as counts rather than as accuracy:

- **A1 (severity):** 278 of 278 legacy findings had their severity silently rewritten to
  `high` — 100%. The severity column in every Bastet report is a constant.
- **A2/B-parsing:** 221 of 360 legacy responses (61%) were not bare JSON and would have been
  rejected by n8n's Structured Output Parser and dropped. With an explicit `response_format`
  schema, 1300 of 1300 enhanced calls parsed natively on the first attempt.

The single most valuable knob turned out to be **verifier asymmetry** — using a stronger
model for verification than for detection. It is the only configuration that drives
clean-file noise to zero, and it costs nothing in recall. Note that the slicing improvement
(B1) is *not* measured here: every benchmark file is below the slicing threshold, so
`--no-slice` is a no-op on this corpus.

---

## D. What was deliberately not changed

- **The detector prompts.** All 56 are reused verbatim apart from their output-contract
  block, which is plumbing rather than knowledge. The A/B would be meaningless otherwise.
- **The vulnerability taxonomy and packs.** Unchanged.
- **The dataset.** The upstream Bastet dataset (450 Code4rena codebases) lives on Google
  Drive and is not in the repository, so `benchmark/` is a small self-contained stand-in
  built for this comparison, not a replacement for it.

## E. Known limitations

- The benchmark is 20 files. It is enough to separate a harness that reports 5 findings per
  clean file from one that reports 0.3, and not enough to resolve a two-point difference in
  F1. The confidence intervals in `RESULTS.md` are there to make that explicit.
- The cases are purpose-built and therefore cleaner than production Solidity. Findings here
  are an upper bound on both arms.
- Slicing is a brace matcher, not a Solidity parser. It is written to never raise on
  malformed input, which means it can mis-slice exotic files (inline Yul with unbalanced
  braces inside strings is handled; assembly blocks with unusual comment nesting may not be).
  A `solc --ast-compact-json` backend would be strictly better where `solc` is available.
- Verification adds one call per candidate. On a large codebase that is the dominant cost;
  `--min-severity` and `--no-verify` exist for when it is not worth it.
