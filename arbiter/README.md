# ARBITER

Proof-carrying smart contract auditing. A finding is a transcript of an execution,
not an assertion by a language model.

Built to beat [OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) on the
same model, same gateway, same evaluation set, same scorer.

## The problem with the baseline

Bastet runs 56 hand-written detector prompts, one LLM call per detector per `.sol`
file, and decides `vulnerable` iff any detector returns a non-empty list. Measured on
a balanced 14-sample set where every negative is the *patched version of a positive*:

| model | TP | TN | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| `ais3/nemotron-3-ultra-550b` | 7 | **0** | 7 | 0 | 0.500 | 1.000 | 0.667 |
| `ais3/llama-3.3-70b` | 7 | **0** | 7 | 0 | 0.500 | 1.000 | 0.667 |

TN = 0. F1 0.667 is exactly the score of answering "vulnerable" every time.

This is arithmetic before it is prompt quality. With 53 detectors, even at a generous
5% per-detector false-positive rate, `1 - 0.95**53 = 0.934` — it would still flag 93%
of safe code. The decision rule has no representation for "this is fine".

Two further measured facts: patched code triggers *more* detectors than the vulnerable
original in 4 of 5 matched pairs, and 25 of 53 detectors have discriminative power
≤ 0 (they fire as often or more on safe code).

## What ARBITER does instead

An agentic loop shaped like a coding agent, with a compiler and a real EVM as tools.

```
read_source / grep_source     deterministic, zero requests
run_poc                       write Solidity, compile it, execute it on the EVM
submit_finding                REJECTED unless the cited PoC compiled, ran, and passed
conclude_safe                 a first-class answer, which the baseline cannot express
```

The submission gate is a dictionary lookup against `forge` output produced in-process
from the agent's own code. The model cannot argue past it.

### The mechanism, validated without a model

The same hand-written reentrancy PoC, against the vulnerable sample and its patched pair:

```
V1_reentrancy_withdraw        [PASS] testDrain() (gas: 785169)
S1_reentrancy_withdraw_fixed  [FAIL: eth send failed] testDrain() (gas: 822271)
```

The EVM separates them for free. Bastet flagged both.

## Cost

One gateway request per agent turn, capped at 16. Bastet spends 53 requests per sample.
The gateway's measured limits are `rpm=120` / `tpm=20,000,000` — 166,667 tokens per
request — so requests are the scarce resource and ARBITER is cheaper on the axis that
actually binds.

## Fairness

`BENCH_PROTOCOL` obligations are discharged in shared code so neither arm can discharge
them differently: `gateway.py` recovers `content: null` responses from the reasoning
field and reads the served model back out of the response body; `score.py` is the only
scorer either arm may use. Parse failures are counted separately and never folded into
false negatives.

## Use

```bash
export AIS3_API_KEY=...
python cli.py run --evalset evalsets/v1_paired14.json \
  --model ais3/nemotron-3-ultra-550b --run-id arbiter-n550 --repeats 5
python cli.py compare --a runs/bastet.summary.json --b runs/arbiter-n550.summary.json \
  --evalset evalsets/v1_paired14.json
```
