# ARBITER

Proof-carrying smart contract auditing. A finding is a transcript of an execution, not an
assertion by a language model.

Built against [OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) on the same
model, the same gateway, the same evaluation set and the same scorer.

AIS3 2026, track *安全工具開發與研究自動化*.

---

## The result, in one paragraph

ARBITER **does not beat Bastet on F1** — 0.5455 against a fairly tuned 0.6909 — and this
document says so before it says anything else. What it does do is find each real
vulnerability in **8.7 analyst-minutes against Bastet's 28.5**, surfacing 3.3× more real
bugs inside a one-hour review budget, on the cost-weighted metric that
`BENCH_PROTOCOL.md` pre-registered on 2026-07-25 and that round 1 never computed. Every
positive it reports arrives with an exploit its own harness compiled, executed and
adjudicated; Bastet's arrive as assertions. Both numbers are in the same table in
[`RESULTS.md`](RESULTS.md), along with a bootstrap defect found in our own statistics that
had been narrowing every interval in our favour.

## What this project contributes

**1. A quantitative audit of a published tool's instrument.** Bastet's shipped decision
rule is a 53-way OR, and it is not merely permissive — it is *saturated*. Thresholds k=1
through k=8 give identical results because every sample in the benchmark has at least 8
detectors firing. Its measured true-negative count is 0 across 20 patched contracts, its
F1 of 0.6667 equals the constant-"vulnerable" floor to four decimal places, and its MCC
is exactly 0.000. Given one tuning decision it reaches MCC 0.229 — so the defect is in
the shipped configuration, not the architecture, and this project says that too.

**2. An execution-gated auditing architecture, and the three ways it first failed.** The
research content is the failure sequence, not the final design: accepting "a test passed"
let the agent prove a *patched* contract's `withdraw()` reverts and submit it; taking the
success condition away from the agent still accepted a patched contract because the
contract pays a 1-ether airdrop by design; only a *differential* predicate — beat what an
honest user gets — holds. Naive proof-carrying does not work, and the reason is
documented rather than smoothed over.

**3. A machine-verified paired benchmark.** 20 vulnerability classes, 40 samples, where
each negative is the patched original differing by 1–4 lines. No pair enters unless the
reference exploit passes on the vulnerable half and the *same* exploit fails on the
patched half, checked by `forge` with no model involved. Reusable independently of this
project.

**4. An adversarial self-audit.** A reviewer attacked this work and 11 of 12 findings
landed. The bootstrap PRNG was stratifying its own resamples — 10,000 of 10,000 draws had
exactly 20 of each class — which narrowed every confidence interval in our favour; after
fixing it the headline MCC advantage no longer excludes zero. Confidence intervals had
been computed for the one metric we lose and not for the two carrying the claim. Our own
fairness suite had a `constant_yes_baseline` but no `constant_no`, which is why
specificity looked like a headline when a predictor that always answers "safe" beats us
on it. All fixed, all recorded, none quietly dropped.

**5. A pre-registered round 2.** [`PREREGISTRATION_V2.md`](PREREGISTRATION_V2.md) fixes
splits, power, arms and the decision rule before running, because round 1's headline
configuration was chosen by comparing settings on the only evaluation set there was.

---

## 1. What is wrong with the baseline

Bastet runs 56 hand-written detector prompts, one LLM call per detector per `.sol` file,
and decides `vulnerable` iff any detector returns a non-empty list. Measured on a
balanced 14-sample set whose every negative is the *patched version of a positive*:

| model | TP | TN | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| `ais3/nemotron-3-ultra-550b` | 7 | **0** | 7 | 0 | 0.500 | 1.000 | 0.667 |
| `ais3/llama-3.3-70b` | 7 | **0** | 7 | 0 | 0.500 | 1.000 | 0.667 |

TN = 0. F1 = 0.667 is *exactly* the score of answering "vulnerable" every time.

**This is arithmetic before it is prompt quality.** The decision rule is a 53-way OR. At
even a generous 5% per-detector false-positive rate, `1 − 0.95⁵³ = 0.934` — it would
still flag 93% of safe code. No amount of prompt engineering fixes a disjunction that
wide, and no new detector can lower it, because a detector can only ever add another
term. The architecture as shipped has no way to say "this code is fine".

> **Correction, after adversarial review.** That argument holds for Bastet's *shipped
> configuration* and was overstated as a claim about the architecture. Given one tuning
> decision — score on the single best detector rather than OR-ing 53 — Bastet reaches
> **F1 0.6909 and MCC +0.227** on the same 40 samples, beating ARBITER's F1 outright.
> The "structurally uninformative" framing was resting on an untuned baseline. See
> `RESULTS.md` and `scripts/detector_baselines.py`. Read the whole of `RESULTS.md`
> before quoting any number from this file: a bootstrap defect was found that had
> narrowed every confidence interval in this project's favour, and after fixing it the
> MCC advantage no longer excludes zero.

Two more measured facts point the same way:

- Patched code triggers **more** detectors than the vulnerable original in 4 of 5 matched
  pairs (reentrancy 13→14, phantom-balance 15→29, stakecredit 22→24, rwavault 18→30).
  Fixing a bug makes Bastet report more bugs, because a patch adds guards and a guard is
  more surface for a pattern-matcher to recognise.
- 25 of 53 detectors have discriminative power ≤ 0 — they fire as often or more on safe
  code. The worst is inverted: `ERC4626-Rounding` fires 0.00 on vulnerable, 0.43 on safe.

## 2. What ARBITER does instead

An agentic loop shaped like a coding agent, holding a compiler and a real EVM.

```
read_source / grep_source   deterministic, zero requests
run_exploit                 write an attacker, compile it, execute it — ADJUDICATED
run_poc                     free-form probe; capped at 3; can never back a finding
submit_finding              REJECTED unless it cites a run_exploit that passed
conclude_safe               a first-class answer, which the baseline cannot express
```

`submit_finding` is a dictionary lookup against `forge` output produced in-process from
the agent's own code. The model cannot argue past it.

### The hard part: who writes the success condition

Proof-carrying auditing does not work naively, and this project has the failures on
record rather than in a footnote.

**Attempt 1 — "the test passed".** On `S1`, a *patched* sample, the agent deployed the
vault under-funded, proved `withdraw()` reverts with `eth send failed`, asserted that the
revert happened, and submitted the passing test as evidence. The test was true. The
finding was false. A reverting withdraw is the contract working.

**Attempt 2 — the harness owns the predicate.** The agent supplies only the deployment
and an attacker; the harness writes the check. It still accepted `S1`, because
`UtopiaVault` pays every caller a 1 ether airdrop *by design* — so `claim()` then
`withdraw()` leaves an EOA richer on the patched contract too. "The attacker profited" is
a true statement about correct code.

**Attempt 3 — the predicate is differential.** The agent must also supply `honest_body`,
the intended happy path. The harness runs it first as a separate, identically funded
account, then runs the attack, and requires the attack to beat it **strictly**.
Collecting a designed reward stops being an exploit. Draining five times it does not.

```
V1_reentrancy_withdraw        [PASS]
S1_reentrancy_withdraw_fixed  [FAIL: eth send failed]

the tautology from attempt 1, replayed against the current gate:
V1  [FAIL: ARBITER: attacker did not profit]
S1  [FAIL: ARBITER: attacker did not profit]
```

Three predicates, all measuring something the agent does not get to restate:

| predicate | question the harness asks |
|---|---|
| `eth_profit` | did the attacker end up with more ether than an honest user? |
| `token_profit` | same, for a named ERC20 — most DeFi theft is not in ether |
| `state_change` | did privileged state move when an unprivileged account acted? |

And two attacker modes. `contract` drives an `Attacker` contract; `eoa` runs statements
under `vm.startPrank(eoa, eoa)`, which sets `msg.sender` *and* `tx.origin`. The second
exists because `require(msg.sender == tx.origin)` makes a contract attacker structurally
impossible — sample `V2` is exactly that, and any contract-only harness fails it by
construction rather than by weakness.

### Unioning attempts — a claim this project made and then measured

`--attempts k` runs a sample through k independent audits and takes the union, stopping
at the first proof. An earlier version of this section argued that Bastet's 53-way OR can
only accumulate false positives because nothing checks any term, whereas every ARBITER
attempt must clear the same execution predicate, so extra attempts **cannot** manufacture
a false positive.

That was measured, and it is false. Going from 3 attempts to 5 on the 40-sample benchmark:

| attempts | TP | TN | FP | FN | precision | recall | specificity | F1 | MCC | requests | cost |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 3 | 9 | 16 | **4** | 11 | 0.692 | 0.450 | **0.800** | 0.5455 | **0.267** | **1555** | **$13.82** |
| 5 | 10 | 14 | **6** | 10 | 0.625 | 0.500 | 0.700 | 0.5556 | 0.204 | 2412 | $21.50 |

Two extra attempts bought one true positive and two false positives. F1 moved by 0.01,
MCC got *worse*, request count overtook Bastet's 2125, and cost rose 55%.

The corrected claim: unioning is safe only to the extent the predicate is sound. Ours has
holes — `state_change` most of all — and more attempts find them more often. The
difference from Bastet is one of degree rather than of kind: its 53-way OR has no check
at all, ours has a check that is imperfect. `--attempts 3` is the configuration this
project stands behind.

## 3. The benchmark

The 14 original samples turned out to be *fragments*, not contracts — only 4 compile.
`V3` alone references `DoubleEndedQueue`, `STAKE_HUB_ADDR`, `IStakeHub`, `_burnAndSync`
and six custom errors that extraction left behind. Nothing can execute against them.

`reconstruct.py` restores stripped compilation context under enforced constraints
(additions only; every significant original line verified present verbatim; one shared
prelude per vulnerable/patched pair, so the pair still differs only by the fix). It
recovered some, not enough.

So `evalsets/v3_authored.json` is a purpose-built paired benchmark: **20 vulnerable /
patched pairs across 20 documented vulnerability classes, 40 samples.** Every pair had to
earn admission with no model involved:

```
both halves compile
   AND the reference exploit PASSES on the vulnerable half
   AND the SAME exploit FAILS on the patched half
```

**20/20 admitted.** The halves differ by 1–4 lines, so each negative is the patched
original rather than unrelated safe code — a pattern-matcher must flag both, and only
exploitability separates them.

That gate immediately caught a bug in its own harness: `";"` is not a valid Solidity
empty statement, so 17 of 20 reference exploits were failing to compile and being blamed
on the samples. Admission went 3/20 → 20/20 once it became `{}`.

Classes covered: reentrancy, missing access control, unchecked call return, `tx.origin`
auth, unbounded-loop DoS, forced ether, approval double-spend, unchecked `delegatecall`,
spot-price oracle, skipped slippage branch, missing deadline, stale cached price,
first-depositor share inflation, rounding direction, fee-on-transfer accounting, `uint128`
downcast, signature replay, `ecrecover` zero address, commit-reveal front-running, weak
randomness.

## 4. Request economy

The gateway's measured limits, from live response headers:

```
x-litellm-key-rpm-limit:  120
x-litellm-key-tpm-limit:  20000000
```

166,667 tokens for every one request. **Requests are the scarce resource and context is
nearly free** — and Bastet's shape spends the scarce one at the maximum possible rate
while leaving the free one almost untouched. It needs 53 requests per sample by
construction; a 200-file repository costs it 10,600.

ARBITER spends one request per turn, capped at 16, and stops early on proof. The cap is
per *API key*, not per process, so `RateLimiter` defaults to a minority share (45 rpm)
and a 429 waits out the window rather than retrying into the same collision.

## 5. Fairness

`BENCH_PROTOCOL` obligations are discharged in **shared code**, so the arms cannot
discharge them differently — they do not each implement them:

- `gateway.py` is used by both arms. It recovers `content: null` responses from the
  reasoning field (clause 1), reads the served model back out of the response body so a
  silent reroute cannot pass unnoticed, and takes cost from `x-litellm-response-cost`
  rather than estimating it.
- `score.py` is the only scorer either arm may use.
- Parse failures are counted separately and never folded into false negatives.
- Bastet keeps its own verbatim n8n prompts, its own format instructions with `{{`
  restored to `{`, `temperature` omitted because its workflow options are `{}`, and its
  own decision rule. The three gas-optimisation detectors are excluded, leaving 53 — gas
  findings are not vulnerabilities and counting them would manufacture false positives it
  never claimed.
- Clause 3's equal-request control is not owed: it protects the baseline from a challenger
  that buys accuracy with extra sampling, and here the challenger is the cheaper arm.

## 6. Layout

```
arbiter/
  gateway.py     shared client: rate limit, cost from headers, model read-back
  workspace.py   disposable forge project; composes the adjudicated exploit
  tools.py       the tool surface and its deterministic dispatcher
  agent.py       the audit loop
  run.py         concurrent, resumable, fully recorded
  bastet_arm.py  Arm A, verbatim, through our gateway and our scorer
  benchmark.py   admission control for paired samples
  reconstruct.py restores stripped compilation context, additions only
  score.py       one scorer; exact McNemar, paired bootstrap, MCC
evalsets/
  v1_paired14.json    the original samples (10 do not compile)
  v2_compilable.json  the subset that executes
  v3_authored.json    40-sample paired benchmark, 20/20 machine-admitted
```

## 7. Use

```bash
export AIS3_API_KEY=...

# Arm A
python cli.py bastet --evalset evalsets/v3_authored.json \
  --prompts ../bastet-run/prompts --model ais3/nemotron-3-ultra-550b --run-id h2h-bastet

# Arm B
python cli.py run --evalset evalsets/v3_authored.json \
  --model ais3/nemotron-3-ultra-550b --run-id h2h-arbiter --attempts 3

# paired comparison: exact McNemar, bootstrap, and the constant-yes floor
python cli.py compare --a runs/h2h-bastet.summary.json \
  --b runs/h2h-arbiter.summary.json --evalset evalsets/v3_authored.json
```

Rebuild the benchmark from its pairs, re-verifying every one against a real EVM:

```bash
python cli.py bench --pairs evalsets/authored_pairs.json --out evalsets/v3_authored.json
```

## 8. Honest limits

- The benchmark pairs are authored for this project. They are machine-verified to be
  exploitable and to resist their fix, but they are not third-party-labelled findings.
  Results on the natively-compiling real-world samples are reported separately.
- Ground truth is per-sample exploitability, not localisation. A true positive means the
  system proved *an* exploit, not that it found the same bug an auditor would name.
- `state_change` is the weakest of the three predicates, because "privileged" is the
  agent's choice of getter. `eth_profit` and `token_profit` are differential and are not.
- A gateway error currently scores a sample negative. The rate is reported in every run
  summary rather than hidden, but it is a floor on measured recall, not a property of the
  architecture.
- The gateway is nondeterministic even at `temperature=0` and offers no seed, so a single
  run is not a measurement; repeats and ranges are reported.

## 9. Credits

Built on [OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) (Apache-2.0); the
detector prompts in Arm A are theirs, extracted verbatim from their n8n workflows.
Inference on the AIS3 2026 LLM infrastructure. Apache-2.0, for research and education.
