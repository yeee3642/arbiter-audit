# Head-to-head: ARBITER vs Bastet

40 paired samples, one model, one gateway, one scorer. Run 2026-07-26 on the AIS3
infrastructure, both arms on `ais3/nemotron-3-ultra-550b`, `system_fingerprint`
`vllm-0.24.0-tp8-ep-d6a91272`.

## The headline, stated plainly

**ARBITER does not yet win outright.** It wins four metrics of seven and loses the one
most people quote.

| | Bastet | ARBITER |
|---|---|---|
| TP / TN / FP / FN | 20 / **0** / 20 / 0 | 9 / **16** / 4 / 11 |
| precision | 0.500 | **0.692** |
| recall | **1.000** | 0.450 |
| specificity | 0.000 | **0.800** |
| **F1** | **0.6667** | 0.5455 |
| accuracy | 0.500 | **0.625** |
| **MCC** | 0.000 | **0.267** |
| requests | 2125 | **1555** |
| requests / sample | 53.0 | **38.9** |
| cost | **$2.93** | $13.82 |
| findings backed by an execution | **0%** | **100%** |

Paired exact McNemar over the 40 shared decisions: ARBITER alone correct on 16, Bastet
alone correct on 11, 27 discordant, **p = 0.442**. The difference favours ARBITER but is
**not statistically significant**, and saying otherwise at n=40 would be dishonest.

## What the F1 number is worth

Bastet scores F1 **0.6667**. The constant predictor that answers "vulnerable" without
reading anything scores F1 **0.6667** on this set. Those are the same number, to four
decimal places, and Bastet's MCC is **0.000** — the value a coin with both sides painted
the same returns. It flagged all 20 patched contracts.

So the F1 loss is real and is reported as a loss, but it is a loss to a degenerate
strategy on a metric that rewards degenerate strategies at 50/50 balance. MCC and
specificity are the metrics that separate the arms, and on those the gap is 0.267 vs
0.000 and 0.800 vs 0.000.

Both readings belong in the same table, which is why both are above.

## Where ARBITER's recall goes

All 11 false negatives have the same cause, and it is not the one that would be
comfortable:

| cause | count |
|---|---|
| exploit compiled and ran, but did not satisfy the predicate | **11** |
| exploit never compiled | 0 |
| never attempted an adjudicated exploit | 0 |

Compile failures are gone — an earlier revision lost nine consecutive exploits on one
sample because `forge build` compiles the whole test directory and a stale probe was
poisoning every later build. Tool avoidance is gone too. What remains is the hard part:
the agent writes a valid, executable attack that simply does not extract value.

Every one of those 11 samples is provably exploitable. Benchmark admission proved each
one with a reference exploit inside this same harness before the sample was allowed in.
So this is a search failure, not an expressiveness failure, and it is the entire
remaining gap.

Arithmetic on what closing it takes: at precision 0.8, F1 overtakes 0.667 at recall
0.571. That is 12 of 20 proven, against 9 today. **Three more.**

## Where ARBITER's false positives come from

| sample | predicate that passed |
|---|---|
| S_reentrancy_unstake | `state_change` |
| S_missing_access_control_disburse | `state_change` |
| S_slippage_check_skipped_branch | `eth_profit` |
| S_weak_randomness_flip_payout | `eth_profit` |

`state_change` remains the weakest predicate and accounts for half of them, even after it
was made differential against an honest baseline. It is the only predicate where the
agent still chooses the question — which state counts as privileged — and that latitude
is exactly what the harness-owned design exists to remove elsewhere.

## Fairness

Both arms shared `gateway.py` and `score.py`, so rate limiting, cost accounting from
response headers, model read-back, `content: null` recovery from the reasoning field, and
parse-failure accounting are the same code rather than matched implementations. Bastet
ran its own verbatim n8n prompts, its own format instructions, `temperature` omitted, its
own decision rule, and its 53 non-gas detectors. `same_model` verified true by reading
the served model out of every response body.

## Honest accounting of the cost claim

An earlier note in this project said ARBITER was "3.7× cheaper". That was true of
requests and false of money. Corrected: **1555 requests against 2125** — cheaper in the
resource the gateway actually rations at 120/min — but **$13.82 against $2.93**, roughly
4.7× more expensive, because an agent turn carries a far larger context than a single
detector prompt. On this infrastructure requests are the binding constraint and tokens
are nearly free, so the request number is the operationally relevant one; the dollar
number is still the dollar number.

## Reproduce

```bash
export AIS3_API_KEY=...
python cli.py bench   --pairs evalsets/authored_pairs.json --out evalsets/v3_authored.json
python cli.py bastet  --evalset evalsets/v3_authored.json --prompts ../bastet-run/prompts \
                      --model ais3/nemotron-3-ultra-550b --run-id h2h-bastet
python cli.py run     --evalset evalsets/v3_authored.json \
                      --model ais3/nemotron-3-ultra-550b --run-id h2h-arbiter --attempts 3
python cli.py compare --a runs/h2h-bastet.summary.json --b runs/h2h-arbiter.summary.json \
                      --evalset evalsets/v3_authored.json
```

Raw artefacts for this run are in `runs/`: both summaries and the paired comparison.
