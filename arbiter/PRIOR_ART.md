# Prior art, and what it does to this project's claims

Searched 2026-07-26. Recorded here because two of the findings remove novelty this
project had implicitly claimed, and a judge who knows the literature would find them
immediately.

## The core idea is not new, and the published systems are better

**SmartPoC** (arXiv:2511.12993, Nov 2025) already does LLM proof-of-concept synthesis
inside a *generate-repair-execute loop*, with *differential verification as an oracle to
confirm exploitability* — the same three ideas ARBITER arrived at independently, eight
months earlier. Its results:

| | precision | recall | cost |
|---|---|---|---|
| SmartPoC on SmartBugs-Vul | 98.32% | 84.17% | — |
| SmartPoC on FORGE-Vul | 98.65% | 85.28% | — |
| SmartPoC on Etherscan corpus | — | 64 bugs / 545 findings | **$0.03 per bug** |
| **ARBITER on this benchmark** | **69.2%** | **45.0%** | **~$1.54 per bug** |

**Heimdallr** (arXiv:2601.17833, Jan 2026) is an agentic auditor with a *cascaded
verification layer*, reporting 92.45% detection in audit contests, reconstruction of 17
of 20 real post-June-2025 attacks totalling $384M, and 4 confirmed zero-days — at $2.31
per 10,000 lines, on an open-weight model.

So: **"a finding is a transcript of an execution" is established practice, not a
contribution of this project.** Any wording here that implied otherwise was wrong and has
been corrected.

### One distinction that is real, and is not an excuse

The numbers above are not directly comparable, and the reason cuts both ways.

SmartPoC's input is an **audit report**: it takes findings a static analyser or a human
already produced, and confirms which are genuinely exploitable. Its 84% recall means "of
the findings handed to it, it can build a working PoC for 84%". It is a *triage* tool.

ARBITER's input is **source with no report**. It must form the hypothesis before it can
prove it, and its 45% recall means "of vulnerable contracts, it discovered and proved
45%". Those are different tasks and the harder one is discovery.

That distinction explains part of the gap. It does not close it, and SmartPoC is
comfortably stronger at the task it addresses.

## What the prior art actually points at

If confirmation-from-a-report works at 98% precision, and this project's measured
bottleneck is *hypothesis formation* rather than proof construction — seven of ten missed
samples had every attempt reach for reentrancy while the real defect was a comparison
operator, a rounding direction or a stale price source — then the two halves are
complementary. One tool proposes; the other proves.

The obvious candidate proposer is the very baseline this project set out to beat.

## Measured: Bastet's detector hits carry information its verdict does not

Bastet's *sample-level* verdict is worthless as a proposal — it flags everything, which is
the whole finding of the instrument audit. But its *per-detector* hits are a different
signal, and `scripts/cascade_potential.py` measures it against the committed rows:

**Of the 11 vulnerable samples ARBITER failed to prove, 8 (73%) had an on-class detector
fire.**

| sample ARBITER missed | detector that named it correctly |
|---|---|
| `V_tx_origin_auth_router` | `4naly3er-M-avoidTx-origin` |
| `V_unbounded_queue_dos` | `Unbounded-loop`, `SC10-2025-Denial-Of-Service` |
| `V_stale_cached_price_liquidation` | 9 oracle/staleness detectors |
| `V_withdraw_rounding_favours_user` | `ERC4626-Rounding` |
| `V_fee_on_transfer_credit` | `4naly3er-M-FoTTokens` |
| `V_uint128_downcast_reward_debt` | `SC08-2025-Integer-Overflow-and-Underflow` |
| `V_amm_spot_price_oracle` | 14 oracle-manipulation detectors |
| `V_missing_deadline_signed_order` | `Slippage-No-Expiration-Deadline` |

Every one of those is a hypothesis ARBITER never formed. The information needed to fix
its worst failure mode was already sitting in the baseline's output, discarded by the
baseline's own decision rule.

## The composition this suggests

Neither tool works alone, and they fail in exactly complementary ways:

- Bastet has **recall 1.000 and specificity 0.000** — it proposes everything, decides
  nothing.
- ARBITER has **specificity 0.800 and recall 0.450** — it decides well, proposes badly.

A cascade uses each for the half it is good at: Bastet's per-detector hits become the
hypothesis queue, ARBITER's execution gate accepts or refuses each one. The 73% figure is
the ceiling on how much that could recover, and it is not a promise — an on-class
detector firing means the class was named, not that the agent can then build the exploit.

This is the direction round 2 should take, and it is pre-registered in
`PREREGISTRATION_V2.md` terms before being run: **if the cascade does not beat ARBITER
alone on MCC, the proposal channel added nothing and the result says so.**
