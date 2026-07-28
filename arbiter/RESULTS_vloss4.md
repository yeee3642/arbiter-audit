# Result: bounding the attacker's authority. Not a win, by the criteria set beforehand.

`PREREGISTRATION_vloss4.md` was committed at 2026-07-28T15:10 with the run at 34 of 70,
and it said two things would count as *not* a win: false positives falling because recall
collapsed, or a difference that sits inside the noise at n=70. Both happened. This
document reports it that way.

Same 70 paired samples, same model, same 26-turn budget, same 2 attempts. The only
intended difference is the predicates and the gates.

|  | arm A — retired predicates | arm B — victim_loss + gates |
| --- | ---: | ---: |
| TP | 15 | 10 |
| TN | 22 | **31** |
| FP | 13 | **4** |
| FN | 20 | 25 |
| accuracy | 0.529 | 0.586 |
| precision | 0.536 | 0.714 |
| recall | 0.429 | **0.286** |
| specificity | 0.629 | **0.886** |
| f1 | 0.476 | **0.408** |
| mcc | 0.058 | 0.214 |

Paired bootstrap on the difference, 20,000 draws:

| | B − A | 95% interval | |
| --- | ---: | --- | --- |
| precision | +0.179 | [−0.083, +0.438] | includes zero |
| recall | −0.142 | [−0.355, +0.074] | includes zero |
| f1 | −0.068 | [−0.288, +0.152] | includes zero |
| mcc | +0.156 | [−0.155, +0.459] | includes zero |

**Every interval includes zero.** At seventy samples this comparison is underpowered, and
the honest sentence is "not separated at this sample size", not "we improved it". That was
written down before the numbers existed precisely so it could not be argued away now.

## What actually moved

False positives fell from 13 to 4 and true negatives rose from 22 to 31. Specificity —
the ability to say "this contract is fine" — went from 0.629 to 0.886. That is the axis
the baseline this project set out to beat fails on completely: over its own benchmark it
scored TN=1, because a 53-way OR over detectors has no way to reach a negative.

It was paid for. Ten true positives that arm A found were lost, five new ones gained: a
net five findings given up to remove nine false ones. Whether that trade is worth making
depends on who reads the report, and this project should not pretend the question is
settled by a table.

f1 got worse, and that is not a metric artifact to be explained away — it is the trade
above, stated in one number.

## Where the remaining false positives come from

| sample | predicate |
| --- | --- |
| S_withdrawal_queue_unbounded_batch | liveness_broken |
| S_self_reported_collateral_balance_callback | victim_loss |
| S_module_allowlist_checked_by_code_length | victim_loss |
| S_lock_duration_uint64_downcast | victim_loss |

Three of four came from `victim_loss`, the predicate introduced to fix this. An
adversarial review predicted this class before the run finished, and the diagnosis on
`S_self_reported_collateral_balance_callback` confirms it: the victim's exit was
`target.redeem(10 ether)`, a FIXED amount. The attacker consumed shared liquidity, the
fixed-size redemption then reverted, and the harness scored a recovery of zero as harm.
Ordinary contention for a shared pool is not a defect. Fees, slippage and interest accrual
produce the same shape.

The fourth came from `liveness_broken`, which this work did not touch.

`module_allowlist_checked_by_code_length` is the worst single case: arm B calls the
patched half vulnerable and the vulnerable half safe. It gets that pair exactly backwards.

## True positives by predicate

`victim_loss` 6, `liveness_broken` 3, `eth_profit` 1 — the last from a sample audited
before the retired predicates were removed from the tool surface mid-run.

## What this licenses saying, and what it does not

Supported: the gates raise specificity and precision and lower recall; false positives
fall by roughly two thirds in absolute count; MCC roughly quadruples off a near-zero base.

Not supported: that any of this is statistically separated at n=70. Not supported: that
`victim_loss` fixes the false positive problem — it produced three of the four remaining
ones. Not supported: that the trade is favourable, since it costs five net findings.

The next measurement that would settle it is more paired samples, not another gate.
