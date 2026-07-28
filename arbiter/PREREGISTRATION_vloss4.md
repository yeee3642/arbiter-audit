# Pre-registration: does bounding the attacker's authority reduce false positives?

Written and committed while run `vloss4` is at 34 of 70 samples, before its outcome is
known. The point of writing it now is that it cannot be rewritten afterwards to match
whatever came out. This project's whole argument is that a claim without a check is
worthless; that applies to its own claims first.

## The comparison

Both arms audit the same 70 samples of `evalsets/v4_test.json` -- 35 vulnerable
contracts and 35 patched twins, every pair machine-verified so that a false positive is
unambiguous: the exploit ran against the half that is known to be fixed.

Same model (`ais3/nemotron-3-ultra-550b`), same turn budget (26), same attempt count (2),
same gateway. The only difference is the gates.

| | arm A, recorded (`r2-arbiter`) | arm B (`vloss4`) |
| --- | --- | --- |
| predicates | eth_profit, token_profit, state_change, liveness_broken | victim_loss, liveness_broken |
| cheatcodes in the attack | allowed | refused |
| negation test | none | built in |
| halt sentinel, drain invariant | none | present |
| **TP / TN / FP / FN** | **15 / 22 / 13 / 20** | to be filled in |
| **precision** | **0.536** | |
| **recall** | **0.429** | |
| **MCC** | **0.058** | |

## What will be reported, whatever it says

1. The full confusion matrix, not a selected metric.
2. Precision, recall, MCC together. Precision alone is unfalsifiable -- a gate that
   refuses everything scores 1.000 -- so it will never appear without recall beside it.
3. A confidence interval on the precision difference. At these counts the interval is
   wide, and if it spans arm A the honest statement is "not separated at this sample
   size", not "we improved it".
4. A breakdown of every false positive by which predicate produced it.
5. What the retired predicates cost in true positives. Re-gating the older proofs already
   showed the new gates remove 3 false positives and 4 TRUE ones. If arm B's recall is
   below arm A's 0.429, that is the same trade appearing again and it will be stated as a
   loss, not smoothed over.

## Limitations already known, recorded before the result

These were identified by an adversarial review while the run was in flight, and two of
them have already been confirmed against arm B's partial output. They are written down
now so that they cannot later be presented as things we knew all along, nor quietly
dropped if the numbers look good.

- **The cheatcode ban relocates the boundary rather than closing it.** Cheatcodes are
  refused in the attack and still allowed in setup, so an agent can write
  `vm.prank(owner)` during setup to hand the attacker a role and forge the same authority
  a moment earlier. There is no probe proving setup cannot launder authority. This is the
  next boundary, not a solved problem.
- **`victim_loss` has a contention-shaped false positive class, confirmed.** In arm B's
  false positive on `S_self_reported_collateral_balance_callback`, the victim's exit was
  `target.redeem(10 ether)` -- a fixed amount. The attacker consumed shared liquidity, the
  fixed-size redemption then reverted, and the harness scored a recovery of zero as harm.
  Ordinary contention for a shared pool is not a defect. Fees, slippage and interest
  accrual produce the same shape.
- **Every gate here is a precision gate.** `victim_loss` requires a counterfactual in
  which somebody's balance falls, so it structurally cannot express privilege escalation
  with no immediate transfer, griefing, denial of service, or frozen funds.
  `liveness_broken` covers part of that and is itself unmodified in this work -- one of
  arm B's two false positives so far came from it. The false-negative ceiling of this
  design has not been measured.
- **Arm A ran with a 26-turn budget and so does arm B, but arm A predates several
  unrelated changes** to triage, compilation and repository navigation. The predicates
  and gates are the intended difference; they are not the only difference.

## What would count as a win, and what would not

A win: arm B's false positives fall materially below 13 while recall stays at or above
0.429, and the interval on the difference excludes zero.

Not a win, and will be reported as such: false positives fall because recall collapsed;
or the difference is inside the noise at n=70; or the improvement is carried entirely by
the agent attempting fewer exploits rather than by the gates refusing bad ones.
