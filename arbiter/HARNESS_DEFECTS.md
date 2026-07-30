# Defects in the harness, not in the agent

Every entry below is a way the harness fails an attack that was not wrong. They were
found by reading `workspace.py` against the error census in
`runs/casc2-broad.scorecard.txt`, and the first two were then reproduced.

## Status

`scripts/collide_probe.py` is the record. It runs the same cases against the harness
before and after, and it BUILDS every one of them, because every case here composed
cleanly before the repair and then died at solc -- a composition-only check would have
passed while proving nothing.

```
                         before   after
declared collision         solc     ok      D5
comment/string intact      solc     ok      D5, and the rename must not reach either
assertions resolve         solc     ok      D6
memory decl in deploy      solc     ok      D2, deploy_code half
tuple decl survives        solc     ok      D7
storage decl               (silent) refused D8
reference-only cast          ok     ok      must not be renamed
nested struct                ok     ok      not file scope, so not a clash
Attacker                     ok     ok      never renamed, the setup writes it verbatim
tuple with bytes             ok     ok      mixed decl/assign is illegal: leave it alone
                          -----   -----
                           4/10   10/10
```

D1, D2 (victim half) and D3 were fixed earlier and have their own probes. D4 is still
open and is deliberately not fixed here; see its entry for why it cannot ship alone.

## What it did to the ceiling: nothing, and that is the result

```
                 before   after
expressible           8       8
unharmed             13      13
uncredited            3       3
no_victim            10      11
no_build              1       0
```

The bound is still 0.229. The one sample that could not build now fails as `no_victim`,
which means the category is empty: **of the twenty-seven reference exploits this predicate
cannot express, not one is our own tooling any more.** All twenty-seven are the predicate
being deliberately stricter than "the attacker profited".

That is worth more than a higher number would have been. Before this, the honest reading
of the ceiling had a footnote -- one of the failures was ours. It no longer does.

The distinction that matters: a recall defect costs findings, a soundness defect ships
false positives. D3 is the second kind, which is why it outranks everything except the
three-line fix above it.

## D1 -- `victim_loss` with `mode='eoa'` can never compile  (REPRODUCED)

`_VICTIM_TEMPLATE` declares `Attacker internal atk;` unconditionally, but
`compose_victim_loss` only requires an `Attacker` contract when `mode == "contract"`.
Composing in EOA mode therefore emits a file that names a type nothing declares:

```
28     Attacker internal atk;
--- declares contract Attacker: False
```

`DeclarationError: Identifier not found or not unique` -- 14 in the census, and some
share of the 161 unqualified `Undeclared identifier`.

`victim_loss` is the only strict predicate, so under `STRICT_PREDICATES` **every
EOA-mode attempt dies at composition**. That is the only route to a contract guarded by
`require(msg.sender == tx.origin)`, and it is also the shape an agent reaches for first
when the attack needs no contract at all.

The state variable is dead weight in contract mode too: `_ATTACKER_SETUP` declares a
local `Attacker atk` inside `arbAttack()` that shadows it.

Fix: emit the declaration only in contract mode.

## D2 -- `hoist_declarations` cannot see memory or storage declarations

`DECL_RE` matches `Type name =` and nothing else, so

```solidity
address[] memory users = new address[](2);
```

stays a local inside `arbSetup()`. Any `victim_enter` or `attack_body` that refers to
`users` fails to compile, and the agent is shown an error at a line number in a file it
never wrote.

Fix: admit an optional data location and an optional `[]`, and then scan the rewritten
body for declarations that still look hoistable and refuse at composition time with the
offending line quoted. A composition-time refusal costs one turn; a compile failure the
agent cannot map back to its own text costs the rest of the audit.

## D3 -- `gain` is inflated by round, which loosens the conservation check  (REPRODUCED)

`arbAttack()` opens with `{setup}`, and `{setup}` is `_ATTACKER_SETUP`:

```solidity
Attacker atk = new Attacker(address(target));
vm.deal(address(atk), {funding_wei});
```

That runs **once per round**. At `rounds = 8` the attacker is redeployed and re-funded
eight times, so nothing an attacker accumulates survives into the next round. The EOA
path has the same defect by a different route: `vm.deal` sets a balance rather than
adding to it, so each round resets the attacker's costs to zero.

Then each round's contribution is floored before it is summed:

```solidity
return atkPost > atkPre ? atkPost - atkPre : 0;     // per round
gain += abi.decode(data, (uint256));                // then accumulated
```

An attack that gains 1 ether and loses 1 ether each round reports `gain = 4 ether` after
eight rounds while its true net is zero.

`gain` is the left-hand side of the conservation requirement `g >= shortfall` -- the
clause that makes `victim_loss` mean *the attacker is holding what the victim lost*.
Inflating it weakens the strongest gate in the system. This is a false-positive path,
and it is constructible.

Two consequences beyond soundness. The `rounds = 8` environment exists to expose
per-round rounding bias, and a per-round redeploy makes that entire class structurally
unprovable. And profit that ends up in the attacker's EOA rather than the attacker
contract is measured as zero.

Fix: deploy and fund once per trial, take `gain` as a single delta across the whole
trial, and measure the attacker as the sum of both identities the harness created for
them.

## D4 -- the environment sweep never varies the attacker's capital

`VICTIM_ENVIRONMENTS` spends its endowment axis on `vm.deal(arbVictim, endow)`. The
attacker's `funding_wei` stays at its default; `compose_victim_loss` is never called
with anything else. So the thousandfold-scale environment scales the **victim's** wallet.

Every class that needs capital -- first-depositor inflation, spot-price manipulation,
TWAP collapse, liquidation -- is unreachable under `victim_loss` at any scale.

Fix, with a caveat that is not optional: an attacker-capital axis is the one knob in the
sweep that has no counterpart in the unattacked trial, because that trial has no
attacker. It can manufacture victim shortfall through nothing but ordinary competition
for shared liquidity. It must ship together with a third trial in which a harness-owned
ordinary user is funded identically, and harm must be counted only in excess of what
that user causes. Shipping the axis without the control trial should be expected to
roughly double the false positives.

## D5 -- the agent's own interfaces collide with the target's

`import "../src/Target.sol"` is unnamed, so every top-level declaration in the target is
in scope. Nine of the 35 vulnerable samples declare `IERC20` themselves; an agent that
writes one to cast with gets `Identifier already declared` (41 in the census), and one
that skips it and casts against the target's own gets the explicit-conversion errors
(41 more between the two rows).

Fix: rename mechanically rather than refuse. Collect the target's top-level names,
rewrite colliding declarations in the agent's fragment to `Name_arb`. Interfaces are
structural, so renaming changes nothing about what the cast means. A refusal costs a
turn; a rename costs nothing.

## D6 -- the assertion family does not exist  (REPRODUCED, FIXED)

`Harness` declared `assertTrue(bool, string)` and nothing else. An agent reaching for
forge-std out of habit -- `assertEq`, `assertGt`, one-argument `assertTrue` -- got

```
Error (7576): Undeclared identifier. Did you mean "assert"?
```

54 in the census, second only to the unqualified `Undeclared identifier` row.

Two details decided the fix. The shims live at **file scope**, not in `Harness`, because a
contract member shadows the whole overload set: a `Harness` declaring
`assertTrue(bool,string)` makes `assertTrue(cond)` fail to resolve from inside it, and an
`Attacker`, which inherits nothing, could reach neither. And they **revert** rather than
no-op, because the agent wrote them as control flow. Neither direction can manufacture a
finding: the verdict is computed from balances the EVM reported and no assertion the agent
writes is consulted anywhere in it.

`int256` overloads are deliberately absent. With them, `assertEq(1, 2)` matches both
`uint256` and `int256` and fails with "No unique declaration found" -- one compile error
traded for another.

## D7 -- a name declared inside a tuple is invisible to hoisting  (REPRODUCED, FIXED)

`VICTIM_DECL_RE` and `DECL_RE` both matched `Type name =` at the start of a line, so

```solidity
(bool okWithdraw, ) = address(target).call(abi.encodeWithSelector(...));
require(okWithdraw, "withdraw failed");
```

left `okWithdraw` a local. Every stage of the trial is a separate external call, so the
`require` one stage later came back as `Undeclared identifier` at a line in a file the
agent never wrote. This is not an exotic shape -- it is how Solidity sends ether -- and it
is the whole reason `proxy_implementation_slot_unguarded_upgrade` was the one `no_build`
in the ceiling measurement.

All-or-nothing per statement: mixed tuple declaration and assignment has been illegal
since 0.5.0, so `(arbv_ok, bytes memory ret) = ...` will not compile. A tuple with a
reference-typed component is left exactly as written, which is the old behaviour and
cannot regress.

## D8 -- a `storage` pointer was hoisted into a deep copy  (FIXED, by refusing)

Dropping the data location off `memory` on the way up is a copy from memory into storage,
which is what the assignment already meant. Dropping it off `storage` is a deep copy of
whatever the pointer aimed at: silently different semantics when the struct is copyable,
and a compile error the agent cannot map back to its own text when it holds a mapping.

So it is refused at composition with the offending line quoted. A refusal costs one turn;
a compile error inside generated code costs the rest of the audit.

## Before any of this: measure the ceiling

`evalsets/test_pairs_v2.json` carries 35 reference exploits, each already shown to pass
on the vulnerable half and fail on the patched half. Their predicates:

| predicate | count |
|---|---:|
| eth_profit | 24 |
| liveness_broken | 7 |
| state_change | 2 |
| token_profit | 2 |
| **victim_loss** | **0** |

The ground truth and the instrument the agent is graded with are not the same yardstick.
The agent is asked to prove, under `victim_loss`, twenty-six classes that nobody has ever
proven under `victim_loss`.

So run the reference exploits through `compose_victim_loss` -- deploy and attacker code
verbatim, victim fragments split out of `honest_body` -- on both halves of every pair.
Two numbers come out: how many known-exploitable samples the harness will accept, and how
many patched ones it wrongly accepts.

It costs no gateway requests and it decides where the remaining budget goes. If the
ceiling is near 30/35 the harness is expressive and the bottleneck is the agent's search
cost. If it is near 15/35 then a large part of the 66% that ran and extracted nothing is
mechanism that is correct and unexpressible, and the templates need the work.

Prediction on record: 14-20 of 35, failing mostly because the attack must precede the
victim's entry, because no time passes between the attack and the victim's exit, and
because of D4. A ceiling at or above 28 refutes that reading.
