# Demo

Four commands, in the order the argument is made. Every timing below was measured on
the infra box, not estimated.

Set up once per shell:

```bash
source ~/.arbiter_env      # AIS3_API_KEY + foundry on PATH
cd ~/rig/arbiter
```

`~/.arbiter_env` is mode 600 and outside the repository. The gateway key is never in a
file that git can see; the pre-commit hook blocks it if anyone tries.

---

## 0. The gates check themselves — 60s, no network, no key

```bash
for p in victim forgery halt drain sweep latebinding; do
  printf '%-12s ' $p; python3 scripts/${p}_probe.py 2>&1 | tail -1
done
```

Measured:

```
victim       4/4 as expected
forgery      6/6 as expected
halt         3/3 as expected
drain        2/2 as expected
sweep        2/2 as expected
latebinding  4/4 as expected
```

To show one in full, `python3 scripts/forgery_probe.py` is the clearest:

```
[OK  ] prank in attack                    REFUSED   attack_body calls vm.startPrank...
[OK  ] store in attack                    REFUSED   attack_body calls vm.store...
[OK  ] deal in attack                     REFUSED   attack_body calls vm.deal...
[OK  ] prank in attacker_code             REFUSED   attacker_code calls vm.prank...
[OK  ] warp in attack stays allowed       composed
[OK  ] cheatcodes in setup stay allowed   composed
```

This is the safest thing to open with, because it needs nothing: no gateway, no
network, no corpus. Note the last two lines — each probe asserts in **both**
directions, so the thing it must refuse is refused *and* the thing it must not refuse
still passes. A gate that only ever says no is not a gate, it is a broken tool.

---

## 1. A real audit against the live gateway — 53s, 10 requests, $0.06

```bash
python3 cli.py audit ~/demo/WithdrawalQueue.sol --run-id demo1 \
  --attempts 1 --max-turns 14
```

Measured output:

```
[MISS] r0 demo::WithdrawalQueue   -> vuln  (proven, 1x10t, 53.48s)

VULNERABLE  demo::WithdrawalQueue: Reentrancy in claim() allows draining the contract
            function: claim()
            severity: critical
            proof:    ReentrancyExploitExploitPoc (executed, predicate satisfied)

1/1 reported vulnerable, each backed by an executed exploit
usage: {"requests": 10, ..., "cost_usd": 0.059323}
```

The line that matters is `proof: ... (executed, predicate satisfied)`. The model did not
report a vulnerability — it is not allowed to. It wrote an attack, the harness compiled
it, ran it on an EVM, and checked a condition the model never saw.

**Before running this, confirm `forge` is on PATH.** Without it the audit reports every
contract as CLEAR, which is exactly the kind of unmeasured clean answer this project
exists to stop producing. `source ~/.arbiter_env` handles it; the command refuses to
start if forge is missing.

---

## 2. The proof becomes something anyone can run — 4s

```bash
python3 cli.py dump --results runs/demo1.results.jsonl --out ~/demo-exploits
cd ~/demo-exploits/demo_WithdrawalQueue__* && forge test -vv && cd -
```

`dump` runs `forge test` on each project before reporting, so `reproduced` is measured
rather than claimed. The reader re-runs it themselves; nobody has to trust our summary.

---

## 3. The attack as real transactions — 25s, two directions

```bash
python3 scripts/live_attack.py --port 8599              # drained
python3 scripts/live_attack.py --port 8600 --patched    # refused
```

Measured:

```
vulnerable   queue drained 6.0000 ether, attacker net +5.9999 after 231,081 gas,
             the victim's claim reverts and their 5 ether is gone
patched      the attack transaction reverts, the victim's claim succeeds,
             shortfall zero, attacker down the gas they burned trying
```

The second run is the argument. The attacker contract, the accounts, the amounts and
the transactions are identical — the only difference is whether `nonce[msg.sender]` is
written before or after the transfer.

This is where the harness stops being the EVM's administrator. Over JSON-RPC there is
no `vm.prank` and no `vm.deal`: to act as an account you hold its key and sign, to spend
you have the balance, to be included you pay for gas. Nothing is left to forge.

---

## 4. The ladder — 12 findings, ~8 min

```bash
python3 cli.py prove --dump ~/exploits-casc2
```

```
finding                          1 synthetic  2 standalone   3 live
V_arbitrary_call_executed...             yes           yes      yes
V_module_allowlist_checked...            yes           yes      yes
...
S_stablevault_price_deadline...          yes           yes       --
S_vesting_cliff_block_number...          yes           yes       --

8 reached a chain, 4 stopped at a standalone test, 0 only ever held inside the harness
every finding that reached a chain was on the vulnerable half of its pair
```

Both false positives are refused at rung 3, and refused on their merits rather than by
failing to run: one leaves the victim short while handing the attacker nothing, the
other moves no tokens out of the contract at all.

The rungs are not redundant, and the asymmetry is the point. **Rung 1 is the only one
that searches. Rung 3 cannot find anything at all — it can only refuse.**

---

## What to say when it does not go the way you want

Two of the twelve stop at rung 2 for reasons worth having ready.

`V_lottery_recent_blockhash` reproduces about once in four attempts. Predicting a
blockhash needs the power to choose it, and a chain does not hand that over. Quote the
live figure as **8 stable**, not 9.

A freshly audited contract can also stop at rung 2 with `took 3 but this user was still
paid`. That is not a failure to run: the attacker really did extract three ether with
signed transactions, and the particular user being modelled still got their money
because the agent's setup had seeded the contract with ten ether of somebody else's.
`victim_loss` is stricter than "the attacker stole something", and this is what it looks
like when the two come apart.

Saying that out loud is stronger than hiding it. The whole claim of the project is that
a finding is a transcript rather than an assertion, and a transcript you only show when
it flatters you is an assertion again.
