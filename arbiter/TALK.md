# Fifteen minutes

Twelve minutes of talking, three of questions. The structure follows one rule: **lead
with what does not move.**

The confusion matrix is not the spine of this talk, and now there is a measurement
saying why. Three runs, same config, same 70 samples:

```
run             TP  TN  FP  FN    prec     rec      f1     mcc
fixed1           7  31   4  28   0.636   0.200   0.304   0.118
fixed2          13  30   5  22   0.722   0.371   0.491   0.261
casc2-strict    10  33   2  25   0.833   0.286   0.426   0.303
                          mean  0.731   0.286   0.407   0.227
                         range  .64-.83 .20-.37 .30-.49 .12-.30
```

MCC swings by a factor of two and a half between identical runs. The dip after this
week's fixes was a low draw, not a regression -- but nobody could have said so from one
run, which is the point. Quote the range, never a single figure.

Four other results are stable, checkable live, and stronger:

| stable | what it is |
|---|---|
| 0 of 1152 | baseline findings carrying anything executable |
| 37 of 53 | baseline detectors that never discriminate a single pair |
| 8 vs 0 | vulnerability classes discriminated, ours against theirs |
| 8 of 35 | classes our own strict predicate can express at all — measured against ourselves |

---

## 0:00 — 0:45  One sentence, then stop talking

> Every LLM audit tool I know of produces an **assertion**: a paragraph saying "there is
> a reentrancy here". This one is not allowed to. The model has to write an attack, and
> the harness compiles it and runs it on an EVM against a success condition **the model
> never sees**.

On screen: that sentence. Nothing else. Do not say "eight axioms", do not say
`victim_loss`, do not say MCC. Every one of those is a word the room does not have yet.

## 0:45 — 2:30  Why the obvious comparison is the wrong one

Put the baseline's scoreboard up **first**, as their number, not yours:

```
Bastet, 40 paired samples:   TP 20   TN 0   FP 20   FN 0     F1 0.667
```

Then the plain-language version, and wait:

> It answered "vulnerable" to all forty. Twenty of them were the *fixed* versions. Its
> F1 is 0.667 because a smoke alarm that is always going off is right every time there
> is a fire.

Now the per-detector table, which is the part nobody can argue with:

```
detector                              pairs   V    S   both   discriminated
SC03:2025 - Logic Errors                20   20   20    20        0
SC04:2025 - Lack of Input Validation    20   20   20    20        0
Refund failed                           20   20   20    20        0
Lack of access control  (best of 53)    20   19   16    16        3
```

> Thirty-seven of its fifty-three detectors never once fired on a bug and stayed quiet on
> its fix. The best of them manages three pairs out of twenty. The ensemble carries no
> information because almost every part of it carries none.

**This is the strongest slide in the deck.** It is computed from their recorded run, it
needs no claim about our tool at all, and it is reproducible in front of the judges in
four seconds.

## 2:30 — 4:00  And nobody can check any of it

```
findings produced:            1152
carrying anything executable:    0   (0.0%)
```

> Their output is prose: a summary, a severity, a function name, a description. No
> contract, no test, no transaction. So it is not that our judge rejects their findings —
> **no judge can reach them.** There is nothing to run.
>
> That is the gap this project is about. Not accuracy. What kind of object a finding is.

## 4:00 — 7:30  The demo — this is the middle of the talk, give it the time

Run `scripts/demo.sh` live, or play `DEMO.html`. Four beats:

**(a) The gates check themselves — 30s, no network, no key.** Eight probes, each
asserting in *both* directions.

> A gate that only ever says no is not a gate, it is a broken tool. So each of these
> proves it refuses what it must **and** still admits what it must not refuse.

**(b) A real attack on a real chain — 15s.** anvil, real keys, real gas.

```
queue drained        6.0000 ether
attacker net         5.9999 ether   (put in 1, gas 231,081)
victim shortfall     5.0000 ether
```

**(c) The same attack, one line moved — 15s.** `nonce` written before the transfer
instead of after. Attacker contract, accounts, amounts: byte-identical.

```
attack tx REVERTED     victim's claim succeeded     shortfall 0
```

> That second run is the whole argument. An exploit that drained both would never have
> been about the defect.

**(d) The ladder.** Each finding walked from the harness, to a standalone project anyone
can run, to signed transactions on a chain.

> The rungs are not redundant, and the asymmetry is the design. **Rung one is the only
> one that searches. Rung three cannot find anything at all — it can only refuse.**

If asked why: over JSON-RPC there is no `vm.prank`. To act as an account you hold its
key; to spend you have the balance; to be included you pay for gas. Nothing is left to
forge, so there is no lint to write.

## 7:30 — 9:30  Our own ceiling — put this in, do not bury it

```
The 35 reference exploits, under the predicate we are graded with:

  expressible      8    passes on the buggy half, fails on the fixed one
  unharmed        13    the attacker really takes value -- up to 9 ether -- and the
                        modelled user is still paid in full
  uncredited       3    the user loses and nobody holds it: griefing has no beneficiary
  no_victim       10    no depositor round trip exists: signature replay has no depositor
  no_build         1    ours
```

> Our recall is bounded by **0.229**, not by 1.000. And twenty-six of those twenty-seven
> are the predicate being deliberately stricter than "the attacker profited" — not a bug.
>
> Nobody asked us to measure this. It is the number that makes our recall interpretable,
> and the baseline cannot produce its equivalent because it has no predicate to measure.

## 9:30 — 11:00  Where we actually are

Give the matrix, once, with the honesty that makes it credible:

> Across three identical runs precision is 0.64 to 0.83, recall 0.20 to 0.37, MCC 0.12
> to 0.30. I am not going to quote you one figure, because the spread is a factor of two
> and a half and I only know that because we ran it three times. Our own scoring code has
> always said every headline should be a mean over repeats; it had been run with repeats
> of one, and the first thing measuring that produced was a number I did not want.
>
> What is stable is per class: of thirty-five vulnerability classes we discriminate
> **eight** — flag the bug and stay quiet on the fix — against **zero**.

## 11:00 — 12:00  Close

> Three sentences.
>
> A finding here is a transcript of an execution, and you can re-run every one of them
> without trusting a word I have said.
>
> Every gate exists because the tool caught **itself** cheating: draining scenery it had
> built, halting before the predicate ran, writing an owner slot in setup. Those are
> commits, not hypotheticals.
>
> And the one number that decides whether our recall means anything, we measured against
> ourselves and published.

---

## Questions to have answers for

**"An always-*no* detector also scores MCC 0.000. What have you beaten?"**
> Per class: eight discriminated against zero. And an always-no detector produces no
> exploit, so there is nothing to adjudicate — same category as the baseline.

**"Your recall is 0.2. That is useless in practice."**
> Yes, as a detector. Look at what it is instead: for any claim that arrives with an
> exploit, this adjudicates it in seconds, and it refused both of our own false positives
> at the top rung on their merits. Recall is the wrong axis for a falsifier.

**"Who wrote the benchmark and who set the predicate?"**
> We did, and that is a real weakness — say so first. Mitigations, in order: the pairs
> are one defect and its one-line fix, so a false positive is unambiguous; the ground
> truth was audited and two of our own errors were found and fixed; the baseline runs
> verbatim, unmodified, on its own prompts; and we published the ceiling our own predicate
> imposes. **Then concede what remains: 35 pairs is underpowered, and the baseline has not
> yet been run on the same 70 samples the per-class table uses.**

**"Did you re-run after the fixes?"**
> Three times. It came back worse once (MCC 0.118), better once (0.261), against 0.303
> before. It was variance, and I could not have told you that from one run. The spread
> itself is now the number I report.

**"Why is the demo not a live audit?"**
> It can be, and the recording contains one — three requests, twelve cents, a reentrancy
> found and proven in three turns. On stage it is out, because on a harder contract it
> lands one run in three, and a recording can be made again where a room cannot.

---

## Do not put on a slide

- **`broadside`** — never run, and its internal judge uses a predicate we retired for
  having 37% false positives. Free ammunition.
- **The cascade** — did not reproduce end to end; the adjudication stage refused 0 of 21,
  and `RESULTS_cascade.md` still describes the older ablation.
- **The eight axiom names.** One sentence at 0:00 carries all of it.
- **MCC as the headline.** Use it once, at 9:30, after the room has the always-red-alarm
  picture.
- **Five different denominators.** Fix on: **35 pairs / 70 samples**. If a number uses a
  different base, say the base out loud.
