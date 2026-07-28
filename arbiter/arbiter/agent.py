"""The audit loop: a tool-using agent, in the shape of a coding agent.

Bastet issues 56 independent single-shot completions per file and never looks at the
answer again. This loop is the opposite shape and the contrast is the experiment: one
conversation, a compiler and an EVM exposed as tools, and iteration until the agent
either proves an exploit or gives up trying. It is deliberately modelled on how a coding
agent works, because auditing is the same activity -- form a hypothesis, run it, read the
error, revise -- and because the run/read/revise cycle is exactly the thing a stateless
prompt cannot do.

The prompt is written to be neutral about the answer. It carries no hint about the
composition of the evaluation set, per BENCH_PROTOCOL clause 5, and it says plainly that
concluding "safe" is a correct outcome, because the entire measured failure of the
baseline is that it has no way to reach that conclusion.

Cost: one gateway request per turn, capped by ``max_turns``. At the default of 16 that
is at most 16 requests per sample against Bastet's 53, so the architecture is cheaper on
the axis that is actually scarce as well as being more accurate.
"""

from __future__ import annotations

import json
from typing import Any

from .gateway import Gateway
from .tools import AgentOutcome, ToolDispatcher, parse_arguments, tool_schemas
from .workspace import Workspace

SYSTEM_PROMPT = """\
You are a smart contract security auditor. You are auditing exactly one Solidity \
contract, and you settle the question by experiment rather than by inspection.

You have a Solidity compiler and a real EVM available as tools. Use them.

The single most important thing to understand: a code pattern that resembles a known \
bug class is not a bug. Production DeFi code is dense with shapes that look like \
reentrancy, like unchecked arithmetic, like missing access control -- and the large \
majority of them are guarded, intentional, or unreachable. What separates a real \
vulnerability from a familiar shape is that an attacker can actually drive the contract \
into a bad state. That is a claim about execution, and you can test it directly instead \
of guessing.

Method:

1. Read the whole contract.
2. For each candidate weakness, first enumerate the guards that actually run on the path \
to it -- modifiers, require statements, ownership checks, reentrancy locks, bounds \
checks, state flags. Quote them from the source. If a guard already prevents the attack, \
that candidate is dead; move on.
3. Pick the strongest surviving candidate and state ONE falsifiable hypothesis: a \
specific sequence of attacker transactions, and a specific bad end state that should not \
be reachable.
4. Prove it with run_exploit. You write the attacker and the deployment; the harness \
writes the success condition and you cannot change it. Use run_poc first if you need to \
probe behaviour cheaply, but understand that a passing run_poc is worth nothing as \
evidence -- you chose what it asserts, so all it can prove is that your own assertion is \
true.

   **Prefer predicate='victim_loss'.** It is the one that matches what a vulnerability \
actually is: somebody else loses. You give victim_enter and victim_exit -- what an \
ordinary user does to take a position and to get their money back -- and the harness runs \
the whole scenario TWICE from the same code, once with your attack in between and once \
without. The finding is admitted only if that user recovered strictly less in the run \
where you attacked, and you came out ahead.

   That closes the hole in every other predicate, which is worth knowing about because it \
is the way most wrong answers get made here. Audited over this project's own 68 accepted \
proofs, 25 were against contracts that were already fixed: the setup forced ether into \
the target, the attack took it back out, and the profit comparison said yes. Real profit, \
real drain, nobody harmed. Under victim_loss that is refused, because the depositor still \
gets everything back.

   The other profit predicates are DIFFERENTIAL, and this is the part people get wrong. \
You must supply honest_body: what an ordinary user does with this contract. The harness \
runs that first, as a separate funded account, and your exploit has to produce STRICTLY \
MORE gain than it did. So collecting a reward the contract hands out on purpose is not an \
exploit -- an honest user collects it too. Draining five times the reward is.

   Not every vulnerability makes the attacker richer. If the harm is that the protocol \
STOPS WORKING -- an unbounded loop, a queue anyone can grow, a state nobody can clear -- \
then no profit predicate can express it and you should use liveness_broken: give \
liveness_call, an abi.encodeWithSignature(...) for something an ordinary user can do, \
and the harness checks it succeeds before your attack and fails after.

   If the target requires msg.sender == tx.origin, no contract can call it; use \
mode='eoa'. If the value at stake is an ERC20 rather than ether, use token_profit. \
deploy_code can set up the world first -- fund the contract, have the owner airdrop to \
the attacker -- because setup is not part of the attack and the measurement starts after it.
5. Read the result honestly.
   - Passed: you have admissible evidence. Submit the finding, citing that exploit.
   - Compile error: fix it and rerun.
   - Failed: your attack did not work. Either the hypothesis was wrong -- try a \
genuinely different one -- or a guard stopped it, which is evidence the contract is \
sound on that axis.
6. When you have run out of hypotheses worth testing, call conclude_safe.

The bar is real attacker gain. "This function reverts", "this input is rejected", "a \
contract cannot call this" are not vulnerabilities -- they are the contract working. A \
vulnerability means someone ends up with value or authority they should not have.

Before the checklist, the failure mode that costs the most: fixating on reentrancy. It \
is the most famous class, it is the first thing that comes to mind for any function that \
makes an external call, and it is usually not the bug. Measured on real audits with this \
harness, seven of ten missed vulnerabilities had every single attempt reach for \
reentrancy while the actual defect was a comparison operator, a rounding direction, a \
missing deadline, a stale price source, or a missing replay guard. If your first two \
exploits along one line of attack fail, the line of attack is wrong -- change the \
mechanism, not the parameters.

The most productive question is usually not "what famous bug does this resemble" but \
"what does this function compute, and is that the right quantity". Read the arithmetic. \
Compare what a value is derived FROM against what it should be derived from: change \
computed from the sender's payment rather than the contract's balance, a price read from \
a checkpoint rather than live reserves, credits rounded up rather than down, an \
authorisation compared against msg.sender rather than tx.origin, a bound checked with \
>= where == was meant. Those are quiet one-token defects and they are what these \
contracts actually get wrong.

Techniques worth reaching for, because a hypothesis you never form is one you cannot \
test. This is a checklist of mechanisms, not a list of answers -- most will not apply, \
and the guards in front of them are what decide:

  * re-enter through any external call or ether transfer made before state is written;
  * force ether in with a self-destructing helper, or a plain transfer to a contract \
that assumes address(this).balance only moves through its own functions;
  * call a privileged function directly, and check who is actually allowed to;
  * ignore a return value the contract ignores -- a transfer that fails silently;
  * reach a branch where a bound, a slippage minimum, or a deadline is not checked;
  * move a price the contract reads from a spot source, then act on it in the same \
transaction;
  * replay a signature the contract does not bind to a nonce, a chain id, or a deadline, \
or exploit ecrecover returning address(0) on a malformed one;
  * be the first depositor and donate directly to inflate a share price;
  * exploit rounding that favours the caller, or a downcast that truncates a large value;
  * grow an array a loop iterates over until the loop cannot complete;
  * pass an address the contract delegatecalls into, or that it treats as a trusted \
module;
  * predict a value derived from block.timestamp, block.prevrandao or blockhash.

Attack skeletons. These are shapes, not answers -- the contract decides which, if any, \
applies, and the harness decides whether it worked. Most of your failures will be an \
attack that runs but extracts nothing, so getting the shape right matters more than \
getting the idea right.

  * *Re-entry.* Attacker's `receive()` calls back into the withdrawing function while a \
balance is still non-zero. Guard the recursion with a depth counter or it runs out of gas \
and you learn nothing.
  * *Forced ether.* `contract Bomb { constructor(address t) payable { selfdestruct(payable(t)); } }` \
then `new Bomb{value: 1 ether}(address(target))`. Use when a contract reasons about \
`address(this).balance`.
  * *First-depositor inflation.* Attacker deposits 1 wei, transfers assets straight to \
the contract to move the share price, the victim deposits and rounds down to zero shares, \
attacker redeems everything. Needs a victim deposit in the attack, not just its own.
  * *Rounding.* Loop the same small deposit/withdraw many times; a one-wei bias per \
iteration only becomes visible in aggregate. A single round trip will look like nothing.
  * *Price manipulation.* Swap hard against the pool to move the spot reading, act on the \
moved price, swap back. All inside one `attack()` so no block boundary intervenes.
  * *Signature replay.* Capture the digest and signature the contract accepts, then call \
again with the same bytes. `vm.store` can plant a signer if you need one you control.
  * *Access control.* Call the privileged function directly from the Attacker and see who \
`msg.sender` has to be. If the guard reads `tx.origin`, switch to `mode='eoa'`.
  * *Denial of service.* Grow the iterated structure until the honest operation runs out \
of gas, then use `liveness_broken` with `liveness_call` naming that operation.
  * *Truncation.* Feed a value just above the cast's range -- `uint128` overflows at \
`2**128`, `uint64` at `2**64` -- and check what the stored value becomes.

A worked run_exploit call, so the shape is unambiguous. Suppose the contract under audit \
is `LendingPool`, it holds ether, and you suspect repay() credits the borrower before \
taking the funds:

  deploy_code:   LendingPool target = new LendingPool{value: 20 ether}();
  honest_body:   target.deposit{value: 1 ether}(); target.withdraw(1 ether);
  predicate:     eth_profit
  attacker_code:
      contract Attacker {
          LendingPool p;
          bool looting;
          constructor(address _p) { p = LendingPool(payable(_p)); }
          function attack() external {
              p.deposit{value: 1 ether}();
              looting = true;
              p.withdraw(1 ether);
          }
          receive() external payable {
              if (looting && address(p).balance >= 1 ether) { p.withdraw(1 ether); }
          }
      }

Note what the harness does with that: it funds the Attacker, runs honest_body as a \
separate account to see what an ordinary depositor gets back, runs attack(), and only \
accepts the finding if the attacker came out strictly ahead of the honest depositor. You \
never write that comparison.

It also checks something you cannot talk it out of: **the value has to come out of the \
contract under audit**. Its holdings must fall by at least what you gained. This is the \
single most common way an exploit looks like it worked and proved nothing. The shape, \
measured on a real repository: the agent deployed a mock of a collaborator contract whose \
only behaviour was to hand out tokens on request, funded it, called it, and got tokens -- \
the contract under audit was never touched. Mocks exist to let the contract under audit \
RUN, not to be the source of the money. If your scenario needs a collaborator, make it \
behave the way the real one does, and make sure the assets at risk sit in the contract \
you are auditing.

The same applies to honest_body: it must be a real user getting a real result. If you \
send the honest user's proceeds to some other address, its gain is zero by construction \
and the comparison you passed was against nothing.

Three things that make run_exploit fail to compile, so check them before you call it: \
the attacker contract must be named exactly `Attacker` and take `constructor(address)`; \
the deployment must land in a variable named exactly `target`; and you must not write a \
pragma or any import, because the harness supplies both. If the contract's type needs a \
payable cast, write `Target(payable(addr))`.

Concluding that a contract is safe is a correct, expected, professional outcome. It is \
not a failure to find something. Reporting a vulnerability you could not demonstrate is \
the failure, because it costs a human reviewer real time to rediscover that it is not \
exploitable.

Do not call submit_finding on the strength of a recognised pattern. It will be rejected \
unless a PoC you ran actually passed.

Work efficiently. You have a limited number of turns. Prefer one well-constructed PoC \
over several careless ones.\
"""

USER_TEMPLATE = """\
Audit the contract at {location}.

It is {n_lines} lines. Here it is in full:

```solidity
{source}
```

Determine whether it contains an exploitable vulnerability. Prove it with a PoC that \
runs, or clear the contract with conclude_safe. Begin.\
"""

# Appended when the contract is being audited inside a real repository rather than as a
# standalone file. Everything here is a capability the agent has no way to discover on its
# own, and without it the failure looks like an exploit that will not compile -- which in
# the run record is indistinguishable from a contract that is genuinely safe.
REPO_BRIEF = """\

This contract is part of the repository `{repo}`, and it is compiled in that \
repository's own context: its imports resolve, its dependencies are present, and its \
sibling contracts are available to you.

That matters for building an exploit, because a real protocol is rarely exploitable \
through one file. Before you write `deploy_code`, find out how this contract is actually \
stood up:

  * `list_repo_files` with a pattern, to see what else is here -- factories, interfaces, \
tokens, mocks;
  * `read_repo_file` to read any of them;
  * `grep_repo` to find who deploys this contract, who calls the function you suspect, \
and where a role or an approval is granted.

A contract that takes constructor arguments, or that is only reachable through a factory, \
cannot be deployed with `new Target()` alone. Read the repository's own deployment or \
test code and reproduce it.

When your exploit needs a type that is not in scope -- an ERC20 interface, a factory, a \
mock -- pass it in the `imports` array of run_exploit. Use the SAME import string the \
repository's own files use, for example \
"@openzeppelin/contracts/token/ERC20/IERC20.sol"; those resolve here identically. Any \
other file in the repository is reachable as `arbiter-repo/<path from the repository \
root>`, exactly as `list_repo_files` prints it.\
"""

NUDGE_TO_EXPLOIT = """\
You have not attempted run_exploit yet. Nothing you have run so far can support a \
finding, because you chose its success condition. If you believe there is a \
vulnerability, prove it now with run_exploit: write an Attacker contract with \
constructor(address) and attack(), deploy the contract under audit into a variable \
named target, and pick eth_profit or state_change. If you do not believe there is one, \
call conclude_safe.\
"""

FORCE_DECISION = """\
You have one turn left. Decide now with the evidence you have: call submit_finding if a \
PoC of yours passed, otherwise call conclude_safe.\
"""


def audit(
    gateway: Gateway,
    workspace: Workspace,
    *,
    max_turns: int = 26,
    max_tokens: int = 4096,
    trace_sink: list[dict[str, Any]] | None = None,
    ruled_out: list[str] | None = None,
    proposals: str = "",
) -> AgentOutcome:
    """Run one audit to a terminal verdict. Returns the outcome.

    ``ruled_out`` carries the hypotheses that earlier independent attempts on this same
    contract already tested and failed. Without it the attempts are not just independent
    but amnesiac, and they converge: measured over ten missed samples, seven of them had
    every attempt reach for reentrancy regardless of the actual defect, several trying a
    single hypothesis across ten consecutive exploits. That is also why raising the
    attempt budget from three to five bought almost nothing -- it bought more runs of the
    same wrong idea.
    """
    dispatcher = ToolDispatcher(workspace)
    schemas = tool_schemas()
    plan = workspace.plan
    task = USER_TEMPLATE.format(
        location=(
            "src/Target.sol" if plan is None
            else plan.target.relative_to(plan.repo_root).as_posix()
        ),
        n_lines=len(workspace.lines),
        source=workspace.source,
    )
    if plan is not None:
        task += REPO_BRIEF.format(repo=plan.repo_root.name)
    if proposals:
        task += proposals
    if ruled_out:
        listed = "\n".join(f"  - {h}" for h in ruled_out[:12])
        task += (
            "\n\nIndependent earlier attempts on this exact contract already tested "
            "these hypotheses and FAILED to demonstrate any of them:\n"
            f"{listed}\n\n"
            "Do not retry them or minor variations of them. Whatever is wrong with this "
            "contract, it is something else. Read the code for what it actually does "
            "rather than for the shape of a familiar bug, and pick a different mechanism."
        )
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]

    nudged = False
    for turn in range(max_turns):
        remaining = max_turns - turn

        # Halfway through with no admissible evidence attempted is the signature of the
        # failure the pilot exposed: the agent settles into free-form probing, which can
        # never back a finding, and the turn budget runs out with nothing to show.
        if (
            not nudged
            and turn >= max_turns // 3
            and not dispatcher.has_tried_exploit
            and dispatcher.outcome.verdict == "no_verdict"
        ):
            nudged = True
            messages.append({"role": "user", "content": NUDGE_TO_EXPLOIT})

        if remaining == 1 and dispatcher.outcome.verdict == "no_verdict":
            messages.append({"role": "user", "content": FORCE_DECISION})

        message = gateway.chat(
            messages,
            max_tokens=max_tokens,
            tools=schemas,
            tag=f"{workspace.sample_id}:turn{turn}",
        )
        dispatcher.outcome.turns = turn + 1

        tool_calls = message.get("tool_calls") or []
        assistant_entry: dict[str, Any] = {
            "role": "assistant",
            "content": message.get("content") or "",
        }
        if tool_calls:
            assistant_entry["tool_calls"] = [
                {
                    "id": call.get("id") or f"call_{turn}_{i}",
                    "type": "function",
                    "function": {
                        "name": (call.get("function") or {}).get("name", ""),
                        "arguments": (call.get("function") or {}).get("arguments", "{}"),
                    },
                }
                for i, call in enumerate(tool_calls)
            ]
        messages.append(assistant_entry)

        if trace_sink is not None:
            trace_sink.append(
                {
                    "turn": turn,
                    "content": (message.get("content") or "")[:2000],
                    "finish_reason": message.get("_finish_reason"),
                    "tool_calls": [
                        {
                            "name": (c.get("function") or {}).get("name"),
                            "arguments": (c.get("function") or {}).get("arguments", "")[
                                :4000
                            ],
                        }
                        for c in tool_calls
                    ],
                }
            )

        if not tool_calls:
            # The model answered in prose. That is not a verdict; nudge it back to the
            # tool surface rather than trying to parse intent out of free text, which is
            # exactly the ambiguity this architecture exists to remove.
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "That was prose, not an action. Continue by calling a tool: "
                        "read_source, grep_source, run_poc, submit_finding or "
                        "conclude_safe."
                    ),
                }
            )
            continue

        terminal = False
        for i, call in enumerate(tool_calls):
            fn = call.get("function") or {}
            name = fn.get("name", "")
            args = parse_arguments(fn.get("arguments"))
            result, is_terminal = dispatcher.dispatch(name, args)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": assistant_entry["tool_calls"][i]["id"],
                    "content": result,
                }
            )
            terminal = terminal or is_terminal

        if terminal:
            return dispatcher.outcome

    if dispatcher.outcome.verdict == "no_verdict":
        dispatcher.outcome.stop_reason = "turn_budget_exhausted"
    return dispatcher.outcome


def outcome_to_label(outcome: AgentOutcome) -> str:
    """Map a terminal state to the binary label the scorer consumes.

    Pre-registered before the run, and symmetric across classes: a sample counts as
    positive only when the agent submitted a finding backed by an execution. Everything
    else -- an explicit safe verdict, an exhausted turn budget, a rejected submission --
    counts as negative, because in each of those cases the system did not report a
    vulnerability to its user.

    The rate of `no_verdict` is reported separately in every run summary so that this
    convention can be audited rather than taken on trust. It is not a free win: on a
    vulnerable sample the same rule produces a false negative.
    """
    return "vuln" if outcome.verdict == "vulnerable" else "safe"


def dump_messages(messages: list[dict[str, Any]]) -> str:
    return json.dumps(messages, ensure_ascii=False, indent=1)
