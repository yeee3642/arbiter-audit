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
4. Prove it with run_exploit. You write the attacker contract and the deployment; the \
harness writes the success condition and you cannot change it. It asks one of two \
questions: did the attacker end up with more ether than it was given, or did privileged \
state move when an unprivileged account acted. Use run_poc first if you need to probe \
behaviour cheaply, but understand that a passing run_poc is worth nothing as evidence -- \
you chose what it asserts, so all it can prove is that your own assertion is true.
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
Audit the contract at src/Target.sol.

It is {n_lines} lines. Here it is in full:

```solidity
{source}
```

Determine whether it contains an exploitable vulnerability. Prove it with a PoC that \
runs, or clear the contract with conclude_safe. Begin.\
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
    max_turns: int = 16,
    max_tokens: int = 4096,
    trace_sink: list[dict[str, Any]] | None = None,
) -> AgentOutcome:
    """Run one audit to a terminal verdict. Returns the outcome."""
    dispatcher = ToolDispatcher(workspace)
    schemas = tool_schemas()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": USER_TEMPLATE.format(
                n_lines=len(workspace.lines), source=workspace.source
            ),
        },
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
