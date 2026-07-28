"""Batch candidate generation, executed in parallel. The minimum viable PLUMBLINE.

The recall arithmetic is the whole argument. The agentic loop reaches recall 0.424 with
two attempts, so its per-attempt success rate is 1 - (1 - 0.424)^(1/2) = 0.241. Recall is
therefore governed by the NUMBER of independent attempts, and turns are an absurdly
expensive way to buy them: 26 requests per attempt against a hard cap of 120 requests per
minute for the whole team.

Tokens are not scarce. The gateway allows 20,000,000 tokens per minute against 120
requests -- 166,667 tokens per request -- and the agentic loop spends a few thousand.
Cores are not scarce either; the box has 20 of them and the current design uses them to
run one forge invocation at a time.

So: ask for N candidate attacks in ONE request, and execute all N on idle cores. If the
candidates were fully independent at p = 0.241, eight of them would reach recall 0.87.
They are not independent -- one model, one context, one construction skill -- so the
honest expectation is lower, and measuring that correlation is the point of this module.

What the model emits is deliberately impoverished, because every previous version of this
gate was beaten by the model authoring something inside the judge's scope:

    attack_body      Solidity statements, spliced into Attacker.attack()
    on_receive_body  Solidity statements, spliced into Attacker.receive()
    honest_body      Solidity statements, spliced into the harness's control path

It emits no file, no setUp, no assertion, no actor address, no endowment, and no verdict.
The bodies land inside an Attacker compilation unit that declares no `Vm` and contains no
reference to the predicate, so cheatcode access is not forbidden by a rule -- it is absent
from the namespace. `guard_bytecode` is the backstop for anyone who materialises the
cheatcode address numerically.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gateway import Gateway
from .tools import _test_passed
from .workspace import Workspace

# The Foundry cheatcode precompile. A candidate that reaches this has escaped the
# namespace restriction and is rejected regardless of what it proved.
CHEATCODE_ADDR = "7109709ecfa91a80626ff3989d68f67f5b1dd12d"

CANDIDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "minItems": 4,
            "maxItems": 8,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["hypothesis", "deploy_code", "attack_body", "honest_body"],
                "properties": {
                    "hypothesis": {
                        "type": "string",
                        "description": "One sentence: what this attack extracts and how.",
                    },
                    "deploy_code": {
                        "type": "string",
                        "description": (
                            "Solidity statements creating the contract under audit in a "
                            "variable named exactly 'target', plus any scenario setup "
                            "(funding it, other users depositing). No cheatcodes."
                        ),
                    },
                    "attack_body": {
                        "type": "string",
                        "description": (
                            "Solidity statements for the body of Attacker.attack(). "
                            "The contract under audit is at the state variable 't'. "
                            "No pragma, no imports, no assertions, no cheatcodes."
                        ),
                    },
                    "on_receive_body": {
                        "type": "string",
                        "description": (
                            "Optional. Statements for Attacker.receive(), which runs "
                            "whenever the attacker is paid. Use for reentrancy. Guard "
                            "recursion with the provided 'depth' counter."
                        ),
                    },
                    "honest_body": {
                        "type": "string",
                        "description": (
                            "Solidity statements an ORDINARY user runs against 'target'. "
                            "The harness runs this as a separate funded account and your "
                            "attack must extract STRICTLY MORE than it does."
                        ),
                    },
                },
            },
        }
    },
}

SYSTEM = """\
You are a smart contract exploitation specialist. You are given one Solidity contract and \
you produce a BATCH of independent candidate attacks against it, in one reply.

This is not a conversation and there are no follow-up turns. Everything you emit is \
compiled and executed immediately, in parallel, on a real EVM. You will not see the \
results. So do not converge on one idea and refine it -- spread across genuinely \
DIFFERENT mechanisms, because the batch succeeds if ANY member succeeds and identical \
candidates are wasted slots.

For each candidate you supply only statement bodies. You do not write the test, the \
assertions, the accounts, or the success condition; the harness owns all of those. The \
harness measures whether your attacker ends up with strictly more value than an ordinary \
user of the same contract, so collecting a reward the contract grants by design does not \
count -- an ordinary user collects it too.

Mechanisms worth spreading across, when the code admits them: re-entering through an \
external call made before state is written; forcing ether in with a self-destructing \
helper; calling a privileged function directly to see who is actually allowed to; \
ignoring a return value the contract ignores; reaching a branch where a bound, a slippage \
minimum or a deadline is not checked; moving a price read from a spot source within one \
transaction; replaying a signature not bound to a nonce; being the first depositor and \
donating to inflate a share price; exploiting a rounding direction that favours the \
caller or a downcast that truncates; growing an array a loop must traverse.

The most productive question is rarely "what famous bug does this resemble" but "what \
does this function compute, and is that the right quantity". Read the arithmetic: change \
computed from the sender's payment rather than the contract's balance, a price from a \
checkpoint rather than live reserves, credits rounded up rather than down, >= where == \
was meant, msg.sender where tx.origin was meant.

Constraints on your Solidity, enforced mechanically:
- The contract under audit is reachable as the state variable `t` inside the attacker.
- No `pragma`, no `import`, no `assert`, no `require` on the outcome, no cheatcodes. None \
of those exist in the unit your code compiles into.
- `depth` is a uint256 state variable you may use to bound recursion in receive().
- deploy_code must assign the contract under audit to a local variable named `target`.
"""

USER = """\
Contract under audit, {n_lines} lines:

```solidity
{source}
```

Produce {k} independent candidate attacks. Spread them across different mechanisms and \
different functions. If you believe the contract is sound, still produce your {k} best \
attempts -- the harness decides, and a candidate that fails costs nothing.\
"""

# Harness-owned. The model's bodies are spliced into the marked holes and nowhere else.
# Note what is absent from this compilation unit: any `Vm` declaration, any assertion, and
# any reference to the predicate that will judge it.
ATTACKER_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import "../src/Target.sol";

contract Helper {{
    constructor(address payable to) payable {{ selfdestruct(to); }}
}}

contract Attacker {{
    address public t;
    uint256 public depth;

    constructor(address _t) payable {{ t = _t; }}

    function attack() external payable {{
{attack_body}
    }}

    receive() external payable {{
{on_receive_body}
    }}

    fallback() external payable {{}}
}}
"""

# Harness-owned judge. Lives in its own file; the model never sees or names it.
JUDGE_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import "../src/Target.sol";
import "./Attacker.sol";
import "./Vm.sol";

contract TestBroadside is Harness {{
    error NoGain(uint256 honest, uint256 attack);

    function testBroadside() public {{
        // ---- world for the honest control ----
        {deploy_code}
        address ctrl = address(uint160(uint256(keccak256("arbiter.control"))));
        vm.deal(ctrl, 10 ether);
        uint256 cPre = ctrl.balance;
        vm.startPrank(ctrl, ctrl);
{honest_body}
        vm.stopPrank();
        uint256 honestGain = ctrl.balance > cPre ? ctrl.balance - cPre : 0;

        // ---- same world, rebuilt, for the attacker ----
        {deploy_code2}
        Attacker atk = new Attacker{{value: 10 ether}}(address(target2));
        uint256 aPre = address(atk).balance;
        atk.attack();
        uint256 attackGain =
            address(atk).balance > aPre ? address(atk).balance - aPre : 0;

        if (attackGain <= honestGain) revert NoGain(honestGain, attackGain);
    }}
}}
"""


@dataclass
class Candidate:
    index: int
    hypothesis: str
    compiled: bool = False
    passed: bool = False
    rejected: str = ""
    output: str = ""


@dataclass
class BroadsideResult:
    verdict: str = "safe"
    candidates: list[Candidate] = field(default_factory=list)
    requests: int = 0
    error: str = ""

    @property
    def proven(self) -> bool:
        return any(c.passed and not c.rejected for c in self.candidates)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "proven": self.proven,
            "requests": self.requests,
            "error": self.error,
            "n_candidates": len(self.candidates),
            "n_compiled": sum(1 for c in self.candidates if c.compiled),
            "n_passed": sum(1 for c in self.candidates if c.passed),
            "n_rejected": sum(1 for c in self.candidates if c.rejected),
            "candidates": [
                {
                    "index": c.index,
                    "hypothesis": c.hypothesis[:200],
                    "compiled": c.compiled,
                    "passed": c.passed,
                    "rejected": c.rejected,
                    "output_tail": c.output[-600:],
                }
                for c in self.candidates
            ],
        }


def guard_bytecode(root: Path, name: str) -> str:
    """Reject a candidate whose compiled artifact embeds the cheatcode address.

    The model cannot name `vm` -- it is not in scope -- but it could in principle
    materialise the address numerically and call it. This is decidable: look for the
    20-byte constant in the compiled bytecode. Returns a rejection reason or "".
    """
    for artifact in root.glob(f"out/{name}.sol/*.json"):
        try:
            data = json.loads(artifact.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for key in ("bytecode", "deployedBytecode"):
            obj = data.get(key) or {}
            code = (obj.get("object") or "").lower()
            if CHEATCODE_ADDR in code:
                return "candidate embeds the cheatcode address in its bytecode"
    return ""


def _indent(text: str, spaces: int = 8) -> str:
    body = (text or "").strip()
    if not body:
        return " " * spaces + "// (empty)"
    return "\n".join(" " * spaces + line for line in body.splitlines())


def _sanitise(text: str) -> str:
    """Strip anything that belongs to the harness rather than to the model."""
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith(("pragma ", "import ", "//")):
            continue
        out.append(line)
    return "\n".join(out)


def run_candidate(
    ws_root: Path, sample_id: str, source: str, cand: dict[str, Any], index: int
) -> Candidate:
    """Compile and execute one candidate in its own scratch tree."""
    rec = Candidate(index=index, hypothesis=str(cand.get("hypothesis", "")))
    deploy = _sanitise(str(cand.get("deploy_code") or ""))
    if "target" not in deploy:
        rec.rejected = "deploy_code does not create a variable named 'target'"
        return rec

    ws = Workspace(ws_root, f"{sample_id}_c{index}", source)
    try:
        (ws.root / "test" / "Attacker.sol").write_text(
            ATTACKER_TEMPLATE.format(
                attack_body=_indent(_sanitise(str(cand.get("attack_body") or ""))),
                on_receive_body=_indent(
                    _sanitise(str(cand.get("on_receive_body") or ""))
                ),
            ),
            encoding="utf-8",
        )
        # The attacker's world is rebuilt from the same deploy_code, with the variable
        # renamed, so the honest control and the attacker face identical initial states.
        deploy2 = re.sub(r"\btarget\b", "target2", deploy)
        judge = JUDGE_TEMPLATE.format(
            deploy_code=_indent(deploy, 8).lstrip(),
            deploy_code2=_indent(deploy2, 8).lstrip(),
            honest_body=_indent(_sanitise(str(cand.get("honest_body") or ""))),
        )
        (ws.root / "test" / "Judge.t.sol").write_text(judge, encoding="utf-8")

        build = ws.build()
        rec.output = build.combined
        if not build.ok:
            return rec
        rec.compiled = True

        reason = guard_bytecode(ws.root, "Attacker")
        if reason:
            rec.rejected = reason
            return rec

        run = ws._forge(["test", "--match-path", "test/Judge.t.sol", "-vv"], timeout=180)
        rec.output = run.combined
        rec.passed = _test_passed(run)
        return rec
    finally:
        ws.cleanup()


def broadside_audit(
    gateway: Gateway,
    sample_id: str,
    source: str,
    ws_root: Path,
    *,
    k: int = 8,
    shards: int = 1,
    max_tokens: int = 16384,
    workers: int = 8,
) -> BroadsideResult:
    """One (or a few) generation requests, then every candidate executed in parallel."""
    result = BroadsideResult()
    cands: list[dict[str, Any]] = []

    for shard in range(shards):
        try:
            reply = gateway.chat(
                [
                    {"role": "system", "content": SYSTEM},
                    {
                        "role": "user",
                        "content": USER.format(
                            n_lines=len(source.splitlines()), source=source, k=k
                        ),
                    },
                ],
                max_tokens=max_tokens,
                temperature=0.0 if shards == 1 else 0.8,
                response_format={
                    "type": "json_schema",
                    "json_schema": {"name": "candidates", "schema": CANDIDATE_SCHEMA},
                },
                tag=f"broadside:{sample_id}:s{shard}",
            )
            result.requests += 1
            payload = json.loads(reply.get("content") or "{}")
            cands.extend(payload.get("candidates") or [])
        except Exception as exc:  # noqa: BLE001
            result.error = f"{type(exc).__name__}: {exc}"

    if not cands:
        result.error = result.error or "no candidates returned"
        return result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_candidate, ws_root, sample_id, source, c, i): i
            for i, c in enumerate(cands)
        }
        for fut in as_completed(futures):
            try:
                result.candidates.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                result.candidates.append(
                    Candidate(index=futures[fut], hypothesis="", rejected=str(exc)[:120])
                )

    result.candidates.sort(key=lambda c: c.index)
    result.verdict = "vulnerable" if result.proven else "safe"
    return result
