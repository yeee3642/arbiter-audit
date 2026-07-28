"""The tool surface the auditor agent is given, and its deterministic dispatcher.

Two things about this file carry the argument against Bastet.

First, `submit_finding` is *gated*. It will not accept a finding unless the named PoC
has already been compiled and executed and the EVM agreed the exploit worked. The model
cannot talk its way past this; the gate is a dictionary lookup against results produced
by `forge`, in this process, from the agent's own code. A finding is therefore not an
assertion by a language model, it is a transcript of an execution.

Second, `conclude_safe` exists at all. Bastet's decision rule is
`any(detector_output != [])` over 56 detectors, so it has no representation for "this
code is fine" -- the only way it can emit a negative is for all 56 detectors to return
empty simultaneously. That is why its measured TN is 0 and why the arithmetic, not the
prompt quality, is the problem: even at a generous 5% per-detector false-positive rate,
1 - 0.95**53 = 0.934, so it would still flag 93% of safe files. Giving the agent an
explicit, first-class way to answer "no" is a precondition for ever scoring a true
negative.

Request economy: writing, compiling and running a PoC is a single tool because each
assistant turn costs one request against a 120 rpm cap, and separating them would triple
the turn count for no information gain.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .workspace import CommandResult, Workspace

MAX_TOOL_OUTPUT = 6000

# The taxonomy OneSavie's own dataset labels findings with -- 35 tags over 504 curated
# findings from real audit contests. Adopted verbatim rather than invented, because the
# comparison is only meaningful if both arms answer the same question, and the question
# that evaluation actually asks is "does this repository contain a finding tagged X".
# Bastet cannot answer it: its decision rule is `any(detector fired)` over 53 detectors
# with no class filter at all, so it returns the same 1 whatever tag is being scored.
VULN_CLASSES = (
    "Access Control", "Accounting Error", "Arithmetic", "Bad Randomness", "Bridge",
    "Chainlink", "Cross-Chain", "DAO", "DoS", "EIP712", "ERC1155", "ERC20", "ERC721",
    "ERC777", "ERC4626", "Flashloan", "Governance", "Input Validation", "Liquidation",
    "Logic error", "MEV", "Oracle", "Pause", "Replay Attack", "Reentrancy", "Slippage",
    "TWAP", "Uniswap", "Upgradeable", "call / delegatecall",
)


def tool_schemas() -> list[dict[str, Any]]:
    """OpenAI-style function schemas for the gateway's native tool calling."""
    return [
        {
            "type": "function",
            "function": {
                "name": "read_source",
                "description": (
                    "Read numbered lines of the contract under audit. Call with no "
                    "arguments to read the whole file."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep_source",
                "description": (
                    "Regex search the contract. Use it to establish which guards exist "
                    "before claiming one is missing, e.g. 'require|modifier|onlyOwner|"
                    "nonReentrant'."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"pattern": {"type": "string"}},
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_repo_files",
                "description": (
                    "List the Solidity files in the repository this contract belongs to, "
                    "optionally filtered by regex on the path. Use it to find the "
                    "factory that deploys the target, the token it holds, or the "
                    "interface its constructor takes -- an exploit against a real "
                    "protocol usually needs more than the file under audit."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex on the path, e.g. 'interfaces/|Factory'.",
                        }
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_repo_file",
                "description": (
                    "Read numbered lines of another file in the repository, by path "
                    "relative to the repository root as shown by list_repo_files."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep_repo",
                "description": (
                    "Regex search every Solidity file in the repository, returning "
                    "path:line matches. Use it to find who calls the vulnerable "
                    "function, where a role is granted, or how the protocol is wired."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"pattern": {"type": "string"}},
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_exploit",
                "description": (
                    "Run an adjudicated exploit. THIS IS THE ONLY EVIDENCE THAT CAN "
                    "BACK A FINDING. You supply the deployment and an attacker "
                    "contract; the harness writes the success condition itself and you "
                    "cannot change it. Requirements: (a) deploy_code must assign the "
                    "contract under audit to a local variable literally named 'target', "
                    "e.g. 'UtopiaVault target = new UtopiaVault{value: 10 ether}();'; "
                    "(b) attacker_code must define a contract literally named 'Attacker' "
                    "with 'constructor(address)' and a function 'attack() external'; it "
                    "may also define helper contracts and a receive() function. "
                    "IMPORTANT: if the target guards with require(msg.sender == "
                    "tx.origin), a contract attacker is impossible -- set mode='eoa' "
                    "instead and supply attack_body, plain Solidity statements that the "
                    "harness runs from a real externally owned account under "
                    "vm.startPrank(eoa, eoa), operating on the variable 'target'. "
                    "deploy_code may also set up scenario state (fund the contract, "
                    "have the owner airdrop to eoa) before the measurement starts. "
                    "Every profit predicate is DIFFERENTIAL: you must also give "
                    "honest_body, the intended happy path, and your attack has to beat "
                    "it strictly. Collecting a reward the contract grants by design is "
                    "not an exploit. "
                    "Predicates: eth_profit (attacker ends up with more ether), "
                    "token_profit (attacker's balance of the token named by token_expr "
                    "goes up -- use this whenever the value stolen is an ERC20), or "
                    "state_change (state that an honest user cannot move, moved by an "
                    "unprivileged account), or liveness_broken (an operation an "
                    "ordinary user could complete stops working after your attack -- "
                    "use this for denial of service, where the attacker gains nothing). "
                    "Every predicate is differential."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "deploy_code": {
                            "type": "string",
                            "description": (
                                "Solidity statements that create the contract under "
                                "audit in a variable named 'target'."
                            ),
                        },
                        "attacker_code": {
                            "type": "string",
                            "description": (
                                "Full source of a contract named 'Attacker' with "
                                "constructor(address) and attack() external. No pragma "
                                "and no imports -- the harness supplies both."
                            ),
                        },
                        "predicate": {
                            "type": "string",
                            "enum": ["victim_loss", "eth_profit", "token_profit",
                                     "state_change", "liveness_broken"],
                        },
                        "victim_enter": {
                            "type": "string",
                            "description": (
                                "For victim_loss. What an ordinary user does to take a "
                                "position, e.g. 'target.deposit{value: 2 ether}();'. Run "
                                "by a harness-owned account, in BOTH trials."
                            ),
                        },
                        "victim_exit": {
                            "type": "string",
                            "description": (
                                "For victim_loss. What that same user does to get their "
                                "money back, e.g. 'target.withdraw();'. The harness runs "
                                "the whole scenario twice, once with your attack in "
                                "between and once without, and admits the finding only "
                                "if your attack is what stopped them getting it out."
                            ),
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["contract", "eoa"],
                            "description": (
                                "contract: you supply attacker_code. eoa: you supply "
                                "attack_body and the calls come from a real EOA, which "
                                "is the only way past a tx.origin check."
                            ),
                        },
                        "attack_body": {
                            "type": "string",
                            "description": (
                                "For mode='eoa'. Solidity statements run as the "
                                "attacker EOA, e.g. 'target.redeem(1000e9);'"
                            ),
                        },
                        "honest_body": {
                            "type": "string",
                            "description": (
                                "REQUIRED for every predicate. Solidity "
                                "statements an ordinary, non-attacking user would run "
                                "against 'target' -- the intended happy path, e.g. "
                                "'target.claim(); target.withdraw();'. The harness runs "
                                "this first as a separate funded account. For a profit "
                                "predicate your exploit must produce STRICTLY MORE gain "
                                "than it does; for state_change, the getter you name must "
                                "be UNMOVED by the honest path, which is how the harness "
                                "checks the state really is privileged. "
                                "This is why merely collecting a reward the contract "
                                "hands out by design does not count as an exploit."
                            ),
                        },
                        "liveness_call": {
                            "type": "string",
                            "description": (
                                "For liveness_broken (denial of service). An "
                                "abi.encodeWithSignature(...) expression for an "
                                "operation an ordinary user can complete, e.g. "
                                "abi.encodeWithSignature(\"claim()\"). The harness "
                                "checks it SUCCEEDS before your attack and FAILS after."
                            ),
                        },
                        "token_expr": {
                            "type": "string",
                            "description": (
                                "For token_profit. A Solidity expression for the token "
                                "whose balance should rise, e.g. 'address(usdg)' -- it "
                                "must be in scope from deploy_code."
                            ),
                        },
                        "observed_getter": {
                            "type": "string",
                            "description": (
                                "Required for state_change. A zero-argument public view "
                                "function with its signature, e.g. 'owner()' or "
                                "'totalSupply()'."
                            ),
                        },
                        "imports": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Extra files your exploit needs in scope. Use the SAME "
                                "import strings the repository's own files use, e.g. "
                                "'@openzeppelin/contracts/token/ERC20/IERC20.sol' -- they "
                                "resolve identically here. Any other file in the "
                                "repository is reachable as "
                                "'arbiter-repo/<path from the repository root>'. Needed "
                                "because a named import in the target does not put that "
                                "type in scope for your exploit."
                            ),
                        },
                        "hypothesis": {"type": "string"},
                    },
                    "required": ["name", "deploy_code", "predicate", "hypothesis"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_poc",
                "description": (
                    "EXPLORATION ONLY -- a passing run_poc cannot back a finding, "
                    "because you write its success condition yourself. Use it to probe "
                    "behaviour, confirm how a function reacts, or check an assumption "
                    "cheaply; then prove the actual exploit with run_exploit. "
                    "Write a Solidity proof-of-concept, compile it, and execute it "
                    "against the contract under audit on a real EVM. The contract under "
                    "audit is at src/Target.sol and you import it with "
                    "'import \"../src/Target.sol\";'. Foundry cheatcodes are available "
                    "with 'import \"./Vm.sol\";' and inheriting Harness, which gives you "
                    "vm.prank, vm.deal, vm.warp, vm.store and assertTrue. Your test "
                    "contract already holds a large ether balance, so you can fund the "
                    "target at construction. Name the test contract with a "
                    "'Test' prefix and the exploit function with a 'test' prefix. "
                    "Write the test so that IT PASSES ONLY IF THE EXPLOIT SUCCEEDS: end "
                    "it with require(...) on the post-exploit state, for example "
                    "require(address(attacker).balance > deposited, 'no drain'). "
                    "If the code is actually safe, a correct PoC will FAIL, and that "
                    "failure is the evidence you needed. Returns compiler errors and "
                    "the full execution trace; iterate on them."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Short identifier, letters and digits only.",
                        },
                        "solidity": {
                            "type": "string",
                            "description": (
                                "Complete Solidity source for the test file, including "
                                "the pragma and the import of ../src/Target.sol."
                            ),
                        },
                        "hypothesis": {
                            "type": "string",
                            "description": (
                                "What this PoC proves if it passes, in one sentence."
                            ),
                        },
                    },
                    "required": ["name", "solidity", "hypothesis"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_finding",
                "description": (
                    "Report a confirmed vulnerability. REJECTED unless poc_name refers "
                    "to a run_exploit that PASSED. A free-form run_poc is exploration "
                    "and can never back a finding, because you wrote its success "
                    "condition yourself. Do not call this on the strength of a "
                    "recognised pattern; the pattern is not the bug."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "poc_name": {
                            "type": "string",
                            "description": "Name of the PoC that passed.",
                        },
                        "title": {"type": "string"},
                        "vulnerable_function": {"type": "string"},
                        "offending_expression": {
                            "type": "string",
                            "description": (
                                "Copied character-for-character from src/Target.sol. "
                                "Checked verbatim; an invented expression is rejected."
                            ),
                        },
                        "attack_path": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "vuln_class": {
                            "type": "string",
                            "enum": list(VULN_CLASSES),
                            "description": (
                                "Which class of defect this is. Required because the "
                                "question a user actually asks is 'does this code have a "
                                "bug of kind X', and a report that cannot name the kind "
                                "cannot answer it."
                            ),
                        },
                    },
                    "required": [
                        "poc_name",
                        "title",
                        "vulnerable_function",
                        "offending_expression",
                        "attack_path",
                        "severity",
                        "vuln_class",
                    ],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "conclude_safe",
                "description": (
                    "Conclude that the contract has no exploitable vulnerability you "
                    "could demonstrate. This is a legitimate and expected answer. Use it "
                    "when your PoCs failed because a guard stopped them -- that is "
                    "evidence of safety, not a failure on your part."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "reason": {"type": "string"},
                        "guards_verified": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Each guard quoted verbatim from the source. Checked."
                            ),
                        },
                        "hypotheses_tested": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "What you tried to exploit and why it failed.",
                        },
                    },
                    "required": ["reason", "guards_verified", "hypotheses_tested"],
                },
            },
        },
    ]


@dataclass
class PocRecord:
    name: str
    hypothesis: str
    solidity: str
    compiled: bool
    passed: bool
    output: str
    # True only when the success condition was written by the harness rather than by
    # the agent. Findings may cite these and nothing else.
    adjudicated: bool = False
    predicate: str = ""
    # Set when the evidence came from the harness's environment sweep rather than from
    # the environment the agent first chose. Never inferred: if this is present, the
    # exploit needed a scale the agent did not pick, and the record says so.
    sweep: dict[str, Any] | None = None


@dataclass
class AgentOutcome:
    """Terminal state of one audit. `verdict` is what gets scored."""

    verdict: str = "no_verdict"  # vulnerable | safe | no_verdict
    findings: list[dict[str, Any]] = field(default_factory=list)
    safe_reason: dict[str, Any] | None = None
    pocs: list[PocRecord] = field(default_factory=list)
    rejected_submissions: list[dict[str, Any]] = field(default_factory=list)
    turns: int = 0
    stop_reason: str = ""

    @property
    def proven(self) -> bool:
        """True when the vulnerable verdict is backed by a harness-adjudicated exploit.

        `adjudicated` is the whole point: a passing test whose assertion the agent chose
        proves only that the assertion is true, which is how an earlier revision was
        talked into a false positive on patched code.
        """
        return self.verdict == "vulnerable" and any(
            p.passed and p.adjudicated for p in self.pocs
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "proven": self.proven,
            "turns": self.turns,
            "stop_reason": self.stop_reason,
            "findings": self.findings,
            "safe_reason": self.safe_reason,
            "rejected_submissions": self.rejected_submissions,
            "pocs": [
                {
                    "name": p.name,
                    "hypothesis": p.hypothesis,
                    "compiled": p.compiled,
                    "passed": p.passed,
                    "adjudicated": p.adjudicated,
                    "predicate": p.predicate,
                    "sweep": p.sweep,
                    "output_tail": p.output[-1200:],
                    "solidity": p.solidity,
                }
                for p in self.pocs
            ],
        }


class ToolDispatcher:
    """Executes tool calls against one workspace and accumulates the outcome."""

    # Free-form probes allowed before the tool is withdrawn. The first pilot showed why
    # a cap is needed: on three of five samples the agent spent all sixteen turns in
    # run_poc, re-running a near-identical probe up to thirteen times, and never once
    # called run_exploit -- so it finished with no admissible evidence and the sample
    # scored negative. Exploration is useful; unbounded exploration is how the run dies.
    MAX_FREEFORM_POCS = 3

    # Repository navigation before the first exploit attempt. Giving the agent the rest
    # of the repository was necessary -- a protocol is not exploitable through one file --
    # but it is also the most inviting way to spend a turn, and turns are the budget.
    # Measured on the first in-repo run: 41 navigation calls, 0 exploit attempts, three
    # samples burning 52 requests each to reach a verdict by reading alone. Reading is not
    # evidence here; only execution is. The cap does not remove the tools, it stops them
    # being an alternative to using the EVM.
    MAX_RECON_BEFORE_EXPLOIT = 10

    def __init__(self, workspace: Workspace) -> None:
        self.ws = workspace
        self.outcome = AgentOutcome()
        self._poc_by_name: dict[str, PocRecord] = {}
        self._freeform_calls = 0
        self._exploit_calls = 0
        self._recon_calls = 0
        self._refused_safe = False
        self._hypotheses: list[str] = []

    @property
    def has_tried_exploit(self) -> bool:
        return self._exploit_calls > 0

    def dispatch(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Run one tool. Returns (result_text, is_terminal)."""
        handler = {
            "read_source": self._read_source,
            "grep_source": self._grep_source,
            "list_repo_files": self._list_repo_files,
            "read_repo_file": self._read_repo_file,
            "grep_repo": self._grep_repo,
            "run_poc": self._run_poc,
            "run_exploit": self._run_exploit,
            "submit_finding": self._submit_finding,
            "conclude_safe": self._conclude_safe,
        }.get(name)
        if handler is None:
            return f"error: no such tool {name!r}", False
        try:
            result = handler(arguments)
        except Exception as exc:  # noqa: BLE001 - a tool crash must not kill the run
            return f"error: tool {name} raised {type(exc).__name__}: {exc}", False
        # A handler that returns a bare string unpacks into characters at the call site
        # and takes the whole audit down with a ValueError. That cost one sample and two
        # attempts before it was noticed, so the shape is normalised here rather than
        # trusted at each of the dozen return statements.
        if isinstance(result, tuple) and len(result) == 2:
            return result
        return str(result), False

    # -- read-only tools, zero cost -----------------------------------------

    def _read_source(self, args: dict[str, Any]) -> tuple[str, bool]:
        start = int(args.get("start_line") or 1)
        end = args.get("end_line")
        return self.ws.read(start, int(end) if end else None)[:MAX_TOOL_OUTPUT], False

    def _grep_source(self, args: dict[str, Any]) -> tuple[str, bool]:
        return self.ws.grep(str(args.get("pattern", "")))[:MAX_TOOL_OUTPUT], False

    def _recon_budget(self) -> str:
        """Empty while reconnaissance is affordable; a refusal once it is not."""
        if self._exploit_calls:
            return ""
        self._recon_calls += 1
        if self._recon_calls <= self.MAX_RECON_BEFORE_EXPLOIT:
            return ""
        return (
            f"Repository reconnaissance is CLOSED: you have used all "
            f"{self.MAX_RECON_BEFORE_EXPLOIT} reads without attempting a single "
            "exploit. Reading is not evidence here -- only an execution is, and every "
            "turn you spend reading is a turn you cannot spend building. Call "
            "run_exploit with the best hypothesis you have now, even if you are not "
            "certain of it; a failed exploit tells you more than another file will. "
            "If you genuinely have no hypothesis, call conclude_safe. Reconnaissance "
            "reopens once you have made an attempt."
        )

    def _list_repo_files(self, args: dict[str, Any]) -> tuple[str, bool]:
        refusal = self._recon_budget()
        if refusal:
            return refusal, False
        return self.ws.repo_files(str(args.get("pattern") or ""))[:MAX_TOOL_OUTPUT], False

    def _read_repo_file(self, args: dict[str, Any]) -> tuple[str, bool]:
        refusal = self._recon_budget()
        if refusal:
            return refusal, False
        end = args.get("end_line")
        return (
            self.ws.read_repo(
                str(args.get("path") or ""),
                int(args.get("start_line") or 1),
                int(end) if end else None,
            )[:MAX_TOOL_OUTPUT],
            False,
        )

    def _grep_repo(self, args: dict[str, Any]) -> tuple[str, bool]:
        refusal = self._recon_budget()
        if refusal:
            return refusal, False
        return self.ws.grep_repo(str(args.get("pattern") or ""))[:MAX_TOOL_OUTPUT], False

    # -- the execution tool --------------------------------------------------

    def _run_poc(self, args: dict[str, Any]) -> tuple[str, bool]:
        raw_name = str(args.get("name") or "poc")
        solidity = str(args.get("solidity") or "")
        hypothesis = str(args.get("hypothesis") or "")
        if not solidity.strip():
            return "error: solidity source was empty", False

        self._freeform_calls += 1
        if self._freeform_calls > self.MAX_FREEFORM_POCS:
            return (
                f"run_poc is now CLOSED for this audit; you have used all "
                f"{self.MAX_FREEFORM_POCS} exploratory probes. Nothing it returns could "
                "back a finding anyway, because you write its success condition. "
                "Use run_exploit to prove the attack, or conclude_safe if you have "
                "none left to try.",
                False,
            )

        name = self.ws.write_poc(raw_name, solidity)
        build = self.ws.build()
        if not build.ok:
            record = PocRecord(name, hypothesis, solidity, False, False, build.combined)
            self._poc_by_name[name] = record
            self.outcome.pocs.append(record)
            return (
                "COMPILATION FAILED. The PoC does not build. Fix the Solidity and call "
                "run_poc again.\n\n" + _tail(build.combined),
                False,
            )

        run = self.ws.run_poc(name)
        passed = _test_passed(run)
        record = PocRecord(name, hypothesis, solidity, True, passed, run.combined)
        self._poc_by_name[name] = record
        self.outcome.pocs.append(record)

        if passed:
            head = (
                f"PoC {name!r} COMPILED AND PASSED. The exploit executed successfully "
                "on the EVM. You may now call submit_finding citing this poc_name.\n\n"
            )
        else:
            head = (
                f"PoC {name!r} compiled but FAILED. The exploit did not work against "
                "this code. Either your attack was wrong -- in which case try a "
                "different hypothesis -- or a guard genuinely prevents it, in which "
                "case that is evidence the contract is safe and you should say so with "
                "conclude_safe.\n\n"
            )
        return head + _tail(run.combined), False

    def _run_exploit(self, args: dict[str, Any]) -> tuple[str, bool]:
        """Compile and run an exploit whose success condition the harness owns."""
        raw_name = str(args.get("name") or "exploit")
        predicate = str(args.get("predicate") or "eth_profit")
        hypothesis = str(args.get("hypothesis") or "")
        attacker_code = str(args.get("attacker_code") or "")
        deploy_code = str(args.get("deploy_code") or "")
        self._exploit_calls += 1

        # Repeating a hypothesis verbatim is the failure mode that ate three of five
        # pilot audits. Say so rather than silently running it again.
        squashed = re.sub(r"\s+", " ", hypothesis.strip().lower())[:120]
        repeated = squashed and squashed in self._hypotheses
        self._hypotheses.append(squashed)

        mode = str(args.get("mode") or ("eoa" if args.get("attack_body") else "contract"))
        attack_body = str(args.get("attack_body") or "")

        if mode == "contract" and "contract Attacker" not in attacker_code:
            return (
                "error: mode='contract' needs attacker_code defining a contract named "
                "exactly 'Attacker'. If the target requires msg.sender == tx.origin, "
                "use mode='eoa' with attack_body instead.",
                False,
            )
        if mode == "eoa" and not attack_body.strip():
            return "error: mode='eoa' needs attack_body statements.", False
        if "target" not in deploy_code:
            return (
                "error: deploy_code must assign the contract under audit to a variable "
                "named exactly 'target'.",
                False,
            )

        try:
            if predicate == "victim_loss":
                solidity = self.ws.compose_victim_loss(
                    deploy_code=deploy_code,
                    victim_enter=str(args.get("victim_enter") or ""),
                    victim_exit=str(args.get("victim_exit") or ""),
                    attacker_code=attacker_code,
                    attack_body=attack_body,
                    mode=mode,
                    token_expr=str(args.get("token_expr") or ""),
                    extra_imports=[str(x) for x in (args.get("imports") or [])],
                )
                return self._finish_exploit(
                    raw_name, solidity, hypothesis, predicate, repeated, sweep=False
                )
            solidity = self.ws.compose_exploit(
                deploy_code=deploy_code,
                attacker_code=attacker_code,
                predicate=predicate,
                observed_getter=str(args.get("observed_getter") or ""),
                token_expr=str(args.get("token_expr") or ""),
                liveness_call=str(args.get("liveness_call") or ""),
                attack_body=attack_body,
                honest_body=str(args.get("honest_body") or ""),
                mode=mode,
                extra_imports=[str(x) for x in (args.get("imports") or [])],
            )
        except ValueError as exc:
            return f"error: {exc}", False

        name = self.ws.write_poc(f"{raw_name}Exploit", solidity)
        build = self.ws.build()
        if not build.ok:
            record = PocRecord(
                name, hypothesis, solidity, False, False, build.combined,
                adjudicated=True, predicate=predicate,
            )
            self._poc_by_name[name] = record
            self.outcome.pocs.append(record)
            # Show the composed file, numbered. The agent supplies fragments and the
            # harness assembles them, so solc's line numbers refer to a file the agent
            # has never seen -- without this it is debugging blind, and repeated compile
            # failures were the single largest cause of missed vulnerable samples.
            listing = "\n".join(
                f"{i:>3}| {line}" for i, line in enumerate(solidity.splitlines(), 1)
            )
            return (
                "COMPILATION FAILED. Below is the COMPLETE file the harness assembled "
                "from your fragments -- the compiler's line numbers refer to this, not "
                "to what you sent. Read the error, find that line here, and call "
                "run_exploit again with corrected fragments. Do not add a pragma, an "
                "import, or a success check; the harness owns those lines.\n\n"
                "----- composed exploit -----\n" + listing[:7000] +
                "\n----- compiler output -----\n" + _tail(build.combined),
                False,
            )

        run = self.ws.run_poc(name)
        passed = _test_passed(run)
        caused = ""
        if passed:
            survives, caused = self._negation_holds(name, solidity)
            passed = survives
        record = PocRecord(
            name, hypothesis, solidity, True, passed, run.combined,
            adjudicated=True, predicate=predicate,
        )
        self._poc_by_name[name] = record
        self.outcome.pocs.append(record)

        if caused:
            return (
                f"EXPLOIT {name!r} satisfied {predicate!r}, but it is REFUSED: {caused}",
                False,
            )
        if passed:
            head = (
                f"EXPLOIT {name!r} PASSED the harness predicate {predicate!r}, and fails "
                "when the attack is removed, so the attack is what caused it. This is "
                "admissible evidence. Call submit_finding citing this name.\n\n"
            )
        elif predicate in ("eth_profit", "token_profit"):
            # An exploit that compiles, runs and extracts nothing is usually the right
            # mechanism at the wrong magnitude. The environment it failed in was never
            # the agent's to choose -- the endowment, the clock and the number of rounds
            # are the harness's -- so before charging the failure to the hypothesis, the
            # harness re-runs the agent's own attack across those three axes. One compile,
            # no gateway requests, and the knobs move for the honest baseline too, so a
            # sweep can only surface an asymmetry that was already present.
            swept = self._sweep(raw_name, args, predicate, hypothesis, mode)
            if swept is not None:
                return swept
            head = _EXPLOIT_FAILED_HEAD.format(name=name, predicate=predicate)
            if repeated:
                head += _REPEATED_HYPOTHESIS
            return head + _tail(run.combined), False
        else:
            head = (
                f"EXPLOIT {name!r} compiled but did NOT satisfy {predicate!r} (fallback). The "
                "attacker gained nothing, or the state you named did not move. Either "
                "the attack is wrong, or the contract genuinely resists it. Look at the "
                "revert reason.\n"
                "  'ArbiterNoGain(honestGain, attackGain)' -- the two numbers are what "
                "an honest user extracted and what your attack extracted, in wei or "
                "token units. Read them. If attackGain is 0 your attack extracted "
                "nothing and the hypothesis is wrong. If attackGain is large but "
                "honestGain is as large or larger, the attack works and your "
                "honest_body is too generous: it must be the MINIMAL intended use, not "
                "a maximal one. If they are equal, you reproduced the happy path.\n"
                "  'ordinary use already moves this state' -- the getter you chose is "
                "not privileged, because honest_body moved it too. Pick state only an "
                "authorised party should be able to change, such as an owner or a role.\n"
                "  'privileged state did not change' -- the attack left it alone.\n"
                "  anything else -- the target reverted, so a guard stopped you.\n"
                "A guard stopping you is evidence of safety, not a failure on your "
                "part.\n\n"
            )
            if repeated:
                head += (
                    "NOTE: you have already tested this exact hypothesis and it failed. "
                    "Repeating it will not change the result. Attack a different "
                    "function or a different invariant, or call conclude_safe.\n\n"
                )
        return head + _tail(run.combined), False

    def _finish_exploit(
        self,
        raw_name: str,
        solidity: str,
        hypothesis: str,
        predicate: str,
        repeated: bool,
        sweep: bool,
    ) -> tuple[str, bool]:
        """Compile, run and record an adjudicated exploit with no environment sweep.

        The victim-loss predicate runs its own two trials, so there is nothing for the
        sweep to add and the failure text has to name the quantities IT reports.
        """
        name = self.ws.write_poc(f"{raw_name}Exploit", solidity)
        build = self.ws.build()
        if not build.ok:
            record = PocRecord(name, hypothesis, solidity, False, False, build.combined,
                               adjudicated=True, predicate=predicate)
            self._poc_by_name[name] = record
            self.outcome.pocs.append(record)
            listing = "\n".join(
                f"{i:>3}| {line}" for i, line in enumerate(solidity.splitlines(), 1)
            )
            return (
                "COMPILATION FAILED. Below is the COMPLETE file the harness assembled "
                "from your fragments -- the compiler's line numbers refer to this.\n\n"
                "----- composed exploit -----\n" + listing[:7000] +
                "\n----- compiler output -----\n" + _tail(build.combined),
                False,
            )
        run = self.ws.run_poc(name)
        passed = _test_passed(run)
        caused = ""
        if passed:
            survives, caused = self._negation_holds(name, solidity)
            passed = survives
        record = PocRecord(name, hypothesis, solidity, True, passed, run.combined,
                           adjudicated=True, predicate=predicate)
        self._poc_by_name[name] = record
        self.outcome.pocs.append(record)
        if caused:
            return (
                f"EXPLOIT {name!r} satisfied {predicate!r}, but it is REFUSED: {caused}",
                False,
            )
        if passed:
            return (
                f"EXPLOIT {name!r} PASSED the harness predicate {predicate!r}. The victim "
                "recovered strictly less because your attack ran, and the attacker came "
                "out ahead. This is admissible evidence; call submit_finding citing this "
                "name.\n\n" + _tail(run.combined),
                False,
            )
        head = (
            f"EXPLOIT {name!r} compiled but did NOT satisfy {predicate!r}.\n"
            "  'ArbiterNoHarm(withoutAttack, withAttack, attackerGain)' -- the first two "
            "numbers are what an ordinary user got back when nobody attacked and when you "
            "did. If they are EQUAL, your attack cost that user nothing, so whatever it "
            "extracted was not theirs; taking a donation out of a contract is not a "
            "vulnerability in it. If attackerGain is 0 the attack extracted nothing.\n"
            "  'the victim gets nothing back even with no attack' -- victim_enter and "
            "victim_exit do not work as an ordinary round trip, so no harm can be shown. "
            "Fix them first.\n"
            "  'the attack itself reverted' -- a guard stopped you, which is evidence of "
            "safety.\n\n"
        )
        if repeated:
            head += _REPEATED_HYPOTHESIS
        return head + _tail(run.combined), False

    def _negation_holds(self, name: str, solidity: str) -> tuple[bool, str]:
        """Does the predicate still hold with the attack deleted?

        The decisive check, and the cheapest one: a real exploit must FAIL when the attack
        is taken out. If it passes anyway, whatever satisfied the predicate was not the
        attack -- ether forced in during setup, a transaction that halted early, profit
        drawn from scenery the agent built. Auditing this project's own accepted proofs
        found two of that shape, and nothing at the time could see them.

        Returns (the proof survives, an explanation when it does not). One compile and one
        run, no gateway request.
        """
        neutered, found = self.ws.neuter(solidity)
        if not found:
            return True, ""
        probe = self.ws.write_poc(f"{name}Negated", neutered)
        if not self.ws.build().ok:
            return True, ""      # cannot check; do not punish the agent for that
        still = _test_passed(self.ws.run_poc(probe))
        self.ws.write_poc(name, solidity)   # restore, so the proof is what is on disk
        if not still:
            return True, ""
        return False, (
            "the predicate is ALSO satisfied when your attack is deleted, so it was not "
            "your attack that satisfied it. Something in the setup did -- ether forced "
            "into the target, a contract you funded, a transaction that ended early. "
            "Rebuild the scenario so that removing the attack removes the effect."
        )

    def _sweep(
        self,
        raw_name: str,
        args: dict[str, Any],
        predicate: str,
        hypothesis: str,
        mode: str,
    ) -> tuple[str, bool] | None:
        """Retry the agent's attack across endowment, repetition and elapsed time.

        Returns a tool result if some variant satisfied the predicate, otherwise None so
        the caller reports the original failure. Recorded as its own PoC with the winning
        variant named, so a reader can always see that the evidence came from a swept
        environment rather than the one the agent first chose.
        """
        try:
            solidity, grid = self.ws.compose_sweep(
                deploy_code=str(args.get("deploy_code") or ""),
                attacker_code=str(args.get("attacker_code") or ""),
                predicate=predicate,
                token_expr=str(args.get("token_expr") or ""),
                attack_body=str(args.get("attack_body") or ""),
                honest_body=str(args.get("honest_body") or ""),
                mode=mode,
                extra_imports=[str(x) for x in (args.get("imports") or [])],
            )
        except ValueError:
            return None

        name = self.ws.write_poc(f"{raw_name}Sweep", solidity)
        if not self.ws.build().ok:
            return None
        run = self.ws.run_poc(name)
        winners = self.ws.passing_sweep_variants(run.combined)
        if not winners:
            return None

        endow, repeats, warp = grid[winners[0]]
        record = PocRecord(
            name, hypothesis, solidity, True, True, run.combined,
            adjudicated=True, predicate=predicate,
        )
        record.sweep = {"variant": winners[0], "endowment_wei": endow,
                        "repetitions": repeats, "warp_seconds": warp,
                        "variants_passed": winners, "variants_tried": len(grid)}
        self._poc_by_name[name] = record
        self.outcome.pocs.append(record)
        return (
            f"EXPLOIT {name!r} PASSED the harness predicate {predicate!r}.\n\n"
            "Your attack was right in mechanism and wrong in scale. It extracted nothing "
            "in the default environment, so the harness re-ran it -- unchanged -- across "
            "twelve environments, with the same endowment, the same number of rounds and "
            f"the same elapsed time given to the honest baseline. It succeeded in "
            f"{len(winners)} of {len(grid)}: the first was an endowment of {endow} wei, "
            f"{repeats} repetition(s), {warp}s elapsed.\n\n"
            "This is admissible evidence. Call submit_finding citing this name, and say "
            "in attack_path what scale the attack needs to be worth running.\n\n"
        ) + _tail(run.combined), False

    # -- terminal tools ------------------------------------------------------

    def _submit_finding(self, args: dict[str, Any]) -> tuple[str, bool]:
        poc_name = str(args.get("poc_name") or "")
        record = self._poc_by_name.get(poc_name)

        # Try a forgiving match: the model sometimes cites the name it asked for rather
        # than the sanitised name it got back. This is leniency toward our own arm, but
        # it only ever helps a finding that a passing execution already backs.
        if record is None:
            for key, value in self._poc_by_name.items():
                if key.lower().startswith(poc_name.lower().replace("poc", "").strip()):
                    record, poc_name = value, key
                    break

        if record is None:
            reason = f"no PoC named {args.get('poc_name')!r} has been run"
        elif not record.adjudicated:
            reason = (
                f"{poc_name!r} is a free-form run_poc, not a run_exploit. You wrote its "
                "success condition yourself, so it proves only that an assertion you "
                "chose is true. Reproduce the attack with run_exploit"
            )
        elif not record.compiled:
            reason = f"PoC {poc_name!r} never compiled"
        elif not record.passed:
            reason = (
                f"PoC {poc_name!r} ran but FAILED, so the exploit was not demonstrated"
            )
        elif not self.ws.contains_verbatim(str(args.get("offending_expression") or "")):
            reason = (
                "offending_expression does not appear verbatim in src/Target.sol"
            )
        else:
            reason = ""

        if reason:
            self.outcome.rejected_submissions.append(
                {"reason": reason, "submission": args}
            )
            return (
                f"SUBMISSION REJECTED: {reason}. A finding requires a PoC that "
                "compiled, ran, and passed, plus an offending expression copied "
                "verbatim from the source. Keep working or call conclude_safe.",
                False,
            )

        finding = dict(args)
        finding["poc_name"] = poc_name
        finding["poc_hypothesis"] = record.hypothesis
        self.outcome.findings.append(finding)
        self.outcome.verdict = "vulnerable"
        self.outcome.stop_reason = "submit_finding"
        return "Finding accepted with execution evidence. Audit complete.", True

    def _conclude_safe(self, args: dict[str, Any]) -> tuple[str, bool]:
        # A clean bill of health that was never tested is an opinion, and an opinion is
        # what this architecture exists to replace. Refused once -- not permanently, since
        # forcing a hopeless exploit would be its own kind of theatre -- so that "safe"
        # means "I attacked it and it held" rather than "I read it and nothing jumped out".
        if self._exploit_calls == 0 and not self._refused_safe:
            self._refused_safe = True
            self.outcome.rejected_submissions.append(
                {"reason": "conclude_safe before any exploit attempt", "submission": args}
            )
            return (
                "NOT YET. You are certifying this contract as safe without having "
                "attacked it once. Reading it and finding nothing is how the tool you "
                "are replacing works; the whole point here is that you have an EVM. "
                "Take your single best hypothesis -- even a weak one -- and run it "
                "through run_exploit. If a guard stops it, that failure is real evidence "
                "of safety and you can call conclude_safe again immediately, this time "
                "with something behind it.",
                False,
            )
        guards = [str(g) for g in (args.get("guards_verified") or [])]
        verified = [g for g in guards if self.ws.contains_verbatim(g)]
        invented = [g for g in guards if not self.ws.contains_verbatim(g)]
        self.outcome.safe_reason = {
            "reason": args.get("reason"),
            "guards_claimed": guards,
            "guards_verified_verbatim": verified,
            "guards_not_found_in_source": invented,
            "hypotheses_tested": args.get("hypotheses_tested") or [],
        }
        self.outcome.verdict = "safe"
        self.outcome.stop_reason = "conclude_safe"
        return "Safe verdict recorded. Audit complete.", True


_EXPLOIT_FAILED_HEAD = (
    "EXPLOIT {name!r} compiled but did NOT satisfy {predicate!r}, in the default "
    "environment or in any of the twelve the harness then swept -- larger endowments, "
    "up to thirty-two repetitions, and a week of elapsed time, each also granted to the "
    "honest baseline. So this is not a question of scale: the attacker gained nothing "
    "the honest path did not.\n"
    "  'ArbiterNoGain(honestGain, attackGain)' -- the two numbers are what an honest "
    "user extracted and what your attack extracted, in wei or token units. Read them. "
    "If attackGain is 0 your attack extracted nothing and the hypothesis is wrong. If "
    "attackGain is large but honestGain is as large or larger, the attack works and your "
    "honest_body is too generous: it must be the MINIMAL intended use, not a maximal "
    "one. If they are equal, you reproduced the happy path.\n"
    "  'ArbiterNotDrained(targetBefore, targetAfter, attackGain)' -- you profited, but "
    "the value did not come out of the contract under audit. Its holdings did not fall "
    "by what you gained. That means you drained scenery you built yourself -- a mock you "
    "deployed and funded, a token you minted -- and nothing you have shown is a "
    "statement about this contract. Rebuild the scenario so the assets at risk are held "
    "BY the contract under audit, and take them from it.\n"
    "  anything else -- the target reverted, so a guard stopped you.\n"
    "A guard stopping you is evidence of safety, not a failure on your part.\n\n"
)

_REPEATED_HYPOTHESIS = (
    "NOTE: you have already tested this exact hypothesis and it failed. Repeating it "
    "will not change the result. Attack a different function or a different invariant, "
    "or call conclude_safe.\n\n"
)


def _tail(text: str) -> str:
    if len(text) <= MAX_TOOL_OUTPUT:
        return text
    return "... output truncated ...\n" + text[-MAX_TOOL_OUTPUT:]


def _test_passed(result: CommandResult) -> bool:
    """Decide whether forge reported a passing test.

    Parsed from forge's summary line rather than from the exit code, because a run with
    zero matched tests also exits non-zero and must not be read as a failed exploit.
    """
    text = result.combined
    if "No tests match" in text or "0 tests for" in text:
        return False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[PASS]"):
            return True
    return False


def parse_arguments(raw: Any) -> dict[str, Any]:
    """Tolerantly decode a tool call's arguments field."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        # Models occasionally emit trailing prose after the JSON object.
        depth, end = 0, -1
        for i, ch in enumerate(raw):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end == -1:
            return {}
        try:
            value = json.loads(raw[:end])
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}
