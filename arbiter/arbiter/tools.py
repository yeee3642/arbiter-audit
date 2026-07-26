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
                            "enum": ["eth_profit", "token_profit", "state_change", "liveness_broken"],
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
                    },
                    "required": [
                        "poc_name",
                        "title",
                        "vulnerable_function",
                        "offending_expression",
                        "attack_path",
                        "severity",
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

    def __init__(self, workspace: Workspace) -> None:
        self.ws = workspace
        self.outcome = AgentOutcome()
        self._poc_by_name: dict[str, PocRecord] = {}
        self._freeform_calls = 0
        self._exploit_calls = 0
        self._hypotheses: list[str] = []

    @property
    def has_tried_exploit(self) -> bool:
        return self._exploit_calls > 0

    def dispatch(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Run one tool. Returns (result_text, is_terminal)."""
        handler = {
            "read_source": self._read_source,
            "grep_source": self._grep_source,
            "run_poc": self._run_poc,
            "run_exploit": self._run_exploit,
            "submit_finding": self._submit_finding,
            "conclude_safe": self._conclude_safe,
        }.get(name)
        if handler is None:
            return f"error: no such tool {name!r}", False
        try:
            return handler(arguments)
        except Exception as exc:  # noqa: BLE001 - a tool crash must not kill the run
            return f"error: tool {name} raised {type(exc).__name__}: {exc}", False

    # -- read-only tools, zero cost -----------------------------------------

    def _read_source(self, args: dict[str, Any]) -> tuple[str, bool]:
        start = int(args.get("start_line") or 1)
        end = args.get("end_line")
        return self.ws.read(start, int(end) if end else None)[:MAX_TOOL_OUTPUT], False

    def _grep_source(self, args: dict[str, Any]) -> tuple[str, bool]:
        return self.ws.grep(str(args.get("pattern", "")))[:MAX_TOOL_OUTPUT], False

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
        record = PocRecord(
            name, hypothesis, solidity, True, passed, run.combined,
            adjudicated=True, predicate=predicate,
        )
        self._poc_by_name[name] = record
        self.outcome.pocs.append(record)

        if passed:
            head = (
                f"EXPLOIT {name!r} PASSED the harness predicate {predicate!r}. This is "
                "admissible evidence. Call submit_finding citing this name.\n\n"
            )
        else:
            head = (
                f"EXPLOIT {name!r} compiled but did NOT satisfy {predicate!r}. The "
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
