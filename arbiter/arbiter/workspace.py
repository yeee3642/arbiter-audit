"""A disposable Foundry project per sample, so that a claim can be executed.

This is the part of ARBITER that Bastet has no counterpart for. Bastet's 56 detector
nodes are chat-completion calls; not one of them can run anything, so nothing it emits
is ever tested against an EVM. Here every sample gets a real forge project, and the
auditor is handed a compiler and a test runner as tools.

The design constraint that matters: audit repositories usually do not build. Missing
dependencies, pinned compilers and broken remappings defeat any approach that needs
`forge build` to succeed on the repository as shipped. ARBITER sidesteps that by never
building the repository -- it builds a *minimal self-contained workspace* around the
single unit under test. For the current evaluation set that is exact rather than
approximate, because all 14 samples are zero-import, self-contained contracts.
Where a sample does carry imports, they are vendored into the workspace and the
degradation is recorded rather than hidden: `Workspace.build_ok` is part of the run
record, and a sample whose harness never compiled is reported as unproven, not as safe.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .repo import RepoPlan

# Chosen because it satisfies every pragma in the evaluation set that is not an exact
# pin, and because forge fetches per-file compilers for the ones that are.
FALLBACK_SOLC = "0.8.24"

FOUNDRY_TOML = """[profile.default]
src = "{src}"
test = "test"
out = "out"
libs = []
auto_detect_solc = true
optimizer = false
via_ir = false
# Deterministic: no fork, no network access during tests.
ffi = false
fs_permissions = []
"""


# The test contract invokes the attack directly, so tx.origin stays the deploying
# account. Pranking an attacker EOA here was tried and reverted: it broke the tx.origin
# sample it was meant to help. A contract that authorises on tx.origin is attacked by
# phishing -- the *victim* originates the transaction into the attacker's contract -- so
# forcing the origin to be the attacker makes that class unexploitable rather than
# exploitable. Agents that need to act as a plain account use mode='eoa'.
_CONTRACT_ATTACK = "        atk.attack();"


class BuildUnavailable(RuntimeError):
    """forge is not installed or not on PATH."""


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int

    @property
    def combined(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


class Workspace:
    """One forge project holding one contract under test plus agent-written PoCs.

    Two modes, and which one is in force is recorded on the run rather than assumed:

      * **hermetic** -- the source is written to `src/Target.sol` and nothing else
        exists. Correct for self-contained contracts, and it guarantees a dependency
        download failure can never be mistaken for a safe verdict.
      * **in-repo** -- a `RepoPlan` supplies remappings that reach the contract where it
        actually lives, together with its import closure. Nothing is copied; forge
        resolves the graph and inlines the sources, so the workspace stays a few hundred
        bytes and hundreds run concurrently.

    The second mode exists because the first compiled 0 of 24 contracts drawn from
    OneSavie's own dataset. A harness that cannot compile the code under audit cannot
    produce evidence, and a tool that produces no evidence answers "safe" to everything,
    which is a degenerate predictor pointed the other way from a 53-detector OR.
    """

    def __init__(
        self,
        root: Path,
        sample_id: str,
        source: str,
        plan: "RepoPlan | None" = None,
    ) -> None:
        self.root = root / re.sub(r"[^A-Za-z0-9_.-]", "_", sample_id)
        self.sample_id = sample_id
        self.source = source
        self.plan = plan
        self.build_ok: bool | None = None
        self.pocs: dict[str, str] = {}
        # Where a PoC reaches the contract under audit, and what syntax the harness may
        # use to talk about it. Both follow the contract rather than forcing it upward:
        # a target pinned to 0.6.12 cannot be compiled alongside a >=0.8.0 test, and
        # custom errors did not exist before 0.8.4.
        self.target_import = "../src/Target.sol" if plan is None else plan.target_import
        self.pragma = ">=0.8.0" if plan is None else plan.test_pragma
        self.custom_errors = True if plan is None else plan.custom_errors_ok
        self._scaffold()

    # -- setup ---------------------------------------------------------------

    def _scaffold(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root)
        (self.root / "src").mkdir(parents=True)
        (self.root / "test").mkdir(parents=True)
        self._write_toml("src" if self.plan is None else self.plan.chosen_src)
        if self.plan is None:
            (self.root / "src" / "Target.sol").write_text(self.source, encoding="utf-8")
        else:
            # src stays empty on purpose: forge compiles what the test reaches, so only
            # the target's import closure is built. A repository whose unrelated half
            # does not compile still yields evidence for the contract under audit.
            (self.root / "remappings.txt").write_text(
                "\n".join(self.plan.remappings) + "\n", encoding="utf-8"
            )
        # Cheatcodes are available in both modes with no dependency at all: they live at
        # a fixed address on the Foundry EVM, so a hand-written interface reaches them.
        (self.root / "test" / "Vm.sol").write_text(
            VM_SOL.replace("__PRAGMA__", self.pragma), encoding="utf-8"
        )

    # -- source access -------------------------------------------------------

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    def read(self, start: int = 1, end: int | None = None) -> str:
        lines = self.lines
        end = len(lines) if end is None else min(end, len(lines))
        start = max(1, start)
        if start > len(lines):
            return f"(file has only {len(lines)} lines)"
        width = len(str(end))
        return "\n".join(
            f"{i:>{width}}| {lines[i - 1]}" for i in range(start, end + 1)
        )

    def grep(self, pattern: str, max_hits: int = 40) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"invalid regex: {exc}"
        hits = [
            f"{i}| {line}" for i, line in enumerate(self.lines, 1) if rx.search(line)
        ]
        if not hits:
            return f"no match for {pattern!r}"
        out = hits[:max_hits]
        if len(hits) > max_hits:
            out.append(f"... {len(hits) - max_hits} more matches suppressed")
        return "\n".join(out)

    # -- the rest of the repository ------------------------------------------
    #
    # An exploit against a real protocol is rarely written against one file. The vault
    # under audit is deployed by a factory, holds a token declared elsewhere, and takes a
    # constructor argument whose type lives in an interface directory. Without these the
    # agent can read the bug and still not be able to stand the contract up, which shows
    # up as a compile failure it has no way to fix -- indistinguishable, in the run
    # record, from a contract that is actually safe.

    @property
    def in_repo(self) -> bool:
        return self.plan is not None

    def repo_files(self, pattern: str = "") -> str:
        if self.plan is None:
            return "this contract was audited standalone; there is no repository to list"
        from .repo import SKIP_DIRS

        root = self.plan.repo_root
        try:
            rx = re.compile(pattern) if pattern else None
        except re.error as exc:
            return f"invalid regex: {exc}"
        out: list[str] = []
        for dirpath, dirnames, filenames in __import__("os").walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in sorted(filenames):
                if not name.endswith(".sol"):
                    continue
                rel = (Path(dirpath) / name).relative_to(root).as_posix()
                if rx is None or rx.search(rel):
                    out.append(rel)
        if not out:
            return f"no .sol file matches {pattern!r}"
        head = out[:200]
        text = "\n".join(head)
        if len(out) > len(head):
            text += f"\n... {len(out) - len(head)} more suppressed; narrow the pattern"
        return text

    def read_repo(self, rel: str, start: int = 1, end: int | None = None) -> str:
        path = self._repo_path(rel)
        if isinstance(path, str):
            return path
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        end = len(lines) if end is None else min(end, len(lines))
        start = max(1, start)
        if start > len(lines):
            return f"({rel} has only {len(lines)} lines)"
        width = len(str(end))
        return "\n".join(f"{i:>{width}}| {lines[i - 1]}" for i in range(start, end + 1))

    def grep_repo(self, pattern: str, max_hits: int = 60) -> str:
        if self.plan is None:
            return "this contract was audited standalone; there is no repository to search"
        from .repo import SKIP_DIRS

        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"invalid regex: {exc}"
        root = self.plan.repo_root
        hits: list[str] = []
        for dirpath, dirnames, filenames in __import__("os").walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in sorted(filenames):
                if not name.endswith(".sol"):
                    continue
                path = Path(dirpath) / name
                rel = path.relative_to(root).as_posix()
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{rel}:{i}| {line.strip()[:160]}")
                        if len(hits) >= max_hits:
                            return "\n".join(hits) + "\n... truncated; narrow the pattern"
        return "\n".join(hits) if hits else f"no match for {pattern!r} in the repository"

    def _repo_path(self, rel: str) -> "Path | str":
        if self.plan is None:
            return "this contract was audited standalone; there is no repository"
        root = self.plan.repo_root
        candidate = (root / rel.lstrip("/")).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return f"{rel!r} is outside the repository"
        if not candidate.is_file():
            return f"{rel!r} does not exist; use list_repo_files to see what does"
        return candidate

    def contains_verbatim(self, fragment: str) -> bool:
        """Whitespace-insensitive verbatim containment check.

        Free, deterministic, and it removes a whole class of hallucination before any
        model is asked to adjudicate: an expression that is not in the file cannot be
        the expression that makes the file exploitable.
        """
        if not fragment or not fragment.strip():
            return False
        squash = lambda s: re.sub(r"\s+", " ", s).strip()  # noqa: E731
        return squash(fragment) in squash(self.source)

    # -- toolchain -----------------------------------------------------------

    def compose_exploit(
        self,
        *,
        deploy_code: str,
        attacker_code: str = "",
        predicate: str,
        observed_getter: str = "",
        token_expr: str = "",
        liveness_call: str = "",
        attack_body: str = "",
        honest_body: str = "",
        mode: str = "contract",
        require_honest: bool = True,
        funding_wei: int = 10**19,
        extra_imports: list[str] | None = None,
    ) -> str:
        """Build the exploit test file. The agent never writes the success check.

        This is the load-bearing detail of ARBITER. An earlier revision let the agent
        write the whole test and accepted "the test passed" as proof, and the agent
        promptly defeated it: on a *patched* sample it under-funded the vault, proved
        that `withdraw()` reverts, asserted that the revert happened, and submitted a
        passing test as evidence of a vulnerability. A reverting withdraw is the
        contract working. The test was true and the finding was false.

        The lesson is that "a test passed" is not a proof of anything unless someone
        other than the claimant chose what the test asserts. So the agent now supplies
        only the deployment, the attacker contract, and which predicate to use; the
        success condition is written here, is identical for every sample, and measures
        an outcome the agent cannot restate: did the attacker end up richer, or did
        privileged state move when a non-privileged account acted.
        """
        if mode not in ("contract", "eoa"):
            raise ValueError(f"unknown mode {mode!r}")
        if not honest_body.strip():
            if require_honest:
                raise ValueError(
                    "profit predicates need honest_body: the statements an ordinary, "
                    "non-attacking user would run. The exploit must beat that baseline."
                )
            # Benchmark admission is the one place this is relaxed. There the
            # discriminator is the PAIR -- the same exploit must pass on the vulnerable
            # half and fail on the patched one -- which is a stronger test than beating
            # an honest baseline, and it is available because admission can see both
            # halves. An auditing agent cannot: it sees one contract and has no patched
            # twin to compare against, which is exactly why it owes a baseline instead.
            # An empty BLOCK, not a bare semicolon: Solidity has no empty statement,
            # and ";" made 17 of 20 reference exploits fail to compile.
            honest_body = "{}"

        # How the attacker's holdings are read. Same expression before and after, so the
        # predicate is a strict increase in whatever the attacker actually walks away
        # with -- ether, or a token balance.
        if predicate == "eth_profit":
            measure = "{who}.balance"
        elif predicate == "token_profit":
            if not token_expr.strip():
                raise ValueError("token_profit predicate needs token_expr")
            measure = f"_ArbiterToken({token_expr.strip()}).balanceOf({{who}})"
        elif predicate == "state_change":
            if not observed_getter.strip():
                raise ValueError("state_change predicate needs observed_getter")
            measure = ""
        elif predicate == "liveness_broken":
            if not liveness_call.strip():
                raise ValueError("liveness_broken predicate needs liveness_call")
            measure = ""
        else:
            raise ValueError(f"unknown predicate {predicate!r}")

        if predicate == "liveness_broken":
            action = (
                _CONTRACT_ATTACK
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = _LIVENESS_BODY.replace("__CALL__", liveness_call.strip()).replace(
                "__ACTION__", action
            )
        elif predicate == "state_change":
            action = (
                _CONTRACT_ATTACK
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = (
                _STATE_CHANGE_BODY.replace("__GETTER__", observed_getter.strip())
                .replace("__ACTION__", action)
                .replace("__HONEST__", _indent(honest_body, 8))
            )
        else:
            # Profit alone does not mean a vulnerability. The reentrancy pair proves it:
            # UtopiaVault pays every caller a 1 ether airdrop by design, so
            # claim()+withdraw() leaves an EOA richer on the PATCHED contract too. An
            # earlier revision accepted exactly that and reported S1, a patched sample,
            # as "proven".
            #
            # So the bar is no longer "did the attacker profit" but "did the attacker do
            # better than an honest user of the same contract". The harness runs the
            # honest path first, as a separate account under identical funding, and
            # requires the attack to strictly beat it. On S1 both paths yield 1 ether and
            # the exploit is refused; on V1 the honest path yields 1 and the reentrant
            # one yields several, so it passes.
            attacker_expr = "address(atk)" if mode == "contract" else "eoa"
            attack_action = (
                _CONTRACT_ATTACK
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = _PROFIT_BODY.format(
                honest_body=_indent(honest_body, 8),
                measure_ctrl=measure.format(who="ctrl"),
                measure_atk=measure.format(who=attacker_expr),
                setup=_ATTACKER_SETUP.format(funding_wei=int(funding_wei))
                if mode == "contract"
                else "",
                attack_action=attack_action,
                fail_report=_FAIL_CUSTOM_ERROR if self.custom_errors else _FAIL_REQUIRE,
            )

        if mode == "contract":
            if "contract Attacker" not in attacker_code:
                raise ValueError("contract mode needs an Attacker contract")
            setup = (
                ""
                if predicate not in ("state_change", "liveness_broken")
                else _ATTACKER_SETUP.format(funding_wei=int(funding_wei))
            )
        else:
            # attacker_code is still emitted in EOA mode. It is no longer required to
            # contain an `Attacker`, but a realistic scenario usually needs helper
            # contracts declared -- a mock ERC20 to be the stolen asset, for instance --
            # and there is nowhere else to put them.
            setup = _EOA_SETUP.format(funding_wei=int(funding_wei))

        # Named imports do not re-export, so a token or interface the target imported
        # that way is not in scope here. The agent asks for what it needs by the same
        # path the repository's own files use, which resolves through the same
        # remappings; `arbiter-repo/<path from the repo root>` reaches anything else.
        extras = "\n".join(
            f'import "{spec.strip()}";'
            for spec in (extra_imports or [])
            if spec and spec.strip()
        )

        return _EXPLOIT_TEMPLATE.format(
            pragma=self.pragma,
            target_import=self.target_import,
            extra_imports=("\n" + extras if extras else ""),
            error_decl=(
                "error ArbiterNoGain(uint256 honestGain, uint256 attackGain);\n"
                if self.custom_errors
                else ""
            ),
            attacker_code=attacker_code.strip(),
            deploy_code=deploy_code.strip(),
            setup=setup,
            check=check,
        )

    def write_poc(self, name: str, solidity: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_]", "", name) or "Poc"
        if not safe.endswith("Poc"):
            safe = f"{safe}Poc"

        # Retire every earlier PoC before writing this one. `forge build` compiles the
        # whole test directory, so a single malformed exploratory PoC left on disk makes
        # every LATER build fail with ITS errors -- and the agent, reading a compiler
        # error about a file it has moved on from, cannot fix the file it is actually
        # working on. This was the dominant cause of compile failures: 72 "Undeclared
        # identifier" errors, most of them belonging to abandoned probes rather than to
        # the exploit being compiled. Each PoC is independent, so only the current one
        # ever needs to build.
        for stale in (self.root / "test").glob("*.t.sol"):
            stale.unlink()

        path = self.root / "test" / f"{safe}.t.sol"
        path.write_text(solidity, encoding="utf-8")
        self.pocs[safe] = solidity
        return safe

    @property
    def _force(self) -> list[str]:
        """Whether this workspace must recompile everything rather than incrementally.

        In project mode the contract only resolves when the project's own files are
        compilation roots -- that is the whole reason the mode exists. forge's cache
        defeats it: with only the test file changed it recompiles that file alone, the
        repository drops out of the unit, and a build that passed a moment earlier fails
        with the same cycle error. Costly and unavoidable, so it is paid only in the mode
        that needs it.
        """
        return ["--force"] if self.plan is not None and self.plan.chosen_src != "src" else []

    def build(self, timeout: int = 240) -> CommandResult:
        result = self._forge(["build", *self._force], timeout=timeout)
        self.build_ok = result.ok
        return result

    def context_ok(self, timeout: int = 300) -> CommandResult:
        """Does the contract under audit compile at all, before any exploit is written?

        Reported separately from the exploit build because the two failures mean opposite
        things. An exploit that does not compile is the agent's problem and it can be
        told to fix it. A *context* that does not compile is the harness's problem, and
        answering "safe" there is not a verdict -- it is a missing measurement. Keeping
        them apart is what turned "0 of 24 vulnerable" into a diagnosable defect instead
        of a plausible-looking result.
        """
        probe = _CONTEXT_PROBE.format(
            pragma=self.pragma, target_import=self.target_import
        )
        self.write_poc("ArbiterContext", probe)
        result = self._forge(["build"], timeout=timeout)
        for stale in (self.root / "test").glob("*.t.sol"):
            stale.unlink()
        self.pocs.pop("ArbiterContextPoc", None)
        return result

    def _write_toml(self, src: str) -> None:
        (self.root / "foundry.toml").write_text(
            FOUNDRY_TOML.format(src=src), encoding="utf-8"
        )

    def prepare_context(self, rounds: int = 3, timeout: int = 300) -> dict[str, object]:
        """Compile the contract under audit, repairing until it does.

        Two escalating compilation sets, cheapest first, because they fail for different
        reasons and the cheap one is right most of the time:

          1. **minimal** -- only the test is a compilation root, so forge builds exactly
             the target's import closure. Fast, and unaffected by a broken sibling.
          2. **project** -- the project's own source root becomes `src`, reproducing the
             compilation set its toolchain used. Needed for projects that rely on
             Solidity's transitive re-export through an import cycle, which resolves only
             when the files involved are roots. Measured on defiprotocol: minimal fails
             with "Identifier not found or not unique", project succeeds.

        Each set gets its own repair loop, which feeds the exact source names the
        compiler asked for back into the remappings. Bounded and recorded: "it still does
        not build" is a result the run must carry, not round down to a clean bill.
        """
        if self.plan is None:
            result = self.context_ok(timeout=timeout)
            return {"ok": result.ok, "mode": "hermetic", "rounds": 0,
                    "error": _first_error(result.combined)}

        from .repo import repair

        attempts: list[dict[str, object]] = []
        modes = [("minimal", "src"), ("project", self.plan.source_root.as_posix())]
        # A plan that already knows which set worked starts there, so re-auditing the
        # same contract does not repeat the discovery.
        if self.plan.chosen_src != "src":
            modes.reverse()
        for mode, src in modes:
            self._write_toml(src)
            # Set before probing, not after: `_force` reads it, and the project-mode
            # probe is exactly the build that must not come from cache.
            self.plan.chosen_src = src
            result = None
            for attempt in range(rounds + 1):
                result = self.context_ok(timeout=timeout)
                if result.ok:
                    return {
                        "ok": True, "mode": mode, "rounds": attempt,
                        "remappings": len(self.plan.remappings),
                        "external": list(self.plan.external_used),
                        "failed_modes": attempts,
                    }
                if attempt == rounds or not repair(self.plan, result.combined):
                    break
                (self.root / "remappings.txt").write_text(
                    "\n".join(self.plan.remappings) + "\n", encoding="utf-8"
                )
            attempts.append(
                {"mode": mode, "error": _first_error(result.combined if result else "")}
            )

        # Leave the workspace in the cheaper configuration: a failed project-wide build
        # usually means an unrelated sibling is broken, and the agent's own PoCs should
        # not be charged for that.
        self.plan.chosen_src = "src"
        self._write_toml("src")
        return {
            "ok": False, "mode": "none", "rounds": rounds,
            "remappings": len(self.plan.remappings),
            "error": attempts[-1]["error"] if attempts else "",
            "failed_modes": attempts,
        }

    def run_poc(self, name: str, timeout: int = 240) -> CommandResult:
        return self._forge(
            ["test", "--match-path", f"test/{name}.t.sol", "-vvv", *self._force],
            timeout=timeout,
        )

    def _forge(self, args: list[str], timeout: int) -> CommandResult:
        forge = shutil.which("forge")
        if forge is None:
            raise BuildUnavailable("forge not found on PATH")
        try:
            proc = subprocess.run(  # noqa: S603
                [forge, *args],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(False, "", f"timed out after {timeout}s", 124)
        return CommandResult(
            proc.returncode == 0, proc.stdout or "", proc.stderr or "", proc.returncode
        )

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


# A dependency-free stand-in for forge-std. `forge test` discovers any contract whose
# name starts with `Test` and runs its `test*` functions, so no base class is needed;
# and the cheatcode precompile sits at a fixed address, so declaring the interface by
# hand gives a PoC prank/deal/warp/expectRevert without vendoring anything.
VM_SOL = """// SPDX-License-Identifier: Apache-2.0
pragma solidity __PRAGMA__;

/// Subset of the Foundry cheatcode interface, declared by hand so that a proof of
/// concept needs no external dependency and the workspace stays hermetic.
interface Vm {
    function prank(address) external;
    // Two-argument forms set msg.sender AND tx.origin, which is the only way to satisfy
    // a require(msg.sender == tx.origin) guard from inside a test.
    function prank(address, address) external;
    function startPrank(address) external;
    function startPrank(address, address) external;
    function stopPrank() external;
    function deal(address, uint256) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function label(address, string calldata) external;
    function store(address, bytes32, bytes32) external;
    function load(address, bytes32) external returns (bytes32);
}

/// Inherit this in a PoC to get `vm` and `assertTrue`.
/// The exploit template below is written by the harness, never by the auditor.
/// forge runs `test*` functions on contracts whose name starts with `Test`;
/// a function that reverts is a failing test, one that returns is a passing test.
contract Harness {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function assertTrue(bool cond, string memory why) internal pure {
        require(cond, why);
    }

    /// Render a uint so the harness can tell the auditor HOW MUCH it fell short by.
    /// A bare "you did not profit" is a dead end; "you gained 1000000000000000000,
    /// honest gained 1000000000000000000" says the attack merely reproduced the
    /// intended behaviour, which points at what to change.
    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v;
        uint256 digits;
        while (n != 0) { digits++; n /= 10; }
        bytes memory buf = new bytes(digits);
        while (v != 0) { digits--; buf[digits] = bytes1(uint8(48 + v % 10)); v /= 10; }
        return string(buf);
    }
}
"""


# The smallest file that proves the contract under audit and its whole import closure
# resolve and compile. It asserts nothing; it exists so a failure to build can be
# attributed to the harness rather than charged to the contract as a clean bill of health.
_CONTEXT_PROBE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "{target_import}";
import "./Vm.sol";

contract TestArbiterContextPoc is Harness {{
    function testArbiterContext() public pure {{ }}
}}
"""


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line for line in text.strip().splitlines())


def _first_error(output: str) -> str:
    """The first compiler diagnostic, for the run record. Full text stays in the trace."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Error") or "Error (" in stripped:
            return stripped[:200]
    return output.strip().splitlines()[-1][:200] if output.strip() else ""


# The exploit test. Everything outside the agent-supplied holes is fixed, so the success
# condition is the same sentence for every sample, every predicate and every model.
_EXPLOIT_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "{target_import}";{extra_imports}
import "./Vm.sol";

interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

{error_decl}
{attacker_code}

contract TestArbiterExploit is Harness {{
    function testArbiterExploit() public {{
        // ---- agent-supplied deployment and scenario setup ----
        {deploy_code}
{setup}
{check}
    }}
}}
"""

# Contract-driven attacker: funded first, so spending its own money cannot pass.
_ATTACKER_SETUP = """        Attacker atk = new Attacker(address(target));
        vm.deal(address(atk), {funding_wei});
        address atkEoa = address(uint160(uint256(keccak256("arbiter.attacker"))));
        vm.deal(atkEoa, {funding_wei});"""

# EOA-driven attacker. Needed because a great many real guards are written as
# `require(msg.sender == tx.origin)`, which makes a contract attacker structurally
# impossible -- V2 of the evaluation set is exactly that, and no contract-based harness
# could ever prove it. vm.startPrank with two arguments sets msg.sender AND tx.origin,
# so the calls arrive exactly as they would from a real externally owned account.
_EOA_SETUP = """        address eoa = address(uint160(uint256(keccak256("arbiter.attacker"))));
        vm.deal(eoa, {funding_wei});"""

_PROFIT_CONTRACT_BODY = """        uint256 pre = {measure_pre};
        atk.attack();
        uint256 post = {measure_post};
        require(post > pre, "ARBITER: attacker did not profit");"""

_PROFIT_EOA_BODY = """        uint256 pre = {measure_pre};
        vm.startPrank(eoa, eoa);
{attack_body}
        vm.stopPrank();
        uint256 post = {measure_post};
        require(post > pre, "ARBITER: attacker did not profit");"""

_EOA_ACTION = """        vm.startPrank(eoa, eoa);
{attack_body}
        vm.stopPrank();"""

# Did privileged state move when an unprivileged account acted? Read through a
# staticcall before and after, so any public view function works and the harness never
# needs to know the contract's type.
_STATE_CHANGE_BODY = """        (bool ok0, bytes memory v0) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(ok0, "ARBITER: observed_getter did not execute");

        // First establish that the state named really is privileged: an ordinary user
        // running the intended happy path must NOT be able to move it. Without this the
        // predicate accepts any mutation at all, which is how a patched sample was
        // reported as vulnerable for "changing" coverageRatio() -- a view over the
        // contract balance that ordinary staking moves too.
        address ctrl = address(uint160(uint256(keccak256("arbiter.control"))));
        vm.deal(ctrl, 10000000000000000000);
        vm.startPrank(ctrl, ctrl);
__HONEST__
        vm.stopPrank();
        (bool ok1, bytes memory v1) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(ok1, "ARBITER: observed_getter did not execute after the honest path");
        require(
            keccak256(v0) == keccak256(v1),
            "ARBITER: ordinary use already moves this state, so it is not privileged"
        );

__ACTION__
        (bool ok2, bytes memory v2) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(ok2, "ARBITER: observed_getter did not execute after the attack");
        require(
            keccak256(v1) != keccak256(v2),
            "ARBITER: privileged state did not change"
        );"""


# Honest baseline first, attack second, and the attack has to win. `ctrl` and the
# attacker get the same funding, so the comparison is between what the contract gives an
# ordinary user and what it gives someone trying to break it. Gains are computed with a
# guard against underflow, because an honest path that loses money is legitimate.
_PROFIT_BODY = """        address ctrl = address(uint160(uint256(keccak256("arbiter.control"))));
        vm.deal(ctrl, 10000000000000000000);
        uint256 ctrlPre = {measure_ctrl};
        vm.startPrank(ctrl, ctrl);
{honest_body}
        vm.stopPrank();
        uint256 ctrlPost = {measure_ctrl};
        uint256 honestGain = ctrlPost > ctrlPre ? ctrlPost - ctrlPre : 0;

{setup}
        uint256 atkPre = {measure_atk};
{attack_action}
        uint256 atkPost = {measure_atk};
        uint256 attackGain = atkPost > atkPre ? atkPost - atkPre : 0;

        // Both quantities reach the agent, not just a verdict. "did not satisfy the
        // predicate" told it nothing it could act on; the actual pair of numbers tells
        // it whether the attack extracted nothing at all, or extracted something and was
        // outrun by an over-generous honest baseline.
{fail_report}"""

# Custom errors arrived in 0.8.4. Above it the two quantities travel in the revert data
# and forge decodes them; below it they are rendered into the revert string instead, so a
# contract pinned to 0.6 or 0.7 gets the same feedback rather than no harness at all.
_FAIL_CUSTOM_ERROR = """        if (attackGain <= honestGain) {
            revert ArbiterNoGain(honestGain, attackGain);
        }"""

_FAIL_REQUIRE = """        if (attackGain <= honestGain) {
            revert(string(abi.encodePacked(
                "ArbiterNoGain(honestGain=", _u(honestGain),
                ", attackGain=", _u(attackGain), ")"
            )));
        }"""


# Denial of service is a real vulnerability class that no profit predicate can express:
# the attacker gains nothing, the protocol simply stops working. The benchmark contains
# such a pair, and admission had certified it under a relaxed baseline while the agent
# was being held to a stricter one -- so the harness, not the contract, was refusing a
# provable finding. The differential form is the definition of the bug: an operation
# that an ordinary user could complete before the attack must fail after it.
_LIVENESS_BODY = """        address live = address(uint160(uint256(keccak256("arbiter.liveness"))));
        vm.deal(live, 10000000000000000000);
        vm.prank(live, live);
        (bool okBefore, ) = address(target).call(__CALL__);
        require(
            okBefore,
            "ARBITER: the honest operation already fails before the attack"
        );

__ACTION__

        vm.prank(live, live);
        (bool okAfter, ) = address(target).call(__CALL__);
        require(
            !okAfter,
            "ARBITER: the honest operation still succeeds after the attack, so "
            "availability was not broken"
        );"""
