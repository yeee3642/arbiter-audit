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

# Chosen because it satisfies every pragma in the evaluation set that is not an exact
# pin, and because forge fetches per-file compilers for the ones that are.
FALLBACK_SOLC = "0.8.24"

FOUNDRY_TOML = """[profile.default]
src = "src"
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
    """One forge project holding one contract under test plus agent-written PoCs."""

    def __init__(self, root: Path, sample_id: str, source: str) -> None:
        self.root = root / sample_id
        self.sample_id = sample_id
        self.source = source
        self.build_ok: bool | None = None
        self.pocs: dict[str, str] = {}
        self._scaffold()

    # -- setup ---------------------------------------------------------------

    def _scaffold(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root)
        (self.root / "src").mkdir(parents=True)
        (self.root / "test").mkdir(parents=True)
        (self.root / "foundry.toml").write_text(FOUNDRY_TOML, encoding="utf-8")
        (self.root / "src" / "Target.sol").write_text(self.source, encoding="utf-8")
        # forge-std is not vendored, and no git submodule is fetched. The workspace is
        # hermetic so that a dependency download failure can never be mistaken for a
        # safe verdict. Cheatcodes are still available: they live at a fixed address on
        # the Foundry EVM, so a hand-written interface reaches them with no dependency.
        (self.root / "test" / "Vm.sol").write_text(VM_SOL, encoding="utf-8")

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
        attack_body: str = "",
        honest_body: str = "",
        mode: str = "contract",
        require_honest: bool = True,
        funding_wei: int = 10**19,
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
        if predicate != "state_change" and not honest_body.strip():
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
        else:
            raise ValueError(f"unknown predicate {predicate!r}")

        if predicate == "state_change":
            action = (
                "        atk.attack();"
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = _STATE_CHANGE_BODY.replace(
                "__GETTER__", observed_getter.strip()
            ).replace("__ACTION__", action)
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
                "        atk.attack();"
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
            )

        if mode == "contract":
            if "contract Attacker" not in attacker_code:
                raise ValueError("contract mode needs an Attacker contract")
            setup = (
                ""
                if predicate != "state_change"
                else _ATTACKER_SETUP.format(funding_wei=int(funding_wei))
            )
        else:
            # attacker_code is still emitted in EOA mode. It is no longer required to
            # contain an `Attacker`, but a realistic scenario usually needs helper
            # contracts declared -- a mock ERC20 to be the stolen asset, for instance --
            # and there is nowhere else to put them.
            setup = _EOA_SETUP.format(funding_wei=int(funding_wei))

        return _EXPLOIT_TEMPLATE.format(
            attacker_code=attacker_code.strip(),
            deploy_code=deploy_code.strip(),
            setup=setup,
            check=check,
        )

    def write_poc(self, name: str, solidity: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_]", "", name) or "Poc"
        if not safe.endswith("Poc"):
            safe = f"{safe}Poc"
        path = self.root / "test" / f"{safe}.t.sol"
        path.write_text(solidity, encoding="utf-8")
        self.pocs[safe] = solidity
        return safe

    def build(self, timeout: int = 240) -> CommandResult:
        result = self._forge(["build"], timeout=timeout)
        self.build_ok = result.ok
        return result

    def run_poc(self, name: str, timeout: int = 240) -> CommandResult:
        return self._forge(
            ["test", "--match-path", f"test/{name}.t.sol", "-vvv"], timeout=timeout
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
pragma solidity >=0.8.0;

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
}
"""


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line for line in text.strip().splitlines())


# The exploit test. Everything outside the agent-supplied holes is fixed, so the success
# condition is the same sentence for every sample, every predicate and every model.
_EXPLOIT_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import "../src/Target.sol";
import "./Vm.sol";

interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

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
        vm.deal(address(atk), {funding_wei});"""

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
_STATE_CHANGE_BODY = """        (bool okPre, bytes memory pre) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(okPre, "ARBITER: observed_getter did not execute before the attack");
__ACTION__
        (bool okPost, bytes memory post) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(okPost, "ARBITER: observed_getter did not execute after the attack");
        require(
            keccak256(pre) != keccak256(post),
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

        require(
            attackGain > honestGain,
            "ARBITER: attacker did no better than an honest user of this contract"
        );"""
