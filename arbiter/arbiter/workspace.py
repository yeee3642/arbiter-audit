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
    function startPrank(address) external;
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
/// forge runs `test*` functions on contracts whose name starts with `Test`;
/// a function that reverts is a failing test, one that returns is a passing test.
contract Harness {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function assertTrue(bool cond, string memory why) internal pure {
        require(cond, why);
    }
}
"""
