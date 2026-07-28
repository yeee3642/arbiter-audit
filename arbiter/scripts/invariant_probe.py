#!/usr/bin/env python3
"""Does invariant fuzzing separate a vulnerable contract from its patched twin?

The claim under test: if the model states a PROPERTY and the machine searches for a
violation, we move the expensive half of auditing off the rationed resource (gateway
turns) onto the free one (32 idle cores), and we simultaneously close every gaming vector
-- the agent no longer chooses the initial state, the attacker, the call sequence, or the
success condition.

The load-bearing detail is that the adversarial handler is written HERE, by the harness,
once, generically. If the model had to write it, this would just be exploit construction
again under a different name.

Two phases, mirroring the honest-baseline differential that is the only mechanism in this
project that has actually held:

    phase A -- honest    fuzz only the plain vault functions, from plain senders
                         the invariant MUST HOLD, or it is a bogus invariant
    phase B -- adversarial  fuzz through a reentrant, ether-forcing handler
                         the invariant MUST BREAK, or there is no finding

A contract is reported vulnerable only on hold-then-break.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

RIG = Path("/home/ubuntu/rig/arbiter")
WS = Path("/tmp/inv-probe")

FOUNDRY_TOML = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
auto_detect_solc = true
optimizer = false
ffi = false

[invariant]
runs = 64
depth = 32
fail_on_revert = false
call_override = false
"""

# The generic adversarial handler. Harness-owned, contract-agnostic, written once.
# It re-enters on receive() and can force ether in. Nothing here is specific to any
# vulnerability or to any target -- it is a hostile environment, not an exploit.
HANDLER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/Target.sol";

/// Forces ether into a target that cannot refuse it.
contract Bomb {
    constructor(address payable t) payable { selfdestruct(t); }
}

/// A hostile counterparty. The fuzzer drives its public functions; on every ether
/// receipt it attempts to re-enter the target. Ghost accounting records what each
/// actor put in and took out, which is what the invariant is stated over.
contract Adversary {
    StakingVault public v;
    uint256 public depositedIn;
    uint256 public withdrawnOut;
    uint256 private depth;
    uint256 public maxDepth = 4;
    bool public immutable reenter;

    constructor(address payable _v, bool _reenter) payable {
        v = StakingVault(_v);
        reenter = _reenter;
    }

    function doStake(uint96 amount) external {
        uint256 a = uint256(amount) % 3 ether;
        if (a == 0) return;
        if (address(this).balance < a) return;
        depositedIn += a;
        v.stake{value: a}();
    }

    function doUnstake() external {
        uint256 before = address(this).balance;
        depth = 0;
        try v.unstake() {} catch {}
        uint256 got = address(this).balance;
        if (got > before) withdrawnOut += (got - before);
    }

    receive() external payable {
        if (reenter && depth < maxDepth && address(v).balance >= 1 wei) {
            depth++;
            try v.unstake() {} catch {}
        }
    }
}
"""

# The part a language model would supply: one property, in Solidity. Nothing else.
MODEL_WRITTEN_INVARIANT = """
    function invariant_noFreeMoney() public view {
        require(
            adv.withdrawnOut() <= adv.depositedIn(),
            "ARBITER: an actor withdrew more than it ever deposited"
        );
    }
"""

TEST_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/Target.sol";
import "./Adversary.sol";

contract TestInv {{
    StakingVault public vault;
    Adversary public adv;

    function setUp() public {{
        vault = new StakingVault{{value: 5 ether}}();
        adv = new Adversary{{value: 20 ether}}(payable(address(vault)), {reenter});
    }}

    /// forge reads this by selector; it does not need forge-std.
    function targetContracts() public view returns (address[] memory a) {{
        a = new address[](1);
        a[0] = address(adv);
    }}

{invariant}
}}
"""


def write_ws(root: Path, target_src: str, reenter: bool) -> Path:
    if root.exists():
        subprocess.run(["rm", "-rf", str(root)], check=False)
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir(parents=True)
    (root / "foundry.toml").write_text(FOUNDRY_TOML)
    (root / "src" / "Target.sol").write_text(target_src)
    (root / "test" / "Adversary.sol").write_text(HANDLER)
    (root / "test" / "TestInv.t.sol").write_text(
        TEST_TEMPLATE.format(
            reenter="true" if reenter else "false",
            invariant=MODEL_WRITTEN_INVARIANT,
        )
    )
    return root


def run(root: Path) -> tuple[bool, str]:
    """Returns (invariant_held, output)."""
    p = subprocess.run(
        ["forge", "test", "--match-path", "test/TestInv.t.sol", "-vv"],
        cwd=root, capture_output=True, text=True, timeout=600,
    )
    out = (p.stdout or "") + (p.stderr or "")
    if "Compiler run failed" in out or "Error (" in out:
        return None, out
    held = "[PASS]" in out and "[FAIL" not in out
    return held, out


def main() -> int:
    ev = json.loads((RIG / "evalsets" / "v3_authored.json").read_text())
    items = {x["id"]: x for x in ev["items"]}

    print("phase A = honest fuzzing (handler cannot re-enter): invariant MUST HOLD")
    print("phase B = adversarial fuzzing (handler re-enters):   invariant MUST BREAK")
    print()
    verdicts = {}
    for sid, expect in [("V_reentrancy_unstake", "vuln"), ("S_reentrancy_unstake", "safe")]:
        src = items[sid]["code"]
        row = {}
        for phase, reenter in (("A_honest", False), ("B_adversarial", True)):
            root = write_ws(WS / f"{sid}_{phase}", src, reenter)
            held, out = run(root)
            if held is None:
                print(f"  {sid:28s} {phase:14s} COMPILE FAIL")
                print("    " + "\n    ".join(
                    l for l in out.splitlines() if "Error" in l)[:400])
                row[phase] = "compile_fail"
                continue
            row[phase] = "HELD" if held else "BROKEN"
            marker = ""
            for l in out.splitlines():
                if "[FAIL" in l or "[PASS" in l:
                    marker = l.strip()[:90]
                    break
            print(f"  {sid:28s} {phase:14s} {row[phase]:7s}  {marker}")
        # hold-then-break is the only combination that reports a vulnerability
        called = "vuln" if (row.get("A_honest") == "HELD"
                            and row.get("B_adversarial") == "BROKEN") else "safe"
        verdicts[sid] = (expect, called)
        print(f"    -> verdict {called}  (truth {expect})  "
              f"{'OK' if called == expect else 'WRONG'}")
        print()

    ok = sum(1 for e, c in verdicts.values() if e == c)
    print(f"{ok}/{len(verdicts)} correct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
