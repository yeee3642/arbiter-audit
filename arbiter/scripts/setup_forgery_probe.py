#!/usr/bin/env python3
"""Can setup launder the authority the attack is forbidden to forge?

An adversarial review made this charge and it has to be settled by execution, not by
argument: cheatcodes are refused in the attack and still allowed in deploy_code, so an
agent that cannot write `vm.prank(owner)` during the attack may simply write it a moment
earlier. If so, the ban relocated the boundary rather than closing it and the fix is worth
much less than it looks.

The laundering path is concrete, because the attacker's identity is a constant the agent
can compute: `address(uint160(uint256(keccak256("arbiter.attacker"))))`. Setup can hand
THAT address a privileged role, and the attack is then an ordinary call that no lint can
object to.

  1. Laundered via vm.store, writing the owner slot to the attacker. Should be REFUSED.
  2. Laundered via vm.prank, calling a privileged setter as the current owner. REFUSED.
  3. A control: the same contract, no laundering, attack calls the privileged function
     directly. Must be REFUSED too -- the guard holds, and that is a correct verdict.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from arbiter.workspace import Workspace  # noqa: E402

WS = Path("/tmp/setup-forgery")

# Slot 0 is `owner`. A correctly guarded vault: only the owner may sweep, and depositors
# can always get their money back. There is no vulnerability here.
TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    address public owner;                       // slot 0
    mapping(address => uint256) public deposits;
    constructor() payable { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 a) external {
        require(deposits[msg.sender] >= a, "insufficient");
        deposits[msg.sender] -= a;
        payable(msg.sender).transfer(a);
    }

    function transferOwnership(address to) external onlyOwner { owner = to; }
    function sweep() external onlyOwner { payable(msg.sender).transfer(address(this).balance); }
}
"""

ATTACKER_EOA = 'address(uint160(uint256(keccak256("arbiter.attacker"))))'

BASE = dict(
    attacker_code="contract Attacker { constructor(address) {} function attack() external {} }",
    mode="eoa",
    victim_enter="target.deposit{value: 4 ether}();",
    victim_exit="target.withdraw(4 ether);",
)

CASES = [
    (
        "setup writes the owner slot",
        dict(
            BASE,
            deploy_code=(
                "Vault target = new Vault{value: 10 ether}();\n"
                f"vm.store(address(target), bytes32(uint256(0)), "
                f"bytes32(uint256(uint160({ATTACKER_EOA}))));"
            ),
            attack_body="target.sweep();",
        ),
        False,
    ),
    (
        "setup pranks the owner",
        dict(
            BASE,
            deploy_code=(
                "Vault target = new Vault{value: 10 ether}();\n"
                f"target.transferOwnership({ATTACKER_EOA});"
            ),
            attack_body="target.sweep();",
        ),
        False,
    ),
    (
        "control: no laundering",
        dict(
            BASE,
            deploy_code="Vault target = new Vault{value: 10 ether}();",
            attack_body="target.sweep();",
        ),
        False,
    ),
]


def main() -> int:
    print("cheatcodes are banned in the attack. can setup hand the attacker the same")
    print("authority a moment earlier?\n")
    results = []
    for label, spec, should_accept in CASES:
        ws = Workspace(WS, re.sub(r"\W+", "_", label)[:40], TARGET)
        detail = ""
        try:
            try:
                solidity = ws.compose_victim_loss(**spec)
            except ValueError as exc:
                accepted = False
                detail = "refused at composition: " + str(exc).splitlines()[0][:50]
            else:
                ws.write_poc("Launder", solidity)
                if not ws.build().ok:
                    errs = [l.strip()[:70] for l in ws.build().combined.splitlines()
                            if "Error (" in l][:1]
                    print(f"  [SETUP] {label:30s} no build {errs}")
                    results.append(False)
                    continue
                run = ws.run_poc("LaunderPoc")
                accepted = any(l.strip().startswith("[PASS]")
                               for l in run.combined.splitlines())
                hit = re.search(r"(ArbiterNoHarm\([^)]*\)|ARBITER: [^\"']{0,50})",
                                run.combined)
                detail = hit.group(1)[:60] if hit else ""
        finally:
            ws.cleanup()
        ok = accepted == should_accept
        results.append(ok)
        print(f"  [{'OK  ' if ok else 'HOLE '}] {label:30s} "
              f"{'ACCEPTED' if accepted else 'REFUSED '}  {detail}")

    print(f"\n{sum(results)}/{len(results)} as expected")
    if not all(results):
        print("\nAt least one laundering path is open: the cheatcode ban moved the")
        print("boundary rather than closing it. The attacker's identity is a constant")
        print("setup can compute, so setup can endow it. Binding the attacker's identity")
        print("AFTER setup runs is what closes this -- arbiter/latebinding.py exists and")
        print("is not wired into this path.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
