#!/usr/bin/env python3
"""Can an attack forge the authority it would otherwise have to earn?

Found live on a PATCHED sample, and it defeated every predicate the project has,
victim_loss included. The agent wrote

    vm.startPrank(owner);
    target.emergencyWithdraw(attacker);
    vm.stopPrank();

against an `onlyOwner` function. The depositor really did lose their money, so the harm
was real and measurable -- and the finding was still false, because the contract was
working exactly as designed and the cheatcode was doing the attacking.

The rule that follows is not a heuristic: an attacker standing in front of a deployed
contract cannot become its owner, cannot write its storage, and cannot mint themselves a
balance. Setup may do all three, because building a world is what setup is for.

  1. vm.prank inside the attack must be REFUSED, and the refusal must say where
     cheatcodes are still allowed.
  2. vm.store and vm.deal likewise, in the attack and in the attacker contract.
  3. vm.warp must still be ALLOWED everywhere, because waiting is something an attacker
     really can do.
  4. Cheatcodes in deploy_code must still be allowed.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.workspace import Workspace  # noqa: E402

WS = Path("/tmp/forgery-probe")

TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    mapping(address => uint256) public deposits;
    constructor() payable { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 a) external {
        require(deposits[msg.sender] >= a, "insufficient");
        deposits[msg.sender] -= a;
        payable(msg.sender).transfer(a);
    }
    function emergencyWithdraw(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }
}
"""

BASE = dict(
    deploy_code="Vault target = new Vault{value: 10 ether}();",
    attacker_code="contract Attacker { constructor(address) {} function attack() external {} }",
    mode="eoa",
    victim_enter="target.deposit{value: 3 ether}();",
    victim_exit="target.withdraw(3 ether);",
)

CASES = [
    ("prank in attack", dict(BASE, attack_body=(
        "vm.startPrank(address(0x5678));\n"
        "target.emergencyWithdraw(eoa);\nvm.stopPrank();")), False),
    ("store in attack", dict(BASE, attack_body=(
        "vm.store(address(target), bytes32(uint256(0)), bytes32(uint256(uint160(eoa))));\n"
        "target.emergencyWithdraw(eoa);")), False),
    ("deal in attack", dict(BASE, attack_body="vm.deal(eoa, 1000 ether);"), False),
    ("prank in attacker_code", dict(
        BASE,
        attack_body="target.withdraw(0);",
        attacker_code=("contract Attacker { constructor(address) {} "
                       "function attack() external { Vm(address(0)).prank(msg.sender); } }"),
    ), False),
    ("warp in attack stays allowed", dict(BASE, attack_body=(
        "vm.warp(block.timestamp + 1 days);\ntarget.withdraw(0);")), True),
    ("cheatcodes in setup stay allowed", dict(
        BASE,
        deploy_code=("Vault target = new Vault{value: 10 ether}();\n"
                     "vm.deal(address(target), 50 ether);"),
        attack_body="target.withdraw(0);",
    ), True),
]


def main() -> int:
    print("an attack may not forge what a real attacker would have to earn.\n")
    ws = Workspace(WS, "forgery", TARGET)
    results = []
    for label, spec, should_compose in CASES:
        try:
            ws.compose_victim_loss(**spec)
            composed, reason = True, ""
        except ValueError as exc:
            composed, reason = False, str(exc).splitlines()[0][:64]
        ok = composed == should_compose
        results.append(ok)
        verdict = "composed" if composed else "REFUSED "
        print(f"  [{'OK  ' if ok else 'WRONG'}] {label:34s} {verdict}  {reason}")
    ws.cleanup()
    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
