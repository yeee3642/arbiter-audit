#!/usr/bin/env python3
"""Competing for a scarce resource is not a vulnerability, and D4 cannot tell them apart.

`victim_loss` asks whether the victim recovered less BECAUSE the attack ran. On a contract
where a shared resource is finite and first come first served, everyone who arrives early
makes everyone who arrives late worse off, and none of them has done anything wrong. The
predicate survives that today only because nobody in the sweep is given enough money to
matter: the endowment axis scales the VICTIM's wallet and the attacker's funding never
moves off its default. That is D4, and it is the reason first-depositor inflation,
spot-price manipulation and liquidation are unreachable under this predicate.

D4 says the fix is an attacker-capital axis shipped together with a third trial in which a
harness-owned ordinary user is funded identically, with harm counted only in excess of
what that user causes. Both were built and measured, on the `BonusVault` below -- a
contract with no defect in it, which pays a 10% bonus out of a fixed reserve while the
reserve lasts:

    capital 10 ether (today)      refused    withoutAttack=5.5 withRival=5.5 withAttack=5.5
    capital 10,000 ether + rival  ADMITTED

The control does not work, and funding is not why. The rival IS funded identically; the
harness pranks it and Solidity debits the pranked account, which this probe's sibling
checked directly. What the rival cannot do is ACT at the same scale, because the only
description of ordinary use the harness has is `victim_enter` and `victim_exit`, and the
amounts in those are literals the agent wrote -- `deposit{value: 5 ether}`. So the axis
scales what the attacker can spend and leaves the control reciting a five-ether script.
The rival takes its 0.5 and leaves the reserve alone, the attacker with a thousand times
the money takes all of it, and the difference is scored as harm.

Funding the control identically is therefore not sufficient; it would have to act
comparably, and nothing in the harness knows what this contract's ordinary use looks like
at ten thousand ether. So D4 is not fixed, and this probe is what stops it being fixed
badly -- it fails the moment a capital axis makes an honest contract look guilty.

Both directions, and forge runs both of them:

  1. BonusVault, no defect, an attacker that spends its whole balance to take the reserve
     first -> REFUSED.
  2. LeakyVault, a real reentrancy, an attacker that drains the victim's principal ->
     ADMITTED. A predicate that refuses everything is not sound, it is broken.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.workspace import BuildUnavailable, Workspace  # noqa: E402

WS = Path("/tmp/contention-probe")

# No access control to bypass, no reentrancy, no rounding. Whoever withdraws first is paid
# first, and that is the entire design.
BONUS = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

contract BonusVault {
    mapping(address => uint256) public bal;
    uint256 public reserve;

    constructor() payable { reserve = msg.value; }

    function deposit() external payable { bal[msg.sender] += msg.value; }

    function withdraw() external {
        uint256 b = bal[msg.sender];
        require(b > 0, "nothing to withdraw");
        bal[msg.sender] = 0;
        uint256 bonus = b / 10;
        if (bonus > reserve) { bonus = reserve; }
        reserve -= bonus;
        (bool ok, ) = msg.sender.call{value: b + bonus}("");
        require(ok, "send failed");
    }

    receive() external payable {}
}
"""

# The state write lands after the call, so a reentrant caller is paid out of everyone
# else's principal. This one IS a defect.
LEAKY = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

contract LeakyVault {
    mapping(address => uint256) public bal;

    function deposit() external payable { bal[msg.sender] += msg.value; }

    function withdraw() external {
        uint256 b = bal[msg.sender];
        require(b > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: b}("");
        require(ok, "send failed");
        bal[msg.sender] = 0;
    }

    receive() external payable {}
}
"""

# Spends its whole balance, so any capital the harness grants it turns into scale.
GREEDY = """contract Attacker {
    BonusVault public v;
    constructor(address t) payable { v = BonusVault(payable(t)); }
    function attack() external {
        v.deposit{value: address(this).balance}();
        v.withdraw();
    }
    receive() external payable {}
}"""

REENTRANT = """contract Attacker {
    LeakyVault public v;
    uint256 hops;
    constructor(address t) payable { v = LeakyVault(payable(t)); }
    function attack() external {
        v.deposit{value: 1 ether}();
        v.withdraw();
    }
    receive() external payable {
        if (hops < 5 && address(v).balance >= 1 ether) { hops++; v.withdraw(); }
    }
}"""

CASES = [
    ("contention is refused", BONUS, GREEDY,
     "        BonusVault target = new BonusVault{value: 100 ether}();", False),
    ("a real drain is admitted", LEAKY, REENTRANT,
     "        LeakyVault target = new LeakyVault();", True),
]


def main() -> int:
    results = []
    for label, source, attacker, deploy, want_pass in CASES:
        ws = Workspace(WS, label.replace(" ", "_"), source)
        try:
            sol = ws.compose_victim_loss(
                deploy_code=deploy,
                victim_enter="        target.deposit{value: 5 ether}();",
                victim_exit="        target.withdraw();",
                attacker_code=attacker, mode="contract")
            name = ws.write_poc("Contention", sol)
            build = ws.build()
            if not build.ok:
                results.append(False)
                print(f"  [WRONG] {label:26s} did not build: "
                      f"{build.combined.strip().splitlines()[-1][:60]}")
                continue
            out = ws.run_poc(name).combined
            passed = any(l.strip().startswith("[PASS]") for l in out.splitlines())
            ok = passed == want_pass
            note = "the attack is admissible" if passed else _why(out)
            results.append(ok)
            print(f"  [{'OK  ' if ok else 'WRONG'}] {label:26s} "
                  f"{'ADMITTED' if passed else 'refused ':8s}  {note}")
        finally:
            ws.cleanup()

    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


def _why(out: str) -> str:
    for line in out.splitlines():
        if "ArbiterNoHarm" in line or "ARBITER:" in line:
            return line.strip()[line.strip().find("ArbiterNoHarm")
                                if "ArbiterNoHarm" in line else 0:][:76]
    return "no verdict line"


if __name__ == "__main__":
    print("competing for a scarce resource is not a vulnerability.\n")
    try:
        raise SystemExit(main())
    except BuildUnavailable:
        print("forge is not on PATH. Both cases here are decided by what the EVM does, "
              "so without a compiler this would prove nothing.")
        raise SystemExit(2)
