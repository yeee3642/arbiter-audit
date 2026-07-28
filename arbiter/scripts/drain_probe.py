#!/usr/bin/env python3
"""Does the harness refuse an exploit that drains the agent's own scenery?

The shape this exists to kill was measured on a real repository, not imagined. An audit
of illuminate's ERC5095 produced a PASSING adjudicated exploit in which the attacker's
tokens came from a mock the agent had written and funded itself, while the honest
baseline had been pointed at a third address and therefore gained nothing. Both halves of
the differential were satisfied and the contract under audit was never touched.

Two properties, and both must hold:

  1. An exploit whose profit comes out of a mock the agent deployed must be REFUSED, even
     though the attacker really did end up richer than the honest control.
  2. An exploit that takes the same value out of the contract under audit must still be
     ACCEPTED, so the check costs no real findings.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.workspace import Workspace  # noqa: E402

WS = Path("/tmp/drain-probe")

# A vault with a genuine bug: withdraw() sends the full balance to anyone who deposited,
# not just their own share. Real, and really drains the contract under audit.
TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public deposits;
    constructor() payable {}
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    // BUG: pays out twice what was deposited, so the vault leaks in proportion to stake.
    function withdraw() external {
        uint256 d = deposits[msg.sender];
        require(d > 0, "nothing deposited");
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(d * 2);
    }
}
"""

# The real thing: the ether leaves the Vault.
REAL = dict(
    deploy_code="Vault target = new Vault{value: 50 ether}();",
    attacker_code="""
contract Attacker {
    Vault v;
    constructor(address _v) { v = Vault(payable(_v)); }
    function attack() external { v.deposit{value: 9 ether}(); v.withdraw(); }
    receive() external payable {}
}
""",
    predicate="eth_profit",
    mode="contract",
    honest_body="target.deposit{value: 1 ether}(); target.withdraw();",
)

# The artefact: profit comes from a faucet the agent wrote and funded. The attacker really
# does end up richer than the control, and the contract under audit is untouched.
SCENERY = dict(
    deploy_code=(
        "Vault target = new Vault{value: 50 ether}();\n"
        "Faucet faucet = new Faucet{value: 30 ether}();"
    ),
    attacker_code="""
contract Faucet {
    constructor() payable {}
    function take(uint256 amount) external { payable(msg.sender).transfer(amount); }
}

contract Attacker {
    Vault v;
    constructor(address _v) { v = Vault(payable(_v)); }
    function attack() external { Faucet(payable(faucetAddr)).take(5 ether); }
    address public faucetAddr;
    function point(address f) external { faucetAddr = f; }
    receive() external payable {}
}
""",
    predicate="eth_profit",
    mode="contract",
    # Points the honest user at nothing, exactly as the measured false positive did.
    honest_body="target.deposit{value: 1 ether}();",
)


def probe(label: str, spec: dict, expect_pass: bool) -> bool:
    ws = Workspace(WS, label, TARGET)
    try:
        solidity = ws.compose_exploit(**spec)
        # The scenery case needs the attacker pointed at the faucet before it runs; the
        # harness composes deploy_code before the attacker exists, so wire it in here the
        # same way an agent would have to.
        if label == "scenery":
            solidity = solidity.replace(
                "        atk.attack();",
                "        atk.point(address(faucet));\n        atk.attack();",
            )
        ws.write_poc("Drain", solidity)
        build = ws.build()
        if not build.ok:
            errs = [ln.strip()[:110] for ln in build.combined.splitlines()
                    if "Error" in ln][:2]
            print(f"  [SETUP] {label:9s} did not compile: {errs}")
            return False
        run = ws.run_poc("DrainPoc")
        passed = "[PASS]" in run.combined
        reason = ""
        if not passed:
            for ln in run.combined.splitlines():
                if "ArbiterNotDrained" in ln or "ArbiterNoGain" in ln:
                    reason = ln.strip()[:90]
                    break
    finally:
        ws.cleanup()

    ok = passed == expect_pass
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:9s} "
          f"{'ACCEPTED' if passed else 'REFUSED '}  {reason}")
    return ok


def main() -> int:
    print("value must come out of the contract under audit, not out of scenery the")
    print("agent built for itself.\n")
    results = [
        probe("real", REAL, True),
        probe("scenery", SCENERY, False),
    ]
    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
