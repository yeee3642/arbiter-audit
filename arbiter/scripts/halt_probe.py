#!/usr/bin/env python3
"""Can an exploit pass by escaping the predicate instead of satisfying it?

Measured on a real repository, auditing axelar's DepositHandler: the setup contained
`selfdestruct(payable(address(target)))`. SELFDESTRUCT halts execution and returns
success, so every harness check below that line was skipped and forge printed [PASS].
The predicate had not been satisfied. It had never run.

Three properties:

  1. selfdestruct in an agent-supplied fragment is REFUSED with an explanation, and the
     technique that does work -- a helper contract -- is named.
  2. Even if a halt reaches the EVM by some other route, the test FAILS, because the
     exploit body must return a sentinel the harness checks.
  3. A normal exploit is unaffected.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.workspace import Workspace  # noqa: E402

WS = Path("/tmp/halt-probe")

TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public deposits;
    constructor() payable {}
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 d = deposits[msg.sender];
        require(d > 0, "nothing deposited");
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(d * 2);
    }
}
"""

GOOD = dict(
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

# The measured escape, verbatim in shape: halt the test in setup.
HALTING = dict(GOOD, deploy_code=(
    "Vault target = new Vault{value: 50 ether}();\n"
    "selfdestruct(payable(address(target)));"
))


def probe(label: str, spec: dict, expect: str) -> bool:
    ws = Workspace(WS, label, TARGET)
    got = ""
    detail = ""
    try:
        try:
            solidity = ws.compose_exploit(**spec)
        except ValueError as exc:
            got, detail = "refused", str(exc).splitlines()[0][:80]
        else:
            ws.write_poc("Halt", solidity)
            if not ws.build().ok:
                got, detail = "nobuild", ""
            else:
                run = ws.run_poc("HaltPoc")
                got = "accepted" if "[PASS]" in run.combined else "failed"
                hit = re.search(r"(ARBITER:[^\"']{0,70})", run.combined)
                detail = hit.group(1) if hit else ""
    finally:
        ws.cleanup()
    ok = got == expect
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:22s} {got:9s} {detail}")
    return ok


def main() -> int:
    print("an exploit must SATISFY the predicate, not escape it.\n")
    results = [
        probe("normal exploit", GOOD, "accepted"),
        probe("selfdestruct in setup", HALTING, "refused"),
    ]

    # Property 2: the sentinel must hold even with the lint bypassed, since the lint is a
    # message and the sentinel is the guarantee.
    print("\n  with the lint bypassed, the sentinel alone must still refuse it:")
    ws = Workspace(WS, "sentinel", TARGET)
    try:
        solidity = ws.compose_exploit(**GOOD).replace(
            "        Vault target = new Vault{value: 50 ether}();",
            "        Vault target = new Vault{value: 50 ether}();\n"
            "        selfdestruct(payable(address(target)));",
        )
        ws.write_poc("Sentinel", solidity)
        built = ws.build().ok
        run = ws.run_poc("SentinelPoc") if built else None
        passed = bool(run and "[PASS]" in run.combined)
    finally:
        ws.cleanup()
    ok = built and not passed
    print(f"  [{'OK  ' if ok else 'WRONG'}] {'sentinel':22s} "
          f"{'accepted' if passed else 'failed'}")
    results.append(ok)

    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
