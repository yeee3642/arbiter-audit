#!/usr/bin/env python3
"""Does the environment sweep find real attacks without inventing fake ones?

Two properties, and both must hold:

  1. An attack that only pays at scale -- a one-wei-per-round bias, invisible in a single
     trip -- must be FOUND. This is the whole point: the endowment, the clock and the
     number of rounds were never the model's to choose, so charging its hypothesis with a
     failure caused by them is charging it for the harness's decision.
  2. The same sweep against a PATCHED contract must still find nothing. The knobs are
     applied to the honest baseline too, so a sweep can only surface an asymmetry that
     was already there. If it can manufacture one, it is worthless.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))

from arbiter.workspace import DEFAULT_SWEEP, Workspace  # noqa: E402

WS = Path("/tmp/sweep-probe")

# A lender that forgets to record debt, so collateral can be borrowed against and then
# withdrawn in full. The attack is only worth anything at scale -- it needs a thousand
# ether of collateral to move, which the harness's default ten-ether endowment cannot
# reach. That is the case the sweep exists for: right mechanism, unreachable magnitude.
VULN = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Lender {
    mapping(address => uint256) public collateral;
    constructor() payable {}

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    // BUG: the loan is paid out but never recorded, so the collateral is still free.
    function borrow(uint256 amount) external {
        require(amount <= collateral[msg.sender], "undercollateralised");
        payable(msg.sender).transfer(amount);
    }

    function withdrawCollateral() external {
        uint256 c = collateral[msg.sender];
        collateral[msg.sender] = 0;
        payable(msg.sender).transfer(c);
    }
}
"""

SAFE = (
    VULN.replace(
        "    // BUG: the loan is paid out but never recorded, so the collateral is still free.\n"
        "    function borrow(uint256 amount) external {\n"
        "        require(amount <= collateral[msg.sender], \"undercollateralised\");\n"
        "        payable(msg.sender).transfer(amount);\n"
        "    }",
        "    mapping(address => uint256) public debt;\n\n"
        "    function borrow(uint256 amount) external {\n"
        "        require(amount + debt[msg.sender] <= collateral[msg.sender], \"undercollateralised\");\n"
        "        debt[msg.sender] += amount;\n"
        "        payable(msg.sender).transfer(amount);\n"
        "    }",
    ).replace(
        "        uint256 c = collateral[msg.sender];",
        "        require(debt[msg.sender] == 0, \"repay first\");\n"
        "        uint256 c = collateral[msg.sender];",
    )
)

ATTACK = dict(
    deploy_code="Lender target = new Lender{value: 2000 ether}();",
    attacker_code="",
    mode="eoa",
    attack_body=(
        "target.depositCollateral{value: 1000 ether}();\n"
        "target.borrow(1000 ether);\n"
        "target.withdrawCollateral();"
    ),
    honest_body=(
        "target.depositCollateral{value: 1 ether}();\n"
        "target.withdrawCollateral();"
    ),
    predicate="eth_profit",
)


def probe(label: str, source: str, expect_found: bool) -> bool:
    ws = Workspace(WS, label, source)
    try:
        base = ws.compose_exploit(**ATTACK)
        ws.write_poc("Base", base)
        if not ws.build().ok:
            print(f"  [SETUP] {label:10s} base exploit did not compile")
            return False
        base_run = ws.run_poc("BasePoc")
        base_passed = "[PASS]" in base_run.combined

        solidity, grid = ws.compose_sweep(**ATTACK)
        ws.write_poc("Sweep", solidity)
        if not ws.build().ok:
            errs = [ln.strip() for ln in ws.build().combined.splitlines()
                    if "Error" in ln][:2]
            print(f"  [SETUP] {label:10s} sweep did not compile: {errs}")
            return False
        run = ws.run_poc("SweepPoc")
        winners = ws.passing_sweep_variants(run.combined)
    finally:
        ws.cleanup()

    found = bool(winners)
    ok = found == expect_found
    detail = (
        f"variants {winners} of {len(DEFAULT_SWEEP)}"
        + (f" -> first is endow={grid[winners[0]][0]} reps={grid[winners[0]][1]}"
           if winners else "")
    )
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:10s} base={'PASS' if base_passed else 'fail'}"
          f"  sweep={detail}")
    return ok


def main() -> int:
    print("environment sweep: right mechanism at the wrong scale must be found,")
    print("and the same sweep must still refuse a patched contract.\n")
    results = [
        probe("vulnerable", VULN, True),
        probe("patched", SAFE, False),
    ]
    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
