#!/usr/bin/env python3
"""The conservation clause must count what the attacker actually kept.

`gain` is the left-hand side of `attackerGain >= shortfall`, the clause that makes
victim_loss mean *the attacker is holding what the victim lost* rather than merely
*something bad happened*. It used to be a sum of per-round deltas, each floored at zero,
against an attacker that was redeployed and re-funded on every round. Both halves of
that are wrong in the same direction:

    accepted   an attacker that alternates -- take one ether, then give one back --
               ends every trial exactly where it started. Floored per round, the giving
               rounds contribute nothing and the taking rounds contribute one each, so
               eight rounds reported four ether of profit against a true net of zero.

    lost       an attacker that accumulates across rounds could not, because each round
               got a fresh one. Per-round rounding bias -- the only reason the
               eight-round environment exists at all -- was structurally unprovable.

So the probe runs both shapes and reads the number the harness itself reports.

    churn        must report gain 0.  Under the old accounting it reported four ether.
    accumulate   must report gain > 0. Under the old accounting it reported zero,
                 because the attacker holding the proceeds was thrown away each round.

Run:  python3 scripts/gain_probe.py
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import arbiter.workspace as _ws  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

# The two accountings only differ across rounds, and the harness reports the first
# environment that ran -- which has rounds=1, where a churn is indistinguishable from a
# single honest take. So the sweep is pinned to the eight-round environment for the
# duration of this probe. That is the axis under test; the others are not.
_ws.VICTIM_ENVIRONMENTS = [(10**19, 0, 8)]

# A pot anyone may pay into and anyone may take from, with a latch so an attacker can
# tell which move it is on. Nothing here is a vulnerability; it exists so the two
# attacker shapes below are expressible.
TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

contract Pot {
    bool public taken;
    mapping(address => uint256) public paid;

    function deposit() external payable { paid[msg.sender] += msg.value; taken = false; }

    function take(uint256 amount) external {
        require(address(this).balance >= amount, "empty");
        taken = true;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function withdraw() external {
        uint256 owed = paid[msg.sender];
        paid[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: owed}("");
        require(ok, "withdraw failed");
    }

    receive() external payable {}
}
"""

# Ends every trial where it began. Any accounting that reports a profit here is counting
# the same ether more than once.
CHURN = """contract Attacker {
    Pot t;
    constructor(address _t) payable { t = Pot(payable(_t)); }
    function attack() external {
        if (t.taken()) { t.deposit{value: 1 ether}(); }
        else { t.take(1 ether); }
    }
    receive() external payable {}
}"""

# Takes a little every round and keeps it. Only provable if the attacker survives
# between rounds.
ACCUMULATE = """contract Attacker {
    Pot t;
    constructor(address _t) payable { t = Pot(payable(_t)); }
    function attack() external { t.take(1 ether); }
    receive() external payable {}
}"""

DEPLOY = "Pot target = new Pot();"
ENTER = "target.deposit{value: 8 ether}();"
EXIT = "target.withdraw();"

# ArbiterNoHarm(recoveredWithoutAttack, recoveredWithAttack, attackerGain)
NOHARM_RE = re.compile(r"ArbiterNoHarm\((\d+)[^,]*,\s*(\d+)[^,]*,\s*(\d+)")
ETHER = 10**18


def _gain(ws: Workspace, attacker: str, name: str) -> int | None:
    """Compose, run, and read back the gain the harness computed. None if it passed."""
    solidity = ws.compose_victim_loss(
        deploy_code=DEPLOY, victim_enter=ENTER, victim_exit=EXIT,
        attacker_code=attacker, mode="contract",
    )
    poc = ws.write_poc(name, solidity)
    build = ws.build()
    if not build.ok:
        raise RuntimeError(f"{name} did not compile: {build.output[-300:]}")
    out = ws.run_poc(poc).combined
    m = NOHARM_RE.search(out)
    if m:
        return int(m.group(3))
    if any(l.strip().startswith("[PASS]") for l in out.splitlines()):
        return None          # the predicate was satisfied; gain covered the shortfall
    raise RuntimeError(f"{name}: neither a verdict nor a gain in the output:\n{out[-400:]}")


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        ws = Workspace(Path(tmp), "gain", TARGET)
        try:
            churn = _gain(ws, CHURN, "Churn")
            if churn is None:
                failures.append(
                    "the churn attack SATISFIED the predicate -- value that never left "
                    "the attacker's own hands was counted as taken from the victim"
                )
            elif churn > 0:
                failures.append(
                    f"churn reported {churn / ETHER:g} ether of gain over eight rounds; "
                    f"it ends where it started, so the only correct answer is 0"
                )
            else:
                print("  churn        gain 0, as expected")

            acc = _gain(ws, ACCUMULATE, "Accumulate")
            if acc is None:
                print("  accumulate   predicate satisfied, as expected")
            elif acc > 0:
                print(f"  accumulate   gain {acc / ETHER:g} ether, as expected")
            else:
                failures.append(
                    "the accumulating attack reported no gain at all -- it took ether "
                    "every round and kept it, so the attacker is not surviving between "
                    "rounds"
                )
        finally:
            ws.cleanup()

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\n2/2 as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
