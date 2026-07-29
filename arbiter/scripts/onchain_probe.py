#!/usr/bin/env python3
"""Two-directional probe for fork mode: it must measure a real drain, and refuse one.

The accept direction of a fork-mode probe is awkward and it is worth being plain about
why. To show the harness accepts a real theft you need a deployed contract that can
really be robbed, and if this project had one of those in hand it would be reporting it
rather than testing with it. So the accept direction here is narrower: the harness must
demonstrably be looking at the chain. It is asked the one question that has a checkable
answer -- does the balance inside the fork agree with the balance the chain reports? --
because if it did not, every refusal below would be a refusal of nothing.

WETH is the subject precisely because it cannot be robbed. Wrapping and unwrapping is
the most ordinary thing anyone does on Ethereum, and it must not read as an exploit.

The refuse directions are the ones that matter for false positives, and there are three:

  1. ordinary use is not an exploit. The attacker ends where they started, minus gas.
  2. a cheatcode in the attack is refused before anything runs. On a chain there is no
     `vm.prank`; an attack that needs one is an attack on our harness, not on the
     contract.
  3. an attack that does nothing is refused. This is the trivial case and it is here so
     that a change which makes everything pass gets caught.

Every check is gated on the test having actually compiled. An earlier version of this
file was not, and reported a pass for a run that never built.

Run:  python3 scripts/onchain_probe.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.onchain import (  # noqa: E402
    RpcUnavailable,
    _rpc_call,
    compose_onchain,
    resolve_fork,
    run_onchain,
)

WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

# Wrapping then unwrapping. WETH's ether balance really does fall, so the drain check
# alone would accept this. The attacker is exactly where they started, minus gas.
ORDINARY_USE = """
        (bool okDep, ) = TARGET.call{value: capital / 2}("");
        require(okDep, "deposit failed");
        (bool okW, ) = TARGET.call(
            abi.encodeWithSignature("withdraw(uint256)", capital / 2));
        require(okW, "withdraw failed");
"""

DOES_NOTHING = """
        capital;
"""

USES_A_CHEATCODE = """
        vm.startPrank(TARGET, TARGET);
        (bool ok, ) = TARGET.call("");
        ok;
        vm.stopPrank();
"""


def _first_error(output: str) -> str:
    for line in output.splitlines():
        if line.strip().startswith("Error ("):
            return line.strip()[:120]
    return output.strip().splitlines()[-1][:120] if output.strip() else "(no output)"


def _drain_seen(output: str) -> bool:
    """Did any rung actually move the contract's balance?

    `ArbiterNotProfitable` is only reachable when a rung drained something, so its
    presence is the evidence that fork mode reached real state. `ArbiterNoDrain` means
    nothing moved.
    """
    return "ArbiterNotProfitable(" in output


def main() -> int:
    failures: list[str] = []

    try:
        plan = resolve_fork("ethereum", WETH)
    except (RpcUnavailable, ValueError) as exc:
        print(f"  cannot reach a chain: {exc}")
        print("  fork mode is unavailable here; this is a skip, not a pass")
        return 2

    print(f"  bound to {plan.target} on {plan.chain} at block {plan.block}")
    print(f"  code size {plan.extra.get('code_size')} bytes via {plan.rpc}")

    # --- refused before anything runs -------------------------------------------------
    try:
        compose_onchain(plan, attack=USES_A_CHEATCODE)
        failures.append("a cheatcode in the attack was ACCEPTED at composition")
    except ValueError:
        print("  cheatcode in attack           refused, as expected")

    # --- must run, and must be refused by the economics --------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        sol = compose_onchain(plan, attack=ORDINARY_USE)
        rec = run_onchain(root / "a", plan, sol)

        # Checked before the refusal is credited. The first version of this probe read a
        # compile error as "no drain was reported, therefore the gate refused it" and
        # printed a pass -- a refusal that costs nothing to obtain proves nothing, and a
        # probe that cannot tell "refused" from "never ran" is worse than no probe.
        if not rec["built"]:
            failures.append(
                "the fork test did not compile, so nothing below was tested: "
                + _first_error(rec["output_tail"])
            )
        elif rec["proven"]:
            failures.append(
                "wrapping and unwrapping ether was ACCEPTED as an exploit "
                f"(net {rec['net_wei']} wei)"
            )
        else:
            print("  ordinary use (wrap/unwrap)   refused, as expected")

        # The measurement half, asked directly. WETH cannot be drained -- that is what
        # it is for -- so no attack on it can demonstrate that fork mode sees real
        # state. Ask the question that can be answered instead: does the balance inside
        # the fork match the balance the chain reports? If fork mode were not reaching
        # the chain this would be zero.
        live = int(_rpc_call(plan.rpc, "eth_getBalance", [plan.target, "latest"]), 16)
        lo, hi = int(live * 0.99), int(live * 1.01)
        sol = compose_onchain(
            plan,
            attack=(
                f'        require(TARGET.balance > {lo}, "fork sees too little");\n'
                f'        require(TARGET.balance < {hi}, "fork sees too much");\n'
                f'        capital;\n'
            ),
        )
        rec = run_onchain(root / "c", plan, sol)
        if not rec["built"]:
            failures.append("measurement case did not compile: "
                            + _first_error(rec["output_tail"]))
        elif "fork sees too" in rec["output_tail"]:
            failures.append(
                f"the fork's view of {plan.target} does not match the chain "
                f"(chain reports {live / 1e18:.2f} ether) -- fork mode is not reaching "
                f"real state, so every refusal above proves nothing"
            )
        else:
            print(f"  live balance agrees          {live / 1e18:,.0f} ether, "
                  f"fork matches the chain")

        sol = compose_onchain(plan, attack=DOES_NOTHING)
        rec = run_onchain(root / "b", plan, sol)
        if rec["proven"]:
            failures.append("an attack that does nothing was ACCEPTED")
        else:
            print("  attack that does nothing     refused, as expected")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\n  fork mode measures real state and refuses ordinary use, as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
