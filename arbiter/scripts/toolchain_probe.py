#!/usr/bin/env python3
"""Can a missing compiler certify a contract as safe?

Found live, and not by reading. Driving ARBITER's own tools from another agent -- omp,
over MCP -- put the dispatch in a host that had not run `run.py`'s preflight. forge was
not on that process's PATH, so all three `run_exploit` calls raised `BuildUnavailable`,
`dispatch` caught it in the same generic handler it used for a bad argument, and the
agent was told `error: tool run_exploit raised BuildUnavailable`. It read that as the
tool being unavailable, wrote a lucid paragraph explaining that the contract DOES contain
an exploitable reentrancy, and called `conclude_safe`.

The verdict recorded was **safe**, on a contract this project's own loop breaks in three
turns. A tool that cannot execute answering "no problem" to everything is the exact
failure the whole architecture exists to prevent, and it was reachable from inside.

The preflight is not the fix. A preflight protects one entry point; this has to hold
wherever the tools are dispatched from. So the rule now lives with the verdict:

  1. `BuildUnavailable` is its own case in `dispatch`, not a generic tool crash.
  2. An attempt that never reached the compiler does NOT count as an attempt.
  3. `conclude_safe` with nothing ever compiled is refused, terminally, and the verdict
     is `no_verdict` -- "I do not know", never "safe".

And the direction that matters just as much, because a gate that only ever says no is not
a gate:

  4. With forge present and an exploit that genuinely failed, `conclude_safe` is still
     ACCEPTED and still records `safe`. Failing to break a contract is evidence.
  5. With forge present and no attempt at all, the old refusal-once behaviour is intact.

Needs forge. Case 4 is the whole reason.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.tools import ToolDispatcher  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

WS = Path("/tmp/toolchain-probe")

TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = bal[msg.sender];
        require(a > 0, "nothing");
        bal[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
    }
    receive() external payable {}
}
"""

EXPLOIT = dict(
    name="probe",
    predicate="victim_loss",
    deploy_code="        Vault target = new Vault();",
    victim_enter="        target.deposit{value: 5 ether}();",
    victim_exit="        target.withdraw();",
    attacker_code="""contract Attacker {
    Vault public v;
    uint256 hops;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external { v.deposit{value: 1 ether}(); v.withdraw(); }
    receive() external payable { if (hops < 3) { hops++; v.withdraw(); } }
}""",
    hypothesis="reentrancy on withdraw",
)

SAFE = dict(reason="the state write precedes the call", guards_verified=[],
            hypotheses_tested=["reentrancy on withdraw"])


class NoForge:
    """PATH with every directory holding a forge removed."""

    def __enter__(self):
        self.old = os.environ.get("PATH", "")
        keep = [d for d in self.old.split(os.pathsep)
                if d and not (Path(d) / "forge").exists()]
        os.environ["PATH"] = os.pathsep.join(keep)
        return self

    def __exit__(self, *a):
        os.environ["PATH"] = self.old


def main() -> int:
    print("a missing compiler must not be able to certify anything.\n")
    results = []

    def check(label: str, ok: bool, note: str) -> None:
        results.append(ok)
        print(f"  [{'OK  ' if ok else 'WRONG'}] {label:38s} {note}")

    # -- forge gone -------------------------------------------------------------
    with NoForge():
        ws = Workspace(WS, "down", TARGET)
        d = ToolDispatcher(ws)
        text, terminal = d.dispatch("run_exploit", EXPLOIT)
        check("exploit names the missing compiler",
              "TOOLCHAIN UNAVAILABLE" in text and not terminal,
              text.split(":")[0][:38])
        check("it does not count as an attempt",
              d._exploit_calls == 0 and d._toolchain_failures == 1,
              f"calls={d._exploit_calls} failures={d._toolchain_failures}")

        text, terminal = d.dispatch("conclude_safe", SAFE)
        check("safe is refused, terminally",
              terminal and d.outcome.verdict == "no_verdict"
              and d.outcome.stop_reason == "toolchain_unavailable",
              f"verdict={d.outcome.verdict} stop={d.outcome.stop_reason}")
        ws.cleanup()

    # -- forge back -------------------------------------------------------------
    ws = Workspace(WS, "up", TARGET)
    d = ToolDispatcher(ws)
    text, _ = d.dispatch("conclude_safe", SAFE)
    check("untested safe still refused once",
          "NOT YET" in text and d.outcome.verdict != "safe",
          text.split(".")[0][:38])

    text, _ = d.dispatch("run_exploit", EXPLOIT)
    reached = d._reached_toolchain == 1 and d._toolchain_failures == 0
    check("a real attempt reaches the compiler", reached,
          f"reached={d._reached_toolchain} failures={d._toolchain_failures}")

    text, terminal = d.dispatch("conclude_safe", SAFE)
    check("safe accepted once something ran",
          terminal and d.outcome.verdict == "safe",
          f"verdict={d.outcome.verdict} stop={d.outcome.stop_reason}")
    ws.cleanup()

    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
