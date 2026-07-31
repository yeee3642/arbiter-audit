#!/usr/bin/env python3
"""What a failed attempt costs, and what it must still say.

The binding constraint is turns, not compilation. Three runs on the same forty samples
said so: removing compile errors put 33 of 40 samples on the turn ceiling and pushed
context per request from 15,037 to 21,441 tokens, and recall fell 0.450 -> 0.100 until
max_turns went 16 -> 26. So a failed attempt has to get CHEAPER, and every character the
harness returns is paid for twice -- once in the reply, then again in every later request
of the same conversation, because nothing trims the transcript.

Two cuts, and both are only allowed if nothing the agent needs goes with them:

  * the composed file. It used to come back whole on every compile failure, cut at 7000
    characters. That cut is about 150 lines and the composed file is longer, so in 49 of
    62 compile failures in `refixed2` the line solc actually named had already been
    dropped -- the listing was failing at its one job four times in five while costing
    the most of anything the harness returns. Now: the named lines with four lines of
    context each, at their true numbers.
  * the revert legends. Static prose explaining ArbiterNoHarm and ArbiterNoGain, appended
    in full to every failure. Said once per audit; the first copy is still in the
    transcript and nothing removes it.

Both directions, and forge runs, because a renderer that shows the wrong line is worse
than a long one:

  1. an error DEEP in the composed file -- past where the old cut fell -- is quoted, at
     its real line number, and the old renderer is shown to have missed it.
  2. an error in the agent's own attacker_code near the top is quoted too.
  3. an import the agent asked for and forge could not resolve is quoted at the line the
     HARNESS wrote it on.
  4. the compiler's own output is passed through untouched, forge's and solc's both.
  5. when the compiler names a line that is not in this file -- an error raised inside an
     import -- the WHOLE listing comes back, exactly as before. Cheaper is not worth
     being less informative.
  6. the legend is there the first time and gone the second, and the NUMBERS -- which are
     the per-attempt evidence, not prose -- are there both times.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.tools import (  # noqa: E402
    ToolDispatcher, _composed_view, _numbered_listing,
)
from arbiter.workspace import BuildUnavailable, Workspace  # noqa: E402

WS = Path("/tmp/economy-probe")

TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable { balanceOf[msg.sender] += msg.value; }

    function withdraw() external {
        uint256 a = balanceOf[msg.sender];
        require(a > 0, "nothing to withdraw");
        balanceOf[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
    }

    receive() external payable {}
}
"""

ATTACKER = """contract Attacker {
    Vault public v;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external { v.deposit{value: 1 ether}(); }
    receive() external payable {}
}"""

# The composed files in `refixed2` run to a median of 217 lines and 9,961 characters, and
# 90% of them are past the 7000-character cut the old listing was made with. A toy
# attacker would compose to about 135 lines and the cut would never bite, so the case that
# has to show the cut biting uses an attacker_code of the shape the runs actually
# contain: a mock, a helper and the Attacker itself.
ATTACKER_REALISTIC = """// The agent narrates its attacker, at length, and those comments are composed into the
// file along with everything else. They matter here for one reason: the old renderer cut
// the listing at 7000 CHARACTERS, not at a line count, so text the agent wrote near the
// top of its fragment bought down the number of lines that ever came back. A fragment of
// this shape -- three helper contracts and a paragraph explaining each -- is what the
// recorded runs contain, and it is why the cut landed short of the error in 49 of 62 of
// them.
//
// Plan: deposit as an ordinary user so the vault credits us, then re-enter through the
// helper's receive() while the vault is mid-transfer. The vault zeroes the balance
// before it sends, so the re-entry is expected to fail; the Griefer exists to hold the
// second identity, because a contract that keys its state by msg.sender treats a fresh
// address as a fresh depositor and one round of the trial is not enough to show that.
// The MockToken is scenery -- the vault under audit is ether-denominated, so the token
// is only here to stand in for the accounting the real protocol keeps alongside it, and
// nothing is ever drawn from it. Anything taken out of a mock the attacker deployed and
// funded is not a statement about the contract under audit, and the harness says so.
contract MockToken {
    string public name = "Mock";
    string public symbol = "MCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Helper {
    Vault public v;
    address public owner;
    uint256 public hops;

    constructor(address t) payable {
        v = Vault(payable(t));
        owner = msg.sender;
    }

    function prime() external payable {
        v.deposit{value: msg.value}();
    }

    function pull() external {
        require(msg.sender == owner, "owner");
        v.withdraw();
    }

    function sweep(address payable to) external {
        require(msg.sender == owner, "owner");
        to.transfer(address(this).balance);
    }

    receive() external payable {
        if (hops < 3 && address(v).balance >= 1 ether) {
            hops++;
            v.withdraw();
        }
    }
}

contract Griefer {
    Vault public v;
    address public owner;
    uint256 public seen;
    mapping(address => uint256) public credited;

    constructor(address t) {
        v = Vault(payable(t));
        owner = msg.sender;
    }

    function credit(address who, uint256 amount) external {
        require(msg.sender == owner, "owner");
        credited[who] += amount;
        seen++;
    }

    function debit(address who, uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(credited[who] >= amount, "credited");
        credited[who] -= amount;
    }

    function total(address who) external view returns (uint256) {
        return credited[who] + address(this).balance;
    }

    function poke() external payable {
        v.deposit{value: msg.value}();
        seen++;
    }

    receive() external payable {}
}

contract Attacker {
    Vault public v;
    MockToken public token;
    Helper public helper;
    Griefer public griefer;

    constructor(address t) payable {
        v = Vault(payable(t));
        token = new MockToken();
        helper = new Helper{value: 0}(t);
        griefer = new Griefer(t);
    }

    function attack() external {
        v.deposit{value: 1 ether}();
        v.withdraw();
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }

    function held() external view returns (uint256) {
        return v.balanceOf(address(this));
    }

    function heldBy(address who) external view returns (uint256) {
        return v.balanceOf(who);
    }

    function drain(address payable to) external {
        v.withdraw();
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}"""


def exploit(**over):
    args = dict(
        name="Econ",
        predicate="victim_loss",
        hypothesis="a hypothesis",
        mode="contract",
        deploy_code="        Vault target = new Vault();",
        victim_enter="        target.deposit{value: 5 ether}();",
        victim_exit="        target.withdraw();",
        attacker_code=ATTACKER,
    )
    args.update(over)
    return args


def solc_lines(reply: str) -> list[int]:
    """Line numbers solc named, read back out of the compiler output the reply carries."""
    body = reply.split("----- compiler output -----", 1)[-1]
    return sorted({int(m.group(2)) for m in re.finditer(r"-->\s+(\S+?):(\d+):\d+", body)
                   if m.group(1).endswith(".t.sol")})


def quoted_lines(reply: str) -> set[int]:
    """Line numbers the reply actually shows the agent."""
    view = reply.split("failed -----\n", 1)[-1].split("\n----- compiler output", 1)[0]
    return {int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\|", view, re.M)}


def main() -> int:
    ws = Workspace(WS, "economy", TARGET)
    disp = ToolDispatcher(ws)
    results: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, note: str) -> None:
        results.append((label, ok, note))

    # 1. An error deep in the composed file. `victim_exit` lands near the bottom, well
    #    past the 7000-character cut the old listing was made with.
    reply, _ = disp.dispatch("run_exploit", exploit(
        name="Deep",
        attacker_code=ATTACKER_REALISTIC,
        victim_exit="        target.wthdraw();"))     # deliberate typo, a Member error
    named, shown = solc_lines(reply), quoted_lines(reply)
    ok = bool(named) and set(named) <= shown
    check("deep error is quoted", ok,
          f"solc named {named}, reply shows {sorted(shown)[:6]}...")

    # The comparison that justifies the change: the renderer this replaced would have cut
    # those very lines off. Reconstructed from the same composed file, not asserted.
    poc = disp._poc_by_name["DeepExploitPoc"]
    old = _numbered_listing(poc.solidity.splitlines())[:7000]
    old_shown = {int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\|", old, re.M)}
    check("the old listing had dropped it", bool(named) and not set(named) <= old_shown,
          f"old listing reached line {max(old_shown)}, solc named {named}")
    check("and it is much shorter", len(reply) < len(old) // 2,
          f"reply {len(reply)} chars, old listing alone {len(old)}")

    # 2. An error in the agent's own attacker_code, near the top of the file.
    reply, _ = disp.dispatch("run_exploit", exploit(
        name="Top",
        attacker_code=ATTACKER.replace("v.deposit{value: 1 ether}();", "v.dpsit();")))
    named, shown = solc_lines(reply), quoted_lines(reply)
    check("error in attacker_code is quoted", bool(named) and set(named) <= shown,
          f"solc named {named}")

    # 3. An import the agent asked for and forge could not resolve. Worth its own case
    #    because the failure is nowhere near the agent's code: solc points at the import
    #    line, which the HARNESS wrote from the agent's `imports` argument, and that line
    #    is exactly what has to come back.
    reply, _ = disp.dispatch("run_exploit", exploit(
        name="NoLoc", imports=["@openzeppelin/contracts/token/ERC20/IERC20.sol"]))
    named, shown = solc_lines(reply), quoted_lines(reply)
    check("unresolved import is quoted at its line", bool(named) and set(named) <= shown,
          f"solc named {named}")

    # 4. The compiler's own output is not touched.
    check("compiler output passed through",
          "not found" in reply and "Unable to resolve imports" in reply,
          "solc's own text and forge's both survive")

    # 5. And the branch that has to stay expensive: when the compiler names a line but not
    #    one of OURS -- an error raised inside an import -- there is nothing to centre a
    #    window on, so the whole listing comes back exactly as it did before. Real
    #    compiler output from the run above, with the file it points at changed.
    poc = disp._poc_by_name["NoLocExploitPoc"]
    elsewhere = poc.output.replace("NoLocExploitPoc.t.sol", "Target.sol")
    view = _composed_view(poc.solidity, elsewhere, "NoLocExploitPoc")
    full = _numbered_listing(poc.solidity.splitlines())[:7000]
    check("a line in another file falls back whole", view == full,
          f"{len(view)} chars, the whole listing is {len(full)}")

    # 6. The legend is prose and the numbers are evidence. Say the prose once; say the
    #    numbers every time. Both of these compile and run, and both fail the predicate.
    first, _ = disp.dispatch("run_exploit", exploit(name="Harm1"))
    second, _ = disp.dispatch("run_exploit", exploit(name="Harm2"))
    legend = "'ArbiterNoHarm(withoutAttack, withAttack, attackerGain)'"
    check("legend the first time", legend in first, f"{len(first)} chars")
    check("not the second time", legend not in second, f"{len(second)} chars")
    check("but the numbers both times",
          "ArbiterNoHarm(" in first and "ArbiterNoHarm(" in second,
          "the revert reason is per-attempt evidence, so it always comes back")
    check("and the second reply is shorter", len(second) < len(first),
          f"{len(first)} -> {len(second)} chars")

    for label, ok, note in results:
        print(f"  [{'OK  ' if ok else 'WRONG'}] {label:38s} {note}")
    ws.cleanup()
    print(f"\n{sum(1 for _, ok, _ in results if ok)}/{len(results)} as expected")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    print("what a failed attempt costs, and what it must still say.\n")
    try:
        raise SystemExit(main())
    except BuildUnavailable:
        print("forge is not on PATH. This probe judges what comes back from a real "
              "compile and a real run, so without a compiler it would prove nothing.")
        raise SystemExit(2)
