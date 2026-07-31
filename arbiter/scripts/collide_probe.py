#!/usr/bin/env python3
"""Does a name the agent declares survive contact with a target that declares it too?

`import "../src/Target.sol"` is unnamed, so every top-level declaration in the target is
in scope. Nine of the thirty-five vulnerable samples declare `IERC20` themselves, and the
census of one broad run says what that cost:

    41  Identifier already declared.
    22  Explicit type conversion from "contract MockERC20"
    19  Explicit type conversion from "contract IERC20"

Eighty-two compile failures, not one of them about the attack. The fix is a rename rather
than a refusal, because an interface is structural: `IERC20_arb` and `IERC20` describe the
same calls, so a cast through either means the same thing, and a refusal would spend a
turn saying so.

A rename is a rewrite of somebody else's text, so it has to be checked in BOTH
directions -- what it must rewrite, and everything it must leave alone:

  1. A name the agent DECLARES and the target also declares  -> renamed, and it COMPILES.
  2. A name the agent only REFERENCES                        -> untouched. The cast still
     points at the target's type, which is where the agent aimed it.
  3. A `struct` nested inside the target's contract          -> not file scope, so an
     agent's top-level struct of the same name is not colliding and is not renamed.
  4. `Attacker`                                              -> never renamed, whatever
     the target declares; the setup template writes `new Attacker(...)` verbatim.
  5. The name inside a comment or a revert string            -> left exactly as written.

And three unrelated repairs that share a cause with it -- the harness fails the agent at a
line the agent did not write:

  6. The assertion family (`assertEq`, `assertGt`, ...) resolves, in the test AND inside
     an Attacker, which inherits nothing.
  7. `address[] memory users = ...` in deploy_code is hoisted, so a later reference to
     `users` resolves. The victim path learned this; deploy_code had been left behind.
  8. A `storage` pointer in deploy_code is REFUSED at composition with the line quoted,
     rather than deep-copied into a state variable behind the agent's back.

Needs forge: every case above composed fine before this change and then died at solc, so
a composition-only check would pass while proving nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.workspace import BuildUnavailable, Workspace  # noqa: E402

WS = Path("/tmp/collide-probe")

# Declares IERC20 at file scope and Position INSIDE the contract. Both names are then
# reachable in a PoC by the same unnamed import, but only one of them is a collision.
TARGET = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract Vault {
    struct Position { uint256 amount; }
    struct Conf { uint256 cap; }
    mapping(address => Position) public positions;

    /// A struct-returning getter, so a fragment can legally write the one shape neither
    /// hoisting regex could see: a CONTRACT-QUALIFIED type, `Vault.Conf memory c = ...`.
    function conf() external pure returns (Conf memory) { return Conf(100 ether); }

    function deposit() external payable { positions[msg.sender].amount += msg.value; }

    /// The state write lands after the call, so a reentrant caller is paid twice.
    function withdraw() external {
        uint256 a = positions[msg.sender].amount;
        require(a > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
        positions[msg.sender].amount = 0;
    }

    receive() external payable {}
}
"""

DEPLOY = "        Vault target = new Vault();"
ENTER = "        target.deposit{value: 5 ether}();"
EXIT = "        target.withdraw();"

REENTER = """contract Attacker {
    Vault public v;
    uint256 hops;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external {
        v.deposit{value: 1 ether}();
        v.withdraw();
    }
    receive() external payable {
        if (hops < 4 && address(v).balance >= 1 ether) { hops++; v.withdraw(); }
    }
}"""


def case(**over):
    spec = dict(deploy_code=DEPLOY, victim_enter=ENTER, victim_exit=EXIT,
                attacker_code=REENTER, mode="contract")
    spec.update(over)
    return spec


# (label, spec, must_compose, expected renames or None to skip the check)
CASES = [
    ("declared collision renamed", case(attacker_code="""interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract Attacker {
    Vault public v;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external {
        IERC20 t = IERC20(address(v));
        t.balanceOf(address(this));
        v.deposit{value: 1 ether}();
    }
    receive() external payable {}
}"""), True, ["IERC20"]),

    ("reference only, untouched", case(attacker_code="""contract Attacker {
    Vault public v;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external {
        IERC20 t = IERC20(address(v));
        t.balanceOf(address(this));
        v.deposit{value: 1 ether}();
    }
    receive() external payable {}
}"""), True, []),

    ("nested struct is not a clash", case(attacker_code="""struct Position { uint256 slot; }

contract Attacker {
    Vault public v;
    Position p;
    constructor(address t) payable { v = Vault(payable(t)); p.slot = 1; }
    function attack() external { v.deposit{value: 1 ether}(); }
    receive() external payable {}
}"""), True, []),

    ("Attacker never renamed", case(), True, []),

    ("comments and strings intact", case(attacker_code="""interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract Attacker {
    Vault public v;
    // IERC20 is named here on purpose and must survive verbatim.
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external {
        require(address(v) != address(0), "IERC20 missing");
        IERC20(address(v)).balanceOf(address(this));
        v.deposit{value: 1 ether}();
    }
    receive() external payable {}
}"""), True, ["IERC20"]),

    ("assertions resolve everywhere", case(attacker_code="""contract Attacker {
    Vault public v;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external {
        assertGt(address(v).balance, 0, "target should hold something");
        v.deposit{value: 1 ether}();
        assertEq(address(this).balance > 0, true);
        assertTrue(address(v) != address(0));
    }
    receive() external payable {}
}"""), True, []),

    # The reference has to be in a LATER stage. A first cut of this case declared and used
    # `users` inside deploy_code alone, which compiles whether or not the declaration was
    # hoisted -- it passed against the unfixed harness and proved nothing. Every stage is a
    # separate external call, so only a reference from another one can tell the difference.
    ("memory decl in deploy hoisted", case(
        deploy_code="""        Vault target = new Vault();
        address[] memory users = new address[](2);
        users[0] = address(this);""",
        victim_exit="""        require(users.length == 2, "users did not survive the stage");
        target.withdraw();""",
        attacker_code=REENTER), True, []),

    ("storage decl refused", case(
        deploy_code="""        Vault target = new Vault();
        Vault storage held = target;"""), False, None),

    # `(bool ok, ) = addr.call{value: v}("")` is how Solidity sends ether, so a victim
    # whose entry is a low-level call declares its name inside a tuple -- which hoisting
    # could not see at all. One of the benchmark's own reference exploits is unbuildable
    # for this and nothing else.
    ("tuple decl survives a stage", case(
        victim_enter="""        (bool okDep, ) = address(target).call{value: 5 ether}(
            abi.encodeWithSignature("deposit()"));
        require(okDep, "deposit failed");""",
        victim_exit="""        require(okDep, "the tuple name did not survive the stage");
        target.withdraw();"""), True, []),

    # And the half that must NOT change: mixed tuple declaration and assignment has been
    # illegal since 0.5.0, so a tuple with a reference-typed component has to be left as
    # written. It stays a local, exactly as it did before.
    ("tuple with bytes left alone", case(
        victim_enter="""        (bool okDep, bytes memory ret) = address(target).call{value: 5 ether}(
            abi.encodeWithSignature("deposit()"));
        require(okDep && ret.length == 0, "deposit failed");"""), True, []),

    # D9. An Attacker inherits nothing, and everyone writing Foundry writes `vm.warp`.
    # The file-level constant used to be spelt `vm_`, so this came back as
    # `Undeclared identifier. Did you mean "Vm"?` -- 42 in one 40-sample run, the largest
    # named class left once the assert family existed.
    ("vm reaches inside an Attacker", case(attacker_code="""contract Attacker {
    Vault public v;
    constructor(address t) payable { v = Vault(payable(t)); }
    function attack() external {
        vm.warp(block.timestamp + 1 days);
        v.deposit{value: 1 ether}();
    }
    receive() external payable {}
}"""), True, []),

    # D10. `hoist_declarations` decided what to LIFT with a keyword skip list and then
    # rewrote every match regardless, so a declaration it refused to lift still had its
    # type deleted. `uint`, `int` and `bool` were on that list -- so `uint256 n = 1` was
    # hoisted and `uint n = 1` became an assignment to a name nothing declared.
    ("bool decl in deploy hoisted", case(
        deploy_code="""        Vault target = new Vault();
        bool primed = true;""",
        victim_exit="""        require(primed, "the bool did not survive the stage");
        target.withdraw();"""), True, []),

    ("uint decl in deploy hoisted", case(
        deploy_code="""        Vault target = new Vault();
        uint seats = 2;
        int drift = -1;""",
        victim_exit="""        require(seats == 2 && drift == -1, "the ints did not survive");
        target.withdraw();"""), True, []),

    # The other half of D10, and the one that does NOT announce itself. `else flag = x;`
    # matched `Type name =` with `else` in the type slot. The scan skipped it and the
    # rewrite did not, so the `else` was DELETED and the branch became unconditional --
    # code that still compiles and no longer means what the agent wrote. A build check
    # cannot see this, so the probe reads the composed text.
    ("else survives, undeleted", case(
        victim_enter="""        bool flag = false;
        if (address(target).balance > 100 ether) flag = true;
        else flag = false;
        target.deposit{value: 5 ether}();""",
        victim_exit="""        require(!flag, "flag did not survive the stage");
        target.withdraw();"""), True, []),

    # D11. The two hoisting patterns had drifted apart: `DECL_RE` learned about `payable`
    # and `VICTIM_DECL_RE` never did, so the same declaration was lifted out of deploy_code
    # and left a local in victim_enter.
    ("address payable in victim enter", case(
        victim_enter="""        address payable sink = payable(address(0xBEEF));
        target.deposit{value: 5 ether}();""",
        victim_exit="""        require(sink != address(0), "the payable did not survive");
        target.withdraw();"""), True, []),

    # D12. Neither pattern admitted a dot, so `Vault.Conf memory c = target.conf();` --
    # the ordinary way to read a struct-returning getter -- was invisible to both.
    ("qualified type hoisted", case(
        deploy_code="""        Vault target = new Vault();
        Vault.Conf memory c = target.conf();""",
        victim_exit="""        require(c.cap == 100 ether, "the struct did not survive the stage");
        target.withdraw();"""), True, []),

    # And its control. Admitting a dot must not turn a member ASSIGNMENT into a
    # declaration: `pos.amount = 1;` is not `Type name =` and has to reach solc verbatim.
    ("member assignment left alone", case(
        deploy_code="""        Vault target = new Vault();
        Vault.Conf memory c = target.conf();
        c.cap = 7;""",
        victim_exit="""        require(c.cap == 7, "the member write was lost");
        target.withdraw();"""), True, []),
]


# A case whose damage is a SILENT rewrite rather than a compile error needs the composed
# text read back; a build alone would pass while the meaning had changed underneath.
def _else_intact(sol: str) -> str:
    return "" if re.search(r"^\s*else\s+arbv_flag\s*=", sol, re.M) else (
        "built, but the `else` was deleted from the victim's branch")


def _member_write_intact(sol: str) -> str:
    return "" if re.search(r"^\s*c\.cap\s*=\s*7;", sol, re.M) else (
        "built, but `c.cap = 7;` was rewritten as if it were a declaration")


def _comment_and_string_intact(sol: str) -> str:
    return "" if ('"IERC20 missing"' in sol and "// IERC20 is named here" in sol) else (
        "built but the rename reached a comment or a string")


TEXT_CHECKS = {
    "comments and strings intact": _comment_and_string_intact,
    "else survives, undeleted": _else_intact,
    "member assignment left alone": _member_write_intact,
}


def main() -> int:
    print("a name the agent declares, against a target that declares it too.\n")
    ws = Workspace(WS, "collide", TARGET)
    results = []
    for label, spec, must_compose, want_renamed in CASES:
        note = ""
        sol = ""
        try:
            sol = ws.compose_victim_loss(**spec)
            # getattr, so this same probe still runs against a harness from before the
            # rename existed. That is the only way it can show what it repaired.
            composed, got = True, list(getattr(ws, "renamed", []))
        except ValueError as exc:
            composed, got = False, []
            note = str(exc).splitlines()[0][:52]

        ok = composed == must_compose
        if composed and must_compose:
            # The whole point: every one of these composed before this change too, and
            # then died at solc. Build it, always, before judging anything else.
            ws.write_poc("Collide", sol)
            build = ws.build()
            if not build.ok:
                ok = False
                note = _first_solc_error(build.combined)
            else:
                note = f"built; renamed {got or '[]'}"
                if want_renamed is not None and got != want_renamed:
                    ok = False
                    note = f"built, but renamed {got}, expected {want_renamed}"
                elif label in TEXT_CHECKS:
                    # Building is not enough for these: the damage they guard against is a
                    # silent rewrite that still compiles.
                    complaint = TEXT_CHECKS[label](sol)
                    ok = not complaint
                    note = complaint or "built, and the text survived verbatim"

        results.append(ok)
        state = "composed" if composed else "REFUSED "
        print(f"  [{'OK  ' if ok else 'WRONG'}] {label:31s} {state}  {note}")

    ws.cleanup()
    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


def _first_solc_error(output: str) -> str:
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Error") and "Compiler run failed" not in line:
            return line[:70]
    return output.strip().splitlines()[-1][:70] if output.strip() else "build failed"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildUnavailable:
        print("forge is not on PATH. Every case here composed before this change and then "
              "failed at solc, so a run without a compiler would pass and prove nothing.")
        raise SystemExit(2)
