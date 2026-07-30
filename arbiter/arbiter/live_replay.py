"""Replay a proven exploit as real transactions, and see how many survive the trip.

`live.py` gave one hand-written scenario to a chain. This does it for exploits the
harness already proved, without rewriting them: the dumped proof-of-concept is parsed
back into its parts and those parts are redeployed as three actors with keys.

The translation, and what it costs.

    the test contract        ->  ArbWorld, deployed by the victim's own account.
                                 It holds the same state declarations, runs the same
                                 setup in its constructor, and exposes enter() and
                                 exit() -- so the victim is an account that took a
                                 position, not an address the harness pranked.

    arbAttack()              ->  the Attacker contract verbatim, deployed by the
                                 attacker's account through a factory, and driven by a
                                 transaction that account signs.

    vm.deal / vm.prank       ->  gone. There is no cheatcode address on a chain. Setup
                                 is funded by sending ether to the constructor, and
                                 every actor acts by holding a key.

    the two worlds           ->  two chains. The harness ran the scenario twice in one
                                 process with a snapshot in between; here each world is
                                 its own anvil, started from genesis.

Some exploits will not survive this and that is the point of running it. An attack that
needed the harness to prank somebody, or needed a mock the setup minted for it, has
nowhere to get that on a chain. The number that still work is the number that were
always about the contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .live import ChainUnavailable, LiveChain, Step

PRAGMA_RE = re.compile(r"^\s*pragma solidity ([^;]+);", re.MULTILINE)
TARGET_DECL_RE = re.compile(
    r"^\s*([A-Za-z_]\w*)\s+(?:internal\s+|public\s+|private\s+)?target\s*;", re.MULTILINE
)


class Untranslatable(RuntimeError):
    """The proof-of-concept cannot be expressed as transactions. Said, not swallowed."""


def _balanced_block(text: str, start: int) -> tuple[str, int]:
    """Return the {...} block beginning at or after `start`, and the index after it."""
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1 : j], j + 1
    raise Untranslatable("unbalanced braces")


def _contract(text: str, name: str) -> str:
    m = re.search(rf"\bcontract\s+{re.escape(name)}\b", text)
    if not m:
        raise Untranslatable(f"no contract {name}")
    body, end = _balanced_block(text, m.end())
    return text[m.start() : end]


def _function_body(text: str, name: str) -> str:
    m = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", text)
    if not m:
        raise Untranslatable(f"no function {name}")
    body, _ = _balanced_block(text, m.end())
    return body


_HARNESS_CONTRACTS = re.compile(r"^(TestArbiter|Harness$|Vm$|_Arbiter)")


def _agent_declarations(text: str) -> str:
    """Every top-level type the agent wrote, not just the Attacker.

    Taking `contract Attacker` alone was tried and lost the mocks: an exploit whose
    setup deploys a MockERC20 declared beside the attacker compiled against a name that
    no longer existed. Anything the harness itself emits is left behind, because the
    chain provides none of it.
    """
    out: list[str] = []
    for m in re.finditer(
        r"^(?:abstract\s+)?(contract|interface|library)\s+(\w+)", text, re.MULTILINE
    ):
        name = m.group(2)
        if _HARNESS_CONTRACTS.match(name):
            continue
        body, end = _balanced_block(text, m.end())
        out.append(text[m.start() : end])
    if not any("contract Attacker" in d for d in out):
        raise Untranslatable("no Attacker contract")
    return "\n\n".join(out)


WARP_RE = re.compile(r"vm\.warp\(\s*block\.timestamp\s*\+\s*(\d+)\s*\)")
ROLL_RE = re.compile(r"vm\.roll\(\s*block\.number\s*\+\s*(\d+)\s*\)")


def _strip_pranks(body: str) -> str:
    """Remove the harness's impersonation. What is left is what the account itself did."""
    body = re.sub(r"^\s*vm\.(startPrank|stopPrank|prank)\s*\([^;]*\);\s*$", "",
                  body, flags=re.MULTILINE)
    return body


def _take_waits(body: str) -> tuple[str, int, int]:
    """Pull the clock changes out of a fragment; return the fragment and how long to wait.

    A `vm.warp` is not an impersonation, so deleting it would change what the scenario
    means. It is the scenario saying "and then some time passed", which a chain can do
    for real -- so it is lifted out here and replayed against the node instead.
    """
    seconds = sum(int(m) for m in WARP_RE.findall(body))
    blocks = sum(int(m) for m in ROLL_RE.findall(body))
    body = re.sub(r"^\s*vm\.(warp|roll)\s*\([^;]*\);\s*$", "", body,
                  flags=re.MULTILINE)
    return body, seconds, blocks


_DECL_RE = re.compile(
    r"^\s*([A-Za-z_]\w*(?:\[\])?)\s+"
    r"(?:(?:internal|public|private|constant|immutable|payable)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;\s*$"
)
# Declarations that belong to the harness rather than to the scenario. `atk` is the
# dead state variable the harness emits and never uses; on a chain the Attacker is
# deployed by the attacker's own factory, so carrying it over would only shadow that.
_HARNESS_NAMES = {"ARB_COMPLETED", "arbVictim", "vm", "vm_", "atk"}


def _state_declarations(test_body: str) -> str:
    """Collect the contract's state variables, wherever in the body they were written.

    Cutting at the first `function` was tried and does not work: the harness emits an
    accessor above the declarations, so everything the scenario needs was discarded and
    every sample came back "no target declaration". Track brace depth instead and take
    the lines that sit directly in the contract.
    """
    out: list[str] = []
    depth = 0
    for line in test_body.splitlines():
        if depth == 0:
            m = _DECL_RE.match(line)
            if m and m.group(2) not in _HARNESS_NAMES and "constant" not in line:
                out.append(f"    {m.group(1)} {m.group(2)};")
        depth += line.count("{") - line.count("}")
    return "\n".join(out)


# Every denominated amount, not just the ones written as a call option. Matching only
# `{value: N ether}` was tried and misses `.send(10 ether)` and `.transfer(...)` -- and
# `send` does not revert on failure, so a setup that hands the target everything the
# world had left the world broke, the constructor "succeeded", and the victim's entry
# reverted with no reason string in both worlds. The finding was then reported as not
# proven live, which is the worst kind of wrong answer: a real refusal in shape, an
# accounting mistake in fact.
VALUE_RE = re.compile(r"(\d+)\s*(ether|gwei|wei)\b")
_UNITS = {"ether": 10**18, "gwei": 10**9, "wei": 1}


def _required_endowment(*fragments: str) -> int:
    """How much the world has to start with for its own setup and entry to succeed.

    Deliberately generous: the surplus never leaves the world, so over-funding costs
    nothing measurable -- `recovered` is a delta -- while under-funding breaks the
    scenario silently.
    """
    spend = sum(
        int(m.group(1)) * _UNITS[m.group(2)]
        for frag in fragments
        for m in VALUE_RE.finditer(frag)
    )
    return max(10 * 10**18, min(3 * spend, 900 * 10**18))


def _attacker_ctor_payable(text: str) -> bool:
    """Is the ATTACKER's constructor payable -- not somebody else's.

    Searching the whole set of agent declarations was wrong: a mock with a payable
    constructor made every Attacker look payable, and `new Attacker{value: ...}`
    against a non-payable one does not compile.
    """
    try:
        atk = _contract(text, "Attacker")
    except Untranslatable:
        return False
    m = re.search(r"constructor\s*\([^)]*\)([^{]*)\{", atk)
    return bool(m and "payable" in m.group(1))


@dataclass
class Replay:
    """Everything needed to rebuild one exploit as transactions."""

    sample_id: str
    pragma: str
    target_source: str
    attacker_contract: str
    state_decls: str
    setup_body: str
    enter_body: str
    exit_body: str
    target_type: str
    ctor_payable: bool = True
    setup_wait: int = 0
    enter_wait: int = 0
    notes: list[str] = field(default_factory=list)


def parse_poc(poc_path: Path, target_path: Path, sample_id: str) -> Replay:
    """Take a dumped proof-of-concept apart into the pieces a chain can run."""
    text = poc_path.read_text(encoding="utf-8")
    pragma = (PRAGMA_RE.search(text).group(1).strip()
              if PRAGMA_RE.search(text) else ">=0.8.0")

    attacker = _agent_declarations(text)
    test_m = re.search(r"\bcontract\s+TestArbiter\w*\b", text)
    if not test_m:
        raise Untranslatable("no test contract")
    test_body, _ = _balanced_block(text, test_m.end())

    state_decls = _state_declarations(test_body)
    tm = TARGET_DECL_RE.search(state_decls)
    if not tm:
        raise Untranslatable("no `target` state declaration to bind the world to")

    setup_body, setup_wait, _ = _take_waits(
        _strip_pranks(_function_body(test_body, "arbSetup")))
    enter_body, enter_wait, _ = _take_waits(
        _strip_pranks(_function_body(test_body, "arbEnter")))

    return Replay(
        sample_id=sample_id,
        pragma=pragma,
        target_source=target_path.read_text(encoding="utf-8"),
        attacker_contract=attacker,
        state_decls=state_decls,
        setup_body=setup_body,
        enter_body=enter_body,
        exit_body=_strip_pranks(_function_body(test_body, "arbExit")),
        setup_wait=setup_wait,
        enter_wait=enter_wait,
        target_type=tm.group(1),
        # Not every Attacker takes ether in its constructor, and `new X{value: ...}`
        # against a non-payable one does not compile. Seven of twelve replays died on
        # exactly this before it was checked.
        ctor_payable=_attacker_ctor_payable(text),
    )


_LIVE_SOL = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "./Target.sol";

/// How an Attacker written for the harness finds out who the victim is. On a chain the
/// deployer has to be somebody who can answer, so the attacker's own factory does.
interface _ArbiterHarness {{ function arbiterVictim() external view returns (address); }}
interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

{attacker_contract}

/// The victim's own contract. It runs setup in its constructor and holds the position,
/// so the account that deployed it is a user with something to lose rather than an
/// address somebody pranked.
contract ArbWorld {{
{state_decls}
    address public owner;

    constructor() payable {{ owner = msg.sender;
{setup_body}
    }}

    function targetAddr() external view returns (address) {{ return address(target); }}
    function enter() external payable {{
{enter_body}
    }}
    function exit() external {{
{exit_body}
    }}
    function sweep() external {{
        (bool ok, ) = owner.call{{value: address(this).balance}}("");
        require(ok, "sweep failed");
    }}
    receive() external payable {{}}
}}

/// The attacker's account deploys this, and this deploys the Attacker. It exists for
/// one reason: an Attacker written for the harness may ask its deployer who the victim
/// is, and on a chain the deployer has to be somebody who can answer.
contract AttackerFactory {{
    address public victim;
    address public atk;
    address public owner;

    constructor(address v) payable {{ victim = v; owner = msg.sender; }}
    function arbiterVictim() external view returns (address) {{ return victim; }}

    function build(address t) external payable {{
{build_body}
    }}
    function run() external {{
        (bool ok, ) = atk.call(abi.encodeWithSignature("attack()"));
        require(ok, "attack reverted");
    }}
    function sweep() external {{
        atk.call(abi.encodeWithSignature("sweep()"));
        (bool ok, ) = owner.call{{value: address(this).balance}}("");
        ok;
    }}
    receive() external payable {{}}
}}
"""


def build_project(root: Path, rep: Replay) -> Path:
    proj = root / "live"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n'
        "auto_detect_solc = true\nvia_ir = true\n",
        encoding="utf-8",
    )
    (proj / "src" / "Target.sol").write_text(rep.target_source, encoding="utf-8")
    (proj / "src" / "Live.sol").write_text(
        _LIVE_SOL.format(
            pragma=rep.pragma,
            attacker_contract=rep.attacker_contract,
            state_decls=rep.state_decls,
            setup_body=rep.setup_body,
            enter_body=rep.enter_body,
            exit_body=rep.exit_body,
            build_body=(
                "        atk = address(new Attacker{value: msg.value}(t));"
                if rep.ctor_payable else
                "\n".join([
                    "        atk = address(new Attacker(t));",
                    "        // The constructor does not take ether, so the capital is",
                    "        // sent after; an Attacker with no way to receive it simply",
                    "        // works with none, which is a fact about the attack.",
                    '        (bool funded, ) = atk.call{value: msg.value}("");',
                    "        funded;",
                ])
            ),
        ),
        encoding="utf-8",
    )
    return proj


ETHER = 10**18


def run_world(chain: LiveChain, proj: Path, with_attack: bool,
              endow_wei: int = 10 * ETHER, setup_wait: int = 0,
              enter_wait: int = 0, world_endow: int = 0) -> dict[str, Any]:
    """One world on one chain. Returns what the victim got back and what the attacker took."""
    victim, attacker = chain.accounts[1], chain.accounts[2]
    steps: list[Step] = []

    world, tx = chain.deploy(proj, "src/Live.sol:ArbWorld", victim.key,
                             value_wei=world_endow or endow_wei)
    steps.append(Step(what="deploy ArbWorld (setup)", actor=victim.address, tx=tx))
    target = chain.call(world, "targetAddr()(address)").strip()

    if setup_wait:
        chain.advance(setup_wait)
    steps.append(chain.send(victim.key, world, "enter()"))
    if enter_wait:
        chain.advance(enter_wait)
    mid = chain.balance(world)
    tgt_pre = chain.balance(target)

    atk_gain = 0
    if with_attack:
        factory, tx = chain.deploy(proj, "src/Live.sol:AttackerFactory", attacker.key,
                                   ctor=[world])
        steps.append(Step(what="deploy AttackerFactory", actor=attacker.address, tx=tx))
        steps.append(chain.send(attacker.key, factory, "build(address)", [target],
                                value_wei=endow_wei))
        before = chain.balance(factory) + chain.balance(chain.call(
            factory, "atk()(address)").strip())
        steps.append(chain.send(attacker.key, factory, "run()"))
        steps.append(chain.send(attacker.key, factory, "sweep()"))
        after = chain.balance(factory) + chain.balance(chain.call(
            factory, "atk()(address)").strip())
        atk_gain = max(0, after - before)

    exit_step = chain.send(victim.key, world, "exit()")
    steps.append(exit_step)
    recovered = max(0, chain.balance(world) - mid)

    return {
        "with_attack": with_attack,
        "target": target,
        "recovered": recovered,
        # Recorded whether or not the predicate is satisfied. A bare "not proven" hides
        # the difference between an attack that did nothing and one that emptied real
        # value out of the contract while the particular user being modelled happened to
        # still get paid -- and those call for opposite next steps.
        "target_drained": max(0, tgt_pre - chain.balance(target)),
        "target_held_end": chain.balance(target),
        "target_held_mid": tgt_pre,
        "attacker_gain": atk_gain,
        "exit_ok": exit_step.ok,
        "steps": [vars(s) for s in steps],
    }


def replay(rep: Replay, root: Path, port: int) -> dict[str, Any]:
    """Run both worlds and adjudicate. Every number came back over JSON-RPC."""
    proj = build_project(root, rep)
    out: dict[str, Any] = {"sample_id": rep.sample_id}
    worlds = []
    for i, with_attack in enumerate((False, True)):
        chain = LiveChain(port=port + i)
        try:
            chain.start()
        except ChainUnavailable as exc:
            out["error"] = str(exc)
            return out
        try:
            worlds.append(run_world(chain, proj, with_attack,
                                    setup_wait=rep.setup_wait,
                                    enter_wait=rep.enter_wait,
                                    world_endow=_required_endowment(
                                        rep.setup_body, rep.enter_body)))
        except Exception as exc:  # noqa: BLE001 -- one sample must not stop the sweep
            out["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
            return out
        finally:
            chain.stop()

    clean, attacked = worlds
    shortfall = max(0, clean["recovered"] - attacked["recovered"])
    drained = attacked.get("target_drained", 0) - clean.get("target_drained", 0)
    target_held_rose = attacked.get("target_held_end", 0) > attacked.get("target_held_mid", 0)
    out.update({
        "recovered_clean": clean["recovered"],
        "recovered_attacked": attacked["recovered"],
        "attacker_gain": attacked["attacker_gain"],
        "shortfall": shortfall,
        "extracted_from_contract": max(0, drained),
        "target_held_rose": target_held_rose,
        # The same predicate the harness uses, computed from balances a node reported:
        # the victim got less back because the attack happened, and the attacker is
        # holding at least what the victim lost.
        # The drain invariant, which this predicate was missing. The synthetic harness
        # has always required that value leave the contract under audit; the live path
        # measured it, recorded it as a diagnostic, and then did not use it -- so an
        # attack could satisfy the conservation clause entirely inside scenery the setup
        # built. Caught by a patched half reaching a real chain with
        # shortfall 10 ether, attacker_gain 10 ether, extracted_from_contract 0: the
        # victim really was robbed, and the contract being audited never lost a wei.
        #
        # `target_held_rose` is the same exception the synthetic harness carries. A
        # stale-oracle attack deposits overvalued collateral and borrows against it, so
        # the target ends up holding MORE while the victim is robbed; requiring a fall
        # would refuse that whole class.
        "proven": bool(
            clean["recovered"] > 0
            and shortfall > 0
            and attacked["attacker_gain"] >= shortfall
            and (max(0, drained) > 0 or target_held_rose)
        ),
        "worlds": worlds,
    })
    return out


# ---------------------------------------------------------------------------
# The other template. state_change, liveness_broken and token_profit are not
# composed from arbSetup/arbEnter/arbExit -- everything lives inside arbiterRun,
# and the control is not a victim who takes a position but an ordinary user who
# runs the happy path and must NOT be able to move the state in question.
#
# Translating it needs one more account. The harness pranks `ctrl`; a chain has
# no pranks, so `ctrl` becomes a third key and the happy path becomes a
# transaction that key signs.
# ---------------------------------------------------------------------------

GETTER_RE = re.compile(r'staticcall\(\s*abi\.encodeWithSignature\(\s*"([^"]+)"')
CTRL_BLOCK_RE = re.compile(
    r"vm\.startPrank\(ctrl,\s*ctrl\);(.*?)vm\.stopPrank\(\);", re.DOTALL
)
ATTACKER_DEPLOY_RE = re.compile(r"^\s*Attacker\s+atk\s*=\s*new\s+Attacker", re.MULTILINE)


@dataclass
class ReplayExploit:
    """A proof written against the exploit template rather than the victim one."""

    sample_id: str
    pragma: str
    target_source: str
    agent_decls: str
    state_decls: str
    setup_body: str
    honest_body: str
    getter_sig: str
    target_type: str
    ctor_payable: bool = True


def parse_poc_exploit(poc_path: Path, target_path: Path,
                      sample_id: str) -> ReplayExploit:
    from .workspace import hoist_declarations

    text = poc_path.read_text(encoding="utf-8")
    pragma = (PRAGMA_RE.search(text).group(1).strip()
              if PRAGMA_RE.search(text) else ">=0.8.0")
    agent_decls = _agent_declarations(text)

    m = re.search(r"\bcontract\s+TestArbiterExploit\b", text)
    if not m:
        raise Untranslatable("not the exploit template")
    body, _ = _balanced_block(text, m.end())
    run = _function_body(body, "arbiterRun")

    # Setup is everything the agent deployed before the harness built the attacker.
    am = ATTACKER_DEPLOY_RE.search(run)
    if not am:
        raise Untranslatable("no Attacker deployment to split setup at")
    setup_src = run[: am.start()]
    try:
        state_decls, hoisted = hoist_declarations(setup_src)
    except ValueError as exc:
        raise Untranslatable(str(exc)[:120]) from exc

    gm = GETTER_RE.search(run)
    if not gm:
        raise Untranslatable("no observed getter to read")

    cm = CTRL_BLOCK_RE.search(run)
    honest = cm.group(1) if cm else ""

    tm = TARGET_DECL_RE.search(state_decls)
    if not tm:
        raise Untranslatable("no `target` declaration in setup")

    return ReplayExploit(
        sample_id=sample_id,
        pragma=pragma,
        target_source=target_path.read_text(encoding="utf-8"),
        agent_decls=agent_decls,
        state_decls=state_decls,
        setup_body=hoisted,
        honest_body=honest,
        getter_sig=gm.group(1),
        target_type=tm.group(1),
        ctor_payable=_attacker_ctor_payable(text),
    )


_LIVE_EXPLOIT_SOL = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "./Target.sol";

interface _ArbiterHarness {{ function arbiterVictim() external view returns (address); }}
interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

{agent_decls}

contract ArbWorld {{
{state_decls}
    address public owner;
    constructor() payable {{ owner = msg.sender;
{setup_body}
    }}
    function targetAddr() external view returns (address) {{ return address(target); }}
    receive() external payable {{}}
}}

/// An ordinary user running the happy path, deployed and driven by its own account.
/// The harness pranked this actor; a chain cannot, so it holds a key like anyone else.
/// If the state under test moves for THIS account too, it was never privileged.
contract HonestUser {{
{state_decls}
    constructor(address t) payable {{ target = {target_type}(payable(t)); }}
    function act() external payable {{
{honest_body}
    }}
    receive() external payable {{}}
}}

contract AttackerFactory {{
    address public victim;
    address public atk;
    address public owner;
    constructor(address v) payable {{ victim = v; owner = msg.sender; }}
    function arbiterVictim() external view returns (address) {{ return victim; }}
    function build(address t) external payable {{
{build_body}
    }}
    function run() external {{
        (bool ok, ) = atk.call(abi.encodeWithSignature("attack()"));
        require(ok, "attack reverted");
    }}
    receive() external payable {{}}
}}
"""


def build_exploit_project(root: Path, rep: ReplayExploit) -> Path:
    proj = root / "live"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n'
        "auto_detect_solc = true\nvia_ir = true\n",
        encoding="utf-8",
    )
    (proj / "src" / "Target.sol").write_text(rep.target_source, encoding="utf-8")
    (proj / "src" / "Live.sol").write_text(
        _LIVE_EXPLOIT_SOL.format(
            pragma=rep.pragma,
            agent_decls=rep.agent_decls,
            state_decls=rep.state_decls,
            setup_body=rep.setup_body,
            honest_body=rep.honest_body,
            target_type=rep.target_type,
            build_body=_build_body(rep.ctor_payable),
        ),
        encoding="utf-8",
    )
    return proj


def _build_body(ctor_payable: bool) -> str:
    if ctor_payable:
        return "        atk = address(new Attacker{value: msg.value}(t));"
    return "\n".join([
        "        atk = address(new Attacker(t));",
        '        (bool funded, ) = atk.call{value: msg.value}("");',
        "        funded;",
    ])


def replay_exploit(rep: ReplayExploit, root: Path, port: int) -> dict[str, Any]:
    """Read the privileged state three times: at rest, after honest use, after the attack."""
    proj = build_exploit_project(root, rep)
    out: dict[str, Any] = {"sample_id": rep.sample_id, "template": "exploit"}
    chain = LiveChain(port=port)
    try:
        chain.start()
    except ChainUnavailable as exc:
        out["error"] = str(exc)
        return out
    try:
        deployer, honest, attacker = (
            chain.accounts[0], chain.accounts[3], chain.accounts[2]
        )
        world, _ = chain.deploy(proj, "src/Live.sol:ArbWorld", deployer.key,
                                value_wei=10 * ETHER)
        target = chain.call(world, "targetAddr()(address)").strip()
        v0 = chain.call(target, rep.getter_sig)

        # The control. An ordinary account runs the happy path with its own key.
        hu, _ = chain.deploy(proj, "src/Live.sol:HonestUser", honest.key,
                             ctor=[target], value_wei=10 * ETHER)
        honest_step = chain.send(honest.key, hu, "act()", value_wei=2 * ETHER)
        v1 = chain.call(target, rep.getter_sig)

        factory, _ = chain.deploy(proj, "src/Live.sol:AttackerFactory", attacker.key,
                                  ctor=[hu])
        chain.send(attacker.key, factory, "build(address)", [target],
                   value_wei=10 * ETHER)
        attack_step = chain.send(attacker.key, factory, "run()")
        v2 = chain.call(target, rep.getter_sig)

        out.update({
            "target": target,
            "getter": rep.getter_sig,
            "at_rest": v0,
            "after_honest": v1,
            "after_attack": v2,
            "honest_ok": honest_step.ok,
            "attack_ok": attack_step.ok,
            # Privileged means an ordinary account cannot move it. Both halves are
            # required: unchanged by honest use, changed by the attack.
            "privileged": v0 == v1,
            "proven": bool(attack_step.ok and v0 == v1 and v1 != v2),
        })
        return out
    except Exception as exc:  # noqa: BLE001 -- one sample must not stop the sweep
        out["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
        return out
    finally:
        chain.stop()


# ---------------------------------------------------------------------------
# The third and fourth shapes. liveness_broken asks whether an operation an
# ordinary user could complete stops working; token_profit asks whether the
# attacker's balance of a named token rose further than an honest user's, and
# whether the tokens came out of the contract under audit.
#
# The liveness one is the easiest of all to put on a chain, because the honest
# operation is already just a function signature -- an account can send it with
# no wrapper contract at all, which is exactly what "an ordinary user could do
# this" is supposed to mean.
# ---------------------------------------------------------------------------

LIVENESS_RE = re.compile(
    r"vm\.prank\(live,\s*live\);\s*\(bool\s+ok\w+,\s*\)\s*=\s*"
    r'address\(target\)\.call\(abi\.encodeWithSignature\(\s*"([^"]+)"'
)
# The expression is usually `address(someToken)`, which a lazy [^)] class truncates to
# `address(someToken` -- one nesting level has to be spelled out.
TOKEN_RE = re.compile(
    r"_ArbiterToken\(\s*(address\([^()]*\)|[A-Za-z_]\w*)\s*\)\.balanceOf")
SETUP_END_RE = re.compile(
    r"^\s*(?:Attacker\s+atk\s*=\s*new\s+Attacker|address\s+(?:ctrl|live)\s*=)",
    re.MULTILINE,
)


def _split_setup(run: str) -> str:
    m = SETUP_END_RE.search(run)
    if not m:
        raise Untranslatable("cannot find where the agent's setup ends")
    return run[: m.start()]


@dataclass
class ReplayOther:
    """A proof written against the liveness or token-profit shape."""

    sample_id: str
    kind: str                       # "liveness" | "token"
    pragma: str
    target_source: str
    agent_decls: str
    state_decls: str
    setup_body: str
    target_type: str
    liveness_sig: str = ""
    token_expr: str = ""
    honest_body: str = ""
    ctor_payable: bool = True
    setup_wait: int = 0


def parse_poc_other(poc_path: Path, target_path: Path,
                    sample_id: str) -> ReplayOther:
    from .workspace import hoist_declarations

    text = poc_path.read_text(encoding="utf-8")
    pragma = (PRAGMA_RE.search(text).group(1).strip()
              if PRAGMA_RE.search(text) else ">=0.8.0")
    agent_decls = _agent_declarations(text)

    m = re.search(r"\bcontract\s+TestArbiterExploit\b", text)
    if not m:
        raise Untranslatable("not the exploit template")
    body, _ = _balanced_block(text, m.end())
    run = _function_body(body, "arbiterRun")

    setup_src, wait, _ = _take_waits(_split_setup(run))
    try:
        state_decls, hoisted = hoist_declarations(setup_src)
    except ValueError as exc:
        raise Untranslatable(str(exc)[:120]) from exc
    tm = TARGET_DECL_RE.search(state_decls)
    if not tm:
        raise Untranslatable("no `target` declaration in setup")

    lm = LIVENESS_RE.search(run)
    if lm:
        return ReplayOther(
            sample_id=sample_id, kind="liveness", pragma=pragma,
            target_source=target_path.read_text(encoding="utf-8"),
            agent_decls=agent_decls, state_decls=state_decls, setup_body=hoisted,
            target_type=tm.group(1), liveness_sig=lm.group(1), setup_wait=wait,
            ctor_payable=_attacker_ctor_payable(text),
        )

    km = TOKEN_RE.search(run)
    if km:
        cm = CTRL_BLOCK_RE.search(run)
        return ReplayOther(
            sample_id=sample_id, kind="token", pragma=pragma,
            target_source=target_path.read_text(encoding="utf-8"),
            agent_decls=agent_decls, state_decls=state_decls, setup_body=hoisted,
            target_type=tm.group(1), token_expr=km.group(1),
            honest_body=(cm.group(1) if cm else ""), setup_wait=wait,
            ctor_payable=_attacker_ctor_payable(text),
        )
    raise Untranslatable("neither a liveness call nor a token balance to measure")


_LIVE_OTHER_SOL = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "./Target.sol";

interface _ArbiterHarness {{ function arbiterVictim() external view returns (address); }}
interface _ArbiterToken {{
    function balanceOf(address) external view returns (uint256);
}}

{agent_decls}

contract ArbWorld {{
{state_decls}
    address public owner;
    constructor() payable {{ owner = msg.sender;
{setup_body}
    }}
    function targetAddr() external view returns (address) {{ return address(target); }}
{token_accessor}
    receive() external payable {{}}
}}

contract HonestUser {{
{state_decls}
    constructor(address t) payable {{ target = {target_type}(payable(t)); }}
    function act() external payable {{
{honest_body}
    }}
    receive() external payable {{}}
}}

contract AttackerFactory {{
    address public victim;
    address public atk;
    address public owner;
    constructor(address v) payable {{ victim = v; owner = msg.sender; }}
    function arbiterVictim() external view returns (address) {{ return victim; }}
    function build(address t) external payable {{
{build_body}
    }}
    function run() external {{
        (bool ok, ) = atk.call(abi.encodeWithSignature("attack()"));
        require(ok, "attack reverted");
    }}
    receive() external payable {{}}
}}
"""


def build_other_project(root: Path, rep: ReplayOther) -> Path:
    proj = root / "live"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n'
        "auto_detect_solc = true\nvia_ir = true\n",
        encoding="utf-8",
    )
    (proj / "src" / "Target.sol").write_text(rep.target_source, encoding="utf-8")
    (proj / "src" / "Live.sol").write_text(
        _LIVE_OTHER_SOL.format(
            pragma=rep.pragma,
            agent_decls=rep.agent_decls,
            state_decls=rep.state_decls,
            setup_body=rep.setup_body,
            target_type=rep.target_type,
            honest_body=rep.honest_body,
            build_body=_build_body(rep.ctor_payable),
            token_accessor=(
                f"    function tokenAddr() external view returns (address) "
                f"{{ return {rep.token_expr}; }}"
                if rep.kind == "token" else ""
            ),
        ),
        encoding="utf-8",
    )
    return proj


def replay_other(rep: ReplayOther, root: Path, port: int) -> dict[str, Any]:
    proj = build_other_project(root, rep)
    out: dict[str, Any] = {"sample_id": rep.sample_id, "template": rep.kind}
    chain = LiveChain(port=port)
    try:
        chain.start()
    except ChainUnavailable as exc:
        out["error"] = str(exc)
        return out
    try:
        deployer, honest, attacker = (
            chain.accounts[0], chain.accounts[3], chain.accounts[2]
        )
        endow = _required_endowment(rep.setup_body, rep.honest_body)
        world, _ = chain.deploy(proj, "src/Live.sol:ArbWorld", deployer.key,
                                value_wei=endow)
        target = chain.call(world, "targetAddr()(address)").strip()
        if rep.setup_wait:
            chain.advance(rep.setup_wait)

        if rep.kind == "liveness":
            # No wrapper: the honest operation is a signature, so an account sends it.
            # That is what "an ordinary user could do this" is supposed to mean, and on
            # a chain it is literally true rather than arranged.
            before = chain.send(honest.key, target, rep.liveness_sig)
            factory, _ = chain.deploy(proj, "src/Live.sol:AttackerFactory",
                                      attacker.key, ctor=[honest.address])
            chain.send(attacker.key, factory, "build(address)", [target],
                       value_wei=10 * ETHER)
            atk_step = chain.send(attacker.key, factory, "run()")
            after = chain.send(honest.key, target, rep.liveness_sig)
            out.update({
                "target": target, "operation": rep.liveness_sig,
                "worked_before": before.ok, "attack_ok": atk_step.ok,
                "worked_after": after.ok,
                "proven": bool(before.ok and atk_step.ok and not after.ok),
            })
            return out

        token = chain.call(world, "tokenAddr()(address)").strip()

        def bal(addr: str) -> int:
            return int(chain.call(token, "balanceOf(address)(uint256)",
                                  addr).split()[0])

        tgt_pre = bal(target)
        hu, _ = chain.deploy(proj, "src/Live.sol:HonestUser", honest.key,
                             ctor=[target], value_wei=10 * ETHER)
        h_pre = bal(hu)
        chain.send(honest.key, hu, "act()", value_wei=2 * ETHER)
        honest_gain = max(0, bal(hu) - h_pre)

        factory, _ = chain.deploy(proj, "src/Live.sol:AttackerFactory", attacker.key,
                                  ctor=[hu])
        chain.send(attacker.key, factory, "build(address)", [target],
                   value_wei=10 * ETHER)
        atk_addr = chain.call(factory, "atk()(address)").strip()
        a_pre = bal(atk_addr) + bal(factory)
        atk_step = chain.send(attacker.key, factory, "run()")
        attack_gain = max(0, bal(atk_addr) + bal(factory) - a_pre)
        tgt_post = bal(target)

        out.update({
            "target": target, "token": token,
            "honest_gain": honest_gain, "attack_gain": attack_gain,
            "target_held_before": tgt_pre, "target_held_after": tgt_post,
            "attack_ok": atk_step.ok,
            # The drain invariant, unchanged: the tokens have to have come out of the
            # contract under audit, or the attack was a tour of scenery the setup built.
            "drained": tgt_post < tgt_pre,
            "proven": bool(
                atk_step.ok and attack_gain > honest_gain and tgt_post < tgt_pre
            ),
        })
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
        return out
    finally:
        chain.stop()
