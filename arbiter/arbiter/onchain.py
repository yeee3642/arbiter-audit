"""Proving an attack against a chain instead of against a world we built ourselves.

Everything else in this project proves exploits in a world the harness constructs: the
contract is deployed fresh from source, `deploy_code` configures it, `vm.deal` conjures
the attacker's capital, and the victim is an address the harness invented and funded.
That is the right design for a benchmark -- it is reproducible, hermetic and paired --
but it leaves a gap that no amount of gating inside that world can close.

The gap, stated exactly. In the synthetic harness:

  1. the contract is freshly deployed, so its owner, config and storage are whatever
     setup chose; on chain they are already set, by someone who is not the attacker
  2. `vm.deal` manufactures capital from nothing
  3. the victim is an address the harness created and made deposit
  4. `deploy_code` may mint tokens, seed pools and set prices -- it builds the world
  5. gas is free, so a profit of one wei counts as a profit
  6. there is no competition, no mempool and no ordering; the attacker is always first
  7. mock tokens and pools behave ideally
  8. liquidity is whatever setup put there, so "drained 5 ether" says nothing about
     whether five ether was ever there
  9. the code is the source we were handed, not the bytecode that is actually deployed

Items 1, 3, 4, 7, 8 and 9 are all the same defect wearing different clothes: **setup
built the world**. On a real chain nobody hands you the world. So this module removes
setup entirely.

What that leaves is a much smaller claim, and an honest one: bound to a deployed
address, at a real block, with real storage and real liquidity, an unprivileged account
starting with a declared amount of capital ends up holding more than it started with,
and the contract holds less -- after paying for gas.

The cheatcode rule inverts here, and the reason is worth stating. In the synthetic
harness cheatcodes are allowed in setup because setup has legitimate work to do: it must
build a world before anything can happen in it. In fork mode the world already exists,
so setup has no legitimate work left, and a cheatcode in it is never construction -- it
is always forgery. The only cheatcodes this module emits are the ones that say "this is
my own account": a fork selection, a prank as an address the harness drew, and a funding
call whose amount is reported as a requirement rather than hidden as a gift.

This module is NOT part of the paired benchmark and its results are not comparable to
it. A finding proven here carries `environment: onchain/<chain>@<block>`; a finding from
the benchmark carries `environment: synthetic`. They must never be shown as the same
kind of evidence.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .workspace import (
    FOUNDRY_TOML,
    _indent,
    _reject_forgery,
    _reject_halting,
    draw_identity,
    strip_preamble,
)

# Keyless endpoints, so an audit needs no account and no secret in a config file. The
# first that answers is used. Archive requests (a pinned historical block) need a paid
# key on all of these, so fork mode runs at the chain head unless a key is supplied.
PUBLIC_RPC: dict[str, list[str]] = {
    "ethereum": [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://rpc.flashbots.net",
    ],
    "bsc": [
        "https://bsc-rpc.publicnode.com",
        "https://binance.llamarpc.com",
    ],
    "arbitrum": [
        "https://arbitrum-one-rpc.publicnode.com",
    ],
    "base": [
        "https://base-rpc.publicnode.com",
    ],
    "polygon": [
        "https://polygon-bor-rpc.publicnode.com",
    ],
}

# What the attack is allowed to start with. The harness reports the smallest rung that
# works rather than picking one, because "this needs ten thousand ether of capital" and
# "this needs a tenth of an ether" are different findings and the difference is the
# whole question of whether anyone would actually do it.
CAPITAL_LADDER: list[int] = [
    10**17,      # 0.1 ether -- anyone
    10**18,      # 1
    10**19,      # 10
    10**20,      # 100
    10**21,      # 1,000
    10**22,      # 10,000 -- flash-loan territory
]

# Gas is priced at the block's own basefee, so the threshold is the one that applied at
# the moment being audited rather than a number chosen here.
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class RpcUnavailable(RuntimeError):
    """No endpoint answered. Fork mode cannot run, and must not silently degrade."""


@dataclass
class ForkPlan:
    """Where the audit is bound: one address, one chain, one block."""

    chain: str
    target: str
    rpc: str
    block: int
    label: str = ""
    verified_source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def environment(self) -> str:
        return f"onchain/{self.chain}@{self.block}"


def _rpc_call(url: str, method: str, params: list[Any], timeout: int = 15) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
    req = urllib.request.Request(  # noqa: S310 -- fixed https endpoints from PUBLIC_RPC
        url, data=body.encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        payload = json.loads(resp.read())
    if "error" in payload:
        raise RpcUnavailable(str(payload["error"])[:200])
    return payload["result"]


def resolve_fork(chain: str, target: str, rpc: str = "") -> ForkPlan:
    """Find an endpoint that answers and confirm the address actually holds code.

    An address with no code is not a contract, and an audit of one would be an audit of
    nothing -- so that is an error here rather than a clean report later.
    """
    if not ADDRESS_RE.match(target.strip()):
        raise ValueError(f"not an address: {target!r}")
    candidates = [rpc] if rpc else list(PUBLIC_RPC.get(chain, []))
    if not candidates:
        raise ValueError(f"no endpoint known for chain {chain!r}; pass one explicitly")

    last: str = ""
    for url in candidates:
        try:
            block = int(_rpc_call(url, "eth_blockNumber", []), 16)
            code = _rpc_call(url, "eth_getCode", [target, "latest"])
        except Exception as exc:  # noqa: BLE001 -- try the next endpoint
            last = f"{url}: {type(exc).__name__}: {exc}"
            continue
        if code in ("0x", "", None):
            raise ValueError(
                f"{target} holds no code on {chain}. An address without code is not a "
                f"contract; there is nothing at that address to audit."
            )
        return ForkPlan(chain=chain, target=target, rpc=url, block=block,
                        extra={"code_size": (len(code) - 2) // 2})
    raise RpcUnavailable(f"no endpoint answered for {chain}. last: {last}")


_ONCHAIN_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

/// Bound to a contract that is deployed, at a block that really happened, with the
/// storage and the liquidity it really has. Nothing here builds a world: there is no
/// deploy step, and the only cheatcodes are the fork selection, a prank as an address
/// this file drew at random, and the capital that prank is given -- which is reported
/// as a requirement of the attack, not hidden inside the profit.
interface Vm {{
    function createSelectFork(string calldata) external returns (uint256);
    function createSelectFork(string calldata, uint256) external returns (uint256);
    function deal(address, uint256) external;
    function startPrank(address, address) external;
    function stopPrank() external;
    function label(address, string calldata) external;
}}

interface _ArbiterToken {{
    function balanceOf(address) external view returns (uint256);
}}

{attacker_code}

contract TestArbiterOnchain {{
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address constant TARGET = {target_addr};
    // Through uint160 rather than a direct literal: `draw_identity` writes 42 hex
    // digits so that solc does not demand an EIP-55 checksum the harness has no keccak
    // to compute, and a 42-digit literal is not directly convertible to an address.
    address payable constant ATTACKER = payable(address(uint160({attacker_addr})));

    /// Value did not leave the contract. Whatever else happened, this is not a theft.
    error ArbiterNoDrain(uint256 heldBefore, uint256 heldAfter);
    /// The attacker came out ahead of where they started, but not ahead of the gas the
    /// transaction would have cost. On a chain that is a loss.
    error ArbiterNotProfitable(uint256 gross, uint256 gasCost, uint256 capital);
    /// Reported on success so the numbers are in the transcript rather than in a claim.
    error ArbiterOnchainProven(uint256 drained, uint256 net, uint256 capital);

    function testArbiterOnchain() external {{
{fork_call}
        vm.label(TARGET, "target");

        uint256[{n_rungs}] memory ladder = [{rungs}];
        uint256 bestDrain;
        for (uint256 i = 0; i < {n_rungs}; i++) {{
            (bool ok, bytes memory data) = address(this).call(
                abi.encodeWithSignature("arbAttempt(uint256)", ladder[i]));
            if (!ok) {{ continue; }}
            (bool proven, uint256 drained, uint256 net) =
                abi.decode(data, (bool, uint256, uint256));
            if (proven) {{
                // The smallest rung that works is the one reported, so the finding says
                // what the attack actually costs to mount.
                revert ArbiterOnchainProven(drained, net, ladder[i]);
            }}
            if (drained > bestDrain) {{ bestDrain = drained; }}
        }}
        // Two different failures, told apart in the transcript rather than collapsed:
        // value never moved at all, or value moved but the attacker did not come out
        // ahead of gas. A probe cannot check the economic gate without this distinction.
        if (bestDrain == 0) {{ revert ArbiterNoDrain(0, 0); }}
        revert ArbiterNotProfitable(0, 0, bestDrain);
    }}

    /// One rung of the capital ladder, in its own call so a revert only kills the rung.
    function arbAttempt(uint256 capital)
        external
        returns (bool proven, uint256 drained, uint256 net)
    {{
        uint256 tgtPre = {measure_target};
        vm.deal(ATTACKER, capital);
        uint256 atkPre = {measure_attacker};

        uint256 gasBefore = gasleft();
        vm.startPrank(ATTACKER, ATTACKER);
{attack}
        vm.stopPrank();
        uint256 gasUsed = gasBefore - gasleft();

        uint256 tgtPost = {measure_target};
        uint256 atkPost = {measure_attacker};

        // The contract under audit must hold less than it did. Without this an attack
        // that shuffles value between accounts it already controls reads as a theft.
        if (tgtPost >= tgtPre) {{ return (false, 0, 0); }}
        drained = tgtPre - tgtPost;

        // Profit is measured against the capital the attacker was handed, so the
        // handout cannot itself be counted as gain.
        uint256 gross = atkPost > atkPre + capital ? atkPost - atkPre - capital : 0;
        uint256 gasCost = gasUsed * (block.basefee == 0 ? 1 gwei : block.basefee);
        if (gross <= gasCost) {{ return (false, drained, 0); }}
        return (true, drained, gross - gasCost);
    }}

    receive() external payable {{}}
}}
"""


def _reject_world_building(fragment: str, field_name: str) -> None:
    """In fork mode there is nothing legitimate for setup to do.

    The world is already there. A `new` in the attacker's own contract is fine -- an
    attacker may deploy a helper -- but anything that constructs the thing under audit,
    or mints itself a balance, is building scenery that does not exist on chain.
    """
    if not fragment.strip():
        return
    _reject_halting(fragment, field_name)
    _reject_forgery(fragment, field_name)
    for pattern, why in (
        (r"\bvm\s*\.", "cheatcodes"),
        (r"\bhoax\b|\bdeal\b\s*\(", "balance manufacture"),
        (r"\bderiveKey\b|\bsign\s*\(", "key forgery"),
    ):
        if re.search(pattern, fragment):
            raise ValueError(
                f"{field_name} uses {why}. In fork mode the contract is already "
                f"deployed and its state is already what it is, so there is nothing "
                f"for setup to build -- any cheatcode here would be inventing a "
                f"circumstance that does not hold on the chain. Write the attack as an "
                f"ordinary account would have to send it."
            )


def compose_onchain(
    plan: ForkPlan,
    *,
    attack: str,
    attacker_code: str = "",
    token_expr: str = "",
    pin_block: bool = False,
) -> str:
    """Compose an attack against the deployed contract. Raises ValueError if refused."""
    attack = strip_preamble(attack)
    attacker_code = strip_preamble(attacker_code)
    if not attack.strip():
        raise ValueError("onchain mode needs an attack: what the attacker sends")
    _reject_world_building(attack, "attack")
    _reject_world_building(attacker_code, "attacker_code")

    attacker_addr = draw_identity()
    if token_expr.strip():
        tok = token_expr.strip()
        measure_target = f"_ArbiterToken({tok}).balanceOf(TARGET)"
        measure_attacker = f"_ArbiterToken({tok}).balanceOf(ATTACKER)"
    else:
        measure_target = "TARGET.balance"
        measure_attacker = "ATTACKER.balance"

    fork_call = (
        f'        vm.createSelectFork("{plan.rpc}", {plan.block});'
        if pin_block
        else f'        vm.createSelectFork("{plan.rpc}");'
    )
    return _ONCHAIN_TEMPLATE.format(
        attacker_code=attacker_code.strip(),
        target_addr=plan.target,
        attacker_addr=attacker_addr,
        fork_call=fork_call,
        n_rungs=len(CAPITAL_LADDER),
        rungs=", ".join(
            (f"uint256({v})" if i == 0 else str(v))
            for i, v in enumerate(CAPITAL_LADDER)
        ),
        measure_target=measure_target,
        measure_attacker=measure_attacker,
        attack=_indent(attack, 8),
    )


# The hermetic profile forbids network access, which is exactly what fork mode needs, so
# fork mode gets its own and says why in the file it writes.
FORK_TOML = FOUNDRY_TOML.replace(
    "# Deterministic: no fork, no network access during tests.",
    "# Fork mode: the point is to reach a real chain, so the hermetic rule is lifted\n"
    "# here and only here. Findings produced under this profile are labelled\n"
    "# environment=onchain and are not comparable to the paired benchmark.",
)


def run_onchain(
    root: Path, plan: ForkPlan, solidity: str, timeout: int = 600
) -> dict[str, Any]:
    """Write, build and run one fork-mode attack. Returns a record, never raises."""
    # Built by hand rather than through Workspace: there is no contract source to
    # compile here (the code under audit is already on the chain), and Workspace writes
    # its own Vm interface, which would collide with the one this template declares.
    if root.exists():
        shutil.rmtree(root)
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir(parents=True)
    (root / "foundry.toml").write_text(
        FORK_TOML.format(src="src", solc="auto_detect_solc = true", via_ir="false"),
        encoding="utf-8",
    )
    (root / "test" / "Onchain.t.sol").write_text(solidity, encoding="utf-8")

    proc = subprocess.run(  # noqa: S603
        ["forge", "test", "-vv", "--match-contract", "TestArbiterOnchain"],
        cwd=root, capture_output=True, text=True, timeout=timeout,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    proven = re.search(
        r"ArbiterOnchainProven\((\d+)[^,]*,\s*(\d+)[^,]*,\s*(\d+)", out
    )
    built = "Compiler run failed" not in out and "Error: Compilation failed" not in out
    return {
        "built": built,
        "environment": plan.environment,
        "target": plan.target,
        "chain": plan.chain,
        "block": plan.block,
        "rpc": plan.rpc,
        "proven": bool(proven),
        "drained_wei": int(proven.group(1)) if proven else 0,
        "net_wei": int(proven.group(2)) if proven else 0,
        "capital_required_wei": int(proven.group(3)) if proven else 0,
        "output_tail": out[-3000:],
    }
