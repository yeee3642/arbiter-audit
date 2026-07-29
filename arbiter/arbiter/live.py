"""A real chain in a box: the attack as signed transactions, not as a test.

Fork mode (`onchain.py`) removed the harness's power to build the world. This module
removes the last thing that separates a proof from a robbery: the test runner.

Everything in the synthetic harness happens inside one `forge test` process, where the
harness is the EVM's administrator. It can `vm.prank` as anyone, `vm.deal` any balance,
`vm.store` any slot. Every gate in this project exists to stop that power leaking into
the attack -- `_reject_forgery`, `draw_identity`, the halt sentinel, all of it is one
long argument with a capability the harness should not have had in the first place.

Over RPC that argument ends, because the capability is gone. There is no `vm` on a
chain. To act as an account you must hold its private key and sign; to spend you must
have the balance; to be included you must pay for gas. An attack that runs here ran
because it works, and there is no lint to write about it because there is nothing left
to forge.

So this is the same evidence as a passing test, minus the trust. The transcript is a
list of transaction hashes on a chain with a genesis, and every balance in it was read
back over JSON-RPC rather than asserted in Solidity.

What it does NOT establish: the contract is one we deployed from source, so items 1, 4
and 9 of the gap listed in `onchain.py` still apply. Local mode proves the attack is
executable by an ordinary account; fork mode proves the contract is really out there.
Neither alone is the whole claim, and this file does not pretend otherwise.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The trailing boundary matters: without it the address pattern also matches the first
# forty hex digits of a sixty-four digit private key, so anvil's ten accounts read as
# twenty addresses and the counts never line up.
ANVIL_KEY_RE = re.compile(
    r"^\((\d+)\)\s+(0x[0-9a-fA-F]{40})(?![0-9a-fA-F])", re.MULTILINE)
ANVIL_PRIV_RE = re.compile(
    r"^\((\d+)\)\s+(0x[0-9a-fA-F]{64})(?![0-9a-fA-F])", re.MULTILINE)


class ChainUnavailable(RuntimeError):
    """anvil could not be started. Live mode cannot run, and must not degrade quietly."""


@dataclass
class Account:
    index: int
    address: str
    key: str


@dataclass
class Step:
    """One thing that happened on the chain, with the receipt to look it up."""

    what: str
    actor: str
    tx: str = ""
    gas_used: int = 0
    ok: bool = True
    note: str = ""


@dataclass
class Transcript:
    chain_id: int = 0
    rpc: str = ""
    target: str = ""
    attacker_contract: str = ""
    steps: list[Step] = field(default_factory=list)
    balances: dict[str, dict[str, int]] = field(default_factory=dict)
    verdict: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "rpc": self.rpc,
            "target": self.target,
            "attacker_contract": self.attacker_contract,
            "steps": [vars(s) for s in self.steps],
            "balances": self.balances,
            "verdict": self.verdict,
        }


class LiveChain:
    """An anvil instance and the accounts it was born with."""

    def __init__(self, port: int = 8545, balance_eth: int = 1000) -> None:
        self.port = port
        self.rpc = f"http://127.0.0.1:{port}"
        self.balance_eth = balance_eth
        self.proc: subprocess.Popen[str] | None = None
        self.accounts: list[Account] = []

    def __enter__(self) -> LiveChain:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def start(self) -> None:
        if shutil.which("anvil") is None:
            raise ChainUnavailable("anvil is not on PATH")
        # Default mining: every transaction is mined into its own block, which is the
        # behaviour a real chain has and the one the transcript should reflect.
        self.proc = subprocess.Popen(  # noqa: S603
            ["anvil", "--port", str(self.port), "--accounts", "10",
             "--balance", str(self.balance_eth)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        banner = self._await_banner()
        addrs = ANVIL_KEY_RE.findall(banner)
        keys = ANVIL_PRIV_RE.findall(banner)
        if not addrs or len(addrs) != len(keys):
            self.stop()
            raise ChainUnavailable(f"could not read accounts from anvil: {banner[:400]}")
        self.accounts = [
            Account(index=int(i), address=a, key=k)
            for (i, a), (_, k) in zip(addrs, keys, strict=False)
        ]

    def _await_banner(self, timeout: float = 25.0) -> str:
        assert self.proc is not None and self.proc.stdout is not None
        out: list[str] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            out.append(line)
            if "Listening on" in line:
                return "".join(out)
        self.stop()
        raise ChainUnavailable("anvil did not report a listening socket")

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    # -- reading -----------------------------------------------------------------------

    def _cast(self, *args: str, timeout: int = 120) -> str:
        proc = subprocess.run(  # noqa: S603
            ["cast", *args, "--rpc-url", self.rpc],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout).strip()[:400])
        return (proc.stdout or "").strip()

    def balance(self, address: str) -> int:
        return int(self._cast("balance", address))

    def chain_id(self) -> int:
        return int(self._cast("chain-id"))

    def call(self, to: str, sig: str, *args: str) -> str:
        return self._cast("call", to, sig, *args)

    # -- writing -----------------------------------------------------------------------

    def deploy(self, project: Path, contract: str, key: str,
               ctor: list[str] | None = None, value_wei: int = 0) -> tuple[str, str]:
        """Deploy with `forge create`. Returns (address, tx hash)."""
        cmd = ["forge", "create", contract, "--rpc-url", self.rpc,
               "--private-key", key, "--broadcast", "--json"]
        if value_wei:
            cmd += ["--value", str(value_wei)]
        if ctor:
            cmd += ["--constructor-args", *ctor]
        proc = subprocess.run(  # noqa: S603
            cmd, cwd=project, capture_output=True, text=True, timeout=300
        )
        # `forge create --json` pretty-prints, so the object spans several lines. Parse
        # the whole of stdout first and only fall back to per-line for other versions.
        out = (proc.stdout or "").strip()
        for blob in (out, *reversed(out.splitlines())):
            try:
                data = json.loads(blob)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and "deployedTo" in data:
                return data["deployedTo"], data.get("transactionHash", "")
        raise RuntimeError(
            f"deploy of {contract} failed: "
            f"{((proc.stderr or '') + (proc.stdout or '')).strip()[-400:]}"
        )

    def send(self, key: str, to: str, sig: str, args: list[str] | None = None,
             value_wei: int = 0) -> Step:
        """Send a real, signed transaction. A revert is recorded, not raised."""
        cmd = ["cast", "send", to, sig, *(args or []), "--rpc-url", self.rpc,
               "--private-key", key, "--json"]
        if value_wei:
            cmd += ["--value", str(value_wei)]
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=300
        )
        who = self._address_of(key)
        if proc.returncode != 0:
            return Step(what=sig, actor=who, ok=False,
                        note=((proc.stderr or proc.stdout).strip()[-200:]))
        try:
            receipt = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return Step(what=sig, actor=who, ok=False, note="unparseable receipt")
        return Step(
            what=sig,
            actor=who,
            tx=receipt.get("transactionHash", ""),
            gas_used=int(receipt.get("gasUsed", "0x0"), 16)
            if isinstance(receipt.get("gasUsed"), str)
            else int(receipt.get("gasUsed") or 0),
            ok=str(receipt.get("status", "0x1")) in ("0x1", "1", "success"),
        )

    def _address_of(self, key: str) -> str:
        for acct in self.accounts:
            if acct.key == key:
                return acct.address
        return "0x?"


def assert_no_cheatcodes(source: str, what: str) -> None:
    """There is no `vm` on a chain, so a fragment that reaches for one cannot run here.

    This is a courtesy rather than a gate: the transaction would simply revert. It is
    checked anyway so the failure says what went wrong instead of costing a deployment.
    """
    if re.search(r"\bvm\s*\.", source):
        raise ValueError(
            f"{what} uses a Foundry cheatcode. On a chain there is no cheatcode "
            f"address to call -- an account acts by holding its key and signing. "
            f"Rewrite the attack as transactions an ordinary account could send."
        )
