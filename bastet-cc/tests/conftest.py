"""Shared fixtures. No network, no corpus, no API key -- these run anywhere.

The corpus is 6.8 GB of other people's source and is deliberately not in the
repository, so every fixture here is synthetic. That is a constraint worth
stating: these tests protect *invariants* (the control arm equals upstream, the
scorer's arithmetic, the hint ladder's ordering), not measured values. Tests that
would need the corpus are marked `needs_corpus` and skip cleanly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATA = ROOT.parent / "data"


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "needs_corpus: requires data/train.csv and the extracted repos")


@pytest.fixture(scope="session")
def has_corpus() -> bool:
    return (DATA / "train.csv").exists()


@pytest.fixture
def finding_factory():
    """Build Findings without repeating twelve positional fields per test."""
    from bastet_cc.findings import Finding

    def make(repo="r1", detector_id="d1", tag="Slippage", confidence=0.9,
             verdict="unverified", **kw):
        return Finding(
            repo=repo, detector_id=detector_id, tag=tag, subtag=kw.get("subtag", ""),
            severity=kw.get("severity", "High"), path=kw.get("path", "A.sol"),
            contract=kw.get("contract", "A"), function=kw.get("function", "f"),
            description=kw.get("description", "d"), evidence=kw.get("evidence", "L1-L2"),
            confidence=confidence, verdict=verdict, task_id=kw.get("task_id", ""),
        )
    return make


@pytest.fixture
def repo_index():
    """A two-file repository index in the shape solidity.index_repo() returns.

    `Vault.withdraw` calls `_burn` and `_payout`; `_payout` calls `safeTransfer`,
    which is defined in the other file. That gives the call-closure tests a real
    one-hop boundary and a two-hop target that must NOT be pulled in.
    """
    def fn(name, contract, start, src, idents):
        return {"name": name, "kind": "function", "contract": contract,
                "visibility": "public", "modifiers": [], "params": "()",
                "start_line": start, "end_line": start + 3, "source": src,
                "identifiers": sorted(idents)}

    # Filler. The IDF cut is a *ratio* (MAX_DOC_FREQ = 0.15), so a four-function
    # fixture cannot express it: a term in two functions would sit at df = 0.5 and
    # every hint would be culled as ubiquitous. Twenty fillers put a two-function
    # term at 0.083 (kept) and a fourteen-function term at 0.58 (dropped), which is
    # the regime the real 16,518-function corpus operates in.
    filler = [
        fn(f"filler{i}", "Filler", 100 + i * 4,
           f"function filler{i}(uint a) public {{ x{i} = a; }}"
           if i % 2 == 0 else f"function filler{i}() public {{ y{i} = 1; }}",
           {f"filler{i}", f"x{i}" if i % 2 == 0 else f"y{i}", "uint"}
           | ({"a"} if i % 2 == 0 else set()))
        for i in range(20)
    ]

    return {
        "repo": "r1",
        "scope_file": False,
        "n_files": 3,
        "n_functions": 24,
        "n_bytes": 800,
        "skipped": {"vendor": 0, "nonprod": 0, "out_of_scope": 0},
        "files": [
            {"path": "Filler.sol", "contracts": ["Filler"], "imports": [],
             "n_bytes": 400, "parse_errors": 0, "functions": filler},
            {"path": "Vault.sol", "contracts": ["Vault"], "imports": [],
             "n_bytes": 300, "parse_errors": 0,
             "functions": [
                 fn("withdraw", "Vault", 10,
                    "function withdraw(uint a) public { _burn(a); _payout(a); }",
                    {"withdraw", "_burn", "_payout", "a", "uint"}),
                 fn("_burn", "Vault", 20,
                    "function _burn(uint a) internal { total -= a; }",
                    {"_burn", "total", "a"}),
                 fn("_payout", "Vault", 30,
                    "function _payout(uint a) internal { safeTransfer(msg.sender, a); }",
                    {"_payout", "safeTransfer", "msg.sender", "sender", "a"}),
             ]},
            {"path": "Lib.sol", "contracts": ["Lib"], "imports": [],
             "n_bytes": 100, "parse_errors": 0,
             "functions": [
                 fn("safeTransfer", "Lib", 5,
                    "function safeTransfer(address t, uint a) internal { }",
                    {"safeTransfer", "t", "a", "address"}),
             ]},
        ],
    }


@pytest.fixture
def detectors():
    from bastet_cc.routing import Detector
    return [
        Detector(id="d_swap", name="Swap", source_workflow="w", tags=["Slippage"],
                 routing_hints=["_payout", "safeTransfer"], prompt_chars=100),
        Detector(id="d_generic", name="Generic", source_workflow="w", tags=["DoS"],
                 routing_hints=["a"], prompt_chars=100),
    ]
