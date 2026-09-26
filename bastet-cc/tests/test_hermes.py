from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from bastet_cc.hermes import HermesConfig, build_packet


def _fn(name, contract, start, source, identifiers, *, kind="function",
        modifiers=()):
    return {
        "name": name,
        "kind": kind,
        "contract": contract,
        "visibility": "public",
        "modifiers": list(modifiers),
        "params": "()",
        "start_line": start,
        "end_line": start + 3,
        "source": source,
        "identifiers": sorted(identifiers),
    }


@pytest.fixture
def hermes_repo_index():
    return {
        "repo": "r1",
        "scope_file": False,
        "n_files": 3,
        "n_functions": 11,
        "n_bytes": 1000,
        "skipped": {"vendor": 0, "nonprod": 0, "out_of_scope": 0},
        "files": [
            {
                "path": "Vault.sol",
                "contracts": ["Vault", "Router"],
                "imports": [],
                "n_bytes": 700,
                "parse_errors": 0,
                "functions": [
                    _fn(
                        "onlyOwner",
                        "Vault",
                        5,
                        "modifier onlyOwner() { require(msg.sender == owner); _; }",
                        {"onlyOwner", "owner", "msg.sender"},
                        kind="modifier",
                    ),
                    _fn(
                        "nonReentrant",
                        "Vault",
                        9,
                        "modifier nonReentrant() { require(!entered); entered = true; _; }",
                        {"nonReentrant", "entered"},
                        kind="modifier",
                    ),
                    _fn(
                        "withdraw",
                        "Vault",
                        14,
                        ("function withdraw(uint units) public onlyOwner nonReentrant "
                         "{ _burn(units); safeTransfer(msg.sender, units); }"),
                        {"withdraw", "_burn", "safeTransfer", "units", "balance",
                         "limit", "debt", "commonHot", "x", "uint"},
                        modifiers=("onlyOwner()", "nonReentrant"),
                    ),
                    _fn(
                        "_burn",
                        "Vault",
                        24,
                        "function _burn(uint burnQty) internal { total -= burnQty; commonHot = 1; }",
                        {"_burn", "total", "burnQty", "commonHot"},
                    ),
                    _fn(
                        "executeWithdraw",
                        "Vault",
                        34,
                        "function executeWithdraw(uint requestQty) external { withdraw(requestQty); }",
                        {"executeWithdraw", "withdraw", "requestQty"},
                    ),
                    _fn(
                        "emergencyExit",
                        "Vault",
                        44,
                        "function emergencyExit() external { if (commonHot > 0) withdraw(1); }",
                        {"emergencyExit", "withdraw", "commonHot"},
                    ),
                    _fn(
                        "settle",
                        "Vault",
                        54,
                        "function settle() internal { balance = limit; commonHot = 1; }",
                        {"settle", "balance", "limit", "commonHot"},
                    ),
                    _fn(
                        "rebalance",
                        "Vault",
                        64,
                        "function rebalance() internal { balance = balance + 1; commonHot = 1; }",
                        {"rebalance", "balance", "commonHot"},
                    ),
                    _fn(
                        "trigger",
                        "Router",
                        74,
                        "function trigger() external { if (commonHot > 1) withdraw(2); }",
                        {"trigger", "withdraw", "commonHot"},
                    ),
                ],
            },
            {
                "path": "LibA.sol",
                "contracts": ["LibA"],
                "imports": [],
                "n_bytes": 150,
                "parse_errors": 0,
                "functions": [
                    _fn(
                        "safeTransfer",
                        "LibA",
                        5,
                        "function safeTransfer(address recipient, uint value) internal { tokenA = value; }",
                        {"safeTransfer", "recipient", "value"},
                    ),
                ],
            },
            {
                "path": "LibB.sol",
                "contracts": ["LibB"],
                "imports": [],
                "n_bytes": 150,
                "parse_errors": 0,
                "functions": [
                    _fn(
                        "safeTransfer",
                        "LibB",
                        7,
                        "function safeTransfer(address recipient, uint value) internal { tokenB = value; }",
                        {"safeTransfer", "recipient", "value"},
                    ),
                ],
            },
        ],
    }


def test_build_packet_collects_relations_deterministically(
        hermes_repo_index, finding_factory):
    finding = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="withdraw",
        start_line=14,
        end_line=17,
        evidence="L14-L17",
    )

    packet = build_packet(finding, hermes_repo_index, HermesConfig(max_chars=20_000))
    assert packet is not None
    assert packet.resolution_mode == "parser_identity"

    relations_and_sites = [
        (fragment.relation, fragment.path, fragment.contract, fragment.function)
        for fragment in packet.fragments
    ]
    assert relations_and_sites == [
        ("target", "Vault.sol", "Vault", "withdraw"),
        ("modifier", "Vault.sol", "Vault", "nonReentrant"),
        ("modifier", "Vault.sol", "Vault", "onlyOwner"),
        ("caller", "Vault.sol", "Vault", "executeWithdraw"),
        ("caller", "Vault.sol", "Vault", "emergencyExit"),
        ("caller", "Vault.sol", "Router", "trigger"),
        ("callee", "Vault.sol", "Vault", "_burn"),
        ("callee", "LibB.sol", "LibB", "safeTransfer"),
        ("callee", "LibA.sol", "LibA", "safeTransfer"),
        ("state_peer", "Vault.sol", "Vault", "settle"),
        ("state_peer", "Vault.sol", "Vault", "rebalance"),
    ]
    assert dict(packet.relation_counts) == {
        "target": 1,
        "modifier": 2,
        "caller": 3,
        "callee": 3,
        "state_peer": 2,
    }
    assert dict(packet.omitted_counts) == {
        "target": 0,
        "modifier": 0,
        "caller": 0,
        "callee": 0,
        "state_peer": 0,
    }

    render = packet.render()
    assert "provenance=resolution:parser_identity" in render
    assert "shared_count=2 | shared=balance,limit" in render
    assert "shared_count=1 | shared=balance" in render

    repeated = build_packet(finding, hermes_repo_index, HermesConfig(max_chars=20_000))
    assert repeated is not None
    assert packet.id == repeated.id
    assert [fragment.id for fragment in packet.fragments] == [
        fragment.id for fragment in repeated.fragments
    ]


def test_callees_are_globally_ranked_before_budgeting(
        hermes_repo_index, finding_factory):
    functions = hermes_repo_index["files"][0]["functions"]
    target = next(item for item in functions if item["name"] == "withdraw")
    target["identifiers"] = sorted([*target["identifiers"], "claim"])
    functions.append(_fn(
        "claim",
        "Vault",
        18,
        "function claim() internal { debt = 0; }",
        {"claim", "debt"},
    ))
    finding = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="withdraw",
        start_line=14,
        end_line=17,
        evidence="L14-L17",
    )

    packet = build_packet(
        finding, hermes_repo_index, HermesConfig(max_chars=20_000))

    assert packet is not None
    callees = [
        fragment.function
        for fragment in packet.fragments
        if fragment.relation == "callee"
    ]
    assert callees[:2] == ["claim", "_burn"]


def test_target_resolution_modes_and_no_proximity_fallback(
        hermes_repo_index, finding_factory):
    by_name = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="withdraw",
        start_line=0,
        end_line=0,
        evidence="L999-L1000",
    )
    by_name_packet = build_packet(by_name, hermes_repo_index)
    assert by_name_packet is not None
    assert by_name_packet.resolution_mode == "function_fallback"

    by_overlap = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="missing",
        start_line=0,
        end_line=0,
        evidence="L15-L16",
    )
    by_overlap_packet = build_packet(by_overlap, hermes_repo_index)
    assert by_overlap_packet is not None
    assert by_overlap_packet.resolution_mode == "evidence_overlap"
    assert by_overlap_packet.fragments[0].function == "withdraw"

    unresolved = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="missing",
        start_line=0,
        end_line=0,
        evidence="L500-L510",
    )
    assert build_packet(unresolved, hermes_repo_index) is None


def test_budget_is_hard_and_records_zero_count_partial_relations(
        hermes_repo_index, finding_factory):
    finding = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="withdraw",
        start_line=14,
        end_line=17,
        evidence="L14-L17",
    )

    full_packet = build_packet(finding, hermes_repo_index, HermesConfig(max_chars=20_000))
    assert full_packet is not None
    target_budget = len(full_packet.fragments[0].render())

    packet = build_packet(finding, hermes_repo_index, HermesConfig(max_chars=target_budget))
    assert packet is not None
    assert packet.used_chars == target_budget
    assert [fragment.relation for fragment in packet.fragments] == ["target"]
    assert dict(packet.relation_counts) == {
        "target": 1,
        "modifier": 0,
        "caller": 0,
        "callee": 0,
        "state_peer": 0,
    }
    assert dict(packet.candidate_counts) == {
        "target": 1,
        "modifier": 2,
        "caller": 3,
        "callee": 3,
        "state_peer": 2,
    }
    assert dict(packet.omitted_counts) == {
        "target": 0,
        "modifier": 2,
        "caller": 3,
        "callee": 3,
        "state_peer": 2,
    }


def test_models_are_immutable(hermes_repo_index, finding_factory):
    config = HermesConfig(max_chars=20_000)
    finding = finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="withdraw",
        start_line=14,
        end_line=17,
        evidence="L14-L17",
    )
    packet = build_packet(finding, hermes_repo_index, config)
    assert packet is not None

    with pytest.raises(FrozenInstanceError):
        config.max_chars = 1
    with pytest.raises(FrozenInstanceError):
        packet.used_chars = 0
