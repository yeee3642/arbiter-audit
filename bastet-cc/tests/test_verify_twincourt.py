from __future__ import annotations

import asyncio
import json
from dataclasses import replace

from bastet_cc.findings import finding_key
from bastet_cc.hermes import HermesConfig, build_packet
from bastet_cc.llm import LLMResult
from bastet_cc.runstore import RunStore
from bastet_cc.twincourt import TWINCOURT_TREATMENT
from bastet_cc.verify import VerifyPolicy, VerifyStore, verify_findings, verify_id


class _Client:
    model = "ais3/llama-3.1-8b"

    def __init__(self, parsed, error=None):
        self.parsed = parsed
        self.error = error
        self.calls: list[dict] = []

    async def complete(self, system, user, *, schema, task_id, stage):
        self.calls.append({
            "system": system,
            "user": user,
            "schema": schema,
            "task_id": task_id,
            "stage": stage,
        })
        return LLMResult(
            text=json.dumps(self.parsed),
            parsed=self.parsed,
            model=self.model,
            input_tokens=101,
            output_tokens=17,
            latency_s=0.01,
            attempts=1,
            error=self.error,
        )


def _finding(finding_factory):
    return finding_factory(
        path="Vault.sol",
        contract="Vault",
        function="withdraw",
        description="state changes after an external transfer",
        evidence="L10-L13",
        task_id="detect-1",
        start_line=10,
        end_line=13,
    )


def test_twincourt_persists_packet_provenance_and_resumes(
    tmp_path, finding_factory, repo_index
):
    finding = _finding(finding_factory)
    packet = build_packet(
        finding, repo_index, HermesConfig(max_chars=24_000))
    assert packet is not None
    client = _Client({
        "verdict": "confirmed",
        "reason_code": "exploit_path_proven",
        "preconditions": ["attacker can enter withdraw"],
        "causal_steps": [
            "withdraw reaches the payout helper",
            "the helper transfers before the claimed state update",
        ],
        "counter_evidence": [],
        "cited_fragment_ids": [packet.target_fragment_id],
        "summary": "The packet contains a concrete call path.",
    })
    store = RunStore(tmp_path / "run")

    result = asyncio.run(verify_findings(
        [finding],
        repo_index,
        client,
        store,
        policy=VerifyPolicy.all_on(),
        treatment=TWINCOURT_TREATMENT,
        context_chars=24_000,
        provider_fingerprint="profile-a",
    ))

    assert result[0].verdict == "confirmed"
    assert result[0].adjudication_id.startswith("court-")
    assert result[0].adjudication_reason == "exploit_path_proven"
    assert len(client.calls) == 1
    assert packet.id in client.calls[0]["user"]
    assert packet.target_fragment_id in client.calls[0]["user"]
    assert client.calls[0]["stage"] == "verify"

    record = json.loads((store.run_dir / "verify.jsonl").read_text())
    assert record["finding_key"] == packet.finding_id
    assert record["packet"]["id"] == packet.id
    assert record["packet"]["relation_counts"]["target"] == 1
    assert record["provider_fingerprint"] == "profile-a"
    assert "source" not in record["packet"]

    resumed = _Client(client.parsed)
    cached = asyncio.run(verify_findings(
        [finding],
        repo_index,
        resumed,
        store,
        policy=VerifyPolicy.all_on(),
        treatment=TWINCOURT_TREATMENT,
        context_chars=24_000,
        provider_fingerprint="profile-a",
    ))
    assert resumed.calls == []
    assert cached[0].verdict == "confirmed"
    assert cached[0].adjudication_id == result[0].adjudication_id


def test_keyed_legacy_verifier_cache_requires_exact_finding_key(
    tmp_path, finding_factory, repo_index
):
    finding = _finding(finding_factory)
    first = _Client({
        "verdict": "rejected",
        "attack_scenario": "",
        "reject_reason": "guarded",
    })
    store = RunStore(tmp_path / "run")
    initial = asyncio.run(verify_findings(
        [finding],
        repo_index,
        first,
        store,
        policy=VerifyPolicy.all_on(),
    ))
    assert initial[0].verdict == "rejected"
    assert initial[0].adjudication_version == "legacy-v2"
    assert len(first.calls) == 1

    sibling = replace(finding, severity="Critical")
    assert finding_key(sibling) != finding_key(finding)
    assert verify_id(sibling, _Client.model) != verify_id(finding, _Client.model)
    second = _Client({
        "verdict": "uncertain",
        "attack_scenario": "",
        "reject_reason": "severity changed",
    })
    resumed = asyncio.run(verify_findings(
        [sibling],
        repo_index,
        second,
        store,
        policy=VerifyPolicy.all_on(),
    ))

    assert len(second.calls) == 1
    assert resumed[0].verdict == "uncertain"


def test_malformed_or_invalid_cache_rows_are_ignored(
    tmp_path, finding_factory, repo_index
):
    finding = _finding(finding_factory)
    work_id = verify_id(finding, _Client.model)
    store = RunStore(tmp_path / "run")
    (store.run_dir / "verify.jsonl").write_text(
        "[]\n"
        + json.dumps({
            "finding_key": finding_key(finding),
            "verify_id": work_id,
            "verdict": "bogus",
        })
        + "\n",
        encoding="utf-8",
    )
    client = _Client({
        "verdict": "uncertain",
        "attack_scenario": "",
        "reject_reason": "fresh verifier call",
    })

    result = asyncio.run(verify_findings(
        [finding],
        repo_index,
        client,
        store,
        policy=VerifyPolicy.all_on(),
    ))

    assert len(client.calls) == 1
    assert result[0].verdict == "uncertain"


def test_exact_cache_identity_uses_latest_valid_adjudication(
    tmp_path, finding_factory
):
    finding = _finding(finding_factory)
    key = finding_key(finding)
    work_id = verify_id(finding, _Client.model)
    store = RunStore(tmp_path / "run")
    rows = [
        {
            "finding_key": key,
            "verify_id": work_id,
            "verdict": "rejected",
        },
        {
            "finding_key": key,
            "verify_id": work_id,
            "verdict": "confirmed",
        },
    ]
    (store.run_dir / "verify.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )

    cached = VerifyStore(store).done()

    assert cached[(work_id, key)]["verdict"] == "confirmed"


def test_legacy_cache_id_never_hits_twincourt(
    tmp_path, finding_factory, repo_index
):
    finding = _finding(finding_factory)
    packet = build_packet(
        finding, repo_index, HermesConfig(max_chars=24_000))
    assert packet is not None
    store = RunStore(tmp_path / "run")
    (store.run_dir / "verify.jsonl").write_text(json.dumps({
        "verify_id": verify_id(finding, _Client.model),
        "task_id": finding.task_id,
        "repo": finding.repo,
        "detector_id": finding.detector_id,
        "tag": finding.tag,
        "path": finding.path,
        "contract": finding.contract,
        "function": finding.function,
        "verdict": "rejected",
    }) + "\n")
    client = _Client({
        "verdict": "uncertain",
        "reason_code": "insufficient_context",
        "preconditions": [],
        "causal_steps": [],
        "counter_evidence": [],
        "cited_fragment_ids": [packet.target_fragment_id],
        "summary": "The packet does not prove either side.",
    })

    result = asyncio.run(verify_findings(
        [finding],
        repo_index,
        client,
        store,
        policy=VerifyPolicy.all_on(),
        treatment=TWINCOURT_TREATMENT,
        context_chars=24_000,
        provider_fingerprint="profile-a",
    ))

    assert len(client.calls) == 1
    assert result[0].verdict == "uncertain"
    assert result[0].adjudication_id.startswith("court-")


def test_transient_twincourt_failure_stays_unverified_and_uncached(
    tmp_path, finding_factory, repo_index
):
    finding = _finding(finding_factory)
    client = _Client(None, error="timeout")
    store = RunStore(tmp_path / "run")

    result = asyncio.run(verify_findings(
        [finding],
        repo_index,
        client,
        store,
        policy=VerifyPolicy.all_on(),
        treatment=TWINCOURT_TREATMENT,
        context_chars=24_000,
        provider_fingerprint="profile-a",
    ))

    assert result[0].verdict == "unverified"
    assert not (store.run_dir / "verify.jsonl").exists()

    retried = _Client({
        "verdict": "uncertain",
        "reason_code": "insufficient_context",
        "preconditions": [],
        "causal_steps": [],
        "counter_evidence": [],
        "cited_fragment_ids": [],
        "summary": "Retry reached the model.",
    })
    asyncio.run(verify_findings(
        [finding],
        repo_index,
        retried,
        store,
        policy=VerifyPolicy.all_on(),
        treatment=TWINCOURT_TREATMENT,
        context_chars=24_000,
        provider_fingerprint="profile-a",
    ))
    assert len(retried.calls) == 1
