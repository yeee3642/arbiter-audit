"""Durable adjudication overlays over immutable detector findings."""

from __future__ import annotations

import json
from dataclasses import replace

from bastet_cc.aggregate import Calibration, aggregate
from bastet_cc.emit import to_json, to_markdown, to_sarif
from bastet_cc.findings import finding_key
from bastet_cc.llm import LLMResult
from bastet_cc.runstore import RunStore


def _finding(**kw) -> dict:
    value = {
        "repo": "r1",
        "detector_id": "d1",
        "tag": "Slippage",
        "subtag": "",
        "severity": "High",
        "path": "A.sol",
        "contract": "A",
        "function": "f",
        "description": "claim",
        "evidence": "L1-L2",
        "confidence": 0.9,
        "verdict": "unverified",
        "task_id": "task-1",
        "start_line": 1,
        "end_line": 5,
    }
    value.update(kw)
    return value


def _result() -> LLMResult:
    return LLMResult(
        text="{}", parsed={}, model="model-a", input_tokens=1,
        output_tokens=1, latency_s=0.1, attempts=1, error=None,
    )


def _append_jsonl(path, value: dict) -> None:
    with path.open("a") as fh:
        fh.write(json.dumps(value) + "\n")


def test_overlay_survives_restart_and_export_without_rewriting_raw_log(tmp_path):
    store = RunStore(tmp_path / "run")
    store.write_manifest({"model": "model-a"})
    store.append("task-1", _result(), [_finding()])
    raw_before = store.results_path.read_bytes()
    raw = store.load_findings(apply_verification=False)[0]
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "schema_version": "verify-overlay-v2",
        "adjudication_id": "court-1",
        "finding_key": finding_key(raw),
        "verdict": "rejected",
        "reason_code": "guarded",
    })

    restarted = RunStore(store.run_dir)
    loaded = restarted.load_findings()
    assert loaded[0].verdict == "rejected"
    assert loaded[0].adjudication_id == "court-1"
    assert loaded[0].adjudication_reason == "guarded"
    assert restarted.results_path.read_bytes() == raw_before

    restarted.export_findings()
    exported = json.loads(restarted.findings_path.read_text())
    assert exported[0]["verdict"] == "rejected"
    assert exported[0]["adjudication_id"] == "court-1"
    assert restarted.results_path.read_bytes() == raw_before


def test_latest_valid_overlay_wins_and_torn_tail_is_ignored(tmp_path):
    store = RunStore(tmp_path / "run")
    store.append("task-1", _result(), [_finding()])
    key = finding_key(store.load_findings(apply_verification=False)[0])
    verify_path = store.run_dir / "verify.jsonl"
    _append_jsonl(verify_path, {
        "finding_key": key, "adjudication_id": "old",
        "verdict": "confirmed", "reason_code": "exploit_path_proven",
    })
    _append_jsonl(verify_path, {
        "finding_key": key, "adjudication_id": "new",
        "verdict": "rejected", "reason_code": "guarded",
    })
    with verify_path.open("a") as fh:
        fh.write('{"finding_key": "torn"')

    got = store.load_findings()[0]
    assert got.verdict == "rejected"
    assert got.adjudication_id == "new"


def test_multiple_findings_in_one_task_do_not_share_an_overlay(tmp_path):
    store = RunStore(tmp_path / "run")
    store.append("task-1", _result(), [
        _finding(function="f", description="first"),
        _finding(function="g", description="second"),
    ])
    raw = store.load_findings(apply_verification=False)
    assert finding_key(raw[0]) != finding_key(raw[1])
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "finding_key": finding_key(raw[0]),
        "adjudication_id": "only-first",
        "verdict": "rejected",
    })

    got = store.load_findings()
    assert [finding.verdict for finding in got] == ["rejected", "unverified"]


def test_keyed_overlay_never_falls_back_to_a_legacy_id(tmp_path):
    store = RunStore(tmp_path / "run")
    store.write_manifest({"model": "model-a"})
    store.append("task-1", _result(), [_finding()])
    raw = store.load_findings(apply_verification=False)[0]
    sibling = replace(raw, severity="Critical")
    assert finding_key(sibling) != finding_key(raw)
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "finding_key": finding_key(sibling),
        "adjudication_id": store._legacy_verify_id(raw, "model-a"),
        "verdict": "rejected",
    })

    assert store.load_findings()[0].verdict == "unverified"


def test_malformed_keyed_overlay_is_not_reinterpreted_as_legacy(tmp_path):
    store = RunStore(tmp_path / "run")
    store.write_manifest({"model": "model-a"})
    store.append("task-1", _result(), [_finding()])
    raw = store.load_findings(apply_verification=False)[0]
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "finding_key": None,
        "adjudication_id": store._legacy_verify_id(raw, "model-a"),
        "task_id": raw.task_id,
        "repo": raw.repo,
        "detector_id": raw.detector_id,
        "tag": raw.tag,
        "path": raw.path,
        "contract": raw.contract,
        "function": raw.function,
        "verdict": "rejected",
    })

    assert store.load_findings()[0].verdict == "unverified"


def test_legacy_verify_id_is_applied_when_manifest_has_model(tmp_path):
    store = RunStore(tmp_path / "run")
    store.write_manifest({"model": "model-a"})
    store.append("task-1", _result(), [_finding()])
    finding = store.load_findings(apply_verification=False)[0]
    legacy_id = store._legacy_verify_id(finding, "model-a")
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "verify_id": legacy_id,
        "task_id": finding.task_id,
        "repo": finding.repo,
        "detector_id": finding.detector_id,
        "tag": finding.tag,
        "path": finding.path,
        "contract": finding.contract,
        "function": finding.function,
        "verdict": "confirmed",
        "reason": "legacy scenario",
    })

    got = store.load_findings()[0]
    assert got.verdict == "confirmed"
    assert got.adjudication_id == legacy_id
    assert got.adjudication_version == "legacy-v1"


def test_legacy_site_fallback_requires_unique_claim_and_record(tmp_path):
    store = RunStore(tmp_path / "run")
    store.append("task-1", _result(), [
        _finding(description="first claim"),
        _finding(description="second claim"),
    ])
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "verify_id": "legacy-unknown-model",
        "task_id": "task-1",
        "repo": "r1",
        "detector_id": "d1",
        "tag": "Slippage",
        "path": "A.sol",
        "contract": "A",
        "function": "f",
        "verdict": "rejected",
    })

    assert [f.verdict for f in store.load_findings()] == [
        "unverified",
        "unverified",
    ]


def test_legacy_site_fallback_still_loads_unambiguous_manifestless_run(tmp_path):
    store = RunStore(tmp_path / "run")
    store.append("task-1", _result(), [_finding()])
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "verify_id": "legacy-unknown-model",
        "task_id": "task-1",
        "repo": "r1",
        "detector_id": "d1",
        "tag": "Slippage",
        "path": "A.sol",
        "contract": "A",
        "function": "f",
        "verdict": "confirmed",
    })

    assert store.load_findings()[0].verdict == "confirmed"


def test_stale_legacy_id_does_not_fall_back_to_site_when_model_is_known(tmp_path):
    store = RunStore(tmp_path / "run")
    store.write_manifest({"model": "model-a"})
    store.append("task-1", _result(), [_finding(description="current claim")])
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "verify_id": "stale-id-from-another-claim",
        "task_id": "task-1",
        "repo": "r1",
        "detector_id": "d1",
        "tag": "Slippage",
        "path": "A.sol",
        "contract": "A",
        "function": "f",
        "verdict": "rejected",
    })

    assert store.load_findings()[0].verdict == "unverified"


def test_overlay_can_be_explicitly_disabled_for_raw_instrument_checks(tmp_path):
    store = RunStore(tmp_path / "run")
    store.append("task-1", _result(), [_finding()])
    raw = store.load_findings(apply_verification=False)[0]
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "finding_key": finding_key(raw),
        "adjudication_id": "court",
        "verdict": "rejected",
    })

    assert store.load_findings()[0].verdict == "rejected"
    assert store.load_findings(apply_verification=False)[0].verdict == "unverified"


def test_overlay_propagates_to_scoring_json_markdown_and_sarif(tmp_path):
    store = RunStore(tmp_path / "run")
    store.append("task-1", _result(), [_finding()])
    raw = store.load_findings(apply_verification=False)[0]
    _append_jsonl(store.run_dir / "verify.jsonl", {
        "finding_key": finding_key(raw),
        "adjudication_id": "court",
        "adjudication_version": "twincourt-v1",
        "reason_code": "guarded",
        "verdict": "rejected",
    })
    findings = store.load_findings()
    calibration = Calibration(
        detector_prior={},
        tau=0.5,
        verify_multiplier={
            "confirmed": 1.0,
            "unverified": 0.7,
            "uncertain": 0.4,
            "rejected": 0.0,
        },
        default_prior=1.0,
    )

    assert aggregate(
        findings, calibration, repos=["r1"], tags=["Slippage"]
    )["Slippage"]["r1"] is False
    assert json.loads(to_json(findings)) == []
    assert json.loads(to_json(findings, include_suppressed=True))[0][
        "adjudication_id"
    ] == "court"
    assert "claim" not in to_markdown(findings)
    assert "claim" in to_markdown(findings, include_suppressed=True)
    assert to_sarif(findings)["runs"][0]["results"] == []
    included = to_sarif(findings, include_suppressed=True)
    assert included["runs"][0]["results"][0]["properties"]["verdict"] == "rejected"
