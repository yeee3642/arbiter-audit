from __future__ import annotations

import json

import httpx
import pytest
import typer

from bastet_cc.cli import (
    _canonical_fingerprint,
    _provider_profile,
    _quality_manifest_fields,
    _run_quality_cost,
    _validate_quality_options,
)


def _gateway_manifest() -> dict:
    fingerprint_payload = {
        "experiment_id": "experiment-a",
        "subject_id": "subject-a",
        "endpoint": "https://llm-api.zoolab.org/v1",
        "model": "ais3/llama-3.1-8b",
        "provider_mode": "live",
        "selected_workflow": "flashloan",
        "workflow_sha256": "w",
        "prompt_sha256": "p",
        "profile_version": "profile-v1",
        "adapter_version": "adapter-v1",
        "schema_version": "schema-v1",
        "budget": {
            "global_calls": 100,
            "global_tokens": 500_000,
            "per_arm_calls": 50,
            "per_arm_tokens": 250_000,
        },
        "claim_level": "live-provider-evidence",
    }
    return {
        **fingerprint_payload,
        "fingerprint": _canonical_fingerprint(fingerprint_payload),
    }


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (
            dict(
                treatment="hermes_twincourt",
                budget_chars=100,
                arm="broadcast",
                verify=True,
                closure=False,
            ),
            "frozen control",
        ),
        (
            dict(
                treatment="hermes_twincourt",
                budget_chars=100,
                arm="routed",
                verify=False,
                closure=False,
            ),
            "verification",
        ),
        (
            dict(
                treatment="hermes_twincourt",
                budget_chars=100,
                arm="routed",
                verify=True,
                closure=True,
            ),
            "separate treatments",
        ),
        (
            dict(
                treatment="hermes_twincourt",
                budget_chars=0,
                arm="routed",
                verify=True,
                closure=False,
            ),
            "positive",
        ),
    ],
)
def test_quality_treatment_rejects_confounded_runs(values, message):
    with pytest.raises(typer.BadParameter, match=message):
        _validate_quality_options(**values)


def test_quality_treatment_normalizes_valid_value():
    assert _validate_quality_options(
        treatment=" HERMES_TWINCOURT ",
        budget_chars=24_000,
        arm="routed",
        verify=True,
        closure=False,
    ) == "hermes_twincourt"


def test_direct_provider_profile_is_safe_and_stable():
    first = _provider_profile(
        automation_url=None,
        experiment=None,
        subject=None,
        model="ais3/llama-3.1-8b",
    )
    second = _provider_profile(
        automation_url=None,
        experiment=None,
        subject=None,
        model="ais3/llama-3.1-8b",
    )
    assert first == second
    assert len(first[0]) == 64
    assert first[1] is None


def test_quality_manifest_records_budget_fingerprint_and_versions():
    fields = _quality_manifest_fields(
        treatment="hermes_twincourt",
        budget_chars=24_000,
        provider_fingerprint="profile-1",
    )

    assert fields["quality_treatment"] == "hermes_twincourt"
    assert fields["quality_budget_chars"] == 24_000
    assert fields["provider_profile"] == {
        "fingerprint": "profile-1",
        "credential_recorded": False,
    }
    assert set(fields["quality_versions"]) == {
        "hermes",
        "twincourt",
        "twincourt_prompt",
        "twincourt_schema",
        "overlay_schema",
    }


def test_automation_profile_records_fairness_evidence(monkeypatch):
    payload = _gateway_manifest()

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    seen = {}

    def fake_get(url, timeout):
        seen.update(url=url, timeout=timeout)
        return _Response()

    monkeypatch.setattr(httpx, "get", fake_get)
    fingerprint, audit = _provider_profile(
        automation_url="http://127.0.0.1:8765/v1",
        experiment="experiment-a",
        subject="subject-a",
        model="ais3/llama-3.1-8b",
    )

    assert seen["url"] == "http://127.0.0.1:8765/manifest"
    assert fingerprint == payload["fingerprint"]
    assert audit is not None
    assert audit["budget"] == payload["budget"]
    assert audit["evidence_complete"] is True
    for field, value in payload.items():
        assert audit[field] == value
    assert "credential" not in audit


def test_automation_profile_refuses_missing_budget(monkeypatch):
    payload = _gateway_manifest()
    del payload["budget"]

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: _Response())
    with pytest.raises(typer.BadParameter, match="missing budget"):
        _provider_profile(
            automation_url="http://127.0.0.1:8765",
            experiment="experiment-a",
            subject="subject-a",
            model="ais3/llama-3.1-8b",
        )


def test_automation_profile_refuses_non_loopback_url():
    with pytest.raises(typer.BadParameter, match="loopback"):
        _provider_profile(
            automation_url="https://gateway.example",
            experiment="experiment-a",
            subject="subject-a",
            model="ais3/llama-3.1-8b",
        )


def test_automation_profile_refuses_fingerprint_tampering(monkeypatch):
    payload = _gateway_manifest()
    payload["fingerprint"] = "0" * 64

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: _Response())
    with pytest.raises(typer.BadParameter, match="fingerprint"):
        _provider_profile(
            automation_url="http://127.0.0.1:8765",
            experiment="experiment-a",
            subject="subject-a",
            model="ais3/llama-3.1-8b",
        )


def test_automation_profile_refuses_noncanonical_budget(monkeypatch):
    payload = _gateway_manifest()
    payload["budget"] = {"max_requests": 100}
    fingerprint_payload = {
        key: value
        for key, value in payload.items()
        if key != "fingerprint"
    }
    payload["fingerprint"] = _canonical_fingerprint(fingerprint_payload)

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: _Response())
    with pytest.raises(typer.BadParameter, match="budget must contain exactly"):
        _provider_profile(
            automation_url="http://127.0.0.1:8765",
            experiment="experiment-a",
            subject="subject-a",
            model="ais3/llama-3.1-8b",
        )


def test_automation_profile_refuses_claim_level_mode_mismatch(monkeypatch):
    payload = _gateway_manifest()
    payload["provider_mode"] = "mock"
    fingerprint_payload = {
        key: value for key, value in payload.items() if key != "fingerprint"
    }
    payload["fingerprint"] = _canonical_fingerprint(fingerprint_payload)

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: _Response())
    with pytest.raises(typer.BadParameter, match="claim_level"):
        _provider_profile(
            automation_url="http://127.0.0.1:8765",
            experiment="experiment-a",
            subject="subject-a",
            model="ais3/llama-3.1-8b",
        )


def test_run_cost_deduplicates_resume_rows_and_ignores_torn_tail(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    detect = {
        "task_id": "task-1",
        "usage": {
            "attempts": 2,
            "input_tokens": 10,
            "output_tokens": 3,
        },
    }
    (run_dir / "results.jsonl").write_text(
        json.dumps(detect) + "\n" + json.dumps(detect) + "\n{")
    (run_dir / "verify.jsonl").write_text(json.dumps({
        "adjudication_id": "court-1",
        "usage": {
            "attempts": 1,
            "input_tokens": 7,
            "output_tokens": 2,
        },
    }) + "\n")

    cost = _run_quality_cost(run_dir)

    assert cost == {
        "detection_items": 1,
        "verification_items": 1,
        "model_calls": 3,
        "input_tokens": 17,
        "output_tokens": 5,
    }
